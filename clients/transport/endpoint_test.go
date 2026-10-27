package transport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func dnsName(value string) []byte {
	var result []byte
	for _, label := range strings.Split(strings.TrimSuffix(value, "."), ".") {
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	return append(result, 0)
}

// A real DNS server returns alias -> edge.provider.test -> A/AAAA records.
// Changing answers exercises reconnect/refresh without an external DNS service.
func cnameResolver(t *testing.T, answers func() []netip.Addr) (*net.Resolver, *atomic.Int32) {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	var cnames atomic.Int32
	go func() {
		buffer := make([]byte, 4096)
		for {
			size, remote, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			if size < 17 {
				continue
			}
			query := append([]byte(nil), buffer[:size]...)
			offset := 12
			var labels []string
			for offset < size && query[offset] != 0 {
				n := int(query[offset])
				offset++
				if n > 63 || offset+n > size {
					break
				}
				labels = append(labels, string(query[offset:offset+n]))
				offset += n
			}
			offset++
			if offset+4 > size {
				continue
			}
			questionEnd := offset + 4
			kind := binary.BigEndian.Uint16(query[offset:])
			name := strings.Join(labels, ".") + "."
			response := append([]byte(nil), query[:questionEnd]...)
			binary.BigEndian.PutUint16(response[2:], 0x8180)
			for i := 6; i < 12; i++ {
				response[i] = 0
			}
			count := uint16(0)
			record := func(owner []byte, typ uint16, data []byte) {
				response = append(response, owner...)
				header := make([]byte, 10)
				binary.BigEndian.PutUint16(header, typ)
				binary.BigEndian.PutUint16(header[2:], 1)
				binary.BigEndian.PutUint16(header[8:], uint16(len(data)))
				response = append(response, header...)
				response = append(response, data...)
				count++
			}
			origin := "edge.provider.test."
			if name != origin {
				record([]byte{0xc0, 0x0c}, 5, dnsName(origin))
				cnames.Add(1)
			}
			for _, address := range answers() {
				if kind == 1 && address.Is4() {
					value := address.As4()
					record(dnsName(origin), 1, value[:])
				}
				if kind == 28 && address.Is6() {
					value := address.As16()
					record(dnsName(origin), 28, value[:])
				}
			}
			binary.BigEndian.PutUint16(response[6:], count)
			listener.WriteTo(response, remote)
		}
	}()
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", listener.LocalAddr().String())
	}}
	return resolver, &cnames
}

func TestCNAMERefreshAndRebindingProtection(t *testing.T) {
	var stage atomic.Int32
	resolver, cnames := cnameResolver(t, func() []netip.Addr {
		switch stage.Load() {
		case 0:
			return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("2606:4700:4700::1111")}
		case 1:
			return []netip.Addr{netip.MustParseAddr("8.8.4.4")}
		default:
			return []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("100.96.127.54")}
		}
	})
	p := &Proxy{endpointNetwork: endpointNetwork{resolver: resolver}, configuration: Configuration{publicIngress: true, GatewayTransportURLs: []string{"udp://vpn.alias.test:51820"}}, remote: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 51820}, status: Status{Transport: "udp", Failures: map[string]uint64{}}}
	ctx := context.Background()
	p.refreshUDP(ctx)
	if p.Snapshot().Endpoint != "udp://vpn.alias.test:51820" {
		t.Fatal("CNAME hostname was not retained in telemetry")
	}
	addresses, err := p.resolveEndpoint(ctx, "vpn.alias.test:51820")
	if err != nil || len(addresses) != 2 {
		t.Fatalf("CNAME A/AAAA results missing: %v %v", addresses, err)
	}
	stage.Store(1)
	p.refreshUDP(ctx)
	if p.remote.String() != "8.8.4.4:51820" {
		t.Fatal("DNS change did not update the UDP destination")
	}
	stage.Store(2)
	p.endpointNetwork.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("a private DNS answer reached the dialer")
		return nil, errors.New("unexpected dial")
	}
	if _, err := p.dialEndpoint(ctx, "tcp", "vpn.alias.test:51820"); !errors.Is(err, errDNSNonpublic) {
		t.Fatalf("DNS rebinding was not rejected: %v", err)
	}
	p.refreshUDP(ctx)
	if p.remote.String() != "8.8.4.4:51820" || p.Snapshot().Failures["dns_nonpublic"] == 0 {
		t.Fatal("bad DNS answers replaced the working endpoint or hid the error")
	}
	if cnames.Load() == 0 {
		t.Fatal("fixture did not exercise real CNAME responses")
	}
}

func TestCNAMEDialRetriesFreshDNSAndUnreachableAddressFamily(t *testing.T) {
	var stage atomic.Int32
	resolver, _ := cnameResolver(t, func() []netip.Addr {
		if stage.Load() == 0 {
			return []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("8.8.8.8")}
		}
		return []netip.Addr{netip.MustParseAddr("8.8.4.4")}
	})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer connection.Close(); io.Copy(connection, connection) }()
		}
	}()
	var lock sync.Mutex
	var dialed []string
	p := &Proxy{configuration: Configuration{publicIngress: true}, endpointNetwork: endpointNetwork{resolver: resolver, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		lock.Lock()
		dialed = append(dialed, address)
		lock.Unlock()
		if strings.HasPrefix(address, "[") {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		if address != "8.8.8.8:443" && address != "8.8.4.4:443" {
			return nil, errors.New("unexpected destination")
		}
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	}}}
	for i := 0; i < 2; i++ {
		stage.Store(int32(i))
		started := time.Now()
		connection, err := p.dialEndpoint(context.Background(), "tcp", "vpn.alias.test:443")
		if err != nil {
			t.Fatal(err)
		}
		connection.SetDeadline(time.Now().Add(time.Second))
		connection.Write([]byte{byte(i)})
		var reply [1]byte
		if _, err = io.ReadFull(connection, reply[:]); err != nil {
			t.Fatal(err)
		}
		connection.Close()
		if reply[0] != byte(i) || time.Since(started) > 2*time.Second {
			t.Fatal("CNAME family fallback or socket transfer failed")
		}
	}
	lock.Lock()
	defer lock.Unlock()
	if !strings.Contains(strings.Join(dialed, ","), "8.8.4.4:443") {
		t.Fatal("reconnect reused a stale DNS address")
	}
}

func TestCNAMEHTTPSPreservesHostSNIAndVerifiesCertificate(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"vpn.alias.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if !strings.HasPrefix(r.Host, "vpn.alias.test:") || r.TLS.ServerName != "vpn.alias.test" {
			http.Error(w, "wrong hostname", 400)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"token": strings.Repeat("a", 64)})
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	defer server.Close()
	resolver, _ := cnameResolver(t, func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("8.8.8.8")} })
	port := strconv.Itoa(server.Listener.Addr().(*net.TCPAddr).Port)
	keyPrivate, keyPublic := keys()
	for _, scenario := range []struct {
		host    string
		trust   bool
		success bool
	}{{"vpn.alias.test", true, true}, {"vpn.alias.test", false, false}, {"wrong.alias.test", true, false}} {
		roots := x509.NewCertPool()
		if scenario.trust {
			roots.AddCert(certificate)
		}
		p, err := startWithNetwork(Configuration{publicIngress: true, ClientNodeID: "client", GatewayNodeID: "gateway", PrivateKey: keyPrivate, GatewayWireGuardPublicKey: keyPublic, GatewayEndpoint: "127.0.0.1:1"}, nil, endpointNetwork{resolver: resolver, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "8.8.8.8:"+port {
				return nil, errors.New("DNS was not pinned to its public answer")
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}})
		if err != nil {
			t.Fatal(err)
		}
		transport := p.client.Transport.(*http.Transport)
		transport.Proxy = nil
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		packet := make([]byte, 148)
		packet[0] = 1
		_, err = p.open(context.Background(), "https://"+scenario.host+":"+port+"/v1/tunnels/wireguard/open", packet)
		p.Close()
		if (err == nil) != scenario.success {
			t.Fatalf("TLS scenario %+v: %v", scenario, err)
		}
	}
	if requests.Load() != 1 {
		t.Fatal("untrusted or mismatched certificates reached the application")
	}
}
