package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/curve25519"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func keys() (string, string) {
	private := bytes.Repeat([]byte{7}, 32)
	public, _ := curve25519.X25519(bytes.Repeat([]byte{11}, 32), curve25519.Basepoint)
	return hex.EncodeToString(private), hex.EncodeToString(public)
}
func TestValidationAndProofBinding(t *testing.T) {
	for _, value := range []string{"http://127.0.0.1/v1/tunnels/wireguard/open", "https://example.com/v1/tunnels/wireguard/open", "https://8.8.8.8/v1/tunnels/wireguard/open?secret=x", "https://token@8.8.8.8/v1/tunnels/wireguard/open", "http://8.8.8.8:0/v1/tunnels/wireguard/open"} {
		if ValidateURLs([]string{value}) == nil {
			t.Fatalf("accepted invalid endpoint: %s", value)
		}
	}
	if err := ValidateURLs([]string{"https://8.8.8.8/v1/tunnels/wireguard/open", "http://8.8.8.8/v1/tunnels/wireguard/open"}); err != nil {
		t.Fatal(err)
	}
	private, public := keys()
	key, err := transportAuthenticationKey(private, public)
	if err != nil {
		t.Fatal(err)
	}
	proof := transportProof(key, "client", "gateway", 123, "00112233445566778899aabbccddeeff", []byte("test"))
	if proof != "cb4a2ccf100a94e0d1872b22a8fec340595db2e1460e89e9745a000ebf287974" {
		t.Fatal("cross-language proof mismatch")
	}
	if proof == transportProof(key, "other", "gateway", 123, "00112233445566778899aabbccddeeff", []byte("test")) {
		t.Fatal("proof did not bind identity")
	}
	if _, err = transportAuthenticationKey(private, strings.Repeat("00", 32)); err == nil {
		t.Fatal("accepted low-order public key")
	}
}
func TestUDPBlockedFallbackHTTPSAndHTTP(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(fmt.Sprint("tls=", secure), func(t *testing.T) {
			private, public := keys()
			key, _ := transportAuthenticationKey(private, public)
			packet := make([]byte, 148)
			packet[0] = 1
			reply := make([]byte, 92)
			reply[0] = 2
			received := make(chan []byte, 64)
			var lock sync.Mutex
			opens := 0
			invalid := false
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Upgrade") != "" || r.URL.RawQuery != "" {
					lock.Lock()
					invalid = true
					lock.Unlock()
					http.Error(w, "unexpected request", 400)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/open") {
					body, _ := io.ReadAll(io.LimitReader(r.Body, transportMaximumBatch+1))
					timestamp, _ := strconv.ParseInt(r.Header.Get("X-HeteroNetwork-Time"), 10, 64)
					expected := transportProof(key, "client", "gateway", timestamp, r.Header.Get("X-HeteroNetwork-Nonce"), body)
					if len(body) < 6 || string(body[:4]) != "HNT1" || r.Header.Get("X-HeteroNetwork-Proof") != expected || time.Now().Unix()-timestamp > 60 {
						http.Error(w, "bad proof", 401)
						return
					}
					n := int(binary.BigEndian.Uint16(body[4:6]))
					var diagnostics map[string]uint64
					if 6+n >= len(body) || json.Unmarshal(body[6:6+n], &diagnostics) != nil || diagnostics["udp_probe_timeout"] == 0 {
						http.Error(w, "bad diagnostics", 400)
						return
					}
					if !bytes.Equal(body[6+n:], packet) {
						http.Error(w, "packet changed", 400)
						return
					}
					lock.Lock()
					opens++
					lock.Unlock()
					received <- reply
					json.NewEncoder(w).Encode(map[string]any{"token": strings.Repeat("a", 64), "first_packet": []int{}})
					return
				}
				if r.Header.Get("Authorization") != "HeteroNetworkTunnel "+strings.Repeat("a", 64) {
					http.Error(w, "bad session", 401)
					return
				}
				if r.Method == http.MethodGet {
					select {
					case packet := <-received:
						binary.Write(w, binary.BigEndian, uint16(len(packet)))
						w.Write(packet)
					case <-r.Context().Done():
						return
					case <-time.After(time.Second):
						w.WriteHeader(200)
					}
					return
				}
				if r.Method == http.MethodPost {
					io.Copy(io.Discard, r.Body)
					w.WriteHeader(204)
					return
				}
				http.Error(w, "unexpected method", 400)
			})
			var server *httptest.Server
			if secure {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			blackhole, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			defer blackhole.Close()
			httpTransport := http.DefaultTransport.(*http.Transport).Clone()
			httpTransport.Proxy = nil
			if secure {
				roots := x509.NewCertPool()
				roots.AddCert(server.Certificate())
				httpTransport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
			}
			client := &http.Client{Transport: httpTransport, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			p, err := start(Configuration{ClientNodeID: "client", GatewayNodeID: "gateway", PrivateKey: private, GatewayWireGuardPublicKey: public, GatewayEndpoint: blackhole.LocalAddr().String(), GatewayHTTPTunnelURLs: []string{server.URL + "/v1/tunnels/wireguard/open"}}, client)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			local, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			defer local.Close()
			endpoint, _ := net.ResolveUDPAddr("udp", p.Endpoint())
			local.WriteToUDP(packet, endpoint)
			local.SetReadDeadline(time.Now().Add(9 * time.Second))
			buffer := make([]byte, 65535)
			n, source, err := local.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !source.IP.Equal(endpoint.IP) || source.Port != endpoint.Port || !bytes.Equal(buffer[:n], reply) {
				t.Fatal("reply did not use the stable local endpoint")
			}
			status := p.Snapshot()
			expectedMode := "http"
			if secure {
				expectedMode = "https"
			}
			if status.Transport != expectedMode || status.Switches != 1 || status.RXBytes == 0 {
				t.Fatalf("missing telemetry: %+v", status)
			}
			status.Failures["outside_mutation"] = 9
			if p.Snapshot().Failures["outside_mutation"] != 0 {
				t.Fatal("snapshot aliases mutable counters")
			}
			lock.Lock()
			defer lock.Unlock()
			if opens != 1 || invalid {
				t.Fatalf("unexpected HTTP behavior: opens=%d invalid=%v", opens, invalid)
			}
		})
	}
}
func TestRedirectNeverForwardsCredential(t *testing.T) {
	var leaked bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer server.Close()
	p := &Proxy{client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	if _, err := p.request(context.Background(), http.MethodPost, server.URL, "secret", []byte("ciphertext")); err == nil {
		t.Fatal("redirect accepted")
	}
	if leaked {
		t.Fatal("credential followed redirect")
	}
}
