package transport

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeTCPFallbackDoesNotIssueHTTPRequests(t *testing.T) {
	private, public := keys()
	key, _ := transportAuthenticationKey(private, public)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var httpRequests atomic.Int32
	unusedHTTP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpRequests.Add(1)
		http.Error(w, "TCP must not use HTTP", 500)
	}))
	defer unusedHTTP.Close()
	serverResult := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(12 * time.Second))
		serverResult <- func() error {
			preface := make([]byte, 8)
			if _, err := io.ReadFull(connection, preface); err != nil {
				return err
			}
			if string(preface) != tcpPreface {
				return fmt.Errorf("opening was not native TCP")
			}
			var headerLength uint16
			var bodyLength uint32
			if err := binary.Read(connection, binary.BigEndian, &headerLength); err != nil {
				return err
			}
			if err := binary.Read(connection, binary.BigEndian, &bodyLength); err != nil {
				return err
			}
			if headerLength > 4096 || bodyLength > transportMaximumPacket+2054 {
				return fmt.Errorf("opening exceeded bounds")
			}
			header := make([]byte, headerLength)
			body := make([]byte, bodyLength)
			if _, err := io.ReadFull(connection, header); err != nil {
				return err
			}
			if _, err := io.ReadFull(connection, body); err != nil {
				return err
			}
			var auth struct {
				Node      string `json:"node"`
				Relay     bool   `json:"relay"`
				Timestamp int64  `json:"timestamp"`
				Nonce     string `json:"nonce"`
				Proof     string `json:"proof"`
			}
			if err := json.Unmarshal(header, &auth); err != nil {
				return err
			}
			if auth.Node != "client" || auth.Relay || auth.Proof != transportProof(key, "client", "gateway", auth.Timestamp, auth.Nonce, body) || !bytes.HasPrefix(body, []byte("HNT1")) {
				return fmt.Errorf("TCP opening did not bind the registered identity and packet")
			}
			if _, err := connection.Write([]byte{0}); err != nil {
				return err
			}
			// Verify the zero-length keepalive is answered on the same stream.
			if _, err := connection.Write([]byte{0, 0}); err != nil {
				return err
			}
			reply := make([]byte, 92)
			reply[0] = 2
			if err := binary.Write(connection, binary.BigEndian, uint16(len(reply))); err != nil {
				return err
			}
			if _, err := connection.Write(reply); err != nil {
				return err
			}
			for {
				var size uint16
				if err := binary.Read(connection, binary.BigEndian, &size); err != nil {
					return err
				}
				if size == 0 {
					continue
				}
				packet := make([]byte, size)
				if _, err := io.ReadFull(connection, packet); err != nil {
					return err
				}
				if len(packet) > 0 && packet[0] == 4 {
					if err := binary.Write(connection, binary.BigEndian, size); err != nil {
						return err
					}
					_, err := connection.Write(packet)
					return err
				}
			}
		}()
	}()
	blackhole, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer blackhole.Close()
	p, err := start(Configuration{ClientNodeID: "client", GatewayNodeID: "gateway", PrivateKey: private, GatewayWireGuardPublicKey: public, GatewayEndpoint: blackhole.LocalAddr().String(), GatewayTCPTunnelEndpoints: []string{listener.Addr().String()}, GatewayHTTPTunnelURLs: []string{unusedHTTP.URL + "/v1/tunnels/wireguard/open"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	local, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer local.Close()
	endpoint, _ := net.ResolveUDPAddr("udp", p.Endpoint())
	packet := make([]byte, 148)
	packet[0] = 1
	local.WriteToUDP(packet, endpoint)
	local.SetReadDeadline(time.Now().Add(10 * time.Second))
	buffer := make([]byte, 65535)
	n, _, err := local.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != 92 || buffer[0] != 2 {
		t.Fatal("TCP reply was not delivered to WireGuard")
	}
	packet = make([]byte, 57)
	packet[0] = 4
	local.WriteToUDP(packet, endpoint)
	n, source, err := local.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(packet) || !bytes.Equal(packet, buffer[:n]) || source.Port != endpoint.Port {
		t.Fatal("TCP framing or the stable local endpoint changed")
	}
	if p.Snapshot().Transport != "tcp" {
		t.Fatalf("TCP mode was not reported: %+v", p.Snapshot())
	}
	if httpRequests.Load() != 0 {
		t.Fatal("native TCP used HTTP")
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}
func TestTCPIngressValidation(t *testing.T) {
	for _, invalid := range []string{"127.0.0.1:51820", "8.8.8.8:0", "localhost:51820", "8.8.8.8", "8.8.8.8:70000", "http://8.8.8.8:80"} {
		if ValidateTCPEndpoints([]string{invalid}) == nil {
			t.Fatalf("accepted invalid TCP ingress %s", invalid)
		}
	}
	if ValidateTCPEndpoints([]string{"8.8.8.8:51820", "[2606:4700:4700::1111]:443"}) != nil {
		t.Fatal("valid TCP endpoints rejected")
	}
	if ValidateTCPEndpoints(strings.Fields(strings.Repeat("8.8.8.8:51820 ", 9))) == nil {
		t.Fatal("unbounded TCP ingress list accepted")
	}
}
