//go:build linux

package headless

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestPhysicalBridgeChecksInnerAddressesBeforeForwarding(t *testing.T) {
	var requests atomic.Int32
	control := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Action action `json:"action"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Action.Operation != "forward" {
			t.Error("unexpected forwarding request")
			w.WriteHeader(400)
			return
		}
		requests.Add(1)
		if request.Action.Destination == "192.0.2.1" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"accepted":true}`))
	}))
	defer control.Close()
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	api, err := newAPI(control.URL, "", identity, control.Client(), false)
	if err != nil {
		t.Fatal(err)
	}
	node := &Node{ctx: context.Background(), api: api, bind: &meshBind{}, Record: NodeRecord{VPNIP: "10.254.0.1"}}
	filter := &kernelFilter{node: node, decisions: make(map[forwardingPair]forwardingDecision)}
	packet := make([]byte, 20)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], 20)
	source := netip.MustParseAddr("10.254.0.2").As4()
	copy(packet[12:16], source[:])
	for _, destination := range []string{"192.0.2.1", "10.254.0.3"} {
		address := netip.MustParseAddr(destination).As4()
		copy(packet[16:20], address[:])
		expected := destination != "192.0.2.1"
		for count := 0; count < 2; count++ {
			if filter.permit(packet, true) != expected {
				t.Fatal("inner-address policy was bypassed")
			}
		}
	}
	if requests.Load() != 2 {
		t.Fatal("forwarding decisions were not cached within their short validity")
	}
	copy(packet[16:20], []byte{10, 254, 0, 1})
	if !filter.permit(packet, true) || requests.Load() != 2 {
		t.Fatal("authorized local tunnel traffic should not request transit policy")
	}
	if filter.permit(packet[:10], true) {
		t.Fatal("malformed IP packet accepted")
	}
}
