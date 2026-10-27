//go:build linux

package headless

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"testing"
	"time"
)

// This privileged boundary test is separate from the unprivileged cloud test:
// the existing physical VPN host owns the kernel bridge, never the cloud node.
func TestHTTPMeshPhysicalBridgeRoutesPrivateCloudTraffic(t *testing.T) {
	if os.Getenv("HTTP_MESH_KERNEL_TEST") != "1" {
		t.Skip("enable the isolated privileged host-bridge test")
	}
	if os.Geteuid() != 0 {
		t.Fatal("the host-bridge acceptance test requires root")
	}
	database, issuer, at, operator := fixtureInputs(t)
	backend := startFixture(t, database, issuer, at, operator, 201)
	pool := &replicaPool{backends: []*fixtureBackend{backend}, seen: make(map[string]map[string]bool), marker: []byte("private-host-bridge")}
	control := httptest.NewTLSServer(pool)
	defer control.Close()
	data := httptest.NewServer(pool)
	defer data.Close()
	client := control.Client()
	client.Timeout = 25 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cloud, err := Start(ctx, Config{Endpoint: control.URL, MeshEndpoint: data.URL, HTTPClient: client, JoinToken: backend.token})
	if err != nil {
		t.Fatal(err)
	}
	defer cloud.Close()
	bridge, err := Start(ctx, Config{Endpoint: control.URL, MeshEndpoint: data.URL, HTTPClient: client, JoinToken: backend.token, KernelInterface: "hnmeshe2e"})
	if err != nil {
		t.Fatal(err)
	}
	defer bridge.Close()
	for !bridge.Status().Ready {
		select {
		case <-ctx.Done():
			t.Fatal("physical bridge did not become ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	cloudListener, err := cloud.ListenTCP(18082)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "cloud-private") })}
	defer server.Close()
	go server.Serve(cloudListener)
	// Ordinary kernel TCP reaches the cloud's userspace stack over HTTP packets.
	hostClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}}
	defer hostClient.CloseIdleConnections()
	response, err := hostClient.Get("http://" + net.JoinHostPort(cloud.Record.VPNIP, "18082"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "cloud-private" {
		t.Fatal("kernel -> cloud transfer failed")
	}
	hostListener, err := bridge.ListenTCP(18083)
	if err != nil {
		t.Fatal(err)
	}
	hostServer := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "host-private") })}
	defer hostServer.Close()
	go hostServer.Serve(hostListener)
	vpnClient := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: cloud.DialContext}}
	defer vpnClient.CloseIdleConnections()
	response, err = vpnClient.Get("http://" + net.JoinHostPort(bridge.Record.VPNIP, "18083"))
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "host-private" {
		t.Fatal("cloud -> kernel transfer failed")
	}
	cloud.Close()
	for {
		output, err := exec.Command("/usr/sbin/ip", "-j", "route", "show", "table", "51989").Output()
		var routes []struct {
			Destination string `json:"dst"`
		}
		present := false
		if err == nil && json.Unmarshal(output, &routes) == nil {
			for _, route := range routes {
				if route.Destination == cloud.Record.VPNIP || route.Destination == cloud.Record.VPNIP+"/32" {
					present = true
				}
			}
			if !present {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("departed cloud node route was not removed")
		case <-time.After(50 * time.Millisecond):
		}
	}
	bridge.Close()
	if _, err := os.Stat("/sys/class/net/hnmeshe2e"); !os.IsNotExist(err) {
		t.Fatal("host bridge interface remained after shutdown")
	}
	t.Log("PASS: ordinary kernel TCP <-> unprivileged HTTP-only cloud VPN; departed node route removed; bridge cleaned up")
}
