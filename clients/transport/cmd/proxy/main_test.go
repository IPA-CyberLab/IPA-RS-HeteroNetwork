package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestChildProcess(t *testing.T) {
	if os.Getenv("HNN_TRANSPORT_TEST_CHILD") != "1" {
		return
	}
	if err := run(); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
func TestParentEOFStopsTheNativeTransportProcess(t *testing.T) {
	child := exec.Command(os.Args[0], "-test.run=^TestChildProcess$")
	child.Env = append(os.Environ(), "HNN_TRANSPORT_TEST_CHILD=1")
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			child.Process.Kill()
			child.Wait()
		}
	}()
	config := map[string]any{"client_node_id": "client", "gateway_node_id": "gateway", "private_key": strings.Repeat("07", 32), "gateway_wireguard_public_key": "57db4b359f23ae5e146e4e2512056704722506348c150c14753d0c0f49368d5e", "gateway_endpoint": "8.8.8.8:51820", "gateway_http_tunnel_urls": []string{"http://8.8.8.8/v1/tunnels/wireguard/open"}}
	if err = json.NewEncoder(input).Encode(config); err != nil {
		t.Fatal(err)
	}
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(output).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		var value struct{ Endpoint string }
		if json.Unmarshal([]byte(line), &value) != nil || !strings.HasPrefix(value.Endpoint, "127.0.0.1:") {
			t.Fatal("child did not produce a loopback endpoint")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child readiness timed out")
	}
	input.Close()
	finished := make(chan error, 1)
	go func() { finished <- child.Wait() }()
	select {
	case err = <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("child did not exit when the parent pipe closed")
	}
}
