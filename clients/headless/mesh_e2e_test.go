package headless

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

type fixtureBackend struct {
	url     *url.URL
	command *exec.Cmd
	token   json.RawMessage
}
type replicaPool struct {
	mutex       sync.Mutex
	backends    []*fixtureBackend
	sequence    atomic.Uint64
	dropped     atomic.Bool
	duplicate   atomic.Uint64
	seen        map[string]map[string]bool
	plaintext   atomic.Bool
	fullPeerMap atomic.Bool
	marker      []byte
}

func (pool *replicaPool) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Query  query  `json:"query"`
		Action action `json:"action"`
	}
	if r.URL.Path == "/v1/http-mesh" {
		body, err := io.ReadAll(io.LimitReader(r.Body, 128*1024+1))
		if err != nil || len(body) > 128*1024 {
			http.Error(w, "oversized", 400)
			return
		}
		r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		json.Unmarshal(body, &request)
		for _, packet := range request.Action.Packets {
			raw, _ := base64.StdEncoding.DecodeString(packet)
			if bytes.Contains(raw, pool.marker) {
				pool.plaintext.Store(true)
			}
		}
	}
	pool.mutex.Lock()
	if len(pool.backends) == 0 {
		pool.mutex.Unlock()
		http.Error(w, "no replicas", 503)
		return
	}
	backend := pool.backends[int(pool.sequence.Add(1)-1)%len(pool.backends)]
	if request.Query.NodeID != "" {
		if pool.seen[request.Query.NodeID] == nil {
			pool.seen[request.Query.NodeID] = make(map[string]bool)
		}
		pool.seen[request.Query.NodeID][backend.url.String()] = true
	}
	pool.mutex.Unlock()
	proxy := httputil.NewSingleHostReverseProxy(backend.url)
	proxy.ErrorLog = nil
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) { http.Error(w, "retry another replica", 502) }
	proxy.ModifyResponse = func(response *http.Response) error {
		if r.URL.Path == "/v1/http-mesh/join" && response.StatusCode == 200 {
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				return err
			}
			if len(body) > 8192 || bytes.Contains(body, []byte(`"peer_map"`)) {
				pool.fullPeerMap.Store(true)
			}
			response.Body = io.NopCloser(bytes.NewReader(body))
			response.ContentLength = int64(len(body))
		}
		if request.Action.Operation == "send" && response.StatusCode == 200 {
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil {
				return err
			}
			var reply meshResponse
			json.Unmarshal(body, &reply)
			if reply.Accepted != nil && !*reply.Accepted {
				pool.duplicate.Add(1)
			}
			response.Body = io.NopCloser(bytes.NewReader(body))
			response.ContentLength = int64(len(body))
			if pool.dropped.CompareAndSwap(true, false) {
				response.Body.Close()
				return errors.New("injected loss after database commit")
			}
		}
		return nil
	}
	proxy.ServeHTTP(w, r)
}

func startFixture(t *testing.T, database, issuer, at, operator string, index int) *fixtureBackend {
	t.Helper()
	binary := os.Getenv("HETERONETWORK_HTTP_MESH_FIXTURE")
	if binary == "" {
		t.Skip("set HETERONETWORK_HTTP_MESH_FIXTURE to the compiled Rust fixture")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	tokenPath := filepath.Join(t.TempDir(), "join-token.json")
	command := exec.Command(binary)
	command.Env = append(os.Environ(), "HTTP_MESH_FIXTURE_DATABASE="+database, "HTTP_MESH_FIXTURE_ISSUER="+issuer, "HTTP_MESH_FIXTURE_TIME="+at, "HTTP_MESH_FIXTURE_OPERATOR="+operator, "HTTP_MESH_FIXTURE_LISTEN="+address, "HTTP_MESH_FIXTURE_TOKEN_PATH="+tokenPath)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	t.Cleanup(func() {
		command.Process.Kill()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("fixture did not exit")
		}
	})
	endpoint, _ := url.Parse("http://" + address)
	until := time.Now().Add(30 * time.Second)
	for {
		response, err := http.Get(endpoint.String() + "/healthz")
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 || response.StatusCode == 204 {
				break
			}
		}
		select {
		case err := <-finished:
			t.Fatalf("fixture %d exited: %v", index, err)
		default:
		}
		if time.Now().After(until) {
			t.Fatalf("fixture %d did not become ready", index)
		}
		time.Sleep(20 * time.Millisecond)
	}
	token, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	return &fixtureBackend{endpoint, command, token}
}

func fixtureInputs(t *testing.T) (database, issuer, at, operator string) {
	t.Helper()
	if os.Getenv("HETERONETWORK_HTTP_MESH_FIXTURE") == "" {
		t.Skip("compiled Rust fixture required")
	}
	database = os.Getenv("HTTP_MESH_TEST_DATABASE")
	if database == "" {
		database = "sqlite://" + filepath.Join(t.TempDir(), "mesh.sqlite") + "?mode=rwc"
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	issuer = base64.StdEncoding.EncodeToString(secret)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	operator = base64.RawURLEncoding.EncodeToString(secret)
	at = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return
}

func TestHTTPMeshRealWireGuardAcrossScaleAndRestart(t *testing.T) {
	database, issuer, at, operator := fixtureInputs(t)
	pool := &replicaPool{seen: make(map[string]map[string]bool), marker: []byte("PRIVATE-APP-DATA-HTTP-MESH-TEST")}
	for i := 0; i < 3; i++ {
		pool.backends = append(pool.backends, startFixture(t, database, issuer, at, operator, i))
	}
	token := pool.backends[0].token
	control := httptest.NewTLSServer(pool)
	defer control.Close()
	data := httptest.NewServer(pool)
	defer data.Close()
	client := control.Client()
	client.Timeout = 25 * time.Second
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var nodes []*Node
	for i := 0; i < 2; i++ {
		node, err := Start(ctx, Config{Endpoint: control.URL, MeshEndpoint: data.URL, JoinToken: token, HTTPClient: client})
		if err != nil {
			t.Fatalf("HTTP-only join %d: %v", i, err)
		}
		nodes = append(nodes, node)
		defer node.Close()
	}
	listener, err := nodes[1].ListenTCP(8443)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(pool.marker) }), ReadHeaderTimeout: 5 * time.Second}
	defer server.Close()
	go server.Serve(listener)
	transport := &http.Transport{DialContext: nodes[0].DialContext}
	defer transport.CloseIdleConnections()
	application := &http.Client{Transport: transport, Timeout: 12 * time.Second}
	read := func() {
		t.Helper()
		response, err := application.Get("http://" + net.JoinHostPort(nodes[1].Record.VPNIP, "8443") + "/private")
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || !bytes.Equal(body, pool.marker) {
			t.Fatal("private application transfer failed")
		}
	}
	pool.dropped.Store(true)
	read()
	// New HTTP replicas have no session/key state in memory and immediately
	// participate in requests for the same established WireGuard/TCP flow.
	for i := 3; i < 5; i++ {
		backend := startFixture(t, database, issuer, at, operator, i)
		pool.mutex.Lock()
		pool.backends = append(pool.backends, backend)
		pool.mutex.Unlock()
	}
	for i := 0; i < 3; i++ {
		read()
	}
	pool.mutex.Lock()
	removed := append([]*fixtureBackend(nil), pool.backends[:3]...)
	pool.backends = append([]*fixtureBackend(nil), pool.backends[3:]...)
	pool.mutex.Unlock()
	for _, backend := range removed {
		backend.command.Process.Kill()
	}
	for i := 0; i < 3; i++ {
		read()
	}
	replacement := startFixture(t, database, issuer, at, operator, 5)
	pool.mutex.Lock()
	pool.backends = append(pool.backends, replacement)
	pool.mutex.Unlock()
	read()
	// UDP inside the VPN is carried over the same HTTP-only outer transport.
	udp, err := nodes[1].ListenUDP(5353)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buffer := make([]byte, 256)
		for {
			n, address, err := udp.ReadFrom(buffer)
			if err != nil {
				return
			}
			udp.WriteTo(buffer[:n], address)
		}
	}()
	connection, err := nodes[0].DialContext(ctx, "udp", net.JoinHostPort(nodes[1].Record.VPNIP, "5353"))
	if err != nil {
		t.Fatal(err)
	}
	connection.SetDeadline(time.Now().Add(8 * time.Second))
	connection.Write(pool.marker)
	reply := make([]byte, 256)
	count, err := connection.Read(reply)
	connection.Close()
	if err != nil || !bytes.Equal(reply[:count], pool.marker) {
		t.Fatalf("VPN UDP over HTTP failed: %v", err)
	}
	if pool.plaintext.Load() {
		t.Fatal("application plaintext reached an HTTP mesh worker")
	}
	if pool.fullPeerMap.Load() {
		t.Fatal("HTTP-only registration returned a full cluster peer map")
	}
	if pool.duplicate.Load() == 0 {
		t.Fatal("test did not exercise retry after a lost committed response")
	}
	pool.mutex.Lock()
	for _, node := range nodes {
		if len(pool.seen[node.Record.NodeID]) < 2 {
			t.Error("requests stayed pinned to one replica")
		}
	}
	pool.mutex.Unlock()
	request, _ := http.NewRequest(http.MethodGet, control.URL+"/v1/admin/transports?node_id="+nodes[1].Record.NodeID, nil)
	request.Header.Set("Authorization", "Bearer "+operator)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	var stats struct {
		Mesh []struct {
			ReceivedBytes uint64     `json:"received_bytes"`
			LastPoll      *time.Time `json:"last_poll_at"`
		} `json:"http_mesh"`
	}
	err = json.NewDecoder(response.Body).Decode(&stats)
	response.Body.Close()
	if err != nil || response.StatusCode != 200 || len(stats.Mesh) != 1 || stats.Mesh[0].ReceivedBytes == 0 || stats.Mesh[0].LastPoll == nil {
		t.Fatal("shared transport usage or liveness was missing")
	}
	t.Log("PASS: TUN-free real WireGuard TCP/UDP; HTTP replicas 3 -> 5 -> 2 -> 3; committed-response loss; cross-replica usage")
}

func TestHTTPMeshThousandMembersUseLazyDiscovery(t *testing.T) {
	if os.Getenv("HTTP_MESH_SCALE_TEST") != "1" {
		t.Skip("enable the 1000-member acceptance test explicitly")
	}
	database, issuer, at, operator := fixtureInputs(t)
	backend := startFixture(t, database, issuer, at, operator, 100)
	pool := &replicaPool{backends: []*fixtureBackend{backend}, seen: make(map[string]map[string]bool), marker: []byte("no-plaintext")}
	control := httptest.NewTLSServer(pool)
	defer control.Close()
	client := control.Client()
	client.Timeout = 30 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	jobs := make(chan int)
	failures := make(chan error, 1000)
	var completed atomic.Int32
	var workers sync.WaitGroup
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for range jobs {
				_, identity, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					failures <- err
					continue
				}
				api, err := newAPI(control.URL, "", identity, client, false)
				if err != nil {
					failures <- err
					continue
				}
				private := make([]byte, 32)
				rand.Read(private)
				public, _ := curve25519.X25519(private, curve25519.Basepoint)
				if _, err = api.join(ctx, backend.token, public, true); err != nil {
					failures <- err
					continue
				}
				acks := []ack{}
				wait := uint64(0)
				if _, err = api.meshRequest(ctx, action{Operation: "poll", Acknowledgements: &acks, WaitMS: &wait}); err != nil {
					failures <- err
					continue
				}
				completed.Add(1)
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if completed.Load() != 1000 || pool.fullPeerMap.Load() {
		t.Fatalf("1000-member lazy HTTP registration failed: %d", completed.Load())
	}
	t.Log("PASS: 1000 distinct authenticated members; no per-join full peer map or UDP reachability requirement")
}

func TestRestrictedEnvironment(t *testing.T) {
	if os.Getenv("HETERONETWORK_HTTP_MESH_RESTRICTED") != "1" {
		t.Skip("restricted acceptance runner only")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			capabilities, err := strconv.ParseUint(fields[1], 16, 64)
			if err != nil || capabilities != 0 {
				t.Fatal("acceptance process still has Linux capabilities")
			}
		}
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err == nil {
		socket.Close()
		t.Fatal("outer UDP was not blocked")
	}
	if os.Geteuid() == 0 {
		t.Fatal("acceptance process is still root")
	}
	t.Log("PASS: no root, no capabilities, OS UDP sockets denied")
}

func TestControlAndDataEndpointSecurity(t *testing.T) {
	_, identity, _ := ed25519.GenerateKey(rand.Reader)
	for _, endpoint := range []string{"http://public.example", "https://user:secret@public.example", "https://public.example?token=secret", "file:///tmp/key"} {
		if _, err := newAPI(endpoint, "", identity, nil, false); err == nil {
			t.Fatalf("accepted unsafe control endpoint: %s", endpoint)
		}
	}
	if _, err := newAPI("https://control.example", "http://data.example", identity, nil, false); err != nil {
		t.Fatal("encrypted data transport incorrectly requires TLS:", err)
	}
}

func TestHTTPMeshExpiredLeasesPreservePersistentStoppedAndRenewedNodes(t *testing.T) {
	database, issuer, at, _ := fixtureInputs(t)
	command := exec.Command(os.Getenv("HETERONETWORK_HTTP_MESH_FIXTURE"))
	command.Env = append(os.Environ(), "HTTP_MESH_FIXTURE_DATABASE="+database, "HTTP_MESH_FIXTURE_ISSUER="+issuer, "HTTP_MESH_FIXTURE_TIME="+at, "HTTP_MESH_FIXTURE_VERIFY_LEASES=1")
	output, err := command.Output()
	if err != nil || strings.TrimSpace(string(output)) != "lease_cleanup_ok" {
		t.Fatalf("lease cleanup acceptance failed: %v", err)
	}
}
