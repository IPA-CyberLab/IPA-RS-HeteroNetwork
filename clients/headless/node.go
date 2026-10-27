package headless

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type Config struct {
	KernelInterface     string
	IPCommand           string
	Endpoint            string
	MeshEndpoint        string
	JoinToken           json.RawMessage
	IdentitySeed        []byte
	WireGuardPrivateKey []byte
	HTTPClient          *http.Client
	Ephemeral           *bool
	// Local test fixtures only. Public enrollment always requires HTTPS.
	AllowInsecureLocal bool
}
type cachedPeer struct {
	ttl         time.Duration
	destination netip.Addr
	endpoint    meshEndpoint
	publicKey   string
	at          time.Time
}
type Node struct {
	kernel    *kernelState
	Record    NodeRecord
	network   *netstack.Net
	device    *device.Device
	bind      *meshBind
	api       *API
	ctx       context.Context
	cancel    context.CancelFunc
	peersMu   sync.Mutex
	lookupMu  sync.Mutex
	peers     map[string]cachedPeer
	close     sync.Once
	ephemeral bool
	errors    chan error
}
type Status struct {
	NodeID        string    `json:"node_id"`
	VPNIP         string    `json:"vpn_ip"`
	Transport     string    `json:"transport"`
	Ready         bool      `json:"ready"`
	Peers         int       `json:"active_peers"`
	SentBytes     uint64    `json:"sent_bytes"`
	ReceivedBytes uint64    `json:"received_bytes"`
	PendingBytes  int64     `json:"pending_bytes"`
	Failures      uint64    `json:"failures"`
	LastPoll      time.Time `json:"last_poll"`
}

func Start(ctx context.Context, config Config) (*Node, error) {
	if (len(config.IdentitySeed) == 0) != (len(config.WireGuardPrivateKey) == 0) {
		return nil, errors.New("persist the identity and WireGuard key together")
	}
	seed := append([]byte(nil), config.IdentitySeed...)
	private := append([]byte(nil), config.WireGuardPrivateKey...)
	if len(seed) == 0 {
		seed = make([]byte, 32)
		private = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if _, err := rand.Read(private); err != nil {
			return nil, err
		}
	}
	if len(seed) != 32 || len(private) != 32 {
		return nil, errors.New("node keys must contain 32 bytes")
	}
	identity := ed25519.NewKeyFromSeed(seed)
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return nil, errors.New("invalid WireGuard key")
	}
	if config.AllowInsecureLocal {
		// Never provide a flag that sends a real join token over public HTTP.
		parsed, parseErr := neturlHost(config.Endpoint)
		if parseErr != nil || !parsed.IsLoopback() {
			return nil, errors.New("insecure enrollment is limited to loopback test fixtures")
		}
	}
	api, err := newAPI(config.Endpoint, config.MeshEndpoint, identity, config.HTTPClient, config.AllowInsecureLocal)
	if err != nil {
		return nil, err
	}
	ephemeral := len(config.IdentitySeed) == 0
	if config.Ephemeral != nil {
		ephemeral = *config.Ephemeral
	}
	record, err := api.join(ctx, config.JoinToken, public, ephemeral)
	if err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(record.VPNIP)
	if err != nil {
		return nil, errors.New("join returned an invalid VPN address")
	}
	var local tun.Device
	var network *netstack.Net
	var kernel *kernelState
	if config.KernelInterface == "" {
		local, network, err = netstack.CreateNetTUN([]netip.Addr{address}, nil, 1280)
	} else {
		local, kernel, err = prepareKernel(config, address)
	}
	if err != nil {
		return nil, err
	}
	child, cancel := context.WithCancel(ctx)
	node := &Node{kernel: kernel, Record: record, network: network, api: api, ctx: child, cancel: cancel, peers: make(map[string]cachedPeer), ephemeral: ephemeral, errors: make(chan error, 1)}
	bind := &meshBind{api: api, base: child, ensurePeer: node.ensurePeer, fatal: node.errors}
	node.bind = bind
	local = filterKernelTraffic(local, node)
	wireguard := device.NewDevice(local, bind, device.NewLogger(device.LogLevelSilent, ""))
	node.device = wireguard
	if err = wireguard.IpcSet("private_key=" + hex.EncodeToString(private) + "\n"); err != nil {
		node.Close()
		return nil, errors.New("WireGuard initialization failed")
	}
	if err = wireguard.Up(); err != nil {
		node.Close()
		return nil, errors.New("WireGuard could not start HTTP transport")
	}
	if kernel != nil {
		go kernel.routes(node)
	}

	return node, nil
}

func (node *Node) ensurePeer(ctx context.Context, address string) (meshEndpoint, error) {
	cachedPeerFor := func() (cachedPeer, bool) {
		node.peersMu.Lock()
		defer node.peersMu.Unlock()
		cached, ok := node.peers[address]
		return cached, ok && time.Since(cached.at) < cached.ttl
	}
	if cached, ok := cachedPeerFor(); ok {
		return cached.endpoint, nil
	}
	node.lookupMu.Lock()
	defer node.lookupMu.Unlock()
	if cached, ok := cachedPeerFor(); ok {
		return cached.endpoint, nil
	}
	node.peersMu.Lock()
	full := len(node.peers) >= 4096
	node.peersMu.Unlock()
	if full {
		return meshEndpoint{}, errors.New("active HTTP mesh peer cache full")
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	record, err := node.api.peer(call, address)
	if err != nil {
		return meshEndpoint{}, err
	}
	return node.configurePeer(record, address)
}

// Caller holds lookupMu. Records come from authenticated HTTPS discovery.
func (node *Node) configurePeer(record NodeRecord, address string) (meshEndpoint, error) {
	ip, err := netip.ParseAddr(record.VPNIP)
	if err != nil {
		return meshEndpoint{}, errors.New("invalid peer VPN address")
	}
	destination := record.Destination
	if destination == "" {
		destination = record.VPNIP
	}
	destinationID := record.DestinationNode
	if destinationID == "" {
		destinationID = record.NodeID
	}
	resolved, err := netip.ParseAddr(destination)
	if err != nil {
		return meshEndpoint{}, errors.New("invalid peer destination")
	}
	if address != destinationID && address != destination && address != record.NodeID && address != record.VPNIP {
		return meshEndpoint{}, errors.New("peer discovery returned a different address")
	}
	public, err := base64.StdEncoding.DecodeString(record.WireGuardPublicKey)
	if err != nil || len(public) != 32 {
		return meshEndpoint{}, errors.New("invalid peer WireGuard key")
	}
	endpoint := meshEndpoint{record.NodeID, ip}
	key := hex.EncodeToString(public)
	node.peersMu.Lock()
	previous, exists := node.peers[record.NodeID]
	node.peersMu.Unlock()
	if exists && previous.publicKey != key {
		if err = node.device.IpcSet("public_key=" + previous.publicKey + "\nremove=true\n"); err != nil {
			return meshEndpoint{}, errors.New("old peer key could not be removed")
		}
	}
	prefixes := record.AllowedIPs
	if len(prefixes) == 0 {
		bits := 32
		if ip.Is6() {
			bits = 128
		}
		prefixes = []string{netip.PrefixFrom(ip, bits).String()}
	}
	configuration := fmt.Sprintf("public_key=%s\nreplace_allowed_ips=true\n", key)
	for _, value := range prefixes {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Bits() != prefix.Addr().BitLen() {
			return meshEndpoint{}, errors.New("invalid peer source prefix")
		}
		configuration += "allowed_ip=" + prefix.String() + "\n"
	}
	configuration += "endpoint=" + endpoint.DstToString() + "\n"
	if err = node.device.IpcSet(configuration); err != nil {
		return meshEndpoint{}, errors.New("WireGuard peer configuration rejected")
	}
	node.peersMu.Lock()
	ttl := 30 * time.Second
	if len(record.Candidates) > 0 {
		ttl = time.Second
	}
	cached := cachedPeer{destination: ip, endpoint: endpoint, publicKey: key, at: time.Now(), ttl: ttl}
	node.peers[record.NodeID] = cached
	node.peers[record.VPNIP] = cached
	cached.destination = resolved
	node.peers[address] = cached
	node.peersMu.Unlock()
	return endpoint, nil
}

func (node *Node) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if node.kernel != nil {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid peer port")
	}
	peer, err := node.ensurePeer(ctx, host)
	if err != nil {
		return nil, err
	}
	node.peersMu.Lock()
	destination := node.peers[host].destination
	node.peersMu.Unlock()
	if !destination.IsValid() {
		destination = peer.ip
	}
	if network == "tcp" {
		return node.network.DialContextTCPAddrPort(ctx, netip.AddrPortFrom(destination, uint16(port)))
	}
	if network == "udp" {
		return node.network.DialUDPAddrPort(netip.AddrPort{}, netip.AddrPortFrom(destination, uint16(port)))
	}
	return nil, errors.New("unsupported stream network")
}
func (node *Node) ListenTCP(port uint16) (net.Listener, error) {
	if node.kernel != nil {
		return net.Listen("tcp", net.JoinHostPort(node.Record.VPNIP, strconv.Itoa(int(port))))
	}
	if port == 0 {
		return nil, errors.New("a VPN service port is required")
	}
	ip, err := netip.ParseAddr(node.Record.VPNIP)
	if err != nil {
		return nil, err
	}
	return node.network.ListenTCPAddrPort(netip.AddrPortFrom(ip, port))
}
func (node *Node) ListenUDP(port uint16) (net.PacketConn, error) {
	if node.kernel != nil {
		return net.ListenPacket("udp", net.JoinHostPort(node.Record.VPNIP, strconv.Itoa(int(port))))
	}
	if port == 0 {
		return nil, errors.New("a VPN service port is required")
	}
	ip, err := netip.ParseAddr(node.Record.VPNIP)
	if err != nil {
		return nil, err
	}
	return node.network.ListenUDPAddrPort(netip.AddrPortFrom(ip, port))
}
func (node *Node) Status() Status {
	node.peersMu.Lock()
	unique := make(map[string]struct{})
	for _, peer := range node.peers {
		unique[peer.endpoint.node] = struct{}{}
	}
	peers := len(unique)
	node.peersMu.Unlock()
	last := time.Unix(0, node.bind.lastPoll.Load())
	ready := node.bind.lastPoll.Load() != 0 && time.Since(last) < 45*time.Second
	if node.kernel != nil {
		ready = ready && node.kernel.ready.Load()
	}
	return Status{node.Record.NodeID, node.Record.VPNIP, "http-mesh", ready, peers, node.bind.sent.Load(), node.bind.receivedBytes.Load(), node.bind.pending.Load(), node.bind.failures.Load(), last}
}
func (node *Node) Errors() <-chan error { return node.errors }
func (node *Node) Close() {
	node.close.Do(func() {
		node.cancel()
		if node.kernel != nil {
			node.kernel.cleanup()
		}
		node.device.Close()
		if node.ephemeral {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			node.api.meshRequest(ctx, action{Operation: "leave"})
		}
	})
}
