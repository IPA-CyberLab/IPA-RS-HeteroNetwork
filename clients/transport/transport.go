package transport

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
)

const transportMaximumPacket = 65507
const transportMaximumBatch = 256 * 1024

type Configuration struct {
	GatewayTransportURLs      []string `json:"gateway_transport_urls,omitempty"`
	publicIngress             bool
	GatewayTCPTunnelEndpoints []string `json:"gateway_tcp_tunnel_endpoints,omitempty"`
	ClientNodeID              string   `json:"client_node_id"`
	GatewayNodeID             string   `json:"gateway_node_id"`
	PrivateKey                string   `json:"private_key"`
	GatewayWireGuardPublicKey string   `json:"gateway_wireguard_public_key"`
	GatewayEndpoint           string   `json:"gateway_endpoint"`
	GatewayHTTPTunnelURLs     []string `json:"gateway_http_tunnel_urls"`
	ProxyURL                  string   `json:"proxy_url,omitempty"`
}

type Status struct {
	ResolvedEndpoint string            `json:"resolved_endpoint,omitempty"`
	Failures         map[string]uint64 `json:"failures"`
	Transport        string            `json:"transport"`
	Phase            string            `json:"phase"`
	Endpoint         string            `json:"endpoint"`
	FallbackReason   string            `json:"fallback_reason,omitempty"`
	LastError        string            `json:"last_error,omitempty"`
	TXBytes          uint64            `json:"tx_bytes"`
	RXBytes          uint64            `json:"rx_bytes"`
	Switches         uint64            `json:"switches"`
	Reconnects       uint64            `json:"reconnects"`
}

type Proxy struct {
	endpointNetwork endpointNetwork
	udpLabel        string
	local, network  *net.UDPConn
	remote          *net.UDPAddr
	configuration   Configuration
	authKey         []byte
	client          *http.Client
	cancel          context.CancelFunc
	done            chan struct{}
	mu              sync.Mutex
	status          Status
	lastUDP         time.Time
	lastSender      *net.UDPAddr
}

func ValidateURLs(values []string) error {
	if len(values) > 8 {
		return errors.New("too many HTTP tunnel URLs")
	}
	for _, value := range values {
		parsed, err := url.Parse(value)
		if err != nil || len(value) > 2048 || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
			(parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Path != "/v1/tunnels/wireguard/open" {
			return errors.New("invalid HTTP tunnel URL")
		}
		ip, err := netip.ParseAddr(parsed.Hostname())
		if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("HTTP tunnel requires a public literal IP address")
		}
		if port := parsed.Port(); port != "" {
			n, err := strconv.Atoi(port)
			if err != nil || n < 1 || n > 65535 {
				return errors.New("invalid HTTP tunnel port")
			}
		}
	}
	return nil
}

func transportAuthenticationKey(privateText, publicText string) ([]byte, error) {
	private, err := hex.DecodeString(privateText)
	if err != nil {
		return nil, err
	}
	public, err := hex.DecodeString(publicText)
	if err != nil {
		return nil, err
	}
	shared, err := curve25519.X25519(private, public)
	if err != nil {
		return nil, err
	}
	kdf := hmac.New(sha256.New, []byte("heteronetwork-tunnel-auth-v1"))
	kdf.Write(shared)
	return kdf.Sum(nil), nil
}

func transportProof(key []byte, node, gateway string, timestamp int64, nonce string, first []byte) string {
	digest := sha256.Sum256(first)
	message := fmt.Sprintf("heteronetwork-http-tunnel-v1\n%s\n%s\n%d\n%s\n%x\n", node, gateway, timestamp, nonce, digest)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func Start(configuration Configuration) (*Proxy, error) {
	if len(configuration.GatewayHTTPTunnelURLs) == 0 && len(configuration.GatewayTCPTunnelEndpoints) == 0 && len(configuration.GatewayTransportURLs) == 0 {
		return nil, nil
	}
	if err := ValidateURLs(configuration.GatewayHTTPTunnelURLs); err != nil {
		return nil, err
	}
	if err := ValidateTCPEndpoints(configuration.GatewayTCPTunnelEndpoints); err != nil {
		return nil, err
	}
	if err := ValidateTransportURLs(configuration.GatewayTransportURLs); err != nil {
		return nil, err
	}
	for _, node := range []string{configuration.ClientNodeID, configuration.GatewayNodeID} {
		if len(node) == 0 || len(node) > 128 || strings.ContainsAny(node, "\r\n\x00") {
			return nil, errors.New("invalid transport node ID")
		}
	}
	host, portText, err := net.SplitHostPort(configuration.GatewayEndpoint)
	ip, ipErr := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || ipErr != nil || portErr != nil || port < 1 || port > 65535 || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		return nil, errors.New("invalid public UDP gateway endpoint")
	}

	configuration.publicIngress = true
	return start(configuration, nil)
}

// Exported Start always validates the public ingress catalog first.
func start(configuration Configuration, suppliedClient *http.Client) (*Proxy, error) {
	return startWithNetwork(configuration, suppliedClient, endpointNetwork{})
}

func startWithNetwork(configuration Configuration, suppliedClient *http.Client, endpoints endpointNetwork) (*Proxy, error) {
	if endpoints.resolver == nil {
		endpoints.resolver = net.DefaultResolver
	}
	if endpoints.dial == nil {
		endpoints.dial = (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	var namedHTTP, namedTCP []string
	namedUDP := false
	for _, value := range configuration.GatewayTransportURLs {
		parsed, err := normalizeTransportURL(value)
		if err != nil {
			return nil, err
		}
		switch parsed.Scheme {
		case "http", "https":
			namedHTTP = append(namedHTTP, parsed.String())
		case "tcp":
			namedTCP = append(namedTCP, parsed.Host)
		case "udp":
			namedUDP = true
		}
	}
	configuration.GatewayHTTPTunnelURLs = append(namedHTTP, configuration.GatewayHTTPTunnelURLs...)
	configuration.GatewayTCPTunnelEndpoints = append(namedTCP, configuration.GatewayTCPTunnelEndpoints...)
	// Preserve protocol preference while preferring names within a protocol.
	sort.SliceStable(configuration.GatewayHTTPTunnelURLs, func(i, j int) bool {
		return strings.HasPrefix(configuration.GatewayHTTPTunnelURLs[i], "https:") && !strings.HasPrefix(configuration.GatewayHTTPTunnelURLs[j], "https:")
	})
	key, err := transportAuthenticationKey(configuration.PrivateKey, configuration.GatewayWireGuardPublicKey)
	if err != nil {
		return nil, errors.New("invalid HTTP tunnel key material")
	}
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", configuration.GatewayEndpoint)
	if err != nil {
		local.Close()
		return nil, err
	}
	family := "udp4"
	if remote.IP.To4() == nil {
		family = "udp6"
	}
	if namedUDP {
		family = "udp"
	}
	network, err := net.ListenUDP(family, nil)
	if err != nil && family == "udp6" {
		network, err = net.ListenUDP("udp4", nil)
	}
	if err != nil {
		local.Close()
		return nil, err
	}
	httpTransport := http.DefaultTransport.(*http.Transport).Clone()
	httpTransport.MaxConnsPerHost = 4
	httpTransport.TLSHandshakeTimeout = 3 * time.Second
	var proxy *Proxy
	httpTransport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if !configuration.publicIngress || proxy.proxyAddress(address) {
			return endpoints.dial(ctx, network, address)
		}
		return proxy.dialEndpoint(ctx, network, address)
	}
	if configuration.ProxyURL != "" {
		proxyURL, parseErr := url.Parse(configuration.ProxyURL)
		if parseErr != nil || proxyURL.Host == "" || (proxyURL.Scheme != "http" && proxyURL.Scheme != "https") {
			local.Close()
			network.Close()
			return nil, errors.New("invalid HTTP proxy URL")
		}
		httpTransport.Proxy = http.ProxyURL(proxyURL)
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxy = &Proxy{local: local, network: network, remote: remote, configuration: configuration, authKey: key, endpointNetwork: endpoints, udpLabel: configuration.GatewayEndpoint,
		client: &http.Client{Transport: httpTransport, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		cancel: cancel, done: make(chan struct{}), status: Status{Transport: "udp", Phase: "probing", Endpoint: configuration.GatewayEndpoint, Failures: make(map[string]uint64)},
		lastUDP: time.Now(),
	}
	if suppliedClient != nil {
		proxy.client = suppliedClient
	}
	if namedUDP {
		proxy.refreshUDP(ctx)
		go func() {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					proxy.refreshUDP(ctx)
				}
			}
		}()
	}
	go proxy.run(ctx)
	return proxy, nil
}

func (p *Proxy) Endpoint() string { return p.local.LocalAddr().String() }
func (p *Proxy) Snapshot() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	status := p.status
	status.Failures = make(map[string]uint64, len(p.status.Failures))
	for key, count := range p.status.Failures {
		status.Failures[key] = count
	}
	return status
}
func (p *Proxy) Close() {
	p.cancel()
	p.local.Close()
	p.network.Close()
	<-p.done
	p.client.CloseIdleConnections()
}

func validTransportWireGuard(packet []byte) bool {
	if len(packet) < 4 || packet[1] != 0 || packet[2] != 0 || packet[3] != 0 {
		return false
	}
	switch packet[0] {
	case 1:
		return len(packet) == 148
	case 2:
		return len(packet) == 92
	case 3:
		return len(packet) == 64
	case 4:
		return len(packet) >= 32 && len(packet) <= transportMaximumPacket
	}
	return false
}

type transportOpen struct {
	Token       string `json:"token"`
	FirstPacket []byte `json:"-"`
}

func (p *Proxy) open(ctx context.Context, endpoint string, first []byte) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	body, err := p.openingBody(first)
	if err != nil {
		return "", err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	if p.configuration.publicIngress {
		address := request.URL.Host
		if request.URL.Port() == "" {
			port := "80"
			if request.URL.Scheme == "https" {
				port = "443"
			}
			address = net.JoinHostPort(request.URL.Hostname(), port)
		}
		if _, err := p.resolveEndpoint(ctx, address); err != nil {
			p.recordDNSError(err)
			return "", err
		}
	}
	var connected atomic.Value
	connected.Store("")
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { connected.Store(info.Conn.RemoteAddr().String()) }}))
	nonceBytes := make([]byte, 16)
	if _, err = rand.Read(nonceBytes); err != nil {
		return "", err
	}
	nonce := hex.EncodeToString(nonceBytes)
	timestamp := time.Now().Unix()
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-HeteroNetwork-Node", p.configuration.ClientNodeID)
	request.Header.Set("X-HeteroNetwork-Time", strconv.FormatInt(timestamp, 10))
	request.Header.Set("X-HeteroNetwork-Nonce", nonce)
	request.Header.Set("X-HeteroNetwork-Proof", transportProof(p.authKey, p.configuration.ClientNodeID, p.configuration.GatewayNodeID, timestamp, nonce, body))
	response, err := p.client.Do(request)
	if err != nil {
		return "", errors.New("HTTP tunnel open failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return "", errors.New("HTTP tunnel open rejected")
	}
	var opened transportOpen
	if err = json.NewDecoder(io.LimitReader(response.Body, transportMaximumBatch)).Decode(&opened); err != nil {
		return "", err
	}
	if len(opened.Token) != 64 {
		return "", errors.New("invalid HTTP tunnel token")
	}
	if _, err = hex.DecodeString(opened.Token); err != nil {
		return "", errors.New("invalid HTTP tunnel token")
	}
	p.mu.Lock()
	p.status.ResolvedEndpoint = connected.Load().(string)
	p.mu.Unlock()
	return opened.Token, nil
}

func (p *Proxy) request(ctx context.Context, method, endpoint, token string, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "HeteroNetworkTunnel "+token)
	request.Header.Set("Content-Type", "application/octet-stream")
	response, err := p.client.Do(request)
	if err != nil {
		return nil, errors.New("HTTP tunnel request failed")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("HTTP tunnel unavailable")
	}
	result, err := io.ReadAll(io.LimitReader(response.Body, transportMaximumBatch+1))
	if len(result) > transportMaximumBatch {
		return nil, errors.New("HTTP tunnel batch too large")
	}
	return result, err
}

func (p *Proxy) deliver(packet []byte) {
	if !validTransportWireGuard(packet) {
		return
	}
	p.mu.Lock()
	sender := p.lastSender
	p.status.RXBytes += uint64(len(packet))
	p.mu.Unlock()
	if sender != nil {
		_, _ = p.local.WriteToUDP(packet, sender)
	}
}

func (p *Proxy) run(ctx context.Context) {
	defer close(p.done)
	packets := make(chan []byte, 64)
	udpReplies := make(chan []byte, 64)
	go func() {
		buffer := make([]byte, transportMaximumPacket)
		for {
			n, sender, err := p.local.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			if !sender.IP.IsLoopback() || !validTransportWireGuard(buffer[:n]) {
				continue
			}
			p.mu.Lock()
			if p.lastSender == nil {
				p.lastSender = sender
			}
			allowed := p.lastSender.String() == sender.String()
			p.mu.Unlock()
			if allowed {
				select {
				case packets <- append([]byte(nil), buffer[:n]...):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() {
		buffer := make([]byte, transportMaximumPacket)
		for {
			n, source, err := p.network.ReadFromUDP(buffer)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				time.Sleep(250 * time.Millisecond)
				continue
			}
			p.mu.Lock()
			remote := p.remote
			p.mu.Unlock()
			if source.Port != remote.Port || !source.IP.Equal(remote.IP) {
				continue
			}
			if validTransportWireGuard(buffer[:n]) {
				select {
				case udpReplies <- append([]byte(nil), buffer[:n]...):
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	var pending [][]byte
	var first []byte
	var udpProbePending []byte
	var udpProbeDeadline time.Time
	var outgoing chan []byte
	var stopHTTP context.CancelFunc
	defer func() {
		if stopHTTP != nil {
			stopHTTP()
		}
	}()
	failures := make(chan uint64, 1)
	generation := uint64(0)
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	deadline := time.Now().Add(3 * time.Second)
	retryAt := time.Now()
	backoff := time.Second
	nextUDP := time.Now()
	returnUDPAfter := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case packet := <-packets:
			p.mu.Lock()
			p.status.TXBytes += uint64(len(packet))
			lastUDP := p.lastUDP
			p.mu.Unlock()
			if outgoing != nil {
				probing := len(packet) > 32 && time.Now().After(nextUDP)
				if probing {
					p.sendUDP(packet)
					nextUDP = time.Now().Add(time.Minute)
					udpProbePending = packet
					udpProbeDeadline = time.Now().Add(2 * time.Second)
				} else {
					select {
					case outgoing <- packet:
					default:
						p.mu.Lock()
						p.status.LastError = "send_queue_full"
						p.mu.Unlock()
					}
				}
			} else {
				p.sendUDP(packet)
				if (len(packet) > 32 && time.Since(lastUDP) > 20*time.Second) || p.Snapshot().Phase != "connected" {
					if first == nil && len(packet) > 32 {
						first = append([]byte(nil), packet...)
						delay := 3 * time.Second
						if packet[0] != 1 {
							delay = 12 * time.Second
						}
						deadline = time.Now().Add(delay)
					}
					if len(pending) < 64 {
						pending = append(pending, packet)
					}
				}
			}
		case packet := <-udpReplies:
			if outgoing != nil && time.Now().Before(returnUDPAfter) {
				p.deliver(packet)
				continue
			}
			generation++
			if stopHTTP != nil {
				stopHTTP()
				stopHTTP = nil
			}
			outgoing = nil
			udpProbePending = nil
			first = nil
			pending = nil
			p.mu.Lock()
			if p.status.Transport != "udp" {
				p.status.Switches++
			}
			p.status.Transport = "udp"
			p.status.Phase = "connected"
			p.status.Endpoint = p.udpLabel
			p.status.ResolvedEndpoint = p.remote.String()
			p.status.LastError = ""
			p.lastUDP = time.Now()
			p.mu.Unlock()
			p.deliver(packet)
		case failedGeneration := <-failures:
			if failedGeneration != generation {
				continue
			}
			if stopHTTP != nil {
				stopHTTP()
				stopHTTP = nil
			}
			outgoing = nil
			p.mu.Lock()
			p.status.Phase = "reconnecting"
			if p.status.Transport == "tcp" {
				p.status.LastError = "tcp_tunnel_unavailable"
			} else {
				p.status.LastError = "http_tunnel_unavailable"
			}
			p.status.Reconnects++
			p.mu.Unlock()
			retryAt = time.Now().Add(backoff)
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		case <-tick.C:
			if udpProbePending != nil && time.Now().After(udpProbeDeadline) {
				if outgoing != nil {
					select {
					case outgoing <- udpProbePending:
					default:
					}
				}
				udpProbePending = nil
			}
			if first == nil || outgoing != nil || time.Now().Before(deadline) || time.Now().Before(retryAt) {
				continue
			}
			generation++
			httpGeneration := generation
			nextUDP = time.Now().Add(time.Minute)
			returnUDPAfter = time.Now().Add(30 * time.Second)
			httpCtx, cancel := context.WithCancel(ctx)
			stopHTTP = cancel
			outgoing = make(chan []byte, 64)
			initial := append([]byte(nil), first...)
			queue := pending
			pending = nil
			sender := outgoing
			p.mu.Lock()
			p.status.Phase = "reconnecting"
			p.status.FallbackReason = "udp_probe_timeout"
			p.status.Failures["udp_probe_timeout"]++
			p.mu.Unlock()
			go func() {
				var stream *tcpSession
				var token, endpoint string
				for _, candidate := range p.configuration.GatewayTCPTunnelEndpoints {
					opened, err := p.openTCP(httpCtx, candidate, initial)
					if err == nil {
						stream = opened
						endpoint = "tcp://" + candidate
						break
					}
					p.mu.Lock()
					p.status.Failures["tcp_unavailable"]++
					p.mu.Unlock()
				}
				httpCandidates := p.configuration.GatewayHTTPTunnelURLs
				if stream != nil {
					httpCandidates = nil
				}
				for _, candidate := range httpCandidates {
					if opened, err := p.open(httpCtx, candidate, initial); err == nil {
						token = opened
						endpoint = candidate
						break
					} else {
						protocol := "http"
						if strings.HasPrefix(candidate, "https:") {
							protocol = "https"
						}
						p.mu.Lock()
						p.status.Failures[protocol+"_unavailable"]++
						p.mu.Unlock()
					}
				}
				if token == "" && stream == nil {
					if httpCtx.Err() == nil {
						select {
						case failures <- httpGeneration:
						default:
						}
					}
					return
				}
				if stream != nil {
					defer stream.close()
					done := make(chan struct{})
					defer close(done)
					go func() {
						select {
						case <-httpCtx.Done():
							stream.close()
						case <-done:
						}
					}()
				}
				if httpCtx.Err() != nil {
					return
				}

				packetsURL := strings.TrimSuffix(endpoint, "/open") + "/packets"
				p.mu.Lock()
				mode := "http"
				if strings.HasPrefix(endpoint, "tcp:") {
					mode = "tcp"
				} else if strings.HasPrefix(endpoint, "https:") {
					mode = "https"
				}
				if p.status.Transport != mode {
					p.status.Switches++
				}
				p.status.Transport = mode
				p.status.Endpoint = endpoint
				p.status.Phase = "connected"
				p.status.LastError = ""
				p.mu.Unlock()
				receiveCtx, receiveCancel := context.WithCancel(httpCtx)
				defer receiveCancel()
				go func() {
					defer func() {
						if receiveCtx.Err() == nil {
							select {
							case failures <- httpGeneration:
							default:
							}
						}
					}()
					for {
						var body []byte
						var err error
						if stream != nil {
							body, err = stream.receive()
						} else {
							body, err = p.request(receiveCtx, http.MethodGet, packetsURL, token, nil)
						}
						if err != nil {
							if receiveCtx.Err() == nil {
								select {
								case failures <- httpGeneration:
								default:
								}
							}
							return
						}
						count := 0
						for len(body) > 0 {
							if len(body) < 2 || count >= 64 {
								return
							}
							n := int(binary.BigEndian.Uint16(body))
							body = body[2:]
							if n == 0 || n > transportMaximumPacket || len(body) < n {
								return
							}
							p.deliver(body[:n])
							body = body[n:]
							count++
						}
					}
				}()
				for _, packet := range queue {
					select {
					case sender <- packet:
					default:
					}
				}
				for {
					select {
					case <-httpCtx.Done():
						return
					case packet := <-sender:
						body := make([]byte, 2, len(packet)+2)
						binary.BigEndian.PutUint16(body, uint16(len(packet)))
						body = append(body, packet...)
						var err error
						if stream != nil {
							err = stream.send(body)
						} else {
							_, err = p.request(httpCtx, http.MethodPost, packetsURL, token, body)
						}
						if err != nil {
							if httpCtx.Err() == nil {
								select {
								case failures <- httpGeneration:
								default:
								}
							}
							return
						}
					}
				}
			}()
		}
	}
}
