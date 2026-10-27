package transport

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

var errDNSUnavailable = errors.New("transport DNS resolution failed")
var errDNSNonpublic = errors.New("transport DNS returned no public addresses")

func publicAddress(address netip.Addr) bool {
	address = address.Unmap()
	if address.Is6() && (!netip.MustParsePrefix("2000::/3").Contains(address) || netip.MustParsePrefix("2001::/23").Contains(address) || netip.MustParsePrefix("2002::/16").Contains(address) || netip.MustParsePrefix("3fff::/20").Contains(address)) {
		return false
	}
	if !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
		return false
	}
	for _, block := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "100::/64", "2001:db8::/32", "2001:10::/28", "2001:20::/28", "64:ff9b:1::/48"} {
		if netip.MustParsePrefix(block).Contains(address) {
			return false
		}
	}
	return true
}

func validDNSHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if len(host) > 253 || !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func normalizeTransportURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00?#") || parsed.User != nil || parsed.Opaque != "" || parsed.RawPath != "" {
		return nil, errors.New("invalid public transport URL")
	}
	host := strings.TrimSuffix(parsed.Hostname(), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		if !publicAddress(ip) {
			return nil, errDNSNonpublic
		}
	} else if !validDNSHost(host) {
		return nil, errors.New("invalid public transport hostname")
	}
	port := parsed.Port()
	switch parsed.Scheme {
	case "http", "https":
		if parsed.Path != "" && parsed.Path != "/" && parsed.Path != "/v1/tunnels/wireguard/open" {
			return nil, errors.New("invalid public HTTP transport path")
		}
		parsed.Path = "/v1/tunnels/wireguard/open"
	case "tcp", "udp":
		if port == "" || (parsed.Path != "" && parsed.Path != "/") {
			return nil, errors.New("TCP/UDP transport URL requires a port and no path")
		}
		parsed.Path = ""
	default:
		return nil, errors.New("unsupported public transport URL scheme")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, errors.New("invalid public transport port")
		}
	}
	if port != "" {
		parsed.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		parsed.Host = "[" + host + "]"
	} else {
		parsed.Host = host
	}
	return parsed, nil
}

func ValidateTransportURLs(values []string) error {
	if len(values) > 8 {
		return errors.New("too many public transport URLs")
	}
	for _, value := range values {
		if _, err := normalizeTransportURL(value); err != nil {
			return err
		}
	}
	return nil
}

type endpointNetwork struct {
	resolver *net.Resolver
	dial     func(context.Context, string, string) (net.Conn, error)
}

func (p *Proxy) resolveEndpoint(ctx context.Context, address string) ([]netip.AddrPort, error) {
	host, portText, err := net.SplitHostPort(address)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid transport endpoint")
	}
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		ips = []netip.Addr{ip}
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		ips, err = p.endpointNetwork.resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errDNSUnavailable
		}
	}
	var result []netip.AddrPort
	for _, ip := range ips {
		if p.configuration.publicIngress && !publicAddress(ip) {
			continue
		}
		candidate := netip.AddrPortFrom(ip.Unmap(), uint16(port))
		duplicate := false
		for _, previous := range result {
			if candidate == previous {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result = append(result, candidate)
		}
		if len(result) == 32 {
			break
		}
	}
	if len(result) == 0 {
		return nil, errDNSNonpublic
	}
	var v4, v6 []netip.AddrPort
	for _, address := range result {
		if address.Addr().Is4() {
			v4 = append(v4, address)
		} else {
			v6 = append(v6, address)
		}
	}
	first, second := v6, v4
	if result[0].Addr().Is4() {
		first, second = v4, v6
	}
	result = nil
	for i := 0; len(result) < 8 && (i < len(first) || i < len(second)); i++ {
		if i < len(first) {
			result = append(result, first[i])
		}
		if i < len(second) && len(result) < 8 {
			result = append(result, second[i])
		}
	}
	return result, nil
}

func (p *Proxy) dialEndpoint(ctx context.Context, network, address string) (net.Conn, error) {
	addresses, err := p.resolveEndpoint(ctx, address)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	type answer struct {
		connection net.Conn
		err        error
	}
	completed := make(chan answer)
	for index, resolved := range addresses {
		go func(index int, address netip.AddrPort) {
			timer := time.NewTimer(time.Duration(index) * 250 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
			connection, dialErr := p.endpointNetwork.dial(ctx, network, address.String())
			select {
			case completed <- answer{connection, dialErr}:
			case <-ctx.Done():
				if connection != nil {
					connection.Close()
				}
			}
		}(index, resolved)
	}
	for range addresses {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case answer := <-completed:
			if answer.err == nil {
				return answer.connection, nil
			}
			err = answer.err
		}
	}
	return nil, err
}

func (p *Proxy) proxyAddress(address string) bool {
	values := []string{p.configuration.ProxyURL}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		values = append(values, os.Getenv(name))
	}
	for _, value := range values {
		proxy, err := url.Parse(value)
		if err != nil || proxy.Host == "" {
			continue
		}
		port := proxy.Port()
		if port == "" {
			if proxy.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		if net.JoinHostPort(proxy.Hostname(), port) == address {
			return true
		}
	}
	return false
}

func (p *Proxy) recordDNSError(err error) {
	reason := ""
	if errors.Is(err, errDNSUnavailable) {
		reason = "dns_unavailable"
	}
	if errors.Is(err, errDNSNonpublic) {
		reason = "dns_nonpublic"
	}
	if reason != "" {
		p.mu.Lock()
		p.status.Failures[reason]++
		p.mu.Unlock()
	}
}

func (p *Proxy) refreshUDP(ctx context.Context) {
	for _, value := range p.configuration.GatewayTransportURLs {
		parsed, err := normalizeTransportURL(value)
		if err != nil || parsed.Scheme != "udp" {
			continue
		}
		addresses, err := p.resolveEndpoint(ctx, parsed.Host)
		if err != nil {
			p.recordDNSError(err)
			continue
		}
		p.mu.Lock()
		selected := addresses[0]
		for _, address := range addresses {
			if address.Addr().Is4() == (p.remote.IP.To4() != nil) {
				selected = address
				break
			}
		}
		p.remote = net.UDPAddrFromAddrPort(selected)
		p.udpLabel = parsed.String()
		if p.status.Transport == "udp" {
			p.status.Endpoint = parsed.String()
			p.status.ResolvedEndpoint = selected.String()
		}
		p.mu.Unlock()
		return
	}
}

func (p *Proxy) sendUDP(packet []byte) {
	p.mu.Lock()
	remote := p.remote
	p.mu.Unlock()
	_, _ = p.network.WriteToUDP(packet, remote)
}
