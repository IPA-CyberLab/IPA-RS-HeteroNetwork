package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	configurationSchemaVersion = 1
	helperProtocolVersion      = "1"
	maximumConfigurationBytes  = 64 * 1024
	overlayDNSDomain           = "heteronetwork.internal"
	requiredMTU                = 1280
)

type tunnelConfiguration struct {
	SchemaVersion             int      `json:"schema_version"`
	OwnerUID                  int      `json:"owner_uid"`
	PrivateKey                string   `json:"private_key"`
	ClientAddress             string   `json:"client_address"`
	GatewayNodeID             string   `json:"gateway_node_id"`
	GatewayVPNIP              string   `json:"gateway_vpn_ip"`
	GatewayWireGuardPublicKey string   `json:"gateway_wireguard_public_key"`
	GatewayEndpoint           string   `json:"gateway_endpoint"`
	AllowedIPs                []string `json:"allowed_ips"`
	DNSServer                 string   `json:"dns_server"`
	DNSDomain                 string   `json:"dns_domain"`
	MTU                       int      `json:"mtu"`
}

func (configuration *tunnelConfiguration) validateAndNormalize() error {
	if configuration.SchemaVersion != configurationSchemaVersion {
		return fmt.Errorf("unsupported configuration schema %d", configuration.SchemaVersion)
	}
	if configuration.OwnerUID <= 0 {
		return errors.New("owner_uid must identify a non-root user")
	}
	if err := validateKey("private_key", configuration.PrivateKey); err != nil {
		return err
	}
	if err := validateKey("gateway_wireguard_public_key", configuration.GatewayWireGuardPublicKey); err != nil {
		return err
	}

	clientPrefix, err := netip.ParsePrefix(configuration.ClientAddress)
	if err != nil || (clientPrefix.Bits() != 32 && clientPrefix.Bits() != 128) {
		return errors.New("client_address must be an IPv4 /32 or IPv6 /128 address")
	}
	clientPrefix = netip.PrefixFrom(clientPrefix.Addr().Unmap(), clientPrefix.Bits())
	configuration.ClientAddress = clientPrefix.String()

	gatewayIP, err := netip.ParseAddr(configuration.GatewayVPNIP)
	if err != nil {
		return errors.New("gateway_vpn_ip must be an IP address")
	}
	gatewayIP = gatewayIP.Unmap()
	configuration.GatewayVPNIP = gatewayIP.String()

	dnsIP, err := netip.ParseAddr(configuration.DNSServer)
	if err != nil || dnsIP.Unmap() != gatewayIP {
		return errors.New("dns_server must equal gateway_vpn_ip")
	}
	configuration.DNSServer = dnsIP.Unmap().String()
	if configuration.DNSDomain != overlayDNSDomain {
		return errors.New("dns_domain is not the HeteroNetwork overlay zone")
	}
	if configuration.MTU != requiredMTU {
		return fmt.Errorf("mtu must be %d", requiredMTU)
	}
	if err := validateGatewayNodeID(configuration.GatewayNodeID); err != nil {
		return err
	}

	host, portText, err := net.SplitHostPort(configuration.GatewayEndpoint)
	if err != nil {
		return errors.New("gateway_endpoint must contain a literal IP address and port")
	}
	endpointIP, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("gateway_endpoint host must be a usable literal IP address")
	}
	endpointIP = endpointIP.Unmap()
	if !endpointIP.IsGlobalUnicast() || endpointIP.IsPrivate() || endpointIP.IsLoopback() ||
		endpointIP.IsLinkLocalUnicast() || endpointIP.IsLinkLocalMulticast() {
		return errors.New("gateway_endpoint host must be a usable literal IP address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return errors.New("gateway_endpoint port is invalid")
	}
	configuration.GatewayEndpoint = net.JoinHostPort(endpointIP.String(), strconv.Itoa(port))

	if len(configuration.AllowedIPs) == 0 || len(configuration.AllowedIPs) > 512 {
		return errors.New("allowed_ips must contain between 1 and 512 routes")
	}
	normalized := make([]string, 0, len(configuration.AllowedIPs))
	seen := make(map[string]struct{}, len(configuration.AllowedIPs))
	containsGateway := false
	for _, value := range configuration.AllowedIPs {
		prefix, parseErr := netip.ParsePrefix(value)
		if parseErr != nil || prefix.Bits() == 0 {
			return fmt.Errorf("allowed_ips contains an invalid or default route: %q", value)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		canonical := prefix.String()
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		normalized = append(normalized, canonical)
		if prefix.Contains(gatewayIP) {
			containsGateway = true
		}
	}
	if !containsGateway {
		return errors.New("allowed_ips does not contain gateway_vpn_ip")
	}
	configuration.AllowedIPs = normalized
	return nil
}

func validateKey(name, value string) error {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
		return fmt.Errorf("%s must be a lowercase 32-byte hexadecimal key", name)
	}
	return nil
}

func validateGatewayNodeID(value string) error {
	if value == "" || len(value) > 256 || strings.TrimSpace(value) != value {
		return errors.New("gateway_node_id is invalid")
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return errors.New("gateway_node_id contains a control character")
		}
	}
	return nil
}

func (configuration tunnelConfiguration) uapiConfiguration() string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "private_key=%s\n", configuration.PrivateKey)
	builder.WriteString("replace_peers=true\n")
	fmt.Fprintf(&builder, "public_key=%s\n", configuration.GatewayWireGuardPublicKey)
	fmt.Fprintf(&builder, "endpoint=%s\n", configuration.GatewayEndpoint)
	builder.WriteString("persistent_keepalive_interval=25\n")
	builder.WriteString("replace_allowed_ips=true\n")
	for _, allowedIP := range configuration.AllowedIPs {
		fmt.Fprintf(&builder, "allowed_ip=%s\n", allowedIP)
	}
	return builder.String()
}
