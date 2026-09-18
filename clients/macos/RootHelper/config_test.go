package main

import (
	"strings"
	"testing"
)

func validTestConfiguration() tunnelConfiguration {
	return tunnelConfiguration{
		SchemaVersion:             1,
		OwnerUID:                  501,
		PrivateKey:                strings.Repeat("11", 32),
		ClientAddress:             "10.250.0.9/32",
		GatewayNodeID:             "node-gateway",
		GatewayVPNIP:              "10.250.0.1",
		GatewayWireGuardPublicKey: strings.Repeat("22", 32),
		GatewayEndpoint:           "203.0.113.8:51820",
		AllowedIPs:                []string{"10.250.0.1/32", "10.42.0.0/16"},
		DNSServer:                 "10.250.0.1",
		DNSDomain:                 overlayDNSDomain,
		MTU:                       1280,
	}
}

func TestConfigurationValidation(t *testing.T) {
	configuration := validTestConfiguration()
	if err := configuration.validateAndNormalize(); err != nil {
		t.Fatalf("valid configuration rejected: %v", err)
	}
	if configuration.ClientAddress != "10.250.0.9/32" {
		t.Fatalf("unexpected client address: %s", configuration.ClientAddress)
	}
	if !strings.Contains(configuration.uapiConfiguration(), "replace_peers=true\n") {
		t.Fatal("UAPI configuration does not replace stale peers")
	}
}

func TestConfigurationRejectsDefaultRoute(t *testing.T) {
	configuration := validTestConfiguration()
	configuration.AllowedIPs = []string{"0.0.0.0/0"}
	if err := configuration.validateAndNormalize(); err == nil {
		t.Fatal("default route was accepted")
	}
}

func TestConfigurationRejectsMismatchedDNS(t *testing.T) {
	configuration := validTestConfiguration()
	configuration.DNSServer = "10.250.0.2"
	if err := configuration.validateAndNormalize(); err == nil {
		t.Fatal("mismatched DNS server was accepted")
	}
}

func TestConfigurationRejectsPrivateGatewayEndpoint(t *testing.T) {
	configuration := validTestConfiguration()
	configuration.GatewayEndpoint = "192.168.1.10:51820"
	if err := configuration.validateAndNormalize(); err == nil {
		t.Fatal("private gateway endpoint was accepted")
	}
}

func TestConfigurationCanonicalizesRoutes(t *testing.T) {
	configuration := validTestConfiguration()
	configuration.AllowedIPs = append(configuration.AllowedIPs, "10.42.4.9/16")
	if err := configuration.validateAndNormalize(); err != nil {
		t.Fatalf("configuration rejected: %v", err)
	}
	if len(configuration.AllowedIPs) != 2 {
		t.Fatalf("duplicate canonical route retained: %#v", configuration.AllowedIPs)
	}
}
