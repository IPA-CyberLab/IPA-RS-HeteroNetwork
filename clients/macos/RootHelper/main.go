package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
)

var buildVersion = "development"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "heteronetwork-root-helper: %v\n", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return usageError()
	}
	switch arguments[0] {
	case "version":
		if len(arguments) != 1 {
			return usageError()
		}
		fmt.Printf("%s %s\n", helperProtocolVersion, buildVersion)
		return nil
	case "self-test":
		if len(arguments) != 1 {
			return usageError()
		}
		return runSelfTest()
	case "status":
		if len(arguments) != 1 {
			return usageError()
		}
		response, err := requestControl(controlRequest{Action: "status"})
		if disconnected, ok := disconnectedResponseFor(err); ok {
			return encodeResponse(disconnected)
		}
		if err != nil {
			return err
		}
		return encodeResponse(response)
	case "update":
		if len(arguments) != 2 {
			return usageError()
		}
		return updateTunnel(arguments[1])
	case "stop":
		if len(arguments) != 1 {
			return usageError()
		}
		response, err := requestControl(controlRequest{Action: "stop"})
		if disconnected, ok := disconnectedResponseFor(err); ok {
			return encodeResponse(disconnected)
		}
		if err != nil {
			return err
		}
		return encodeResponse(response)
	case "start":
		if len(arguments) != 2 {
			return usageError()
		}
		return startTunnel(arguments[1])
	case "daemon":
		if len(arguments) != 2 {
			return usageError()
		}
		return runTunnelDaemon(arguments[1])
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: heteronetwork-root-helper {version|self-test|status|update CONFIG|stop|start CONFIG}")
}

func updateTunnel(path string) error {
	defer os.Remove(path)
	uid := uint32(os.Geteuid())
	if uid == 0 {
		return errors.New("update must be requested by the tunnel owner")
	}
	configuration, _, err := readSecureConfiguration(path, &uid)
	if err != nil {
		return err
	}
	if configuration.OwnerUID != int(uid) {
		return errors.New("configuration owner does not match the requesting user")
	}
	response, err := requestControl(controlRequest{
		Action:        "update",
		Configuration: &configuration,
	})
	if err != nil {
		return err
	}
	return encodeResponse(response)
}

func runSelfTest() error {
	configuration := tunnelConfiguration{
		SchemaVersion:             1,
		OwnerUID:                  501,
		PrivateKey:                "1111111111111111111111111111111111111111111111111111111111111111",
		ClientAddress:             "10.250.0.9/32",
		GatewayNodeID:             "self-test-gateway",
		GatewayVPNIP:              "10.250.0.1",
		GatewayWireGuardPublicKey: "2222222222222222222222222222222222222222222222222222222222222222",
		GatewayEndpoint:           "203.0.113.8:51820",
		AllowedIPs:                []string{"10.250.0.1/32"},
		DNSServer:                 "10.250.0.1",
		DNSDomain:                 overlayDNSDomain,
		MTU:                       requiredMTU,
	}
	if err := configuration.validateAndNormalize(); err != nil {
		return err
	}
	payload, err := json.Marshal(controlRequest{Action: "update", Configuration: &configuration})
	if err != nil || len(payload) < 2 || len(payload) > maximumConfigurationBytes {
		return errors.New("control protocol self-test failed")
	}
	if _, _, err := net.SplitHostPort(configuration.GatewayEndpoint); err != nil {
		return errors.New("endpoint self-test failed")
	}
	fmt.Println("HeteroNetwork root helper self-test passed.")
	return nil
}
