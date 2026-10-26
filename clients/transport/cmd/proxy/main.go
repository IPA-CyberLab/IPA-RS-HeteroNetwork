package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"

	"github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/clients/transport"
)

// Configuration and keys travel over an inherited private pipe, never through
// command arguments, environment variables, a URL, or a world-readable file.
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "HeteroNetwork transport proxy failed")
		os.Exit(1)
	}
}

func run() error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 64*1024)
	if !scanner.Scan() {
		return fmt.Errorf("missing configuration")
	}
	var config transport.Configuration
	if err := json.Unmarshal(scanner.Bytes(), &config); err != nil {
		return err
	}
	proxy, err := transport.Start(config)
	if err != nil {
		return err
	}
	if proxy == nil {
		return fmt.Errorf("HTTP transport is disabled")
	}
	defer proxy.Close()
	encoder := json.NewEncoder(os.Stdout)
	if err = encoder.Encode(map[string]string{"endpoint": proxy.Endpoint()}); err != nil {
		return err
	}
	for scanner.Scan() {
		switch scanner.Text() {
		case "status":
			if err = encoder.Encode(proxy.Snapshot()); err != nil {
				return err
			}
		case "close":
			return nil
		default:
			return fmt.Errorf("unknown command")
		}
	}
	return scanner.Err()
}
