//go:build !darwin

package main

import "errors"

func startTunnel(string) error {
	return errors.New("starting a tunnel is supported only on macOS")
}

func runTunnelDaemon(string) error {
	return errors.New("running a tunnel is supported only on macOS")
}
