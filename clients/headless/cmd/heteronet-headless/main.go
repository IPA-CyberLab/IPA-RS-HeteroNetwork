package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	headless "github.com/IPA-CyberLab/IPA-RS-HeteroNetwork/clients/headless"
)

type values []string

func (values *values) String() string         { return strings.Join(*values, ",") }
func (values *values) Set(value string) error { *values = append(*values, value); return nil }
func key(name string) ([]byte, error) {
	value := os.Getenv(name)
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("%s must be a base64 32-byte key", name)
	}
	return decoded, nil
}
func token() ([]byte, error) {
	value := []byte(os.Getenv("HETERONETWORK_JOIN_TOKEN"))
	if path := os.Getenv("HETERONETWORK_JOIN_TOKEN_FILE"); path != "" {
		var err error
		value, err = os.ReadFile(path)
		if err != nil {
			return nil, errors.New("join token file is unavailable")
		}
	}
	value = []byte(strings.TrimSpace(string(value)))
	if len(value) == 0 || json.Valid(value) {
		return value, nil
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(string(value)); err == nil && json.Valid(decoded) {
			return decoded, nil
		}
	}
	return nil, errors.New("join token must be JSON or base64-encoded JSON")
}
func publish(value string) (uint16, string, error) {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 {
		return 0, "", errors.New("publish must be VPN_PORT=127.0.0.1:APP_PORT")
	}
	port, err := strconv.Atoi(parts[0])
	if err != nil || port < 1 || port > 65535 {
		return 0, "", errors.New("invalid VPN service port")
	}
	host, targetPort, err := net.SplitHostPort(parts[1])
	ip := net.ParseIP(host)
	number, portError := strconv.Atoi(targetPort)
	if err != nil || ip == nil || !ip.IsLoopback() || portError != nil || number < 1 || number > 65535 {
		return 0, "", errors.New("application target must use a loopback IP and a valid port")
	}
	return uint16(port), parts[1], nil
}
func run() error {
	endpoint := flag.String("endpoint", os.Getenv("HETERONETWORK_ENDPOINT"), "HTTPS control-plane origin")
	mesh := flag.String("mesh-endpoint", os.Getenv("HETERONETWORK_HTTP_MESH_ENDPOINT"), "optional HTTP(S) encrypted-packet ingress")
	kernel := flag.String("kernel-interface", "", "optional Linux host bridge interface (requires CAP_NET_ADMIN)")
	ipTool := flag.String("ip-command", "/usr/sbin/ip", "trusted iproute2 executable for the host bridge")
	socks := flag.String("socks-listen", "auto", "loopback SOCKS5 listener; empty disables it")
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	health := flag.String("http-listen", "auto", "HTTP health listener; empty disables it")
	var tcp, udp values
	flag.Var(&tcp, "publish", "publish VPN_PORT=127.0.0.1:APP_PORT over TCP")
	flag.Var(&udp, "publish-udp", "publish VPN_PORT=127.0.0.1:APP_PORT over UDP")
	flag.Parse()
	if *socks == "auto" {
		*socks = ""
		if *kernel == "" {
			*socks = "127.0.0.1:1080"
		}
	}
	if *health == "auto" {
		*health = net.JoinHostPort("0.0.0.0", port)
		if *kernel != "" {
			*health = "127.0.0.1:19881"
		}
	}
	identity, err := key("HETERONETWORK_IDENTITY_KEY")
	if err != nil {
		return err
	}
	private, err := key("HETERONETWORK_WIREGUARD_PRIVATE_KEY")
	if err != nil {
		return err
	}
	join, err := token()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	node, err := headless.Start(ctx, headless.Config{KernelInterface: *kernel, IPCommand: *ipTool, Endpoint: *endpoint, MeshEndpoint: *mesh, JoinToken: join, IdentitySeed: identity, WireGuardPrivateKey: private})
	if err != nil {
		return err
	}
	defer node.Close()
	fmt.Printf("HeteroNetwork joined: node=%s vpn_ip=%s transport=http-mesh\n", node.Record.NodeID, node.Record.VPNIP)
	for _, value := range tcp {
		port, target, err := publish(value)
		if err != nil {
			return err
		}
		if _, err = node.PublishTCP(port, target); err != nil {
			return err
		}
	}
	for _, value := range udp {
		port, target, err := publish(value)
		if err != nil {
			return err
		}
		if _, err = node.PublishUDP(port, target); err != nil {
			return err
		}
	}
	if *socks != "" {
		if _, err = node.SOCKS5(*socks); err != nil {
			return err
		}
	}
	serverErrors := make(chan error, 1)
	if *health != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNoContent)
		})
		mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if !node.Status().Ready {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		server := &http.Server{Addr: *health, Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		go func() { serverErrors <- server.ListenAndServe() }()
		defer server.Close()
	}
	childErrors := make(chan error, 1)
	if arguments := flag.Args(); len(arguments) > 0 {
		child := exec.CommandContext(ctx, arguments[0], arguments[1:]...)
		child.Stdout, child.Stderr, child.Stdin = os.Stdout, os.Stderr, os.Stdin
		for _, entry := range os.Environ() {
			name, _, _ := strings.Cut(entry, "=")
			switch name {
			case "HETERONETWORK_JOIN_TOKEN", "HETERONETWORK_JOIN_TOKEN_FILE", "HETERONETWORK_IDENTITY_KEY", "HETERONETWORK_WIREGUARD_PRIVATE_KEY":
				continue
			}
			child.Env = append(child.Env, entry)
		}
		child.Env = append(child.Env, "HETERONETWORK_VPN_IP="+node.Record.VPNIP, "HETERONETWORK_NODE_ID="+node.Record.NodeID)
		child.Cancel = func() error { return child.Process.Signal(syscall.SIGTERM) }
		child.WaitDelay = 10 * time.Second
		if err = child.Start(); err != nil {
			return errors.New("application process could not start")
		}
		go func() { childErrors <- child.Wait() }()
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-serverErrors:
		return err
	case err := <-node.Errors():
		return err
	case err := <-childErrors:
		return err
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "heteronet-headless:", err)
		os.Exit(1)
	}
}
