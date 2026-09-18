//go:build darwin

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	runtimeDirectory = "/var/run/heteronetwork-client"
	lockFilePath     = runtimeDirectory + "/start.lock"
	logFilePath      = runtimeDirectory + "/daemon.log"
	dnsStoreKey      = "State:/Network/Service/jp.go.ipa.cyberlab.heteronetwork/DNS"
)

type daemonReady struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type activeTunnel struct {
	configuration tunnelConfiguration
	device        *device.Device
	interfaceName string
	addedRoutes   map[string]struct{}
	dns           *splitDNSSession
}

type splitDNSSession struct {
	command *exec.Cmd
	input   io.WriteCloser
}

func startTunnel(path string) error {
	if os.Geteuid() != 0 {
		return errors.New("start requires administrator privileges")
	}
	defer os.Remove(path)
	configuration, fileOwner, err := readSecureConfiguration(path, nil)
	if err != nil {
		return err
	}
	if fileOwner == 0 || configuration.OwnerUID != int(fileOwner) {
		return errors.New("configuration owner does not match its file owner")
	}
	if err := ensureRuntimeDirectory(); err != nil {
		return err
	}
	if response, running, requestErr := updateExistingTunnel(configuration); running {
		return encodeResponse(response)
	} else if requestErr != nil {
		return requestErr
	}
	lock, existingResponse, err := acquireStartLock(configuration)
	if err != nil {
		return err
	}
	if existingResponse != nil {
		return encodeResponse(*existingResponse)
	}
	defer lock.Close()

	if response, running, requestErr := updateExistingTunnel(configuration); running {
		return encodeResponse(response)
	} else if requestErr != nil {
		return requestErr
	}
	if err := removeStaleSocket(); err != nil {
		return err
	}

	rootConfigurationPath, err := writeRootConfiguration(configuration)
	if err != nil {
		return err
	}
	removeRootConfiguration := true
	defer func() {
		if removeRootConfiguration {
			_ = os.Remove(rootConfigurationPath)
		}
	}()

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate root helper: %w", err)
	}
	if err := validateInstalledExecutable(executable); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logFilePath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open daemon log: %w", err)
	}
	defer logFile.Close()
	if err := logFile.Chmod(0o600); err != nil {
		return fmt.Errorf("protect daemon log: %w", err)
	}

	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create daemon readiness pipe: %w", err)
	}
	defer readyReader.Close()
	command := exec.Command(executable, "daemon", rootConfigurationPath)
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.ExtraFiles = []*os.File{readyWriter, lock}
	command.Env = append(
		os.Environ(),
		"HETERONETWORK_READY_FD=3",
		"HETERONETWORK_LIFECYCLE_FD=4",
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		readyWriter.Close()
		return fmt.Errorf("start tunnel daemon: %w", err)
	}
	readyWriter.Close()
	removeRootConfiguration = false

	readiness := make(chan daemonReady, 1)
	go func() {
		var result daemonReady
		if decodeErr := json.NewDecoder(io.LimitReader(readyReader, 4096)).Decode(&result); decodeErr != nil {
			result = daemonReady{Error: "tunnel daemon exited before reporting readiness"}
		}
		readiness <- result
	}()
	select {
	case result := <-readiness:
		if !result.OK {
			_ = command.Process.Kill()
			_ = command.Wait()
			if result.Error == "" {
				result.Error = "tunnel daemon failed to start"
			}
			return errors.New(result.Error)
		}
	case <-time.After(20 * time.Second):
		_ = readyReader.Close()
		_ = command.Process.Kill()
		_ = command.Wait()
		return errors.New("timed out while starting the tunnel daemon")
	}
	if err := command.Process.Release(); err != nil {
		return fmt.Errorf("detach tunnel daemon: %w", err)
	}
	response, err := requestControl(controlRequest{Action: "status"})
	if err != nil {
		return fmt.Errorf("verify tunnel daemon: %w", err)
	}
	return encodeResponse(response)
}

func runTunnelDaemon(path string) (returnError error) {
	if os.Geteuid() != 0 {
		return errors.New("daemon requires administrator privileges")
	}
	unix.CloseOnExec(3)
	lifecycleFileDescriptor, conversionErr := strconv.Atoi(
		os.Getenv("HETERONETWORK_LIFECYCLE_FD"),
	)
	if conversionErr != nil || lifecycleFileDescriptor != 4 {
		err := errors.New("daemon requires an inherited lifecycle lock")
		notifyDaemonReady(err)
		return err
	}
	lifecycleLock := os.NewFile(uintptr(lifecycleFileDescriptor), "tunnel-lifecycle-lock")
	if lifecycleLock == nil {
		err := errors.New("daemon lifecycle lock is unavailable")
		notifyDaemonReady(err)
		return err
	}
	unix.CloseOnExec(lifecycleFileDescriptor)
	defer lifecycleLock.Close()
	rootUID := uint32(0)
	configuration, _, err := readSecureConfiguration(path, &rootUID)
	_ = os.Remove(path)
	if err != nil {
		notifyDaemonReady(err)
		return err
	}
	tunnel, err := createActiveTunnel(configuration)
	if err != nil {
		notifyDaemonReady(err)
		return err
	}
	defer tunnel.close()

	listener, err := createControlListener(configuration.OwnerUID)
	if err != nil {
		notifyDaemonReady(err)
		return err
	}
	defer func() {
		listener.Close()
		_ = os.Remove(controlSocketPath)
	}()
	notifyDaemonReady(nil)
	return tunnel.serve(listener)
}

func createActiveTunnel(configuration tunnelConfiguration) (*activeTunnel, error) {
	tunDevice, err := tun.CreateTUN("utun", 0)
	if err != nil {
		return nil, fmt.Errorf("create utun interface: %w", err)
	}
	interfaceName, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("identify utun interface: %w", err)
	}
	logger := device.NewLogger(device.LogLevelError, "HeteroNetwork: ")
	wireGuardDevice := device.NewDevice(tunDevice, conn.NewStdNetBind(), logger)
	tunnel := &activeTunnel{
		configuration: configuration,
		device:        wireGuardDevice,
		interfaceName: interfaceName,
		addedRoutes:   make(map[string]struct{}),
	}
	fail := func(setupErr error) (*activeTunnel, error) {
		tunnel.close()
		return nil, setupErr
	}
	if err := wireGuardDevice.IpcSet(configuration.uapiConfiguration()); err != nil {
		return fail(fmt.Errorf("configure WireGuard: %w", err))
	}
	if err := tunnel.configureInterface(); err != nil {
		return fail(err)
	}
	for _, route := range configuration.AllowedIPs {
		if err := tunnel.addRoute(route); err != nil {
			return fail(err)
		}
	}
	dnsSession, err := startSplitDNS(configuration.DNSServer, configuration.DNSDomain)
	if err != nil {
		return fail(err)
	}
	tunnel.dns = dnsSession
	if err := wireGuardDevice.Up(); err != nil {
		return fail(fmt.Errorf("bring WireGuard device up: %w", err))
	}
	return tunnel, nil
}

func (tunnel *activeTunnel) configureInterface() error {
	prefix, _ := netip.ParsePrefix(tunnel.configuration.ClientAddress)
	var arguments []string
	if prefix.Addr().Is4() {
		arguments = []string{
			tunnel.interfaceName,
			"inet",
			tunnel.configuration.ClientAddress,
			prefix.Addr().String(),
			"alias",
		}
	} else {
		arguments = []string{
			tunnel.interfaceName,
			"inet6",
			tunnel.configuration.ClientAddress,
			"alias",
		}
	}
	if err := runSystemCommand("/sbin/ifconfig", arguments...); err != nil {
		return fmt.Errorf("assign tunnel address: %w", err)
	}
	if err := runSystemCommand(
		"/sbin/ifconfig",
		tunnel.interfaceName,
		"mtu",
		strconv.Itoa(tunnel.configuration.MTU),
		"up",
	); err != nil {
		return fmt.Errorf("bring tunnel interface up: %w", err)
	}
	return nil
}

func (tunnel *activeTunnel) addRoute(route string) error {
	family := "-inet"
	if strings.Contains(route, ":") {
		family = "-inet6"
	}
	if err := runSystemCommand(
		"/sbin/route",
		"-q", "-n", "add", family, route, "-interface", tunnel.interfaceName,
	); err != nil {
		return fmt.Errorf("add overlay route %s: %w", route, err)
	}
	tunnel.addedRoutes[route] = struct{}{}
	return nil
}

func (tunnel *activeTunnel) deleteRoute(route string) {
	if _, exists := tunnel.addedRoutes[route]; !exists {
		return
	}
	family := "-inet"
	if strings.Contains(route, ":") {
		family = "-inet6"
	}
	_ = runSystemCommand("/sbin/route", "-q", "-n", "delete", family, route)
	delete(tunnel.addedRoutes, route)
}

func (tunnel *activeTunnel) update(configuration tunnelConfiguration) error {
	if configuration.OwnerUID != tunnel.configuration.OwnerUID {
		return errors.New("configuration owner cannot change while connected")
	}
	if configuration.ClientAddress != tunnel.configuration.ClientAddress {
		return errors.New("client address cannot change while connected")
	}
	oldRoutes := make(map[string]struct{}, len(tunnel.configuration.AllowedIPs))
	newRoutes := make(map[string]struct{}, len(configuration.AllowedIPs))
	for _, route := range tunnel.configuration.AllowedIPs {
		oldRoutes[route] = struct{}{}
	}
	for _, route := range configuration.AllowedIPs {
		newRoutes[route] = struct{}{}
	}
	added := make([]string, 0)
	for route := range newRoutes {
		if _, exists := oldRoutes[route]; exists {
			continue
		}
		if err := tunnel.addRoute(route); err != nil {
			for _, rollbackRoute := range added {
				tunnel.deleteRoute(rollbackRoute)
			}
			return err
		}
		added = append(added, route)
	}
	if err := tunnel.device.IpcSet(configuration.uapiConfiguration()); err != nil {
		for _, rollbackRoute := range added {
			tunnel.deleteRoute(rollbackRoute)
		}
		return fmt.Errorf("update WireGuard gateway: %w", err)
	}
	dnsChanged := configuration.DNSServer != tunnel.configuration.DNSServer ||
		configuration.DNSDomain != tunnel.configuration.DNSDomain
	if dnsChanged {
		if tunnel.dns == nil {
			return errors.New("split DNS session is unavailable")
		}
		if err := tunnel.dns.update(configuration.DNSServer, configuration.DNSDomain); err != nil {
			_ = tunnel.device.IpcSet(tunnel.configuration.uapiConfiguration())
			_ = tunnel.dns.update(
				tunnel.configuration.DNSServer,
				tunnel.configuration.DNSDomain,
			)
			for _, rollbackRoute := range added {
				tunnel.deleteRoute(rollbackRoute)
			}
			return err
		}
	}
	for route := range oldRoutes {
		if _, exists := newRoutes[route]; !exists {
			tunnel.deleteRoute(route)
		}
	}
	tunnel.configuration = configuration
	return nil
}

func (tunnel *activeTunnel) close() {
	if tunnel.dns != nil {
		tunnel.dns.close()
		tunnel.dns = nil
	} else {
		_ = removeSplitDNS()
	}
	for route := range tunnel.addedRoutes {
		tunnel.deleteRoute(route)
	}
	if tunnel.device != nil {
		tunnel.device.Close()
	}
}

func (tunnel *activeTunnel) serve(listener *net.UnixListener) error {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)
	for {
		select {
		case <-signals:
			return nil
		case <-tunnel.device.Wait():
			return errors.New("WireGuard device stopped unexpectedly")
		default:
		}
		_ = listener.SetDeadline(time.Now().Add(time.Second))
		connection, err := listener.AcceptUnix()
		if err != nil {
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				continue
			}
			return fmt.Errorf("accept control connection: %w", err)
		}
		stop := tunnel.handleControlConnection(connection)
		connection.Close()
		if stop {
			return nil
		}
	}
}

func (tunnel *activeTunnel) handleControlConnection(connection net.Conn) bool {
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	request, err := decodeControlRequest(connection)
	response := controlResponse{
		OK:        true,
		Status:    "connected",
		Interface: tunnel.interfaceName,
		Gateway:   tunnel.configuration.GatewayNodeID,
		PID:       os.Getpid(),
	}
	stop := false
	if err != nil {
		response.OK = false
		response.Error = "invalid control request"
	} else {
		switch request.Action {
		case "status":
		case "update":
			if request.Configuration == nil {
				response.OK = false
				response.Error = "update requires a configuration"
			} else if validateErr := request.Configuration.validateAndNormalize(); validateErr != nil {
				response.OK = false
				response.Error = validateErr.Error()
			} else if updateErr := tunnel.update(*request.Configuration); updateErr != nil {
				response.OK = false
				response.Error = updateErr.Error()
			} else {
				response.Gateway = tunnel.configuration.GatewayNodeID
			}
		case "stop":
			response.Status = "disconnected"
			response.Interface = ""
			response.Gateway = ""
			response.PID = 0
			stop = true
		default:
			response.OK = false
			response.Error = "unsupported control action"
		}
	}
	_ = json.NewEncoder(connection).Encode(response)
	return stop && response.OK
}

func createControlListener(ownerUID int) (*net.UnixListener, error) {
	oldUmask := unix.Umask(0o077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: controlSocketPath, Net: "unix"})
	unix.Umask(oldUmask)
	if err != nil {
		return nil, fmt.Errorf("create control socket: %w", err)
	}
	if err := os.Chown(controlSocketPath, ownerUID, -1); err != nil {
		listener.Close()
		return nil, fmt.Errorf("set control socket owner: %w", err)
	}
	if err := os.Chmod(controlSocketPath, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("protect control socket: %w", err)
	}
	return listener, nil
}

func startSplitDNS(server, domain string) (*splitDNSSession, error) {
	_ = removeSplitDNS()
	command := exec.Command("/usr/sbin/scutil")
	input, err := command.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("create split DNS session: %w", err)
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		input.Close()
		return nil, fmt.Errorf("start split DNS session: %w", err)
	}
	session := &splitDNSSession{command: command, input: input}
	script := splitDNSDictionaryScript(server, domain) + "add " + dnsStoreKey + " temporary\n"
	if _, err := io.WriteString(input, script); err != nil {
		session.close()
		return nil, fmt.Errorf("install temporary split DNS: %w", err)
	}
	if err := waitForSplitDNS(server, domain); err != nil {
		session.close()
		return nil, err
	}
	return session, nil
}

func (session *splitDNSSession) update(server, domain string) error {
	if session == nil || session.command == nil || session.command.Process == nil {
		return errors.New("split DNS session is unavailable")
	}
	script := "remove " + dnsStoreKey + "\n" +
		splitDNSDictionaryScript(server, domain) +
		"add " + dnsStoreKey + " temporary\n"
	if _, err := io.WriteString(session.input, script); err != nil {
		return fmt.Errorf("update temporary split DNS: %w", err)
	}
	return waitForSplitDNS(server, domain)
}

func (session *splitDNSSession) close() {
	if session == nil || session.command == nil {
		return
	}
	if session.input != nil {
		_, _ = io.WriteString(session.input, "remove "+dnsStoreKey+"\nquit\n")
		_ = session.input.Close()
	}
	exited := make(chan struct{})
	go func() {
		_ = session.command.Wait()
		close(exited)
	}()
	select {
	case <-exited:
	case <-time.After(2 * time.Second):
		if session.command.Process != nil {
			_ = session.command.Process.Kill()
		}
		<-exited
	}
	_ = removeSplitDNS()
}

func splitDNSDictionaryScript(server, domain string) string {
	return fmt.Sprintf(
		"d.init\nd.add ServerAddresses * %s\nd.add SupplementalMatchDomains * %s\nd.add SupplementalMatchOrders # 101000\n",
		server,
		domain,
	)
}

func waitForSplitDNS(server, domain string) error {
	for attempt := 0; attempt < 20; attempt++ {
		command := exec.Command("/usr/sbin/scutil")
		command.Stdin = strings.NewReader("show " + dnsStoreKey + "\nquit\n")
		output, err := command.CombinedOutput()
		if err == nil && strings.Contains(string(output), server) && strings.Contains(string(output), domain) {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("temporary split DNS state was not published")
}

func removeSplitDNS() error {
	command := exec.Command("/usr/sbin/scutil")
	command.Stdin = strings.NewReader("remove " + dnsStoreKey + "\nquit\n")
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("remove split DNS: %w: %s", err, safeCommandOutput(output))
	}
	return nil
}

func runSystemCommand(name string, arguments ...string) error {
	command := exec.Command(name, arguments...)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %w: %s", filepath.Base(name), err, safeCommandOutput(output))
	}
	return nil
}

func safeCommandOutput(output []byte) string {
	value := strings.TrimSpace(string(output))
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func notifyDaemonReady(err error) {
	fileDescriptor, conversionErr := strconv.Atoi(os.Getenv("HETERONETWORK_READY_FD"))
	if conversionErr != nil || fileDescriptor < 3 {
		return
	}
	file := os.NewFile(uintptr(fileDescriptor), "daemon-ready")
	if file == nil {
		return
	}
	defer file.Close()
	result := daemonReady{OK: err == nil}
	if err != nil {
		result.Error = err.Error()
	}
	_ = json.NewEncoder(file).Encode(result)
}

func ensureRuntimeDirectory() error {
	if err := os.Mkdir(runtimeDirectory, 0o755); err != nil && !os.IsExist(err) {
		return fmt.Errorf("create runtime directory: %w", err)
	}
	information, err := os.Lstat(runtimeDirectory)
	if err != nil {
		return fmt.Errorf("inspect runtime directory: %w", err)
	}
	status, ok := information.Sys().(*syscall.Stat_t)
	if !ok || !information.IsDir() || information.Mode()&os.ModeSymlink != 0 || status.Uid != 0 {
		return errors.New("runtime directory is not a root-owned directory")
	}
	if err := os.Chmod(runtimeDirectory, 0o755); err != nil {
		return fmt.Errorf("protect runtime directory: %w", err)
	}
	return nil
}

func acquireStartLock(
	configuration tunnelConfiguration,
) (*os.File, *controlResponse, error) {
	deadline := time.Now().Add(20 * time.Second)
	for {
		file, err := os.OpenFile(lockFilePath, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, nil, fmt.Errorf("open start lock: %w", err)
		}
		if err := file.Chmod(0o600); err != nil {
			file.Close()
			return nil, nil, fmt.Errorf("protect start lock: %w", err)
		}
		err = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return file, nil, nil
		}
		file.Close()
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return nil, nil, fmt.Errorf("lock tunnel startup: %w", err)
		}
		if response, running, requestErr := updateExistingTunnel(configuration); running {
			return nil, &response, nil
		} else if requestErr != nil {
			return nil, nil, requestErr
		}
		if time.Now().After(deadline) {
			return nil, nil, errors.New("timed out waiting for the existing tunnel lifecycle")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func updateExistingTunnel(
	configuration tunnelConfiguration,
) (controlResponse, bool, error) {
	response, err := requestControl(controlRequest{
		Action:        "update",
		Configuration: &configuration,
	})
	if err == nil {
		return response, true, nil
	}
	if _, disconnected := disconnectedResponseFor(err); disconnected {
		return controlResponse{}, false, nil
	}
	return controlResponse{}, false, fmt.Errorf("contact existing tunnel: %w", err)
}

func removeStaleSocket() error {
	information, err := os.Lstat(controlSocketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect stale control socket: %w", err)
	}
	if information.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to replace a non-socket control path")
	}
	if err := os.Remove(controlSocketPath); err != nil {
		return fmt.Errorf("remove stale control socket: %w", err)
	}
	return nil
}

func writeRootConfiguration(configuration tunnelConfiguration) (string, error) {
	file, err := os.CreateTemp(runtimeDirectory, ".configuration-")
	if err != nil {
		return "", fmt.Errorf("create root configuration: %w", err)
	}
	path := file.Name()
	keep := false
	defer func() {
		file.Close()
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("protect root configuration: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(configuration); err != nil {
		return "", fmt.Errorf("write root configuration: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync root configuration: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close root configuration: %w", err)
	}
	keep = true
	return path, nil
}

func validateInstalledExecutable(path string) error {
	information, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect installed root helper: %w", err)
	}
	status, ok := information.Sys().(*syscall.Stat_t)
	if !ok || !information.Mode().IsRegular() || information.Mode()&os.ModeSymlink != 0 || status.Uid != 0 {
		return errors.New("installed root helper must be a root-owned regular file")
	}
	if information.Mode().Perm()&0o022 != 0 {
		return errors.New("installed root helper must not be group- or world-writable")
	}
	parentInformation, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("inspect root helper directory: %w", err)
	}
	parentStatus, ok := parentInformation.Sys().(*syscall.Stat_t)
	if !ok || !parentInformation.IsDir() || parentInformation.Mode()&os.ModeSymlink != 0 ||
		parentStatus.Uid != 0 || parentInformation.Mode().Perm()&0o022 != 0 {
		return errors.New("installed root helper directory must be root-owned and protected")
	}
	return nil
}
