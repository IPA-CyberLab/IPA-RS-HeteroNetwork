//go:build linux

package headless

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// The optional physical-host bridge adds only host routes in a dedicated table.
// Existing WireGuard/tenant routes in the main table are left to their owners.
type kernelState struct {
	name, command, source string
	table, priority       int
	ready                 atomic.Bool
	mutex                 sync.Mutex
	installed             map[string]NodeRecord
	ownRule               bool
}

func (state *kernelState) commandOutput(ctx context.Context, args ...string) ([]byte, error) {
	command := exec.CommandContext(ctx, state.command, args...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}
	output, err := command.Output()
	if err != nil {
		return nil, errors.New("HTTP bridge network configuration failed")
	}
	return output, nil
}
func (state *kernelState) ip(ctx context.Context, args ...string) error {
	_, err := state.commandOutput(ctx, args...)
	return err
}

func prepareKernel(config Config, address netip.Addr) (tun.Device, *kernelState, error) {
	if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,14}$`).MatchString(config.KernelInterface) {
		return nil, nil, errors.New("invalid kernel interface name")
	}
	if !address.Is4() {
		return nil, nil, errors.New("the physical-host bridge currently requires an IPv4 VPN address")
	}
	if _, err := os.Stat("/sys/class/net/" + config.KernelInterface); !os.IsNotExist(err) {
		return nil, nil, errors.New("kernel interface already exists or cannot be checked")
	}
	command := config.IPCommand
	if command == "" {
		command = "/usr/sbin/ip"
	}
	if !filepath.IsAbs(command) {
		return nil, nil, errors.New("ip command must use an absolute path")
	}
	resolved, err := filepath.EvalSymlinks(command)
	if err != nil {
		return nil, nil, errors.New("ip command is unavailable")
	}
	command = resolved
	for path := command; ; path = filepath.Dir(path) {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0022 != 0 {
			return nil, nil, errors.New("ip command path must not be writable by other users")
		}
		if owner, ok := info.Sys().(*syscall.Stat_t); !ok || owner.Uid != 0 {
			return nil, nil, errors.New("ip command path must be root-owned")
		}
		if path == "/" {
			break
		}
	}
	state := &kernelState{name: config.KernelInterface, command: command, source: address.String(), table: 51989, priority: 19780, installed: make(map[string]NodeRecord)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := state.commandOutput(ctx, "-j", "rule", "show")
	if err != nil {
		return nil, nil, err
	}
	var rules []map[string]any
	if json.Unmarshal(raw, &rules) != nil {
		return nil, nil, errors.New("cannot inspect existing routing rules")
	}
	existing := false
	for _, rule := range rules {
		if rule["priority"] != float64(state.priority) {
			continue
		}
		if fmt.Sprint(rule["table"]) != strconv.Itoa(state.table) || rule["src"] != "all" {
			return nil, nil, errors.New("HTTP bridge routing priority is already in use")
		}
		for key, value := range rule {
			switch key {
			case "priority", "table", "src", "protocol":
			case "dst":
				if value != "all" {
					return nil, nil, errors.New("routing rule has a destination selector")
				}
			default:
				return nil, nil, errors.New("routing rule has additional selectors")
			}
		}
		existing = true
	}
	// A stale, empty rule after SIGKILL can be reused. Never take over a live
	// table belonging to another interface or routing component.
	routes, err := state.commandOutput(ctx, "-j", "route", "show", "table", "all")
	if err != nil {
		return nil, nil, err
	}
	var rows []map[string]any
	if json.Unmarshal(routes, &rows) != nil {
		return nil, nil, errors.New("cannot inspect existing routing tables")
	}
	for _, row := range rows {
		if fmt.Sprint(row["table"]) == strconv.Itoa(state.table) {
			return nil, nil, errors.New("HTTP bridge routing table is already in use")
		}
	}
	local, err := tun.CreateTUN(state.name, 1280)
	if err != nil {
		return nil, nil, errors.New("kernel bridge requires an available TUN device and CAP_NET_ADMIN")
	}
	fail := func(err error) (tun.Device, *kernelState, error) { local.Close(); return nil, nil, err }
	if err = state.ip(ctx, "address", "replace", state.source+"/32", "dev", state.name); err != nil {
		return fail(err)
	}
	if err = state.ip(ctx, "link", "set", "dev", state.name, "up"); err != nil {
		return fail(err)
	}
	if !existing {
		if err = state.ip(ctx, "rule", "add", "priority", strconv.Itoa(state.priority), "lookup", strconv.Itoa(state.table)); err != nil {
			return fail(err)
		}
		state.ownRule = true
	}
	return local, state, nil
}

func (state *kernelState) routes(node *Node) {
	ticker := time.NewTicker(4 * time.Second)
	defer ticker.Stop()
	for {
		ctx, cancel := context.WithTimeout(node.ctx, 20*time.Second)
		desired := make(map[string]NodeRecord)
		var after *string
		self, selfErr := node.api.peer(ctx, node.Record.NodeID)
		if selfErr == nil && self.WireGuardPublicKey != node.Record.WireGuardPublicKey {
			select {
			case node.errors <- errors.New("host key rotated; reload local bridge identity"):
			default:
			}
			cancel()
			return
		}
		limit := uint16(50)
		var failure error
		for {
			response, err := node.api.meshRequest(ctx, action{Operation: "routes", After: after, Limit: &limit})
			if err != nil {
				failure = err
				break
			}
			for _, record := range response.Nodes {
				desired[record.NodeID] = record
			}
			if response.NextCursor == nil {
				break
			}
			after = response.NextCursor
		}
		if failure == nil {
			state.mutex.Lock()
			for id, record := range desired {
				previous, exists := state.installed[id]
				if exists && previous.VPNIP == record.VPNIP && previous.WireGuardPublicKey == record.WireGuardPublicKey {
					continue
				}
				address, err := netip.ParseAddr(record.VPNIP)
				if err != nil || !address.Is4() {
					failure = errors.New("invalid HTTP peer route")
					break
				}
				node.lookupMu.Lock()
				_, err = node.configurePeer(record, id)
				node.lookupMu.Unlock()
				if err != nil {
					failure = err
					break
				}
				if err = state.ip(ctx, "route", "replace", address.String()+"/32", "dev", state.name, "src", state.source, "table", strconv.Itoa(state.table)); err != nil {
					failure = err
					break
				}
				state.installed[id] = record
			}
			if failure == nil {
				for id, previous := range state.installed {
					if _, ok := desired[id]; ok {
						continue
					}
					state.ip(ctx, "route", "delete", previous.VPNIP+"/32", "dev", state.name, "table", strconv.Itoa(state.table))
					delete(state.installed, id)
				}
			}
			state.mutex.Unlock()
			if failure == nil {
				state.ready.Store(true)
			}
		}
		if failure != nil && node.ctx.Err() == nil {
			state.ready.Store(false)
			node.bind.failures.Add(1)
		}
		cancel()
		select {
		case <-node.ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (state *kernelState) cleanup() {
	state.mutex.Lock()
	defer state.mutex.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, record := range state.installed {
		state.ip(ctx, "route", "delete", record.VPNIP+"/32", "dev", state.name, "table", strconv.Itoa(state.table))
	}
	if state.ownRule {
		state.ip(ctx, "rule", "delete", "priority", strconv.Itoa(state.priority), "lookup", strconv.Itoa(state.table))
	}
}
