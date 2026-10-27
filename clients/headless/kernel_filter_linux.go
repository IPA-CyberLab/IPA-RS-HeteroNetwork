//go:build linux

package headless

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type forwardingPair struct{ source, destination netip.Addr }
type forwardingDecision struct {
	allowed bool
	expires time.Time
}
type kernelFilter struct {
	tun.Device
	node      *Node
	mutex     sync.Mutex
	decisions map[forwardingPair]forwardingDecision
}

func filterKernelTraffic(local tun.Device, node *Node) tun.Device {
	if node.kernel == nil {
		return local
	}
	return &kernelFilter{Device: local, node: node, decisions: make(map[forwardingPair]forwardingDecision)}
}
func (filter *kernelFilter) permit(packet []byte, incoming bool) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 || int(packet[0]&15)*4 < 20 || int(packet[0]&15)*4 > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) > len(packet) {
		return false
	}
	source := netip.AddrFrom4([4]byte(packet[12:16]))
	destination := netip.AddrFrom4([4]byte(packet[16:20]))
	// Local traffic was already authorized by the outer, authenticated peer pair.
	own := netip.MustParseAddr(filter.node.Record.VPNIP)
	if incoming && destination == own || !incoming && source == own {
		return true
	}
	pair := forwardingPair{source, destination}
	now := time.Now()
	filter.mutex.Lock()
	previous, exists := filter.decisions[pair]
	if exists && now.Before(previous.expires) {
		filter.mutex.Unlock()
		return previous.allowed
	}
	if len(filter.decisions) >= 4096 {
		for key, value := range filter.decisions {
			if now.After(value.expires) {
				delete(filter.decisions, key)
			}
		}
		if len(filter.decisions) >= 4096 {
			filter.mutex.Unlock()
			return false
		}
	}
	filter.mutex.Unlock()
	ctx, cancel := context.WithTimeout(filter.node.ctx, 2*time.Second)
	defer cancel()
	result, err := filter.node.api.meshRequest(ctx, action{Operation: "forward", Source: source.String(), Destination: destination.String()})
	allowed := err == nil && result.Accepted != nil && *result.Accepted
	duration := time.Second
	if allowed {
		duration = 5 * time.Second
	} else {
		filter.node.bind.failures.Add(1)
	}
	filter.mutex.Lock()
	filter.decisions[pair] = forwardingDecision{allowed, time.Now().Add(duration)}
	filter.mutex.Unlock()
	return allowed
}
func (filter *kernelFilter) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	count, err := filter.Device.Read(buffers, sizes, offset)
	accepted := 0
	for index := 0; index < count; index++ {
		if filter.permit(buffers[index][offset:offset+sizes[index]], false) {
			buffers[accepted], buffers[index] = buffers[index], buffers[accepted]
			sizes[accepted] = sizes[index]
			accepted++
		}
	}
	return accepted, err
}
func (filter *kernelFilter) Write(buffers [][]byte, offset int) (int, error) {
	accepted := make([][]byte, 0, len(buffers))
	for _, packet := range buffers {
		if filter.permit(packet[offset:], true) {
			accepted = append(accepted, packet)
		}
	}
	if len(accepted) > 0 {
		if _, err := filter.Device.Write(accepted, offset); err != nil {
			return 0, err
		}
	}
	return len(buffers), nil
}
