package headless

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/tun"
)

// Discover at the packet boundary as well as DialContext: an existing TCP
// connection must reconnect its WireGuard peer after idle state is evicted.
type lazyTUN struct {
	tun.Device
	node *Node
}

func (local *lazyTUN) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	count, err := local.Device.Read(buffers, sizes, offset)
	accepted := 0
	for index := 0; index < count; index++ {
		packet := buffers[index][offset : offset+sizes[index]]
		var destination netip.Addr
		if len(packet) >= 20 && packet[0]>>4 == 4 {
			destination = netip.AddrFrom4([4]byte(packet[16:20]))
		}
		if len(packet) >= 40 && packet[0]>>4 == 6 {
			destination = netip.AddrFrom16([16]byte(packet[24:40]))
		}
		if !destination.IsValid() {
			continue
		}
		if _, lookupErr := local.node.ensurePeer(local.node.ctx, destination.String()); lookupErr != nil {
			local.node.bind.failures.Add(1)
			continue
		}
		buffers[accepted], buffers[index] = buffers[index], buffers[accepted]
		sizes[accepted] = sizes[index]
		accepted++
	}
	return accepted, err
}
