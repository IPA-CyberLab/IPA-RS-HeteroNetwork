//go:build !linux

package headless

import (
	"errors"
	"golang.zx2c4.com/wireguard/tun"
	"net/netip"
	"sync/atomic"
)

type kernelState struct{ ready atomic.Bool }

func prepareKernel(Config, netip.Addr) (tun.Device, *kernelState, error) {
	return nil, nil, errors.New("kernel bridge mode requires Linux")
}
func (*kernelState) routes(*Node) {}
func (*kernelState) cleanup()     {}
