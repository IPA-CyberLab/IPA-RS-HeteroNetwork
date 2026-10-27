package headless

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

type meshEndpoint struct {
	node string
	ip   netip.Addr
}

func (e meshEndpoint) ClearSrc()           {}
func (e meshEndpoint) SrcToString() string { return "" }
func (e meshEndpoint) DstToString() string { return e.node + "@" + e.ip.String() }
func (e meshEndpoint) DstToBytes() []byte  { return []byte(e.DstToString()) }
func (e meshEndpoint) DstIP() netip.Addr   { return e.ip }
func (e meshEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type receivedPacket struct {
	data     []byte
	endpoint meshEndpoint
}
type peerSender struct{ packets chan []byte }

type meshBind struct {
	api                           *API
	ensurePeer                    func(context.Context, string) (meshEndpoint, error)
	base                          context.Context
	mu                            sync.Mutex
	context                       context.Context
	cancel                        context.CancelFunc
	received                      chan receivedPacket
	senders                       map[string]*peerSender
	inflight                      chan struct{}
	pending                       atomic.Int64
	sent, receivedBytes, failures atomic.Uint64
	lastPoll                      atomic.Int64
	fatal                         chan<- error
}

func (bind *meshBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.cancel != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	ctx, cancel := context.WithCancel(bind.base)
	bind.context, bind.cancel = ctx, cancel
	received := make(chan receivedPacket, 256)
	bind.received = received
	bind.senders = make(map[string]*peerSender)
	bind.inflight = make(chan struct{}, 32)
	go bind.poll(ctx, received)
	receive := func(packets [][]byte, sizes []int, endpoints []conn.Endpoint) (int, error) {
		select {
		case <-ctx.Done():
			return 0, net.ErrClosed
		case packet := <-received:
			if len(packets) == 0 || len(sizes) == 0 || len(endpoints) == 0 || len(packets[0]) < len(packet.data) {
				return 0, errors.New("WireGuard receive buffer too small")
			}
			sizes[0] = copy(packets[0], packet.data)
			endpoints[0] = packet.endpoint
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{receive}, 0, nil
}
func (bind *meshBind) Close() error {
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.cancel != nil {
		bind.cancel()
		bind.cancel = nil
		bind.senders = nil
	}
	return nil
}
func (bind *meshBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("HTTP mesh has no kernel packet mark")
	}
	return nil
}
func (bind *meshBind) BatchSize() int { return 1 }
func (bind *meshBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	parts := strings.Split(value, "@")
	if len(parts) != 2 || len(parts[0]) == 0 || len(parts[0]) > 128 {
		return nil, errors.New("invalid HTTP mesh endpoint")
	}
	ip, err := netip.ParseAddr(parts[1])
	if err != nil {
		return nil, err
	}
	return meshEndpoint{parts[0], ip}, nil
}
func (bind *meshBind) Send(packets [][]byte, endpoint conn.Endpoint) error {
	peer, ok := endpoint.(meshEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.cancel == nil || bind.context.Err() != nil {
		return net.ErrClosed
	}
	sender := bind.senders[peer.node]
	if sender == nil {
		if len(bind.senders) >= 2048 {
			return errors.New("active HTTP mesh peer limit reached")
		}
		sender = &peerSender{packets: make(chan []byte, 64)}
		bind.senders[peer.node] = sender
		go bind.sendPeer(bind.context, peer.node, sender, bind.inflight)
	}
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > 65507 {
			return errors.New("invalid WireGuard packet size")
		}
		if bind.pending.Add(int64(len(packet))) > 8*1024*1024 {
			bind.pending.Add(-int64(len(packet)))
			return errors.New("HTTP mesh send buffer full")
		}
		copyPacket := append([]byte(nil), packet...)
		select {
		case sender.packets <- copyPacket:
		default:
			bind.pending.Add(-int64(len(packet)))
			return errors.New("HTTP mesh peer send buffer full")
		}
	}
	return nil
}

func (bind *meshBind) sendPeer(ctx context.Context, target string, sender *peerSender, inflight chan struct{}) {
	var carry []byte
	defer func() {
		if carry != nil {
			bind.pending.Add(-int64(len(carry)))
		}
		for {
			select {
			case packet := <-sender.packets:
				bind.pending.Add(-int64(len(packet)))
			default:
				return
			}
		}
	}()
	for {
		first := carry
		carry = nil
		if first == nil {
			idle := time.NewTimer(2 * time.Minute)
			select {
			case <-ctx.Done():
				idle.Stop()
				return
			case first = <-sender.packets:
				idle.Stop()
			case <-idle.C:
				bind.mu.Lock()
				if bind.senders[target] == sender && len(sender.packets) == 0 {
					delete(bind.senders, target)
					bind.mu.Unlock()
					return
				}
				bind.mu.Unlock()
				continue
			}
		}
		packets := []string{base64.StdEncoding.EncodeToString(first)}
		bytes := len(first)
		// WireGuard batches produced in one scheduling slice share one signed
		// request. Different peers have independent queues and retry loops.
		for len(packets) < 32 {
			select {
			case packet := <-sender.packets:
				if bytes+len(packet) > 65536 {
					carry = packet
					goto collected
				}
				packets = append(packets, base64.StdEncoding.EncodeToString(packet))
				bytes += len(packet)
			default:
				goto collected
			}
		}
	collected:
		id, err := randomID()
		if err != nil {
			bind.pending.Add(-int64(bytes))
			return
		}
		until := time.Now().Add(30 * time.Second)
		delay := 50 * time.Millisecond
		for {
			select {
			case <-ctx.Done():
				bind.pending.Add(-int64(bytes))
				return
			case inflight <- struct{}{}:
			}
			call, cancel := context.WithTimeout(ctx, 10*time.Second)
			_, err = bind.api.meshRequest(call, action{Operation: "send", Target: target, BatchID: id, Packets: packets})
			cancel()
			<-inflight
			if err == nil {
				bind.sent.Add(uint64(bytes))
				break
			}
			bind.failures.Add(1)
			var httpError HTTPError
			if errors.As(err, &httpError) && httpError.Status >= 400 && httpError.Status < 500 && httpError.Status != 429 {
				break
			}
			if time.Now().After(until) {
				break
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				bind.pending.Add(-int64(bytes))
				return
			case <-timer.C:
			}
			if delay < time.Second {
				delay *= 2
			}
		}
		bind.pending.Add(-int64(bytes))
	}
}

func (bind *meshBind) poll(ctx context.Context, received chan<- receivedPacket) {
	acknowledgements := []ack{}
	wait := uint64(0)
	delay := 100 * time.Millisecond
	for {
		response, err := bind.api.meshRequest(ctx, action{Operation: "poll", Acknowledgements: &acknowledgements, WaitMS: &wait})
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var status HTTPError
			if errors.As(err, &status) && status.Status == 404 {
				select {
				case bind.fatal <- errors.New("HTTP mesh registration or endpoint no longer exists"):
				default:
				}
				return
			}
			bind.failures.Add(1)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			if delay < 3*time.Second {
				delay *= 2
			}
			continue
		}
		bind.lastPoll.Store(time.Now().UnixNano())
		wait = 10_000
		delay = 100 * time.Millisecond
		acknowledgements = nil
		for _, envelope := range response.Envelopes {
			if envelope.Target != bind.api.nodeID || len(envelope.Packets) > 32 {
				bind.failures.Add(1)
				continue
			}
			peer, err := bind.ensurePeer(ctx, envelope.Source)
			if err != nil {
				bind.failures.Add(1)
				continue
			}
			for _, encoded := range envelope.Packets {
				packet, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil || len(packet) < 4 || len(packet) > 65507 {
					bind.failures.Add(1)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case received <- receivedPacket{packet, peer}:
					bind.receivedBytes.Add(uint64(len(packet)))
				}
			}
			acknowledgements = append(acknowledgements, ack{envelope.Source, envelope.BatchID})
		}
		if acknowledgements == nil {
			acknowledgements = []ack{}
		}
	}
}
