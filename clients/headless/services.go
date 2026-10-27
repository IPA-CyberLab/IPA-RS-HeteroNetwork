package headless

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

func pump(ctx context.Context, left, right net.Conn) {
	defer left.Close()
	defer right.Close()
	stop := context.AfterFunc(ctx, func() { left.Close(); right.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		io.Copy(left, right)
		if half, ok := left.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
		close(done)
	}()
	io.Copy(right, left)
	if half, ok := right.(interface{ CloseWrite() error }); ok {
		half.CloseWrite()
	}
	<-done
}

func serveStreams(ctx context.Context, listener net.Listener, handler func(net.Conn)) {
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	limit := make(chan struct{}, 256)
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case limit <- struct{}{}:
			go func() { defer func() { <-limit }(); handler(connection) }()
		default:
			connection.Close()
		}
	}
}

func (node *Node) PublishTCP(port uint16, target string) (net.Listener, error) {
	listener, err := node.ListenTCP(port)
	if err != nil {
		return nil, err
	}
	go serveStreams(node.ctx, listener, func(incoming net.Conn) {
		outgoing, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(node.ctx, "tcp", target)
		if err != nil {
			incoming.Close()
			return
		}
		pump(node.ctx, incoming, outgoing)
	})
	return listener, nil
}

func (node *Node) ForwardTCP(listen, target string) (net.Listener, error) {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	go serveStreams(node.ctx, listener, func(incoming net.Conn) {
		call, cancel := context.WithTimeout(node.ctx, 10*time.Second)
		defer cancel()
		outgoing, err := node.DialContext(call, "tcp", target)
		if err != nil {
			incoming.Close()
			return
		}
		pump(node.ctx, incoming, outgoing)
	})
	return listener, nil
}

func (node *Node) SOCKS5(listen string) (net.Listener, error) {
	host, _, err := net.SplitHostPort(listen)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() {
		return nil, errors.New("SOCKS listener must use a loopback IP")
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	go serveStreams(node.ctx, listener, func(incoming net.Conn) {
		incoming.SetDeadline(time.Now().Add(10 * time.Second))
		var greeting [2]byte
		if _, err := io.ReadFull(incoming, greeting[:]); err != nil || greeting[0] != 5 {
			incoming.Close()
			return
		}
		methods := make([]byte, int(greeting[1]))
		if _, err := io.ReadFull(incoming, methods); err != nil {
			incoming.Close()
			return
		}
		permitted := false
		for _, method := range methods {
			if method == 0 {
				permitted = true
			}
		}
		if !permitted {
			incoming.Write([]byte{5, 255})
			incoming.Close()
			return
		}
		incoming.Write([]byte{5, 0})
		var request [4]byte
		if _, err := io.ReadFull(incoming, request[:]); err != nil || request[0] != 5 || request[1] != 1 || request[2] != 0 {
			incoming.Close()
			return
		}
		var host string
		switch request[3] {
		case 1:
			var address [4]byte
			if _, err := io.ReadFull(incoming, address[:]); err != nil {
				incoming.Close()
				return
			}
			host = net.IP(address[:]).String()
		case 4:
			var address [16]byte
			if _, err := io.ReadFull(incoming, address[:]); err != nil {
				incoming.Close()
				return
			}
			host = net.IP(address[:]).String()
		case 3:
			var length [1]byte
			if _, err := io.ReadFull(incoming, length[:]); err != nil {
				incoming.Close()
				return
			}
			address := make([]byte, int(length[0]))
			if _, err := io.ReadFull(incoming, address); err != nil {
				incoming.Close()
				return
			}
			host = string(address)
		default:
			incoming.Close()
			return
		}
		var port [2]byte
		if _, err := io.ReadFull(incoming, port[:]); err != nil {
			incoming.Close()
			return
		}
		call, cancel := context.WithTimeout(node.ctx, 8*time.Second)
		outgoing, err := node.DialContext(call, "tcp", net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))))
		cancel()
		if err != nil {
			incoming.Write([]byte{5, 4, 0, 1, 0, 0, 0, 0, 0, 0})
			incoming.Close()
			return
		}
		incoming.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
		incoming.SetDeadline(time.Time{})
		pump(node.ctx, incoming, outgoing)
	})
	return listener, nil
}

func (node *Node) PublishUDP(port uint16, target string) (io.Closer, error) {
	incoming, err := node.ListenUDP(port)
	if err != nil {
		return nil, err
	}
	remote, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		incoming.Close()
		return nil, err
	}
	type session struct {
		connection *net.UDPConn
		address    net.Addr
	}
	var mutex sync.Mutex
	sessions := make(map[string]*session)
	stop := context.AfterFunc(node.ctx, func() { incoming.Close() })
	go func() {
		defer stop()
		defer incoming.Close()
		defer func() {
			mutex.Lock()
			defer mutex.Unlock()
			for _, session := range sessions {
				session.connection.Close()
			}
		}()
		buffer := make([]byte, 65507)
		for {
			count, address, err := incoming.ReadFrom(buffer)
			if err != nil {
				return
			}
			key := address.String()
			mutex.Lock()
			current := sessions[key]
			if current == nil && len(sessions) < 256 {
				connection, err := net.DialUDP("udp", nil, remote)
				if err == nil {
					current = &session{connection, address}
					sessions[key] = current
					go func(current *session, key string) {
						defer current.connection.Close()
						defer func() { mutex.Lock(); delete(sessions, key); mutex.Unlock() }()
						reply := make([]byte, 65507)
						for {
							current.connection.SetReadDeadline(time.Now().Add(60 * time.Second))
							n, err := current.connection.Read(reply)
							if err != nil {
								return
							}
							if _, err = incoming.WriteTo(reply[:n], current.address); err != nil {
								return
							}
						}
					}(current, key)
				}
			}
			mutex.Unlock()
			if current != nil {
				current.connection.Write(buffer[:count])
			}
		}
	}()
	return incoming, nil
}
