package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const tcpPreface = "HNTCP1\r\n"

func ValidateTCPEndpoints(endpoints []string) error {
	if len(endpoints) > 8 {
		return errors.New("too many TCP tunnel endpoints")
	}
	for _, endpoint := range endpoints {
		host, portText, err := net.SplitHostPort(endpoint)
		ip, ipErr := netip.ParseAddr(host)
		port, portErr := strconv.Atoi(portText)
		if err != nil || ipErr != nil || portErr != nil || port < 1 || port > 65535 || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			return errors.New("invalid public TCP tunnel endpoint")
		}
	}
	return nil
}

type tcpSession struct {
	connection net.Conn
	writer     sync.Mutex
}

func (p *Proxy) openingBody(first []byte) ([]byte, error) {
	p.mu.Lock()
	diagnostics, err := json.Marshal(p.status.Failures)
	p.mu.Unlock()
	if err != nil || len(diagnostics) > 2048 {
		return nil, errors.New("invalid transport diagnostics")
	}
	body := append([]byte("HNT1"), byte(len(diagnostics)>>8), byte(len(diagnostics)))
	body = append(body, diagnostics...)
	return append(body, first...), nil
}
func (p *Proxy) openTCP(ctx context.Context, endpoint string, first []byte) (*tcpSession, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	connection, err := p.dialEndpoint(ctx, "tcp", endpoint)
	if err != nil {
		p.recordDNSError(err)
		return nil, errors.New("TCP tunnel connection failed")
	}
	stop := context.AfterFunc(ctx, func() { connection.Close() })
	defer stop()
	committed := false
	defer func() {
		if !committed {
			connection.Close()
		}
	}()
	connection.SetDeadline(time.Now().Add(4 * time.Second))
	body, err := p.openingBody(first)
	if err != nil {
		return nil, err
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(random)
	timestamp := time.Now().Unix()
	header, err := json.Marshal(map[string]any{"node": p.configuration.ClientNodeID, "relay": false, "timestamp": timestamp, "nonce": nonce, "proof": transportProof(p.authKey, p.configuration.ClientNodeID, p.configuration.GatewayNodeID, timestamp, nonce, body)})
	if err != nil || len(header) > 4096 || len(body) > transportMaximumPacket+2054 {
		return nil, errors.New("invalid TCP opening frame")
	}
	frame := bytes.NewBufferString(tcpPreface)
	binary.Write(frame, binary.BigEndian, uint16(len(header)))
	binary.Write(frame, binary.BigEndian, uint32(len(body)))
	frame.Write(header)
	frame.Write(body)
	if _, err = io.Copy(connection, frame); err != nil {
		return nil, errors.New("TCP tunnel authentication failed")
	}
	reply := []byte{1}
	if _, err = io.ReadFull(connection, reply); err != nil || reply[0] != 0 {
		return nil, errors.New("TCP tunnel authentication failed")
	}
	connection.SetDeadline(time.Time{})
	committed = true
	p.mu.Lock()
	p.status.ResolvedEndpoint = connection.RemoteAddr().String()
	p.mu.Unlock()
	return &tcpSession{connection: connection}, nil
}
func (session *tcpSession) send(body []byte) error {
	session.writer.Lock()
	defer session.writer.Unlock()
	session.connection.SetWriteDeadline(time.Now().Add(20 * time.Second))
	_, err := io.Copy(session.connection, bytes.NewReader(body))
	return err
}
func (session *tcpSession) receive() ([]byte, error) {
	session.connection.SetReadDeadline(time.Now().Add(30 * time.Second))
	header := make([]byte, 2)
	if _, err := io.ReadFull(session.connection, header); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(header))
	if size == 0 {
		return nil, session.send([]byte{0, 0})
	}
	if size > transportMaximumPacket {
		return nil, errors.New("invalid TCP packet length")
	}
	body := make([]byte, size+2)
	copy(body, header)
	_, err := io.ReadFull(session.connection, body[2:])
	return body, err
}
func (session *tcpSession) close() { session.connection.Close() }
