// The migration acceptance probe keeps its identity, memory and TCP sockets
// exclusively in process memory. A cold start or reconnect cannot pass.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

type state struct {
	sync.Mutex
	Nonce       string `json:"nonce"`
	MemoryHash  string `json:"memory_hash"`
	StartedNS   int64  `json:"started_ns"`
	GuestPID    int    `json:"guest_pid"`
	Connections int    `json:"connections"`
	Sequence    int    `json:"sequence"`
	Memory      []byte `json:"-"`
}

func main() {
	mem := make([]byte, 32<<20)
	if _, err := rand.Read(mem); err != nil {
		panic(err)
	}
	hash := sha256.Sum256(mem)
	s := &state{Nonce: hex.EncodeToString(mem[:32]), MemoryHash: hex.EncodeToString(hash[:]),
		StartedNS: time.Now().UnixNano(), GuestPID: os.Getpid(), Memory: mem}
	listener, err := net.Listen("tcp4", "0.0.0.0:6069")
	if err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		s.Lock()
		s.Connections++
		s.Unlock()
		go func() {
			defer conn.Close()
			reader := bufio.NewScanner(conn)
			for reader.Scan() {
				if reader.Text() != "state" {
					return
				}
				s.Lock()
				s.Sequence++
				// Read the restored bytes, rather than trusting a saved hash.
				actual := sha256.Sum256(s.Memory)
				s.MemoryHash = hex.EncodeToString(actual[:])
				payload, err := json.Marshal(s)
				s.Unlock()
				if err != nil {
					return
				}
				if _, err := fmt.Fprintf(conn, "%s\n", payload); err != nil {
					return
				}
			}
		}()
	}
}
