/* SPDX-License-Identifier: MIT */

package conn

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// A failed UDP destination must not terminate the shared RIO receive loop.
func TestWinRingBindReceivesAfterPortUnreachable(t *testing.T) {
	for _, tc := range []struct {
		network, host string
		receiver      int
	}{
		{"udp4", "127.0.0.1", 0}, {"udp6", "::1", 1},
	} {
		t.Run(tc.network, func(t *testing.T) {
			bind, ok := NewWinRingBind().(*WinRingBind)
			if !ok {
				t.Skip("Windows registered I/O unavailable")
			}
			receive, port, err := bind.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			defer bind.Close()
			failed, err := net.ListenUDP(tc.network, &net.UDPAddr{IP: net.ParseIP(tc.host)})
			if err != nil {
				t.Fatal(err)
			}
			endpoint, err := bind.ParseEndpoint(failed.LocalAddr().String())
			if err != nil {
				failed.Close()
				t.Fatal(err)
			}
			failed.Close() // Send to a closed port to provoke ICMP port unreachable.
			sender, err := net.DialUDP(tc.network, nil, &net.UDPAddr{IP: net.ParseIP(tc.host), Port: int(port)})
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			type result struct {
				data []byte
				err  error
			}
			received := make(chan result, 1)
			go func() {
				buf := make([]byte, 2048)
				sizes := []int{0}
				endpoints := make([]Endpoint, 1)
				_, err := receive[tc.receiver]([][]byte{buf}, sizes, endpoints)
				received <- result{buf[:sizes[0]], err}
			}()
			if err := bind.Send([][]byte{[]byte("closed destination")}, endpoint); err != nil {
				t.Fatal(err)
			}
			// Let the asynchronous ICMP error arrive before sending healthy traffic.
			time.Sleep(100 * time.Millisecond)
			payload := []byte("receive loop survived")
			if _, err := sender.Write(payload); err != nil {
				t.Fatal(err)
			}
			select {
			case got := <-received:
				if got.err != nil {
					t.Fatalf("receive failed after unreachable destination: %v", got.err)
				}
				if !bytes.Equal(got.data, payload) {
					t.Fatalf("received %q, want %q", got.data, payload)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("receive did not recover after unreachable destination")
			}
		})
	}
}
