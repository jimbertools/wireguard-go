/* SPDX-License-Identifier: MIT */

package device

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun/tuntest"
)

type handshakeRebindTestBind struct {
	conn.Bind
	opens   atomic.Int32
	opening chan struct{}
	resume  chan struct{}
	sent    chan int
}

func (b *handshakeRebindTestBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	if b.opens.Add(1) == 2 {
		close(b.opening)
		<-b.resume
	}
	return nil, port, nil
}

func (*handshakeRebindTestBind) Close() error { return nil }

func (b *handshakeRebindTestBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	for _, buf := range bufs {
		b.sent <- len(buf)
	}
	return nil
}

func newHandshakeRebindTestPeer(t *testing.T) (*Device, *Peer, *handshakeRebindTestBind, func()) {
	t.Helper()
	b := &handshakeRebindTestBind{
		Bind: conn.NewDefaultBind(), opening: make(chan struct{}),
		resume: make(chan struct{}), sent: make(chan int, 16),
	}
	tun := tuntest.NewChannelTUN().TUN()
	<-tun.Events() // Bring the device up explicitly after adding the peer.
	d := NewDevice(tun, b, NewLogger(LogLevelSilent, ""))
	privateKey, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.SetPrivateKey(privateKey); err != nil {
		t.Fatal(err)
	}
	remoteKey, err := newPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.NewPeer(remoteKey.publicKey())
	if err != nil {
		t.Fatal(err)
	}
	p.endpoint.val, err = b.ParseEndpoint("127.0.0.1:51820")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	// Exercise the real Windows callback on Windows, and the same recovery
	// helper under the real timer lock on other platforms.
	p.timers.retransmitHandshake = p.NewTimer(func(peer *Peer) {
		if runtime.GOOS == "windows" {
			expiredRetransmitHandshake(peer)
		} else {
			peer.timers.handshakeAttempts.Add(1)
			peer.rebindAndRetryHandshake()
		}
	})
	var once sync.Once
	release := func() { once.Do(func() { close(b.resume) }) }
	t.Cleanup(func() {
		release()
		done := make(chan struct{})
		go func() { d.Close(); close(done) }()
		awaitHandshakeRebind(t, done, "device shutdown")
	})
	return d, p, b, release
}

func awaitHandshakeRebind(t *testing.T, done <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for %s", operation)
	}
}

func TestHandshakeRebindDoesNotBlockPeerRemoval(t *testing.T) {
	d, p, b, release := newHandshakeRebindTestPeer(t)
	p.timers.retransmitHandshake.Mod(time.Millisecond)
	awaitHandshakeRebind(t, b.opening, "rebind to enter Open")
	removed := make(chan struct{})
	go func() {
		d.RemovePeer(p.handshake.remoteStatic)
		close(removed)
	}()
	// Removal must finish even while the new socket is still opening. The
	// synchronous implementation waits for the timer here and deadlocks.
	awaitHandshakeRebind(t, removed, "peer removal during rebind")
	release()
	// Recovery owns device.state, so Close also waits for recovery to finish.
	done := make(chan struct{})
	go func() { d.Close(); close(done) }()
	awaitHandshakeRebind(t, done, "shutdown after peer removal")
	select {
	case <-b.sent:
		t.Fatal("retried a handshake for the removed peer")
	default:
	}
	if p.timers.retransmitHandshake.IsPending() {
		t.Fatal("rearmed the removed peer's retry timer")
	}
}

func TestHandshakeRebindFinishesBeforeRetry(t *testing.T) {
	_, p, b, release := newHandshakeRebindTestPeer(t)
	p.timers.retransmitHandshake.Mod(time.Millisecond)
	awaitHandshakeRebind(t, b.opening, "rebind to enter Open")
	select {
	case <-b.sent:
		t.Fatal("sent a handshake before the new socket was open")
	default:
	}
	release()
	select {
	case size := <-b.sent:
		if size != MessageInitiationSize {
			t.Fatalf("sent %d bytes, want handshake initiation (%d)", size, MessageInitiationSize)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("did not retry the handshake after rebinding")
	}
}
