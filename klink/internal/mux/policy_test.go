package mux

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestDefaultPolicyBlocksServerInternalDestinations(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{}, 1)
	go func() {
		if c, err := listener.Accept(); err == nil {
			accepted <- struct{}{}
			c.Close()
		}
	}()
	sender := &fakeSender{frames: make(chan []byte, 4)}
	m := New(sender)
	defer m.Close()
	open, _ := BuildOpen(3, NetworkTCP, "localhost", uint16(listener.Addr().(*net.TCPAddr).Port))
	m.HandleFrame(open)
	if id, code, err := ParseStatus(receive(t, sender.frames)); err != nil || id != 3 || code != StatusFailed {
		t.Fatalf("loopback destination not refused: %d %v", code, err)
	}
	select {
	case <-accepted:
		t.Fatal("connection to loopback was made")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestPolicyRanges(t *testing.T) {
	var p Policy
	for _, s := range []string{"127.0.0.1", "::1", "169.254.169.254", "10.1.2.3", "192.168.1.1", "100.64.0.1",
		"0.0.0.0", "224.0.0.1", "255.255.255.255", "fe80::1", "fd00::1", "::ffff:127.0.0.1"} {
		if p.allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s allowed by default", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"} {
		if !p.allowed(netip.MustParseAddr(s)) {
			t.Errorf("%s blocked", s)
		}
	}
	if !(Policy{AllowPrivate: true}).allowed(netip.MustParseAddr("10.0.0.1")) {
		t.Error("AllowPrivate ignored")
	}
}

// Open must not block the caller (the shared network reader) while dialing.
func hangingDial(ctx context.Context, _, _ string) (net.Conn, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestOpenDoesNotBlockAndCloseCancelsDial(t *testing.T) {
	sender := &fakeSender{frames: make(chan []byte, 4)}
	m := New(sender)
	m.dialContext = hangingDial
	defer m.Close()
	open, _ := BuildOpen(11, NetworkTCP, "192.0.2.1", 9)
	start := time.Now()
	m.HandleFrame(open)
	if time.Since(start) > 100*time.Millisecond {
		t.Fatal("HandleFrame blocked on dial")
	}
	m.HandleFrame(BuildClose(11))
	m.mu.Lock()
	pending := len(m.opening)
	m.mu.Unlock()
	if pending != 0 {
		t.Fatal("close did not cancel the pending dial")
	}
}

func TestStreamLimit(t *testing.T) {
	sender := &fakeSender{frames: make(chan []byte, MaxStreams+8)}
	m := New(sender)
	m.dialContext = hangingDial
	defer m.Close()
	for i := 1; i <= MaxStreams+1; i++ {
		open, _ := BuildOpen(uint32(i), NetworkTCP, "192.0.2.1", 9)
		m.HandleFrame(open)
	}
	status := receive(t, sender.frames)
	if id, code, _ := ParseStatus(status); id != MaxStreams+1 || code != StatusFailed {
		t.Fatalf("stream over the limit not refused: id=%d code=%d", id, code)
	}
}
