package session

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"path/filepath"
	"testing"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/obfuscation"
	"github.com/kankipro/klink/internal/store"
	"github.com/kankipro/klink/internal/transport"
)

type udpFixture struct {
	db        *store.Store
	manager   *Manager
	listener  *transport.UDPListener
	serverKey kcrypto.KeyPair
	clientKey kcrypto.KeyPair
	received  chan []byte
}

func newUDPFixture(t *testing.T, deviceLimit int) *udpFixture {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "klink.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	f := &udpFixture{db: db, received: make(chan []byte, 64)}
	f.clientKey, _ = kcrypto.GenerateKey()
	f.serverKey, _ = kcrypto.GenerateKey()
	u := &store.User{Name: "robust", PublicKey: base64.StdEncoding.EncodeToString(f.clientKey.Public[:]),
		Token: "robust-token", Enabled: true, DeviceLimit: deviceLimit}
	if err := db.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	f.listener, err = transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.listener.Close() })
	f.manager, err = NewManager(Config{ServerKey: f.serverKey, Store: db, Obfuscation: obfuscation.Random{},
		RekeyInterval: time.Hour,
		OnSession: func(s *Session) {
			s.SetHandlers(func(b []byte) { f.received <- append([]byte(nil), b...) }, nil)
		}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.manager.Close() })
	go f.listener.Serve(2, func(p transport.Packet) { f.manager.HandlePacket(f.listener, p) })
	return f
}

type handshakeResult struct {
	client  *testClient
	sid     [16]byte
	binding []byte
	m3raw   []byte
	out     *kcrypto.Channel
}

func (f *udpFixture) handshake(t *testing.T) handshakeResult {
	t.Helper()
	c := newTestClient(t, f.listener.LocalAddr().(*net.UDPAddr), obfuscation.Random{})
	t.Cleanup(func() { c.conn.Close() })
	hs, _ := kcrypto.NewInitiator(f.clientKey, f.serverKey.Public)
	var hello [16]byte
	_, _ = rand.Read(hello[:])
	m1, _, _, _ := hs.WriteMessage(nil)
	c.write(t, append(append([]byte{Version, msgHello1}, hello[:]...), m1...))
	raw2 := c.read(t)
	if _, _, _, err := hs.ReadMessage(raw2[18:]); err != nil {
		t.Fatal(err)
	}
	m3, binding, _, err := hs.WriteMessage(nil)
	if err != nil {
		t.Fatal(err)
	}
	m3raw := append(append([]byte{Version, msgHello3}, hello[:]...), m3...)
	c.write(t, m3raw)
	ack := c.read(t)
	if len(ack) != 34 || ack[1] != msgHelloAck {
		t.Fatalf("bad ACK %x", ack)
	}
	var sid [16]byte
	copy(sid[:], ack[18:34])
	k1, _, _ := kcrypto.ChannelKeys(binding)
	out, _ := kcrypto.NewChannel(k1)
	return handshakeResult{client: c, sid: sid, binding: binding, m3raw: m3raw, out: out}
}

func dataPacket(t *testing.T, h handshakeResult, payload string) []byte {
	t.Helper()
	sealed, _, err := h.out.Seal([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte{Version, msgData}, h.sid[:]...), sealed...)
}

func expect(t *testing.T, ch <-chan []byte, want string) {
	t.Helper()
	select {
	case b := <-ch:
		if string(b) != want {
			t.Fatalf("got %q want %q", b, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("%q not delivered", want)
	}
}

// A lost ACK on UDP makes the client resend message 3; it must get the same
// session instead of silence (which used to leave an orphan session holding
// the user's only device slot).
func TestLostAckIsRetransmitted(t *testing.T) {
	f := newUDPFixture(t, 1)
	h := f.handshake(t)
	h.client.write(t, h.m3raw)
	ack := h.client.read(t)
	if len(ack) != 34 || ack[1] != msgHelloAck || !bytes.Equal(ack[18:34], h.sid[:]) {
		t.Fatalf("retransmitted ACK differs: %x", ack)
	}
	if n := f.manager.Snapshot().OnlineSessions; n != 1 {
		t.Fatalf("duplicate message 3 created %d sessions", n)
	}
}

// With device_limit=1, a client that reconnects after its previous session
// went silent must not be locked out until idle_timeout.
func TestStaleSessionIsReplacedWithinDeviceLimit(t *testing.T) {
	oldStale, oldUnused := staleSessionAge, unusedSessionAge
	staleSessionAge, unusedSessionAge = 200*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { staleSessionAge, unusedSessionAge = oldStale, oldUnused })

	f := newUDPFixture(t, 1)
	first := f.handshake(t)
	first.client.write(t, dataPacket(t, first, "first"))
	expect(t, f.received, "first")

	// An active session keeps its slot: a second device is refused.
	c := newTestClient(t, f.listener.LocalAddr().(*net.UDPAddr), obfuscation.Random{})
	defer c.conn.Close()
	hs, _ := kcrypto.NewInitiator(f.clientKey, f.serverKey.Public)
	hello := [16]byte{9}
	m1, _, _, _ := hs.WriteMessage(nil)
	c.write(t, append(append([]byte{Version, msgHello1}, hello[:]...), m1...))
	raw2 := c.read(t)
	_, _, _, _ = hs.ReadMessage(raw2[18:])
	m3, _, _, _ := hs.WriteMessage(nil)
	c.write(t, append(append([]byte{Version, msgHello3}, hello[:]...), m3...))
	_ = c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := c.conn.Read(make([]byte, 2048)); err == nil {
		t.Fatal("second concurrent device admitted")
	}

	// After the first session goes silent, a reconnect takes over.
	time.Sleep(300 * time.Millisecond)
	second := f.handshake(t)
	second.client.write(t, dataPacket(t, second, "second"))
	expect(t, f.received, "second")
	if n := f.manager.Snapshot().OnlineSessions; n != 1 {
		t.Fatalf("expected one session after replacement, got %d", n)
	}
}

// Moving an established session to a new TCP connection: the client writes the
// first frame with bootstrap framing, upgrades, and immediately writes more.
// The server must read the second frame with the upgraded mask.
func TestTCPMigrationBackToBackFrames(t *testing.T) {
	f := newUDPFixture(t, 0)
	h := f.handshake(t)
	h.client.write(t, dataPacket(t, h, "udp"))
	expect(t, f.received, "udp")

	tl, err := transport.ListenTCPHandler("127.0.0.1:0", kcrypto.Prologue, f.manager.HandlePacket)
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	conn, err := net.Dial("tcp", tl.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	framer := transport.NewFramer(kcrypto.Prologue)
	profile := obfuscation.Random{}
	var batch bytes.Buffer
	if err := framer.WriteFrame(&batch, profile.Wrap(dataPacket(t, h, "tcp-1"))); err != nil {
		t.Fatal(err)
	}
	framer.Upgrade(h.binding)
	for _, p := range []string{"tcp-2", "tcp-3"} {
		if err := framer.WriteFrame(&batch, profile.Wrap(dataPacket(t, h, p))); err != nil {
			t.Fatal(err)
		}
	}
	// One write: all three frames arrive in the same TCP segment.
	if _, err := conn.Write(batch.Bytes()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tcp-1", "tcp-2", "tcp-3"} {
		expect(t, f.received, want)
	}
}

func TestPendingHandshakesLimitedPerSource(t *testing.T) {
	f := newUDPFixture(t, 0)
	c := newTestClient(t, f.listener.LocalAddr().(*net.UDPAddr), obfuscation.Random{})
	defer c.conn.Close()
	for i := 0; i < maxPendingPerIP+10; i++ {
		hs, _ := kcrypto.NewInitiator(f.clientKey, f.serverKey.Public)
		var hello [16]byte
		_, _ = rand.Read(hello[:])
		m1, _, _, _ := hs.WriteMessage(nil)
		c.write(t, append(append([]byte{Version, msgHello1}, hello[:]...), m1...))
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.manager.mu.RLock()
		n := len(f.manager.pending)
		f.manager.mu.RUnlock()
		if n == maxPendingPerIP {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.manager.mu.RLock()
	defer f.manager.mu.RUnlock()
	t.Fatalf("pending handshakes from one source: %d (limit %d)", len(f.manager.pending), maxPendingPerIP)
}
