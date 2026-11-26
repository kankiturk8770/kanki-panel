package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

// hostIP an address of this machine other than loopback (the relay never dials loopback); nil = none
func hostIP() net.IP {
	as, _ := net.InterfaceAddrs()
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			return n.IP.To4()
		}
	}
	return nil
}

// testServer: a KANKI MIX server with one user on a real UDP socket, its relay and its keyring
type testServer struct {
	addr  *net.UDPAddr
	relay *dgramRelay
	ring  *obfs.Keyring
	oc    *obfs.PacketConn
}

func startServer(t *testing.T, key []byte, user string) *testServer {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ring := obfs.NewKeyring()
	if err := ring.Set(map[string]string{hex.EncodeToString(key): user}); err != nil {
		t.Fatal(err)
	}
	s := &testServer{addr: udp.LocalAddr().(*net.UDPAddr), ring: ring}
	s.relay = newDgramRelay(func(k byte, b []byte, a net.Addr) {
		if err := s.oc.WritePacket(k, b, a); err != nil {
			t.Logf("write: %v", err)
		}
	})
	s.relay.ring = ring
	s.oc = obfs.NewMulti(udp, ring, s.relay.handle)
	t.Cleanup(func() { s.oc.Close() })
	return s
}

// serveKCP: the server's two KCP listeners as in main (with FEC, and without FEC for KindKCP sent without it),
// each echoing what a stream sends
func (s *testServer) serveKCP(t *testing.T, parity int) {
	t.Helper()
	echo := func(ln *kcp.Listener) {
		for {
			sess, err := ln.AcceptKCP()
			if err != nil {
				return
			}
			go func() {
				tuneKCP(sess) // as handleSession: the MTU fits one obfs packet
				mux, err := smux.Server(sess, smuxConfig())
				if err != nil {
					return
				}
				for {
					st, err := mux.AcceptStream()
					if err != nil {
						return
					}
					go func() { io.Copy(st, st) }()
				}
			}()
		}
	}
	bare, err := kcp.ServeConn(nil, 0, 0, s.oc.Bare())
	if err != nil {
		t.Fatal(err)
	}
	withFEC, err := kcp.ServeConn(nil, 10, parity, s.oc)
	if err != nil {
		t.Fatal(err)
	}
	go echo(bare)
	go echo(withFEC)
}

// client: one phone network (its own UDP socket) speaking to the server with the user's key
type client struct {
	udp *net.UDPConn
	pc  *obfs.PacketConn
}

func newClient(t *testing.T, key []byte) *client {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	pc, err := obfs.New(udp, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	return &client{udp: udp, pc: pc}
}

// read the next packet of kind want (others are skipped) within d
func (c *client) read(t *testing.T, want byte, d time.Duration) ([]byte, bool) {
	t.Helper()
	buf := make([]byte, 65535)
	c.udp.SetReadDeadline(time.Now().Add(d))
	for {
		k, n, _, err := c.pc.ReadPacket(buf)
		if err != nil {
			return nil, false
		}
		if k == want {
			return append([]byte(nil), buf[:n]...), true
		}
	}
}

// pump: the server reads its socket (the handler gets every packet that is not KCP)
func (s *testServer) pump() {
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, _, err := s.oc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
}

var testKey = []byte("0123456789abcdef0123456789abcdef")

// protocol 3: a hello brings a hint (and gaming mode); the phone moves to another network and its game goes on
// at once from the new address with the hint; the game flow is protected from its first packet, DNS is not; a
// replayed hello gets nothing
func TestHelloHintRoamingAndGaming(t *testing.T) {
	host := hostIP()
	if host == nil {
		t.Skip("no address other than loopback")
	}
	s := startServer(t, testKey, "ali")
	s.pump()
	wifi := newClient(t, testKey)
	const sid = 4242
	now := time.Now()
	hello := proto.Hello{Session: sid, Version: proto.HelloVersion, Caps: proto.HelloCapHint | proto.HelloCapGaming, SentAt: now.UnixNano()}
	if err := wifi.pc.WritePacket(proto.KindHello, proto.AppendHello(nil, &hello), s.addr); err != nil {
		t.Fatal(err)
	}
	b, ok := wifi.read(t, proto.KindHelloAck, 2*time.Second)
	if !ok {
		t.Fatal("no answer to the hello")
	}
	ack, err := proto.ParseHelloAck(b)
	if err != nil || ack.Session != sid || ack.Caps != proto.HelloCapHint|proto.HelloCapGaming || ack.LifeSec == 0 || ack.SentAt != hello.SentAt {
		t.Fatalf("answer %+v %v", ack, err)
	}
	if !s.relay.gamingSess(sid) {
		t.Fatal("gaming mode not taken")
	}
	// the game server and a DNS-like server on this machine's own address
	gs, err := net.ListenUDP("udp", &net.UDPAddr{IP: host})
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()
	ga := gs.LocalAddr().(*net.UDPAddr)
	// the phone is on mobile data now: a new socket, a new address, the same session and key
	cell := newClient(t, testKey)
	up := proto.UDPUp{Session: sid, Flow: 1, Seq: 1, DstPort: uint16(ga.Port)} // no FlagGame: gaming mode says it
	copy(up.DstIP[:], ga.IP.To4())
	pkt, err := cell.pc.SealHinted(ack.Hint, proto.KindUDPUp, proto.AppendUDPUp(nil, &up, []byte("shot")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cell.udp.WriteTo(pkt, s.addr); err != nil {
		t.Fatal(err)
	}
	gs.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, 100)
	n, from, err := gs.ReadFromUDP(got)
	if err != nil || string(got[:n]) != "shot" {
		t.Fatalf("the game did not get the packet from the new network: %q %v", got[:n], err)
	}
	if u := s.ring.UserOf(cell.udp.LocalAddr()); u == nil || u.Name != "ali" {
		t.Fatal("the new address is not the user's")
	}
	s.relay.mu.Lock()
	f := s.relay.flows[flowKey{sid, 1}]
	s.relay.mu.Unlock()
	if f == nil || !f.s.game.Load() {
		t.Fatal("the flow of a gaming session is not a game from its first packet")
	}
	if _, playing := downLimit.rateOf("ali", time.Now()); !playing {
		t.Fatal("the user's downloads do not give way to the game")
	}
	// the answer goes back to the phone's new address
	if _, err := gs.WriteToUDP([]byte("hit"), from); err != nil {
		t.Fatal(err)
	}
	if d, ok := cell.read(t, proto.KindUDPDown, 2*time.Second); !ok || !bytes.HasSuffix(d, []byte("hit")) {
		t.Fatal("the answer did not reach the new network")
	}
	// a DNS flow of the same session is never a game
	s.relay.mu.Lock()
	df := &udpFlow{key: flowKey{sid, 2}, dstPort: dnsPort}
	s.relay.flows[df.key] = df
	s.relay.mu.Unlock()
	s.relay.setGaming(sid, true, time.Now())
	if df.s.game.Load() {
		t.Fatal("DNS taken for a game")
	}
	// a hello sent long ago (copied and sent again) gets no answer and no hint
	old := hello
	old.SentAt = now.Add(-10 * time.Minute).UnixNano()
	wifi.pc.WritePacket(proto.KindHello, proto.AppendHello(nil, &old), s.addr)
	if _, ok := wifi.read(t, proto.KindHelloAck, 300*time.Millisecond); ok {
		t.Fatal("a replayed hello was answered")
	}
	if s.ring.Hinted() != 1 {
		t.Fatalf("%d sessions with hints", s.ring.Hinted())
	}
}

// an app from before never says hello: its 16-byte ping still gets its pong, unchanged
func TestOldAppUnchanged(t *testing.T) {
	s := startServer(t, testKey, "old")
	s.pump()
	c := newClient(t, testKey)
	ping := make([]byte, proto.PingLen)
	ping[7] = 9
	c.pc.WritePacket(proto.KindPing, ping, s.addr)
	b, ok := c.read(t, proto.KindPong, 2*time.Second)
	if !ok || !bytes.Equal(b, ping) {
		t.Fatal("the old ping lost its pong")
	}
	if s.ring.Hinted() != 0 {
		t.Fatal("a hint without a hello")
	}
}

// KCP from an app on a link with FEC off (fec=10-0, KindKCP without framing) reaches the listener without FEC
// and works; an app still on a link with FEC (10-3, framed) reaches the listener with FEC and works too
func TestKCPWithAndWithoutFEC(t *testing.T) {
	s := startServer(t, testKey, "kcp")
	s.serveKCP(t, 3)
	for _, parity := range []int{0, 3} {
		c := newClient(t, testKey)
		sess, err := kcp.NewConn(s.addr.String(), nil, 10, parity, c.pc)
		if err != nil {
			t.Fatal(err)
		}
		tuneKCP(sess)
		mux, err := smux.Client(sess, smuxConfig())
		if err != nil {
			t.Fatal(err)
		}
		st, err := mux.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		msg := bytes.Repeat([]byte{byte('a' + parity)}, 5000)
		if _, err := st.Write(msg); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(msg))
		st.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(st, got); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("fec 10-%d: the echo did not come back: %v", parity, err)
		}
		mux.Close()
		sess.Close()
	}
	if !obfs.FECFramed([]byte{1, 0, 0, 0, 0xf1, 0}) || obfs.FECFramed([]byte{1, 0, 0, 0, 81, 0}) {
		t.Fatal("FEC framing told wrong")
	}
}

// the downloads: no limit with no game; while a game plays a token bucket at the line's rate; a lossy report cuts
// it at once, clean ones raise it again, within the bounds
func TestDownloadsGiveWayToTheGame(t *testing.T) {
	l := &limiter{users: map[string]*userBucket{}}
	now := time.Now()
	if d := l.delay("u", 1<<20, now); d != 0 {
		t.Fatal("a limit with no game")
	}
	l.noteGame("u", now)
	if d := l.delay("u", bucketMax, now); d != 0 {
		t.Fatalf("the bucket's own bytes waited %v", d)
	}
	d := l.delay("u", startRate, now)
	if d < 900*time.Millisecond || d > 1100*time.Millisecond {
		t.Fatalf("a second's worth over the bucket waits %v, want ~1s", d)
	}
	l.report("u", 50)
	if r, _ := l.rateOf("u", now); r != startRate*cutBy {
		t.Fatalf("a lossy report: rate %v", r)
	}
	for i := 0; i < 200; i++ {
		l.report("u", 0)
	}
	if r, _ := l.rateOf("u", now); r != maxRate {
		t.Fatalf("clean reports: rate %v", r)
	}
	for i := 0; i < 200; i++ {
		l.report("u", 900)
	}
	if r, _ := l.rateOf("u", now); r != minRate {
		t.Fatalf("a broken line: rate %v", r)
	}
	// the game stopped: no limit again; and long after, the user is forgotten
	later := now.Add(gameActive + time.Second)
	if d := l.delay("u", 1<<20, later); d != 0 {
		t.Fatal("still limited after the game")
	}
	l.gc(now.Add(time.Hour))
	if _, ok := l.users["u"]; ok {
		t.Fatal("not forgotten")
	}
	// a paced reader: what it reads is the stream's, unchanged
	l.noteGame("p", time.Now())
	var out bytes.Buffer
	if _, err := io.Copy(&out, pacedReader{r: bytes.NewReader(bytes.Repeat([]byte("z"), 50000)), user: "p", l: l}); err != nil || out.Len() != 50000 {
		t.Fatalf("paced copy: %d %v", out.Len(), err)
	}
}

// the loss of /health: weighted by the packets each session counted, only the last minute
func TestHealthLossAverage(t *testing.T) {
	now := time.Now()
	lossBook.mu.Lock()
	lossBook.m = map[uint64]lossNote{}
	lossBook.mu.Unlock()
	noteLoss(1, 10, 100, now)
	noteLoss(2, 40, 300, now)
	noteLoss(3, 900, 50, now.Add(-2*lossWindow))
	noteLoss(4, 500, 0, now)
	avg, n := lossAverage(now)
	if n != 2 || avg != 33 {
		t.Fatalf("average %d‰ over %d sessions, want 33 over 2", avg, n)
	}
	h := health(nil, now)
	if h["loss_permille"] != 33 || h["fec_legacy"] != legacyParity() {
		t.Fatalf("%v", h)
	}
}
