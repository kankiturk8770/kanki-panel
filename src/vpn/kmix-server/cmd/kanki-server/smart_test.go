package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"kanki-tunnel/internal/game"
	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

// a repair and a report of the largest protected packet fit one obfs packet
func TestSmartFitsOnePacket(t *testing.T) {
	if proto.RepairUpHdr+game.RepHdr+game.MaxBlock > obfs.MaxPayload {
		t.Fatal("an upload repair does not fit")
	}
	if proto.RepairDownHdr+game.RepHdr+game.MaxBlock > obfs.MaxPayload {
		t.Fatal("a download repair does not fit")
	}
}

type sent struct {
	mu sync.Mutex
	l  []struct {
		kind byte
		b    []byte
	}
}

func (s *sent) send(k byte, b []byte, _ net.Addr) {
	s.mu.Lock()
	s.l = append(s.l, struct {
		kind byte
		b    []byte
	}{k, append([]byte(nil), b...)})
	s.mu.Unlock()
}

func (s *sent) of(k byte) [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var o [][]byte
	for _, x := range s.l {
		if x.kind == k {
			o = append(o, x.b)
		}
	}
	return o
}

// an app that reports gets an answer with the loss of its uploads; an old app (pings only) gets only pongs;
// an upload packet lost on the way comes back from the app's repairs and goes on to the game server once
func TestSmartRelay(t *testing.T) {
	// the relay never dials loopback: the "game server" listens on this machine's own address
	var host net.IP
	if as, _ := net.InterfaceAddrs(); as != nil {
		for _, a := range as {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
				host = n.IP.To4()
				break
			}
		}
	}
	if host == nil {
		t.Skip("no address other than loopback")
	}
	gs, err := net.ListenUDP("udp", &net.UDPAddr{IP: host})
	if err != nil {
		t.Fatal(err)
	}
	defer gs.Close()
	var out sent
	r := newDgramRelay(out.send)
	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
	const sid = 77

	// the old app: a 16-byte ping, a pong, nothing else
	var ping [proto.PingLen]byte
	ping[7] = sid
	r.handle(proto.KindPing, ping[:], client)
	if len(out.of(proto.KindPong)) != 1 || len(out.of(proto.KindStat)) != 0 {
		t.Fatal("an old app got more than its pong")
	}

	// the app says it protects its uploads (step 3)
	st0 := proto.Stat{Session: sid, Version: proto.StatVersion, Caps: proto.CapRepair | proto.CapCopy, Step: 3}
	r.handle(proto.KindStat, proto.AppendStat(nil, &st0), client)
	out.mu.Lock()
	out.l = nil
	out.mu.Unlock()

	// upload packets 1..10, packet 5 lost; the app's repair over 1..10 brings it back
	ga := gs.LocalAddr().(*net.UDPAddr)
	var tx game.Tx
	now := time.Now()
	for s := uint32(1); s <= 10; s++ {
		p := []byte{byte(s), 'g', 'a', 'm', 'e'}
		tx.Add(s, p, now.Add(time.Second))
		if s == 5 {
			continue
		}
		h := proto.UDPUp{Session: sid, Flow: 1, Seq: s, Flags: proto.FlagGame, DstPort: uint16(ga.Port)}
		copy(h.DstIP[:], ga.IP.To4())
		r.handle(proto.KindUDPUp, proto.AppendUDPUp(nil, &h, p), client)
	}
	// the first repair makes the decoder; the next ones rebuild with what came since
	for i := 0; i < 3; i++ {
		rep := append([]byte(nil), tx.Repair(now, 10)...)
		r.handle(proto.KindRepair, proto.AppendRepairUp(nil, sid, 1, rep), client)
		h := proto.UDPUp{Session: sid, Flow: 1, Seq: uint32(11 + i), Flags: proto.FlagGame, DstPort: uint16(ga.Port)}
		copy(h.DstIP[:], ga.IP.To4())
		p := []byte{byte(11 + i), 'g', 'a', 'm', 'e'}
		tx.Add(uint32(11+i), p, now.Add(time.Second))
		r.handle(proto.KindUDPUp, proto.AppendUDPUp(nil, &h, p), client)
	}
	got := map[byte]int{}
	gs.SetReadDeadline(time.Now().Add(time.Second))
	b := make([]byte, 100)
	for {
		n, err := gs.Read(b)
		if err != nil {
			break
		}
		if n > 0 {
			got[b[0]]++
		}
	}
	for s := byte(1); s <= 13; s++ {
		if s == 5 {
			continue
		}
		if got[s] != 1 {
			t.Fatalf("packet %d reached the game %d times", s, got[s])
		}
	}
	if got[5] != 1 {
		t.Fatalf("the lost packet reached the game %d times (want 1, rebuilt)", got[5])
	}

	// the new app reports: it gets the loss of its uploads (1 of 13 here)
	st := proto.Stat{Session: sid, Version: proto.StatVersion, Caps: proto.CapRepair | proto.CapCopy, Count: 100}
	r.handle(proto.KindStat, proto.AppendStat(nil, &st), client)
	ans := out.of(proto.KindStat)
	if len(ans) != 1 {
		t.Fatal("no answer to the report")
	}
	a, err := proto.ParseStat(ans[0])
	if err != nil || a.Session != sid || a.Caps&proto.CapRepair == 0 || a.Loss == 0 || a.Loss > 200 {
		t.Fatalf("answer %+v %v", a, err)
	}
	// a report of a session that is not allowed (another user's key) is not answered: single-key mode allows all,
	// so here the parse alone is checked
	r.handle(proto.KindStat, []byte{1, 2, 3}, client)
	if len(out.of(proto.KindStat)) != 1 {
		t.Fatal("a short report was answered")
	}
}
