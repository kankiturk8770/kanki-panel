package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

func upPkt(flow, seq uint32, ip [4]byte, port uint16, n int) []byte {
	h := proto.UDPUp{Session: 7, Flow: flow, Seq: seq, DstIP: ip, DstPort: port}
	return proto.AppendUDPUp(nil, &h, make([]byte, n))
}

func downPkt(flow, seq uint32, payload []byte) []byte {
	return proto.AppendUDPDown(nil, flow, seq, payload)
}

// kcpPkt: یک بسته‌ی داده‌ی FEC با یک سگمنت KCP با این فرمان
func kcpPkt(cmd byte, n int) []byte {
	b := make([]byte, 8+24+n)
	binary.LittleEndian.PutUint16(b[4:6], 0xf1)
	b[8+4] = cmd
	binary.LittleEndian.PutUint32(b[8+20:8+24], uint32(n))
	return b
}

func dnsAnswer(t *testing.T, name string, ip [4]byte) []byte {
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	b.EnableCompression()
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	b.Question(q)
	b.StartAnswers()
	b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: ip})
	out, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestKcpKinds(t *testing.T) {
	if kcpKind(kcpPkt(81, 100)) != 'd' || kcpKind(kcpPkt(82, 0)) != 'a' || kcpKind(kcpPkt(83, 0)) != 'o' {
		t.Fatal("kcp kinds")
	}
	p := make([]byte, 40)
	binary.LittleEndian.PutUint16(p[4:6], 0xf2)
	if kcpKind(p) != 'p' {
		t.Fatal("parity")
	}
}

// یک «مسابقه»: جریان UDP ۴۵ ثانیه با ۳۰ بسته در ثانیه هر طرف، یک رگبار بزرگ، چند بسته‌ی گم‌شده؛ کنارش DNS،
// یک دانلود TCP و یک سیل ACK در KCP
func TestReportLabelsAMatch(t *testing.T) {
	r := newRecorder("", 600, time.Now().Add(-50*time.Second))
	game := [4]byte{20, 1, 2, 3}
	addr := "5.5.5.5:4444"
	at := func(ms int) { r.start = time.Now().Add(-time.Duration(ms) * time.Millisecond) }
	feed := func(in bool, kind byte, wire int, p []byte) { r.packet(in, kind, wire, p, addr) }

	// DNS
	at(100)
	q := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
	q.StartQuestions()
	q.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("match.game.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	qb, _ := q.Finish()
	feed(true, proto.KindUDPUp, 80, upPkt(1, 1, [4]byte{8, 8, 8, 8}, 53, 0)[:proto.UpHdrLen])
	up := append(upPkt(1, 2, [4]byte{8, 8, 8, 8}, 53, 0)[:proto.UpHdrLen], qb...)
	feed(true, proto.KindUDPUp, 90, up)
	feed(false, proto.KindUDPDown, 120, downPkt(1, 1, dnsAnswer(t, "match.game.test", game)))

	seq := uint32(0)
	for ms := 1000; ms < 46000; ms += 33 {
		at(ms)
		seq++
		if seq%50 == 0 {
			continue // گم شد
		}
		feed(true, proto.KindUDPUp, 140, upPkt(2, seq, game, 17500, 90))
		feed(false, proto.KindUDPDown, 200, downPkt(2, seq, make([]byte, 150)))
	}
	// رگبار: ده بسته‌ی ۱۲۰۰ بایتی در ۵ میلی‌ثانیه
	for i := 0; i < 10; i++ {
		at(20000 + i/2)
		feed(false, proto.KindUDPDown, 1260, downPkt(2, 90000+uint32(i), make([]byte, 1200)))
	}
	// سیل ACK در KCP، ثانیه‌ی ۳۰ (۴۰۰ بسته)
	for i := 0; i < 400; i++ {
		at(30000 + i*2)
		feed(true, obfs.KindKCP, 90, kcpPkt(82, 0))
	}
	// یک دانلود TCP
	rec.Store(r)
	defer rec.Store(nil)
	tap := &tcpTap{host: "cdn.game.test", port: 443}
	for i := 0; i < 30; i++ {
		at(2000 + i*100)
		tap.add(1, 100_000)
	}
	at(50000)
	rep, raw := r.report(time.Now())

	if len(rep.Flows) != 2 {
		t.Fatalf("flows: %d", len(rep.Flows))
	}
	m := rep.Flows[0]
	if m.Label != "match" || m.Domain != "match.game.test" || m.Target != "20.1.2.3:17500" {
		t.Fatalf("match flow: %+v", m)
	}
	if m.UpLost < 25 || m.UpLost > 30 {
		t.Fatalf("lost %d", m.UpLost)
	}
	if m.Down.Burst20 < 10 || m.Down.MaxSize != 1200 || m.Down.Big != 10 || m.Up.Big != 0 {
		t.Fatalf("down: %+v", m.Down)
	}
	if rep.Flows[1].Label != "dns" {
		t.Fatalf("dns: %+v", rep.Flows[1])
	}
	if len(rep.Queries) != 1 || rep.Queries[0].Name != "match.game.test" {
		t.Fatalf("queries %+v", rep.Queries)
	}
	if len(rep.Streams) != 1 || rep.Streams[0].Label != "download" || rep.Streams[0].Down != 3_000_000 {
		t.Fatalf("streams %+v", rep.Streams)
	}
	if rep.Vip.HeavyUp != 1 || rep.Vip.HeavyUpMatch != 1 || rep.Vip.BigBurst50Down < 10*1260 || rep.Vip.MatchBigDown <= 0 {
		t.Fatalf("vip %+v", rep.Vip)
	}
	// مرحله‌ها: لابی، شروع، مسابقه، لابی
	labels := []string{}
	for _, p := range rep.Phases {
		labels = append(labels, p.Label)
	}
	if len(labels) < 3 || labels[0] != "lobby" || labels[1] != "start" || labels[2] != "match" {
		t.Fatalf("phases %+v", rep.Phases)
	}
	if n := len(raw["packets"].([][6]uint32)); n != rep.Events || n < 2600 {
		t.Fatalf("raw %d", n)
	}
}

// فقط کاربر خواسته‌شده ضبط می‌شود، و بعد از پایان زمان چیزی اضافه نمی‌شود
func TestRecordOnlyThatUserAndOnlyThatLong(t *testing.T) {
	ring := obfs.NewKeyring()
	if err := ring.Set(map[string]string{"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff": "ali"}); err != nil {
		t.Fatal(err)
	}
	old := relayRing
	relayRing = ring
	defer func() { relayRing = old }()
	r := newRecorder("ali", 1, time.Now())
	rec.Store(r)
	defer rec.Store(nil)
	a := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 9}
	tapPacket(true, proto.KindUDPUp, 100, upPkt(1, 1, [4]byte{1, 1, 1, 1}, 9000, 10), a) // آدرس مال کسی نیست
	if len(r.ev) != 0 {
		t.Fatal("recorded a stranger")
	}
	(&tcpTap{user: "reza", host: "x", port: 1}).add(1, 10)
	if len(r.streams) != 0 {
		t.Fatal("recorded another user's TCP")
	}
	(&tcpTap{user: "ali", host: "x", port: 1}).add(1, 10)
	if len(r.streams) != 1 {
		t.Fatal("did not record the user's TCP")
	}
	r.until = time.Now().Add(-time.Millisecond)
	(&tcpTap{user: "ali", host: "y", port: 1}).add(1, 10)
	if len(r.streams) != 1 || !r.stopped {
		t.Fatal("recorded after the end")
	}
	rep, _ := r.report(time.Now())
	if rep.Recording {
		t.Fatal("still recording")
	}
}
