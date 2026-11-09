// The KPING lab: a game-like UDP stream (60 packets a second, 120 bytes) to an echo "game server",
// through KPING (one or two paths) or microtun, with loss and delay put on the phone's paths by
// scripts/kping_lab.sh. Prints loss and round-trip times.
//
//	kplab echo <addr>
//	kplab kping <link file> <seconds> <local ip>[,<local ip>…] <relay ip[:port]>[,…] <game ip:port>
//	kplab lossy <listen ip:port> <upstream ip:port> <delay ms> <jitter ms> <loss %> <mean outage ms>
//	kplab mtun <link file> <seconds> <game ip:port>
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mtuncore/mtun"
)

const pps, size = 60, 120

// one path: the second copy goes this much later (KP_DUP_MS)
var dupDelay = func() time.Duration {
	ms, err := strconv.Atoi(os.Getenv("KP_DUP_MS"))
	if err != nil {
		ms = 10
	}
	return time.Duration(ms) * time.Millisecond
}()

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

// an IPv4/UDP game packet: [seq 4 | sent ns 8 | padding]
func gamePkt(src, dst net.IP, dport int, seq uint32) []byte {
	pl := make([]byte, size)
	binary.BigEndian.PutUint32(pl, seq)
	binary.BigEndian.PutUint64(pl[4:], uint64(time.Now().UnixNano()))
	udp := make([]byte, 8, 8+len(pl))
	binary.BigEndian.PutUint16(udp, 40000)
	binary.BigEndian.PutUint16(udp[2:], uint16(dport))
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(pl)))
	udp = append(udp, pl...)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
	ip[8], ip[9] = 64, 17
	copy(ip[12:], src.To4())
	copy(ip[16:], dst.To4())
	binary.BigEndian.PutUint16(ip[10:], csum(ip))
	return append(ip, udp...)
}

type meter struct {
	mu   sync.Mutex
	sent int
	got  map[uint32]time.Duration
}

func (m *meter) back(ip []byte) {
	if len(ip) < 40 || ip[9] != 17 {
		return
	}
	pl := ip[28:]
	seq := binary.BigEndian.Uint32(pl)
	rtt := time.Duration(time.Now().UnixNano() - int64(binary.BigEndian.Uint64(pl[4:])))
	m.mu.Lock()
	if _, dup := m.got[seq]; !dup {
		m.got[seq] = rtt
	}
	m.mu.Unlock()
}

func (m *meter) report(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var r []time.Duration
	for _, v := range m.got {
		r = append(r, v)
	}
	sort.Slice(r, func(i, j int) bool { return r[i] < r[j] })
	pc := func(p float64) float64 {
		if len(r) == 0 {
			return 0
		}
		return float64(r[int(float64(len(r)-1)*p)]) / 1e6
	}
	var sum time.Duration
	for _, v := range r {
		sum += v
	}
	avg := 0.0
	if len(r) > 0 {
		avg = float64(sum) / float64(len(r)) / 1e6
	}
	// jitter: mean change between packets in send order
	var jit float64
	var prev time.Duration
	n := 0
	for s := uint32(0); s < uint32(m.sent); s++ {
		if v, ok := m.got[s]; ok {
			if n > 0 {
				d := float64(v-prev) / 1e6
				if d < 0 {
					d = -d
				}
				jit += d
			}
			prev = v
			n++
		}
	}
	if n > 1 {
		jit /= float64(n - 1)
	}
	late := 0
	for _, v := range r {
		if v > 150*time.Millisecond {
			late++
		}
	}
	loss := 100 * float64(m.sent-len(r)) / float64(max(m.sent, 1))
	fmt.Printf("RESULT %s sent=%d back=%d loss=%.2f%% avg=%.1f p50=%.1f p95=%.1f p99=%.1f max=%.1f jitter=%.1f late150=%d\n",
		name, m.sent, len(r), loss, avg, pc(0.5), pc(0.95), pc(0.99), pc(1), jit, late)
}

func stream(m *meter, secs int, send func(seq uint32)) {
	t := time.NewTicker(time.Second / pps)
	defer t.Stop()
	end := time.Now().Add(time.Duration(secs) * time.Second)
	for seq := uint32(0); time.Now().Before(end); seq++ {
		<-t.C
		m.mu.Lock()
		m.sent++
		m.mu.Unlock()
		send(seq)
	}
	time.Sleep(time.Second)
}

func echo(addr string) {
	a, _ := net.ResolveUDPAddr("udp", addr)
	c, err := net.ListenUDP("udp", a)
	if err != nil {
		panic(err)
	}
	b := make([]byte, 2048)
	for {
		n, from, err := c.ReadFromUDP(b)
		if err == nil {
			c.WriteToUDP(b[:n], from)
		}
	}
}

// ------------------------------------------------------------------ KPING

type kpLink struct {
	key, obfs string
	uid       uint32
	ip        net.IP
	port      string
	fec       int
}

func parseKping(s string) kpLink {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "kping" {
		panic("bad link")
	}
	q := u.Query()
	uid, _ := strconv.Atoi(q.Get("uid"))
	fec, _ := strconv.Atoi(q.Get("fec"))
	return kpLink{key: u.User.Username(), obfs: q.Get("obfs"), uid: uint32(uid), ip: net.ParseIP(q.Get("ip")), port: u.Port(), fec: fec}
}

func kping(linkFile string, secs int, locals, relays []string, game string) {
	raw, _ := os.ReadFile(linkFile)
	l := parseKping(string(raw))
	w, err := newWire(l.obfs, l.key)
	if err != nil {
		panic(err)
	}
	sess := uint16(rand.Intn(65535) + 1)
	var paths []*net.UDPConn
	for i, lip := range locals {
		r := relays[i]
		if _, _, err := net.SplitHostPort(r); err != nil {
			r = net.JoinHostPort(r, l.port)
		}
		ra, _ := net.ResolveUDPAddr("udp", r)
		c, err := net.DialUDP("udp", &net.UDPAddr{IP: net.ParseIP(lip)}, ra)
		if err != nil {
			panic(err)
		}
		paths = append(paths, c)
	}
	gh, gp, _ := net.SplitHostPort(game)
	gport, _ := strconv.Atoi(gp)
	m := &meter{got: map[uint32]time.Duration{}}
	var mu sync.Mutex
	var win window
	rx := &fecRx{}
	pongs := make([]int, len(paths))
	dups, fixed := 0, 0
	for i, c := range paths {
		go func(i int, c *net.UDPConn) {
			b := make([]byte, 2048)
			for {
				n, err := c.Read(b)
				if err != nil {
					return
				}
				h, p, ok := w.open(b[:n])
				if !ok || h.kind&down == 0 || h.sess != sess {
					continue
				}
				mu.Lock()
				switch h.kind &^ down {
				case kPong:
					pongs[i]++
				case kData:
					if win.take(h.seq) {
						m.back(p)
						if s, rp, ok := rx.data(h.seq, p, &win); ok {
							win.take(s)
							fixed++
							m.back(rp)
						}
					} else {
						dups++
					}
				case kParity:
					if s, rp, ok := rx.parity(h.aux, p, &win); ok {
						win.take(s)
						fixed++
						m.back(rp)
					}
				}
				mu.Unlock()
			}
		}(i, c)
	}
	var pingSeq uint32
	ping := func() {
		for i, c := range paths {
			ts := make([]byte, 8)
			binary.BigEndian.PutUint64(ts, uint64(time.Now().UnixMilli()))
			mu.Lock()
			s := pingSeq
			pingSeq++
			mu.Unlock()
			c.Write(w.seal(hdr{l.uid, sess, s, kPing, byte(i + 1)}, ts))
		}
	}
	// the session first: a PING on every path until each answered
	for t := 0; t < 50; t++ {
		ping()
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		all := true
		for _, p := range pongs {
			all = all && p > 0
		}
		mu.Unlock()
		if all {
			break
		}
	}
	go func() {
		for range time.Tick(time.Second) {
			ping()
		}
	}()
	tx := &fecTx{k: l.fec}
	var pseq uint32
	sendAll := func(kind, aux byte, seq uint32, p []byte) {
		for i, c := range paths {
			a := aux
			if kind == kData {
				a = byte(i + 1)
			}
			pkt := w.seal(hdr{l.uid, sess, seq, kind, a}, p)
			c.Write(pkt)
			if len(paths) == 1 {
				// one path: the copy goes 2 ms later
				go func(c *net.UDPConn, pkt []byte) { time.Sleep(dupDelay); c.Write(pkt) }(c, pkt)
			}
		}
	}
	go func() {
		for range time.Tick(2 * time.Millisecond) {
			if n, par := tx.flush(); par != nil {
				mu.Lock()
				s := pseq
				pseq++
				mu.Unlock()
				sendAll(kParity, n, s, par)
			}
		}
	}()
	stream(m, secs, func(seq uint32) {
		p := gamePkt(l.ip, net.ParseIP(gh), gport, seq)
		sendAll(kData, 0, seq, p)
		if n, par := tx.add(seq, p); par != nil {
			mu.Lock()
			s := pseq
			pseq++
			mu.Unlock()
			sendAll(kParity, n, s, par)
		}
	})
	mu.Lock()
	fmt.Printf("KPING paths=%d pongs=%v copies-dropped=%d rebuilt=%d\n", len(paths), pongs, dups, fixed)
	mu.Unlock()
	m.report(fmt.Sprintf("kping-%dpath", len(paths)))
}

// ------------------------------------------------------------------ microtun (the app's own client)

type memTun struct {
	in     chan []byte
	closed chan struct{}
	m      *meter
	once   sync.Once
}

func (t *memTun) Read(p []byte) (int, error) {
	select {
	case b := <-t.in:
		return copy(p, b), nil
	case <-t.closed:
		return 0, io.EOF
	}
}
func (t *memTun) Write(p []byte) (int, error) { t.m.back(p); return len(p), nil }
func (t *memTun) Close() error                { t.once.Do(func() { close(t.closed) }); return nil }

func mtunRun(linkFile string, secs int, game string) {
	raw, _ := os.ReadFile(linkFile)
	c, err := mtun.Dial(strings.TrimSpace(string(raw)), "lab-device", func(string) {})
	if err != nil {
		panic(err)
	}
	src, _, _ := net.ParseCIDR(strings.Fields(c.Address())[0])
	m := &meter{got: map[uint32]time.Duration{}}
	t := &memTun{in: make(chan []byte, 256), closed: make(chan struct{}), m: m}
	c.SetTUN(t)
	time.Sleep(500 * time.Millisecond)
	gh, gp, _ := net.SplitHostPort(game)
	gport, _ := strconv.Atoi(gp)
	stream(m, secs, func(seq uint32) { t.in <- gamePkt(src, net.ParseIP(gh), gport, seq) })
	m.report("microtun")
	c.Close()
}

// ------------------------------------------------------------------ a bad path (the kernel here has no netem)

// lossy: a UDP proxy whose path drops out now and then, in time as a real radio does (outages of `outage`
// ms on average, `loss` % of the time; everything sent during one is lost), and delays packets (base +
// random jitter, order kept), each direction on its own
type lane struct {
	bad        bool
	until      time.Time
	good, out  float64
	delay, jit time.Duration
	last       time.Time
	q          chan func()
}

func newLane(delay, jit, loss, outage float64) *lane {
	good := 1e9
	if loss > 0 {
		good = outage * (100 - loss) / loss
	}
	l := &lane{good: good, out: outage, until: time.Now().Add(time.Duration(rand.ExpFloat64() * good * 1e6)), delay: time.Duration(delay * 1e6), jit: time.Duration(jit * 1e6), q: make(chan func(), 4096)}
	go func() {
		for f := range l.q {
			f()
		}
	}()
	return l
}

func (l *lane) pass(send func()) {
	now := time.Now()
	for now.After(l.until) {
		l.bad = !l.bad
		mean := l.good
		if l.bad {
			mean = l.out
		}
		l.until = l.until.Add(time.Duration(rand.ExpFloat64() * mean * 1e6))
	}
	if l.bad {
		return
	}
	at := time.Now().Add(l.delay + time.Duration(rand.Float64()*float64(l.jit)))
	if at.Before(l.last) {
		at = l.last
	}
	l.last = at
	l.q <- func() { time.Sleep(time.Until(at)); send() }
}

func lossy(listen, upstream string, delay, jit, loss, burst float64) {
	la, _ := net.ResolveUDPAddr("udp", listen)
	ua, _ := net.ResolveUDPAddr("udp", upstream)
	in, err := net.ListenUDP("udp", la)
	if err != nil {
		panic(err)
	}
	up, down := newLane(delay, jit, loss, burst), newLane(delay, jit, loss, burst)
	var mu sync.Mutex
	conns := map[string]*net.UDPConn{}
	b := make([]byte, 4096)
	for {
		n, from, err := in.ReadFromUDP(b)
		if err != nil {
			continue
		}
		pkt := append([]byte(nil), b[:n]...)
		mu.Lock()
		c := conns[from.String()]
		if c == nil {
			c, _ = net.DialUDP("udp", nil, ua)
			conns[from.String()] = c
			go func(c *net.UDPConn, to *net.UDPAddr) {
				rb := make([]byte, 4096)
				for {
					n, err := c.Read(rb)
					if err != nil {
						return
					}
					p := append([]byte(nil), rb[:n]...)
					down.pass(func() { in.WriteToUDP(p, to) })
				}
			}(c, from)
		}
		mu.Unlock()
		up.pass(func() { c.Write(pkt) })
	}
}

func main() {
	switch os.Args[1] {
	case "echo":
		echo(os.Args[2])
	case "kping":
		secs, _ := strconv.Atoi(os.Args[3])
		kping(os.Args[2], secs, strings.Split(os.Args[4], ","), strings.Split(os.Args[5], ","), os.Args[6])
	case "lossy":
		f := func(i int) float64 { v, _ := strconv.ParseFloat(os.Args[i], 64); return v }
		lossy(os.Args[2], os.Args[3], f(4), f(5), f(6), f(7))
	case "mtun":
		secs, _ := strconv.Atoi(os.Args[3])
		mtunRun(os.Args[2], secs, os.Args[4])
	}
}
