// ضبط ترافیک یک کاربر (برای فهمیدن الگوی بازی): پنل برای چند دقیقه ضبط یک کاربر را روشن می‌کند و
// این‌جا، جایی که ترافیک باز است، دیده می‌شود هر بسته به کجا می‌رود:
//   - هر بسته‌ی UDP (مسیر سریع دیتاگرام، یعنی بازی): زمان، جریان، جهت، اندازه‌ی خود بسته، اندازه روی سیم
//     (همان چیزی که سرور ایران و تانل می‌بینند) و شماره (برای افت بالارو)
//   - بسته‌های KCP (ترافیک TCP اپ): در خانه‌های ۱۰۰ میلی‌ثانیه‌ای، داده / فقط ACK / پریتی FEC و کوچک / بزرگ
//   - هر اتصال TCP: مقصد (دامنه یا IP)، حجم بالا و پایین در خانه‌های ۱۰۰ میلی‌ثانیه‌ای
//   - پرسش‌های DNS و جواب‌هایشان، تا هر IP اسم دامنه داشته باشد
//
// گزارش (`report`) جریان‌ها را برچسب می‌زند (مسابقه، سرویس بازی، دانلود، DNS …) و زمان را به مرحله‌ها
// (لابی، شروع مسابقه، مسابقه) تقسیم می‌کند. محتوای بسته‌ها ذخیره نمی‌شود (جز نام‌های DNS).
package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

const (
	recMaxSecs    = 3600
	recMaxEvents  = 600_000
	recMaxFlows   = 4096
	recMaxStreams = 8192
	recMaxQueries = 5000
	recBucketMs   = 100
	// مرز بسته‌ی «بزرگ» روی سیم و سقف بسته‌ی کوچک در ثانیه (برای شمردن رگبارها)
	bigWire  = 512
	heavyPps = 300
)

// rec ضبط در جریان یا آخرین ضبط (nil = هیچ)
var rec atomic.Pointer[recorder]

type recEv struct {
	t     uint32 // ms از شروع
	f     uint16 // شماره‌ی جریان
	dir   uint8  // 0 بالا (گوشی ← سرور)، 1 پایین
	inner uint16 // اندازه‌ی بسته‌ی خود بازی
	wire  uint16 // اندازه روی سیم
	seq   uint32
}

type recFlow struct {
	Session uint64
	Flow    uint32
	Target  string
	Dup     bool
}

// kcpB شمارش‌های یک خانه‌ی ۱۰۰ میلی‌ثانیه‌ای یک جهت
type kcpB struct {
	Data, Ack, Parity, Other, Ping, Small, Big, Bytes int32
}

type recStream struct {
	Host  string
	Port  uint16
	Open  uint32
	Close uint32 // 0 = هنوز باز
	b     map[uint32]*[2]int64
}

type recQuery struct {
	T    uint32 `json:"t"`
	Name string `json:"name"`
}

type recorder struct {
	mu      sync.Mutex
	user    string
	start   time.Time
	until   time.Time
	stopped bool
	ended   time.Time
	full    bool
	flows   []*recFlow
	bySess  map[[2]uint64]int
	byAddr  map[flowRef]int
	ev      []recEv
	kcp     [2]map[uint32]*kcpB
	streams []*recStream
	names   map[string]string
	queries []recQuery
}

type flowRef struct {
	addr string
	flow uint32
}

func newRecorder(user string, secs int, now time.Time) *recorder {
	if secs <= 0 || secs > recMaxSecs {
		secs = 600
	}
	return &recorder{
		user: user, start: now, until: now.Add(time.Duration(secs) * time.Second),
		bySess: map[[2]uint64]int{}, byAddr: map[flowRef]int{},
		kcp:   [2]map[uint32]*kcpB{{}, {}},
		names: map[string]string{},
	}
}

// mine: ضبط روشن است و این آدرس مال همان کاربر است
func (r *recorder) mine(addr net.Addr) bool {
	if r.user == "" || relayRing == nil {
		return true
	}
	u := relayRing.UserOf(addr)
	return u != nil && u.Name == r.user
}

// at زمان از شروع؛ false = ضبط تمام شده
func (r *recorder) at(now time.Time) (uint32, bool) {
	if r.stopped {
		return 0, false
	}
	if !now.Before(r.until) {
		r.stopped, r.ended = true, r.until
		return 0, false
	}
	return uint32(now.Sub(r.start) / time.Millisecond), true
}

// tapPacket از لایه‌ی obfs برای هر بسته صدا زده می‌شود
func tapPacket(in bool, kind byte, wire int, p []byte, addr net.Addr) {
	r := rec.Load()
	if r == nil || r.stopped {
		return
	}
	if !r.mine(addr) {
		return
	}
	r.packet(in, kind, wire, p, addr.String())
}

// stop ضبط را زودتر تمام می‌کند (داده‌ها می‌مانند)
func (r *recorder) stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped {
		r.stopped, r.ended = true, time.Now()
		if r.ended.After(r.until) {
			r.ended = r.until
		}
	}
}

func (r *recorder) packet(in bool, kind byte, wire int, p []byte, addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// ساعت داخل قفل: زمان بسته‌ها همیشه رو به جلو
	t, ok := r.at(time.Now())
	if !ok {
		return
	}
	dir := uint8(1)
	if in {
		dir = 0
	}
	b := r.bucket(dir, t)
	if wire > bigWire {
		b.Big++
	} else {
		b.Small++
	}
	b.Bytes += int32(wire)
	switch kind {
	case obfs.KindKCP, obfs.KindKCPPlain:
		switch kcpKind(p) {
		case 'd':
			b.Data++
		case 'a':
			b.Ack++
		case 'p':
			b.Parity++
		default:
			b.Other++
		}
	case proto.KindPing, proto.KindPong, proto.KindStat:
		b.Ping++
	case proto.KindRepair:
		b.Parity++
	case proto.KindUDPUp:
		if !in {
			return
		}
		h, pl, err := proto.ParseUDPUp(p)
		if err != nil {
			return
		}
		f := r.flowUp(h, addr)
		if f < 0 {
			return
		}
		r.event(recEv{t: t, f: uint16(f), dir: 0, inner: uint16(len(pl)), wire: uint16(wire), seq: h.Seq})
		if h.DstPort == 53 {
			r.dnsQuery(t, pl)
		}
	case proto.KindUDPDown, proto.KindUDPDownCopy:
		if in {
			return
		}
		flow, seq, pl, err := proto.ParseUDPDown(p)
		if err != nil {
			return
		}
		f, ok := r.byAddr[flowRef{addr, flow}]
		if !ok {
			// جریانی که قبل از ضبط شروع شده و هنوز بسته‌ی بالارو نداشته
			if len(r.flows) >= recMaxFlows {
				return
			}
			f = len(r.flows)
			r.flows = append(r.flows, &recFlow{Flow: flow})
			r.byAddr[flowRef{addr, flow}] = f
		}
		r.event(recEv{t: t, f: uint16(f), dir: 1, inner: uint16(len(pl)), wire: uint16(wire), seq: seq})
		if fl := r.flows[f]; len(fl.Target) > 3 && fl.Target[len(fl.Target)-3:] == ":53" {
			r.dnsAnswer(pl)
		}
	}
}

func (r *recorder) bucket(dir uint8, t uint32) *kcpB {
	k := t / recBucketMs
	b := r.kcp[dir][k]
	if b == nil {
		b = &kcpB{}
		r.kcp[dir][k] = b
	}
	return b
}

func (r *recorder) event(e recEv) {
	if len(r.ev) >= recMaxEvents {
		r.full = true
		return
	}
	r.ev = append(r.ev, e)
}

func (r *recorder) flowUp(h proto.UDPUp, addr string) int {
	key := [2]uint64{h.Session, uint64(h.Flow)}
	target := h.Target().String()
	f, ok := r.bySess[key]
	if !ok {
		// پایین‌رو قبلاً با همین آدرس دیده شده بود
		if g, ok2 := r.byAddr[flowRef{addr, h.Flow}]; ok2 && r.flows[g].Target == "" {
			f, ok = g, true
		}
	}
	if !ok {
		if len(r.flows) >= recMaxFlows {
			return -1
		}
		f = len(r.flows)
		r.flows = append(r.flows, &recFlow{})
	}
	fl := r.flows[f]
	fl.Session, fl.Flow, fl.Target = h.Session, h.Flow, target
	fl.Dup = fl.Dup || h.Flags&proto.FlagDup != 0
	r.bySess[key] = f
	r.byAddr[flowRef{addr, h.Flow}] = f
	return f
}

// kcpKind: d = داده، a = فقط ACK، p = پریتی FEC، o = بقیه (پرسش پنجره و …)
func kcpKind(p []byte) byte {
	seg := p
	if len(p) >= 8 {
		switch binary.LittleEndian.Uint16(p[4:6]) {
		case 0xf2:
			return 'p'
		case 0xf1:
			seg = p[8:]
		}
	}
	any, push := false, false
	for len(seg) >= 24 {
		cmd := seg[4]
		n := int(binary.LittleEndian.Uint32(seg[20:24]))
		switch cmd {
		case 81:
			push = true
		case 82:
		default:
			any = true
		}
		if n < 0 || 24+n > len(seg) {
			break
		}
		seg = seg[24+n:]
	}
	switch {
	case push:
		return 'd'
	case any:
		return 'o'
	default:
		return 'a'
	}
}

// ------------------------------------------------------------------ DNS

func (r *recorder) dnsQuery(t uint32, b []byte) {
	if len(r.queries) >= recMaxQueries {
		return
	}
	var p dnsmessage.Parser
	if _, err := p.Start(b); err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	r.queries = append(r.queries, recQuery{T: t, Name: trimDot(q.Name.String())})
}

func (r *recorder) dnsAnswer(b []byte) {
	var p dnsmessage.Parser
	if _, err := p.Start(b); err != nil {
		return
	}
	q, err := p.Question()
	if err != nil {
		return
	}
	name := trimDot(q.Name.String())
	_ = p.SkipAllQuestions()
	for {
		h, err := p.AnswerHeader()
		if err != nil {
			return
		}
		switch h.Type {
		case dnsmessage.TypeA:
			a, err := p.AResource()
			if err != nil {
				return
			}
			r.names[netip.AddrFrom4(a.A).String()] = name
		case dnsmessage.TypeAAAA:
			a, err := p.AAAAResource()
			if err != nil {
				return
			}
			r.names[netip.AddrFrom16(a.AAAA).String()] = name
		default:
			if err := p.SkipAnswer(); err != nil {
				return
			}
		}
	}
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// ------------------------------------------------------------------ TCP

// tcpTap حجم هر اتصال TCP را می‌شمارد (فقط وقتی ضبط همین کاربر روشن است)
type tcpTap struct {
	user string
	host string
	port uint16
	r    *recorder
	idx  int
}

func (s *tcpTap) add(dir int, n int) {
	r := rec.Load()
	if r == nil || r.stopped || (r.user != "" && r.user != s.user) {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.at(time.Now())
	if !ok {
		return
	}
	if s.r != r {
		if len(r.streams) >= recMaxStreams {
			return
		}
		s.r, s.idx = r, len(r.streams)
		r.streams = append(r.streams, &recStream{Host: s.host, Port: s.port, Open: t, b: map[uint32]*[2]int64{}})
	}
	st := r.streams[s.idx]
	k := t / recBucketMs
	c := st.b[k]
	if c == nil {
		c = &[2]int64{}
		st.b[k] = c
	}
	c[dir] += int64(n)
}

func (s *tcpTap) closed() {
	r := rec.Load()
	if r == nil || s.r != r {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.at(time.Now()); ok {
		r.streams[s.idx].Close = t
	}
}

// countW هر چه از آن رد شود را به حساب اتصال می‌گذارد (dir 0 بالا، 1 پایین)
type countW struct {
	w   interface{ Write([]byte) (int, error) }
	tap *tcpTap
	dir int
}

func (c countW) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	if n > 0 {
		c.tap.add(c.dir, n)
	}
	return n, err
}

// ------------------------------------------------------------------ report

type dirRep struct {
	Pkts   int     `json:"pkts"`
	Bytes  int64   `json:"bytes"`
	Wire   int64   `json:"wire"`
	Hist   [7]int  `json:"hist"` // اندازه‌ی خود بسته: ≤64، ≤128، ≤256، ≤512، ≤800، ≤1100، بیشتر
	Big    int     `json:"big"`  // روی سیم بالای ۵۱۲
	MaxPps int     `json:"max_pps"`
	AvgPps float64 `json:"avg_pps"`
	// بیشترین بسته و بایت در ۲۰ و ۵۰ میلی‌ثانیه (رگبار)
	Burst20  int `json:"burst20"`
	Burst50B int `json:"burst50_bytes"`
	MaxSize  int `json:"max_size"`
	// همان بسته دوباره (کپی حالت گیمینگ؛ از روی شماره)
	Copies int `json:"copies"`
}

type flowRep struct {
	ID     int     `json:"id"`
	Target string  `json:"target"`
	Domain string  `json:"domain"`
	Label  string  `json:"label"`
	First  float64 `json:"first"`
	Last   float64 `json:"last"`
	Dup    bool    `json:"dup"`
	Up     dirRep  `json:"up"`
	Down   dirRep  `json:"down"`
	// بسته‌های بالارو که به این سرور نرسیدند (از روی شماره‌ها؛ گوشی ← ایران ← تانل ← این‌جا)
	UpLost int     `json:"up_lost"`
	UpLoss float64 `json:"up_loss"`
	// بسته‌های بالارو که دیرتر از بسته‌ی بعدی‌شان رسیدند
	UpLate int `json:"up_late"`
}

type streamRep struct {
	Host    string  `json:"host"`
	Port    uint16  `json:"port"`
	Domain  string  `json:"domain"`
	Label   string  `json:"label"`
	Open    float64 `json:"open"`
	Close   float64 `json:"close"` // -1 = هنوز باز
	Up      int64   `json:"up"`
	Down    int64   `json:"down"`
	PeakBps int64   `json:"peak_bps"`
}

type phase struct {
	From  int    `json:"from"`
	To    int    `json:"to"`
	Label string `json:"label"`
}

type burstView struct {
	RtMax int `json:"rt_max"`
	Heavy int `json:"heavy"`
	// سهم بسته‌های مسابقه که روی سیم از rt_max بزرگ‌ترند
	MatchBigUp   float64 `json:"match_big_up"`
	MatchBigDown float64 `json:"match_big_down"`
	// ثانیه‌هایی که بسته‌ی کوچک این کاربر (همه‌ی انواع) از سقف «سنگین» گذشت؛ و چندتایش وسط مسابقه
	HeavyUp        int `json:"heavy_up"`
	HeavyDown      int `json:"heavy_down"`
	HeavyUpMatch   int `json:"heavy_up_match"`
	HeavyDownMatch int `json:"heavy_down_match"`
	// بیشترین بایت بسته‌های بزرگ پایین‌رو در ۵۰ میلی‌ثانیه
	BigBurst50Down int `json:"big_burst50_down"`
}

type report struct {
	User      string      `json:"user"`
	Start     int64       `json:"start"`
	Secs      int         `json:"secs"`
	Elapsed   float64     `json:"elapsed"`
	Recording bool        `json:"recording"`
	Full      bool        `json:"full"`
	Events    int         `json:"events"`
	Flows     []flowRep   `json:"flows"`
	Streams   []streamRep `json:"streams"`
	Columns   []string    `json:"columns"`
	Timeline  [][]int64   `json:"timeline"`
	Phases    []phase     `json:"phases"`
	Burst     burstView   `json:"burst"`
	Queries   []recQuery  `json:"queries"`
}

var timelineCols = []string{"game_up", "game_down", "game_up_bytes", "game_down_bytes", "udp_other", "tcp_up_bytes", "tcp_down_bytes",
	"kcp_up", "kcp_down", "ack_up", "ack_down", "parity_up", "parity_down", "small_up", "small_down", "big_up", "big_down"}

func sizeSlot(n int) int {
	for i, m := range []int{64, 128, 256, 512, 800, 1100} {
		if n <= m {
			return i
		}
	}
	return 6
}

func labelUDP(target string, f *flowRep) string {
	_, ps, _ := net.SplitHostPort(target)
	port, _ := strconv.Atoi(ps)
	span := f.Last - f.First
	pk := f.Up.Pkts + f.Down.Pkts
	switch {
	case port == 53:
		return "dns"
	case port == 443:
		return "quic"
	case port == 123:
		return "ntp"
	case span >= 30 && pk >= int(span*10):
		return "match"
	default:
		return "game_udp"
	}
}

// report گزارش ضبط؛ raw = همه‌ی بسته‌ها هم (برای دانلود)
func (r *recorder) report(now time.Time) (report, map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.stopped && !now.Before(r.until) {
		r.stopped, r.ended = true, r.until
	}
	end := now
	if r.stopped {
		end = r.ended
	}
	elapsed := end.Sub(r.start).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	secs := int(elapsed) + 1
	out := report{
		User: r.user, Start: r.start.Unix(), Secs: int(r.until.Sub(r.start) / time.Second), Elapsed: elapsed,
		Recording: !r.stopped, Full: r.full, Events: len(r.ev), Columns: timelineCols,
	}
	tl := make([][]int64, secs)
	for i := range tl {
		tl[i] = make([]int64, len(timelineCols))
	}
	col := func(t uint32) []int64 {
		s := int(t / 1000)
		if s >= secs {
			s = secs - 1
		}
		return tl[s]
	}
	// جریان‌ها
	type acc struct {
		pps    [2]map[int]int
		times  [2][]uint32
		sizes  [2][]int
		seqs   map[uint32]bool
		got    [2]map[uint32]bool
		lo, hi uint32
		seqOk  bool
		lastS  uint32
		late   int
		first  uint32
		last   uint32
		seen   bool
	}
	accs := make([]*acc, len(r.flows))
	for i := range accs {
		accs[i] = &acc{pps: [2]map[int]int{{}, {}}, seqs: map[uint32]bool{}, got: [2]map[uint32]bool{{}, {}}}
	}
	reps := make([]flowRep, len(r.flows))
	for i, f := range r.flows {
		reps[i] = flowRep{ID: i, Target: f.Target, Dup: f.Dup}
		if h, _, err := net.SplitHostPort(f.Target); err == nil {
			reps[i].Domain = r.names[h]
		}
	}
	for _, e := range r.ev {
		a, fr := accs[e.f], &reps[e.f]
		d := &fr.Up
		if e.dir == 1 {
			d = &fr.Down
		}
		if !a.seen || e.t < a.first {
			a.first = e.t
		}
		if e.t > a.last {
			a.last = e.t
		}
		a.seen = true
		if a.got[e.dir][e.seq] {
			d.Copies++
		}
		a.got[e.dir][e.seq] = true
		d.Pkts++
		d.Bytes += int64(e.inner)
		d.Wire += int64(e.wire)
		d.Hist[sizeSlot(int(e.inner))]++
		if int(e.wire) > bigWire {
			d.Big++
		}
		if int(e.inner) > d.MaxSize {
			d.MaxSize = int(e.inner)
		}
		a.pps[e.dir][int(e.t/1000)]++
		a.times[e.dir] = append(a.times[e.dir], e.t)
		a.sizes[e.dir] = append(a.sizes[e.dir], int(e.inner))
		if e.dir == 0 && !a.seqs[e.seq] {
			a.seqs[e.seq] = true
			if !a.seqOk {
				a.lo, a.hi, a.seqOk = e.seq, e.seq, true
			} else {
				if int32(e.seq-a.hi) > 0 {
					a.hi = e.seq
				} else {
					a.late++
				}
				if int32(e.seq-a.lo) < 0 {
					a.lo = e.seq
				}
			}
		}
	}
	for i := range reps {
		a, fr := accs[i], &reps[i]
		fr.First, fr.Last = float64(a.first)/1000, float64(a.last)/1000
		for dir, d := range []*dirRep{&fr.Up, &fr.Down} {
			active := 0
			for _, n := range a.pps[dir] {
				active++
				if n > d.MaxPps {
					d.MaxPps = n
				}
			}
			if active > 0 {
				d.AvgPps = float64(d.Pkts) / float64(active)
			}
			ts, sz := a.times[dir], a.sizes[dir]
			j, bytes := 0, 0
			k := 0
			for x := range ts {
				for j < x && int64(ts[x])-int64(ts[j]) >= 20 {
					j++
				}
				if x-j+1 > d.Burst20 {
					d.Burst20 = x - j + 1
				}
				bytes += sz[x]
				for k < x && int64(ts[x])-int64(ts[k]) >= 50 {
					bytes -= sz[k]
					k++
				}
				if bytes > d.Burst50B {
					d.Burst50B = bytes
				}
			}
		}
		if a.seqOk {
			want := int(a.hi-a.lo) + 1
			got := len(a.seqs)
			if want > got {
				fr.UpLost = want - got
				fr.UpLoss = float64(fr.UpLost) / float64(want)
			}
		}
		fr.UpLate = a.late
		fr.Label = labelUDP(fr.Target, fr)
	}
	// خط زمانی: بسته‌های UDP
	matchSpan := [][2]int{}
	for i := range reps {
		if reps[i].Label == "match" {
			matchSpan = append(matchSpan, [2]int{int(reps[i].First), int(reps[i].Last)})
		}
	}
	bigDown := []recEv{}
	for _, e := range r.ev {
		row := col(e.t)
		switch reps[e.f].Label {
		case "match", "game_udp":
			// همه‌ی UDP بازی (مسابقه و سرویس‌های بازی)؛ DNS و QUIC و ساعت جدا
			row[0+int(e.dir)]++
			row[2+int(e.dir)] += int64(e.inner)
			if reps[e.f].Label == "match" && e.dir == 1 && int(e.wire) > bigWire {
				bigDown = append(bigDown, e)
			}
		default:
			row[4]++
		}
	}
	// KCP و همه‌ی بسته‌های روی سیم
	for dir := 0; dir < 2; dir++ {
		for k, b := range r.kcp[dir] {
			row := col(k * recBucketMs)
			row[7+dir] += int64(b.Data + b.Ack + b.Parity + b.Other)
			row[9+dir] += int64(b.Ack)
			row[11+dir] += int64(b.Parity)
			row[13+dir] += int64(b.Small)
			row[15+dir] += int64(b.Big)
		}
	}
	// اتصال‌های TCP
	for _, s := range r.streams {
		sr := streamRep{Host: s.Host, Port: s.Port, Open: float64(s.Open) / 1000, Close: -1}
		if s.Close > 0 {
			sr.Close = float64(s.Close) / 1000
		}
		if net.ParseIP(s.Host) != nil {
			sr.Domain = r.names[s.Host]
		}
		per := map[uint32]int64{}
		for k, c := range s.b {
			sr.Up += c[0]
			sr.Down += c[1]
			row := col(k * recBucketMs)
			row[5] += c[0]
			row[6] += c[1]
			per[k*recBucketMs/1000] += c[1]
		}
		for _, v := range per {
			if v > sr.PeakBps {
				sr.PeakBps = v
			}
		}
		sr.Label = "web"
		if sr.Down >= 2<<20 {
			sr.Label = "download"
		}
		out.Streams = append(out.Streams, sr)
	}
	sort.Slice(out.Streams, func(i, j int) bool { return out.Streams[i].Down > out.Streams[j].Down })
	// مرحله‌ها
	inMatch := func(s int) (bool, bool) {
		for _, m := range matchSpan {
			if s >= m[0] && s <= m[1] {
				return true, s-m[0] < 20
			}
		}
		return false, false
	}
	labels := make([]string, secs)
	for s := 0; s < secs; s++ {
		m, st := inMatch(s)
		switch {
		case st:
			labels[s] = "start"
		case m:
			labels[s] = "match"
		case tl[s][6] > 100_000:
			labels[s] = "download"
		default:
			labels[s] = "lobby"
		}
	}
	for s := 0; s < secs; s++ {
		if n := len(out.Phases); n > 0 && out.Phases[n-1].Label == labels[s] {
			out.Phases[n-1].To = s
		} else {
			out.Phases = append(out.Phases, phase{From: s, To: s, Label: labels[s]})
		}
	}
	// رگبارها و بسته‌های بزرگ
	v := burstView{RtMax: bigWire, Heavy: heavyPps}
	var mUp, mDown, bUp, bDown int
	for i := range reps {
		if reps[i].Label == "match" {
			mUp += reps[i].Up.Pkts
			mDown += reps[i].Down.Pkts
			bUp += reps[i].Up.Big
			bDown += reps[i].Down.Big
		}
	}
	if mUp > 0 {
		v.MatchBigUp = float64(bUp) / float64(mUp)
	}
	if mDown > 0 {
		v.MatchBigDown = float64(bDown) / float64(mDown)
	}
	for s := 0; s < secs; s++ {
		m, _ := inMatch(s)
		if tl[s][13] > heavyPps {
			v.HeavyUp++
			if m {
				v.HeavyUpMatch++
			}
		}
		if tl[s][14] > heavyPps {
			v.HeavyDown++
			if m {
				v.HeavyDownMatch++
			}
		}
	}
	j, bytes := 0, 0
	for x := range bigDown {
		bytes += int(bigDown[x].wire)
		for j < x && int64(bigDown[x].t)-int64(bigDown[j].t) >= 50 {
			bytes -= int(bigDown[j].wire)
			j++
		}
		if bytes > v.BigBurst50Down {
			v.BigBurst50Down = bytes
		}
	}
	out.Burst = v
	// a copy: reps stays in recording order, so the raw flows below keep their own label and domain
	out.Flows = append([]flowRep(nil), reps...)
	sort.SliceStable(out.Flows, func(i, j int) bool {
		return out.Flows[i].Up.Pkts+out.Flows[i].Down.Pkts > out.Flows[j].Up.Pkts+out.Flows[j].Down.Pkts
	})
	out.Timeline = tl
	out.Queries = append([]recQuery(nil), r.queries...)
	// همه‌ی بسته‌ها (برای دانلود): [ms، جریان، جهت، اندازه، روی سیم، شماره]
	ev := make([][6]uint32, len(r.ev))
	for i, e := range r.ev {
		ev[i] = [6]uint32{e.t, uint32(e.f), uint32(e.dir), uint32(e.inner), uint32(e.wire), e.seq}
	}
	// KCP: [خانه‌ی ۱۰۰ms، جهت، داده، ACK، پریتی، بقیه، پینگ، کوچک، بزرگ، بایت]
	kc := [][10]int64{}
	for dir := 0; dir < 2; dir++ {
		for k, b := range r.kcp[dir] {
			kc = append(kc, [10]int64{int64(k), int64(dir), int64(b.Data), int64(b.Ack), int64(b.Parity), int64(b.Other), int64(b.Ping), int64(b.Small), int64(b.Big), int64(b.Bytes)})
		}
	}
	sort.Slice(kc, func(i, j int) bool { return kc[i][0] < kc[j][0] || (kc[i][0] == kc[j][0] && kc[i][1] < kc[j][1]) })
	// TCP: [شماره‌ی اتصال، خانه‌ی ۱۰۰ms، بالا، پایین]
	tc := [][4]int64{}
	for i, s := range r.streams {
		for k, c := range s.b {
			tc = append(tc, [4]int64{int64(i), int64(k), c[0], c[1]})
		}
	}
	sort.Slice(tc, func(i, j int) bool { return tc[i][1] < tc[j][1] })
	streams := make([]map[string]any, len(r.streams))
	for i, s := range r.streams {
		streams[i] = map[string]any{"host": s.Host, "port": s.Port, "open": s.Open, "close": s.Close}
	}
	flows := make([]map[string]any, len(r.flows))
	for i, f := range r.flows {
		flows[i] = map[string]any{"target": f.Target, "domain": reps[i].Domain, "label": reps[i].Label, "dup": f.Dup}
	}
	raw := map[string]any{
		"flows": flows, "packets": ev, "kcp": kc, "streams": streams, "tcp": tc, "names": r.names,
		"format": map[string]string{
			"packets": "[ms, flow, dir 0 up 1 down, size, wire size, seq]",
			"kcp":     "[100ms slot, dir, data, ack-only, parity, other, ping, small (wire<=512), big, wire bytes]",
			"tcp":     "[stream, 100ms slot, up bytes, down bytes]",
		},
	}
	return out, raw
}
