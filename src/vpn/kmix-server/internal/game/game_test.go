package game

import (
	"math/rand"
	"sync/atomic"
	"testing"
	"time"
)

// the line's loss is counted on first copies; late packets are taken back off
func TestMeter(t *testing.T) {
	var m Meter
	rng := rand.New(rand.NewSource(1))
	lost := 0
	for s := uint32(1); s <= 2000; s++ {
		if rng.Float64() < 0.05 {
			lost++
			continue
		}
		m.Seen(s)
	}
	pm, _, n := m.Take()
	if n < 1900 || pm < 40 || pm > 60 {
		t.Fatalf("5%% loss read as %d‰ over %d", pm, n)
	}
	// out of order is not loss
	var o Meter
	for _, s := range []uint32{1, 2, 4, 3, 6, 5, 7, 8} {
		o.Seen(s)
	}
	if pm, _, _ := o.Take(); pm != 0 {
		t.Fatalf("reordering counted as loss: %d‰", pm)
	}
	// a run of 5 lost in a row is the burst
	var b Meter
	for s := uint32(1); s <= 30; s++ {
		if s >= 10 && s < 15 {
			continue
		}
		b.Seen(s)
	}
	if _, burst, _ := b.Take(); burst != 5 {
		t.Fatalf("burst %d", burst)
	}
}

// clean line: nothing; loss: up at once; better line: down only after a calm while
func TestPolicy(t *testing.T) {
	var p Policy
	now := time.Now()
	p.Start(now)
	if pl := p.Plan(now); pl.Every == 0 {
		t.Fatal("a new flow is not protected before the first report")
	}
	// a report about too few packets does not take the start protection away
	p.Report(0, 0, 3, now)
	if pl := p.Plan(now); pl.Every == 0 || pl.Copy {
		t.Fatalf("before a real measure: a light protection, never copies: %+v", pl)
	}
	p.Report(0, 0, 100, now)
	if pl := p.Plan(now); pl.Every != 0 || pl.Copy {
		t.Fatalf("clean line still protected: %+v", pl)
	}
	p.Report(80, 1, 100, now)
	if pl := p.Plan(now); pl.Every != 4 || pl.Copy {
		t.Fatalf("8%% loss: one repair per 4 packets (3× the loss), no copies: %+v", pl)
	}
	p.Report(200, 8, 100, now)
	if pl := p.Plan(now); !pl.Copy {
		t.Fatalf("long bursts without a later copy: %+v", pl)
	}
	// a quiet moment does not take it away
	for i := 0; i < 3; i++ {
		now = now.Add(time.Second)
		p.Report(0, 0, 100, now)
	}
	if p.Step() != 5 {
		t.Fatalf("dropped within seconds: step %d", p.Step())
	}
	for i := 0; i < 60; i++ {
		now = now.Add(time.Second)
		p.Report(0, 0, 100, now)
	}
	if p.Step() != 0 {
		t.Fatalf("a clean minute did not end it: step %d", p.Step())
	}
	// the peer stopped reporting: a small protection, not the old big one and not nothing
	now = now.Add(10 * time.Second)
	if pl := p.Plan(now); pl.Every == 0 || pl.Copy {
		t.Fatalf("no reports: %+v", pl)
	}
}

func TestClass(t *testing.T) {
	now := time.Now()
	var g Class
	for i := 0; i < 60; i++ {
		g.Note(90, 10012, now)
		now = now.Add(33 * time.Millisecond)
	}
	if g.Kind() != KindGame || !g.Playing(now, time.Second) {
		t.Fatal("a 30 Hz game stream is not a game")
	}
	var q Class
	if q.Note(1200, 443, now) != KindBulk {
		t.Fatal("QUIC is protected")
	}
	var d Class
	if d.Note(60, 53, now) != KindCtl {
		t.Fatal("DNS is protected")
	}
	// big packets for a second: bulk (a UDP download), no copies of it
	var b Class
	for i := 0; i < 400; i++ {
		b.Note(1200, 27015, now)
		now = now.Add(3 * time.Millisecond)
	}
	if b.Kind() != KindBulk {
		t.Fatal("a UDP download is protected")
	}
}

// later: on time, in order, never blocking; full = the new one is dropped
func TestLater(t *testing.T) {
	l := NewLater(4)
	defer l.Stop()
	var got atomic.Int32
	at := make(chan time.Duration, 10)
	start := time.Now()
	for i := 0; i < 6; i++ {
		l.Push(10*time.Millisecond, []byte{byte(i)}, func(b []byte) { got.Add(1); at <- time.Since(start) })
	}
	time.Sleep(60 * time.Millisecond)
	if got.Load() != 4 || l.Drops() != 2 {
		t.Fatalf("sent %d, dropped %d", got.Load(), l.Drops())
	}
	d := <-at
	if d < 9*time.Millisecond || d > 40*time.Millisecond {
		t.Fatalf("sent after %v, wanted 10ms", d)
	}
}

// the repairs of one flow at the plans' rates bring back the packets a lossy line drops
func TestRepairsAtPlanRates(t *testing.T) {
	for _, loss := range []uint32{5, 12, 30, 80, 200} {
		pl := planFor(loss, 0)
		rng := rand.New(rand.NewSource(3))
		var tx Tx
		var rx Rx
		now := time.Now()
		got := map[uint32]bool{}
		const total = 3000
		for s := uint32(1); s <= total; s++ {
			p := pkt(s)
			tx.Add(s, p, now.Add(Deadline))
			if rng.Float64() > 0.05 {
				got[s] = true
				for _, r := range rx.Data(s, p, now) {
					got[r.Seq] = true
				}
			}
			if s%uint32(pl.Every) == 0 {
				rep := append([]byte(nil), tx.Repair(now, pl.Win)...)
				if rng.Float64() > 0.05 {
					for _, r := range rx.Repair(rep, now) {
						got[r.Seq] = true
					}
				}
			}
			now = now.Add(20 * time.Millisecond)
		}
		miss := total - len(got)
		if pl.Every <= 3 && miss > total/100 {
			t.Fatalf("plan %+v: %d of %d still lost at 5%%", pl, miss, total)
		}
		t.Logf("plan %+v: 5%% loss → %.2f%% lost", pl, float64(miss)*100/total)
	}
}

// one short cut in an otherwise clean second is no reason to send more
func TestLoneBurst(t *testing.T) {
	if planFor(0, 5) != (Plan{}) || planFor(5, 5).Every <= 2 || planFor(20, 5).Every > 2 {
		t.Fatal("bursts on a clean line raise the protection")
	}
}

// panel 3.67: nothing at all on a clean line; on a lossy one the repairs follow the loss (about 3 repairs for
// every packet lost), never a fixed big step
func TestRepairsFollowTheLoss(t *testing.T) {
	for _, pm := range []uint32{0, 1, 2, 3} {
		if pl := planFor(pm, 0); pl != (Plan{}) {
			t.Fatalf("%d‰ (clean): %+v", pm, pl)
		}
	}
	prev := 0
	for pm := uint32(cleanBelow); pm <= 1000; pm++ {
		c := cost(planFor(pm, 0))
		if c < prev {
			t.Fatalf("less protection for more loss at %d‰: %d < %d", pm, c, prev)
		}
		prev = c
		// in proportion: between the loss and 4× it (the floor of one repair per 64 packets and the copy aside)
		if pm < copyFrom && pm*repairFactor >= 1000/maxEvery {
			if lo, hi := int(pm), int(pm)*4+1; c < lo || c > hi {
				t.Fatalf("%d‰ costs %d per 1000, not in proportion [%d, %d]", pm, c, lo, hi)
			}
		}
	}
	// a measured clean line after a lossy one: the repairs stop within a calm while, not at once
	var p Policy
	now := time.Now()
	p.Report(50, 0, 100, now)
	p.Report(0, 0, 100, now.Add(time.Second))
	if p.Plan(now.Add(time.Second)).Every == 0 {
		t.Fatal("dropped at the first clean second")
	}
	for i := 2; i < 40; i++ {
		p.Report(0, 0, 100, now.Add(time.Duration(i)*time.Second))
	}
	if pl := p.Plan(now.Add(39 * time.Second)); pl != (Plan{}) {
		t.Fatalf("still sending on a clean line: %+v", pl)
	}
}
