package game

import (
	"sync"
	"time"
)

// Plan: how one direction of the game is protected right now
type Plan struct {
	// Every: one repair after every Every packets (0 = no repairs)
	Every int
	// Win: how many of the newest packets a repair covers
	Win int
	// Copy: every packet once more, CopyDelay later (on another moment of the line, not right behind it)
	Copy bool
}

const (
	// CopyDelay: the second copy of a packet; a loss on a mobile line or a busy link lasts a few to some tens of ms,
	// a copy right behind the first one is lost with it
	CopyDelay = 25 * time.Millisecond
	// RepairDelay: a repair waits a little after the packet it follows, for the same reason
	RepairDelay = 5 * time.Millisecond
	// TailDelay: the last packets of a moment of play are covered by one more repair if nothing follows them
	TailDelay = 20 * time.Millisecond
	// Deadline: a packet older than this is not worth rebuilding for a game
	Deadline = 250 * time.Millisecond
	// calmFor: how long the line must be better before the protection goes down a step
	calmFor = 4 * time.Second
	// staleAfter: no report for this long = the peer stopped telling; back to the start plan
	staleAfter = 6 * time.Second
)

// the steps, from a clean line to a broken one; each costs more than the one before. The game itself is a few
// tens of KB a second, so protecting it well costs little; on a clean line nothing is added at all. A repair is
// as long as the longest packet it covers, so for scattered loss few repairs over short windows are the
// cheapest; a run of lost packets needs a repair after every packet over a long window (a copy a moment later is
// inside the same run and is lost with it); only a line that loses most of everything gets a copy too.
var steps = []Plan{
	{},                              // 0 clean: nothing extra, the game goes as it is
	{Every: 8, Win: 16},             // 1 a little loss (under ~1 %): one repair per 8 packets
	{Every: 4, Win: 12},             // 2 1-3 %
	{Every: 2, Win: 12},             // 3 3-8 %
	{Every: 1, Win: 16},             // 4 8-20 %, or runs of lost packets on a lossy line
	{Every: 1, Win: 16, Copy: true}, // 5 the line loses a fifth of everything or more
}

// stepFor: the step the measured loss (permille) and its longest run of lost packets call for
// A run of lost packets only counts on a line that really loses: one short cut in a clean second is not a
// reason to send more for the next seconds.
func stepFor(permille, burst uint32) int {
	s := 0
	switch {
	case permille >= 200:
		s = 5
	case permille >= 80:
		s = 4
	case permille >= 30:
		s = 3
	case permille >= 12:
		s = 2
	case permille >= 4:
		s = 1
	}
	if permille >= 12 && burst >= 4 {
		s = max(s, 4)
	}
	return s
}

// Policy: the plan of one direction, from what the other side measured on it. It goes up at once when
// the line gets worse and down one step only after calmFor of a better line, so a quiet second never takes
// the protection away in the middle of a fight.
type Policy struct {
	mu       sync.Mutex
	step     int
	started  time.Time
	report   time.Time
	better   time.Time // since when the reports ask for less
	measured bool      // a report with enough packets came (the first one is taken as it is)
}

// Start: a game flow began (the first packets are protected before any report)
func (p *Policy) Start(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.started.IsZero() {
		p.started = now
	}
}

// Report: the other side measured this loss on this direction
func (p *Policy) Report(permille, burst, n uint32, now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if n < 10 {
		// too few packets to say anything: keep what there is (before the first real measure, the start plan)
		if p.measured {
			p.report = now
		}
		return
	}
	want := stepFor(permille, burst)
	if !p.measured {
		// the first real measure replaces the start guess, up or down
		p.measured, p.step, p.better, p.report = true, want, time.Time{}, now
		return
	}
	switch {
	case want > p.step:
		p.step, p.better = want, time.Time{}
	case want < p.step:
		if p.better.IsZero() {
			p.better = now
		} else if now.Sub(p.better) >= calmFor {
			p.step--
			p.better = now
		}
	default:
		p.better = time.Time{}
	}
	p.report = now
}

// Plan: what to do now
func (p *Policy) Plan(now time.Time) Plan {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.step
	fresh := !p.report.IsZero() && now.Sub(p.report) < staleAfter
	if !fresh {
		// nothing measured (yet, or not any more): only a light protection (a repair every 4 packets), never
		// copies; the first report comes within a second and says what the line needs
		s = 1
	}
	return steps[s]
}

// Step: the current step (0..5), for the stats
func (p *Policy) Step() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.step
}
