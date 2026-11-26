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

// How much to send (panel 3.67): on a clean line nothing at all; on a lossy one repairs in proportion to the loss
// the other side measured, never a fixed step that costs more than the line needs.
//
//	loss < cleanBelow ‰           nothing (no repair, no copy)
//	otherwise                     one repair per Every packets, Every = 1000 / (loss‰ × repairFactor), 1..maxEvery
//	runs of lost packets          at most every 2 packets (a copy a moment later is inside the same run)
//	loss ≥ copyFrom ‰             a copy of every packet too
//
// So the repairs are about repairFactor times the packets the line loses: enough to rebuild them, and on a line
// that loses little only a trickle (one repair per 64 packets of a game at 0.5 %). A repair covers the newest Win
// packets of the flow.
const (
	cleanBelow   = 4
	repairFactor = 3
	maxEvery     = 64
	copyFrom     = 200
	burstLoss    = 12
	burstRun     = 4
	winWide      = 16
	winNarrow    = 12
)

// planFor: the plan the measured loss (permille) and its longest run of lost packets call for
func planFor(permille, burst uint32) Plan {
	if permille < cleanBelow {
		return Plan{}
	}
	every := int((2000/(permille*repairFactor) + 1) / 2) // rounded
	every = min(max(every, 1), maxEvery)
	// a run of lost packets only counts on a line that really loses: one short cut in a clean second is not a
	// reason to send more for the next seconds
	if permille >= burstLoss && burst >= burstRun {
		every = min(every, 2)
	}
	win := winWide
	if every > 1 && every <= 4 {
		win = winNarrow
	}
	return Plan{Every: every, Win: win, Copy: permille >= copyFrom}
}

// cost: what a plan adds for every 1000 packets of the game
func cost(p Plan) int {
	c := 0
	if p.Every > 0 {
		c = 1000 / p.Every
	}
	if p.Copy {
		c += 1000
	}
	return c
}

// startPlan: a game flow before the first real measure (it comes within a second): a light protection, never
// copies; also when the other side stopped telling
var startPlan = Plan{Every: winWide, Win: winWide}

// Policy: the plan of one direction, from what the other side measured on it. It goes up at once when
// the line gets worse and down only after calmFor of a better line (halfway each time), so a quiet second never
// takes the protection away in the middle of a fight.
type Policy struct {
	mu       sync.Mutex
	permille uint32
	burst    uint32
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
	if !p.measured {
		// the first real measure replaces the start guess, up or down
		p.measured, p.permille, p.burst, p.better, p.report = true, permille, burst, time.Time{}, now
		return
	}
	want, have := cost(planFor(permille, burst)), cost(planFor(p.permille, p.burst))
	switch {
	case want > have:
		p.permille, p.burst, p.better = permille, burst, time.Time{}
	case want < have:
		if p.better.IsZero() {
			p.better = now
		} else if now.Sub(p.better) >= calmFor {
			// halfway down, never below what is measured now
			p.permille = max(permille, p.permille/2)
			if p.permille < cleanBelow {
				p.permille = permille
			}
			p.burst = burst
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
	fresh := !p.report.IsZero() && now.Sub(p.report) < staleAfter
	if !fresh || !p.measured {
		return startPlan
	}
	return planFor(p.permille, p.burst)
}

// Step: how hard this direction is protected now, 0..5 (0 = nothing is sent besides the game), for the peer
// (KindStat) and the stats
func (p *Policy) Step() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	pl := planFor(p.permille, p.burst)
	switch {
	case pl.Copy:
		return 5
	case pl.Every == 0:
		return 0
	case pl.Every <= 2:
		return 4
	case pl.Every <= 5:
		return 3
	case pl.Every <= 15:
		return 2
	default:
		return 1
	}
}
