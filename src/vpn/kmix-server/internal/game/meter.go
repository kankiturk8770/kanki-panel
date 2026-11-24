package game

import "sync"

// Meter: the loss of one direction of a flow as the line gives it (before copies and repairs), counted on the
// first copy of every packet only. A packet that comes late (out of order, within 64) is taken back off
// the losses. The counts decay by half every Take, so the number follows the last few seconds.
type Meter struct {
	mu       sync.Mutex
	top      uint32
	any      bool
	seen     uint64 // the last 64 sequence numbers below top that arrived (bit i = top-i)
	expected uint32
	lost     uint32
	run      uint32 // packets lost in a row right now
	burst    uint32 // the longest run since the last Take
}

// Seen: the first copy of packet seq arrived
func (m *Meter) Seen(seq uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.any {
		m.any, m.top, m.seen = true, seq, 1
		m.expected++
		return
	}
	d := int32(seq - m.top)
	switch {
	case d > 0:
		gap := uint32(d - 1)
		if gap > 1000 {
			// a new start of the counter (or a jump far ahead): not losses
			gap = 0
		}
		m.expected += uint32(d)
		m.lost += gap
		if gap > 0 {
			m.run = gap
			if m.run > m.burst {
				m.burst = m.run
			}
		}
		if d >= 64 {
			m.seen = 1
		} else {
			m.seen = m.seen<<uint(d) | 1
		}
		m.top = seq
	case d > -64:
		bit := uint64(1) << uint(-d)
		if m.seen&bit == 0 {
			m.seen |= bit
			if m.lost > 0 {
				m.lost-- // it was counted lost: it only came late
			}
		}
	}
}

// Take: the counts since the last Take (they decay by half) as loss in permille (0..1000) and the longest
// run of packets lost in a row; n = how many packets this is about
func (m *Meter) Take() (permille, burst, n uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.expected > 0 {
		permille = min(1000, (m.lost*1000+m.expected/2)/m.expected)
	}
	burst, n = m.burst, m.expected
	m.expected, m.lost, m.burst = m.expected/2, m.lost/2, 0
	return
}

// Sum: several flows of one session into one number, weighted by their packets
type Sum struct{ lost1000, n, burst uint32 }

func (s *Sum) Add(permille, burst, n uint32) {
	s.lost1000 += permille * n // lost × 1000: no rounding away of a few lost packets
	s.n += n
	s.burst = max(s.burst, burst)
}

// Result: permille, the longest burst, and the packets it is about
func (s *Sum) Result() (permille, burst, n uint32) {
	if s.n == 0 {
		return 0, 0, 0
	}
	return min(1000, s.lost1000/s.n), s.burst, s.n
}
