package game

import "time"

// Tx: the sending side of the repairs of one flow and one direction
type Tx struct{ t rlcTx }

// Add: a protected packet went out (seq of the flow, payload); it may be covered until deadline
func (t *Tx) Add(seq uint32, p []byte, deadline time.Time) { t.t.add(seq, p, deadline) }

// Last: the newest packet added (false = none yet)
func (t *Tx) Last() (uint32, bool) { return t.t.last, t.t.any }

// Repair: one repair over the newest live packets (at most win); nil = nothing worth protecting.
// The slice is valid until the next call.
func (t *Tx) Repair(now time.Time, win int) []byte { return t.t.repair(now, win) }

// Rebuilt: a packet the repairs gave back
type Rebuilt struct {
	Seq     uint32
	Payload []byte
}

// Rx: the receiving side of one flow and one direction
type Rx struct {
	r   rlcRx
	ok  bool
	out []Rebuilt
}

func (x *Rx) start() {
	if !x.ok {
		x.r.init()
		x.ok = true
	}
}

func (x *Rx) give(l []rebuilt) []Rebuilt {
	x.out = x.out[:0]
	for _, b := range l {
		x.out = append(x.out, Rebuilt{b.seq, b.p})
	}
	return x.out
}

// Data: a packet of the flow arrived (any copy, the first time); returns packets rebuilt thanks to it
func (x *Rx) Data(seq uint32, p []byte, now time.Time) []Rebuilt {
	x.start()
	return x.give(x.r.data(seq, p, now))
}

// Repair: a repair arrived; returns packets rebuilt thanks to it
func (x *Rx) Repair(pl []byte, now time.Time) []Rebuilt {
	x.start()
	return x.give(x.r.repair(pl, now))
}

// Fixed: packets rebuilt in time; Stale: rebuilt too late to be delivered
func (x *Rx) Fixed() uint64 { return x.r.fixed }
func (x *Rx) Stale() uint64 { return x.r.stale }
