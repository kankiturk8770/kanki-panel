package game

import (
	"sync/atomic"
	"time"
)

// Kind of a UDP flow
const (
	KindUnknown = iota
	KindGame    // small packets, many a second: a game (or a call); protected
	KindBulk    // QUIC, video, big packets: never copied or repaired
	KindCtl     // DNS, NTP …: few and short; never protected
)

// Class: what one UDP flow is, from its port, its packet sizes and how often they come. It is decided
// again every second, so a flow that starts with a burst of big packets (a map download over UDP) and
// then plays is protected once it plays.
type Class struct {
	kind    atomic.Int32
	winAt   atomic.Int64 // start of the current second (UnixNano)
	count   atomic.Int32 // packets in it
	bytes   atomic.Int64 // their bytes
	lastAct atomic.Int64 // the last packet of play (UnixNano)
}

// ctlPort: services that are never a game
func ctlPort(p uint16) bool {
	switch p {
	case 53, 853, 5353, 5355, 67, 68, 123, 137, 138, 1900, 3702:
		return true
	}
	return false
}

// Note: a packet of the flow (either direction); port = the port of the far end; returns the kind now
func (c *Class) Note(size int, port uint16, now time.Time) int {
	if ctlPort(port) {
		c.kind.Store(KindCtl)
		return KindCtl
	}
	if port == 443 || port == 80 {
		// QUIC / HTTP/3: a web or video stream, it has its own recovery
		c.kind.Store(KindBulk)
		return KindBulk
	}
	t := now.UnixNano()
	start := c.winAt.Load()
	if start == 0 {
		c.winAt.Store(t)
		start = t
	}
	n := c.count.Add(1)
	b := c.bytes.Add(int64(size))
	if t-start >= int64(time.Second) {
		// the second is over: decide from it
		k := int32(KindBulk)
		if n >= 5 && b/int64(n) <= 600 {
			k = KindGame
		}
		c.kind.Store(k)
		c.winAt.Store(t)
		c.count.Store(0)
		c.bytes.Store(0)
	} else if c.kind.Load() == KindUnknown {
		// the first second: small packets are taken for a game, so the very first fight is protected too
		if size <= 400 {
			c.kind.Store(KindGame)
		}
	}
	k := int(c.kind.Load())
	if k == KindGame {
		c.lastAct.Store(t)
	}
	return k
}

// Kind: the kind decided last
func (c *Class) Kind() int { return int(c.kind.Load()) }

// Playing: a game packet went through this flow within d
func (c *Class) Playing(now time.Time, d time.Duration) bool {
	l := c.lastAct.Load()
	return l != 0 && now.UnixNano()-l < int64(d)
}
