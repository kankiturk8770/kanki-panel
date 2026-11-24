package game

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// Heavy bursty loss never panics: repairs delivered late and out of
// order under bursty loss must never panic the receiver (1.37 security review: evict freed a column of the window itself).
func TestHeavyBurstyLossNeverPanics(t *testing.T) {
	var seed uint64 = 99
	rnd := func() float64 {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return float64(seed%10000) / 10000.0
	}
	for round := 0; round < 200; round++ {
		var tx rlcTx
		var rx rlcRx
		rx.init()
		now := time.Now()
		loss, repRate := 0.1+0.4*rnd(), 0.2+rnd()
		bad := false
		var late [][]byte
		for s := uint32(1); s <= 600; s++ {
			tx.add(s, pkt(s), now.Add(time.Second))
			if bad {
				bad = rnd() > 0.2
			} else {
				bad = rnd() < 0.05
			}
			if !(bad || rnd() < loss) {
				for _, r := range rx.data(s, pkt(s), now) {
					if !bytes.Equal(r.p, pkt(r.seq)) {
						t.Fatalf("round %d wrong", round)
					}
				}
			}
			r := repRate
			for rnd() < r {
				r -= 1.0
				rep := append([]byte(nil), tx.repair(now, 4+int(rnd()*13.0))...)
				if !(bad || rnd() < loss) {
					late = append(late, rep)
				}
			}
			for len(late) > int(rnd()*12.0) {
				i := int(rnd()*float64(len(late))) % len(late)
				rep := late[i]
				late[i] = late[len(late)-1]
				late = late[:len(late)-1]
				func() {
					defer func() {
						if e := recover(); e != nil {
							panic(fmt.Sprintf("round %d seq %d base %d n %d: %v", round, s, uint32(rep[0])<<24|uint32(rep[1])<<16|uint32(rep[2])<<8|uint32(rep[3]), rep[4], e))
						}
					}()
					for _, q := range rx.repair(rep, now) {
						if !bytes.Equal(q.p, pkt(q.seq)) {
							t.Fatalf("round %d wrong rebuild", round)
						}
					}
				}()
			}
		}
	}
}
