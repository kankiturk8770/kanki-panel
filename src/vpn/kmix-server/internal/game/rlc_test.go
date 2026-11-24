package game

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func pkt(seq uint32) []byte {
	return []byte(fmt.Sprintf("packet-%04d-%s", seq, bytes.Repeat([]byte{byte(seq)}, int(seq%37))))
}

// two and three packets lost in a row, one repair per packet over sliding windows: all of them come back
// (v2's XOR parity rebuilds one per group)
func TestRLCBurst(t *testing.T) {
	var tx rlcTx
	var rx rlcRx
	rx.init()
	now := time.Now()
	lost := map[uint32]bool{9: true, 10: true, 20: true, 21: true, 22: true}
	got := map[uint32]string{}
	for s := uint32(1); s <= 40; s++ {
		p := pkt(s)
		tx.add(s, p, now.Add(time.Second))
		if !lost[s] {
			got[s] = string(p)
			for _, r := range rx.data(s, p, now) {
				got[r.seq] = string(r.p)
			}
		}
		rep := append([]byte(nil), tx.repair(now, 8)...)
		for _, r := range rx.repair(rep, now) {
			got[r.seq] = string(r.p)
		}
	}
	for s := uint32(1); s <= 40; s++ {
		if got[s] != string(pkt(s)) {
			t.Fatalf("packet %d missing or wrong", s)
		}
	}
}

// random loss of packets and repairs: never a wrong packet, nearly all come back
func TestRLCRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for trial := 0; trial < 30; trial++ {
		var tx rlcTx
		var rx rlcRx
		rx.init()
		now := time.Now()
		got := map[uint32]string{}
		const total = 500
		for s := uint32(1); s <= total; s++ {
			p := pkt(s)
			tx.add(s, p, now.Add(time.Second))
			if rng.Float64() > 0.12 {
				got[s] = string(p)
				for _, r := range rx.data(s, p, now) {
					got[r.seq] = string(r.p)
				}
			}
			if rng.Float64() < 0.6 {
				rep := append([]byte(nil), tx.repair(now, 12)...)
				if rng.Float64() > 0.12 {
					for _, r := range rx.repair(rep, now) {
						if _, dup := got[r.seq]; dup {
							t.Fatalf("packet %d rebuilt twice", r.seq)
						}
						got[r.seq] = string(r.p)
					}
				}
			}
		}
		for s, v := range got {
			if v != string(pkt(s)) {
				t.Fatalf("trial %d: packet %d wrong", trial, s)
			}
		}
		if len(got) < total*97/100 {
			t.Fatalf("trial %d: only %d of %d", trial, len(got), total)
		}
	}
}

// dead packets are never protected: a repair covers only the ones still before their deadline
func TestRLCDeadline(t *testing.T) {
	var tx rlcTx
	now := time.Now()
	tx.add(1, pkt(1), now.Add(10*time.Millisecond))
	tx.add(2, pkt(2), now.Add(10*time.Millisecond))
	tx.add(3, pkt(3), now.Add(time.Second))
	rep := tx.repair(now.Add(50*time.Millisecond), 8)
	if rep == nil || binary.BigEndian.Uint32(rep) != 3 || rep[4] != 1 {
		t.Fatalf("window %v", rep[:6])
	}
	tx.add(4, pkt(4), now.Add(10*time.Millisecond))
	if tx.repair(now.Add(50*time.Millisecond), 8) != nil {
		t.Fatal("a repair for dead packets")
	}
}

// a packet rebuilt too late is not handed to the game
func TestRLCStale(t *testing.T) {
	var tx rlcTx
	var rx rlcRx
	rx.init()
	t0 := time.Now()
	tx.add(1, pkt(1), t0.Add(time.Hour))
	tx.add(2, pkt(2), t0.Add(time.Hour))
	rx.data(2, pkt(2), t0)
	rep := tx.repair(t0, 8)
	if out := rx.repair(rep, t0.Add(time.Second)); len(out) != 0 || rx.stale != 1 {
		t.Fatalf("stale packet delivered: %d %d", len(out), rx.stale)
	}
}

// the same repair the panel's kprlc test makes (kprlc::tests::same_repair_as_the_app)
func TestRLCVector(t *testing.T) {
	var tx rlcTx
	far := time.Now().Add(10 * time.Second)
	for s := uint32(1); s <= 3; s++ {
		tx.add(s, pkt(s), far)
	}
	rep := tx.repair(time.Now(), 8)
	if got := fmt.Sprintf("%x", rep); got != "00000001030000444e926cb373af1af8f8f8821a7a8b83" || len(rep) != 23 {
		t.Fatal(got, len(rep))
	}
}
