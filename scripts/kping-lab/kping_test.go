package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// the same packet the panel's test makes (kpingd::tests::wire_vector)
func TestWireVector(t *testing.T) {
	w, _ := newWire(strings.Repeat("ab", 32), strings.Repeat("cd", 32))
	h := hdr{7, 0x1234, 42, kData, 1}
	pkt := w.seal(h, []byte("hello"))
	if got := hex.EncodeToString(pkt); got != "43aaf90a2dbcbefbbc162ade68656c6c6f93669fa32522c2df" {
		t.Fatal(got)
	}
	g, p, ok := w.open(pkt)
	if !ok || g != h || string(p) != "hello" {
		t.Fatal("open")
	}
}

func TestParity(t *testing.T) {
	tx := &fecTx{k: 4}
	pk := [][]byte{[]byte("aaaa"), []byte("bbbbbbb"), []byte("cc"), []byte("dddddd")}
	var n byte
	var par []byte
	for i, p := range pk {
		n, par = tx.add(uint32(10+i), p)
	}
	var w window
	rx := &fecRx{}
	for _, s := range []uint32{10, 12, 13} {
		w.take(s)
		rx.data(s, pk[s-10], &w)
	}
	s, p, ok := rx.parity(n, par, &w)
	if !ok || s != 11 || string(p) != "bbbbbbb" {
		t.Fatal(s, string(p), ok)
	}
}
