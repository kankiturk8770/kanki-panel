package obfs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

func hinted(t *testing.T, key []byte, h Hint, payload []byte) []byte {
	t.Helper()
	pc, err := New(&capture{}, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := pc.SealHinted(h, 0x01, payload)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

// exhaust: a flood from ip used up its key scans for this second
func exhaust(ring *Keyring, ip net.IP) {
	junk := make([]byte, 120)
	out := make([]byte, 65535)
	for i := 0; i < scanPerSec+5; i++ {
		ring.open(junk, &net.UDPAddr{IP: ip, Port: 9000 + i}, out)
	}
}

// a phone that moves (Wi-Fi -> mobile data) keeps its session: a hinted packet from the new address is opened
// with its own key at once, without trying the other users' keys (here: even when the scans of that IP are used up)
func TestHintRoutesARoamingPhoneInOneLookup(t *testing.T) {
	ring, keys := ringWith(300)
	out := make([]byte, 65535)
	wifi := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 7), Port: 40000}
	if u, _, ok := ring.open(seal(keys[123], []byte("hi")), wifi, out); !ok || u.Name != "u123" {
		t.Fatal("the first (old format) packet did not open")
	}
	h, ok := ring.IssueHint(wifi, 77)
	if !ok {
		t.Fatal("no hint for a known address")
	}
	if sid, ok := ring.HintSession(h); !ok || sid != 77 {
		t.Fatalf("hint names session %d", sid)
	}
	cell := &net.UDPAddr{IP: net.IPv4(100, 64, 3, 9), Port: 51000}
	exhaust(ring, cell.IP)
	// the old format from the new address: no scan left, dropped (what an old app would see for a moment)
	if _, _, ok := ring.open(seal(keys[123], []byte("old")), &net.UDPAddr{IP: cell.IP, Port: 51001}, out); ok {
		t.Fatal("a key scan ran past its limit")
	}
	u, p, ok := ring.open(hinted(t, keys[123], h, []byte("game")), cell, out)
	if !ok || u.Name != "u123" || !bytes.Equal(p[3:7], []byte("game")) {
		t.Fatalf("the hinted packet did not open: %v %v", ok, u)
	}
	if got := ring.UserOf(cell); got == nil || got.Name != "u123" {
		t.Fatal("the new address was not learned for the answers")
	}
	// another user's key behind this hint (a copied hint): it does not open as that session
	if u, _, ok := ring.open(hinted(t, keys[5], h, []byte("x")), &net.UDPAddr{IP: net.IPv4(100, 64, 3, 10), Port: 1}, out); ok && u.Name == "u123" {
		t.Fatal("another key opened as u123")
	}
}

// the old format keeps working beside hints, and a hint that is gone falls back to the old way
func TestOldClientsAndEndedHints(t *testing.T) {
	ring, keys := ringWith(20)
	out := make([]byte, 65535)
	a := &net.UDPAddr{IP: net.IPv4(1, 1, 1, 1), Port: 1}
	if u, _, ok := ring.open(seal(keys[3], []byte("v1")), a, out); !ok || u.Name != "u3" {
		t.Fatal("an old client's packet did not open")
	}
	// a hint the server never gave: taken as an old packet (and not opened, since it is not one)
	var fake Hint
	copy(fake[:], "notahint")
	if _, _, ok := ring.open(hinted(t, keys[3], fake, []byte("x")), &net.UDPAddr{IP: net.IPv4(2, 2, 2, 2), Port: 2}, out); ok {
		t.Fatal("an unknown hint opened")
	}
	// the newest hintsPerSession stay good, older ones end
	var hs []Hint
	for i := 0; i < hintsPerSession+1; i++ {
		h, ok := ring.IssueHint(a, 9)
		if !ok {
			t.Fatal("no hint")
		}
		hs = append(hs, h)
	}
	if _, ok := ring.HintSession(hs[0]); ok {
		t.Fatal("the oldest hint is still good")
	}
	if _, ok := ring.HintSession(hs[len(hs)-1]); !ok {
		t.Fatal("the newest hint is not good")
	}
	// an ended hint from the address the session already uses: opened with that user's key
	if u, _, ok := ring.open(hinted(t, keys[3], hs[0], []byte("y")), a, out); !ok || u.Name != "u3" {
		t.Fatal("a hinted packet with an ended hint from a known address was dropped")
	}
	// a removed user: their hints end at once
	keep := map[string]string{}
	for i, k := range keys {
		if i != 3 {
			keep[hexOf(k)] = userName(i)
		}
	}
	if err := ring.Set(keep); err != nil {
		t.Fatal(err)
	}
	if _, ok := ring.HintSession(hs[len(hs)-1]); ok {
		t.Fatal("a removed user's hint still routes")
	}
	// an address the hints never knew gets no hint
	if _, ok := ring.IssueHint(&net.UDPAddr{IP: net.IPv4(8, 8, 4, 4), Port: 3}, 1); ok {
		t.Fatal("a hint for an unknown address")
	}
}

// hints given and used from many goroutines at once (go test -race)
func TestHintsUnderLoad(t *testing.T) {
	ring, keys := ringWith(50)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			out := make([]byte, 65535)
			a := &net.UDPAddr{IP: net.IPv4(10, 1, 0, byte(g)), Port: 1000}
			if _, _, ok := ring.open(seal(keys[g], []byte("a")), a, out); !ok {
				t.Error("first packet")
				return
			}
			for i := 0; i < 200; i++ {
				h, ok := ring.IssueHint(a, uint64(g))
				if !ok {
					t.Error("no hint")
					return
				}
				b := &net.UDPAddr{IP: net.IPv4(10, 2, byte(g), byte(i)), Port: 2000}
				if u, _, ok := ring.open(hinted(t, keys[g], h, []byte("p")), b, out); !ok || u.Name != userName(g) {
					t.Error("hinted packet under load")
					return
				}
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			ring.hints.expire()
			_ = ring.Hinted()
			time.Sleep(time.Millisecond)
		}
	}()
	wg.Wait()
	if n := ring.Hinted(); n != 8 {
		t.Fatalf("%d sessions with hints, want 8", n)
	}
}

func hexOf(k []byte) string { return hex.EncodeToString(k) }

func userName(i int) string { return fmt.Sprintf("u%d", i) }
