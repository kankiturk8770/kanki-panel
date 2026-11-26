package obfs

// Routing hints (protocol 3, panel 3.67). A client that said hello (KindHello) gets an 8-byte hint from the
// server inside the encrypted answer, and puts it in front of the packets it sends:
//
//	[ 8B hint ][ 12B random nonce ][ AEAD( [1B kind][2B length][payload] + random padding ) ]
//
// The hint is random bytes the server made and keeps in a table: hint -> (user, session). A packet from an
// address the server has never seen (the phone moved from Wi-Fi to mobile data, or a second path of the same
// session) is opened with that one user's key, found in O(1), instead of trying the key of every user. The
// hint carries nothing of the user or the key, it is not a fixed value (every hello gets a new one, and an old
// one ends after hintTTL), and the rest of the packet is exactly the old format, so nothing on the wire is
// constant.
//
// Old clients send no hint: their packets go the old way (the key of their known address, else every key,
// rate-limited per IP). A packet whose first 8 bytes are not a live hint is taken as an old one, so a random
// collision only costs the old path.

import (
	"crypto/rand"
	"net"
	"sync"
	"time"
)

const (
	// HintLen bytes in front of a hinted packet (client -> server only)
	HintLen = 8
	// HintTTL how long a hint stays good after it was given
	HintTTL = 10 * time.Minute
	// hintsPerSession the newest hints of one session that stay good (the older ones end at once)
	hintsPerSession = 4
	// maxHints all hints of all sessions together (memory stays bounded under a flood of hellos)
	maxHints = 200000
)

// Hint one routing hint
type Hint [HintLen]byte

type hintEntry struct {
	u   *User
	sid uint64
	exp int64 // UnixNano
}

type hintTable struct {
	mu     sync.RWMutex
	byHint map[Hint]*hintEntry
	bySess map[uint64][]Hint // oldest first
}

func newHintTable() *hintTable {
	return &hintTable{byHint: map[Hint]*hintEntry{}, bySess: map[uint64][]Hint{}}
}

// IssueHint gives session sid of the user whose packet just came from addr a new hint. false when the address
// belongs to no user (the hello did not open with a known key) or the table is full.
func (k *Keyring) IssueHint(addr net.Addr, sid uint64) (Hint, bool) {
	var h Hint
	u := k.UserOf(addr)
	if u == nil {
		return h, false
	}
	t := k.hints
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.byHint) >= maxHints {
		t.expireLocked(time.Now().UnixNano())
		if len(t.byHint) >= maxHints {
			return h, false
		}
	}
	for {
		if _, err := rand.Read(h[:]); err != nil {
			return h, false
		}
		if _, used := t.byHint[h]; !used {
			break
		}
	}
	t.byHint[h] = &hintEntry{u: u, sid: sid, exp: time.Now().Add(HintTTL).UnixNano()}
	list := append(t.bySess[sid], h)
	for len(list) > hintsPerSession {
		delete(t.byHint, list[0])
		list = list[1:]
	}
	t.bySess[sid] = list
	return h, true
}

// lookup the live entry of a hint (nil = none)
func (t *hintTable) lookup(b []byte) *hintEntry {
	var h Hint
	copy(h[:], b)
	t.mu.RLock()
	e := t.byHint[h]
	t.mu.RUnlock()
	if e == nil || time.Now().UnixNano() > e.exp {
		return nil
	}
	return e
}

// HintSession the session a live hint was given to (for the tests and the stats)
func (k *Keyring) HintSession(h Hint) (uint64, bool) {
	e := k.hints.lookup(h[:])
	if e == nil {
		return 0, false
	}
	return e.sid, true
}

// Hinted how many sessions hold a live hint (clients that speak protocol 3)
func (k *Keyring) Hinted() int {
	t := k.hints
	now := time.Now().UnixNano()
	t.mu.RLock()
	defer t.mu.RUnlock()
	n := 0
	for _, list := range t.bySess {
		for _, h := range list {
			if e := t.byHint[h]; e != nil && e.exp >= now {
				n++
				break
			}
		}
	}
	return n
}

// keep only the hints of users still in the ring (a removed user or a new key: its hints end at once)
func (t *hintTable) retain(alive func(*User) *User) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, e := range t.byHint {
		if nu := alive(e.u); nu != nil {
			e.u = nu
		} else {
			delete(t.byHint, h)
		}
	}
	t.rebuildLocked()
}

func (t *hintTable) expireLocked(now int64) {
	for h, e := range t.byHint {
		if e.exp < now {
			delete(t.byHint, h)
		}
	}
	t.rebuildLocked()
}

// rebuildLocked drops from bySess the hints that are gone
func (t *hintTable) rebuildLocked() {
	for sid, list := range t.bySess {
		keep := list[:0]
		for _, h := range list {
			if _, ok := t.byHint[h]; ok {
				keep = append(keep, h)
			}
		}
		if len(keep) == 0 {
			delete(t.bySess, sid)
		} else {
			t.bySess[sid] = keep
		}
	}
}

func (t *hintTable) expire() {
	t.mu.Lock()
	t.expireLocked(time.Now().UnixNano())
	t.mu.Unlock()
}

// SealHinted (client side) one packet with the hint in front, in the format above
func (c *PacketConn) SealHinted(h Hint, kind byte, b []byte) ([]byte, error) {
	sc := &sealCapture{}
	tmp := &PacketConn{conn: sc, aead: c.aead}
	if err := tmp.WritePacket(kind, b, nil); err != nil {
		return nil, err
	}
	return append(h[:], sc.last...), nil
}

// sealCapture keeps the sealed packet instead of sending it
type sealCapture struct {
	net.PacketConn
	last []byte
}

func (c *sealCapture) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.last = append([]byte(nil), b...)
	return len(b), nil
}
