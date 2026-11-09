// The KPING v2 client side, as the lab uses it (and the wire the app will speak): see src/vpn/kpingd.rs.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	hdrLen   = 12
	tagLen   = 8
	down     = 0x80
	kData    = 1
	kParity  = 2
	kPing    = 3
	kPong    = 4
	winBits  = 1024
	maxGroup = 8
)

type hdr struct {
	uid  uint32
	sess uint16
	seq  uint32
	kind byte
	aux  byte
}

func (h hdr) bytes() []byte {
	b := make([]byte, hdrLen)
	binary.BigEndian.PutUint32(b, h.uid)
	binary.BigEndian.PutUint16(b[4:], h.sess)
	binary.BigEndian.PutUint32(b[6:], h.seq)
	b[10], b[11] = h.kind, h.aux
	return b
}

type wire struct {
	obfs cipher.Block
	key  []byte
}

func newWire(obfsHex, keyHex string) (*wire, error) {
	o, err := hex.DecodeString(obfsHex)
	if err != nil || len(o) != 32 {
		return nil, errors.New("bad obfs key")
	}
	k, err := hex.DecodeString(keyHex)
	if err != nil || len(k) != 32 {
		return nil, errors.New("bad key")
	}
	b, err := aes.NewCipher(o)
	if err != nil {
		return nil, err
	}
	return &wire{obfs: b, key: k}, nil
}

func (w *wire) tag(h, payload []byte) []byte {
	m := hmac.New(sha256.New, w.key)
	m.Write(h)
	m.Write(payload)
	return m.Sum(nil)[:tagLen]
}

func (w *wire) mask(tag []byte) []byte {
	in := make([]byte, 16)
	copy(in, tag)
	copy(in[8:], "KPNG")
	out := make([]byte, 16)
	w.obfs.Encrypt(out, in)
	return out[:hdrLen]
}

func (w *wire) seal(h hdr, payload []byte) []byte {
	hb := h.bytes()
	t := w.tag(hb, payload)
	m := w.mask(t)
	out := make([]byte, 0, hdrLen+len(payload)+tagLen)
	for i := range hb {
		out = append(out, hb[i]^m[i])
	}
	out = append(out, payload...)
	return append(out, t...)
}

// open: the header and payload of a packet made with this key
func (w *wire) open(pkt []byte) (hdr, []byte, bool) {
	if len(pkt) < hdrLen+tagLen {
		return hdr{}, nil, false
	}
	t := pkt[len(pkt)-tagLen:]
	m := w.mask(t)
	hb := make([]byte, hdrLen)
	for i := range hb {
		hb[i] = pkt[i] ^ m[i]
	}
	payload := pkt[hdrLen : len(pkt)-tagLen]
	if !hmac.Equal(w.tag(hb, payload), t) {
		return hdr{}, nil, false
	}
	return hdr{binary.BigEndian.Uint32(hb), binary.BigEndian.Uint16(hb[4:]), binary.BigEndian.Uint32(hb[6:]), hb[10], hb[11]}, payload, true
}

// window: the first copy of a sequence number passes
type window struct {
	top  uint32
	any  bool
	bits [winBits / 64]uint64
}

func (w *window) take(seq uint32) bool {
	if !w.any {
		w.any, w.top = true, seq
	} else if seq > w.top {
		if seq-w.top >= winBits {
			w.bits = [winBits / 64]uint64{}
		} else {
			for s := w.top + 1; s < seq; s++ {
				w.bits[(s%winBits)/64] &^= 1 << (s % 64)
			}
		}
		w.bits[(seq%winBits)/64] &^= 1 << (seq % 64)
		w.top = seq
	} else if w.top-seq >= winBits {
		return false
	}
	i := seq % winBits
	if w.bits[i/64]&(1<<(i%64)) != 0 {
		return false
	}
	w.bits[i/64] |= 1 << (i % 64)
	return true
}

func (w *window) has(seq uint32) bool {
	if !w.any || seq > w.top || w.top-seq >= winBits {
		return false
	}
	i := seq % winBits
	return w.bits[i/64]&(1<<(i%64)) != 0
}

// fecTx: XOR parity of groups of up to k packets (sent when full, or after 8 ms)
type fecTx struct {
	mu    sync.Mutex
	k     int
	first uint32
	n     int
	lenX  uint16
	x     []byte
	last  time.Time
}

func (f *fecTx) add(seq uint32, p []byte) (byte, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.k < 2 {
		return 0, nil
	}
	if f.n > 0 && seq != f.first+uint32(f.n) {
		f.n = 0
	}
	if f.n == 0 {
		f.first, f.lenX, f.x = seq, 0, f.x[:0]
	}
	f.lenX ^= uint16(len(p))
	for len(f.x) < len(p) {
		f.x = append(f.x, 0)
	}
	for i, b := range p {
		f.x[i] ^= b
	}
	f.n++
	f.last = time.Now()
	if f.n >= f.k {
		return f.take()
	}
	return 0, nil
}

func (f *fecTx) flush() (byte, []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n >= 1 && time.Since(f.last) >= 8*time.Millisecond {
		return f.take()
	}
	return 0, nil
}

func (f *fecTx) take() (byte, []byte) {
	n := f.n
	f.n = 0
	if n < 2 {
		return 0, nil
	}
	p := make([]byte, 6, 6+len(f.x))
	binary.BigEndian.PutUint32(p, f.first)
	binary.BigEndian.PutUint16(p[4:], f.lenX)
	return byte(n), append(p, f.x...)
}

type parity struct {
	first uint32
	n     byte
	lenX  uint16
	x     []byte
}

// fecRx: the last payloads and the parities still missing one packet
type fecRx struct {
	got  map[uint32][]byte
	wait []parity
}

func (f *fecRx) data(seq uint32, p []byte, w *window) (uint32, []byte, bool) {
	if f.got == nil {
		f.got = map[uint32][]byte{}
	}
	f.got[seq] = append([]byte(nil), p...)
	if len(f.got) > 256 {
		for s := range f.got {
			if w.any && w.top-s > 128 {
				delete(f.got, s)
			}
		}
	}
	return f.solve(w)
}

func (f *fecRx) parity(n byte, p []byte, w *window) (uint32, []byte, bool) {
	if len(p) < 6 || n < 2 || n > maxGroup {
		return 0, nil, false
	}
	f.wait = append(f.wait, parity{binary.BigEndian.Uint32(p), n, binary.BigEndian.Uint16(p[4:]), append([]byte(nil), p[6:]...)})
	if len(f.wait) > 16 {
		f.wait = f.wait[1:]
	}
	return f.solve(w)
}

func (f *fecRx) solve(w *window) (uint32, []byte, bool) {
	keep := f.wait[:0]
	var rs uint32
	var rp []byte
	found := false
	for _, q := range f.wait {
		if found {
			keep = append(keep, q)
			continue
		}
		var missing []uint32
		for i := uint32(0); i < uint32(q.n); i++ {
			if !w.has(q.first + i) {
				missing = append(missing, q.first+i)
			}
		}
		switch len(missing) {
		case 0:
		case 1:
			l := q.lenX
			p := append([]byte(nil), q.x...)
			ok := true
			for i := uint32(0); i < uint32(q.n); i++ {
				s := q.first + i
				if s == missing[0] {
					continue
				}
				o, has := f.got[s]
				if !has {
					ok = false
					break
				}
				l ^= uint16(len(o))
				for j := 0; j < len(o) && j < len(p); j++ {
					p[j] ^= o[j]
				}
			}
			if ok && l > 0 && int(l) <= len(p) {
				rs, rp, found = missing[0], p[:l], true
			}
		default:
			keep = append(keep, q)
		}
	}
	f.wait = keep
	return rs, rp, found
}
