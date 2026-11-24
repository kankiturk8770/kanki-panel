// Sliding-window random linear repair over GF(256) for the game packets of KANKI MIX (the same code as
// KPING v3's rlc.go, made smaller for one game flow: blocks up to MaxBlock bytes, 64 kept by the receiver).
//
// A repair covers the newest packets of a window [base, base+n) (n <= 16), as a random linear combination
// of their blocks (block = len (2, BE) | payload), so the lost packets of a window come back as soon as
// enough repairs arrive, and windows that overlap solve together: two or three packets lost in a row come
// back. The receiver keeps only the equations that still have unknowns, in reduced row-echelon form, so a
// repair whose packets all arrived costs nothing.
//
// Repair payload: base seq (4, BE) | n (1) | index (1) | coded block (padded to the longest block)
package game

import (
	"encoding/binary"
	"time"
)

const (
	maxWin    = 16
	RepHdr    = 6
	rxKeep    = 64 // recent blocks kept by the receiver (by sequence)
	maxRows   = 32
	maxCols   = 32
	blockMeta = 2
	// MaxBlock: the largest block (2 + payload); bigger packets are not protected (game packets are far smaller)
	MaxBlock = 720
	maxBlock = MaxBlock
	noPivot  = -1
	// MaxProtect: the largest payload a repair can cover
	MaxProtect = MaxBlock - blockMeta
	rlcRecvAge = 300 * time.Millisecond // a packet rebuilt later than this is old news and is not delivered
)

// ------------------------------------------------------------------ GF(256), 0x11d

var (
	gfExp [512]byte
	gfLog [256]byte
	gfMul [256][256]byte
)

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[x] = byte(i)
		x <<= 1
		if x&0x100 != 0 {
			x ^= 0x11d
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
	for a := 1; a < 256; a++ {
		for b := 1; b < 256; b++ {
			gfMul[a][b] = gfExp[int(gfLog[a])+int(gfLog[b])]
		}
	}
}

func gfInv(a byte) byte {
	if a == 0 {
		return 0
	}
	return gfExp[255-int(gfLog[a])]
}

// mulAdd: dst ^= c*src (len(dst) ≥ len(src))
func mulAdd(dst, src []byte, c byte) {
	switch c {
	case 0:
	case 1:
		for i, v := range src {
			dst[i] ^= v
		}
	default:
		row := &gfMul[c]
		for i, v := range src {
			dst[i] ^= row[v]
		}
	}
}

func scale(dst []byte, c byte) {
	if c == 1 {
		return
	}
	row := &gfMul[c]
	for i, v := range dst {
		dst[i] = row[v]
	}
}

// coef: the coefficient of row `row` in repair `index` of window (base, n). Never 0. The panel uses the same.
func coef(base uint32, n, index byte, row int) byte {
	x := uint64(base) + 0x9e3779b97f4a7c15
	x ^= uint64(n) << 17
	x ^= uint64(index+1) * 0xbf58476d1ce4e5b9
	x ^= uint64(row+1) * 0x94d049bb133111eb
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return byte(x%255) + 1
}

// ------------------------------------------------------------------ sending

type txBlock struct {
	seq      uint32
	ok       bool
	deadline time.Time
	n        int
	b        [maxBlock]byte
}

// rlcTx: the recent protected packets of one direction and the repairs made of them
type rlcTx struct {
	hist      [maxWin * 2]txBlock
	last      uint32
	any       bool
	lastBase  uint32
	lastIndex byte
	hasLast   bool
	buf       [maxBlock + RepHdr]byte
}

// add: a protected packet went out
func (t *rlcTx) add(seq uint32, p []byte, deadline time.Time) {
	if len(p)+blockMeta > maxBlock {
		return
	}
	h := &t.hist[seq%uint32(len(t.hist))]
	h.seq, h.ok, h.deadline = seq, true, deadline
	binary.BigEndian.PutUint16(h.b[:2], uint16(len(p)))
	copy(h.b[2:], p)
	h.n = blockMeta + len(p)
	t.last, t.any = seq, true
}

func (t *rlcTx) get(seq uint32) *txBlock {
	h := &t.hist[seq%uint32(len(t.hist))]
	if h.ok && h.seq == seq {
		return h
	}
	return nil
}

// repair: one repair over the newest packets that are still useful (at most `win`, none past its deadline).
// nil when there is nothing worth protecting. The slice is valid until the next call.
func (t *rlcTx) repair(now time.Time, win int) []byte {
	if !t.any {
		return nil
	}
	win = min(max(win, 1), maxWin)
	// the window: back from the newest while packets are contiguous, kept and not dead
	base := t.last
	for i := 1; i < win; i++ {
		s := t.last - uint32(i)
		h := t.get(s)
		if h == nil || now.After(h.deadline) {
			break
		}
		base = s
	}
	if h := t.get(t.last); h == nil || now.After(h.deadline) {
		return nil // the newest is dead too: nothing to save
	}
	n := byte(t.last - base + 1)
	index := byte(0)
	if t.hasLast && t.lastBase == base {
		index = t.lastIndex + 1
	}
	t.lastBase, t.lastIndex, t.hasLast = base, index, true
	longest := 0
	for i := 0; i < int(n); i++ {
		longest = max(longest, t.get(base+uint32(i)).n)
	}
	out := t.buf[:RepHdr+longest]
	clear(out)
	binary.BigEndian.PutUint32(out, base)
	out[4], out[5] = n, index
	for i := 0; i < int(n); i++ {
		h := t.get(base + uint32(i))
		mulAdd(out[RepHdr:], h.b[:h.n], coef(base, n, index, i))
	}
	return out
}

// ------------------------------------------------------------------ receiving

type rxBlock struct {
	seq uint32
	ok  bool
	at  time.Time
	n   int
	b   [maxBlock]byte
}

type eqRow struct {
	used  bool
	pivot int
	n     int
	coef  [maxCols]byte
	v     [maxBlock]byte
}

// rlcRx: known blocks and the equations of the repairs with unknowns (reduced row-echelon form)
type rlcRx struct {
	blocks  [rxKeep]rxBlock
	top     uint32
	any     bool
	rows    [maxRows]eqRow
	colSeq  [maxCols]uint32
	colUsed [maxCols]bool
	colRow  [maxCols]int
	scratch eqRow
	build   bool
	// rebuilt packets ready to deliver
	out []rebuilt
	// rebuilt in time / too late to be worth delivering
	fixed, stale uint64
}

type rebuilt struct {
	seq uint32
	p   []byte
}

func (r *rlcRx) init() {
	for i := range r.colRow {
		r.colRow[i] = noPivot
	}
	for i := range r.rows {
		r.rows[i].pivot = noPivot
	}
}

func (r *rlcRx) known(seq uint32) *rxBlock {
	b := &r.blocks[seq%rxKeep]
	if b.ok && b.seq == seq {
		return b
	}
	return nil
}

func (r *rlcRx) old(seq uint32) bool {
	return r.any && int32(r.top-seq) >= rxKeep-maxWin-1
}

// data: a packet that arrived (first copy). Returns packets rebuilt thanks to it.
func (r *rlcRx) data(seq uint32, p []byte, now time.Time) []rebuilt {
	r.out = r.out[:0]
	if len(p)+blockMeta > maxBlock || r.known(seq) != nil || r.old(seq) {
		return nil
	}
	b := r.store(seq, now)
	binary.BigEndian.PutUint16(b.b[:2], uint16(len(p)))
	copy(b.b[2:], p)
	b.n = blockMeta + len(p)
	r.advance(seq)
	r.substitute(seq, b.b[:b.n])
	r.collect(now)
	return r.out
}

func (r *rlcRx) store(seq uint32, now time.Time) *rxBlock {
	b := &r.blocks[seq%rxKeep]
	b.seq, b.ok, b.at = seq, true, now
	return b
}

func (r *rlcRx) advance(seq uint32) {
	if !r.any || int32(seq-r.top) > 0 {
		r.top, r.any = seq, true
		for c := range r.colUsed {
			if r.colUsed[c] && r.old(r.colSeq[c]) {
				r.expire(c)
			}
		}
	}
}

// repair: a repair arrived. Returns packets rebuilt thanks to it.
func (r *rlcRx) repair(pl []byte, now time.Time) []rebuilt {
	r.out = r.out[:0]
	if len(pl) <= RepHdr || len(pl)-RepHdr > maxBlock {
		return nil
	}
	base := binary.BigEndian.Uint32(pl)
	n, index := pl[4], pl[5]
	if n == 0 || n > maxWin || r.old(base) {
		return nil
	}
	if r.any && int32(base+uint32(n)-1-r.top) > maxWin {
		return nil // from far ahead of anything seen: not ours
	}
	coded := pl[RepHdr:]
	unknown, need := 0, 0
	for i := 0; i < int(n); i++ {
		s := base + uint32(i)
		if b := r.known(s); b != nil {
			if b.n > len(coded) {
				return nil
			}
			continue
		}
		unknown++
		if r.col(s) < 0 {
			need++
		}
	}
	if unknown == 0 {
		return nil // nothing in it we do not have
	}
	if need > r.free() && !r.evict(need, base, n) {
		return nil
	}
	e := &r.scratch
	clear(e.coef[:])
	clear(e.v[:])
	e.n = len(coded)
	copy(e.v[:], coded)
	r.build = true
	for i := 0; i < int(n); i++ {
		s := base + uint32(i)
		c := coef(base, n, index, i)
		if b := r.known(s); b != nil {
			mulAdd(e.v[:], b.b[:b.n], c)
			continue
		}
		col := r.col(s)
		if col < 0 {
			col = r.alloc(s)
		}
		if col < 0 { // cannot happen after evict; drop the repair, never the program (same as the panel's kprlc.rs)
			r.build = false
			r.gc()
			return nil
		}
		e.coef[col] ^= c
	}
	r.insert(e)
	r.build = false
	r.gc()
	r.collect(now)
	return r.out
}

func (r *rlcRx) col(seq uint32) int {
	for c := range r.colUsed {
		if r.colUsed[c] && r.colSeq[c] == seq {
			return c
		}
	}
	return -1
}

func (r *rlcRx) free() int {
	n := 0
	for _, u := range r.colUsed {
		if !u {
			n++
		}
	}
	return n
}

func (r *rlcRx) alloc(seq uint32) int {
	for c := range r.colUsed {
		if !r.colUsed[c] {
			r.colUsed[c], r.colSeq[c], r.colRow[c] = true, seq, noPivot
			return c
		}
	}
	return -1
}

// evict: drop the oldest unknowns (with their equations) until n columns are free, never one of the
// window [base, base+wn) being added (a late repair would otherwise free a column it needs itself and
// alloc would return -1: index out of range, the whole core exits)
func (r *rlcRx) evict(n int, base uint32, wn byte) bool {
	for r.free() < n {
		oldest := -1
		for c := range r.colUsed {
			if r.colUsed[c] && r.colSeq[c]-base >= uint32(wn) && (oldest < 0 || int32(r.colSeq[oldest]-r.colSeq[c]) > 0) {
				oldest = c
			}
		}
		if oldest < 0 {
			return false
		}
		r.expire(oldest)
	}
	return true
}

func (r *rlcRx) expire(c int) {
	for i := range r.rows {
		if r.rows[i].used && r.rows[i].coef[c] != 0 {
			r.drop(i)
		}
	}
	r.colUsed[c], r.colRow[c] = false, noPivot
}

func (r *rlcRx) drop(i int) {
	row := &r.rows[i]
	if !row.used {
		return
	}
	if row.pivot >= 0 && r.colRow[row.pivot] == i {
		r.colRow[row.pivot] = noPivot
	}
	clear(row.v[:row.n])
	clear(row.coef[:])
	row.used, row.n, row.pivot = false, 0, noPivot
	r.gc()
}

// gc: unknowns no equation mentions any more
func (r *rlcRx) gc() {
	for c := range r.colUsed {
		if !r.colUsed[c] {
			continue
		}
		ref := r.build && r.scratch.coef[c] != 0
		for i := 0; i < maxRows && !ref; i++ {
			ref = r.rows[i].used && r.rows[i].coef[c] != 0
		}
		if !ref {
			r.colUsed[c], r.colRow[c] = false, noPivot
		}
	}
}

// axpy: dst += f*src
func axpy(dst, src *eqRow, f byte) {
	if f == 0 {
		return
	}
	row := &gfMul[f]
	for c := 0; c < maxCols; c++ {
		if v := src.coef[c]; v != 0 {
			dst.coef[c] ^= row[v]
		}
	}
	mulAdd(dst.v[:], src.v[:src.n], f)
	dst.n = max(dst.n, src.n)
}

func norm(e *eqRow, p int) {
	inv := gfInv(e.coef[p])
	if inv == 1 {
		return
	}
	row := &gfMul[inv]
	for c := 0; c < maxCols; c++ {
		e.coef[c] = row[e.coef[c]]
	}
	scale(e.v[:e.n], inv)
}

func firstNZ(e *eqRow) int {
	for c := 0; c < maxCols; c++ {
		if e.coef[c] != 0 {
			return c
		}
	}
	return -1
}

func (r *rlcRx) insert(e *eqRow) {
	for i := range r.rows {
		if row := &r.rows[i]; row.used {
			axpy(e, row, e.coef[row.pivot])
		}
	}
	p := firstNZ(e)
	if p < 0 {
		return // nothing new in it
	}
	norm(e, p)
	for i := range r.rows {
		if row := &r.rows[i]; row.used {
			axpy(row, e, row.coef[p])
		}
	}
	slot := -1
	for i := range r.rows {
		if !r.rows[i].used {
			slot = i
			break
		}
	}
	if slot < 0 {
		// full: the equation of the oldest unknown goes
		slot = 0
		for i := range r.rows {
			if int32(r.colSeq[r.rows[slot].pivot]-r.colSeq[r.rows[i].pivot]) > 0 {
				slot = i
			}
		}
		r.drop(slot)
	}
	row := &r.rows[slot]
	row.coef, row.n, row.pivot, row.used = e.coef, e.n, p, true
	copy(row.v[:e.n], e.v[:e.n])
	r.colRow[p] = slot
}

// substitute: a packet that came after all: out of every equation
func (r *rlcRx) substitute(seq uint32, block []byte) {
	c := r.col(seq)
	if c < 0 {
		return
	}
	pr := r.colRow[c]
	for i := range r.rows {
		row := &r.rows[i]
		if row.used && row.coef[c] != 0 {
			mulAdd(row.v[:], block, row.coef[c])
			row.n = max(row.n, len(block))
			row.coef[c] = 0
		}
	}
	r.colUsed[c], r.colRow[c] = false, noPivot
	if pr == noPivot {
		return
	}
	row := &r.rows[pr]
	row.pivot = noPivot
	p := firstNZ(row)
	if p < 0 {
		r.drop(pr)
		return
	}
	norm(row, p)
	row.pivot = p
	r.colRow[p] = pr
	for i := range r.rows {
		if o := &r.rows[i]; i != pr && o.used {
			axpy(o, row, o.coef[p])
		}
	}
}

// collect: equations down to one unknown are rebuilt packets
func (r *rlcRx) collect(now time.Time) {
	for r.collectOnce(now) {
	}
}

func (r *rlcRx) collectOnce(now time.Time) bool {
	found := false
	for i := range r.rows {
		row := &r.rows[i]
		if !row.used {
			continue
		}
		single := true
		for c := 0; c < maxCols; c++ {
			if c != row.pivot && row.coef[c] != 0 {
				single = false
				break
			}
		}
		if !single {
			continue
		}
		found = true
		seq := r.colSeq[row.pivot]
		var tmp [maxBlock]byte
		v := tmp[:row.n]
		copy(v, row.v[:row.n])
		r.drop(i)
		if len(v) < blockMeta {
			continue
		}
		l := int(binary.BigEndian.Uint16(v))
		if l == 0 || blockMeta+l > len(v) || r.known(seq) != nil {
			continue
		}
		b := r.store(seq, now)
		// when it was due: about when the next packet that did arrive came
		for s := seq + 1; s != seq+maxWin && int32(s-r.top) <= 0; s++ {
			if k := r.known(s); k != nil && k != b {
				b.at = k.at
				break
			}
		}
		copy(b.b[:], v[:blockMeta+l])
		b.n = blockMeta + l
		r.advance(seq)
		r.substitute(seq, b.b[:b.n])
		if now.Sub(b.at) <= rlcRecvAge {
			r.fixed++
			r.out = append(r.out, rebuilt{seq, append([]byte(nil), b.b[blockMeta:b.n]...)})
		} else {
			r.stale++
		}
	}
	return found
}
