package main

// بازی هوشمند، سمت سرور (3.59؛ همان internal/game اپ). فقط با اپی که KindStat می‌فرستد:
//   - افت خام بالارو (نسخه‌ی اصلی هر بسته‌ی بازی) شمرده و در جواب هر گزارش اپ به او گفته می‌شود
//   - پایین‌روی جریان‌های بازی (اپ آن‌ها را با FlagGame می‌گوید) به اندازه‌ی افتی که اپ گزارش داده محافظت
//     می‌شود: خط تمیز هیچ، بعد ترمیم پنجره‌ای RLC، بعد نسخه‌ی دوم ۱۲ms بعد (KindUDPDownCopy)
//   - ترمیم‌های بالاروی اپ بسته‌های گم‌شده را می‌سازند
// اپ قدیمی هیچ‌کدام را نمی‌گیرد: برای او مثل قبل FlagDup، فقط نسخه‌ی دوم با فاصله.

import (
	"hash/maphash"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"kanki-tunnel/internal/game"
	"kanki-tunnel/internal/proto"
)

const (
	maxSmartSess = 50000
	// maxUpRx: decoders of the upload repairs (≈70 KB each), all clients together
	maxUpRx = 2048
	// sessIdle: a session that sent no report this long is forgotten
	sessIdle = 3 * time.Minute
)

// smartSess: what the app of one session told us
type smartSess struct {
	caps    atomic.Uint32
	upStep  atomic.Int32 // how the app protects its uploads now (0 = it sends no repairs)
	at      atomic.Int64 // its last report (UnixNano)
	downPol game.Policy
	mu      sync.Mutex
	flows   map[uint32]*udpFlow
}

// flowSmart: the new parts of one flow (under f.mu, except the atomics)
type flowSmart struct {
	game     atomic.Bool
	upM      game.Meter
	upRx     *game.Rx
	downTx   *game.Tx
	sinceRep int
}

var (
	upRxCount atomic.Int32
	laterSeed = maphash.MakeSeed()
	laters    [4]*game.Later
)

func init() {
	for i := range laters {
		laters[i] = game.NewLater(1 << 15)
	}
}

func laterOf(sid uint64) *game.Later {
	var h maphash.Hash
	h.SetSeed(laterSeed)
	var b [8]byte
	for i := range b {
		b[i] = byte(sid >> (8 * i))
	}
	h.Write(b[:])
	return laters[h.Sum64()%uint64(len(laters))]
}

// sessOf: the session's state, nil = an old app (or one that has not reported yet)
func (r *dgramRelay) sessOf(sid uint64) *smartSess {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.sess[sid]
}

// onStat: the app's report; the answer carries the loss of its uploads as we see it
func (r *dgramRelay) onStat(b []byte, addr net.Addr) {
	st, err := proto.ParseStat(b)
	if err != nil || !r.allowed(addr, st.Session) {
		return
	}
	now := time.Now()
	r.mu.Lock()
	s := r.sess[st.Session]
	if s == nil {
		if len(r.sess) >= maxSmartSess {
			r.mu.Unlock()
			return
		}
		s = &smartSess{flows: map[uint32]*udpFlow{}}
		r.sess[st.Session] = s
		// the flows it already has
		for k, f := range r.flows {
			if k.sess == st.Session {
				s.flows[k.flow] = f
			}
		}
	}
	r.mu.Unlock()
	s.caps.Store(uint32(st.Caps))
	s.upStep.Store(int32(st.Step))
	s.at.Store(now.UnixNano())
	s.downPol.Report(uint32(st.Loss), uint32(st.Burst), uint32(st.Count), now)

	var sum game.Sum
	s.mu.Lock()
	for _, f := range s.flows {
		if f.s.game.Load() {
			sum.Add(f.s.upM.Take())
		}
	}
	s.mu.Unlock()
	pm, burst, n := sum.Result()
	out := proto.Stat{Session: st.Session, Version: proto.StatVersion, Caps: proto.CapRepair | proto.CapCopy | proto.CapMulti,
		Loss: uint16(pm), Burst: byte(min(burst, 255)), Step: byte(s.downPol.Step()), Count: uint16(min(n, 65535))}
	r.send(proto.KindStat, proto.AppendStat(nil, &out), addr)
}

// onRepairUp: a repair of the app's uploads; the packets it rebuilds go on to the game server
func (r *dgramRelay) onRepairUp(b []byte, addr net.Addr) {
	sid, flow, rep, err := proto.ParseRepairUp(b)
	if err != nil || !r.allowed(addr, sid) {
		return
	}
	r.mu.Lock()
	f := r.flows[flowKey{sid, flow}]
	r.mu.Unlock()
	if f == nil {
		return
	}
	now := time.Now()
	f.mu.Lock()
	if f.s.upRx == nil {
		if upRxCount.Add(1) > maxUpRx {
			upRxCount.Add(-1)
			f.mu.Unlock()
			return
		}
		f.s.upRx = new(game.Rx)
	}
	var out [][]byte
	for _, x := range f.s.upRx.Repair(rep, now) {
		if f.win.Accept(x.Seq) {
			out = append(out, append([]byte(nil), x.Payload...))
		}
	}
	f.mu.Unlock()
	for _, p := range out {
		f.conn.Write(p)
	}
}

// upData: a packet of the app arrived (fresh = the first copy of it to arrive); rebuilt ones go out too
func (r *dgramRelay) upData(f *udpFlow, h proto.UDPUp, payload []byte, fresh bool) {
	if h.Flags&proto.FlagGame != 0 {
		f.s.game.Store(true)
	}
	if h.Flags&proto.FlagCopy == 0 {
		f.s.upM.Seen(h.Seq)
	}
	if !fresh {
		return
	}
	f.conn.Write(payload)
	// the app protects its uploads: the decoder must know the packets that arrive, before the first repair
	need := false
	if f.s.game.Load() && len(payload) <= game.MaxProtect {
		if s := r.sessOf(f.key.sess); s != nil && s.upStep.Load() > 0 {
			need = true
		}
	}
	f.mu.Lock()
	if need && f.s.upRx == nil && upRxCount.Add(1) <= maxUpRx {
		f.s.upRx = new(game.Rx)
	} else if need && f.s.upRx == nil {
		upRxCount.Add(-1)
	}
	var out [][]byte
	if f.s.upRx != nil && len(payload) <= game.MaxProtect {
		for _, x := range f.s.upRx.Data(h.Seq, payload, time.Now()) {
			if f.win.Accept(x.Seq) {
				out = append(out, append([]byte(nil), x.Payload...))
			}
		}
	}
	f.mu.Unlock()
	for _, p := range out {
		f.conn.Write(p)
	}
}

// sendDown: one packet of the game server to the app (out = KindUDPDown with its header)
func (r *dgramRelay) sendDown(f *udpFlow, seq uint32, payload, out []byte) {
	client := f.client.Load()
	r.send(proto.KindUDPDown, out, client)
	s := r.sessOf(f.key.sess)
	if s == nil || s.caps.Load() == 0 || time.Since(time.Unix(0, s.at.Load())) > sessIdle {
		// an old app: the second copy as before, only a moment later
		if f.dup.Load() {
			laterOf(f.key.sess).Push(game.CopyDelay, out, func(b []byte) { r.send(proto.KindUDPDown, b, f.client.Load()) })
		}
		return
	}
	if !f.s.game.Load() || len(payload) > game.MaxProtect {
		return
	}
	now := time.Now()
	s.downPol.Start(now)
	pl := s.downPol.Plan(now)
	caps := byte(s.caps.Load())
	lt := laterOf(f.key.sess)
	// another live path of the phone (multipath): the second copy and the repairs go there, at once (a loss of the
	// main path does not reach another path, so nothing has to wait for the loss to pass)
	var alt *net.UDPAddr
	if caps&proto.CapMulti != 0 {
		alt = r.paths.other(f.key.sess, client)
	}
	// the phone's main path stopped answering: the answers go over the other path too until it says otherwise
	mirrored := false
	if alt != nil && caps&proto.CapCopy != 0 && now.UnixNano() < f.mirror.Load() {
		r.send(proto.KindUDPDownCopy, out, alt)
		mirrored = true
	}
	if pl.Copy && caps&proto.CapCopy != 0 && !mirrored {
		if alt != nil {
			r.send(proto.KindUDPDownCopy, out, alt)
		} else {
			lt.Push(game.CopyDelay, out, func(b []byte) { r.send(proto.KindUDPDownCopy, b, f.client.Load()) })
		}
	}
	// where the repairs go: the other path when there is one
	repTo := func() *net.UDPAddr {
		if alt != nil {
			if a := r.paths.other(f.key.sess, f.client.Load()); a != nil {
				return a
			}
		}
		return f.client.Load()
	}
	if caps&proto.CapRepair == 0 {
		return
	}
	f.mu.Lock()
	if f.s.downTx == nil {
		f.s.downTx = new(game.Tx)
	}
	f.s.downTx.Add(seq, payload, now.Add(game.Deadline))
	f.s.sinceRep++
	var rep []byte
	if pl.Every > 0 && f.s.sinceRep >= pl.Every {
		f.s.sinceRep = 0
		if x := f.s.downTx.Repair(now, pl.Win); x != nil {
			rep = proto.AppendRepairDown(nil, f.key.flow, x)
		}
	}
	f.mu.Unlock()
	if rep != nil {
		lt.Push(game.RepairDelay, rep, func(b []byte) { r.send(proto.KindRepair, b, repTo()) })
	}
	if pl.Every > 0 {
		win := pl.Win
		lt.Push(game.TailDelay, nil, func([]byte) {
			f.mu.Lock()
			var rep []byte
			if last, ok := f.s.downTx.Last(); ok && last == seq {
				if x := f.s.downTx.Repair(time.Now(), win); x != nil {
					rep = proto.AppendRepairDown(nil, f.key.flow, x)
				}
			}
			f.mu.Unlock()
			if rep != nil {
				r.send(proto.KindRepair, rep, repTo())
			}
		})
	}
}

// smartAdd / smartDrop keep the session's list of flows (under r.mu)
func (r *dgramRelay) smartAdd(f *udpFlow) {
	if s := r.sess[f.key.sess]; s != nil {
		s.mu.Lock()
		s.flows[f.key.flow] = f
		s.mu.Unlock()
	}
}

func (r *dgramRelay) smartDrop(f *udpFlow) {
	if s := r.sess[f.key.sess]; s != nil {
		s.mu.Lock()
		if s.flows[f.key.flow] == f {
			delete(s.flows, f.key.flow)
		}
		s.mu.Unlock()
	}
	f.mu.Lock()
	if f.s.upRx != nil {
		f.s.upRx = nil
		upRxCount.Add(-1)
	}
	f.mu.Unlock()
}

// smartGC: sessions that stopped reporting and have no flows left (under r.mu)
func (r *dgramRelay) smartGC() {
	cut := time.Now().Add(-sessIdle).UnixNano()
	for id, s := range r.sess {
		s.mu.Lock()
		empty := len(s.flows) == 0
		s.mu.Unlock()
		if empty && s.at.Load() < cut {
			delete(r.sess, id)
		}
	}
}
