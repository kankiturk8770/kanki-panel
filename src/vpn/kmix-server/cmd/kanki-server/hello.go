package main

// Hello (protocol 3, panel 3.67; internal/proto/hello.go): a client says what it can do and gets a routing
// hint. With HelloCapGaming every UDP flow of its session except DNS is taken for a game from its very first
// packet (no waiting for the app's FlagGame or for a loss report), its downloads over TCP are kept from
// filling the line in front of the game (limiter.go), and the game's protection starts at once.

import (
	"net"
	"time"

	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

// dnsPort UDP flows to it are never a game
const dnsPort = 53

func (r *dgramRelay) onHello(b []byte, addr net.Addr) {
	h, err := proto.ParseHello(b)
	now := time.Now()
	// a replayed old hello gets nothing: no new hint for whoever copied it
	if err != nil || !h.Fresh(now) || !r.allowed(addr, h.Session) {
		return
	}
	ack := proto.HelloAck{Session: h.Session, Version: proto.HelloVersion, SentAt: h.SentAt}
	if h.Caps&proto.HelloCapHint != 0 && r.ring != nil {
		if hint, ok := r.ring.IssueHint(addr, h.Session); ok {
			ack.Hint = hint
			ack.Caps |= proto.HelloCapHint
			ack.LifeSec = uint16(obfs.HintTTL / time.Second)
		}
	}
	gaming := h.Caps&proto.HelloCapGaming != 0
	r.setGaming(h.Session, gaming, now)
	if gaming {
		ack.Caps |= proto.HelloCapGaming
		r.smartFromHello(h.Session, now)
	}
	if ua, ok := addr.(*net.UDPAddr); ok {
		r.paths.note(h.Session, ua)
	}
	r.send(proto.KindHelloAck, proto.AppendHelloAck(nil, &ack), addr)
}

// setGaming: the session said (or stopped saying) gaming mode; its existing flows follow at once
func (r *dgramRelay) setGaming(sid uint64, on bool, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !on {
		delete(r.gaming, sid)
		return
	}
	if _, ok := r.gaming[sid]; !ok && len(r.gaming) >= maxSmartSess {
		return
	}
	r.gaming[sid] = now.UnixNano()
	for k, f := range r.flows {
		if k.sess == sid && f.dstPort != dnsPort {
			f.s.game.Store(true)
		}
	}
}

// gamingSess: the session is in gaming mode (it said so in a hello within sessIdle)
func (r *dgramRelay) gamingSess(sid uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	at, ok := r.gaming[sid]
	return ok && time.Since(time.Unix(0, at)) < sessIdle
}

// smartFromHello: a protocol 3 client takes repairs, delayed copies and several paths (it is newer than all of
// them), so its game is protected before its first loss report
func (r *dgramRelay) smartFromHello(sid uint64, now time.Time) {
	r.mu.Lock()
	s := r.sess[sid]
	if s == nil {
		if len(r.sess) >= maxSmartSess {
			r.mu.Unlock()
			return
		}
		s = &smartSess{flows: map[uint32]*udpFlow{}}
		r.sess[sid] = s
		for k, f := range r.flows {
			if k.sess == sid {
				s.flows[k.flow] = f
			}
		}
	}
	r.mu.Unlock()
	if s.caps.Load() == 0 {
		s.caps.Store(uint32(proto.CapRepair | proto.CapCopy | proto.CapMulti))
	}
	s.at.Store(now.UnixNano())
	s.downPol.Start(now)
}

// gamingGC: sessions that said nothing for sessIdle are forgotten (under r.mu)
func (r *dgramRelay) gamingGC(now time.Time) {
	for sid, at := range r.gaming {
		if now.Sub(time.Unix(0, at)) > sessIdle {
			delete(r.gaming, sid)
		}
	}
}
