package main

// Multipath (3.60 / app 1.44): one session of the app comes from several addresses at once (the phone's Wi-Fi and
// mobile data, the server itself and an Iran tunnel entry). Each path pings on its own, so the server knows every
// live address of a session. The answers go to the main one (the address of the last first copy); a second copy
// or a repair goes over another live path, where a loss of the main path does not reach it.

import (
	"net"
	"sync"
	"time"
)

const (
	// pathAlive: a path that sent nothing (not even a ping) this long is not used for the copies
	pathAlive = 3 * time.Second
	// mirrorFor: how long a FlagMirror keeps the answers on both paths
	mirrorFor = time.Second
	maxPaths  = 4
)

type pathAddr struct {
	a  *net.UDPAddr
	at int64 // UnixNano
}

type sessPaths struct {
	l [maxPaths]pathAddr
}

type pathBook struct {
	mu sync.Mutex
	m  map[uint64]*sessPaths
}

// note: an address of session sid was just heard
func (b *pathBook) note(sid uint64, a *net.UDPAddr) {
	if a == nil {
		return
	}
	now := time.Now().UnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.m[sid]
	if p == nil {
		if len(b.m) >= maxSmartSess {
			return
		}
		p = new(sessPaths)
		b.m[sid] = p
	}
	old := 0
	for i := range p.l {
		x := &p.l[i]
		if x.a != nil && x.a.Port == a.Port && x.a.IP.Equal(a.IP) {
			x.at = now
			return
		}
		if x.a == nil || x.at < p.l[old].at {
			old = i
		}
	}
	p.l[old] = pathAddr{a: a, at: now}
}

// other: the most recently heard live address of sid that is not main (nil = only one path)
func (b *pathBook) other(sid uint64, main *net.UDPAddr) *net.UDPAddr {
	cut := time.Now().Add(-pathAlive).UnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.m[sid]
	if p == nil {
		return nil
	}
	var best *pathAddr
	for i := range p.l {
		x := &p.l[i]
		if x.a == nil || x.at < cut || (main != nil && x.a.Port == main.Port && x.a.IP.Equal(main.IP)) {
			continue
		}
		if best == nil || x.at > best.at {
			best = x
		}
	}
	if best == nil {
		return nil
	}
	return best.a
}

func (b *pathBook) gc() {
	cut := time.Now().Add(-sessIdle).UnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()
	for sid, p := range b.m {
		live := false
		for _, x := range p.l {
			if x.a != nil && x.at >= cut {
				live = true
			}
		}
		if !live {
			delete(b.m, sid)
		}
	}
}
