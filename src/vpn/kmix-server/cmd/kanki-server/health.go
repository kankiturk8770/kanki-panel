package main

// Live health of this server's KANKI MIX for the panel (panel 3.67): GET /health on the local API.
//
//	{"sessions": 12, "gaming": 5, "hinted": 4, "loss_permille": 7, "loss_sessions": 9, "fec_parity": 0,
//	 "fec_legacy": 3, "users": 40}
//
// sessions: devices online now; gaming: sessions in gaming mode (hello); hinted: sessions that use routing
// hints (protocol 3 apps); loss_permille: the loss the apps measured on the game's answers (KindStat), averaged
// over the sessions that reported within lossWindow, weighted by the packets each counted.

import (
	"sync"
	"time"
)

const lossWindow = time.Minute

type lossNote struct {
	permille uint16
	count    uint16
	at       time.Time
}

var lossBook = struct {
	mu sync.Mutex
	m  map[uint64]lossNote
}{m: map[uint64]lossNote{}}

// noteLoss: session sid's app reported this loss on the game's answers
func noteLoss(sid uint64, permille, count uint16, now time.Time) {
	if count == 0 {
		return
	}
	lossBook.mu.Lock()
	defer lossBook.mu.Unlock()
	if _, ok := lossBook.m[sid]; !ok && len(lossBook.m) >= maxSmartSess {
		return
	}
	lossBook.m[sid] = lossNote{permille: permille, count: count, at: now}
}

// lossAverage: the weighted average loss (‰) of the sessions that reported within lossWindow, and how many
// sessions that is; the older notes are forgotten
func lossAverage(now time.Time) (int, int) {
	lossBook.mu.Lock()
	defer lossBook.mu.Unlock()
	var sum, weight int64
	n := 0
	for sid, x := range lossBook.m {
		if now.Sub(x.at) > lossWindow {
			delete(lossBook.m, sid)
			continue
		}
		sum += int64(x.permille) * int64(x.count)
		weight += int64(x.count)
		n++
	}
	if weight == 0 {
		return 0, 0
	}
	return int((sum + weight/2) / weight), n
}

// health: the numbers of /health
func health(r *dgramRelay, now time.Time) map[string]any {
	loss, ls := lossAverage(now)
	online := 0
	for _, c := range userSessions.online() {
		online += c
	}
	gaming, hinted, users := 0, 0, 0
	if r != nil {
		r.mu.Lock()
		for _, at := range r.gaming {
			if now.Sub(time.Unix(0, at)) < sessIdle {
				gaming++
			}
		}
		r.mu.Unlock()
		if r.ring != nil {
			hinted = r.ring.Hinted()
			users = r.ring.Len()
		}
	}
	return map[string]any{
		"sessions": online, "gaming": gaming, "hinted": hinted, "users": users,
		"loss_permille": loss, "loss_sessions": ls, "fec_parity": *parity, "fec_legacy": legacyParity(),
	}
}
