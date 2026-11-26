package main

// Downloads never in front of the game (panel 3.67). While a user's game is playing (a game packet of theirs
// went through within gameActive), what their TCP streams bring from the internet is paced by a token bucket of
// their own: the reading from the far server waits, so TCP's own flow control slows that server down; nothing is
// dropped and nothing is sent twice. The rate follows the line: a loss report of the game's answers (KindStat)
// over lossCut cuts it at once (×cutBy), a clean one raises it a step, between minRate and maxRate. With no game
// playing there is no limit at all.

import (
	"io"
	"sync"
	"time"
)

const (
	gameActive = 2 * time.Second
	startRate  = 750 << 10 // bytes a second (≈6 Mbit/s) when a game starts
	minRate    = 160 << 10 // ≈1.3 Mbit/s: a download still moves
	maxRate    = 5 << 20   // ≈40 Mbit/s
	raiseBy    = 96 << 10  // a clean report raises the rate this much
	cutBy      = 0.7
	lossCut    = 15 // ‰: the answers of the game lose more than this: the downloads give way
	lossClean  = 5  // ‰: under this the line has room
	bucketMax  = 64 << 10
	// paceChunk the most a paced stream reads at once (so one read never takes the whole bucket for long)
	paceChunk = 16 << 10
)

type userBucket struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
	gameAt time.Time
}

type limiter struct {
	mu    sync.Mutex
	users map[string]*userBucket
}

var downLimit = &limiter{users: map[string]*userBucket{}}

func (l *limiter) bucket(user string, create bool) *userBucket {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.users[user]
	if b == nil && create {
		b = &userBucket{rate: startRate, tokens: bucketMax}
		l.users[user] = b
	}
	return b
}

// noteGame: a game packet of this user went through now
func (l *limiter) noteGame(user string, now time.Time) {
	b := l.bucket(user, true)
	b.mu.Lock()
	if now.Sub(b.gameAt) > gameActive {
		// a new moment of play starts from the start rate and a full bucket
		b.rate, b.tokens, b.last = startRate, bucketMax, now
	}
	b.gameAt = now
	b.mu.Unlock()
}

// report: the loss (‰) the user's app measured on the game's answers
func (l *limiter) report(user string, permille uint16) {
	b := l.bucket(user, false)
	if b == nil {
		return
	}
	b.mu.Lock()
	switch {
	case permille > lossCut:
		b.rate = max(b.rate*cutBy, minRate)
	case permille < lossClean:
		b.rate = min(b.rate+raiseBy, maxRate)
	}
	b.mu.Unlock()
}

// delay: how long to wait before n more bytes of this user's downloads go (0 = at once: no game playing)
func (l *limiter) delay(user string, n int, now time.Time) time.Duration {
	b := l.bucket(user, false)
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.Sub(b.gameAt) > gameActive {
		return 0
	}
	if !b.last.IsZero() {
		b.tokens = min(b.tokens+now.Sub(b.last).Seconds()*b.rate, bucketMax)
	}
	b.last = now
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / b.rate * float64(time.Second))
}

// rateOf the user's current rate (bytes a second) and whether their game is playing (for the stats and tests)
func (l *limiter) rateOf(user string, now time.Time) (float64, bool) {
	b := l.bucket(user, false)
	if b == nil {
		return 0, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate, now.Sub(b.gameAt) <= gameActive
}

// gc: users whose game stopped long ago are forgotten
func (l *limiter) gc(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for u, b := range l.users {
		b.mu.Lock()
		old := now.Sub(b.gameAt) > 10*time.Minute
		b.mu.Unlock()
		if old {
			delete(l.users, u)
		}
	}
}

// pacedReader: the far server's side of one of the user's TCP streams, paced while their game plays
type pacedReader struct {
	r    io.Reader
	user string
	l    *limiter
}

func (p pacedReader) Read(b []byte) (int, error) {
	if len(b) > paceChunk {
		b = b[:paceChunk]
	}
	n, err := p.r.Read(b)
	if n > 0 {
		if d := p.l.delay(p.user, n, time.Now()); d > 0 {
			time.Sleep(min(d, time.Second))
		}
	}
	return n, err
}
