package game

import (
	"container/heap"
	"sync"
	"time"
)

// Later sends packets a little later from one goroutine (copies and repairs a few ms after the packet
// they protect). Push never blocks the hot path: when too much is waiting the new one is dropped, which is
// only a copy or a repair, never a packet of the game itself.
type Later struct {
	mu    sync.Mutex
	q     laterQ
	max   int
	wake  chan struct{}
	stop  chan struct{}
	once  sync.Once
	pool  sync.Pool
	drops uint64
}

type laterItem struct {
	at  time.Time
	b   []byte
	fn  func([]byte)
	buf *[]byte
}

type laterQ []*laterItem

func (q laterQ) Len() int           { return len(q) }
func (q laterQ) Less(i, j int) bool { return q[i].at.Before(q[j].at) }
func (q laterQ) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *laterQ) Push(x any)        { *q = append(*q, x.(*laterItem)) }
func (q *laterQ) Pop() any {
	o := *q
	n := len(o)
	x := o[n-1]
	o[n-1] = nil
	*q = o[:n-1]
	return x
}
func (q laterQ) peek() *laterItem { return q[0] }

// NewLater: a sender with room for max waiting packets
func NewLater(max int) *Later {
	l := &Later{max: max, wake: make(chan struct{}, 1), stop: make(chan struct{})}
	l.pool.New = func() any { b := make([]byte, 0, 1500); return &b }
	go l.run()
	return l
}

// Push: fn(b) is called d from now (b is copied)
func (l *Later) Push(d time.Duration, b []byte, fn func([]byte)) {
	bp := l.pool.Get().(*[]byte)
	buf := append((*bp)[:0], b...)
	it := &laterItem{at: time.Now().Add(d), b: buf, fn: fn, buf: bp}
	l.mu.Lock()
	if len(l.q) >= l.max {
		l.drops++
		l.mu.Unlock()
		l.pool.Put(bp)
		return
	}
	heap.Push(&l.q, it)
	first := l.q.peek() == it
	l.mu.Unlock()
	if first {
		select {
		case l.wake <- struct{}{}:
		default:
		}
	}
}

// Stop: the goroutine ends; what is waiting is dropped
func (l *Later) Stop() { l.once.Do(func() { close(l.stop) }) }

// Drops: packets dropped because too much was waiting
func (l *Later) Drops() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.drops
}

func (l *Later) run() {
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		l.mu.Lock()
		var wait time.Duration = time.Hour
		now := time.Now()
		var due []*laterItem
		for len(l.q) > 0 {
			it := l.q.peek()
			if d := it.at.Sub(now); d > 0 {
				wait = d
				break
			}
			due = append(due, heap.Pop(&l.q).(*laterItem))
		}
		l.mu.Unlock()
		for _, it := range due {
			it.fn(it.b)
			*it.buf = it.b[:0]
			l.pool.Put(it.buf)
		}
		if len(due) > 0 {
			continue
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(wait)
		select {
		case <-l.stop:
			return
		case <-l.wake:
		case <-t.C:
		}
	}
}
