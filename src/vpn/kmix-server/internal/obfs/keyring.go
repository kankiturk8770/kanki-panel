package obfs

// حالت چندکاربره: هر کاربر کلید خودش را دارد. سرور برای بسته‌ای که از آدرس تازه‌ای می‌آید
// کلیدها را یکی‌یکی امتحان می‌کند؛ کلیدی که بسته را باز کرد صاحب آن آدرس است و بسته‌های بعدی
// همان آدرس مستقیم با همان کلید باز می‌شوند. هیچ شناسه‌ی کاربری روی سیم نیست، پس قالب بسته
// دقیقاً همان حالت تک‌کلیدی است و کلاینت فرقی نمی‌بیند.
//
// حذف کاربر از Keyring = قطع فوری: بسته‌هایش دیگر باز نمی‌شوند.

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// User یک کاربر با کلید خودش.
type User struct {
	Name string
	Key  []byte
	aead cipher.AEAD
	ctr  *counter
}

type counter struct{ rx, tx atomic.Int64 }

type addrEntry struct {
	u    *User
	seen atomic.Int64 // UnixNano
}

// Keyring کلیدهای کاربران و آدرس‌هایی که هر کدام از آن‌ها آمده‌اند.
type Keyring struct {
	mu       sync.RWMutex
	users    []*User
	counters map[string]*counter // با عوض شدن کلید کاربر، مصرف شمرده‌شده‌اش گم نمی‌شود

	amu    sync.RWMutex
	byAddr map[netip.AddrPort]*addrEntry

	// امتحان همه‌ی کلیدها گران است؛ هر IP در ثانیه حداکثر scanPerSec بار (ضد سیل بسته‌ی بی‌معنی)
	smu   sync.Mutex
	scans map[netip.Addr]*scanBucket

	// routing hints of protocol 3 clients (hints.go)
	hints *hintTable
}

const scanPerSec = 20

type scanBucket struct {
	sec int64
	n   int
}

// mayScan اجازه‌ی امتحان همه‌ی کلیدها برای بسته‌ای از این IP.
func (k *Keyring) mayScan(ip netip.Addr) bool {
	sec := time.Now().Unix()
	k.smu.Lock()
	defer k.smu.Unlock()
	b := k.scans[ip]
	if b == nil {
		b = &scanBucket{}
		k.scans[ip] = b
	}
	if b.sec != sec {
		b.sec, b.n = sec, 0
	}
	b.n++
	return b.n <= scanPerSec
}

func NewKeyring() *Keyring {
	k := &Keyring{counters: map[string]*counter{}, byAddr: map[netip.AddrPort]*addrEntry{}, scans: map[netip.Addr]*scanBucket{}, hints: newHintTable()}
	go k.pruneLoop()
	return k
}

// Set فهرست کاربران را عوض می‌کند: keys = کلید hex → نام کاربر.
func (k *Keyring) Set(keys map[string]string) error {
	users := make([]*User, 0, len(keys))
	k.mu.Lock()
	defer k.mu.Unlock()
	for kh, name := range keys {
		raw, err := hex.DecodeString(kh)
		if err != nil || len(raw) != chacha20poly1305.KeySize {
			return errors.New("کلید کاربر " + name + " نامعتبر است")
		}
		a, err := chacha20poly1305.New(raw)
		if err != nil {
			return err
		}
		c := k.counters[name]
		if c == nil {
			c = &counter{}
			k.counters[name] = c
		}
		users = append(users, &User{Name: name, Key: raw, aead: a, ctr: c})
	}
	k.users = users
	// آدرس‌هایی که مال کاربر حذف‌شده یا کلید عوض‌شده‌اند فراموش شوند
	byKey := map[string]*User{}
	for _, u := range users {
		byKey[u.Name+"\x00"+string(u.Key)] = u
	}
	k.amu.Lock()
	for a, e := range k.byAddr {
		if nu := byKey[e.u.Name+"\x00"+string(e.u.Key)]; nu != nil {
			e.u = nu
		} else {
			delete(k.byAddr, a)
		}
	}
	k.amu.Unlock()
	k.hints.retain(func(u *User) *User { return byKey[u.Name+"\x00"+string(u.Key)] })
	return nil
}

// Len تعداد کاربران.
func (k *Keyring) Len() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.users)
}

// Has کاربری با این اسم هست؟
func (k *Keyring) Has(name string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	for _, u := range k.users {
		if u.Name == name {
			return true
		}
	}
	return false
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return netip.AddrPort{}, false
	}
	ap := ua.AddrPort()
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), true
}

// UserOf کاربری که آخرین بار از این آدرس بسته فرستاده.
func (k *Keyring) UserOf(a net.Addr) *User {
	ap, ok := addrPort(a)
	if !ok {
		return nil
	}
	k.amu.RLock()
	e := k.byAddr[ap]
	k.amu.RUnlock()
	if e == nil {
		return nil
	}
	return e.u
}

var scratchPool = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

// open بسته را با کلید آشنای این آدرس، یا اگر آشنا نبود با کلید همه‌ی کاربران، باز می‌کند.
// متن باز شده در out نوشته می‌شود (رمزگشایی ناموفق بافر را صفر می‌کند، پس درجا نیست).
func (k *Keyring) open(pkt []byte, a net.Addr, out []byte) (*User, []byte, bool) {
	if len(pkt) < overhead {
		return nil, nil, false
	}
	nonce, ct := pkt[:nonceSize], pkt[nonceSize:]
	ap, ok := addrPort(a)
	if !ok {
		return nil, nil, false
	}
	// a hinted packet (protocol 3): its user in O(1), whatever address it comes from (a roaming phone, another
	// path of the same session); the address is learned for the answers
	if len(pkt) >= HintLen+overhead {
		if h := k.hints.lookup(pkt[:HintLen]); h != nil {
			if p, err := h.u.aead.Open(out[:0], pkt[HintLen:HintLen+nonceSize], pkt[HintLen+nonceSize:], nil); err == nil {
				k.learn(ap, h.u)
				h.u.ctr.rx.Add(int64(len(pkt)))
				return h.u, p, true
			}
		}
	}
	k.amu.RLock()
	e := k.byAddr[ap]
	k.amu.RUnlock()
	if e != nil {
		if p, err := e.u.aead.Open(out[:0], nonce, ct, nil); err == nil {
			e.seen.Store(time.Now().UnixNano())
			e.u.ctr.rx.Add(int64(len(pkt)))
			return e.u, p, true
		}
		// a hinted packet from a known address whose hint has ended: the same user's key, one more try
		if len(pkt) >= HintLen+overhead {
			if p, err := e.u.aead.Open(out[:0], pkt[HintLen:HintLen+nonceSize], pkt[HintLen+nonceSize:], nil); err == nil {
				e.seen.Store(time.Now().UnixNano())
				e.u.ctr.rx.Add(int64(len(pkt)))
				return e.u, p, true
			}
		}
	}
	if !k.mayScan(ap.Addr()) {
		return nil, nil, false
	}
	k.mu.RLock()
	users := k.users
	k.mu.RUnlock()
	for _, u := range users {
		if e != nil && u == e.u {
			continue
		}
		p, err := u.aead.Open(out[:0], nonce, ct, nil)
		if err != nil {
			continue
		}
		ne := &addrEntry{u: u}
		ne.seen.Store(time.Now().UnixNano())
		k.amu.Lock()
		k.byAddr[ap] = ne
		k.amu.Unlock()
		u.ctr.rx.Add(int64(len(pkt)))
		return u, p, true
	}
	return nil, nil, false
}

// learn: address ap belongs to user u now (only written when it changed)
func (k *Keyring) learn(ap netip.AddrPort, u *User) {
	now := time.Now().UnixNano()
	k.amu.RLock()
	e := k.byAddr[ap]
	k.amu.RUnlock()
	if e != nil && e.u == u {
		e.seen.Store(now)
		return
	}
	ne := &addrEntry{u: u}
	ne.seen.Store(now)
	k.amu.Lock()
	k.byAddr[ap] = ne
	k.amu.Unlock()
}

// sealer کلید رمز کردن بسته‌ای که به این آدرس می‌رود.
func (k *Keyring) sealer(a net.Addr) (cipher.AEAD, *counter) {
	u := k.UserOf(a)
	if u == nil {
		return nil, nil
	}
	return u.aead, u.ctr
}

// Traffic مصرف هر کاربر (بایت روی سیم) از آخرین بار؛ clear=true شمارنده‌ها را صفر می‌کند.
func (k *Keyring) Traffic(clear bool) map[string][2]int64 {
	k.mu.RLock()
	defer k.mu.RUnlock()
	m := map[string][2]int64{}
	for name, c := range k.counters {
		var rx, tx int64
		if clear {
			rx, tx = c.rx.Swap(0), c.tx.Swap(0)
		} else {
			rx, tx = c.rx.Load(), c.tx.Load()
		}
		if rx != 0 || tx != 0 {
			m[name] = [2]int64{rx, tx}
		}
	}
	return m
}

// آدرس‌هایی که ۵ دقیقه ساکت بوده‌اند فراموش می‌شوند (حافظه ثابت می‌ماند)
func (k *Keyring) pruneLoop() {
	for range time.Tick(time.Minute) {
		cut := time.Now().Add(-5 * time.Minute).UnixNano()
		k.amu.Lock()
		for a, e := range k.byAddr {
			if e.seen.Load() < cut {
				delete(k.byAddr, a)
			}
		}
		k.amu.Unlock()
		old := time.Now().Unix() - 5
		k.smu.Lock()
		for ip, b := range k.scans {
			if b.sec < old {
				delete(k.scans, ip)
			}
		}
		k.smu.Unlock()
		k.hints.expire()
	}
}
