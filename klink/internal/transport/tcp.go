package transport

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/blake2s"
)

// Framer قاب‌بندی TCP: هر قاب = طول ۲بایتی ماسک‌شده + payload.
// طول قاب با ماسک متغیرِ وابسته به شمارنده‌ی قاب مبهم می‌شود تا قالب ثابت و
// قابل‌شناسایی روی سیم نباشد؛ محرمانگی اصلی توسط AEAD لایه‌ی نشست تضمین می‌شود
// (طول قاب به‌خودی‌خود محرمانه نیست و نباید به آن اتکا کرد).
type Framer struct {
	mask   atomic.Uint32
	writes uint64
}

// NewFramer با ماسک اولیه (قبل از handshake از Prologue مشتق می‌شود).
func NewFramer(seed []byte) *Framer {
	h := blake2s.Sum256(seed)
	f := &Framer{}
	f.mask.Store(binary.BigEndian.Uint32(h[:4]))
	return f
}

// Upgrade بعد از handshake ماسک را از channel binding تجدید می‌کند.
func (f *Framer) Upgrade(channelBinding []byte) {
	h := blake2s.Sum256(append([]byte("klink/v1 frame mask"), channelBinding...))
	f.mask.Store(binary.BigEndian.Uint32(h[:4]))
}

func (f *Framer) lengthMask(counter uint64) [2]byte {
	var buf [12]byte
	binary.BigEndian.PutUint32(buf[:4], f.mask.Load())
	binary.BigEndian.PutUint64(buf[4:], counter)
	h := blake2s.Sum256(buf[:])
	return [2]byte{h[0], h[1]}
}

// WriteFrame یک قاب می‌نویسد.
func (f *Framer) WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > 65535 {
		return errors.New("transport: frame too large")
	}
	m := f.lengthMask(f.writes)
	f.writes++
	hdr := []byte{byte(len(payload) >> 8), byte(len(payload))}
	hdr[0] ^= m[0]
	hdr[1] ^= m[1]
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame یک قاب می‌خواند.
func (f *Framer) ReadFrame(r io.Reader, reads *uint64) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	m := f.lengthMask(*reads)
	*reads++
	hdr[0] ^= m[0]
	hdr[1] ^= m[1]
	n := binary.BigEndian.Uint16(hdr[:])
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// TCPListener گوش‌دهنده‌ی TCP: هر اتصال یک آدرس مجازی (TCPConnAddr) است و
// قاب‌های همه‌ی اتصال‌ها روی یک کانال مشترک به لایه‌ی نشست می‌رسند.
type TCPListener struct {
	ln        net.Listener
	packets   chan Packet
	done      chan struct{}
	closeOnce sync.Once
	conns     sync.Map // uint64 -> *tcpPeer
	nextID    atomic.Uint64
	closed    atomic.Bool
	seed      []byte
}

type tcpPeer struct {
	addr    *TCPConnAddr
	framer  *Framer
	writeMu sync.Mutex
}

// ListenTCP روی آدرس داده‌شده گوش می‌دهد؛ seed همان Prologue پروتکل است.
func ListenTCP(addr string, seed []byte) (*TCPListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &TCPListener{ln: ln, packets: make(chan Packet, 256), done: make(chan struct{}), seed: append([]byte(nil), seed...)}
	go l.acceptLoop()
	return l, nil
}

func (l *TCPListener) LocalAddr() net.Addr { return l.ln.Addr() }

func (l *TCPListener) acceptLoop() {
	for {
		c, err := l.ln.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			continue
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
			_ = tc.SetKeepAlive(true)
			_ = tc.SetKeepAlivePeriod(30 * time.Second)
		}
		peer := &tcpPeer{
			addr:   &TCPConnAddr{ID: l.nextID.Add(1), Conn: c},
			framer: NewFramer(l.seed),
		}
		l.conns.Store(peer.addr.ID, peer)
		go l.readLoop(peer)
	}
}

func (l *TCPListener) readLoop(p *tcpPeer) {
	defer func() {
		l.conns.Delete(p.addr.ID)
		_ = p.addr.Conn.Close()
	}()
	var reads uint64
	for {
		if l.closed.Load() {
			return
		}
		_ = p.addr.Conn.SetReadDeadline(time.Now().Add(TCPReadTimeout))
		payload, err := p.framer.ReadFrame(p.addr.Conn, &reads)
		if err != nil {
			return
		}
		select {
		case l.packets <- Packet{Data: payload, Addr: p.addr}:
		case <-l.done:
			return
		}
		// برخلاف UDP، قاب TCP نباید هنگام پرشدن صف حذف شود؛ توقف خواندنِ
		// همان اتصال، فشار پس‌رو را بدون خراب‌کردن جریان‌های mux اعمال می‌کند.
	}
}

func (l *TCPListener) ReadPacket() (Packet, error) {
	select {
	case <-l.done:
		return Packet{}, ErrClosed
	default:
	}
	select {
	case p := <-l.packets:
		return p, nil
	case <-l.done:
		return Packet{}, ErrClosed
	}
}

func (l *TCPListener) WriteTo(data []byte, addr net.Addr) error {
	ta, ok := addr.(*TCPConnAddr)
	if !ok {
		return errors.New("transport: not a tcp addr")
	}
	v, ok := l.conns.Load(ta.ID)
	if !ok {
		return ErrClosed
	}
	p := v.(*tcpPeer)
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return p.framer.WriteFrame(p.addr.Conn, data)
}

// UpgradeFraming ماسک قاب‌بندی یک اتصال را بعد از handshake ارتقا می‌دهد.
func (l *TCPListener) UpgradeFraming(addr net.Addr, channelBinding []byte) {
	if ta, ok := addr.(*TCPConnAddr); ok {
		if v, ok := l.conns.Load(ta.ID); ok {
			v.(*tcpPeer).framer.Upgrade(channelBinding)
		}
	}
}

func (l *TCPListener) Close() error {
	var err error
	l.closeOnce.Do(func() {
		l.closed.Store(true)
		close(l.done)
		l.conns.Range(func(_, v any) bool {
			_ = v.(*tcpPeer).addr.Conn.Close()
			return true
		})
		err = l.ln.Close()
	})
	return err
}
