// Package mux multiplexes independent TCP streams and UDP associations over
// one authenticated KLINK session.
package mux

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	FrameOpen   = 1
	FrameData   = 2
	FrameClose  = 3
	FrameStatus = 4

	NetworkTCP = 1
	NetworkUDP = 2

	StatusOK     = 0
	StatusFailed = 1

	MaxTCPPayload = 16 * 1024
	MaxUDPPayload = 64*1024 - 1024

	// MaxStreams سقف جریان‌های هم‌زمان (باز یا در حال اتصال) یک نشست است تا یک
	// کلاینت نتواند با Open بی‌پایان حافظه و سوکت‌های سرور را تمام کند.
	MaxStreams = 1024

	tcpIdleTimeout = 30 * time.Minute
	// association UDP بدون ترافیک در هیچ جهت پس از این مدت بسته می‌شود.
	udpIdleTimeout = 3 * time.Minute
)

type Sender interface {
	Send([]byte) error
}

// payloadLimiter اختیاری است؛ نشست KLINK روی مسیر UDP اندازه‌ی امن کوچک‌تری
// گزارش می‌کند تا داده‌ی TCP در بسته‌های بزرگ‌تر از MTU فرستاده نشود.
type payloadLimiter interface {
	MaxPayload() int
}

// ErrDestinationBlocked مقصد در فهرست ممنوع (loopback، شبکه‌ی داخلی و …) است.
var ErrDestinationBlocked = errors.New("mux: destination is not allowed")

// Policy مقصدهای مجاز جریان‌ها را تعیین می‌کند. مقدار صفر امن است: loopback،
// link-local (از جمله 169.254.169.254 سرویس metadata ابری)، multicast،
// آدرس‌های نامشخص و شبکه‌های خصوصی مسدودند. بدون این سیاست هر کاربر پروکسی
// می‌توانست به سرویس‌های داخلی خود سرور (مثل API وضعیت روی 127.0.0.1:9091،
// پنل یا دیتابیس‌ها) و شبکه‌ی داخلی دیتاسنتر دسترسی پیدا کند (SSRF).
type Policy struct {
	AllowPrivate  bool // 10/8، 172.16/12، 192.168/16، 100.64/10، fc00::/7
	AllowLoopback bool // فقط برای تست
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

func (p Policy) allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid(), ip.IsUnspecified(), ip.IsMulticast(), ip.IsInterfaceLocalMulticast(),
		ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return false
	case ip.IsLoopback():
		return p.AllowLoopback
	case ip.IsPrivate(), cgnat.Contains(ip):
		return p.AllowPrivate
	}
	if ip.Is4() {
		b := ip.As4()
		if b[0] == 0 || b[0] >= 240 { // 0.0.0.0/8 و 240.0.0.0/4 (شامل broadcast)
			return false
		}
	}
	return true
}

// control پس از resolve شدن DNS و درست پیش از اتصال اجرا می‌شود؛ بنابراین
// دورزدن با DNS rebinding یا نام‌هایی که به 127.0.0.1 resolve می‌شوند ممکن نیست.
func (p Policy) control(_, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil || !p.allowed(ap.Addr()) {
		return ErrDestinationBlocked
	}
	return nil
}

type Mux struct {
	session Sender
	policy  Policy
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	streams map[uint32]*stream
	opening map[uint32]context.CancelFunc
	closed  bool
	wg      sync.WaitGroup
	// dialContext در تست‌ها جایگزین می‌شود.
	dialContext func(ctx context.Context, network, address string) (net.Conn, error)
}

type stream struct {
	id        uint32
	network   byte
	conn      net.Conn
	writes    chan []byte
	done      chan struct{}
	closeOnce sync.Once
	mux       *Mux
	lastWrite atomic.Int64
}

// New یک mux با سیاست امن پیش‌فرض می‌سازد.
func New(session Sender) *Mux { return NewWithPolicy(session, Policy{}) }

func NewWithPolicy(session Sender, policy Policy) *Mux {
	ctx, cancel := context.WithCancel(context.Background())
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second, Control: policy.control}
	return &Mux{session: session, policy: policy, ctx: ctx, cancel: cancel,
		streams: make(map[uint32]*stream), opening: make(map[uint32]context.CancelFunc),
		dialContext: dialer.DialContext}
}

// HandleFrame is the server-side entry point for decrypted session payloads.
// Invalid control frames close neither the session nor unrelated streams.
func (m *Mux) HandleFrame(frame []byte) {
	if len(frame) < 5 {
		return
	}
	id := binary.BigEndian.Uint32(frame[1:5])
	if id == 0 {
		return
	}
	switch frame[0] {
	case FrameOpen:
		m.open(frame)
	case FrameData:
		m.data(id, frame[5:])
	case FrameClose:
		m.closeByID(id, false)
	}
}

func (m *Mux) open(frame []byte) {
	// open = kind(1) stream(4) network(1) port(2) hostLen(2) host
	if len(frame) < 10 {
		return
	}
	id := binary.BigEndian.Uint32(frame[1:5])
	network := frame[5]
	port := binary.BigEndian.Uint16(frame[6:8])
	hostLen := int(binary.BigEndian.Uint16(frame[8:10]))
	if id == 0 || port == 0 || hostLen == 0 || hostLen > 255 || len(frame) != 10+hostLen ||
		(network != NetworkTCP && network != NetworkUDP) {
		m.sendStatus(id, StatusFailed)
		return
	}
	m.mu.Lock()
	if m.closed || m.streams[id] != nil || m.opening[id] != nil || len(m.streams)+len(m.opening) >= MaxStreams {
		m.mu.Unlock()
		m.sendStatus(id, StatusFailed)
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
	m.opening[id] = cancel
	m.wg.Add(1)
	m.mu.Unlock()

	host := string(frame[10:])
	// اتصال در goroutine جدا برقرار می‌شود. قبلاً dial (تا ۱۵ ثانیه) در همان
	// goroutine خواننده‌ی شبکه انجام می‌شد و یک مقصد کند، دریافت بسته‌های همه‌ی
	// کاربران را متوقف می‌کرد. کلاینت تا StatusOK داده نمی‌فرستد، پس ترتیب حفظ است.
	go m.dial(ctx, cancel, id, network, host, port)
}

func (m *Mux) dial(ctx context.Context, cancel context.CancelFunc, id uint32, network byte, host string, port uint16) {
	defer m.wg.Done()
	defer cancel()
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	proto := "tcp"
	if network == NetworkUDP {
		proto = "udp"
	}
	conn, err := m.dialContext(ctx, proto, address)
	m.mu.Lock()
	_, stillOpening := m.opening[id]
	delete(m.opening, id)
	if closed := m.closed; err != nil || !stillOpening || closed {
		m.mu.Unlock()
		if conn != nil {
			conn.Close()
		}
		if stillOpening && !closed {
			m.sendStatus(id, StatusFailed)
		}
		return
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	s := &stream{id: id, network: network, conn: conn, writes: make(chan []byte, 256),
		done: make(chan struct{}), mux: m}
	s.lastWrite.Store(time.Now().UnixNano())
	m.streams[id] = s
	m.wg.Add(2)
	m.mu.Unlock()
	m.sendStatus(id, StatusOK)
	go s.writeLoop()
	go s.readLoop()
}

func (m *Mux) data(id uint32, payload []byte) {
	m.mu.Lock()
	s := m.streams[id]
	m.mu.Unlock()
	if s == nil || len(payload) == 0 {
		return
	}
	if s.network == NetworkUDP && len(payload) > MaxUDPPayload {
		m.closeStream(s, true)
		return
	}
	// Copy because the session's receive buffer may be reused by its caller.
	b := append([]byte(nil), payload...)
	if s.network == NetworkUDP {
		// UDP خودش گم‌شدن را تحمل می‌کند؛ صف پر نباید خواننده‌ی نشست را معطل کند.
		select {
		case s.writes <- b:
		default:
		}
		return
	}
	select {
	case s.writes <- b:
	case <-s.done:
	case <-time.After(5 * time.Second):
		// TCP is reliable: dropping a full queue would silently corrupt a
		// stream. Closing applies backpressure to the client instead.
		m.closeStream(s, true)
	}
}

func (s *stream) writeLoop() {
	defer s.mux.wg.Done()
	for {
		select {
		case <-s.done:
			return
		case b := <-s.writes:
			if len(b) == 0 {
				continue
			}
			_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			// برای UDP متصل، هر Write دقیقاً یک دیتاگرام است.
			_, err := s.conn.Write(b)
			s.lastWrite.Store(time.Now().UnixNano())
			if err != nil {
				s.mux.closeStream(s, true)
				return
			}
		}
	}
}

func (s *stream) readLoop() {
	defer s.mux.wg.Done()
	defer s.mux.closeStream(s, true)
	idle := tcpIdleTimeout
	size := MaxTCPPayload
	if s.network == NetworkUDP {
		idle, size = udpIdleTimeout, MaxUDPPayload
	}
	// frame = kind(1) || id(4) || data؛ هدر یک‌بار ساخته و بافر دوباره استفاده
	// می‌شود. Send داده را رمز می‌کند و پس از بازگشت به بافر نیازی ندارد.
	frame := make([]byte, 5+size)
	frame[0] = FrameData
	binary.BigEndian.PutUint32(frame[1:5], s.id)
	for {
		readSize := size
		if s.network == NetworkTCP {
			// روی مسیر UDP قطعه‌ها کوچک می‌شوند تا fragment نشوند؛ گم‌شدن یک
			// fragment کل بسته‌ی ۱۶KB را از بین می‌برد.
			if l, ok := s.mux.session.(payloadLimiter); ok {
				if limit := l.MaxPayload() - 5; limit > 0 && limit < readSize {
					readSize = limit
				}
			}
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(idle))
		n, err := s.conn.Read(frame[5 : 5+readSize])
		if n > 0 {
			if err := s.mux.session.Send(frame[:5+n]); err != nil {
				return
			}
		}
		if err != nil {
			// اگر فقط در جهت کلاینت → مقصد ترافیک بوده، جریان هنوز فعال است.
			if isTimeout(err) && time.Since(time.Unix(0, s.lastWrite.Load())) < idle {
				continue
			}
			if errors.Is(err, io.EOF) || isTimeout(err) {
				return
			}
			return
		}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (m *Mux) closeByID(id uint32, notify bool) {
	m.mu.Lock()
	s := m.streams[id]
	if cancel := m.opening[id]; cancel != nil {
		// Close پیش از تکمیل اتصال: dial لغو می‌شود و اتصال نیمه‌کاره نشت نمی‌کند.
		delete(m.opening, id)
		cancel()
	}
	m.mu.Unlock()
	if s != nil {
		m.closeStream(s, notify)
	}
}

func (m *Mux) closeStream(s *stream, notify bool) {
	s.closeOnce.Do(func() {
		m.mu.Lock()
		delete(m.streams, s.id)
		m.mu.Unlock()
		close(s.done)
		_ = s.conn.Close()
		if notify {
			frame := make([]byte, 5)
			frame[0] = FrameClose
			binary.BigEndian.PutUint32(frame[1:5], s.id)
			_ = m.session.Send(frame)
		}
	})
}

func (m *Mux) sendStatus(id uint32, status byte) {
	if id == 0 {
		return
	}
	frame := []byte{FrameStatus, byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id), status}
	_ = m.session.Send(frame)
}

// BuildOpen is shared by the reference client and protocol tests.
func BuildOpen(id uint32, network byte, host string, port uint16) ([]byte, error) {
	if id == 0 || len(host) == 0 || len(host) > 255 || port == 0 {
		return nil, errors.New("mux: invalid open parameters")
	}
	if network != NetworkTCP && network != NetworkUDP {
		return nil, errors.New("mux: invalid network")
	}
	frame := make([]byte, 10+len(host))
	frame[0], frame[5] = FrameOpen, network
	binary.BigEndian.PutUint32(frame[1:5], id)
	binary.BigEndian.PutUint16(frame[6:8], port)
	binary.BigEndian.PutUint16(frame[8:10], uint16(len(host)))
	copy(frame[10:], host)
	return frame, nil
}

func BuildData(id uint32, payload []byte) []byte {
	frame := make([]byte, 5+len(payload))
	frame[0] = FrameData
	binary.BigEndian.PutUint32(frame[1:5], id)
	copy(frame[5:], payload)
	return frame
}

func BuildClose(id uint32) []byte {
	frame := make([]byte, 5)
	frame[0] = FrameClose
	binary.BigEndian.PutUint32(frame[1:5], id)
	return frame
}

func ParseStatus(frame []byte) (id uint32, status byte, err error) {
	if len(frame) != 6 || frame[0] != FrameStatus {
		return 0, 0, errors.New("mux: invalid status frame")
	}
	return binary.BigEndian.Uint32(frame[1:5]), frame[5], nil
}

func (m *Mux) Close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.cancel()
	for id, cancel := range m.opening {
		delete(m.opening, id)
		cancel()
	}
	streams := make([]*stream, 0, len(m.streams))
	for _, s := range m.streams {
		streams = append(streams, s)
	}
	m.mu.Unlock()
	for _, s := range streams {
		m.closeStream(s, false)
	}
	m.wg.Wait()
}

func (m *Mux) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fmt.Sprintf("mux(streams=%d)", len(m.streams))
}
