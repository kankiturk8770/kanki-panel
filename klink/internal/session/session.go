// Package session implements authenticated KLINK sessions, silent admission,
// address migration, quota accounting and epoch based rekeying.
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	kcrypto "github.com/kankipro/klink/internal/crypto"
	"github.com/kankipro/klink/internal/obfuscation"
	"github.com/kankipro/klink/internal/store"
	"github.com/kankipro/klink/internal/transport"
)

const (
	Version       = 1
	msgHello1     = 1
	msgHello2     = 2
	msgHello3     = 3
	msgHelloAck   = 4
	msgData       = 16
	HandshakeSize = 18 // version, kind, hello/session ID
	DataOffset    = 18
)

var errSilent = errors.New("session: silently dropped")

const (
	// maxPending سقف کل handshakeهای نیمه‌کاره است و maxPendingPerIP سقف هر
	// آدرس IP؛ بدون سقف دوم یک منبع می‌توانست کل ظرفیت را پر کند و جلوی اتصال
	// همه‌ی کاربران را بگیرد.
	maxPending      = 4096
	maxPendingPerIP = 64
	// completedTTL مدت نگه‌داری ACK برای ارسال مجدد است. اگر ACK روی UDP گم شود،
	// کلاینت همان پیام سوم را دوباره می‌فرستد و باید همان ACK را دریافت کند؛ در غیر
	// این صورت نشستی بی‌صاحب ساخته می‌شد که سهمیه‌ی دستگاه را تا idle timeout اشغال می‌کرد.
	completedTTL = 30 * time.Second
)

// متغیر هستند تا تست‌ها بتوانند کوتاهشان کنند.
var (
	// staleSessionAge: نشستی که این مدت هیچ بسته‌ی معتبری نفرستاده، هنگام رسیدن
	// اتصال تازه‌ی همان کاربر جای خود را می‌دهد (کلاینت keepalive هر ۳۰ تا ۶۰ ثانیه دارد).
	staleSessionAge = 2 * time.Minute
	// unusedSessionAge: نشستی که پس از handshake هرگز داده‌ای نفرستاده (مثلاً ACK
	// آن گم شده و کلاینت handshake تازه زده) پس از این مدت قابل جایگزینی است.
	unusedSessionAge = 15 * time.Second
)

const (
	// SafeUDPPayload بیشینه‌ی متن قابل ارسال در یک بسته روی UDP بدون fragment
	// شدن IP است: 1280 (حداقل MTU در IPv6) منهای IP/UDP، هدر KLINK، AEAD و padding.
	SafeUDPPayload = 1280 - 48 - DataOffset - 16 - 16 - 64 - 6
)

type Authenticator interface {
	Authorize(context.Context, string) (*store.User, error)
	AddUsage(context.Context, int64, int64) error
}

type Config struct {
	ServerKey        kcrypto.KeyPair
	Store            Authenticator
	Obfuscation      obfuscation.Profile
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	RekeyInterval    time.Duration
	RekeyPackets     uint64
	OnSession        func(*Session)
	Logger           *slog.Logger
}

type endpoint struct {
	listener transport.Listener
	addr     net.Addr
}

func (e endpoint) key() string {
	if a, ok := e.addr.(*transport.TCPConnAddr); ok {
		return fmt.Sprintf("tcp/%d", a.ID)
	}
	return e.addr.Network() + "/" + e.addr.String()
}

// ip فقط آدرس IP مبدأ را برای محدودسازی هر منبع برمی‌گرداند.
func (e endpoint) ip() string {
	switch a := e.addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *transport.TCPConnAddr:
		if ta, ok := a.Conn.RemoteAddr().(*net.TCPAddr); ok {
			return ta.IP.String()
		}
	}
	host, _, err := net.SplitHostPort(e.addr.String())
	if err != nil {
		return e.addr.String()
	}
	return host
}

func (e endpoint) isUDP() bool {
	_, ok := e.addr.(*net.UDPAddr)
	return ok
}

type pendingHandshake struct {
	state    *kcrypto.HandshakeState
	endpoint endpoint
	ip       string
	expires  time.Time
}

type completedHandshake struct {
	sid      [16]byte
	digest   [32]byte
	endpoint string
	expires  time.Time
}

// userUsage شمارنده‌های مصرف یک کاربر است. هر نشست اشاره‌گر آن را نگه می‌دارد
// تا مسیر داده برای هر بسته قفل سراسری Manager را نگیرد.
type userUsage struct {
	used    atomic.Int64
	pending atomic.Int64
}

// Manager is safe for concurrent UDP and TCP reader goroutines.
type Manager struct {
	cfg       Config
	mu        sync.RWMutex
	pending   map[[16]byte]*pendingHandshake
	pendingIP map[string]int
	completed map[[16]byte]*completedHandshake
	sessions  map[[16]byte]*Session
	byUser    map[int64]map[[16]byte]struct{}
	usage     map[int64]*userUsage
	rx        atomic.Int64
	tx        atomic.Int64
	started   time.Time
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
}

func NewManager(cfg Config) (*Manager, error) {
	if cfg.Store == nil || cfg.Obfuscation == nil {
		return nil, errors.New("session: store and obfuscation are required")
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 30 * time.Second
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 10 * time.Minute
	}
	if cfg.RekeyInterval <= 0 {
		cfg.RekeyInterval = 15 * time.Minute
	}
	if cfg.RekeyPackets == 0 {
		cfg.RekeyPackets = 1 << 20
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		cfg: cfg, pending: make(map[[16]byte]*pendingHandshake),
		pendingIP: make(map[string]int), completed: make(map[[16]byte]*completedHandshake),
		sessions: make(map[[16]byte]*Session), byUser: make(map[int64]map[[16]byte]struct{}),
		usage: make(map[int64]*userUsage), started: time.Now().UTC(), ctx: ctx, cancel: cancel,
	}
	m.wg.Add(1)
	go m.maintenance()
	return m, nil
}

// HandlePacket never sends an error response to the peer. All malformed,
// unauthenticated and replayed packets follow the same silent-drop path.
func (m *Manager) HandlePacket(l transport.Listener, p transport.Packet) {
	if err := m.handlePacket(l, p); err != nil && !errors.Is(err, errSilent) {
		m.cfg.Logger.Debug("packet dropped", "error", err)
	}
}

func (m *Manager) handlePacket(l transport.Listener, p transport.Packet) error {
	raw, err := m.cfg.Obfuscation.Unwrap(p.Data)
	if err != nil || len(raw) < 2 || raw[0] != Version {
		return errSilent
	}
	ep := endpoint{listener: l, addr: p.Addr}
	switch raw[1] {
	case msgHello1:
		return m.handleHello1(ep, raw)
	case msgHello3:
		return m.handleHello3(ep, raw)
	case msgData:
		return m.handleData(ep, raw, len(p.Data))
	default:
		return errSilent
	}
}

func validHello(raw []byte) bool {
	return len(raw) > HandshakeSize && raw[0] == Version
}

func (m *Manager) handleHello1(ep endpoint, raw []byte) error {
	if !validHello(raw) {
		return errSilent
	}
	var hello [16]byte
	copy(hello[:], raw[2:18])
	ip := ep.ip()
	m.mu.RLock()
	_, exists := m.pending[hello]
	full := len(m.pending) >= maxPending || m.pendingIP[ip] >= maxPendingPerIP
	m.mu.RUnlock()
	if exists {
		return errSilent
	}
	if full && !m.prunePending(ip) {
		return errSilent
	}
	// عملیات DH بیرون از قفل سراسری انجام می‌شود؛ در نسخه‌ی قبل هر handshake
	// (حتی جعلی) کل مسیر داده‌ی همه‌ی کاربران را تا پایان X25519 متوقف می‌کرد.
	hs, err := kcrypto.NewResponder(m.cfg.ServerKey)
	if err != nil {
		return err
	}
	if _, _, finished, err := hs.ReadMessage(raw[18:]); err != nil || finished {
		return errSilent
	}
	msg2, _, finished, err := hs.WriteMessage(nil)
	if err != nil || finished {
		return errSilent
	}
	m.mu.Lock()
	if _, exists := m.pending[hello]; exists || len(m.pending) >= maxPending || m.pendingIP[ip] >= maxPendingPerIP {
		m.mu.Unlock()
		return errSilent
	}
	m.pending[hello] = &pendingHandshake{state: hs, endpoint: ep, ip: ip, expires: time.Now().Add(m.cfg.HandshakeTimeout)}
	m.pendingIP[ip]++
	m.mu.Unlock()
	return m.writeHandshake(ep, msgHello2, hello, msg2)
}

// prunePending handshakeهای منقضی را پاک می‌کند و می‌گوید آیا اکنون جا هست.
func (m *Manager) prunePending(ip string) bool {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, p := range m.pending {
		if now.After(p.expires) {
			m.deletePendingLocked(id, p)
		}
	}
	return len(m.pending) < maxPending && m.pendingIP[ip] < maxPendingPerIP
}

func (m *Manager) deletePendingLocked(id [16]byte, p *pendingHandshake) {
	delete(m.pending, id)
	if m.pendingIP[p.ip] <= 1 {
		delete(m.pendingIP, p.ip)
	} else {
		m.pendingIP[p.ip]--
	}
}

func (m *Manager) handleHello3(ep endpoint, raw []byte) error {
	if !validHello(raw) {
		return errSilent
	}
	var hello [16]byte
	copy(hello[:], raw[2:18])
	m.mu.Lock()
	pending := m.pending[hello]
	if pending == nil {
		done := m.completed[hello]
		m.mu.Unlock()
		return m.resendAck(ep, hello, raw, done)
	}
	// فقط همان مسیری که پیام اول را فرستاده می‌تواند handshake را مصرف کند؛
	// قبلاً پیام سوم از هر آدرسی handshake را پاک می‌کرد و کاربر واقعی ناکام می‌ماند.
	if pending.endpoint.key() != ep.key() {
		m.mu.Unlock()
		return errSilent
	}
	m.deletePendingLocked(hello, pending) // one attempt only; handshake retries need fresh randomness
	m.mu.Unlock()
	if time.Now().After(pending.expires) {
		return errSilent
	}

	_, binding, finished, err := pending.state.ReadMessage(raw[18:])
	if err != nil || !finished || len(binding) == 0 {
		return errSilent
	}
	peer := pending.state.PeerStatic()
	if len(peer) != 32 {
		return errSilent
	}
	publicKey := base64.StdEncoding.EncodeToString(peer)
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	user, err := m.cfg.Store.Authorize(ctx, publicKey)
	cancel()
	if err != nil {
		return errSilent
	}
	if err := m.admitUser(user); err != nil {
		return errSilent
	}

	k1, k2, err := kcrypto.ChannelKeys(binding)
	if err != nil {
		return errSilent
	}
	inbound, err := kcrypto.NewChannel(k1)
	if err != nil {
		return err
	}
	outbound, err := kcrypto.NewChannel(k2)
	if err != nil {
		return err
	}
	var sid [16]byte
	if _, err := rand.Read(sid[:]); err != nil {
		return err
	}
	now := time.Now()
	s := &Session{
		ID: sid, User: *user, manager: m, inbound: inbound, outbound: outbound,
		remote: ep, binding: append([]byte(nil), binding...), lastSeen: now, lastRekey: now,
		created: now,
	}
	s.lastSeenUnix.Store(now.UnixNano())
	s.volumeLimit.Store(user.VolumeLimit)
	if !m.register(s) {
		return errSilent
	}
	m.mu.Lock()
	if len(m.completed) < maxPending {
		m.completed[hello] = &completedHandshake{sid: sid, digest: sha256.Sum256(raw), endpoint: ep.key(),
			expires: now.Add(completedTTL)}
	}
	m.mu.Unlock()

	// The third Noise message uses bootstrap framing. Every following TCP frame,
	// including this ACK, uses the channel-binding-derived mask.
	if tcp, ok := ep.listener.(*transport.TCPListener); ok {
		tcp.UpgradeFraming(ep.addr, binding)
	}
	if m.cfg.OnSession != nil {
		m.cfg.OnSession(s)
	}
	if err := m.writeHandshake(ep, msgHelloAck, hello, sid[:]); err != nil {
		m.CloseSession(s)
		return err
	}
	m.cfg.Logger.Info("session established", "user_id", user.ID, "session", base64.RawURLEncoding.EncodeToString(sid[:]), "transport", ep.addr.Network())
	return nil
}

// resendAck به پیام سومِ تکراری (همان بایت‌ها، از همان مسیر) همان ACK قبلی را
// می‌دهد. این پاسخ کوچک‌تر از درخواست است و تقویت ترافیک ایجاد نمی‌کند.
func (m *Manager) resendAck(ep endpoint, hello [16]byte, raw []byte, done *completedHandshake) error {
	if done == nil || time.Now().After(done.expires) || done.endpoint != ep.key() {
		return errSilent
	}
	digest := sha256.Sum256(raw)
	if digest != done.digest {
		return errSilent
	}
	m.mu.RLock()
	_, alive := m.sessions[done.sid]
	m.mu.RUnlock()
	if !alive {
		return errSilent
	}
	return m.writeHandshake(ep, msgHelloAck, hello, done.sid[:])
}

// register نشست را با رعایت محدودیت دستگاه ثبت می‌کند. اگر سهمیه پر باشد،
// نشست‌های مرده‌ی همان کاربر (بدون بسته‌ی معتبر اخیر) جای خود را به اتصال تازه
// می‌دهند؛ بدون این کار کاربری که اینترنتش قطع و وصل شده یا برنامه را دوباره باز
// کرده، تا پایان idle timeout (پیش‌فرض ده دقیقه) نمی‌توانست وصل شود.
func (m *Manager) register(s *Session) bool {
	user := s.User
	for attempt := 0; attempt < 2; attempt++ {
		m.mu.Lock()
		if _, exists := m.sessions[s.ID]; exists {
			m.mu.Unlock()
			return false
		}
		usage := m.usage[user.ID]
		if usage == nil {
			usage = &userUsage{}
			usage.used.Store(user.UsedBytes)
			m.usage[user.ID] = usage
		}
		if user.VolumeLimit > 0 && usage.used.Load() >= user.VolumeLimit {
			m.mu.Unlock()
			return false
		}
		if user.DeviceLimit > 0 && len(m.byUser[user.ID]) >= user.DeviceLimit {
			if attempt > 0 {
				m.mu.Unlock()
				return false
			}
			victims := m.staleSessionsLocked(user.ID, len(m.byUser[user.ID])-user.DeviceLimit+1)
			m.mu.Unlock()
			if len(victims) == 0 {
				return false
			}
			for _, v := range victims {
				m.cfg.Logger.Info("replacing stale session", "user_id", user.ID, "session", v.IDString())
				m.CloseSession(v)
			}
			continue
		}
		s.usage = usage
		m.sessions[s.ID] = s
		if m.byUser[user.ID] == nil {
			m.byUser[user.ID] = make(map[[16]byte]struct{})
		}
		m.byUser[user.ID][s.ID] = struct{}{}
		m.mu.Unlock()
		return true
	}
	return false
}

// staleSessionsLocked حداکثر n نشست مرده‌ی کاربر را، قدیمی‌ترین اول، برمی‌گرداند.
func (m *Manager) staleSessionsLocked(userID int64, n int) []*Session {
	now := time.Now()
	var victims []*Session
	for sid := range m.byUser[userID] {
		s := m.sessions[sid]
		if s == nil {
			continue
		}
		idle := now.Sub(s.LastSeen())
		if idle > staleSessionAge || (!s.gotData.Load() && now.Sub(s.created) > unusedSessionAge) {
			victims = append(victims, s)
		}
	}
	for i := 1; i < len(victims); i++ {
		for j := i; j > 0 && victims[j].LastSeen().Before(victims[j-1].LastSeen()); j-- {
			victims[j], victims[j-1] = victims[j-1], victims[j]
		}
	}
	if len(victims) > n {
		victims = victims[:n]
	}
	return victims
}

// admitUser بررسی ارزان حجم پیش از ساخت کلیدها است؛ محدودیت دستگاه در register
// و به‌صورت اتمیک با ثبت نشست اعمال می‌شود.
func (m *Manager) admitUser(u *store.User) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if usage := m.usage[u.ID]; usage != nil && u.VolumeLimit > 0 && usage.used.Load() >= u.VolumeLimit {
		return errSilent
	}
	return nil
}

func (m *Manager) writeHandshake(ep endpoint, kind byte, hello [16]byte, payload []byte) error {
	out := make([]byte, HandshakeSize+len(payload))
	out[0], out[1] = Version, kind
	copy(out[2:18], hello[:])
	copy(out[18:], payload)
	return ep.listener.WriteTo(m.cfg.Obfuscation.Wrap(out), ep.addr)
}

func (m *Manager) handleData(ep endpoint, raw []byte, wireBytes int) error {
	if len(raw) <= DataOffset {
		return errSilent
	}
	var sid [16]byte
	copy(sid[:], raw[2:18])
	m.mu.RLock()
	s := m.sessions[sid]
	m.mu.RUnlock()
	if s == nil {
		return errSilent
	}
	return s.accept(ep, raw[DataOffset:], wireBytes)
}

// Session is one authenticated client device. Many mux streams share it.
type Session struct {
	ID       [16]byte
	User     store.User
	manager  *Manager
	inbound  *kcrypto.Channel
	outbound *kcrypto.Channel
	recvMu   sync.Mutex
	// دو پنجره‌ی replay: windows[cur] برای epoch جاری و دیگری برای epoch قبلی، تا
	// بسته‌های دیررسیده‌ی پیش از rekey هم پذیرفته شوند و هم replay آن‌ها رد شود.
	windows     [2]kcrypto.ReplayWindow
	cur         int
	replayEpoch uint64
	hasPrev     bool
	usage       *userUsage
	created     time.Time
	gotData     atomic.Bool
	volumeLimit atomic.Int64

	mu           sync.RWMutex
	remote       endpoint
	binding      []byte
	closed       bool
	OnData       func([]byte)
	OnClose      func()
	lastSeen     time.Time
	lastSeenUnix atomic.Int64

	sendMu      sync.Mutex
	lastRekey   time.Time
	sendPackets uint64
	rxBytes     atomic.Int64
	txBytes     atomic.Int64
}

func (s *Session) IDString() string { return base64.RawURLEncoding.EncodeToString(s.ID[:]) }

func (s *Session) SetHandlers(onData func([]byte), onClose func()) {
	s.mu.Lock()
	s.OnData, s.OnClose = onData, onClose
	s.mu.Unlock()
}

func (s *Session) LastSeen() time.Time { return time.Unix(0, s.lastSeenUnix.Load()) }

func (s *Session) Remote() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.remote.addr == nil {
		return ""
	}
	return s.remote.addr.String()
}

func (s *Session) accept(ep endpoint, sealed []byte, wireBytes int) error {
	// Open و ثبت replay یک عملیات اتمیک در سطح نشست‌اند؛ این هم رقابت بین
	// خواننده‌های UDP/TCP را حذف می‌کند و هم reset مربوط به epoch را امن می‌سازد.
	s.recvMu.Lock()
	plaintext, seq, epoch, err := s.inbound.Open(sealed)
	newest := false
	if err == nil {
		switch {
		case epoch == s.replayEpoch:
			newest, err = s.windows[s.cur].CheckNewest(seq)
		case epoch == s.replayEpoch+1:
			// جابه‌جایی پنجره‌ها به‌جای پاک‌کردن: پنجره‌ی epoch قبلی برای بسته‌های
			// دیررسیده حفظ می‌شود.
			s.cur ^= 1
			s.windows[s.cur].Reset()
			s.hasPrev = true
			s.replayEpoch = epoch
			newest, err = s.windows[s.cur].CheckNewest(seq)
		case s.hasPrev && s.replayEpoch > 0 && epoch == s.replayEpoch-1:
			_, err = s.windows[s.cur^1].CheckNewest(seq)
		default:
			err = kcrypto.ErrReplay
		}
	}
	s.recvMu.Unlock()
	if err != nil {
		return errSilent
	}
	s.gotData.Store(true)
	// Migration is accepted only after AEAD and replay validation, and only for
	// the newest packet: a delayed packet from the previous network must not
	// pull the session back. An attacker who merely knows a SessionID cannot
	// redirect traffic or change its epoch.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errSilent
	}
	changed := newest && s.remote.key() != ep.key()
	if changed {
		s.remote = ep
	}
	s.lastSeen = time.Now()
	s.lastSeenUnix.Store(s.lastSeen.UnixNano())
	s.mu.Unlock()
	if changed {
		if tcp, ok := ep.listener.(*transport.TCPListener); ok {
			tcp.UpgradeFraming(ep.addr, s.binding)
		}
		s.manager.cfg.Logger.Info("session migrated", "session", s.IDString(), "transport", ep.addr.Network())
	}
	if !s.manager.account(s, int64(wireBytes), true) {
		s.manager.CloseSession(s)
		return errSilent
	}
	s.rxBytes.Add(int64(wireBytes))
	if len(plaintext) == 0 || plaintext[0] == 0 { // authenticated keepalive
		return nil
	}
	s.mu.RLock()
	handler := s.OnData
	s.mu.RUnlock()
	if handler != nil {
		handler(plaintext)
	}
	return nil
}

// Send encrypts one logical mux packet and sends it to the latest authenticated
// endpoint. The next call after a network switch therefore uses the new path.
func (s *Session) Send(plaintext []byte) error {
	if len(plaintext) > 65535-16-16-64 {
		return errors.New("session: payload too large")
	}
	// هدر و متن رمزشده در یک بافر ساخته می‌شوند تا برای هر بسته یک تخصیص و
	// کپی کامل payload کمتر شود.
	packet := make([]byte, DataOffset, DataOffset+16+len(plaintext)+16)
	packet[0], packet[1] = Version, msgData
	copy(packet[2:18], s.ID[:])
	s.sendMu.Lock()
	if s.sendPackets >= s.manager.cfg.RekeyPackets || time.Since(s.lastRekey) >= s.manager.cfg.RekeyInterval {
		s.outbound.Rekey()
		s.sendPackets = 0
		s.lastRekey = time.Now()
	}
	packet, _, err := s.outbound.SealTo(packet, plaintext)
	s.sendPackets++
	s.sendMu.Unlock()
	if err != nil {
		return err
	}

	s.mu.RLock()
	ep, closed := s.remote, s.closed
	s.mu.RUnlock()
	if closed {
		return transport.ErrClosed
	}
	wrapped := s.manager.cfg.Obfuscation.Wrap(packet)
	if !s.manager.account(s, int64(len(wrapped)), false) {
		s.manager.CloseSession(s)
		return store.ErrUnauthorized
	}
	if err := ep.listener.WriteTo(wrapped, ep.addr); err != nil {
		return err
	}
	s.txBytes.Add(int64(len(wrapped)))
	return nil
}

func (s *Session) KeepAlive() error { return s.Send([]byte{0}) }

// MaxPayload بیشینه‌ی متن پیشنهادی برای یک Send است. روی UDP بسته‌های بزرگ‌تر
// از MTU در IP تکه‌تکه می‌شوند و گم‌شدن هر تکه کل بسته را از بین می‌برد؛ بنابراین
// mux داده‌ی جریان‌های TCP را روی مسیر UDP در قطعه‌های کوچک‌تر می‌فرستد.
func (s *Session) MaxPayload() int {
	s.mu.RLock()
	udp := s.remote.isUDP()
	s.mu.RUnlock()
	if udp {
		return SafeUDPPayload
	}
	return 65535 - 16 - 16 - 64
}

func (m *Manager) account(s *Session, n int64, inbound bool) bool {
	if inbound {
		m.rx.Add(n)
	} else {
		m.tx.Add(n)
	}
	u := s.usage
	if u == nil { // نشست ثبت‌نشده (فقط در تست‌ها)
		return true
	}
	used := u.used.Add(n)
	u.pending.Add(n)
	limit := s.volumeLimit.Load()
	return limit == 0 || used <= limit
}

func (m *Manager) CloseSession(s *Session) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	userID := s.User.ID
	callback := s.OnClose
	s.mu.Unlock()

	m.mu.Lock()
	delete(m.sessions, s.ID)
	delete(m.byUser[userID], s.ID)
	if len(m.byUser[userID]) == 0 {
		delete(m.byUser, userID)
	}
	m.mu.Unlock()
	if callback != nil {
		callback()
	}
}

func (m *Manager) maintenance() {
	defer m.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var rounds uint64
	for {
		select {
		case <-m.ctx.Done():
			m.flushUsage()
			return
		case <-ticker.C:
			rounds++
			m.cleanup(rounds%6 == 0)
			m.flushUsage()
		}
	}
}

func (m *Manager) cleanup(refreshUsers bool) {
	now := time.Now()
	m.mu.Lock()
	for id, p := range m.pending {
		if now.After(p.expires) {
			m.deletePendingLocked(id, p)
		}
	}
	for id, c := range m.completed {
		if now.After(c.expires) {
			delete(m.completed, id)
		}
	}
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.mu.RLock()
		user := s.User
		s.mu.RUnlock()
		if now.Sub(s.LastSeen()) > m.cfg.IdleTimeout || user.Expired(now) {
			m.CloseSession(s)
			continue
		}
		if refreshUsers {
			ctx, cancel := context.WithTimeout(m.ctx, 3*time.Second)
			u, err := m.cfg.Store.Authorize(ctx, user.PublicKey)
			cancel()
			if err != nil {
				if errors.Is(err, store.ErrUnauthorized) {
					m.CloseSession(s)
				} else {
					// خطای موقت دیتابیس نباید کاربران آنلاین را قطع کند؛ بررسی
					// در دور بعد تکرار می‌شود.
					m.cfg.Logger.Warn("user refresh failed", "user_id", user.ID, "error", err)
				}
				continue
			}
			s.mu.Lock()
			s.User = *u
			s.mu.Unlock()
			s.volumeLimit.Store(u.VolumeLimit)
			if usage := s.usage; usage != nil {
				usage.used.Store(u.UsedBytes + usage.pending.Load())
				if u.VolumeLimit > 0 && usage.used.Load() > u.VolumeLimit {
					m.CloseSession(s)
				}
			}
		}
	}
}

func (m *Manager) flushUsage() {
	type delta struct{ id, bytes int64 }
	m.mu.RLock()
	deltas := make([]delta, 0, len(m.usage))
	for id, u := range m.usage {
		if n := u.pending.Swap(0); n > 0 {
			deltas = append(deltas, delta{id, n})
		}
	}
	m.mu.RUnlock()
	for _, d := range deltas {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := m.cfg.Store.AddUsage(ctx, d.id, d.bytes)
		cancel()
		if err != nil {
			m.mu.Lock()
			if errors.Is(err, store.ErrNotFound) {
				delete(m.usage, d.id)
			} else if u := m.usage[d.id]; u != nil {
				// مصرف واقعاً انجام شده است؛ فقط ذخیره‌اش برای دور بعد می‌ماند.
				// نسخه‌ی قبل used را کم می‌کرد و هر خطای دیتابیس حجم رایگان می‌داد.
				u.pending.Add(d.bytes)
			}
			m.mu.Unlock()
			if !errors.Is(err, store.ErrNotFound) {
				m.cfg.Logger.Error("could not persist usage", "user_id", d.id, "error", err)
			}
		}
	}
}

type UserStatus struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Sessions    int        `json:"sessions"`
	Remote      string     `json:"remote,omitempty"`
	LastSeen    time.Time  `json:"last_seen"`
	RXBytes     int64      `json:"rx_bytes"`
	TXBytes     int64      `json:"tx_bytes"`
	UsedBytes   int64      `json:"used_bytes"`
	VolumeLimit int64      `json:"volume_limit"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

type Status struct {
	StartedAt      time.Time    `json:"started_at"`
	UptimeSeconds  int64        `json:"uptime_seconds"`
	RXBytes        int64        `json:"rx_bytes"`
	TXBytes        int64        `json:"tx_bytes"`
	OnlineUsers    int          `json:"online_users"`
	OnlineSessions int          `json:"online_sessions"`
	Users          []UserStatus `json:"users"`
}

func (m *Manager) Snapshot() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := Status{StartedAt: m.started, UptimeSeconds: int64(time.Since(m.started).Seconds()),
		RXBytes: m.rx.Load(), TXBytes: m.tx.Load(), OnlineUsers: len(m.byUser),
		OnlineSessions: len(m.sessions), Users: make([]UserStatus, 0, len(m.byUser))}
	for id, set := range m.byUser {
		var us UserStatus
		for sid := range set {
			s := m.sessions[sid]
			if s == nil {
				continue
			}
			if us.ID == 0 {
				s.mu.RLock()
				remote := ""
				if s.remote.addr != nil {
					remote = s.remote.addr.String()
				}
				us = UserStatus{ID: id, Name: s.User.Name, Remote: remote, LastSeen: s.LastSeen(),
					VolumeLimit: s.User.VolumeLimit, ExpiresAt: s.User.ExpiresAt}
				s.mu.RUnlock()
			}
			us.Sessions++
			us.RXBytes += s.rxBytes.Load()
			us.TXBytes += s.txBytes.Load()
		}
		if usage := m.usage[id]; usage != nil {
			us.UsedBytes = usage.used.Load()
		}
		st.Users = append(st.Users, us)
	}
	return st
}

func (m *Manager) Close() error {
	m.cancel()
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()
	for _, s := range sessions {
		m.CloseSession(s)
	}
	m.wg.Wait()
	return nil
}
