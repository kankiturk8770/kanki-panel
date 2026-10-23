// Package session implements authenticated KLINK sessions, silent admission,
// address migration, quota accounting and epoch based rekeying.
package session

import (
	"context"
	"crypto/rand"
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

type pendingHandshake struct {
	state    *kcrypto.HandshakeState
	endpoint endpoint
	expires  time.Time
}

type userUsage struct {
	used    int64
	pending int64
}

// Manager is safe for concurrent UDP and TCP reader goroutines.
type Manager struct {
	cfg      Config
	mu       sync.RWMutex
	pending  map[[16]byte]*pendingHandshake
	sessions map[[16]byte]*Session
	byUser   map[int64]map[[16]byte]struct{}
	usage    map[int64]*userUsage
	rx       atomic.Int64
	tx       atomic.Int64
	started  time.Time
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
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
	m.mu.Lock()
	if len(m.pending) >= 4096 {
		m.mu.Unlock()
		return errSilent
	}
	if _, exists := m.pending[hello]; exists {
		m.mu.Unlock()
		return errSilent
	}
	hs, err := kcrypto.NewResponder(m.cfg.ServerKey)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if _, _, finished, err := hs.ReadMessage(raw[18:]); err != nil || finished {
		m.mu.Unlock()
		return errSilent
	}
	msg2, _, finished, err := hs.WriteMessage(nil)
	if err != nil || finished {
		m.mu.Unlock()
		return errSilent
	}
	m.pending[hello] = &pendingHandshake{state: hs, endpoint: ep, expires: time.Now().Add(m.cfg.HandshakeTimeout)}
	m.mu.Unlock()
	return m.writeHandshake(ep, msgHello2, hello, msg2)
}

func (m *Manager) handleHello3(ep endpoint, raw []byte) error {
	if !validHello(raw) {
		return errSilent
	}
	var hello [16]byte
	copy(hello[:], raw[2:18])
	m.mu.Lock()
	pending := m.pending[hello]
	delete(m.pending, hello) // one attempt only; handshake retries need fresh randomness
	if pending == nil || time.Now().After(pending.expires) || pending.endpoint.key() != ep.key() {
		m.mu.Unlock()
		return errSilent
	}
	m.mu.Unlock()

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
	}
	s.lastSeenUnix.Store(now.UnixNano())
	m.mu.Lock()
	if _, exists := m.sessions[sid]; exists || (user.DeviceLimit > 0 && len(m.byUser[user.ID]) >= user.DeviceLimit) {
		m.mu.Unlock()
		return errSilent
	}
	if usage := m.usage[user.ID]; usage != nil && user.VolumeLimit > 0 && usage.used >= user.VolumeLimit {
		m.mu.Unlock()
		return errSilent
	}
	m.sessions[sid] = s
	if m.byUser[user.ID] == nil {
		m.byUser[user.ID] = make(map[[16]byte]struct{})
	}
	m.byUser[user.ID][sid] = struct{}{}
	m.mu.Unlock()

	// The third Noise message uses bootstrap framing. Every following TCP frame,
	// including this ACK, uses the channel-binding-derived mask.
	if tcp, ok := ep.listener.(*transport.TCPListener); ok {
		tcp.UpgradeFraming(ep.addr, binding)
	}
	if m.cfg.OnSession != nil {
		m.cfg.OnSession(s)
	}
	if err := m.writeHandshake(ep, msgHelloAck, hello, append(sid[:], []byte{}...)); err != nil {
		m.CloseSession(s)
		return err
	}
	m.cfg.Logger.Info("session established", "user_id", user.ID, "session", base64.RawURLEncoding.EncodeToString(sid[:]), "transport", ep.addr.Network())
	return nil
}

func (m *Manager) admitUser(u *store.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.DeviceLimit > 0 && len(m.byUser[u.ID]) >= u.DeviceLimit {
		return errSilent
	}
	if _, ok := m.usage[u.ID]; !ok {
		m.usage[u.ID] = &userUsage{used: u.UsedBytes}
	}
	if u.VolumeLimit > 0 && m.usage[u.ID].used >= u.VolumeLimit {
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
	ID          [16]byte
	User        store.User
	manager     *Manager
	inbound     *kcrypto.Channel
	outbound    *kcrypto.Channel
	recvMu      sync.Mutex
	replay      kcrypto.ReplayWindow
	replayEpoch uint64

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
	if err == nil {
		if epoch != s.replayEpoch {
			s.replay.Reset()
			s.replayEpoch = epoch
		}
		err = s.replay.Check(seq)
	}
	s.recvMu.Unlock()
	if err != nil {
		return errSilent
	}
	// Migration is accepted only after AEAD and replay validation. An attacker
	// who merely knows a SessionID cannot redirect traffic or change its epoch.
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errSilent
	}
	changed := s.remote.key() != ep.key()
	s.remote = ep
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
	s.sendMu.Lock()
	if s.sendPackets >= s.manager.cfg.RekeyPackets || time.Since(s.lastRekey) >= s.manager.cfg.RekeyInterval {
		s.outbound.Rekey()
		s.sendPackets = 0
		s.lastRekey = time.Now()
	}
	sealed, _, err := s.outbound.Seal(plaintext)
	s.sendPackets++
	s.sendMu.Unlock()
	if err != nil {
		return err
	}
	packet := make([]byte, DataOffset+len(sealed))
	packet[0], packet[1] = Version, msgData
	copy(packet[2:18], s.ID[:])
	copy(packet[DataOffset:], sealed)

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

func (m *Manager) account(s *Session, n int64, inbound bool) bool {
	if inbound {
		m.rx.Add(n)
	} else {
		m.tx.Add(n)
	}
	s.mu.RLock()
	user := s.User
	s.mu.RUnlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.usage[user.ID]
	if u == nil {
		u = &userUsage{used: user.UsedBytes}
		m.usage[user.ID] = u
	}
	u.used += n
	u.pending += n
	return user.VolumeLimit == 0 || u.used <= user.VolumeLimit
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
			delete(m.pending, id)
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
			m.mu.Lock()
			if usage := m.usage[u.ID]; usage != nil {
				usage.used = u.UsedBytes + usage.pending
			}
			m.mu.Unlock()
		}
	}
}

func (m *Manager) flushUsage() {
	type delta struct{ id, bytes int64 }
	m.mu.Lock()
	deltas := make([]delta, 0, len(m.usage))
	for id, u := range m.usage {
		if u.pending > 0 {
			deltas = append(deltas, delta{id, u.pending})
			u.pending = 0
		}
	}
	m.mu.Unlock()
	for _, d := range deltas {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := m.cfg.Store.AddUsage(ctx, d.id, d.bytes)
		cancel()
		if err != nil {
			m.mu.Lock()
			if errors.Is(err, store.ErrNotFound) {
				delete(m.usage, d.id)
			} else if u := m.usage[d.id]; u != nil {
				u.pending += d.bytes
				u.used -= d.bytes
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
			us.UsedBytes = usage.used
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
