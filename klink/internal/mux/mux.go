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
	"strconv"
	"sync"
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
)

type Sender interface {
	Send([]byte) error
}

type Mux struct {
	session Sender
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	streams map[uint32]*stream
	opening map[uint32]bool
	closed  bool
	wg      sync.WaitGroup
}

type stream struct {
	id        uint32
	network   byte
	conn      net.Conn
	writes    chan []byte
	done      chan struct{}
	closeOnce sync.Once
	mux       *Mux
}

func New(session Sender) *Mux {
	ctx, cancel := context.WithCancel(context.Background())
	return &Mux{session: session, ctx: ctx, cancel: cancel,
		streams: make(map[uint32]*stream), opening: make(map[uint32]bool)}
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
	if m.closed || m.streams[id] != nil || m.opening[id] {
		m.mu.Unlock()
		m.sendStatus(id, StatusFailed)
		return
	}
	m.opening[id] = true
	m.mu.Unlock()

	host := string(frame[10:])
	address := net.JoinHostPort(host, strconv.Itoa(int(port)))
	ctx, cancel := context.WithTimeout(m.ctx, 15*time.Second)
	defer cancel()
	dialer := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	proto := "tcp"
	if network == NetworkUDP {
		proto = "udp"
	}
	conn, err := dialer.DialContext(ctx, proto, address)
	if err != nil {
		m.mu.Lock()
		delete(m.opening, id)
		m.mu.Unlock()
		m.sendStatus(id, StatusFailed)
		return
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
	}
	s := &stream{id: id, network: network, conn: conn, writes: make(chan []byte, 256),
		done: make(chan struct{}), mux: m}
	m.mu.Lock()
	delete(m.opening, id)
	if m.closed {
		m.mu.Unlock()
		conn.Close()
		return
	}
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
			var err error
			if s.network == NetworkTCP {
				_, err = s.conn.Write(b)
			} else {
				_, err = s.conn.Write(b) // connected UDP: one Write preserves one datagram
			}
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
	buffer := make([]byte, MaxTCPPayload)
	if s.network == NetworkUDP {
		buffer = make([]byte, MaxUDPPayload)
	}
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(30 * time.Minute))
		n, err := s.conn.Read(buffer)
		if n > 0 {
			frame := make([]byte, 5+n)
			frame[0] = FrameData
			binary.BigEndian.PutUint32(frame[1:5], s.id)
			copy(frame[5:], buffer[:n])
			if err := s.mux.session.Send(frame); err != nil {
				return
			}
		}
		if err != nil {
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
