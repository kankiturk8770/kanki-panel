package transport

import (
	"net"
	"sync"
	"time"
)

// UDPListener یک سوکت UDP مشترک برای همه‌ی کلاینت‌ها؛ بسته‌ها با آدرس فرستنده
// به لایه‌ی نشست تحویل می‌شوند و هر بسته‌ی نامعتبر بی‌صدا رها می‌شود.
type UDPListener struct {
	conn    *net.UDPConn
	mu      sync.Mutex
	closed  bool
	bufSize int
}

// ListenUDP روی آدرس داده‌شده گوش می‌دهد (مثل ":443" یا "0.0.0.0:443").
func ListenUDP(addr string) (*UDPListener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	c, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, err
	}
	// بافرهای سوکت برای ترافیک سنگین.
	_ = c.SetReadBuffer(4 << 20)
	_ = c.SetWriteBuffer(4 << 20)
	return &UDPListener{conn: c, bufSize: 65535}, nil
}

func (l *UDPListener) LocalAddr() net.Addr { return l.conn.LocalAddr() }

func (l *UDPListener) ReadPacket() (Packet, error) {
	for {
		buf := make([]byte, l.bufSize)
		_ = l.conn.SetReadDeadline(time.Now().Add(UDPReadTimeout))
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return Packet{}, ErrClosed
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return Packet{}, err
		}
		return Packet{Data: buf[:n], Addr: addr}, nil
	}
}

func (l *UDPListener) WriteTo(data []byte, addr net.Addr) error {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return net.ErrClosed
	}
	_, err := l.conn.WriteToUDP(data, ua)
	return err
}

func (l *UDPListener) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	return l.conn.Close()
}
