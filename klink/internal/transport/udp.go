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

var udpBuffers = sync.Pool{New: func() any { b := make([]byte, 65535); return &b }}

// ReadPacket بسته‌ی بعدی را برمی‌گرداند. بافر ۶۴KB خواندن بازیافت می‌شود و فقط
// به اندازه‌ی واقعی بسته کپی می‌شود؛ قبلاً برای هر دیتاگرام ۶۴KB تخصیص داده
// می‌شد که زیر بار سنگین فشار شدیدی روی GC می‌گذاشت.
func (l *UDPListener) ReadPacket() (Packet, error) {
	bp := udpBuffers.Get().(*[]byte)
	defer udpBuffers.Put(bp)
	buf := (*bp)[:l.bufSize]
	for {
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
		return Packet{Data: append([]byte(nil), buf[:n]...), Addr: addr}, nil
	}
}

// Serve بسته‌ها را بین workers گوروتین پخش می‌کند. بسته‌های یک آدرس مبدأ همیشه
// به یک worker می‌روند تا ترتیب داده‌ی هر کلاینت حفظ شود، ولی handshake کند یا
// mux معطل یک کاربر دیگر کل سرور را متوقف نمی‌کند. اگر صف یک worker پر باشد
// بسته مثل هر بسته‌ی UDP گم‌شده دور ریخته می‌شود. تا بسته‌شدن listener برمی‌گردد.
func (l *UDPListener) Serve(workers int, handler func(Packet)) error {
	if workers < 1 {
		workers = 1
	}
	queues := make([]chan Packet, workers)
	var wg sync.WaitGroup
	for i := range queues {
		queues[i] = make(chan Packet, 1024)
		wg.Add(1)
		go func(q chan Packet) {
			defer wg.Done()
			for p := range q {
				handler(p)
			}
		}(queues[i])
	}
	defer func() {
		for _, q := range queues {
			close(q)
		}
		wg.Wait()
	}()
	for {
		p, err := l.ReadPacket()
		if err != nil {
			return err
		}
		select {
		case queues[shard(p.Addr.(*net.UDPAddr), workers)] <- p:
		default:
		}
	}
}

func shard(a *net.UDPAddr, n int) int {
	// FNV-1a روی IP و پورت؛ سریع و بدون تخصیص.
	h := uint32(2166136261)
	for _, b := range a.IP {
		h = (h ^ uint32(b)) * 16777619
	}
	h = (h ^ uint32(a.Port&0xff)) * 16777619
	h = (h ^ uint32(a.Port>>8)) * 16777619
	return int(h % uint32(n))
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
