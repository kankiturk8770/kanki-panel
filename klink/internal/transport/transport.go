// Package transport لایه‌ی انتقال انتزاعی KLINK: UDP و TCP با یک رابط واحد.
// بقیه‌ی پروتکل (نشست، mux، obfuscation) از نوع انتقال خبر ندارند و مهاجرت
// بین Wi-Fi/دیتا یا UDP/TCP فقط با به‌روزرسانی آدرس مقصد انجام می‌شود.
package transport

import (
	"errors"
	"net"
	"time"
)

// ErrClosed انتقال بسته شده است.
var ErrClosed = errors.New("transport: closed")

// Packet یک دیتاگرام منطقی: برای UDP همان بسته‌ی شبکه، برای TCP یک قاب کامل.
type Packet struct {
	Data []byte
	Addr net.Addr
}

// Listener رابط واحد انتقال. پیاده‌سازی‌ها: UDPListener و TCPListener.
type Listener interface {
	// ReadPacket تا رسیدن بسته‌ی بعدی مسدود می‌ماند.
	ReadPacket() (Packet, error)
	// WriteTo بسته را به آدرس مقصد می‌فرستد (در TCP، آدرس همان اتصال است).
	WriteTo(data []byte, addr net.Addr) error
	// LocalAddr آدرس گوش‌دادن محلی.
	LocalAddr() net.Addr
	// Close انتقال را می‌بندد.
	Close() error
}

// TCPConnAddr آدرس مجازی یک اتصال TCP؛ هر اتصال یک «آدرس» مجزا در لایه‌ی نشست است.
type TCPConnAddr struct {
	ID   uint64
	Conn net.Conn
}

func (a *TCPConnAddr) Network() string { return "klink-tcp" }
func (a *TCPConnAddr) String() string  { return a.Conn.RemoteAddr().String() }

// SetDeadline روی Packet/Conn در سطح listener مدیریت می‌شود؛ این ثابت‌ها
// تایم‌اوت‌های پیش‌فرض پروتکل‌اند.
const (
	// TCPReadTimeout برای خواندن قاب‌های TCP (keepalive نشست معمولاً زودتر می‌رسد).
	TCPReadTimeout = 5 * time.Minute
	// UDPReadTimeout برای خواندن از سوکت UDP.
	UDPReadTimeout = 1 * time.Minute
)
