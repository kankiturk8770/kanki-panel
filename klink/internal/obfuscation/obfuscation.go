// Package obfuscation پروفایل‌های مخفی‌سازی KLINK:
//   - random: پدینگ تصادفی + شکل‌دهی اندازه‌ی بسته‌ها؛ ترافیک مثل نویز تصادفی است.
//   - tls-mimic: پوشش بسته‌ها داخل رکوردهای TLS 1.3 Application Data.
//
// اصل مهم: مخفی‌سازی جای رمزنگاری را نمی‌گیرد و هر بسته‌ی نامعتبر در لایه‌ی
// نشست بی‌صدا رها می‌شود (ضدپروب فعال؛ سرور هیچ پاسخی به اسکن نمی‌دهد).
package obfuscation

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrInvalid پوشش بسته معتبر نیست؛ صدا زدن = رها کردن بی‌صدا.
var ErrInvalid = errors.New("obfuscation: invalid wrapper")

// Profile لایه‌ی پوشش هر بسته قبل از رفتن روی سیم و بعد از دریافت.
type Profile interface {
	Name() string
	// Wrap بسته را می‌پوشاند؛ overhead ممکن است اضافه شود.
	Wrap(packet []byte) []byte
	// Unwrap پوشش را برمی‌دارد؛ خطا یعنی رها کردن بی‌صدا.
	Unwrap(packet []byte) ([]byte, error)
}

// ByName پروفایل را از رشته‌ی کانفیگ می‌سازد.
func ByName(name string) (Profile, error) {
	switch name {
	case "", "random":
		return Random{}, nil
	case "tls-mimic":
		return TLSMimic{}, nil
	default:
		return nil, fmt.Errorf("obfuscation: unknown profile %q", name)
	}
}

// ---------------------------------------------------------------- random

// Random فقط پدینگ تصادفی اضافه می‌کند. قالب بسته‌ی روی سیم:
//
//	packet || pad(0..63B تصادفی) || padLen(1B)
//
// طول کل بسته دیگر ارتباطی به طول محتوا ندارد و الگوی handshake/keepalive
// از نظر ناظر محو می‌شود.
type Random struct{}

func (Random) Name() string { return "random" }

func (Random) Wrap(packet []byte) []byte {
	padLen := 0
	if len(packet) < 1200 { // بسته‌های بزرگ پدینگ نمی‌گیرند تا MTU نشکند
		var b [1]byte
		_, _ = rand.Read(b[:])
		padLen = int(b[0]) % 64 // ۰ تا ۶۳ بایت
	}
	out := make([]byte, len(packet)+padLen+1)
	copy(out, packet)
	_, _ = rand.Read(out[len(packet) : len(packet)+padLen])
	out[len(out)-1] = byte(padLen)
	return out
}

func (Random) Unwrap(packet []byte) ([]byte, error) {
	n := len(packet)
	if n < 1 {
		return nil, ErrInvalid
	}
	padLen := int(packet[n-1])
	if padLen+1 > n {
		return nil, ErrInvalid
	}
	return packet[:n-1-padLen], nil
}

// ---------------------------------------------------------------- tls-mimic

// TLSMimic هر بسته را داخل یک رکورد TLS 1.3 Application Data می‌پیچد:
//
//	0x17 0x03 0x03 || length(2B) || packet
//
// برای DPI رکورد یک داده‌ی رمزشده‌ی TLS عادی به نظر می‌رسد. توجه: این پوشش
// فینگرپرینت handshake مرورگر را شبیه‌سازی نمی‌کند؛ handshake خود KLINK با
// همان الگوی Noise رمز است و برای تقلید کامل TLS باید ClientHello واقعی
// (تکنیک uTLS) اضافه شود که در نسخه‌ی بعدی می‌آید.
type TLSMimic struct{}

func (TLSMimic) Name() string { return "tls-mimic" }

func (TLSMimic) Wrap(packet []byte) []byte {
	// بسته‌های بزرگ به رکوردهای حداکثر ۱۶KB شکسته می‌شوند (مثل TLS واقعی).
	const maxRec = 16384
	var out []byte
	for len(packet) > 0 {
		n := len(packet)
		if n > maxRec {
			n = maxRec
		}
		hdr := []byte{0x17, 0x03, 0x03, byte(n >> 8), byte(n)}
		out = append(out, hdr...)
		out = append(out, packet[:n]...)
		packet = packet[n:]
	}
	return out
}

func (TLSMimic) Unwrap(packet []byte) ([]byte, error) {
	var out []byte
	for len(packet) > 0 {
		if len(packet) < 5 {
			return nil, ErrInvalid
		}
		if packet[0] != 0x17 || packet[1] != 0x03 || packet[2] != 0x03 {
			return nil, ErrInvalid
		}
		n := int(binary.BigEndian.Uint16(packet[3:5]))
		if n == 0 || n > 16384 || len(packet) < 5+n {
			return nil, ErrInvalid
		}
		out = append(out, packet[5:5+n]...)
		packet = packet[5+n:]
	}
	if out == nil {
		return nil, ErrInvalid
	}
	return out, nil
}
