// Package obfs لایه مخفی‌سازی پروتکل KANKI است.
// هر دیتاگرام UDP قبل از ارسال به این شکل در می‌آید:
//
//	[ 12B nonce تصادفی ][ AEAD( [1B نوع][2B طول واقعی][payload] + padding تصادفی ) ]
//
// نتیجه روی سیم کاملاً تصادفی به نظر می‌رسد: بدون magic number، بدون هدر ثابت،
// و با طول‌های متغیر. بسته‌هایی که رمزگشایی نمی‌شوند بی‌صدا drop می‌شوند
// (مقاوم در برابر active probing).
//
// «نوع» مشخص می‌کند بسته مال کیست: KindKCP برای تونل KCP (ترافیک TCP)، بقیه برای
// مسیر سریع دیتاگرام (ترافیک بازی و پینگ) که از KCP رد نمی‌شود.
package obfs

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KindKCP byte = 0x00 // بسته‌ی KCP
)

const (
	nonceSize = 12
	hdrSize   = 1 + 2 // نوع + طول
	overhead  = nonceSize + chacha20poly1305.Overhead + hdrSize
	maxPad    = 64
	// سقف اندازه‌ی payload UDP بیرونی؛ بالاتر از این روی خیلی از شبکه‌های موبایل
	// فرگمنت می‌شود و یک تکه‌ی گم‌شده یعنی کل بسته گم شده.
	// ۱۳۳۲ + UDP 8 + IPv6 40 = ۱۳۸۰ (روی IPv4 ۱۳۶۰): کل بسته حتی روی IPv6 زیر سقف امن پنل
	// (`mtu_budget`) می‌ماند. پدینگ تصادفی هم فقط تا همین سقف اضافه می‌شود. گیرنده هر اندازه‌ای
	// را می‌خواند، پس اپ و سرور قدیمی و تازه با هم کار می‌کنند.
	MaxWire    = 1332
	MaxPayload = MaxWire - overhead
)

// Handler بسته‌های غیر KCP را دریافت می‌کند. b فقط تا پایان فراخوانی معتبر است.
type Handler func(kind byte, b []byte, addr net.Addr)

// PacketConn یک net.PacketConn رمزنگاری‌شده با پدینگ تصادفی است.
// ReadFrom/WriteTo (برای KCP) فقط بسته‌های KindKCP را جابه‌جا می‌کنند.
type PacketConn struct {
	conn    net.PacketConn
	aead    cipher.AEAD
	ring    *Keyring // حالت چندکاربره (nil = یک کلید مشترک)
	handler Handler
	bufPool sync.Pool
}

// New یک PacketConn مبهم‌سازی‌شده با کلید ۳۲ بایتی می‌سازد.
// handler (می‌تواند nil باشد) بسته‌های غیر KCP را که در ReadFrom دیده می‌شوند می‌گیرد.
func New(conn net.PacketConn, psk []byte, handler Handler) (*PacketConn, error) {
	if len(psk) != chacha20poly1305.KeySize {
		return nil, errors.New("obfs: کلید باید دقیقاً ۳۲ بایت باشد")
	}
	a, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, err
	}
	c := &PacketConn{conn: conn, aead: a, handler: handler}
	c.bufPool.New = func() any { b := make([]byte, 65535); return &b }
	return c, nil
}

// NewMulti مثل New است ولی هر کاربر کلید خودش را دارد (سمت سرور).
func NewMulti(conn net.PacketConn, ring *Keyring, handler Handler) *PacketConn {
	c := &PacketConn{conn: conn, ring: ring, handler: handler}
	c.bufPool.New = func() any { b := make([]byte, 65535); return &b }
	return c
}

// Ring کلیدهای کاربران (nil در حالت تک‌کلیدی).
func (c *PacketConn) Ring() *Keyring { return c.ring }

// WritePacket یک بسته از نوع kind را رمز می‌کند و می‌فرستد.
func (c *PacketConn) WritePacket(kind byte, b []byte, addr net.Addr) error {
	if len(b) > MaxPayload {
		return fmt.Errorf("obfs: بسته بزرگ‌تر از %d بایت", MaxPayload)
	}
	aead := c.aead
	var ctr *counter
	if c.ring != nil {
		if aead, ctr = c.ring.sealer(addr); aead == nil {
			return errors.New("obfs: کاربر این آدرس شناخته نیست")
		}
	}
	// یک بار خواندن تصادفی: ۱۲ بایت nonce + ۱ بایت برای طول پدینگ
	var rnd [nonceSize + 1]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	padMax := MaxPayload - len(b)
	if padMax > maxPad {
		padMax = maxPad
	}
	padLen := int(rnd[nonceSize]) % (padMax + 1)

	out := make([]byte, nonceSize, nonceSize+hdrSize+len(b)+padLen+chacha20poly1305.Overhead)
	copy(out, rnd[:nonceSize])
	plain := out[nonceSize : nonceSize+hdrSize+len(b)+padLen]
	plain[0] = kind
	binary.BigEndian.PutUint16(plain[1:3], uint16(len(b)))
	copy(plain[hdrSize:], b)
	clear(plain[hdrSize+len(b):])
	out = aead.Seal(out[:nonceSize], out[:nonceSize], plain, nil)

	_, err := c.conn.WriteTo(out, addr)
	if err == nil && ctr != nil {
		ctr.tx.Add(int64(len(out)))
	}
	return err
}

// ReadPacket بسته‌ی بعدی (از هر نوعی) را در b می‌خواند.
func (c *PacketConn) ReadPacket(b []byte) (kind byte, n int, addr net.Addr, err error) {
	bp := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bp)
	buf := *bp
	for {
		m, a, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, 0, nil, err
		}
		k, p, ok := c.open(buf[:m], a)
		if !ok || len(p) > len(b) {
			continue
		}
		return k, copy(b, p), a, nil
	}
}

// open رمز بسته را باز می‌کند؛ ok=false یعنی بسته مال ما نیست.
// در حالت تک‌کلیدی درجا، در حالت چندکاربره در بافر جدا (چون ممکن است چند کلید امتحان شود).
func (c *PacketConn) open(pkt []byte, addr net.Addr) (byte, []byte, bool) {
	if len(pkt) < overhead {
		return 0, nil, false // بی‌صدا drop
	}
	var plain []byte
	if c.ring != nil {
		sp := scratchPool.Get().(*[]byte)
		defer scratchPool.Put(sp)
		_, p, ok := c.ring.open(pkt, addr, *sp)
		if !ok {
			return 0, nil, false
		}
		// به جای متن رمز در pkt کپی شود تا بعد از برگشت scratch به pool معتبر بماند
		plain = pkt[:copy(pkt, p)]
	} else {
		nonce, ct := pkt[:nonceSize], pkt[nonceSize:]
		var err error
		if plain, err = c.aead.Open(ct[:0], nonce, ct, nil); err != nil {
			return 0, nil, false // رمزگشایی نشد → بسته متعلق به ما نیست، drop
		}
	}
	if len(plain) < hdrSize {
		return 0, nil, false
	}
	realLen := int(binary.BigEndian.Uint16(plain[1:3]))
	if realLen > len(plain)-hdrSize {
		return 0, nil, false
	}
	return plain[0], plain[hdrSize : hdrSize+realLen], true
}

// ---- رابط net.PacketConn برای KCP ----

func (c *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := c.WritePacket(KindKCP, b, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	bp := c.bufPool.Get().(*[]byte)
	defer c.bufPool.Put(bp)
	buf := *bp
	for {
		m, addr, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		kind, p, ok := c.open(buf[:m], addr)
		if !ok {
			continue
		}
		if kind != KindKCP {
			if c.handler != nil {
				c.handler(kind, p, addr)
			}
			continue
		}
		if len(p) > len(b) {
			continue
		}
		return copy(b, p), addr, nil
	}
}

func (c *PacketConn) Close() error                       { return c.conn.Close() }
func (c *PacketConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *PacketConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *PacketConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
