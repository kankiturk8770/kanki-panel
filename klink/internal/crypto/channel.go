package crypto

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// ErrReplay بسته‌ی تکراری یا خیلی قدیمی است؛ سرور آن را بی‌صدا رها می‌کند.
var ErrReplay = errors.New("crypto: replay detected")

// ErrInvalid بسته خراب، دست‌کاری‌شده یا با کلید اشتباه است.
var ErrInvalid = errors.New("crypto: invalid packet")

// Channel رمزنگاری یک جهت نشست با شمارنده‌ی ۶۴بیتی و Rekey مبتنی بر epoch.
type Channel struct {
	mu    sync.Mutex
	aead  cipher.AEAD
	key   [32]byte
	epoch uint64
	seq   uint64 // آخرین شماره‌ی استفاده‌شده برای ارسال

	// next کلید epoch بعدی را کش می‌کند تا هر بسته‌ی جعلیِ حامل epoch+1 دوباره
	// HKDF و ساخت AEAD را اجرا نکند (هزینه‌ی CPU برای مهاجم بدون احراز).
	next    cipher.AEAD
	nextKey [32]byte
	// prev کلید epoch قبلی را نگه می‌دارد تا بسته‌های UDP که پیش از rekey
	// فرستاده شده‌اند ولی دیرتر رسیده‌اند دور ریخته نشوند. replay آن‌ها با پنجره‌ی
	// جداگانه‌ی همان epoch در لایه‌ی نشست کنترل می‌شود.
	prev    cipher.AEAD
	hasPrev bool
}

// NewChannel یک کانال با کلید ۳۲بایتی می‌سازد.
func NewChannel(key [32]byte) (*Channel, error) {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Channel{aead: a, key: key}, nil
}

func nonceFor(n *[chacha20poly1305.NonceSize]byte, epoch, seq uint64) []byte {
	// nonce = epoch(4B) || seq(8B) — ۱۲ بایت یکتا برای هر بسته در هر epoch.
	binary.BigEndian.PutUint32(n[:4], uint32(epoch))
	binary.BigEndian.PutUint64(n[4:], seq)
	return n[:]
}

// Seal متن را رمز و امضا می‌کند و شماره‌ی توالی بسته را برمی‌گرداند.
// قالب خروجی: epoch(8B) || seq(8B) || ciphertext+tag
func (c *Channel) Seal(plaintext []byte) (out []byte, seq uint64, err error) {
	return c.SealTo(nil, plaintext)
}

// SealTo مثل Seal است ولی خروجی را به انتهای dst اضافه می‌کند تا فرستنده بتواند
// هدر بسته را از قبل در همان بافر بگذارد و کپی اضافه لازم نباشد.
func (c *Channel) SealTo(dst, plaintext []byte) (out []byte, seq uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seq == ^uint64(0) {
		return nil, 0, errors.New("crypto: sequence exhausted; rekey required")
	}
	c.seq++
	seq = c.seq
	need := 16 + len(plaintext) + chacha20poly1305.Overhead
	if cap(dst)-len(dst) < need {
		grown := make([]byte, len(dst), len(dst)+need)
		copy(grown, dst)
		dst = grown
	}
	base := len(dst)
	out = dst[:base+16]
	binary.BigEndian.PutUint64(out[base:base+8], c.epoch)
	binary.BigEndian.PutUint64(out[base+8:base+16], seq)
	var n [chacha20poly1305.NonceSize]byte
	out = c.aead.Seal(out, nonceFor(&n, c.epoch, seq), plaintext, out[base:base+16])
	return out, seq, nil
}

// Open بسته را بررسی و باز می‌کند؛ هر خطا فقط «نامعتبر» است تا اوراکل نسازیم.
func (c *Channel) Open(packet []byte) (plaintext []byte, seq uint64, epoch uint64, err error) {
	if len(packet) < 16+chacha20poly1305.Overhead {
		return nil, 0, 0, ErrInvalid
	}
	epoch = binary.BigEndian.Uint64(packet[:8])
	seq = binary.BigEndian.Uint64(packet[8:16])
	c.mu.Lock()
	defer c.mu.Unlock()
	// فقط epoch قبلی، جاری یا بعدی پذیرفته می‌شود. مهم است که پیش از احراز
	// AEAD هیچ کلید یا شمارنده‌ای تغییر نکند؛ وگرنه یک بسته‌ی جعلی می‌توانست
	// نشست را به epoch نامعتبر ببرد و denial-of-service ایجاد کند.
	var aead cipher.AEAD
	switch {
	case epoch == c.epoch:
		aead = c.aead
	case epoch == c.epoch+1:
		if c.next == nil {
			c.nextKey = RekeyKey(c.key, epoch)
			c.next, err = chacha20poly1305.New(c.nextKey[:])
			if err != nil {
				c.next = nil
				return nil, 0, 0, ErrInvalid
			}
		}
		aead = c.next
	case c.hasPrev && c.epoch > 0 && epoch == c.epoch-1:
		aead = c.prev
	default:
		return nil, 0, 0, ErrInvalid
	}
	var n [chacha20poly1305.NonceSize]byte
	pt, err := aead.Open(nil, nonceFor(&n, epoch, seq), packet[16:], packet[:16])
	if err != nil {
		return nil, 0, 0, ErrInvalid
	}
	if epoch == c.epoch+1 {
		c.prev, c.hasPrev = c.aead, true
		c.epoch, c.key, c.aead = epoch, c.nextKey, c.next
		c.next, c.nextKey = nil, [32]byte{}
	}
	return pt, seq, epoch, nil
}

// Rekey برای فرستنده: رفتن به epoch بعدی و صفرکردن شمارنده.
func (c *Channel) Rekey() (epoch uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch++
	c.key = RekeyKey(c.key, c.epoch)
	a, err := chacha20poly1305.New(c.key[:])
	if err == nil {
		c.aead = a
	}
	c.seq = 0
	return c.epoch
}

// ReplayWindow پنجره‌ی لغزان ۶۴بیتی برای تشخیص بسته‌های تکراری (اندازه: ۱۰۲۴ بسته).
type ReplayWindow struct {
	mu     sync.Mutex
	maxSeq uint64
	bitmap [16]uint64 // 1024 بیت
}

const windowSize = 1024

// Reset پنجره را برای epoch جدید بازنشانی می‌کند؛ توالی فرستنده در هر rekey
// از یک شروع می‌شود و نباید با توالی epoch قبلی مقایسه شود.
func (w *ReplayWindow) Reset() {
	w.mu.Lock()
	w.maxSeq = 0
	w.bitmap = [16]uint64{}
	w.mu.Unlock()
}

// Check بسته را ثبت می‌کند؛ اگر تکراری یا خارج از پنجره باشد ErrReplay می‌دهد.
func (w *ReplayWindow) Check(seq uint64) error {
	_, err := w.CheckNewest(seq)
	return err
}

// CheckNewest مثل Check است و علاوه بر آن می‌گوید آیا این بسته جلوترین توالیِ
// دیده‌شده است. لایه‌ی نشست فقط با چنین بسته‌ای مسیر را مهاجرت می‌دهد تا یک
// بسته‌ی قدیمیِ دیررسیده از مسیر قبلی، مسیر جدید را برنگرداند.
func (w *ReplayWindow) CheckNewest(seq uint64) (newest bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq == 0 {
		return false, ErrReplay
	}
	if seq > w.maxSeq {
		shift := seq - w.maxSeq
		if shift >= windowSize {
			w.bitmap = [16]uint64{}
			w.bitmap[0] = 1
		} else {
			// شیفت کل بیت‌مپ به سمت بیت‌های پرارزش‌تر.
			words := shift / 64
			bits := shift % 64
			var next [16]uint64
			for i := 15; i >= 0; i-- {
				src := i - int(words)
				if src < 0 {
					continue
				}
				next[i] |= w.bitmap[src] << bits
				if bits > 0 && src > 0 {
					next[i] |= w.bitmap[src-1] >> (64 - bits)
				}
			}
			w.bitmap = next
			w.bitmap[0] |= 1
		}
		w.maxSeq = seq
		return true, nil
	}
	diff := w.maxSeq - seq
	if diff >= windowSize {
		return false, ErrReplay
	}
	word := diff / 64
	bit := diff % 64
	mask := uint64(1) << bit
	if w.bitmap[word]&mask != 0 {
		return false, ErrReplay
	}
	w.bitmap[word] |= mask
	return false, nil
}
