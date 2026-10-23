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
}

// NewChannel یک کانال با کلید ۳۲بایتی می‌سازد.
func NewChannel(key [32]byte) (*Channel, error) {
	a, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	return &Channel{aead: a, key: key}, nil
}

func nonceFor(epoch, seq uint64) []byte {
	// nonce = epoch(4B) || seq(8B) — ۱۲ بایت یکتا برای هر بسته در هر epoch.
	n := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint32(n[:4], uint32(epoch))
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// Seal متن را رمز و امضا می‌کند و شماره‌ی توالی بسته را برمی‌گرداند.
// قالب خروجی: epoch(8B) || seq(8B) || ciphertext+tag
func (c *Channel) Seal(plaintext []byte) (out []byte, seq uint64, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	seq = c.seq
	out = make([]byte, 16, 16+len(plaintext)+chacha20poly1305.Overhead)
	binary.BigEndian.PutUint64(out[:8], c.epoch)
	binary.BigEndian.PutUint64(out[8:16], seq)
	out = c.aead.Seal(out, nonceFor(c.epoch, seq), plaintext, out[:16])
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
	// فقط epoch جاری یا epoch بعدی پذیرفته می‌شود. مهم است که پیش از احراز
	// AEAD هیچ کلید یا شمارنده‌ای تغییر نکند؛ وگرنه یک بسته‌ی جعلی می‌توانست
	// نشست را به epoch نامعتبر ببرد و denial-of-service ایجاد کند.
	if epoch != c.epoch && epoch != c.epoch+1 {
		return nil, 0, 0, ErrInvalid
	}
	aead := c.aead
	key := c.key
	if epoch == c.epoch+1 {
		key = RekeyKey(c.key, epoch)
		aead, err = chacha20poly1305.New(key[:])
		if err != nil {
			return nil, 0, 0, ErrInvalid
		}
	}
	pt, err := aead.Open(nil, nonceFor(epoch, seq), packet[16:], packet[:16])
	if err != nil {
		return nil, 0, 0, ErrInvalid
	}
	if epoch != c.epoch {
		c.epoch, c.key, c.aead = epoch, key, aead
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

// advance کلیدهای میانی را تا epoch موردنظر مشتق می‌کند (برای گیرنده).
func (c *Channel) advance(target uint64) error {
	for c.epoch < target {
		c.epoch++
		c.key = RekeyKey(c.key, c.epoch)
		a, err := chacha20poly1305.New(c.key[:])
		if err != nil {
			return err
		}
		c.aead = a
	}
	return nil
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
	w.mu.Lock()
	defer w.mu.Unlock()
	if seq == 0 {
		return ErrReplay
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
		return nil
	}
	diff := w.maxSeq - seq
	if diff >= windowSize {
		return ErrReplay
	}
	word := diff / 64
	bit := diff % 64
	mask := uint64(1) << bit
	if w.bitmap[word]&mask != 0 {
		return ErrReplay
	}
	w.bitmap[word] |= mask
	return nil
}
