// Package crypto لایه‌ی رمزنگاری KLINK: کلیدهای X25519، handshake با الگوی Noise_XK،
// کانال رمزنگاری‌شده با ChaCha20-Poly1305، KDF با BLAKE2s و پنجره‌ی ضد replay.
// رمزنگاری اختراعی نداریم؛ همه‌ی اجزا استاندارد و از کتابخانه‌های اثبات‌شده‌اند.
package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyPair جفت‌کلید X25519 برای سرور یا کاربر.
type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

// GenerateKey یک جفت‌کلید X25519 تازه می‌سازد.
func GenerateKey() (KeyPair, error) {
	var kp KeyPair
	if _, err := rand.Read(kp.Private[:]); err != nil {
		return kp, fmt.Errorf("crypto: rand: %w", err)
	}
	// بیت‌های مربوط به clamping در خود X25519 اعمال می‌شود.
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return kp, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// KeyFromBase64 کلید خصوصی را از رشته‌ی base64 می‌خواند و کلید عمومی را بازسازی می‌کند.
func KeyFromBase64(s string) (KeyPair, error) {
	var kp KeyPair
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return kp, errors.New("crypto: invalid private key")
	}
	copy(kp.Private[:], raw)
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return kp, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

// PublicFromBase64 فقط کلید عمومی را می‌خواند (برای ثبت کلید سرور روی کلاینت).
func PublicFromBase64(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != 32 {
		return out, errors.New("crypto: invalid public key")
	}
	copy(out[:], raw)
	return out, nil
}

func (k KeyPair) PrivateBase64() string { return base64.StdEncoding.EncodeToString(k.Private[:]) }
func (k KeyPair) PublicBase64() string  { return base64.StdEncoding.EncodeToString(k.Public[:]) }
