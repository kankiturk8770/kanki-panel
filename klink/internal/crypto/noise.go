package crypto

import (
	"errors"
	"fmt"
	"hash"

	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/hkdf"
)

// Suite مجموعه‌ی رمزنگاری KLINK: X25519 + ChaCha20-Poly1305 + BLAKE2s.
func Suite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
}

// Prologue نسخه‌ی پروتکل را به handshake می‌بندد تا نسخه‌های ناسازگار به هم وصل نشوند.
var Prologue = []byte("KLINK/1")

// HandshakeState یک handshake در حال انجام را نگه می‌دارد.
type HandshakeState struct {
	hs *noise.HandshakeState
}

// NewInitiator سمت کلاینت: کلید عمومی سرور را از قبل دارد (الگوی XK).
func NewInitiator(client KeyPair, serverPublic [32]byte) (*HandshakeState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   Suite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     true,
		StaticKeypair: noise.DHKey{Private: client.Private[:], Public: client.Public[:]},
		PeerStatic:    serverPublic[:],
		Prologue:      Prologue,
	})
	if err != nil {
		return nil, err
	}
	return &HandshakeState{hs: hs}, nil
}

// NewResponder سمت سرور: کلید استاتیک کلاینت هنوز ناشناخته است و در پیام سوم احراز می‌شود.
func NewResponder(server KeyPair) (*HandshakeState, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   Suite(),
		Pattern:       noise.HandshakeXK,
		Initiator:     false,
		StaticKeypair: noise.DHKey{Private: server.Private[:], Public: server.Public[:]},
		Prologue:      Prologue,
	})
	if err != nil {
		return nil, err
	}
	return &HandshakeState{hs: hs}, nil
}

// keyMaterial کلیدهای محرمانه‌ی Split را صادر می‌کند. ChannelBinding در Noise
// یک handshake hash عمومی است و به‌تنهایی هرگز برای ساخت کلید استفاده نمی‌شود.
func keyMaterial(cs1, cs2 *noise.CipherState) []byte {
	k1, k2 := cs1.UnsafeKey(), cs2.UnsafeKey()
	material := make([]byte, 64)
	copy(material[:32], k1[:])
	copy(material[32:], k2[:])
	return material
}

// WriteMessage پیام handshake بعدی را می‌سازد. خروجی دوم فقط بعد از آخرین
// پیام، ۶۴ بایت مواد کلید محرمانه‌ی دو CipherState است.
func (h *HandshakeState) WriteMessage(payload []byte) (out []byte, secret []byte, finished bool, err error) {
	out, cs1, cs2, err := h.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, nil, false, err
	}
	if cs1 != nil && cs2 != nil {
		return out, keyMaterial(cs1, cs2), true, nil
	}
	return out, nil, false, nil
}

// ReadMessage پیام handshake طرف مقابل را می‌خواند؛ خروجی دوم نیز مواد کلید
// محرمانه‌ی Split است، نه ChannelBinding عمومی.
func (h *HandshakeState) ReadMessage(msg []byte) (payload []byte, secret []byte, finished bool, err error) {
	payload, cs1, cs2, err := h.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, nil, false, err
	}
	if cs1 != nil && cs2 != nil {
		return payload, keyMaterial(cs1, cs2), true, nil
	}
	return payload, nil, false, nil
}

// PeerStatic کلید استاتیک طرف مقابل را برمی‌گرداند (برای سرور: شناسایی کاربر بعد از پیام سوم).
func (h *HandshakeState) PeerStatic() []byte { return h.hs.PeerStatic() }

func blake2sHash() func() hash.Hash {
	return func() hash.Hash {
		h, _ := blake2s.New256(nil)
		return h
	}
}

// ChannelKeys از ۶۴ بایت کلید محرمانه‌ی Noise Split دو کلید مستقل برای دو جهت
// می‌سازد. k1 کلاینت→سرور و k2 سرور→کلاینت است.
func ChannelKeys(secret []byte) (k1, k2 [32]byte, err error) {
	if len(secret) != 64 {
		return k1, k2, errors.New("crypto: invalid Noise key material")
	}
	r := hkdf.New(blake2sHash(), secret, nil, []byte("klink/v1 channel keys"))
	if _, err = r.Read(k1[:]); err != nil {
		return
	}
	_, err = r.Read(k2[:])
	return
}

// RekeyKey کلید جدید epoch را از کلید قبلی مشتق می‌کند؛ هر دو طرف مستقل و هماهنگ
// (بر اساس شماره‌ی epoch) به همان کلید می‌رسند و Rekey بدون قطعی انجام می‌شود.
func RekeyKey(previous [32]byte, epoch uint64) (next [32]byte) {
	info := []byte(fmt.Sprintf("klink/v1 rekey epoch=%d", epoch))
	r := hkdf.New(blake2sHash(), previous[:], nil, info)
	_, _ = r.Read(next[:])
	return
}
