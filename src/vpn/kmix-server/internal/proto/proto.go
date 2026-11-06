// Package proto پیام‌های لایه کاربرد KANKI: احراز هویت و فریمینگ آدرس.
package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	CmdAuth = 0x00 // اولین پیام روی اولین استریم
	CmdTCP  = 0x01 // اتصال TCP (از SOCKS5 CONNECT)
	CmdUDP  = 0x02 // رله دیتاگرام UDP (ترافیک گیم)

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	authSkew = 30 * time.Second
)

// ---- احراز هویت: HMAC(timestamp) — ضد replay و ضد پروب ----

func AuthToken(psk []byte) []byte {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))
	mac := hmac.New(sha256.New, psk)
	mac.Write(ts)
	return append(ts, mac.Sum(nil)...) // 40 بایت
}

func VerifyAuth(psk, token []byte) error {
	if len(token) != 40 {
		return errors.New("توکن نامعتبر")
	}
	ts := int64(binary.BigEndian.Uint64(token[:8]))
	if d := time.Since(time.Unix(ts, 0)); d > authSkew || d < -authSkew {
		return errors.New("انحراف زمانی بیش از حد")
	}
	mac := hmac.New(sha256.New, psk)
	mac.Write(token[:8])
	if !hmac.Equal(mac.Sum(nil), token[8:]) {
		return errors.New("امضا نامعتبر")
	}
	return nil
}

// ---- فریمینگ آدرس (سازگار با قالب SOCKS5) ----

// WriteAddr آدرس host:port را در w می‌نویسد.
func WriteAddr(w io.Writer, host string, port uint16) error {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			if _, err := w.Write([]byte{atypIPv4}); err != nil {
				return err
			}
			if _, err := w.Write(v4); err != nil {
				return err
			}
		} else {
			if _, err := w.Write([]byte{atypIPv6}); err != nil {
				return err
			}
			if _, err := w.Write(ip.To16()); err != nil {
				return err
			}
		}
	} else {
		if len(host) > 255 {
			return errors.New("دامنه طولانی")
		}
		if _, err := w.Write([]byte{atypDomain, byte(len(host))}); err != nil {
			return err
		}
		if _, err := w.Write([]byte(host)); err != nil {
			return err
		}
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], port)
	_, err := w.Write(p[:])
	return err
}

// ReadAddr آدرس را از r می‌خواند و host,port برمی‌گرداند.
func ReadAddr(r io.Reader) (string, uint16, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", 0, err
	}
	var host string
	switch t[0] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = net.IP(b).String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, b); err != nil {
			return "", 0, err
		}
		host = string(b)
	default:
		return "", 0, fmt.Errorf("نوع آدرس ناشناخته: %d", t[0])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(p[:]), nil
}

// WriteUDPGram یک دیتاگرام UDP را با فریم [addr][2B len][payload] می‌نویسد.
func WriteUDPGram(w io.Writer, host string, port uint16, payload []byte) error {
	if err := WriteAddr(w, host, port); err != nil {
		return err
	}
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(payload)))
	if _, err := w.Write(l[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadUDPGram یک دیتاگرام فریم‌شده را می‌خواند.
func ReadUDPGram(r io.Reader, buf []byte) (string, uint16, int, error) {
	host, port, err := ReadAddr(r)
	if err != nil {
		return "", 0, 0, err
	}
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return "", 0, 0, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n > len(buf) {
		return "", 0, 0, errors.New("دیتاگرام بزرگ")
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return "", 0, 0, err
	}
	return host, port, n, nil
}

func JoinAddr(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
