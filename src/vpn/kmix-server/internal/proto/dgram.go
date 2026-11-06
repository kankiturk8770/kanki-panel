package proto

// مسیر سریع دیتاگرام (پروتکل ۲): ترافیک UDP بازی مستقیم داخل بسته‌های obfs می‌رود و از
// KCP رد نمی‌شود. بسته‌ی گم‌شده دوباره فرستاده نمی‌شود (درست مثل UDP خود بازی)، پس یک
// بسته‌ی گم‌شده هیچ‌وقت بسته‌های بعدی را معطل نمی‌کند (head-of-line blocking نداریم).
//
// قالب‌ها (همه big-endian، داخل لایه‌ی obfs که رمز و احراز هویت را انجام می‌دهد):
//
//	KindUDPUp   کلاینت→سرور: [8B نشست][4B جریان][4B شماره][1B پرچم][IPv4 4B][پورت 2B][payload]
//	KindUDPDown سرور→کلاینت: [4B جریان][4B شماره][payload]
//	KindPing    کلاینت→سرور: [8B نشست][8B زمان ارسال] — سرور همان را با KindPong برمی‌گرداند

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	KindUDPUp   byte = 0x01
	KindUDPDown byte = 0x02
	KindPing    byte = 0x03
	KindPong    byte = 0x04

	// FlagDup: هر بسته دو بار فرستاده می‌شود (حالت گیمینگ)؛ سرور هم پاسخ‌ها را دوتایی می‌فرستد
	FlagDup byte = 0x01

	UpHdrLen   = 8 + 4 + 4 + 1 + 4 + 2
	DownHdrLen = 4 + 4
	PingLen    = 8 + 8
)

// UDPUp هدر بسته‌ی بالارو.
type UDPUp struct {
	Session uint64
	Flow    uint32
	Seq     uint32
	Flags   byte
	DstIP   [4]byte
	DstPort uint16
}

func AppendUDPUp(dst []byte, h *UDPUp, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, h.Session)
	dst = binary.BigEndian.AppendUint32(dst, h.Flow)
	dst = binary.BigEndian.AppendUint32(dst, h.Seq)
	dst = append(dst, h.Flags)
	dst = append(dst, h.DstIP[:]...)
	dst = binary.BigEndian.AppendUint16(dst, h.DstPort)
	return append(dst, payload...)
}

func ParseUDPUp(b []byte) (UDPUp, []byte, error) {
	var h UDPUp
	if len(b) < UpHdrLen {
		return h, nil, errors.New("بسته‌ی کوتاه")
	}
	h.Session = binary.BigEndian.Uint64(b[0:8])
	h.Flow = binary.BigEndian.Uint32(b[8:12])
	h.Seq = binary.BigEndian.Uint32(b[12:16])
	h.Flags = b[16]
	copy(h.DstIP[:], b[17:21])
	h.DstPort = binary.BigEndian.Uint16(b[21:23])
	return h, b[UpHdrLen:], nil
}

func (h *UDPUp) Target() *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(h.DstIP[0], h.DstIP[1], h.DstIP[2], h.DstIP[3]), Port: int(h.DstPort)}
}

func AppendUDPDown(dst []byte, flow, seq uint32, payload []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, flow)
	dst = binary.BigEndian.AppendUint32(dst, seq)
	return append(dst, payload...)
}

func ParseUDPDown(b []byte) (flow, seq uint32, payload []byte, err error) {
	if len(b) < DownHdrLen {
		return 0, 0, nil, errors.New("بسته‌ی کوتاه")
	}
	return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint32(b[4:8]), b[DownHdrLen:], nil
}

// Window تکراری‌ها را حذف می‌کند (۶۴ شماره‌ی آخر را به خاطر می‌سپارد).
// بسته‌های جابه‌جا رسیده رد نمی‌شوند، فقط تکراری‌ها و خیلی قدیمی‌ها.
type Window struct {
	max  uint32
	bits uint64
	init bool
}

// Accept true برمی‌گرداند اگر seq تازه باشد.
func (w *Window) Accept(seq uint32) bool {
	if !w.init {
		w.init, w.max, w.bits = true, seq, 1
		return true
	}
	d := int32(seq - w.max) // با سرریز شماره هم درست کار می‌کند
	switch {
	case d > 0:
		if d >= 64 {
			w.bits = 1
		} else {
			w.bits = w.bits<<uint(d) | 1
		}
		w.max = seq
		return true
	case d > -64:
		bit := uint64(1) << uint(-d)
		if w.bits&bit != 0 {
			return false
		}
		w.bits |= bit
		return true
	default:
		return false
	}
}
