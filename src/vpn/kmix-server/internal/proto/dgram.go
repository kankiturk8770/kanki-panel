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
//
// حالت بازی هوشمند (3.59 / اپ ۱.۴۳): فقط بین دو طرفی که هر دو KindStat فرستاده‌اند؛ طرف قدیمی هیچ‌کدام از این‌ها را
// نه می‌فرستد و نه می‌گیرد، پس همه‌چیز با او مثل قبل است:
//
//	KindStat       هر دو طرف: [8B نشست][1B نسخه][1B توانایی][2B افت رسیده‌ها ‰][1B طولانی‌ترین افت پشت هم][1B پله][2B تعداد بسته‌هایی که شمرده شد]
//	               (افت خام خط روی بسته‌های بازی این طرف، قبل از نسخه‌ی دوم و ترمیم)
//	KindRepair     کلاینت→سرور: [8B نشست][4B جریان][ترمیم RLC] — سرور→کلاینت: [4B جریان][ترمیم RLC] (internal/game/rlc.go)
//	KindUDPDownCopy سرور→کلاینت: مثل KindUDPDown، نسخه‌ی دوم دیرتر (برای اینکه افت خام خط را بشود شمرد)
//	FlagCopy (بالارو) این بسته نسخه‌ی دوم است؛ FlagGame (بالارو) کلاینت این جریان را بازی می‌داند

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

	// 0x05 مال obfs.KindKCPPlain است
	KindRepair      byte = 0x06
	KindStat        byte = 0x07
	KindUDPDownCopy byte = 0x08

	// FlagDup: هر بسته دو بار فرستاده می‌شود (حالت گیمینگ)؛ سرور هم پاسخ‌ها را دوتایی می‌فرستد
	FlagDup byte = 0x01
	// FlagCopy: نسخه‌ی دوم یک بسته (در شمارش افت خط حساب نمی‌شود)
	FlagCopy byte = 0x02
	// FlagGame: کلاینت این جریان را بازی می‌داند (سرور پایین‌روی آن را محافظت می‌کند)
	FlagGame byte = 0x04

	// StatVersion و توانایی‌های KindStat
	StatVersion byte = 1
	CapRepair   byte = 0x01 // ترمیم RLC می‌فهمد
	CapCopy     byte = 0x02 // KindUDPDownCopy می‌فهمد
	StatLen          = 8 + 1 + 1 + 2 + 1 + 1 + 2

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

// Stat گزارش یک طرف از خطی که بسته‌های بازی از آن به او می‌رسند
type Stat struct {
	Session uint64
	Version byte
	Caps    byte
	Loss    uint16 // ‰
	Burst   byte
	Step    byte
	Count   uint16 // بسته‌هایی که این عدد از آن‌هاست
}

func AppendStat(dst []byte, s *Stat) []byte {
	dst = binary.BigEndian.AppendUint64(dst, s.Session)
	dst = append(dst, s.Version, s.Caps)
	dst = binary.BigEndian.AppendUint16(dst, s.Loss)
	dst = append(dst, s.Burst, s.Step)
	return binary.BigEndian.AppendUint16(dst, s.Count)
}

// ParseStat طول بیشتر را قبول می‌کند (نسخه‌های بعدی چیز اضافه می‌گذارند)
func ParseStat(b []byte) (Stat, error) {
	var s Stat
	if len(b) < StatLen {
		return s, errors.New("بسته‌ی کوتاه")
	}
	s.Session = binary.BigEndian.Uint64(b[0:8])
	s.Version, s.Caps = b[8], b[9]
	s.Loss = binary.BigEndian.Uint16(b[10:12])
	s.Burst, s.Step = b[12], b[13]
	s.Count = binary.BigEndian.Uint16(b[14:16])
	if s.Loss > 1000 {
		s.Loss = 1000
	}
	return s, nil
}

// RepairUpHdr / RepairDownHdr سرآیند KindRepair پیش از خود ترمیم
const (
	RepairUpHdr   = 8 + 4
	RepairDownHdr = 4
)

func AppendRepairUp(dst []byte, session uint64, flow uint32, rep []byte) []byte {
	dst = binary.BigEndian.AppendUint64(dst, session)
	dst = binary.BigEndian.AppendUint32(dst, flow)
	return append(dst, rep...)
}

func ParseRepairUp(b []byte) (session uint64, flow uint32, rep []byte, err error) {
	if len(b) <= RepairUpHdr {
		return 0, 0, nil, errors.New("بسته‌ی کوتاه")
	}
	return binary.BigEndian.Uint64(b[0:8]), binary.BigEndian.Uint32(b[8:12]), b[RepairUpHdr:], nil
}

func AppendRepairDown(dst []byte, flow uint32, rep []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, flow)
	return append(dst, rep...)
}

func ParseRepairDown(b []byte) (flow uint32, rep []byte, err error) {
	if len(b) <= RepairDownHdr {
		return 0, nil, errors.New("بسته‌ی کوتاه")
	}
	return binary.BigEndian.Uint32(b[0:4]), b[RepairDownHdr:], nil
}
