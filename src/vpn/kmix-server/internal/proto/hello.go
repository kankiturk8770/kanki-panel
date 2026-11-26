package proto

// Hello (protocol 3, panel 3.67): a client says what it can do and gets a routing hint (obfs/hints.go).
// Both messages travel inside the obfs layer like every other kind, so they are encrypted and authenticated
// with the user's key; the hint is never on the wire in the clear before it is used. A server from before
// does not know these kinds and drops them without an answer: the client then simply goes on without hints,
// exactly as before. An old client never sends a hello and never gets one.
//
//	KindHello    client -> server: [8B session][1B version][1B caps][8B send time (UnixNano)]
//	KindHelloAck server -> client: [8B session][1B version][1B caps taken][8B the same send time][8B hint][2B hint life, s]
//
// The client says hello when it starts, every HelloEvery while connected (a new hint each time: the hints
// rotate) and at once when its network changes; until the answer comes it sends without a hint.

import (
	"encoding/binary"
	"errors"
	"time"
)

const (
	KindHello    byte = 0x09
	KindHelloAck byte = 0x0A

	HelloVersion byte = 1
	// HelloCapHint: the client puts the hint in front of its packets
	HelloCapHint byte = 0x01
	// HelloCapGaming: gaming mode; every UDP flow of the session except DNS is a game from its first packet
	HelloCapGaming byte = 0x02

	HelloLen    = 8 + 1 + 1 + 8
	HelloAckLen = 8 + 1 + 1 + 8 + 8 + 2

	// HelloEvery how often a connected client asks for a new hint
	HelloEvery = 60 * time.Second
	// HelloMaxSkew a hello sent longer ago (or ahead) than this is refused (a replayed hello gets no hint)
	HelloMaxSkew = 2 * time.Minute
)

type Hello struct {
	Session uint64
	Version byte
	Caps    byte
	SentAt  int64
}

func AppendHello(dst []byte, h *Hello) []byte {
	dst = binary.BigEndian.AppendUint64(dst, h.Session)
	dst = append(dst, h.Version, h.Caps)
	return binary.BigEndian.AppendUint64(dst, uint64(h.SentAt))
}

// ParseHello takes a longer hello too (later versions may add to it)
func ParseHello(b []byte) (Hello, error) {
	var h Hello
	if len(b) < HelloLen {
		return h, errors.New("بسته‌ی کوتاه")
	}
	h.Session = binary.BigEndian.Uint64(b[0:8])
	h.Version, h.Caps = b[8], b[9]
	h.SentAt = int64(binary.BigEndian.Uint64(b[10:18]))
	return h, nil
}

// Fresh the hello was sent within HelloMaxSkew of now
func (h *Hello) Fresh(now time.Time) bool {
	d := now.Sub(time.Unix(0, h.SentAt))
	return d < HelloMaxSkew && d > -HelloMaxSkew
}

type HelloAck struct {
	Session uint64
	Version byte
	Caps    byte
	SentAt  int64
	Hint    [8]byte
	LifeSec uint16
}

func AppendHelloAck(dst []byte, a *HelloAck) []byte {
	dst = binary.BigEndian.AppendUint64(dst, a.Session)
	dst = append(dst, a.Version, a.Caps)
	dst = binary.BigEndian.AppendUint64(dst, uint64(a.SentAt))
	dst = append(dst, a.Hint[:]...)
	return binary.BigEndian.AppendUint16(dst, a.LifeSec)
}

func ParseHelloAck(b []byte) (HelloAck, error) {
	var a HelloAck
	if len(b) < HelloAckLen {
		return a, errors.New("بسته‌ی کوتاه")
	}
	a.Session = binary.BigEndian.Uint64(b[0:8])
	a.Version, a.Caps = b[8], b[9]
	a.SentAt = int64(binary.BigEndian.Uint64(b[10:18]))
	copy(a.Hint[:], b[18:26])
	a.LifeSec = binary.BigEndian.Uint16(b[26:28])
	return a, nil
}
