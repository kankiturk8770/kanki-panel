package obfs

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"unsafe"
)

// GameTOS: DSCP EF, the mark a game packet leaves the server with. A Game-FEC Pro tunnel on the same server
// reads it and gives only these packets FEC; KCP (the app's TCP) goes without the mark.
const GameTOS = 0xb8

// markOOB: IP_TOS and IPV6_TCLASS for one packet; the kernel uses the one of the packet's family and
// skips the other
var markOOB = func() []byte {
	one := func(level, typ int32) []byte {
		b := make([]byte, syscall.CmsgSpace(4))
		h := (*syscall.Cmsghdr)(unsafe.Pointer(&b[0]))
		h.Level, h.Type = level, typ
		h.SetLen(syscall.CmsgLen(4))
		*(*int32)(unsafe.Pointer(&b[syscall.CmsgLen(0)])) = GameTOS
		return b
	}
	return append(one(syscall.IPPROTO_IP, syscall.IP_TOS), one(syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS)...)
}()

// markBroken: the kernel refused the mark once; from then on packets go plain
var markBroken atomic.Bool

// writeMarked sends one packet with the game mark; false = not sent this way (the caller sends it plain)
func writeMarked(conn net.PacketConn, b []byte, addr net.Addr) bool {
	uc, ok := conn.(*net.UDPConn)
	ua, ok2 := addr.(*net.UDPAddr)
	if !ok || !ok2 || markBroken.Load() {
		return false
	}
	if _, _, err := uc.WriteMsgUDP(b, markOOB, ua); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EPERM) {
			markBroken.Store(true)
		}
		return false
	}
	return true
}
