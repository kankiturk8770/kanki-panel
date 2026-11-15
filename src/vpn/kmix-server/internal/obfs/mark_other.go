//go:build !linux

package obfs

import "net"

const GameTOS = 0xb8

func writeMarked(conn net.PacketConn, b []byte, addr net.Addr) bool { return false }
