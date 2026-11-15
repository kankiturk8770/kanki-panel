//go:build linux

package obfs

import (
	"net"
	"syscall"
	"testing"
	"unsafe"
)

// Game packets leave with the EF mark, KCP packets without; the receiver reads it per packet
func TestGamePacketsAreMarked(t *testing.T) {
	rc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	raw, _ := rc.SyscallConn()
	raw.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_RECVTOS, 1) })
	sc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer sc.Close()
	c, err := New(sc, make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	c.MarkGame = true
	to := rc.LocalAddr()
	c.WritePacket(0x02, []byte("game"), to)
	c.WritePacket(KindKCP, []byte("kcp"), to)
	want := []int{GameTOS, 0}
	for i := 0; i < 2; i++ {
		b, oob := make([]byte, 2048), make([]byte, 128)
		_, on, _, _, err := rc.ReadMsgUDP(b, oob)
		if err != nil {
			t.Fatal(err)
		}
		tos := -1
		msgs, _ := syscall.ParseSocketControlMessage(oob[:on])
		for _, m := range msgs {
			if m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_TOS && len(m.Data) >= 1 {
				tos = int(*(*uint8)(unsafe.Pointer(&m.Data[0])))
			}
		}
		if tos != want[i] {
			t.Fatalf("packet %d: tos %#x, want %#x", i, tos, want[i])
		}
	}
}
