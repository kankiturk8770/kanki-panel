// Dials a KPING link with the app's own microtun client and pings the server's tunnel address
// (10.81.0.1) through a TUN kept in memory: loss and round trips.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"mtuncore/mtun"
)

type memTun struct {
	in     chan []byte
	got    chan []byte
	closed chan struct{}
	once   sync.Once
}

func (t *memTun) Read(p []byte) (int, error) {
	select {
	case b := <-t.in:
		return copy(p, b), nil
	case <-t.closed:
		return 0, io.EOF
	}
}
func (t *memTun) Write(p []byte) (int, error) {
	b := append([]byte(nil), p...)
	select {
	case t.got <- b:
	default:
	}
	return len(p), nil
}
func (t *memTun) Close() error { t.once.Do(func() { close(t.closed) }); return nil }

func csum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s > 0xffff {
		s = s>>16 + s&0xffff
	}
	return ^uint16(s)
}

func echo(src, dst net.IP, seq uint16, size int) []byte {
	icmp := make([]byte, 8+size)
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:], 0x4b50)
	binary.BigEndian.PutUint16(icmp[6:], seq)
	binary.BigEndian.PutUint64(icmp[8:], uint64(time.Now().UnixNano()))
	binary.BigEndian.PutUint16(icmp[2:], csum(icmp))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(icmp)))
	ip[8] = 64
	ip[9] = 1
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	binary.BigEndian.PutUint16(ip[10:], csum(ip))
	return append(ip, icmp...)
}

func main() {
	link, _ := os.ReadFile(os.Args[1])
	c, err := mtun.Dial(strings.TrimSpace(string(link)), "kping-test-device", func(s string) { fmt.Println(s) })
	if err != nil {
		fmt.Println("DIAL FAILED:", err)
		os.Exit(1)
	}
	addr := strings.Fields(c.Address())[0]
	src, _, _ := net.ParseCIDR(addr)
	fmt.Println("connected, address", addr)
	t := &memTun{in: make(chan []byte, 64), got: make(chan []byte, 256), closed: make(chan struct{})}
	c.SetTUN(t)
	dst := net.ParseIP("10.81.0.1")
	sent, recv := 0, 0
	var rtts []time.Duration
	for i := 0; i < 100; i++ {
		t.in <- echo(src, dst, uint16(i), 64)
		sent++
		deadline := time.After(1500 * time.Millisecond)
	wait:
		for {
			select {
			case b := <-t.got:
				if len(b) >= 36 && b[9] == 1 && b[20] == 0 && binary.BigEndian.Uint16(b[26:]) == uint16(i) {
					rtts = append(rtts, time.Duration(time.Now().UnixNano()-int64(binary.BigEndian.Uint64(b[28:]))))
					recv++
					break wait
				}
			case <-deadline:
				break wait
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	avg := time.Duration(0)
	if len(rtts) > 0 {
		avg = sum / time.Duration(len(rtts))
	}
	up, hrtt, rx, tx := c.Stats()
	fmt.Printf("PINGS sent=%d back=%d avg=%v | session up=%v handshake=%dms rx=%d tx=%d\n", sent, recv, avg, up, hrtt, rx, tx)
	c.Close()
}
