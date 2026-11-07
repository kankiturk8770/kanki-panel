package mobile

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestE2EGame: the phone's real KANKI MIX core, dialing SERVER (the Iran entry of a panel tunnel), plays a
// fake game against an echo at HOSTIP: 50 packets a second of 80 bytes for SECS seconds. Prints loss and
// the round trips.
func TestE2EGame(t *testing.T) {
	server, host := os.Getenv("SERVER"), os.Getenv("HOSTIP")
	if server == "" || host == "" {
		t.Skip("SERVER / HOSTIP")
	}
	secs, _ := strconv.Atoi(os.Getenv("SECS"))
	if secs == 0 {
		secs = 20
	}
	gaming := os.Getenv("DUP") == "1"
	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		b := make([]byte, 2000)
		for {
			n, a, err := echo.ReadFromUDP(b)
			if err != nil {
				return
			}
			echo.WriteToUDP(b[:n], a)
		}
	}()
	ea := echo.LocalAddr().(*net.UDPAddr)
	fds, _ := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
	peer := os.NewFile(uintptr(fds[1]), "peer")
	t0 := time.Now()
	for i := 0; ; i++ {
		if err = Start(fds[0], server, testKey, 10, 3, gaming); err == nil {
			break
		}
		if i == 6 {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
	}
	defer Stop()
	fmt.Printf("connected in %v\n", time.Since(t0).Round(time.Millisecond))
	var mu sync.Mutex
	sent := map[int]time.Time{}
	rtt := map[int]float64{}
	go func() {
		b := make([]byte, 2000)
		for {
			n, err := peer.Read(b)
			if err != nil {
				return
			}
			p, err := ParseUDPPacket(b[:n])
			if err != nil || len(p.Payload) < 4 {
				continue
			}
			i := int(p.Payload[0])<<24 | int(p.Payload[1])<<16 | int(p.Payload[2])<<8 | int(p.Payload[3])
			mu.Lock()
			if s, ok := sent[i]; ok {
				if _, dup := rtt[i]; !dup {
					rtt[i] = float64(time.Since(s).Microseconds()) / 1000
				}
			}
			mu.Unlock()
		}
	}()
	time.Sleep(time.Second)
	n := secs * 50
	for i := 0; i < n; i++ {
		pl := make([]byte, 80)
		pl[0], pl[1], pl[2], pl[3] = byte(i>>24), byte(i>>16), byte(i>>8), byte(i)
		mu.Lock()
		sent[i] = time.Now()
		mu.Unlock()
		peer.Write(BuildUDPPacket(net.IPv4(10, 0, 0, 2), ea.IP, 5555, uint16(ea.Port), pl))
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(1500 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	var ok []float64
	seq := []float64{}
	for i := 0; i < n; i++ {
		if r, got := rtt[i]; got && r < 1000 {
			ok = append(ok, r)
			seq = append(seq, r)
		}
	}
	sort.Float64s(ok)
	if len(ok) == 0 {
		t.Fatal("nothing came back")
	}
	q := func(p float64) float64 { return ok[int(float64(len(ok)-1)*p)] }
	jit := 0.0
	for i := 1; i < len(seq); i++ {
		d := seq[i] - seq[i-1]
		if d < 0 {
			d = -d
		}
		jit += d
	}
	jit /= float64(len(seq) - 1)
	over := 0
	for _, r := range ok {
		if r > 200 {
			over++
		}
	}
	fmt.Printf("RESULT loss=%.2f%% p50=%.1f p95=%.1f p99=%.1f max=%.1f jitter=%.1f over200=%d corePing=%d\n",
		100*float64(n-len(ok))/float64(n), q(.5), q(.95), q(.99), ok[len(ok)-1], jit, over, GetPing())
}
