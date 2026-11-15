// kmix-lab: a KANKI MIX client for the VIP tunnel lab (`cargo test --release vip_kmix_lab -- --ignored`).
// It plays like the Kanki app in gaming mode while it downloads over KCP, and prints what came back:
//
//   - a game server on -host: every packet the client sends (60 a second, 40 B) is answered with 150 B,
//     and every 2 s it sends a burst of 76 packets of 500 B, as PUBG does when players appear
//   - a download of -dl MB over KCP (the app's TCP) from second 3
//
// The game server is on -host (not loopback: KANKI MIX refuses loopback targets).
package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

const (
	burstN = 76
	answer = 150
)

func main() {
	server := flag.String("server", "", "KANKI MIX address (the VIP entry)")
	keyHex := flag.String("key", "", "user key (hex)")
	host := flag.String("host", "", "a non-loopback address of this machine for the game server")
	secs := flag.Int("secs", 30, "how long the game plays")
	dlMB := flag.Int("dl", 8, "MB downloaded over KCP during the game")
	gport := flag.Int("gport", 17600, "game server port")
	// the burst: "big" = 76 × 500 B (worst case, 38 KB); "real" = like the biggest PUBG bursts measured
	// (76 packets, every 8th 500 B and the rest 60 B: ~9 KB)
	bkind := flag.String("burst", "real", "big or real")
	tport := flag.Int("tport", 8089, "download server port")
	flag.Parse()
	key, _ := hex.DecodeString(*keyHex)

	// ---- the game server and the download server
	gs, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", *host, *gport))
	if err != nil {
		fail(err)
	}
	var gmu sync.Mutex
	var client net.Addr
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := gs.ReadFrom(b)
			if err != nil {
				return
			}
			gmu.Lock()
			client = a
			gmu.Unlock()
			out := make([]byte, answer)
			copy(out, b[:min(n, 8)])
			gs.WriteTo(out, a)
		}
	}()
	go func() {
		for burst := uint32(0); ; burst++ {
			time.Sleep(2 * time.Second)
			gmu.Lock()
			a := client
			gmu.Unlock()
			if a == nil {
				continue
			}
			for i := uint32(0); i < burstN; i++ {
				size := 500
				if *bkind != "big" && i%8 != 0 {
					size = 60
				}
				out := make([]byte, size)
				binary.BigEndian.PutUint32(out, 0x80000000|burst<<8|i)
				binary.BigEndian.PutUint32(out[4:], uint32(time.Now().UnixMilli()))
				gs.WriteTo(out, a)
			}
		}
	}()
	tl, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *host, *tport))
	if err != nil {
		fail(err)
	}
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() { c.Write(make([]byte, *dlMB<<20)); c.Close() }()
		}
	}()

	// ---- the client
	srv, _ := net.ResolveUDPAddr("udp", *server)
	u, _ := net.ListenUDP("udp", nil)
	var mu sync.Mutex
	sent := map[uint32]time.Time{}
	rtts := []float64{}
	bursts := map[uint32]map[uint32]bool{}
	burstLate := 0
	oc, err := obfs.New(u, key, func(kind byte, b []byte, addr net.Addr) {
		if kind != proto.KindUDPDown {
			return
		}
		_, _, p, err := proto.ParseUDPDown(b)
		if err != nil || len(p) < 8 {
			return
		}
		id := binary.BigEndian.Uint32(p)
		mu.Lock()
		defer mu.Unlock()
		if id&0x80000000 != 0 {
			k := id >> 8
			if bursts[k] == nil {
				bursts[k] = map[uint32]bool{}
			}
			if bursts[k][id] {
				return // the second copy (gaming mode sends each packet twice)
			}
			bursts[k][id] = true
			if ms := uint32(time.Now().UnixMilli()) - binary.BigEndian.Uint32(p[4:]); ms > 400 {
				burstLate++
			}
			return
		}
		if t, ok := sent[id]; ok {
			rtts = append(rtts, float64(time.Since(t).Microseconds())/1000)
			delete(sent, id)
		}
	})
	if err != nil {
		fail(err)
	}
	sess, err := kcp.NewConn2(srv, nil, 10, 3, oc)
	if err != nil {
		fail(err)
	}
	sess.SetNoDelay(1, 10, 2, 1)
	sess.SetWindowSize(512, 512)
	sess.SetMtu(1200)
	sess.SetStreamMode(true)
	sess.SetWriteDelay(false)
	sess.SetACKNoDelay(true)
	sc := smux.DefaultConfig()
	sc.KeepAliveInterval, sc.KeepAliveTimeout = 3*time.Second, 12*time.Second
	mux, err := smux.Client(sess, sc)
	if err != nil {
		fail(err)
	}
	a, err := mux.OpenStream()
	if err != nil {
		fail(err)
	}
	a.Write(proto.AuthToken(key))
	ok := make([]byte, 1)
	a.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(a, ok); err != nil {
		fail(fmt.Errorf("auth: %v", err))
	}

	ip := [4]byte{}
	copy(ip[:], net.ParseIP(*host).To4())
	dl := make(chan [2]float64, 1)
	go func() {
		time.Sleep(3 * time.Second)
		t := time.Now()
		st, err := mux.OpenStream()
		if err != nil {
			dl <- [2]float64{0, 0}
			return
		}
		st.Write([]byte{proto.CmdTCP})
		proto.WriteAddr(st, *host, uint16(*tport))
		n, _ := io.Copy(io.Discard, st)
		dl <- [2]float64{float64(n), time.Since(t).Seconds()}
	}()
	var seq uint32
	end := time.Now().Add(time.Duration(*secs) * time.Second)
	tick := time.NewTicker(16 * time.Millisecond)
	for time.Now().Before(end) {
		<-tick.C
		seq++
		p := make([]byte, 40)
		binary.BigEndian.PutUint32(p, seq)
		h := proto.UDPUp{Session: 7, Flow: 1, Seq: seq, DstIP: ip, DstPort: uint16(*gport), Flags: proto.FlagDup}
		mu.Lock()
		sent[seq] = time.Now()
		mu.Unlock()
		oc.WritePacket(proto.KindUDPUp, proto.AppendUDPUp(nil, &h, p), srv)
	}
	time.Sleep(time.Second)
	var d [2]float64
	select {
	case d = <-dl:
	case <-time.After(60 * time.Second):
	}
	mu.Lock()
	defer mu.Unlock()
	sort.Float64s(rtts)
	pct := func(p float64) float64 {
		if len(rtts) == 0 {
			return 0
		}
		return rtts[int(float64(len(rtts)-1)*p)]
	}
	full, got := 0, 0
	for _, m := range bursts {
		if len(m) >= burstN {
			full++
		}
		got += len(m)
	}
	out := map[string]any{
		"game_sent": seq, "game_back": len(rtts), "p50": pct(0.5), "p99": pct(0.99), "max": pct(1),
		"on_time_150ms": func() int {
			k := 0
			for _, r := range rtts {
				if r <= 150 {
					k++
				}
			}
			return k
		}(),
		"bursts": len(bursts), "bursts_whole": full, "burst_pkts": got, "burst_late": burstLate,
		"dl_bytes": d[0], "dl_secs": d[1],
	}
	json.NewEncoder(os.Stdout).Encode(out)
}

func fail(e error) {
	fmt.Fprintln(os.Stderr, "kmix-lab:", e)
	os.Exit(1)
}
