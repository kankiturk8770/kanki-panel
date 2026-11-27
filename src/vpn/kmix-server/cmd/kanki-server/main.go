// kanki-server — سمت سرور تونل KANKI MIX (پروتکل ۲)
// استفاده:
//
//	kanki-server -listen :4000 -key <hex 64 کاراکتر>
//
// تولید کلید:  openssl rand -hex 32
//
// روی یک پورت UDP دو مسیر هست:
//   - KCP + FEC + smux برای TCP (قابل اطمینان، به ترتیب)
//   - مسیر سریع دیتاگرام برای UDP بازی و پینگ (بدون صف و بدون ارسال مجدد)
package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"kanki-tunnel/internal/egress"
	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

var (
	listen = flag.String("listen", ":4000", "آدرس گوش‌دادن UDP")
	keyHex = flag.String("key", "", "کلید ۳۲ بایتی به صورت hex (خالی = تولید تصادفی و چاپ)")
	data   = flag.Int("fec-data", 10, "تعداد shard داده FEC")
	parity = flag.Int("fec-parity", 3, "تعداد shard parity FEC")
	// the parity of the links apps may still hold from before FEC went off (fec-parity 0): KCP that comes with FEC
	// framing is answered with it; KCP without framing goes to the listener without FEC (panel 3.67)
	fecLegacy = flag.Int("fec-legacy", 3, "parity for KCP that comes with FEC when fec-parity is 0")

	// حالت چندکاربره (پنل): هر کاربر کلید خودش؛ -key لازم نیست
	usersPath = flag.String("users", "", "فایل JSON کاربران (حالت چندکاربره)")
	apiAddr   = flag.String("api", "", "آدرس API آمار، مثلاً 127.0.0.1:31000 (حالت چندکاربره)")
	apiSecret = flag.String("api-secret", "", "رمز API آمار")
)

const (
	kcpMTU          = 1200
	udpIdleTimeout  = 120 * time.Second
	maxFlowsPerSess = 1024
	maxFlowsTotal   = 50000
)

func main() {
	flag.Parse()
	if *apiSecret == "" {
		// از EnvironmentFile سرویس (تا رمز در فایل unit که همه می‌خوانند نباشد)
		*apiSecret = os.Getenv("KANKI_API_SECRET")
	}

	udp, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	var oc *obfs.PacketConn
	relay := newDgramRelay(func(kind byte, b []byte, addr net.Addr) {
		oc.WritePacket(kind, b, addr)
	})
	if *usersPath != "" {
		ring := obfs.NewKeyring()
		if err := loadUsers(ring, *usersPath); err != nil {
			log.Printf("خواندن کاربران: %v (فعلاً بدون کاربر)", err)
		}
		go watchUsers(ring, *usersPath)
		if *apiAddr != "" {
			go serveAPI(*apiAddr, *apiSecret, ring, *usersPath, relay)
		}
		relay.ring = ring
		relayRing = ring
		oc = obfs.NewMulti(udp, ring, relay.handle)
	} else {
		oc, err = obfs.New(udp, loadKey(), relay.handle)
		if err != nil {
			log.Fatal(err)
		}
	}
	// ضبط ترافیک یک کاربر وقتی پنل خواست (record.go)
	oc.Tap = tapPacket
	// بسته‌های بازی با علامت EF می‌روند: تانل Game-FEC Pro فقط به آن‌ها FEC می‌دهد (KCP نه)
	oc.MarkGame = true
	// ServeConn: بلاک‌رمز داخلی nil (رمزنگاری را خودمان در لایه obfs انجام می‌دهیم)
	// KCP بی FEC برای اپ تازه (KindKCPPlain): TCP خودش دوباره می‌فرستد، FEC فقط پهنای باند هدر می‌داد
	plainLn, err := kcp.ServeConn(nil, 0, 0, oc.Plain())
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			sess, err := plainLn.AcceptKCP()
			if err != nil {
				log.Printf("accept (plain): %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go handleSession(sess)
		}
	}()
	// KCP of an old app on a link with FEC off (fec=10-0): no FEC either way (plain.go, Bare)
	bareLn, err := kcp.ServeConn(nil, 0, 0, oc.Bare())
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			sess, err := bareLn.AcceptKCP()
			if err != nil {
				log.Printf("accept (no FEC): %v", err)
				time.Sleep(100 * time.Millisecond)
				continue
			}
			go handleSession(sess)
		}
	}()
	ln, err := kcp.ServeConn(nil, *data, legacyParity(), oc)
	if err != nil {
		log.Fatal(err)
	}
	go relay.janitor()
	log.Printf("[kanki-server] پروتکل ۳ | گوش می‌دهم روی udp %s | FEC %d+%d (با FEC آمده: %d)", *listen, *data, *parity, legacyParity())

	for {
		sess, err := ln.AcceptKCP()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleSession(sess)
	}
}

// SmuxConfig باید در کلاینت و سرور یکی باشد. keepalive کوتاه = اتصال مرده زود تشخیص داده می‌شود.
func smuxConfig() *smux.Config {
	c := smux.DefaultConfig()
	c.KeepAliveInterval = 3 * time.Second
	c.KeepAliveTimeout = 12 * time.Second
	return c
}

func handleSession(sess *kcp.UDPSession) {
	defer sess.Close()
	tuneKCP(sess)
	mux, err := smux.Server(sess, smuxConfig())
	if err != nil {
		return
	}
	defer mux.Close()

	// اولین استریم باید احراز هویت باشد (ضد پروب فعال)
	authStream, err := mux.AcceptStream()
	if err != nil {
		return
	}
	token := make([]byte, 40)
	authStream.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(authStream, token); err != nil {
		authStream.Close()
		return
	}
	psk, user := currentPSK, ""
	if ring := relayRing; ring != nil {
		u := ring.UserOf(sess.RemoteAddr())
		if u == nil {
			authStream.Close()
			return
		}
		psk, user = u.Key, u.Name
	}
	if err := proto.VerifyAuth(psk, token); err != nil {
		log.Printf("احراز هویت ناموفق از %s: %v", sess.RemoteAddr(), err)
		authStream.Close()
		return
	}
	authStream.Write([]byte{0x01}) // OK
	authStream.Close()
	log.Printf("[+] کلاینت احراز شد: %s", sess.RemoteAddr())

	for {
		st, err := mux.AcceptStream()
		if err != nil {
			return
		}
		go handleStream(st, user)
	}
}

func handleStream(st *smux.Stream, user string) {
	defer st.Close()
	var cmd [1]byte
	if _, err := io.ReadFull(st, cmd[:]); err != nil {
		return
	}
	host, port, err := proto.ReadAddr(st)
	if err != nil {
		return
	}
	if cmd[0] == proto.CmdTCP {
		relayTCP(st, host, port, &tcpTap{user: user, host: host, port: port})
	}
}

func relayTCP(st *smux.Stream, host string, port uint16, tap *tcpTap) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	rc, err := egress.DialTCP(ctx, host, port, 10*time.Second)
	cancel()
	if err != nil {
		if !errors.Is(err, egress.ErrBlocked) {
			log.Printf("dial %s: %v", proto.JoinAddr(host, port), err)
		}
		return
	}
	defer rc.Close()
	if tc, ok := rc.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	st.Write([]byte{0x01}) // متصل شد
	defer tap.closed()
	go func() {
		io.Copy(countW{rc, tap, 0}, st)
		if tc, ok := rc.(*net.TCPConn); ok {
			tc.CloseWrite() // اپ دیگر چیزی نمی‌فرستد؛ مقصد هنوز می‌تواند جواب بدهد
		}
	}()
	// while the user's game plays, the download is paced so it never queues in front of it (limiter.go)
	io.Copy(countW{st, tap, 1}, pacedReader{r: rc, user: tap.user, l: downLimit})
	// مقصد اتصال را بست → استریم را ببند تا اپ فوراً بفهمد. smux نیم‌بسته ندارد؛ قبلاً اینجا
	// منتظر اپ می‌ماندیم و اپ منتظر ما، و هر اتصال تا ۳۰ ثانیه آویزان می‌ماند.
	st.Close()
}

// ---- مسیر سریع دیتاگرام ----

type flowKey struct {
	sess uint64
	flow uint32
}

type udpFlow struct {
	key      flowKey
	dstPort  int // the far end's port (DNS flows are never a game)
	conn     *net.UDPConn
	client   atomic.Pointer[net.UDPAddr] // آخرین آدرس کلاینت (با عوض شدن شبکه‌ی گوشی عوض می‌شود)
	dup      atomic.Bool
	mirror   atomic.Int64 // UnixNano until which the answers go over the phone's other path too (FlagMirror)
	lastSeen atomic.Int64
	downSeq  atomic.Uint32
	mu       sync.Mutex
	win      proto.Window
	s        flowSmart
}

type dgramRelay struct {
	ring    *obfs.Keyring // حالت چندکاربره (nil = یک کلید)
	send    func(kind byte, b []byte, addr net.Addr)
	mu      sync.Mutex
	flows   map[flowKey]*udpFlow
	perSess map[uint64]int
	sess    map[uint64]*smartSess // apps that report (smart.go)
	paths   pathBook              // the addresses of each session (multipath.go)
	gaming  map[uint64]int64      // sessions that said gaming mode in a hello, when (hello.go)
}

func newDgramRelay(send func(byte, []byte, net.Addr)) *dgramRelay {
	return &dgramRelay{send: send, flows: make(map[flowKey]*udpFlow), perSess: make(map[uint64]int), sess: make(map[uint64]*smartSess),
		paths: pathBook{m: make(map[uint64]*sessPaths)}, gaming: make(map[uint64]int64)}
}

// handle داخل حلقه‌ی خواندن سوکت اصلی صدا زده می‌شود؛ پس هیچ کار کندی اینجا نیست.
func (r *dgramRelay) handle(kind byte, b []byte, addr net.Addr) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	switch kind {
	case proto.KindPing:
		if len(b) == proto.PingLen {
			if sid := binary.BigEndian.Uint64(b[0:8]); r.allowed(addr, sid) {
				r.send(proto.KindPong, b, addr)
				r.paths.note(sid, ua)
			}
		}
	case proto.KindUDPUp:
		h, payload, err := proto.ParseUDPUp(b)
		if err != nil || !r.allowed(addr, h.Session) {
			return
		}
		f := r.getFlow(h)
		if f == nil {
			return
		}
		// the main address is learned from the first copies only: a second copy or a mirrored packet may come over
		// another path of the phone (multipath), and the answers must keep going on the best one
		if h.Flags&proto.FlagCopy == 0 {
			f.client.Store(ua)
			f.dup.Store(h.Flags&proto.FlagDup != 0)
		} else if f.client.Load() == nil {
			f.client.Store(ua)
		}
		if h.Flags&proto.FlagMirror != 0 {
			f.mirror.Store(time.Now().Add(mirrorFor).UnixNano())
		}
		r.paths.note(h.Session, ua)
		f.lastSeen.Store(time.Now().Unix())
		// a game packet: the user's downloads give way to it while it plays (limiter.go)
		if f.s.game.Load() || h.Flags&proto.FlagGame != 0 {
			downLimit.noteGame(r.userOf(addr), time.Now())
		}
		f.mu.Lock()
		fresh := f.win.Accept(h.Seq)
		f.mu.Unlock()
		r.upData(f, h, payload, fresh)
	case proto.KindHello:
		r.onHello(b, addr)
	case proto.KindRepair:
		r.onRepairUp(b, addr)
	case proto.KindStat:
		r.onStat(b, addr)
	}
}

// userOf the user name of an address ("" with one key, where everyone is one user)
func (r *dgramRelay) userOf(addr net.Addr) string {
	if r.ring == nil {
		return ""
	}
	if u := r.ring.UserOf(addr); u != nil {
		return u.Name
	}
	return ""
}

// allowed در حالت چندکاربره سقف دستگاه هم‌زمان کاربر را اعمال می‌کند.
func (r *dgramRelay) allowed(addr net.Addr, sid uint64) bool {
	if r.ring == nil {
		return true
	}
	u := r.ring.UserOf(addr)
	return u != nil && userSessions.allow(u.Name, sid)
}

func (r *dgramRelay) getFlow(h proto.UDPUp) *udpFlow {
	k := flowKey{h.Session, h.Flow}
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.flows[k]; ok {
		return f
	}
	if len(r.flows) >= maxFlowsTotal || r.perSess[k.sess] >= maxFlowsPerSess {
		return nil
	}
	target := h.Target()
	ta, ok := netip.AddrFromSlice(target.IP)
	if !ok || !egress.Allowed(ta) || target.Port == 0 {
		return nil
	}
	c, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return nil
	}
	f := &udpFlow{key: k, conn: c, dstPort: target.Port}
	f.lastSeen.Store(time.Now().Unix())
	// a session in gaming mode (hello.go): every flow but DNS is a game from its first packet
	if at, ok := r.gaming[k.sess]; ok && target.Port != dnsPort && time.Since(time.Unix(0, at)) < sessIdle {
		f.s.game.Store(true)
	}
	r.flows[k] = f
	r.perSess[k.sess]++
	r.smartAdd(f)
	go r.readLoop(f)
	return f
}

// readLoop پاسخ‌های سرور مقصد (مثلاً سرور بازی) را به کلاینت برمی‌گرداند.
func (r *dgramRelay) readLoop(f *udpFlow) {
	defer r.remove(f)
	buf := make([]byte, 65535)
	out := make([]byte, 0, obfs.MaxPayload)
	for {
		f.conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := f.conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() &&
				time.Since(time.Unix(f.lastSeen.Load(), 0)) < udpIdleTimeout {
				continue // کلاینت هنوز می‌فرستد؛ فقط مقصد ساکت بوده
			}
			return
		}
		if n > obfs.MaxPayload-proto.DownHdrLen {
			continue // بزرگ‌تر از ظرفیت تونل؛ مثل یک بسته‌ی گم‌شده رفتار می‌شود
		}
		f.lastSeen.Store(time.Now().Unix())
		seq := f.downSeq.Add(1)
		out = proto.AppendUDPDown(out[:0], f.key.flow, seq, buf[:n])
		r.sendDown(f, seq, buf[:n], out)
	}
}

func (r *dgramRelay) remove(f *udpFlow) {
	f.conn.Close()
	r.mu.Lock()
	if cur, ok := r.flows[f.key]; ok && cur == f {
		delete(r.flows, f.key)
		if r.perSess[f.key.sess]--; r.perSess[f.key.sess] <= 0 {
			delete(r.perSess, f.key.sess)
		}
		r.smartDrop(f)
	}
	r.mu.Unlock()
}

// janitor جریان‌هایی را که کلاینت دیگر از آن‌ها استفاده نمی‌کند می‌بندد.
func (r *dgramRelay) janitor() {
	for range time.Tick(30 * time.Second) {
		var dead []*udpFlow
		r.mu.Lock()
		for _, f := range r.flows {
			if time.Since(time.Unix(f.lastSeen.Load(), 0)) > udpIdleTimeout {
				dead = append(dead, f)
			}
		}
		r.smartGC()
		r.gamingGC(time.Now())
		r.mu.Unlock()
		downLimit.gc(time.Now())
		r.paths.gc()
		for _, f := range dead {
			f.conn.Close() // readLoop خودش remove را صدا می‌زند
		}
	}
}

// tuneKCP تنظیمات کم‌تأخیر
func tuneKCP(s *kcp.UDPSession) {
	s.SetNoDelay(1, 10, 2, 1) // nodelay، interval=10ms، fast-resend=2، بدون congestion
	s.SetWindowSize(512, 512)
	s.SetMtu(kcpMTU)
	s.SetStreamMode(true)
	s.SetWriteDelay(false)
	s.SetACKNoDelay(true)
}

// legacyParity the parity of KCP that comes with FEC framing: the configured one, or (FEC off) the one the old
// links held
func legacyParity() int {
	if *parity > 0 {
		return *parity
	}
	if *fecLegacy > 0 {
		return *fecLegacy
	}
	return 3
}

var (
	currentPSK []byte
	relayRing  *obfs.Keyring // حالت چندکاربره
)

func loadKey() []byte {
	var psk []byte
	if *keyHex == "" {
		psk = make([]byte, 32)
		rand.Read(psk)
		log.Printf("[!] کلید تصادفی ساخته شد (ذخیره کنید): %s", hex.EncodeToString(psk))
	} else {
		var err error
		psk, err = hex.DecodeString(*keyHex)
		if err != nil || len(psk) != 32 {
			log.Fatal("کلید باید hex با ۶۴ کاراکتر (۳۲ بایت) باشد")
		}
	}
	currentPSK = psk
	return psk
}
