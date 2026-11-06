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
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"

	"kanki-tunnel/internal/obfs"
	"kanki-tunnel/internal/proto"
)

var (
	listen = flag.String("listen", ":4000", "آدرس گوش‌دادن UDP")
	keyHex = flag.String("key", "", "کلید ۳۲ بایتی به صورت hex (خالی = تولید تصادفی و چاپ)")
	data   = flag.Int("fec-data", 10, "تعداد shard داده FEC")
	parity = flag.Int("fec-parity", 3, "تعداد shard parity FEC")

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
			go serveAPI(*apiAddr, *apiSecret, ring, *usersPath)
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
	// ServeConn: بلاک‌رمز داخلی nil (رمزنگاری را خودمان در لایه obfs انجام می‌دهیم)
	ln, err := kcp.ServeConn(nil, *data, *parity, oc)
	if err != nil {
		log.Fatal(err)
	}
	go relay.janitor()
	log.Printf("[kanki-server] پروتکل ۲ | گوش می‌دهم روی udp %s | FEC %d+%d", *listen, *data, *parity)

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
	psk := currentPSK
	if ring := relayRing; ring != nil {
		u := ring.UserOf(sess.RemoteAddr())
		if u == nil {
			authStream.Close()
			return
		}
		psk = u.Key
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
		go handleStream(st)
	}
}

func handleStream(st *smux.Stream) {
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
		relayTCP(st, proto.JoinAddr(host, port))
	}
}

func relayTCP(st *smux.Stream, target string) {
	rc, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("dial %s: %v", target, err)
		return
	}
	defer rc.Close()
	if tc, ok := rc.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}
	st.Write([]byte{0x01}) // متصل شد
	go func() {
		io.Copy(rc, st)
		if tc, ok := rc.(*net.TCPConn); ok {
			tc.CloseWrite() // اپ دیگر چیزی نمی‌فرستد؛ مقصد هنوز می‌تواند جواب بدهد
		}
	}()
	io.Copy(st, rc)
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
	conn     *net.UDPConn
	client   atomic.Pointer[net.UDPAddr] // آخرین آدرس کلاینت (با عوض شدن شبکه‌ی گوشی عوض می‌شود)
	dup      atomic.Bool
	lastSeen atomic.Int64
	downSeq  atomic.Uint32
	mu       sync.Mutex
	win      proto.Window
}

type dgramRelay struct {
	ring    *obfs.Keyring // حالت چندکاربره (nil = یک کلید)
	send    func(kind byte, b []byte, addr net.Addr)
	mu      sync.Mutex
	flows   map[flowKey]*udpFlow
	perSess map[uint64]int
}

func newDgramRelay(send func(byte, []byte, net.Addr)) *dgramRelay {
	return &dgramRelay{send: send, flows: make(map[flowKey]*udpFlow), perSess: make(map[uint64]int)}
}

// handle داخل حلقه‌ی خواندن سوکت اصلی صدا زده می‌شود؛ پس هیچ کار کندی اینجا نیست.
func (r *dgramRelay) handle(kind byte, b []byte, addr net.Addr) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return
	}
	switch kind {
	case proto.KindPing:
		if len(b) == proto.PingLen && r.allowed(addr, binary.BigEndian.Uint64(b[0:8])) {
			r.send(proto.KindPong, b, addr)
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
		f.client.Store(ua)
		f.dup.Store(h.Flags&proto.FlagDup != 0)
		f.lastSeen.Store(time.Now().Unix())
		f.mu.Lock()
		fresh := f.win.Accept(h.Seq)
		f.mu.Unlock()
		if fresh {
			f.conn.Write(payload)
		}
	}
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
	if target.IP.IsUnspecified() || target.IP.IsLoopback() || target.Port == 0 {
		return nil
	}
	c, err := net.DialUDP("udp", nil, target)
	if err != nil {
		return nil
	}
	f := &udpFlow{key: k, conn: c}
	f.lastSeen.Store(time.Now().Unix())
	r.flows[k] = f
	r.perSess[k.sess]++
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
		out = proto.AppendUDPDown(out[:0], f.key.flow, f.downSeq.Add(1), buf[:n])
		client := f.client.Load()
		r.send(proto.KindUDPDown, out, client)
		if f.dup.Load() {
			r.send(proto.KindUDPDown, out, client)
		}
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
		r.mu.Unlock()
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
