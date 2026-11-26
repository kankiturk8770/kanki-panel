package obfs

// KCP بی FEC برای ترافیک TCP اپ (لابی، ورود، دانلود).
//
// FEC فقط به کار بسته‌ی بازی می‌آید (گم شدنش جبران‌پذیر نیست و منتظر ارسال دوباره نمی‌ماند)؛ TCP خودش
// دوباره می‌فرستد، پس FEC روی آن فقط پهنای باند هدر می‌دهد و صف‌ها را پر می‌کند. اپ تازه KCP را با نوع
// KindKCPPlain و بی FEC می‌فرستد؛ سرور تازه آن را به شنونده‌ی KCP دوم (بی FEC) می‌دهد. اپ قدیمی همان
// KindKCP با FEC را می‌فرستد و مثل قبل کار می‌کند. سرور قدیمی KindKCPPlain را نمی‌شناسد و جواب نمی‌دهد؛
// اپ تازه آن‌وقت به KindKCP با FEC برمی‌گردد.

import (
	"net"
	"sync"
	"time"
)

// KindKCPPlain بسته‌ی KCP بی FEC (TCP اپ)
const KindKCPPlain byte = 0x05

// plainQueue بسته‌هایی که منتظر شنونده‌ی KCP بی FEC می‌مانند؛ پر که شد تازه‌ها دور ریخته می‌شوند (KCP دوباره می‌فرستد)
const plainQueue = 4096

type plainPkt struct {
	b    []byte
	addr net.Addr
}

// plainConn نیمه‌ی KCP بی FEC همان سوکت (سمت سرور): بسته‌هایش را حلقه‌ی خواندن اصلی می‌دهد.
type plainConn struct {
	parent *PacketConn
	// kind the answers go with: KindKCPPlain, or KindKCP for an old app on a link with no FEC (Bare)
	kind   byte
	ch     chan plainPkt
	done   chan struct{}
	once   sync.Once
}

// ClientPlain (سمت اپ): KCP این اتصال از این به بعد بی FEC و با نوع KindKCPPlain می‌رود.
func (c *PacketConn) ClientPlain() { c.kcpKind = KindKCPPlain }

// kcpKindOf نوع بسته‌های KCP همین اتصال
func (c *PacketConn) kcpKindOf() byte {
	if c.kcpKind == 0 {
		return KindKCP
	}
	return c.kcpKind
}

// Plain (سمت سرور) یک net.PacketConn برای شنونده‌ی KCP بی FEC؛ فقط یک بار و پیش از شروع خواندن صدا زده شود.
func (c *PacketConn) Plain() net.PacketConn {
	if c.plain == nil {
		c.plain = &plainConn{parent: c, kind: KindKCPPlain, ch: make(chan plainPkt, plainQueue), done: make(chan struct{})}
	}
	return c.plain
}

// Bare (server side, panel 3.67) a net.PacketConn for a KCP listener without FEC that takes the KindKCP packets
// of an app on a link with FEC off (fec=10-0): an app from before KindKCPPlain sends KCP without FEC framing
// then, and its answers must come back as KindKCP, also without FEC. Called once, before reading starts.
func (c *PacketConn) Bare() net.PacketConn {
	if c.bare == nil {
		c.bare = &plainConn{parent: c, kind: KindKCP, ch: make(chan plainPkt, plainQueue), done: make(chan struct{})}
	}
	return c.bare
}

// FECFramed: a KCP packet that carries kcp-go's FEC header (seqid 4, flag 2 little endian: 0x00f1 data, 0x00f2
// parity). A KCP segment without it has its command (81-84) where the flag would be, so the two never mix.
func FECFramed(p []byte) bool {
	return len(p) >= 6 && (p[4] == 0xf1 || p[4] == 0xf2) && p[5] == 0
}

// deliverBare a KindKCP packet without FEC framing to the listener without FEC (false = there is none)
func (c *PacketConn) deliverBare(p []byte, addr net.Addr) bool {
	if c.bare == nil || FECFramed(p) {
		return false
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case c.bare.ch <- plainPkt{b, addr}:
	default:
	}
	return true
}

// deliverPlain یک بسته‌ی KindKCPPlain را به شنونده‌اش می‌دهد (کپی، چون بافر خواندن دوباره استفاده می‌شود)
func (c *PacketConn) deliverPlain(p []byte, addr net.Addr) bool {
	if c.plain == nil {
		return false
	}
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case c.plain.ch <- plainPkt{b, addr}:
	default:
	}
	return true
}

func (p *plainConn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case k := <-p.ch:
		return copy(b, k.b), k.addr, nil
	case <-p.done:
		return 0, nil, net.ErrClosed
	}
}

func (p *plainConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := p.parent.WritePacket(p.kind, b, addr); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *plainConn) Close() error {
	p.once.Do(func() { close(p.done) })
	return nil
}
func (p *plainConn) LocalAddr() net.Addr                { return p.parent.LocalAddr() }
func (p *plainConn) SetDeadline(t time.Time) error      { return nil }
func (p *plainConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *plainConn) SetWriteDeadline(t time.Time) error { return nil }
