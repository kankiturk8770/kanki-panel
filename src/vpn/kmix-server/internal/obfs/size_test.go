package obfs

import (
	"net"
	"testing"
	"time"
)

// پنل: کل بسته روی اینترنت موبایل حداکثر ۱۳۸۰ بایت (mtu_budget)، حتی روی IPv6 (۴۰ + UDP ۸)
const budget = 1380

// هر اندازه‌ای از payload، با هر پدینگ تصادفی، روی سیم از MaxWire بزرگ‌تر نمی‌شود؛ بزرگ‌تر از
// MaxPayload رد می‌شود (نه این‌که بزرگ‌تر فرستاده شود) و گیرنده بسته را درست باز می‌کند.
func TestNoPacketPassesTheBudget(t *testing.T) {
	if MaxWire+8+40 > budget {
		t.Fatalf("MaxWire %d: %d bytes on IPv6", MaxWire, MaxWire+48)
	}
	a, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	psk := make([]byte, 32)
	tx, _ := New(a, psk, nil)
	rx, _ := New(b, psk, nil)
	buf := make([]byte, 65535)
	raw := make([]byte, 65535)
	for size := 0; size <= MaxPayload; size += 7 {
		for _, n := range []int{size, MaxPayload} {
			p := make([]byte, n)
			for i := range p {
				p[i] = byte(i)
			}
			if err := tx.WritePacket(9, p, b.LocalAddr()); err != nil {
				t.Fatalf("payload %d: %v", n, err)
			}
			b.SetReadDeadline(time.Now().Add(2 * time.Second))
			m, from, err := b.ReadFrom(raw)
			if err != nil {
				t.Fatal(err)
			}
			if m > MaxWire {
				t.Fatalf("payload %d → %d bytes on the wire (max %d)", n, m, MaxWire)
			}
			k, got, ok := rx.open(raw[:m], from)
			if !ok || k != 9 || len(got) != n {
				t.Fatalf("payload %d did not come back whole", n)
			}
			copy(buf, got)
		}
	}
	if err := tx.WritePacket(9, make([]byte, MaxPayload+1), b.LocalAddr()); err == nil {
		t.Fatal("a payload over MaxPayload must be refused, not sent bigger")
	}
}
