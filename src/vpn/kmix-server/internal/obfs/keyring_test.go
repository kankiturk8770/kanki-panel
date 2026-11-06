package obfs

import (
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"
)

// capture بسته‌ی رمزشده را به جای فرستادن نگه می‌دارد.
type capture struct {
	net.PacketConn
	last []byte
}

func (c *capture) WriteTo(b []byte, _ net.Addr) (int, error) {
	c.last = append([]byte(nil), b...)
	return len(b), nil
}

func ringWith(n int) (*Keyring, [][]byte) {
	keys := map[string]string{}
	var raw [][]byte
	for i := 0; i < n; i++ {
		k := []byte(fmt.Sprintf("user-%04d-xxxxxxxxxxxxxxxxxxxxxx", i))[:32]
		keys[hex.EncodeToString(k)] = fmt.Sprintf("u%d", i)
		raw = append(raw, k)
	}
	ring := NewKeyring()
	if err := ring.Set(keys); err != nil {
		panic(err)
	}
	return ring, raw
}

func seal(key []byte, payload []byte) []byte {
	c := &capture{}
	pc, _ := New(c, key, nil)
	pc.WritePacket(KindKCP, payload, nil)
	return c.last
}

func TestKeyringOwnerAndScanLimit(t *testing.T) {
	ring, keys := ringWith(50)
	out := make([]byte, 65535)
	a := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5}
	u, p, ok := ring.open(seal(keys[37], []byte("hello")), a, out)
	if !ok || u.Name != "u37" || string(p[3:8]) != "hello" {
		t.Fatalf("باز نشد: %v %v", ok, u)
	}
	if ring.UserOf(a).Name != "u37" {
		t.Fatal("آدرس به کاربر وصل نشد")
	}
	// سیل بسته‌ی بی‌معنی از یک IP: بعد از scanPerSec بار، بقیه بدون امتحان کلیدها رد می‌شوند
	junk := make([]byte, 120)
	for i := 0; i < scanPerSec*3; i++ {
		ring.open(junk, &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 1000 + i}, out)
	}
	if b := ring.scans[netip.MustParseAddr("9.9.9.9")]; b.n != scanPerSec*3 || ring.mayScan(netip.MustParseAddr("9.9.9.9")) {
		t.Fatal("سقف امتحان کلید اعمال نشد")
	}
	// کاربر واقعی از همان IP ولی آدرس آشنا: سقف رویش اثری ندارد
	if _, _, ok := ring.open(seal(keys[37], []byte("x")), a, out); !ok {
		t.Fatal("آدرس آشنا رد شد")
	}
	time.Sleep(10 * time.Millisecond)
}

// ۱۰۰۰ کاربر: هزینه‌ی بسته از آدرس آشنا (یک کلید) و بسته‌ی ناشناس (امتحان همه‌ی کلیدها)
func BenchmarkKeyring(b *testing.B) {
	ring, keys := ringWith(1000)
	out := make([]byte, 65535)
	pkt := seal(keys[999], make([]byte, 100))
	a := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5}
	ring.open(append([]byte(nil), pkt...), a, out)
	b.Run("known", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ring.open(pkt, a, out)
		}
	})
	b.Run("unknown-1000-users", func(b *testing.B) {
		junk := make([]byte, len(pkt))
		for i := 0; i < b.N; i++ {
			ring.scans = map[netip.Addr]*scanBucket{}
			ring.open(junk, &net.UDPAddr{IP: net.IPv4(9, 9, 9, 9), Port: 1}, out)
		}
	})
}
