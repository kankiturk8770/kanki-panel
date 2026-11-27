// Package egress decides which destinations a KANKI MIX user may reach through this server. The server's
// own loopback (the panel, the KANKI MIX API, the DNS and Xray control ports), private and link-local
// networks (other machines of the provider, cloud metadata at 169.254.169.254) are never reachable.
package egress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"
)

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// private: the ranges a lab may open with KMIX_LAB_ALLOW_PRIVATE=1 (the integration tests of kmix-core run the
// server and the client on one LAN address); loopback, link-local and metadata stay closed even then
var private = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

var labPrivate = os.Getenv("KMIX_LAB_ALLOW_PRIVATE") == "1"

// ErrBlocked is the answer for a destination users may not reach
var ErrBlocked = errors.New("destination not allowed")

// Allowed reports whether a user may reach ip
func Allowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return false
	}
	for _, p := range blocked {
		if !p.Contains(ip) {
			continue
		}
		if labPrivate {
			for _, q := range private {
				if q.Contains(ip) {
					return true
				}
			}
		}
		return false
	}
	return true
}

// Resolve gives the first allowed address of host (a name is resolved here, once, and that address is the one
// dialled: a name that later resolves to 127.0.0.1 cannot get past the check)
func Resolve(ctx context.Context, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !Allowed(ip) {
			return netip.Addr{}, ErrBlocked
		}
		return ip.Unmap(), nil
	}
	if host == "" || host == "localhost" {
		return netip.Addr{}, ErrBlocked
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if Allowed(ip) {
			return ip.Unmap(), nil
		}
	}
	return netip.Addr{}, ErrBlocked
}

// DialTCP dials host:port only when the address is allowed
func DialTCP(ctx context.Context, host string, port uint16, timeout time.Duration) (net.Conn, error) {
	ip, err := Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: timeout}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
}
