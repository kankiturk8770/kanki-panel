# Hostile-network transports: `hq`, `h2`, `dual` (v2.9.0)

> **فارسی، خلاصه:** سه روش انتقال جدید برای شبکه‌هایی که بسته‌ها را می‌شمارند و قطع می‌کنند.
> `hq` = QUIC زیر یک ماسک تصادفی (هیچ امضای QUIC روی سیم نیست)، `h2` = وب‌سوکت روی HTTP/2 روی TLS 1.3 شبیه مرورگر،
> `dual` = اول `hq`، و اگر UDP رد نشد خودکار `h2` روی همان شماره پورت. همه‌ی رکوردها padding تصادفی دارند.
> اجرا بدون پنل: `kanki-panel tunnel-run فایل.json` (نمونه‌ها در `docs/examples/`). با پنل: Tunnels › + Tunnel › گروه «سخت‌ترین برای مسدودسازی».
> **توجه:** این کد در محیط نوشتن کامپایل نشد (دسترسی به crates.io نبود)؛ قبل از استفاده `cargo test tunnel::` را اجرا کن.

## What is new

| transport | wire | when it helps |
|-----------|------|---------------|
| `hq`   | QUIC (quinn) over UDP, every datagram masked and padded | the filter cuts QUIC/UDP by its signature or by packet size |
| `h2`   | WebSocket over HTTP/2 (RFC 8441) over TLS 1.3, browser-like ALPN/ciphers/settings, many links on one TCP connection | UDP is cut, TCP 443 is open, the filter looks at the TLS/HTTP shape |
| `dual` | `hq` first, `h2` if UDP does not work; listener serves both on **one port number** (UDP + TCP) | you do not know which one the network allows, or it changes |

All three carry the same thing as the other transports: the Kanki link (X25519 + HKDF-SHA256 keyed by the token +
ChaCha20-Poly1305 records) with the mux on top, so **TCP and UDP** of the forwarded ports go through, from Node A
(the *entry*, where users connect) to Node B (the *exit*, which reaches the targets).

## Layers

```text
 user ─TCP/UDP─► Node A (entry)                                   Node B (exit) ─► target
                   │  mux (OPEN/DATA/FIN/WIN/UDP/PING…)              ▲
                   │  link records: ChaCha20-Poly1305 [len][data][random pad]
                   ▼                                                 │
        ┌──────────────────────── dual ───────────────────────┐
        │ hq : QUIC/TLS1.3 ── Salamander mask ── UDP          │──► same port number, UDP
        │ h2 : WebSocket ── HTTP/2 ── TLS 1.3 (ALPN h2) ── TCP │──► same port number, TCP
        └─────────────────────────────────────────────────────┘
```

### 1. The mask under QUIC (`salamander.rs`, `hq.rs`)

```text
wire = salt(8, random) | mask( tag(4) | pad_len(1) | pad(random) | quic_datagram )
```

* `mask` is a ChaCha20 keystream keyed from the token and nonced by the salt: no byte of the wire is fixed, the
  first byte is uniform, two packets never share a pattern (tested: first byte takes > 100 values, lengths > 100).
* `tag` is derived from the token. A datagram that does not unmask to the right tag is **dropped silently** before
  QUIC sees it: a scanner gets no QUIC version negotiation, no ICMP, nothing (tested end to end).
* `pad` makes the size meaningless: small packets (acks, window updates) get up to 255 random bytes, big ones at most
  32. Nothing grows past 1232 bytes; QUIC is pinned to the 1200-byte minimum with MTU discovery off.
* It is *obfuscation*, not encryption. The real security is QUIC's TLS 1.3 and the token handshake inside it.
* QUIC runs with BBR congestion control (loss does not collapse the window), 5 s keep-alive (NAT mappings stay open),
  30 s idle timeout, large flow-control windows.

### 2. The HTTP/2 layer (`h2ws.rs`)

* TLS 1.3 only on the server; the client offers `h2, http/1.1`, lists cipher suites in Chrome's order and uses
  Chrome-like HTTP/2 SETTINGS and request headers (`user-agent`, `accept-language`, `sec-websocket-*` …).
* Each link is an extended-CONNECT `:protocol = websocket` stream. **Four links share one TCP connection**, so the
  network sees one long HTTPS connection with several streams instead of several tunnel-looking connections. A server
  without RFC 8441 makes the client fall back to HTTP/1.1 WebSocket (remembered for 10 minutes).
* Anyone who is not a tunnel client and opens the site gets an ordinary nginx-like page (and a 404 elsewhere).
* Pre-auth hardening: WebSocket messages are capped at 1 MiB (the library default is 64 MiB), at most 256 half-open
  connections per listener, 12 s for the token handshake, at most 256 handshakes at once.

### 3. Padding of the records (`link.rs`)

On `hq`, `h2` and `dual` every record is `[u16 real_len][data][random pad]` *inside* the AEAD: control records get up
to 192 random bytes, data records almost none. Both ends turn this on from the transport name.

### 4. `dual` (`dual.rs`)

`hq` runs alone for 1.5 s; if it has not finished, `h2` starts beside it and the first success wins. When `h2` wins
the remote is remembered as "UDP bad" for 90 s (new links go straight to `h2`), then `hq` is tried again.

## Run it

### Standalone (no panel)

```bash
# Node B (exit, abroad, the server): open 443/tcp and 443/udp
kanki-panel tunnel-run node-b-exit.json
# Node A (entry, the client): users connect to 8443 / 2222 / 51820 on this machine
kanki-panel tunnel-run node-a-entry.json
```

Edit the `token` (same on both, 32+ random characters: `openssl rand -hex 24`) and `NODE_B_PUBLIC_IP`.
`mode: "direct"` = Node A dials Node B. If Node A cannot dial out but Node B can reach it, use the `-reverse` files
(Node B dials Node A). The program prints which ports to open and a status line whenever something changes.

For a certificate that looks real, put a PEM certificate and PKCS#8 key in `cert` / `key` on the listening side
(a self-signed one is made otherwise; with TLS 1.3 the certificate is encrypted, so a filter cannot see it).

### From the panel

Tunnels › + Tunnel › Transport › *Hardest to block* › **Dual**. Use port **443**. The panel refuses these transports
while an agent is older than 2.9.0 (press *Update all*). The firewall is opened on UDP and TCP by the agent when ufw is on.

## Honest limits

* **rustls cannot copy a browser's TLS fingerprint.** ALPN, cipher order and HTTP/2 settings look like Chrome; the
  extension order and a few extensions still differ, so JA3/JA4 matching on this one fingerprint can tell it from Chrome.
  Putting the tunnel behind a real CDN (`cdn` transport) or a real web server that proxies the WebSocket path removes
  that weakness.
* A network that drops **all** UDP leaves `h2`; one that allows **only whitelisted addresses** needs `cdn`.
* The mask hides *what* the traffic is, not *that* there is a lot of UDP/TLS to one address. Volume analysis is out of scope.
* A random-looking UDP stream that is not QUIC-shaped can itself be a signal for some filters; if that happens `h2`
  (inside a normal-looking HTTPS connection) is the better layer, and `dual` moves there on its own.

## Tests

```bash
cargo test tunnel::            # unit + end-to-end tests of every transport on loopback
cargo test tunnel::salamander  # the mask only (fast)
```

End-to-end tests cover `hq` / `h2` / `dual` in both modes, SNI lists, wrong tokens, the `dual` fallback with a
TCP-only server, silence towards a UDP scanner, and the smart-tunnel probe for `hq` and `h2`.
