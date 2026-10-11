# KCP Patch Notes (v2.9.7-kcp1)

Changes in `src/tunnel/quic.rs` only — the KCP transport of Kanki Tunnel.

## 1. MTU 1350 → 1150 (stealth fix)
With `mtu = 1350`, every full KCP datagram was `8 (salt) + 4 (tag) + 1 (padlen) + 1350 = 1363`
bytes on the wire, because the mask adds zero padding to payloads > 1219 bytes (`pad_cap` in
`salamander.rs`). A constant-size UDP flow is a signature DPI can block even though the KCP header
itself is hidden. With MTU 1150 the relay has room to append up to ~69 bytes of random padding to
every datagram, so sizes on the wire vary again. Cost: ~5% more packets.

## 2. serve_kcp honours the half-open semaphore
The QUIC path already bounds concurrent/half-open handshakes with the semaphore permit; KCP ignored
it (`_sem`). Server-side KCP streams now hold an `OwnedSemaphorePermit` for their lifetime
(`KcpHeld` wrapper), so a handshake flood cannot exhaust the server.

## What was NOT changed
- `wnd_size = (1024, 1024)`, `KcpNoDelayConfig::fastest()`, `session_expire = 45s` — left as-is,
  they are already tuned for speed on lossy links.
- The obfuscation relay (`obfs.rs`) and the mask (`salamander.rs`) — reviewed, correct.

## Verify before deploying
```bash
cargo test tunnel::
cargo build --release
```
Then run two nodes with the `kcp` transport and check the Tunnels page for a stable connection.

## Still recommended (not done here)
- Carry game UDP over QUIC datagrams instead of the reliable stream (lower latency, no
  head-of-line blocking) — needs changes in `mux.rs` + `TransportConfig::max_datagram_frame_size`.
