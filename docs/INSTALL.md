# Installation guide

## 1. Publish the code
1. Create a **public** GitHub repo and push this project to the `main` branch.
2. Open the **Actions** tab and wait for the `build` workflow to finish (green).
3. **Releases** now has a `latest` release with `kanki-panel`, `kanki-panel.sha256` and `version.txt`.

## 2. Main panel server
Ubuntu 22.04 / 24.04, as root:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/<USER>/<REPO>/main/install.sh)
```
Choose **1**. The installer asks for:

| Question | Notes |
|---|---|
| GitHub repo | `user/repo` (saved for updates) |
| Panel domain + email | Must point straight to the server (no Cloudflare proxy). Port 80 free for SSL. |
| Panel HTTPS port | default 2053 (pick another free port if 2053 is taken; 443 only if nothing else uses it) |
| Admin username / password | password min 8 chars |
| Public host for users | empty = panel domain |
| Server name | shown to users on the subscription page |
| Internal panel port | local only, random by default |
| WireGuard / AmneziaWG / Hysteria2 ports | Hysteria2 can be skipped |
| Telegram bot token + admin IDs | optional, can be set later |

A summary is shown before anything is installed.

## 3. Extra servers (nodes)
Run the same command on the new server and choose **2**. At the end it prints:
`API address`, `Endpoint`, `Node token`. Add them in the panel: **Nodes > Add node**.
No domain on the node? Tick **Self-signed certificate** when adding it.

## 4. Day-to-day: `kanki`
| # | Action |
|---|---|
| 3 | Update to the latest release |
| 4 | Set / change / remove the Telegram sales bot |
| 5 | Reset admin login (also disables 2FA) |
| 6 | Service status |
| 7 | Uninstall |

## Files on the server
| Path | What |
|---|---|
| `/etc/kanki/kanki.env` | install settings (ports, domain, secrets) |
| `/var/lib/kanki/kanki.db` | database |
| `/etc/kanki/tls/` | certificate used by Caddy / Hysteria2 |
| `/etc/wireguard/wg0.conf`, `/etc/amnezia/amneziawg/awg0.conf` | WG / AWG servers |
| `/etc/hysteria/config.yaml` | Hysteria2 |
| `/etc/caddy/Caddyfile` | HTTPS front |

## Locked out?
```bash
kanki-panel reset-admin <user> <pass>   # forgot password / lost 2FA phone
kanki-panel reset-security              # blocked by IP allow/deny list
systemctl restart kanki-panel
```

## Add a tunnel server (Kanki Tunnel)
A server that only carries tunnels (for example in Iran) does **not** get the VPN panel — only a small agent.

1. In the panel: **Tunnels > + Server**, give it a name, press **Create command**.
2. Run the command it shows, as root, on that server (Ubuntu / Debian):
   ```bash
   KANKI_REPO=<user/repo> KANKI_TUNNEL=<id>:<token> KANKI_PANEL=<panel-origin> \
     bash <(curl -fsSL https://raw.githubusercontent.com/<user/repo>/main/install.sh)
   ```
   It installs the `kanki` binary, writes `/etc/kanki/tunnel.env`, turns on BBR and starts the
   `kanki-tunnel` service (`kanki tunnel-agent`). The server appears in the panel as Connected
   within a few seconds.
3. Make a tunnel: **Tunnels > + Tunnel**. Entry = this server, Exit = the panel/VPN server.
   Pick the ports to carry (for the VPN there is a one-tap "VPN ports of the panel server"
   preset). Open the tunnel port in the entry server's cloud firewall.
4. Point your users at the entry server's address (node Endpoint / Public Host) so they connect
   through it; traffic leaves from the exit.

Files on a tunnel server: `/etc/kanki/tunnel.env` (panel URL, id, token), `/var/lib/kanki/tunnels.json`
(last tunnel list, so tunnels survive a reboot), `/etc/systemd/system/kanki-tunnel.service`.
