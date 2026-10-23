# Installation guide

## 1. Publish the code
1. Create a **public** GitHub repo and push this project to the `main` branch.
2. Open the **Actions** tab and wait for the `build` workflow to finish (green).
3. **Releases** now has a `latest` release with `kanki-panel`, `kanki-panel.sha256` and `version.txt`.

## 2. Main panel server
Ubuntu 22.04 / 24.04, as root:
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/kankiturk8770/kanki-panel/main/install.sh)
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

## 3. Extra servers
The panel runs on one server; every other server is a node of it.
1. In the panel: **Servers > Add server**. Give it a name, pick Abroad or Inside Iran, optionally a domain (for a
   real SSL certificate), and whether it serves VPN users (an Iran relay: off).
2. Run the one command it shows on the new server, as root (Ubuntu / Debian). It installs everything: the server
   agent (tunnels, Xray, Kanki DNS) and the VPN part (WireGuard, AmneziaWG, Hysteria2, KANKI MIX), on ports no
   other server of the panel uses. The installer and the program come from the panel itself (GitHub second).
3. The card shows «agent connected» and «VPN part installed». From then on everything is switched on in the panel.

Servers added before 3.9 have only one of the two parts: press **Install** / **Install VPN** on their card.

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

## A tunnel entry (for example in Iran)
1. Add it like any server (**Servers > Add server**, Inside Iran). Its VPN is installed but serves nobody.
   On the server the agent runs as the `kanki-tunnel` service, with `/etc/kanki/tunnel.env`.
2. Make a tunnel: **Tunnels > + Tunnel**. Entry = this server, Exit = the panel/VPN server.
   Pick the ports to carry (for the VPN there is a one-tap "VPN ports of the panel server"
   preset). Open the tunnel port in the entry server's cloud firewall.
4. Point your users at the entry server's address (node Endpoint / Public Host) so they connect
   through it; traffic leaves from the exit.

Files on a tunnel server: `/etc/kanki/tunnel.env` (panel URL, id, token), `/var/lib/kanki/tunnels.json`
(last tunnel list, so tunnels survive a reboot), `/etc/systemd/system/kanki-tunnel.service`.
