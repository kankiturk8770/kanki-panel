// ==================================================================== Anti-DPI
// the anti-DPI tunnels page: one-click inbound presets on the Xray engine and the server-to-server
// transports that resist DPI. Everything is made in the normal Xray inbound editor, so links, users
// and limits work like any other inbound.
var AD_METHODS=[
 {pre:'vr',icn:'shield2',tags:['TCP','REALITY','Vision'],dif:1,
  name:'VLESS + REALITY',
  what:'The strongest known anti-DPI method. The server borrows the TLS certificate of a real site (Microsoft, Apple, …) in real time: to the filter the connection IS a TLS session to that site. No domain, no certificate of your own, nothing to block by name.',
  when:'Default choice for everyday filtering. Very fast (xtls-rprx-vision has no inner encryption cost).'},
 {pre:'vx',icn:'shield2',tags:['XHTTP','REALITY'],dif:1,
  name:'VLESS + XHTTP + REALITY',
  what:'REALITY with the XHTTP transport: requests are split and padded, so traffic volume and timing look like ordinary web downloads. Survives traffic-shape analysis better than raw TCP.',
  when:'When plain REALITY works but you also want padding against shape analysis.'},
 {pre:'vw',icn:'srv',tags:['WS','CDN','TLS'],dif:2,
  name:'VLESS + WebSocket behind a CDN',
  what:'The domain fronts through a CDN (ArvanCloud, Cloudflare, …). The filter only sees HTTPS to the CDN edge — the real server IP never appears. Works in whitelist mode if the CDN edge is reachable.',
  when:'When the server IP is burned, or in whitelist mode with a reachable CDN edge. Set “Link and CDN” in the editor: link address = your CDN domain, TLS at the CDN = on.'},
 {pre:'gc',icn:'srv',tags:['gRPC','CDN','TLS'],dif:2,
  name:'VLESS + gRPC behind a CDN',
  what:'Same fronting idea over HTTP/2 gRPC: many streams inside long-lived HTTP/2 connections, which matches API traffic patterns. Needs a CDN that passes gRPC to the origin over HTTPS (ArvanCloud and Cloudflare do); the server uses its own certificate.',
  when:'Alternative fronting when WS is throttled; also good for many parallel streams.'},
 {pre:'tt',icn:'xray',tags:['TCP','TLS'],dif:2,
  name:'Trojan + TLS',
  what:'A plain TLS server with your own domain and certificate; the password lives inside the TLS handshake. Simple and mature, but the SNI is your own domain — a blocked domain kills it.',
  when:'Fallback when REALITY is not possible (old clients) and you have a clean domain.'},
 {pre:'ss',icn:'xray',tags:['TCP','UDP','AEAD'],dif:1,
  name:'Shadowsocks 2022',
  what:'Fully random-looking encrypted traffic with no handshake at all (2022-blake3 methods). Nothing for DPI to fingerprint; carries UDP natively, so it is also a light cover for game/WireGuard UDP.',
  when:'The lightweight stealth UDP cover: no TLS overhead, no handshake, minimal per-packet cost.'}];
var AD_TUNNELS=[
 {icn:'tunnel',name:'Hysteria2 (server link)',href:'#tunnels',
  what:'QUIC-based with Salamander obfuscation: brutal congestion control keeps speed even with loss. In the tunnel wizard pick “Hysteria2” — the panel makes password, certificate and fingerprint pinning itself.',
  when:'Replaces TUIC for users: same family (QUIC, UDP, 0-RTT). For a user-facing Hysteria2 service use the Kanki VPN page.'},
 {icn:'nodes',name:'AmneziaWG',href:'#tunnels',
  what:'WireGuard with junk packets and scrambled headers (Jc/S1/S2/H1-H4): the WG handshake no longer matches the DPI signature. Can itself ride inside WSS / CDN / QUIC / KCP / Game / FakeTCP.',
  when:'When you need a real VPN interface (TUN) between servers or for users.'},
 {icn:'ports',name:'Game (KCP + FEC) / FakeTCP',href:'#tunnels',
  what:'Game adds Reed-Solomon FEC and optional duplication on masked KCP — loss is repaired in flight. FakeTCP wraps UDP inside hand-made TCP packets (udp2raw style) so UDP throttling does not apply.',
  when:'Gaming and WireGuard-over-tunnel: lowest visible loss, and UDP that looks like TCP.'}];
function p_antidpi(){$('#pg').innerHTML='<div class="ph"><div><h2>'+ic('security',22)+' '+t('Advanced anti-DPI tunnels')+'</h2><p>'+t('One-click inbounds with the methods that resist DPI: REALITY, WS/gRPC behind a CDN, Shadowsocks 2022 — plus the server-link transports')+'</p></div><button class="btn" onclick="xrInbound()">+ '+t('Custom inbound')+'</button></div>'+
 '<div class="card"><h3>'+t('User inbounds (Xray)')+'</h3><p class="sub" style="margin:0 0 12px">'+t('Pick a method: the inbound editor opens with the right settings filled in. Then press Save — the panel makes keys, certificates and user links by itself.')+'</p>'+
 '<div class="g2">'+AD_METHODS.map(function(m,i){return '<div class="box" style="margin:0"><b>'+esc(m.name)+'</b> <span class="muted ltr" style="font-size:12px">'+m.tags.map(function(x){return '<em class="ttg">'+x+'</em>'}).join(' ')+'</span>'+
  '<small class="muted" style="display:block;margin:6px 0">'+t(m.what)+'</small>'+
  '<small style="display:block;margin:0 0 8px;color:var(--info)">'+t('When')+': '+t(m.when)+'</small>'+
  '<button class="b2 sm" style="width:100%" onclick="adNew(\''+m.pre+'\')">'+ic('plus',14)+' '+t('Make this inbound')+'</button></div>'}).join('')+'</div></div>'+
 '<div class="card"><h3>'+t('Server-to-server transports')+'</h3><p class="sub" style="margin:0 0 12px">'+t('These live in the tunnel wizard; they carry whole VPNs between your Iran and foreign servers.')+'</p>'+
 '<div class="g2">'+AD_TUNNELS.map(function(m){return '<div class="box" style="margin:0"><b>'+esc(m.name)+'</b><small class="muted" style="display:block;margin:6px 0">'+t(m.what)+'</small>'+
  '<small style="display:block;margin:0 0 8px;color:var(--info)">'+t('When')+': '+t(m.when)+'</small>'+
  '<a class="b2 sm" style="width:100%;text-align:center" href="'+m.href+'">'+t('Open the tunnels')+'</a></div>'}).join('')+'</div></div>'+
 '<div class="card"><h3>'+t('Which one, when?')+'</h3><div class="sub" style="line-height:2">'+
  '🟢 '+t('Normal filtering:')+' <b>VLESS + REALITY</b> · '+t('fastest, nothing to maintain')+'<br>'+
  '🟡 '+t('Heavy filtering / burned IPs:')+' <b>VLESS + WS or gRPC behind a CDN</b> · '+t('the server IP hides behind the edge')+'<br>'+
  '🔴 '+t('Whitelist mode (only domestic sites open):')+' <b>'+t('the CDN transport of the tunnels + an ArvanCloud domain')+'</b> · '+t('see the whitelist guide in the tunnel wizard')+'<br>'+
  '🎮 '+t('Gaming / UDP:')+' <b>Shadowsocks 2022</b> '+t('for users')+' · <b>Game / FakeTCP</b> '+t('between the servers')+'<br>'+
  'ℹ️ '+t('TUIC and ShadowTLS are not in Xray-core; Hysteria2 (QUIC + obfs) and the hq transport cover the same ground.')+'</div></div>'}
function adNew(pre){if(typeof xrInbound!='function')return toast(t('Xray page is not loaded yet'),1);xrInbound();
 var n=0,iv=setInterval(function(){var b=document.querySelector('[data-pre="'+pre+'"]');if(b){b.click();toast(t('Settings are filled in: check the port and press Save'));clearInterval(iv)}else if(++n>50)clearInterval(iv)},100)}

