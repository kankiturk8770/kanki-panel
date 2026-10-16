// Kanki Panel: the Advanced anti-DPI tunnels page (v3.5.3).
// Curated one-click inbound presets on top of the Xray engine, plus the
// server-to-server transports that resist DPI. Everything here is created
// through the normal Xray inbound editor, so links, users and limits work
// the same as any other inbound.
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
 '<div class="g2">'+AD_METHODS.map(function(m,i){return '<div class="box" style="margin:0"><b>'+esc(m.name)+'</b> <span class="muted ltr" style="font-size:11px">'+m.tags.map(function(x){return '<em class="ttg">'+x+'</em>'}).join(' ')+'</span>'+
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
// Persian text: added to FA by KEXT() once the main script has defined it (it loads after this file)
var AD_FA={"Advanced anti-DPI tunnels":"تانل‌های پیشرفته ضد DPI","Custom inbound":"اینباند سفارشی","Make this inbound":"ساخت این اینباند","When":"کی","Open the tunnels":"باز کردن تانل‌ها","User inbounds (Xray)":"اینباند کاربران (Xray)","Server-to-server transports":"انتقال‌های سرور‌به‌سرور","Which one, when?":"کدام، چه موقع؟",
 "One-click inbounds with the methods that resist DPI: REALITY, WS/gRPC behind a CDN, Shadowsocks 2022 — plus the server-link transports":"اینباند یک‌کلیکی با روش‌های مقاوم در برابر DPI: REALITY، WS/gRPC پشت CDN، Shadowsocks 2022 — به‌همراه انتقال‌های سرور‌به‌سرور",
 "Pick a method: the inbound editor opens with the right settings filled in. Then press Save — the panel makes keys, certificates and user links by itself.":"یک روش را انتخاب کن: ویرایشگر اینباند با تنظیمات درست باز می‌شود. بعد ذخیره را بزن — پنل خودش کلیدها، گواهی‌ها و لینک کاربران را می‌سازد.",
 "These live in the tunnel wizard; they carry whole VPNs between your Iran and foreign servers.":"این‌ها در ویزارد تانل هستند؛ VPN کامل را بین سرور ایران و خارج حمل می‌کنند.",
 "Settings are filled in: check the port and press Save":"تنظیمات پر شد: پورت را چک کن و ذخیره را بزن","Xray page is not loaded yet":"صفحه Xray هنوز بارگذاری نشده",
 "The strongest known anti-DPI method. The server borrows the TLS certificate of a real site (Microsoft, Apple, …) in real time: to the filter the connection IS a TLS session to that site. No domain, no certificate of your own, nothing to block by name.":"قوی‌ترین روش شناخته‌شده ضد DPI. سرور گواهی TLS یک سایت واقعی (مایکروسافت، اپل و…) را لحظه‌ای قرض می‌گیرد: برای فیلتر، اتصال همان نشست TLS به آن سایت است. نه دامنه لازم است، نه گواهی خودت؛ چیزی برای مسدودکردن با اسم نیست.",
 "Default choice for everyday filtering. Very fast (xtls-rprx-vision has no inner encryption cost).":"انتخاب پیش‌فرض برای فیلترینگ روزمره. خیلی سریع (xtls-rprx-vision هزینهٔ رمزنگاری داخلی ندارد).",
 "REALITY with the XHTTP transport: requests are split and padded, so traffic volume and timing look like ordinary web downloads. Survives traffic-shape analysis better than raw TCP.":"REALITY با انتقال XHTTP: درخواست‌ها تکه‌تکه و پد می‌شوند تا حجم و زمان‌بندی ترافیک شبیه دانلودهای معمولی وب به نظر برسد. در برابر تحلیل شکل ترافیک بهتر از TCP خام دوام می‌آورد.",
 "When plain REALITY works but you also want padding against shape analysis.":"وقتی REALITY ساده کار می‌کند اما پدینگ ضد تحلیل شکل ترافیک هم می‌خواهی.",
 "The domain fronts through a CDN (ArvanCloud, Cloudflare, …). The filter only sees HTTPS to the CDN edge — the real server IP never appears. Works in whitelist mode if the CDN edge is reachable.":"دامنه از پشت CDN (ابرآروان، کلادفلر و…) عبور می‌کند. فیلتر فقط HTTPS به لبهٔ CDN را می‌بیند — آی‌پی واقعی سرور هرگز دیده نمی‌شود. اگر لبهٔ CDN در دسترس باشد، در حالت لیست سفید هم کار می‌کند.",
 "When the server IP is burned, or in whitelist mode with a reachable CDN edge. Set “Link and CDN” in the editor: link address = your CDN domain, TLS at the CDN = on.":"وقتی آی‌پی سرور سوخته، یا در حالت لیست سفید با لبهٔ CDN در دسترس. در ویرایشگر «لینک و CDN» را تنظیم کن: آدرس لینک = دامنهٔ CDN، «TLS روی CDN» = روشن.",
 "Same fronting idea over HTTP/2 gRPC: many streams inside long-lived HTTP/2 connections, which matches API traffic patterns. Needs a CDN that passes gRPC to the origin over HTTPS (ArvanCloud and Cloudflare do); the server uses its own certificate.":"همان ایدهٔ فرانتینگ روی gRPC با HTTP/2: استریم‌های زیاد داخل اتصال‌های HTTP/2 طولانی، شبیه الگوی ترافیک API. به CDN‌ای نیاز دارد که gRPC را با HTTPS به مبدأ برساند (ابرآروان و Cloudflare می‌رسانند)؛ سرور از گواهی خودش استفاده می‌کند.",
 "Alternative fronting when WS is throttled; also good for many parallel streams.":"جایگزین فرانتینگ وقتی WS محدود می‌شود؛ برای استریم‌های موازی زیاد هم خوب است.",
 "A plain TLS server with your own domain and certificate; the password lives inside the TLS handshake. Simple and mature, but the SNI is your own domain — a blocked domain kills it.":"سرور TLS ساده با دامنه و گواهی خودت؛ رمز داخل دست‌دادن TLS است. ساده و بالغ، اما SNI همان دامنهٔ خودت است — با مسدودشدن دامنه می‌میرد.",
 "Fallback when REALITY is not possible (old clients) and you have a clean domain.":"جایگزین وقتی REALITY ممکن نیست (کلاینت قدیمی) و دامنهٔ تمیز داری.",
 "Fully random-looking encrypted traffic with no handshake at all (2022-blake3 methods). Nothing for DPI to fingerprint; carries UDP natively, so it is also a light cover for game/WireGuard UDP.":"ترافیک رمزنگاری‌شدهٔ کاملاً تصادفی به‌نظر بدون هیچ دست‌دادنی (متدهای 2022-blake3). چیزی برای اثرانگشت DPI ندارد؛ UDP را ذاتی حمل می‌کند، پس پوشش سبکی برای UDP گیم/وایرگارد هم هست.",
 "The lightweight stealth UDP cover: no TLS overhead, no handshake, minimal per-packet cost.":"پوشش سبک و مخفی UDP: بدون سربار TLS، بدون دست‌دادن، کمترین هزینهٔ هر بسته.",
 "QUIC-based with Salamander obfuscation: brutal congestion control keeps speed even with loss. In the tunnel wizard pick “Hysteria2” — the panel makes password, certificate and fingerprint pinning itself.":"مبتنی بر QUIC با مبهم‌سازی Salamander: کنترل ازدحام brutal سرعت را حتی با لاست نگه می‌دارد. در ویزارد تانل «Hysteria2» را انتخاب کن — پنل خودش رمز، گواهی و پین اثرانگشت را می‌سازد.",
 "Replaces TUIC for users: same family (QUIC, UDP, 0-RTT). For a user-facing Hysteria2 service use the Kanki VPN page.":"جایگزین TUIC برای کاربران: همان خانواده (QUIC، UDP، ‏0-RTT). برای سرویس Hysteria2 روبه‌کاربر از صفحهٔ Kanki VPN استفاده کن.",
 "WireGuard with junk packets and scrambled headers (Jc/S1/S2/H1-H4): the WG handshake no longer matches the DPI signature. Can itself ride inside WSS / CDN / QUIC / KCP / Game / FakeTCP.":"وایرگارد با بسته‌های جانبی و هدرهای به‌هم‌ریخته (Jc/S1/S2/H1-H4): دست‌دادن WG دیگر با امضای DPI نمی‌خواند. خودش هم می‌تواند داخل WSS / CDN / QUIC / KCP / Game / FakeTCP سوار شود.",
 "When you need a real VPN interface (TUN) between servers or for users.":"وقتی رابط VPN واقعی (TUN) بین سرورها یا برای کاربران لازم است.",
 "Game adds Reed-Solomon FEC and optional duplication on masked KCP — loss is repaired in flight. FakeTCP wraps UDP inside hand-made TCP packets (udp2raw style) so UDP throttling does not apply.":"گیم روی KCP ماسک‌شده FEC رید-سولومون و ارسال دوبارهٔ اختیاری می‌افزاید — لاست در راه ترمیم می‌شود. FakeTCP بسته‌های UDP را داخل TCP دست‌ساز (سبک udp2raw) می‌پیچد تا محدودیت UDP اعمال نشود.",
 "Gaming and WireGuard-over-tunnel: lowest visible loss, and UDP that looks like TCP.":"گیمینگ و وایرگارد روی تانل: کمترین لاست قابل‌مشاهده، و UDP که شبیه TCP است.",
 "Normal filtering:":"فیلترینگ عادی:","Heavy filtering / burned IPs:":"فیلترینگ شدید / آی‌پی سوخته:","Whitelist mode (only domestic sites open):":"حالت لیست سفید (فقط سایت‌های داخلی باز است):","Gaming / UDP:":"گیمینگ / UDP:",
 "fastest, nothing to maintain":"سریع‌ترین، بدون نیاز به نگهداری","the server IP hides behind the edge":"آی‌پی سرور پشت لبه پنهان می‌شود","the CDN transport of the tunnels + an ArvanCloud domain":"انتقال CDN تانل‌ها + یک دامنهٔ ابرآروان","see the whitelist guide in the tunnel wizard":"راهنمای لیست سفید را در ویزارد تانل ببین","for users":"برای کاربران","between the servers":"بین سرورها",
 "TUIC and ShadowTLS are not in Xray-core; Hysteria2 (QUIC + obfs) and the hq transport cover the same ground.":"TUIC و ShadowTLS در هستهٔ Xray نیستند؛ Hysteria2 (QUIC + obfs) و انتقال hq همان کار را می‌کنند."};
