// Kanki Panel extensions (v3.5): the VPN services page (Kanki VPN | Xray), node types, the services part of
// the user form, and the Persian text of the menu, Xray (xray.js) and Kanki DNS (dns.js).
// Loaded before the main script; KEXT() runs once the main script has defined its tables.
function KEXT(){
 PROTOS.push(['xray','Xray'],['dns','DNS']);
 PCOL.xray='#e0a020';PCOL.dns='#2a9df4';
 ICO.dns='<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>';
 ICO.xray='<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>';
 Object.assign(FA,KFA);
 if(window.AD_FA)Object.assign(FA,AD_FA);
}
var KFA={
 // subscription on an Iran server
 "Serve the subscription from an Iran server":"لینک ساب روی سرور ایران",
 "For ISPs that block the panel domain: a tunnel server inside Iran serves the subscription pages with its own SSL and carries them to the panel through a hidden tunnel. Subscription links use it once it works.":"برای اینترنت‌هایی که دامنه‌ی پنل را بسته‌اند: یک سرور تانل داخل ایران صفحه‌های ساب را با SSL خودش می‌دهد و از راه یک تانل مخفی به پنل می‌رساند. وقتی کار کرد، لینک‌های ساب از آن ساخته می‌شوند.",
 "Tunnel server":"سرور تانل","The domain's A record must point to this server's IP":"رکورد A دامنه باید به IP این سرور اشاره کند",
 "Waiting for the server: getting SSL and starting the listener…":"در انتظار سرور: گرفتن SSL و راه‌اندازی…",
 "Tunnel to the panel":"تانل به پنل","down":"قطع",
 // servers inside Iran and abroad
 "Iran servers":"سرورهای ایران","Abroad servers":"سرورهای خارج","Location":"موقعیت سرور","Inside Iran":"داخل ایران","Abroad":"خارج",
 "Location guessed: confirm it in Edit":"موقعیت حدس زده شده: در «ویرایش» تأییدش کن","Location not set: choose it in Edit":"موقعیت مشخص نیست: در «ویرایش» انتخابش کن",
 "Add a tunnel server inside Iran first (Servers), or set its location to Inside Iran.":"اول یک سرور تانل داخل ایران اضافه کن (سرورها)، یا موقعیت سرورت را «داخل ایران» بگذار.",
 "Every server of the panel: Kanki VPN, Xray and Kanki DNS":"همه‌ی سرورهای پنل: VPN کانکی، Xray و DNS کانکی",
 "For the app: games and sanctioned sites":"برای اپ: بازی و سایت‌های تحریمی",
 "Exit server (abroad)":"سرور خروجی (خارج)","Relay (Iran)":"ریلی (ایران)",
 "No Xray server yet: add one in Servers":"هنوز سرور Xray نیست: در «سرورها» اضافه کن",
 "Add or remove DNS servers in Servers":"افزودن و حذف سرور DNS در «سرورها»",
 "and":"و","more inbounds":"اینباند دیگر",
 "Anti-DPI tunnels":"تانل‌های ضد DPI",
 "Certificate changed":"گواهی عوض شده",
 "The node's certificate changed (reinstalled?): run its join command again, or remove and add the node":"گواهی نود عوض شده (دوباره نصب شده؟): دستور اتصال نود را دوباره اجرا کن، یا نود را حذف و دوباره اضافه کن",
 "Not tested, an agent is too old (update it first)":"تست نشد، ایجنت قدیمی است (اول آپدیتش کن)",
 // menu
 "VPN services":"سرویس‌های VPN","All VPN services":"همه‌ی سرویس‌های VPN","Kanki VPN and Xray side by side":"کانکی VPN و Xray کنار هم","Kanki VPN":"کانکی VPN","WireGuard · AmneziaWG · Hysteria2":"WireGuard · AmneziaWG · Hysteria2",
 "VLESS · VMess · Trojan · Shadowsocks":"VLESS · VMess · Trojan · Shadowsocks","Kanki DNS":"دی‌ان‌اس کانکی","Overview":"نمای کلی","Status of the DNS servers":"وضعیت سرورهای DNS","DNS servers":"سرورهای DNS",
 "Exits abroad and relays in Iran":"خروجی‌های خارج و ریلی‌های ایران","Services":"سرویس‌ها","What goes through the DNS":"چه چیزهایی از DNS رد می‌شود","DNS users":"کاربران DNS","Registered addresses and use":"IPهای ثبت‌شده و مصرف",
 "Settings and SSL":"تنظیمات و SSL","Domain, certificate, upstreams":"دامنه، گواهی، DNS بالادست","Tunnels":"تانل‌ها","Sales & support":"فروش و پشتیبانی","System":"سیستم",
 // VPN hub
 "Both kinds of VPN your users get, side by side":"هر دو نوع VPN که کاربرها می‌گیرند، کنار هم","Our own protocols on the nodes":"پروتکل‌های خودمان روی نودها","3X-UI style inbounds":"اینباندها به سبک 3X-UI",
 "Nodes online":"نودهای آنلاین","Manage nodes":"مدیریت نودها","Add node":"افزودن نود","Manage Xray":"مدیریت Xray","New inbound":"اینباند جدید","Users by protocol":"کاربران هر پروتکل",
 "Online now":"الان آنلاین","Users with Xray":"کاربران دارای Xray","Working inbounds":"اینباندهای فعال","Total traffic":"ترافیک کل","No inbound yet.":"هنوز اینباندی نیست.","Make the first one":"اولی را بساز","Main server":"سرور اصلی",
 "Xray is off":"Xray خاموش است","Turn it on":"روشنش کن","Kanki DNS (sanctions)":"دی‌ان‌اس کانکی (رفع تحریم)","Open":"باز کردن",
 // user form
 "Services of this user":"سرویس‌های این کاربر","Everything":"همه","Kanki VPN only":"فقط کانکی VPN","Xray only":"فقط Xray","DNS only":"فقط DNS","Protocols":"پروتکل‌ها","Servers":"سرورها",
 "Links of every Xray inbound go into the subscription":"لینک همه‌ی اینباندهای Xray در ساب می‌آید","Private DNS for sanctioned sites":"DNS اختصاصی برای سایت‌های تحریمی","Is off in the panel":"در پنل خاموش است",
 "No Xray inbound yet":"هنوز اینباند Xray نیست","No DNS server yet":"هنوز سرور DNS نیست","inbounds":"اینباند","on":"روشن",
 // node types
 "Node type":"نوع نود","VPN node":"نود VPN","Xray node":"نود Xray","DNS exit node":"نود DNS خروجی","Smart DNS abroad":"DNS هوشمند در خارج","DNS relay node":"نود ریلی DNS","Iran server in front of a DNS exit":"سرور ایران جلوی DNS خروجی",
 // Xray
 "Xray inbounds for your users: every user with Xray ticked is a client of every inbound":"اینباندهای Xray برای کاربرهای خودت: هر کاربری که تیک Xray دارد کلاینت همه‌ی اینباندهاست",
 "Inbound":"اینباند","Inbounds":"اینباندها","Online clients":"کلاینت‌های آنلاین","Routing and outbounds":"روتینگ و خروجی‌ها","Xray servers":"سرورهای Xray","Add server":"افزودن سرور",
 "Xray is off: nothing runs on the servers and no links go to the users.":"Xray خاموش است: روی سرورها چیزی اجرا نمی‌شود و لینکی به کاربرها نمی‌رسد.",
 "1) Add a server (the panel server or any tunnel server). 2) Make inbounds on it. 3) Tick Xray for a user: the links of every inbound go into the user's subscription, and the traffic counts toward the user's volume.":"۱) یک سرور اضافه کن (سرور پنل یا هر سرور تانل). ۲) روی آن اینباند بساز. ۳) برای کاربر تیک Xray بزن: لینک همه‌ی اینباندها در ساب او می‌آید و ترافیکش از حجم خودش کم می‌شود.",
 "Off":"خاموش","Traffic used up":"حجم تمام شد","Expired":"منقضی","Running":"در حال اجرا","Not running":"اجرا نمی‌شود","Waiting for the server…":"در انتظار سرور…","Panel server":"سرور پنل",
 "All servers":"همه‌ی سرورها","Search":"جستجو","Nothing found":"چیزی پیدا نشد","Fallbacks":"فال‌بک","users only":"کاربر خاص","Traffic":"ترافیک","Clients":"کلاینت‌ها","Expires":"پایان",
 "Links":"لینک‌ها","Copy":"کپی","Reset":"صفر کردن","Delete":"حذف","Edit":"ویرایش","days":"روز",
 "Users whose Xray traffic moved in the last few seconds":"کاربرهایی که در چند ثانیه‌ی اخیر ترافیک Xray داشته‌اند","All users":"همه‌ی کاربرها","Nobody is online right now":"الان کسی آنلاین نیست",
 "Ready-made rules":"قانون‌های آماده","Block private addresses":"مسدود کردن IPهای داخلی","Users cannot reach the server's own network (10.x, 192.168.x …)":"کاربرها به شبکه‌ی داخلی سرور (10.x، 192.168.x …) دسترسی ندارند",
 "Block BitTorrent":"مسدود کردن تورنت","Torrent traffic gets abuse reports to your servers":"تورنت برای سرورهایت گزارش تخلف می‌آورد","Block ads":"مسدود کردن تبلیغات","Ad and tracker domains (geosite:category-ads-all)":"دامنه‌های تبلیغ و ردیاب (geosite:category-ads-all)",
 "Block Iranian sites":"مسدود کردن سایت‌های ایرانی",".ir domains and Iranian addresses do not go through the server: they should be opened directly":"دامنه‌های .ir و IPهای ایران از سرور رد نمی‌شوند: باید مستقیم باز شوند",
 "Outbounds":"خروجی‌ها (اوت‌باند)","Where traffic leaves the server: directly, or on to another server (chain)":"ترافیک از کجا خارج شود: مستقیم، یا ادامه به یک سرور دیگر (زنجیره)","Add outbound":"افزودن خروجی",
 "Default outbound (what no rule catches)":"خروجی پیش‌فرض (هر چه قانونی نگیرد)","Routing rules":"قانون‌های مسیریابی","Checked from top to bottom; the first rule that matches decides":"از بالا به پایین چک می‌شوند؛ اولین قانونی که بخورد تصمیم می‌گیرد",
 "Add rule":"افزودن قانون","Domain strategy":"روش دامنه (Domain strategy)","by name (fastest)":"با اسم (سریع‌ترین)","resolve when no name rule matched":"اگر قانون اسمی نخورد، IP بگیر","always resolve for IP rules":"برای قانون‌های IP همیشه IP بگیر",
 "Advanced: raw JSON":"پیشرفته: JSON خام","Advanced: extra routing rules (JSON array)":"پیشرفته: قوانین مسیریابی اضافه (آرایه‌ی JSON)","Advanced: extra outbounds (JSON array, the first one becomes the default)":"پیشرفته: اوت‌باندهای اضافه (آرایه‌ی JSON، اولی پیش‌فرض می‌شود)",
 "Changes reach the servers within a few seconds of saving":"تغییرات چند ثانیه بعد از ذخیره به سرورها می‌رسد","Save routing":"ذخیره‌ی روتینگ","Block":"مسدود","Direct":"مستقیم",
 "Straight to the internet from this server":"مستقیم از همین سرور به اینترنت","built in":"پیش‌ساخته","Dropped":"دور ریخته می‌شود","port":"پورت","users":"کاربر","Rule":"قانون",
 "No rules yet: everything goes to the default outbound.":"هنوز قانونی نیست: همه چیز به خروجی پیش‌فرض می‌رود.","A rule still sends traffic to this outbound":"هنوز قانونی ترافیک را به این خروجی می‌فرستد",
 "Another server (from its link)":"سرور دیگر (از لینکش)","Direct (freedom)":"مستقیم (freedom)","Block (blackhole)":"مسدود (blackhole)","Edit outbound":"ویرایش خروجی","Tag (name)":"تگ (اسم)","Type":"نوع",
 "Link of the other server (vless, vmess, trojan or ss)":"لینک سرور دیگر (vless، vmess، trojan یا ss)",
 "Typical use: this server is in Iran and the link is of a server abroad, so users connect inside Iran and leave from abroad.":"کاربرد معمول: این سرور در ایران است و لینک مال سرور خارج؛ کاربر داخل ایران وصل می‌شود و از خارج بیرون می‌رود.",
 "Address":"آدرس","Port":"پورت","Username (optional)":"نام کاربری (اختیاری)","Password":"رمز","The whole outbound (JSON object)":"کل اوت‌باند (آبجکت JSON)","Check":"بررسی","OK":"تأیید",
 "an outbound tag is English letters, digits, - and _":"تگ خروجی فقط حروف انگلیسی، عدد، - و _","This tag is already used":"این تگ قبلاً استفاده شده","Press Save routing to apply":"برای اعمال، «ذخیره‌ی روتینگ» را بزن",
 "Edit rule":"ویرایش قانون","Name":"نام","like: AI sites through Germany":"مثلاً: سایت‌های هوش مصنوعی از آلمان","Domains (one per line)":"دامنه‌ها (هر خط یکی)","IP addresses and ranges (one per line)":"IPها و رنج‌ها (هر خط یکی)",
 "Ports":"پورت‌ها","Network":"شبکه","Any":"همه","Sniffed protocol":"پروتکل تشخیص‌داده‌شده","Only from these inbounds":"فقط از این اینباندها","Only for these users":"فقط برای این کاربرها","Send to":"بفرست به",
 "Give the rule at least one condition":"حداقل یک شرط برای قانون بگذار","Settings":"تنظیمات","Xray is on":"Xray روشن است","Off: Xray stops on every server and the links leave the subscriptions":"خاموش: Xray روی همه‌ی سرورها می‌ایستد و لینک‌ها از ساب‌ها حذف می‌شوند",
 "IPv4 only":"فقط IPv4","For servers whose IPv6 does not work well":"برای سرورهایی که IPv6 آن‌ها خوب کار نمی‌کند","Xray-core version":"نسخه‌ی Xray-core","empty = latest":"خالی = آخرین نسخه","A release tag like v26.3.27":"یک تگ ریلیز مثل v26.3.27",
 "Log level":"سطح لاگ","Xray DNS servers (comma separated, empty = the server's own)":"DNSهای Xray (با کاما، خالی = DNS خود سرور)","Save":"ذخیره",
 "Xray can run on the panel server or on any tunnel server. A new server gets a one-line install command.":"Xray روی سرور پنل یا هر سرور تانل اجرا می‌شود. سرور جدید یک دستور نصب یک‌خطی می‌گیرد.",
 "Agent server":"سرور (ایجنت)","New server (install command)":"سرور جدید (دستور نصب)","Server name":"نام سرور","Address for links":"آدرس در لینک‌ها","automatic":"خودکار",
 "A domain or IP the users connect to; empty = the IP the server reports from":"دامنه یا IPی که کاربرها به آن وصل می‌شوند؛ خالی = IPی که سرور از آن گزارش می‌دهد",
 "Config":"کانفیگ","A copy was made (off until you check it)":"کپی ساخته شد (تا چکش نکنی خاموش است)","Reset the traffic of this inbound to zero?":"ترافیک این اینباند صفر شود؟",
 "Users and links":"کاربرها و لینک‌ها","Inactive":"غیرفعال","No address":"آدرس ندارد","No users with Xray yet: tick Xray in a user's form":"هنوز کاربری Xray ندارد: در فرم کاربر تیک Xray را بزن",
 "Add an Xray server first":"اول یک سرور Xray اضافه کن","Basic":"اصلی","Transport":"ترنسپورت","Security":"امنیت","Sniffing":"Sniffing","Link and CDN":"لینک و CDN","Limits and users":"محدودیت و کاربرها",
 "Remark":"نام","Protocol":"پروتکل","Random free port":"پورت آزاد تصادفی","Listen address":"آدرس listen","Method":"روش","Quick setup":"ساخت سریع","random if empty":"خالی = تصادفی",
 "Path":"مسیر (path)","Host":"هاست","Heartbeat (seconds, 0 = off)":"ضربان (ثانیه، ۰ = خاموش)","Mode":"حالت","Padding (bytes)":"پدینگ (بایت)","Service name":"نام سرویس","Authority (in the link)":"Authority (در لینک)",
 "Multi mode (in the link)":"حالت Multi (در لینک)","HTTP header camouflage":"استتار با هدر HTTP","The TCP stream starts like a plain HTTP request (path and Host above)":"اتصال TCP مثل یک درخواست HTTP ساده شروع می‌شود (path و Host بالا)",
 "MTU":"MTU","TTI (ms)":"TTI (میلی‌ثانیه)","Uplink (MB/s)":"آپلود (مگابایت/ثانیه)","Downlink (MB/s)":"دانلود (مگابایت/ثانیه)","Congestion control":"کنترل ازدحام",
 "Accept PROXY protocol":"پذیرش PROXY protocol","Only when nginx / HAProxy in front sends it":"فقط وقتی nginx / HAProxy جلوی سرور آن را می‌فرستد","Flow":"Flow","SNI":"SNI","Lowest TLS version":"کمترین نسخه‌ی TLS","Default":"پیش‌فرض",
 "Refuse unknown SNI":"رد SNI ناشناس","Only connections for the name above are answered":"فقط به اتصال‌های همین اسم جواب داده می‌شود","Certificate":"گواهی","Paste (PEM)":"چسباندن (PEM)","Files on the server":"فایل روی سرور",
 "unchanged":"بدون تغییر","Certificate file":"فایل گواهی","Key file":"فایل کلید","Target (dest)":"مقصد (dest)","Suggestions":"پیشنهادها","Server names":"نام‌های سرور","Short IDs":"Short ID ها","New":"جدید",
 "Private key":"کلید خصوصی","Public key":"کلید عمومی","Largest clock difference (ms, 0 = off)":"بیشترین اختلاف ساعت (میلی‌ثانیه، ۰ = خاموش)","New keys":"کلید جدید","Fingerprint":"اثرانگشت (fp)",
 "Shadowsocks has no TLS or REALITY: its own encryption is enough.":"Shadowsocks نیازی به TLS یا REALITY ندارد: رمزنگاری خودش کافی است.",
 "Read the site name from the traffic (needed for domain rules)":"اسم سایت را از ترافیک بخوان (برای قانون‌های دامنه لازم است)","Look at":"بررسی","Use it for the destination too":"برای مقصد هم استفاده شود",
 "Off = only for routing (recommended)":"خاموش = فقط برای مسیریابی (پیشنهادی)","Metadata only":"فقط متادیتا","Do not read the content, only the connection details":"محتوا خوانده نشود، فقط مشخصات اتصال",
 "What the users' links say. Leave empty unless a CDN or another address is in front of the server.":"چیزی که در لینک کاربرها نوشته می‌شود. خالی بگذار مگر CDN یا آدرس دیگری جلوی سرور باشد.",
 "Link address":"آدرس لینک","Link port":"پورت لینک","Link SNI":"SNI لینک","TLS at the CDN":"TLS در CDN","The CDN has the certificate; the server itself speaks plain WS / gRPC / XHTTP":"گواهی دست CDN است؛ خود سرور WS / gRPC / XHTTP ساده دارد",
 "Total traffic of the inbound (GB, 0 = unlimited)":"حجم کل اینباند (گیگ، ۰ = نامحدود)","Stops on (empty = never)":"تاریخ توقف (خالی = هرگز)",
 "When the traffic is used up or the date passes, the inbound stops by itself; users keep their own limits as well.":"وقتی حجم تمام شود یا تاریخ برسد، اینباند خودش می‌ایستد؛ محدودیت‌های خود کاربرها هم سر جایش است.",
 "Only these users (empty = everyone with Xray)":"فقط این کاربرها (خالی = همه‌ی دارندگان Xray)","All":"همه","None":"هیچ",
 "VLESS / Trojan over TCP with TLS: traffic that is not ours goes to these destinations (a website, another service).":"VLESS / Trojan روی TCP با TLS: ترافیکی که مال ما نیست به این مقصدها می‌رود (یک سایت، سرویس دیگر).",
 "Add fallback":"افزودن فال‌بک","Destination (port or address:port)":"مقصد (پورت یا آدرس:پورت)","ALPN":"ALPN","SNI (name)":"SNI (اسم)","No fallbacks":"فال‌بکی نیست",
 "Domain of this server (or IP)":"دامنه‌ی این سرور (یا IP)","Users connect to this address; empty = the IP the server reports from":"کاربرها به این آدرس وصل می‌شوند؛ خالی = IPی که سرور از آن گزارش می‌دهد",
 "Get SSL for this domain by itself":"گرفتن خودکار SSL برای این دامنه","The panel points the domain at this server and gets a Let's Encrypt certificate; every TLS inbound of this server uses it. Renewed every 60 days.":"پنل دامنه را به همین سرور وصل می‌کند و از Let's Encrypt گواهی می‌گیرد؛ همه‌ی اینباندهای TLS این سرور از آن استفاده می‌کنند. هر ۶۰ روز تمدید می‌شود.",
 "For SSL by itself, first set the DNS provider and API token (Xray › Settings or Kanki DNS › Settings and SSL).":"برای SSL خودکار، اول سرویس DNS و توکن API را بگذار (Xray › تنظیمات یا DNS کانکی › تنظیمات و SSL).",
 "Saved: getting SSL (about a minute)":"ذخیره شد: در حال گرفتن SSL (حدود یک دقیقه)","Working…":"در حال انجام…","error":"خطا","waiting":"در انتظار",
 "Empty SNI = the server's domain and certificate":"SNI خالی = دامنه و گواهی خود سرور","This server has no domain: write one in SNI, or give the server a domain (Edit server).":"این سرور دامنه ندارد: یا در SNI دامنه بنویس، یا برای سرور دامنه بگذار (ویرایش سرور).",
 "Domain of this DNS server":"دامنه‌ی این سرور DNS","Empty = label + DNS domain. The panel points it (and *.) at this server and gets the SSL for it by itself.":"خالی = برچسب + دامنه‌ی DNS. پنل آن را (و *.) به همین سرور وصل می‌کند و SSLش را خودش می‌گیرد.",
 "For SSL by itself, set the DNS provider and API token in Settings and SSL.":"برای SSL خودکار، سرویس DNS و توکن API را در «تنظیمات و SSL» بگذار.", "A pasted certificate is used on every DNS server":"یک گواهی دستی روی همه‌ی سرورهای DNS استفاده می‌شود",
 "Remove it (back to certbot)":"حذفش کن (برگشت به certbot)",
 "Automatic: certbot on each DNS server":"خودکار: certbot روی هر سرور DNS",
 "Each server gets a Let's Encrypt certificate for its own name and renews it by itself":"هر سرور برای اسم خودش از Let's Encrypt گواهی می‌گیرد و خودش تمدید می‌کند",
 "Nothing to set: write each server's domain (or label + DNS domain) and point it to the server. Kanki DNS answers Let's Encrypt itself on port 80, so DNS does not stop. The SSL state of every server is on its card.":"تنظیمی لازم نیست: دامنه‌ی هر سرور را بنویس (یا برچسب + دامنه‌ی DNS) و به همان سرور وصل کن. خود سرویس DNS روی پورت ۸۰ جواب Let's Encrypt را می‌دهد، پس DNS قطع نمی‌شود. وضعیت SSL هر سرور روی کارت خودش است.",
 "Paste a certificate instead (optional)":"به‌جایش گواهی دستی بگذار (اختیاری)",
 "Paste the certificate first":"اول گواهی را بچسبان",
 "Empty = label + DNS domain. Point the domain to this server: its SSL is taken on the server with certbot by itself.":"خالی = برچسب + دامنه‌ی DNS. دامنه را به همین سرور وصل کن: SSL آن را certbot روی خود سرور می‌گیرد.",
 "1) The user taps «Unblock» in the Kanki app: the app registers the phone and uses your DNS. 2) Names of sanctioned services (games, AI, developer sites …) are answered with your server's IP and the server passes those connections on (SNI proxy), so games and sites open; everything else goes direct at full speed. 3) A relay inside Iran sends them to an exit abroad through a hidden Kanki tunnel.":"۱) کاربر در برنامه‌ی کانکی «رفع تحریم» را می‌زند: برنامه گوشی را ثبت می‌کند و از DNS شما استفاده می‌کند. ۲) اسم سرویس‌های تحریمی (بازی، هوش مصنوعی، سایت‌های برنامه‌نویسی …) با IP سرور شما جواب می‌گیرند و سرور اتصالشان را رد می‌کند (SNI پروکسی)، پس بازی و سایت باز می‌شود؛ بقیه مستقیم و با سرعت کامل می‌روند. ۳) ریلی داخل ایران آن‌ها را با تانل مخفی کانکی به خروجی خارج می‌فرستد.",
 "Taken with certbot on the server":"با certbot روی خود سرور گرفته می‌شود",
 "certbot on this server gets a Let's Encrypt certificate for the domain (no e-mail needed) and renews it by itself; every TLS inbound of this server uses it. The domain must point to this server. Whatever uses port 80 (Caddy, nginx, an inbound …) is set aside for a few seconds and comes back by itself.":"certbot روی همین سرور برای دامنه از Let's Encrypt گواهی می‌گیرد (ایمیل لازم نیست) و خودش تمدید می‌کند؛ همه‌ی اینباندهای TLS این سرور از آن استفاده می‌کنند. دامنه باید به همین سرور وصل باشد. هر چه روی پورت ۸۰ باشد (Caddy، nginx، یک اینباند …) چند ثانیه کنار می‌رود و خودش برمی‌گردد.",
 "renewed by itself":"خودش تمدید می‌شود",
 "certbot on the server gets a Let's Encrypt certificate for this domain by itself (no e-mail needed) and renews it. The domain must point to the server; whatever uses port 80 is set aside for a few seconds and comes back by itself. The links use the domain.":"certbot روی سرور خودش برای این دامنه از Let's Encrypt گواهی می‌گیرد (ایمیل لازم نیست) و تمدید می‌کند. دامنه باید به سرور وصل باشد؛ هر چه روی پورت ۸۰ باشد چند ثانیه کنار می‌رود و خودش برمی‌گردد. لینک‌ها با همین دامنه ساخته می‌شوند.",
 "Certificate error":"خطای گواهی","Waiting for the certificate":"در انتظار گواهی","Automatic (Let's Encrypt)":"خودکار (Let's Encrypt)","renewed by itself every 60 days":"هر ۶۰ روز خودش تمدید می‌شود",
 "Get again":"گرفتن دوباره","Try now":"الان امتحان کن","Write the domain in SNI":"دامنه را در SNI بنویس",
 "Write the domain in SNI above. The panel points the domain at this server and gets a Let's Encrypt certificate with a DNS challenge (works for servers inside Iran too, nothing has to be open on the server), and renews it every 60 days. The links use the domain.":"دامنه را در SNI بالا بنویس. پنل دامنه را به همین سرور وصل می‌کند و با چالش DNS از Let's Encrypt گواهی می‌گیرد (برای سرورهای داخل ایران هم کار می‌کند و لازم نیست چیزی روی سرور باز باشد) و هر ۶۰ روز تمدید می‌کند. لینک‌ها با همین دامنه ساخته می‌شوند.",
 "DNS provider":"سرویس DNS","the same as Kanki DNS":"همان DNS کانکی","First set the DNS provider and its API token in Xray › Settings.":"اول سرویس DNS و توکن API را در Xray › تنظیمات بگذار.",
 "Automatic certificates":"گواهی خودکار","For TLS inbounds with \"Automatic\": the panel sets the domain's A record and gets a Let's Encrypt certificate with a DNS challenge through this API. Empty = the same provider as Kanki DNS.":"برای اینباندهای TLS با حالت «خودکار»: پنل با این API رکورد A دامنه را می‌سازد و با چالش DNS از Let's Encrypt گواهی می‌گیرد. خالی = همان سرویس DNS کانکی.",
 "Same as Kanki DNS":"همان DNS کانکی","Kanki DNS uses":"DNS کانکی از این استفاده می‌کند:","Kanki DNS has no provider yet either":"DNS کانکی هم هنوز سرویس DNS ندارد",
 "Point the domain at the server":"وصل کردن دامنه به سرور","Off when you manage the A record yourself (for example behind a CDN)":"اگر رکورد A را خودت مدیریت می‌کنی (مثلاً پشت CDN) خاموش کن",
 "API token":"توکن API","E-mail for Let's Encrypt (optional)":"ایمیل برای Let's Encrypt (اختیاری)", "Filled in: check the Security tab":"پر شد: تب امنیت را چک کن","the port is required":"پورت لازم است","Clients online":"کلاینت آنلاین",
 // Kanki DNS
 "Private smart DNS for your subscribers: sanctioned services go through your servers, everything else goes direct":"DNS هوشمند اختصاصی مشتری‌ها: سرویس‌های تحریمی از سرورهای شما رد می‌شوند و بقیه مستقیم",
 "Add relay":"افزودن ریلی","Add DNS server":"افزودن سرور DNS","Status":"وضعیت","On":"روشن","Running servers":"سرورهای در حال اجرا","Users with DNS":"کاربران دارای DNS","Allowed addresses":"IPهای مجاز",
 "Queries":"درخواست‌ها","routed":"مسیردهی‌شده", "Query log":"لاگ درخواست‌ها","Every name your subscribers asked, and whether it went through your server (routed) or straight to the site (direct). Kept in the panel\'s memory; a restart clears it.":"همه‌ی دامنه‌هایی که مشتری‌ها پرسیده‌اند و اینکه از سرور شما رد شده (مسیردهی‌شده) یا مستقیم به سایت رفته (مستقیم). در حافظه‌ی پنل نگه داشته می‌شود و با ری‌استارت پاک می‌شود.",
 "Refresh":"بروزرسانی","Clear":"پاک کردن","All users":"همه‌ی کاربران","All queries":"همه‌ی درخواست‌ها","Routed only":"فقط مسیردهی‌شده","Direct only":"فقط مستقیم","Grouped by name":"گروه‌بندی بر اساس دامنه","Each query":"تک‌تک درخواست‌ها",
 "direct":"مستقیم","kept":"نگه‌داشته","times":"بار","Clear the whole query log?":"کل لاگ درخواست‌ها پاک شود؟",
 "Nothing yet: queries show up here a few seconds after a subscriber uses DNS (DNS servers must run v3.5.8 or newer).":"هنوز چیزی نیست: چند ثانیه بعد از اینکه مشتری از DNS استفاده کند اینجا می‌آید (سرورهای DNS باید نسخه‌ی ۳.۵.۸ یا جدیدتر باشند).",
"DNS is off: nothing runs on the servers.":"DNS خاموش است: روی سرورها چیزی اجرا نمی‌شود.",
 "No DNS domain yet: encrypted DNS (DoT / DoH) needs one.":"هنوز دامنه‌ی DNS نداری: DNS رمزدار (DoT / DoH) به آن نیاز دارد.",
 "No certificate yet: DoT / DoH and registering by link do not work without it.":"هنوز گواهی نیست: DoT / DoH و ثبت با لینک بدون آن کار نمی‌کند.","Add an exit DNS server first":"اول یک سرور DNS خروجی اضافه کن",
 "Path of the traffic":"مسیر ترافیک","Manage":"مدیریت","Busiest services":"پرمصرف‌ترین سرویس‌ها","Routed names asked for most since the DNS services started":"دامنه‌هایی که از شروع سرویس DNS بیشتر از همه پرسیده شده‌اند",
 "Check a domain":"بررسی یک دامنه","Does this site go through Kanki DNS, and which service lists it?":"این سایت از DNS کانکی رد می‌شود؟ در کدام سرویس است؟",
 "How it works":"چطور کار می‌کند",
 "1) A user's phone uses your DNS (Private DNS with the user's own address). 2) Names of sanctioned services (games, AI, developer sites …) are answered with your server's IP; everything else is answered normally and goes direct. 3) Your server passes those connections on without opening them. A relay inside Iran sends them to an exit abroad through a hidden Kanki tunnel.":"۱) گوشی کاربر از DNS شما استفاده می‌کند (Private DNS با آدرس اختصاصی خودش). ۲) اسم سرویس‌های تحریمی (بازی، هوش مصنوعی، سایت‌های برنامه‌نویسی …) با IP سرور شما جواب داده می‌شود؛ بقیه عادی جواب می‌گیرند و مستقیم می‌روند. ۳) سرور شما آن اتصال‌ها را بدون باز کردن رمز رد می‌کند. ریلی داخل ایران آن‌ها را با یک تانل مخفی کانکی به خروجی خارج می‌فرستد.",
 "Internet":"اینترنت","Nothing yet":"هنوز چیزی نیست","Goes through Kanki DNS":"از DNS کانکی رد می‌شود","Goes direct (not routed)":"مستقیم می‌رود (مسیردهی نمی‌شود)","this group is off":"این گروه خاموش است",
 "your extra domains":"دامنه‌های اضافه‌ی خودت","Add to extra domains":"افزودن به دامنه‌های اضافه","Turn this group on":"روشن کردن این گروه","Saved":"ذخیره شد","Exit":"خروجی","Iran":"ایران","issued":"صادر شده","none yet":"هنوز ندارد",
 "Working… about a minute":"در حال انجام… حدود یک دقیقه","Last error":"آخرین خطا","Relay (inside Iran)":"ریلی (داخل ایران)","Exit (abroad)":"خروجی (خارج)","no name":"بدون اسم",
 "Hidden from subscribers":"مخفی از مشتری‌ها","From cache":"از کش","Refused (not a subscriber)":"رد شده (غیر مشتری)","Connections":"اتصال‌ها","Remove from DNS":"حذف از DNS",
 "Search services or domains":"جستجوی سرویس یا دامنه","Save services":"ذخیره سرویس‌ها",
 "Groups marked \"only on request\" stay off until you turn them on. Some names cannot be routed (they check the address).":"گروه‌های «فقط با درخواست» تا روشنشان نکنی خاموش می‌مانند. بعضی اسم‌ها قابل مسیردهی نیستند (آدرس را چک می‌کنند).",
 "All on":"همه روشن","All off":"همه خاموش","cannot be routed":"قابل مسیردهی نیست","only on request":"فقط با درخواست","Extra domains":"دامنه‌های اضافه","One per line; their subdomains are routed too":"هر خط یکی؛ زیردامنه‌هایشان هم مسیردهی می‌شوند",
 "routed names now":"دامنه‌ی مسیردهی‌شده","Addresses each user registered (allowed now) and their queries since the DNS services started":"IPهایی که هر کاربر ثبت کرده (الان مجاز) و درخواست‌هایش از شروع سرویس DNS",
 "No user has DNS yet: tick DNS in a user's form":"هنوز کاربری DNS ندارد: در فرم کاربر تیک DNS را بزن","queries":"درخواست","addresses":"IP","Copy the Private DNS address":"کپی آدرس Private DNS","Forget addresses":"پاک کردن IPها",
 "The user's phone registers again by itself; someone else using the address loses access. Continue?":"گوشی کاربر خودش دوباره ثبت می‌کند؛ اگر کس دیگری از این IP استفاده می‌کند دسترسی‌اش قطع می‌شود. ادامه بدهم؟",
 "Done: servers forget them within a few seconds":"انجام شد: سرورها تا چند ثانیه‌ی دیگر فراموششان می‌کنند","DNS is on":"DNS روشن است","Off: DNS stops on every server and leaves the subscriptions":"خاموش: DNS روی همه‌ی سرورها می‌ایستد و از ساب‌ها حذف می‌شود",
 "DNS domain":"دامنه‌ی DNS","Each DNS server gets a name under it, like de.dns.example.com":"هر سرور DNS یک اسم زیر آن می‌گیرد، مثل de.dns.example.com","Upstream resolvers":"DNSهای بالادست",
 "AdGuard (no ads)":"AdGuard (بدون تبلیغ)","An allowed address stays open for (hours)":"مدت باز ماندن IP ثبت‌شده (ساعت)","After this long without the user's app registering again, the address is closed":"اگر تا این مدت اپ کاربر دوباره ثبت نکند، IP بسته می‌شود",
 "Certificate and records":"گواهی SSL و رکوردها","Provider":"سرویس DNS دامنه","Manual (paste a certificate)":"دستی (گواهی را خودت بگذار)",
 "The panel makes the A records of every server (and *.) with this API token, then gets a wildcard certificate from Let's Encrypt with a DNS challenge and renews it every 60 days. Works for servers inside Iran too.":"پنل با این توکن API رکورد A هر سرور (و *.) را می‌سازد، بعد با چالش DNS از Let's Encrypt گواهی Wildcard می‌گیرد و هر ۶۰ روز تمدید می‌کند. برای سرورهای داخل ایران هم کار می‌کند.",
 "API token":"توکن API","E-mail for Let's Encrypt (optional)":"ایمیل برای Let's Encrypt (اختیاری)","Set records and get the certificate now":"الان رکوردها را بساز و گواهی بگیر",
 "Certificate (PEM, full chain)":"گواهی (PEM، زنجیره‌ی کامل)","Private key (PKCS#8 PEM)":"کلید خصوصی (PEM)",
 "Ports 53, 80, 443 and 853 must be free on this server: give DNS its own server.":"پورت‌های ۵۳، ۸۰، ۴۴۳ و ۸۵۳ روی این سرور باید آزاد باشند: برای DNS سرور جدا بگذار.",
 "Label":"برچسب","Answer IP":"IP پاسخ","Its exit":"خروجی آن","Transport to the exit":"ترنسپورت تا خروجی","Tunnel port on the relay":"پورت تانل روی ریلی","Note for subscribers":"یادداشت برای مشتری‌ها",
 "like: best on Irancell":"مثلاً: روی ایرانسل بهتر است","For repairs: the server keeps running but is not offered":"برای تعمیر: سرور روشن می‌ماند ولی به مشتری پیشنهاد نمی‌شود","Done":"انجام شد"};
// ---------------------------------------------------------------- the VPN services page: Kanki VPN | Xray
function p_vpn(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('VPN services')+'</h2><p>'+t('Both kinds of VPN your users get, side by side')+'</p></div></div><div class="vhub"><div class="vside" id="vh_k">'+t('Loading…')+'</div><div class="vside" id="vh_x">'+t('Loading…')+'</div></div>'+
  '<div class="vside" id="vh_d" style="margin-top:14px"></div>';
 var go=function(){Promise.all([api('GET','/api/nodes').catch(function(){return []}),api('GET','/api/overview').catch(function(){return {}}),api('GET','/api/xray').catch(function(){return null}),api('GET','/api/dns').catch(function(){return null})]).then(function(r){if(S.page!='vpn')return;S.nodes=r[0]||[];if(r[2])XR.d=r[2];if(r[3])DN.d=r[3];vhKanki(r[0]||[],r[1]||{});vhXray(r[2]);vhDns(r[3])})};
 go();clearInterval(S.timer);S.timer=setInterval(function(){if(document.visibilityState=='visible'&&!$('#modal').classList.contains('on'))go()},8000)}
function vhHead(icon,title,sub,btns){return '<div class="vh"><span class="phi">'+ic(icon,24)+'</span><div><b>'+t(title)+'</b><small>'+t(sub)+'</small></div><span class="sp"></span><div class="vhb">'+(btns||'')+'</div></div>'}
function vhBtn(href,label,on){return '<a class="b2 sm" href="'+href+'"'+(on?' onclick="'+on+';return false"':'')+'>'+label+'</a>'}
function vhKanki(nodes,o){var up=nodes.filter(function(n){return n.id=='local'||n.online}).length,pr=o.protocols||{};
 $('#vh_k').innerHTML=vhHead('nodes','Kanki VPN','WireGuard · AmneziaWG · Hysteria2',vhBtn('#nodes',t('Servers')))+
  '<div class="kv"><div><small>'+t('Nodes online')+'</small><b>'+N(up)+' / '+N(nodes.length)+'</b></div><div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N(o.online||0)+'</b></div><div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(o.traffic_gb||0)+' GB</b></div></div>'+
  '<label class="f">'+t('Users by protocol')+'</label><div class="chs" style="display:flex;gap:6px;flex-wrap:wrap">'+[['wg','WireGuard'],['awg','AmneziaWG'],['hy2','Hysteria2']].map(function(p){return '<span class="chipx a" style="font-size:12px;padding:4px 10px">'+p[1]+' · '+N(pr[p[0]]||0)+'</span>'}).join('')+'</div>'+
  nodes.map(function(n){var s=nState(n),loc=n.id=='local';return '<div class="vrow"><span class="dot '+s.c+'"></span><div class="nm"><b>'+esc(n.name)+(loc?' <span class="rotb">'+t('Main server')+'</span>':'')+'</b><small class="ltr">'+esc(loc?'local':String(n.address||'').replace(/^https?:\/\//,''))+'</small></div><span class="chipx">'+N(n.users||0)+' '+t('users')+'</span></div>'}).join('')+
''}
function vhXray(d){var el=$('#vh_x');if(!d){el.innerHTML=vhHead('xray','Xray','VLESS · VMess · Trojan · Shadowsocks')+'<p class="muted">—</p>';return}
 var act=d.inbounds.filter(function(x){return x.enabled&&!x.state}).length,tot=d.inbounds.reduce(function(a,b){return a+(+b.traffic||0)},0);
 var more=d.inbounds.length-5;
 el.innerHTML=vhHead('xray','Xray','VLESS · VMess · Trojan · Shadowsocks','<span class="chipx '+(d.on?'g':'r')+'">'+(d.on?t('On'):t('Off'))+'</span>'+vhBtn('#',ic('plus',13)+' '+t('New inbound'),'xrInbound()')+vhBtn('#xray/inbounds',t('Open')))+
  (d.on?'':'<div class="warnbox">'+t('Xray is off')+' · <a href="#xray/settings">'+t('Turn it on')+'</a></div>')+
  '<div class="kv"><div><small>'+t('Working inbounds')+'</small><b>'+N(act)+' / '+N(d.inbounds.length)+'</b></div><div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N((d.online||[]).length)+'</b></div><div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(bytes(tot))+'</b></div></div>'+
  (d.inbounds.length?d.inbounds.slice(0,5).map(function(ib){return xrMiniRow(ib)}).join(''):'<p class="muted">'+t('No inbound yet.')+'</p>')+
  (more>0?'<a class="vmore" href="#xray/inbounds">'+t('and')+' '+N(more)+' '+t('more inbounds')+' ›</a>':'')}
function vhDns(d){var el=$('#vh_d');if(!d){el.style.display='none';return}var run=d.servers.filter(function(x){return x.status&&x.status.active}).length;
 el.innerHTML=vhHead('dns','Kanki DNS (sanctions)','Private DNS for sanctioned sites','<span class="chipx '+(d.on?'g':'r')+'">'+(d.on?t('On'):t('Off'))+'</span>'+vhBtn('#dns/overview',t('Open')))+
  '<div class="kv"><div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(d.servers.length)+'</b></div><div><small>'+t('Users with DNS')+'</small><b>'+N(d.users)+'</b></div><div><small>'+t('Allowed addresses')+'</small><b>'+N(d.servers.reduce(function(a,x){return a+(+(x.status||{}).allowed||0)},0))+'</b></div></div>'}

// ---------------------------------------------------------------- user form: what the user gets, service by service
function ufServices(protos,un){var has=function(p){return protos.indexOf(p)>=0},vpnOn=has('wg')||has('awg')||has('hy2');
 var card=function(key,icon,title,sub,on,body,head){return '<div class="ufsvc'+(on?' on':'')+'" data-svc="'+key+'"><div class="hd"><span class="ni">'+ic(icon,18)+'</span><div class="nm"><b>'+t(title)+'</b><small>'+t(sub)+'</small></div>'+(head||'')+'</div><div class="bd3">'+body+'</div></div>'};
 var nodes=S.nodes||[];
 var h='<label class="f" style="margin-top:12px">'+t('Services of this user')+'</label><div class="chipset" id="uf_pre"><button type="button" data-pre="all">'+t('Everything')+'</button><button type="button" data-pre="vpn">'+t('Kanki VPN only')+'</button><button type="button" data-pre="xray">'+t('Xray only')+'</button><button type="button" data-pre="dns">'+t('DNS only')+'</button></div>';
 h+=card('vpn','nodes','Kanki VPN','WireGuard · AmneziaWG · Hysteria2',vpnOn,
  '<div class="ckrow">'+[['wg','WireGuard'],['awg','AmneziaWG'],['hy2','Hysteria2']].map(function(p){return '<label class="pchk" style="--pc:'+PCOL[p[0]]+'"><input type="checkbox" class="f_pr" value="'+p[0]+'" '+(has(p[0])?'checked':'')+'><i></i>'+p[1]+'</label>'}).join('')+'</div>'+
  (nodes.length>1?'<label class="f">'+t('Servers')+'</label><div class="ckrow">'+nodes.map(function(n){return '<label class="chk"><input type="checkbox" class="f_nd" value="'+esc(n.id)+'" '+(un.length==0||un.indexOf(n.id)>=0?'checked':'')+'>'+esc(n.name)+'</label>'}).join('')+'</div>':''),
  '<label class="sw"><input type="checkbox" class="uf_all" data-for="vpn" '+(vpnOn?'checked':'')+'><span></span></label>');
 h+=card('xray','xray','Xray','Links of every Xray inbound go into the subscription',has('xray'),'<div id="uf_xr" class="muted">…</div>','<label class="sw"><input type="checkbox" class="f_pr" value="xray" '+(has('xray')?'checked':'')+'><span></span></label>');
 h+=card('dns','dns','Kanki DNS','Private DNS for sanctioned sites',has('dns'),'<div id="uf_dn" class="muted">…</div>','<label class="sw"><input type="checkbox" class="f_pr" value="dns" '+(has('dns')?'checked':'')+'><span></span></label>');
 setTimeout(ufWire,0);return h}
function ufWire(){if(!$('#uf_pre'))return;
 var sync=function(){$$('.ufsvc').forEach(function(c){var on=$$('.f_pr',c).some(function(x){return x.checked});c.classList.toggle('on',on);var a=$('.uf_all',c);if(a)a.checked=on})};
 $$('.uf_all').forEach(function(a){a.onchange=function(){var c=a.closest('.ufsvc');$$('.f_pr',c).forEach(function(x){x.checked=a.checked});sync()}});
 $$('.ufsvc .f_pr').forEach(function(x){x.addEventListener('change',sync)});
 $$('#uf_pre [data-pre]').forEach(function(b){b.onclick=function(){var k=b.dataset.pre;$$('.ufsvc').forEach(function(c){var on=k=='all'||c.dataset.svc==k;$$('.f_pr',c).forEach(function(x){x.checked=on})});sync()}});
 var xr=function(d){var el=$('#uf_xr');if(!el)return;if(!d){el.textContent='—';return}var l=d.inbounds.filter(function(x){return x.enabled});
  el.innerHTML=(d.on?'':'<span style="color:var(--warn)">'+t('Is off in the panel')+'</span> · ')+(l.length?l.map(function(ib){return '<span class="chipx a" style="margin:2px">'+esc(ib.remark||ib.protocol)+' · '+esc(ib.server_name||ib.server)+'</span>'}).join(''):t('No Xray inbound yet')+' · <a href="#xray/inbounds" onclick="closeModal()">'+t('New inbound')+'</a>')};
 var dn=function(d){var el=$('#uf_dn');if(!el)return;if(!d){el.textContent='—';return}var l=d.servers.filter(function(x){return !x.hidden});
  el.innerHTML=(d.on?'':'<span style="color:var(--warn)">'+t('Is off in the panel')+'</span> · ')+(l.length?l.map(function(x){return '<span class="chipx b" style="margin:2px">'+(x.role=='relay'?'🇮🇷 ':'🌍 ')+esc(x.name||x.server)+'</span>'}).join(''):t('No DNS server yet')+' · <a href="#dns/servers" onclick="closeModal()">'+t('Add DNS server')+'</a>')};
 if(XR.d)xr(XR.d);api('GET','/api/xray').then(function(d){XR.d=d;xr(d)}).catch(function(){xr(null)});
 if(DN.d)dn(DN.d);api('GET','/api/dns').then(function(d){DN.d=d;dn(d)}).catch(function(){dn(null)})}

// ---- node types: the "Add node" button first asks which kind of node
var _nodeAdd=null;
function nodeAddTyped(){var tile=function(k,ico,title,sub){return '<button class="b2" data-nt="'+k+'" style="display:flex;gap:10px;align-items:center;text-align:start;padding:12px;width:100%;margin-bottom:8px"><span class="ni">'+ic(ico,20)+'</span><span><b>'+t(title)+'</b><br><small class="muted">'+t(sub)+'</small></span></button>'};
 modal(mhead(t('Node type'))+tile('vpn','nodes','VPN node','WireGuard · AmneziaWG · Hysteria2')+tile('xray','xray','Xray node','VLESS · VMess · Trojan · Shadowsocks')+tile('dns','dns','DNS exit node','Smart DNS abroad')+tile('relay','dns','DNS relay node','Iran server in front of a DNS exit'));
 $$('[data-nt]').forEach(function(b){b.onclick=function(){var k=b.dataset.nt;if(k=='vpn')return _nodeAdd();if(k=='xray'){closeModal();xrAddNode();return}
  dnsLoad().then(function(){dnsAdd(k=='relay'?'relay':'exit')})}})}
