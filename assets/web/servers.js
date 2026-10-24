// Kanki Panel 3.9: Servers — one list, one kind of server.
// 3.9.3: two boxes (abroad, Iran) of compact rows; a row's arrow opens it (one open at a time) with all
// of the server's own settings. Its VPN ports and protocols are in VPN services (svc.js).
// The panel runs on one server; every other server is a node of it, added with ONE command that
// installs everything (VPN, tunnels, Xray, Kanki DNS). What a server runs is switched on here.
// Loaded after every other script: it replaces the old Servers page (VPN nodes, tunnel servers, Xray
// and DNS servers in separate lists) and the separate "Tunnel servers" page.
(function(){
'use strict';
var SFA={
 "Servers":"سرورها","Add server":"افزودن سرور","Update all":"آپدیت همه",
 "The panel runs on one server. Every other server is a node: add it with one command, then switch on here what it runs.":"پنل روی یک سرور نصب است. هر سرور دیگر یک نود است: با یک دستور اضافه‌اش کن و بعد همین‌جا روشن کن که چه چیزی رویش اجرا شود.",
 "Panel server":"سرور پنل","Node":"نود","Iran":"ایران","Abroad":"خارج","All":"همه","Connected":"وصل","Not connected":"قطع",
 "VPN for users":"VPN برای کاربران","Tunnels":"تانل‌ها","Xray":"Xray","Kanki DNS":"DNS کانکی","inbounds":"اینباند","exit":"خروجی","relay":"رله",
 "VPN is installed but serves nobody (a relay)":"VPN نصب است ولی به هیچ کاربری سرویس نمی‌دهد (رله)","VPN serves users":"VPN به کاربران سرویس می‌دهد",
 "VPN is not installed on this server":"VPN روی این سرور نصب نیست","Install VPN":"نصب VPN",
 "Tunnels, Xray and DNS are not installed on this server":"تانل، Xray و DNS روی این سرور نصب نیست","Install":"نصب",
 "Waiting for this server: run its command":"منتظر این سرور: دستورش را اجرا کن","Show command":"نمایش دستور",
 "Installing the VPN part…":"در حال نصب بخش VPN…","VPN install failed":"نصب VPN نشد","Try again":"دوباره",
 "Port clash":"تداخل پورت","is used by":"استفاده شده توسط","One tunnel entry cannot carry the same port to two servers. Fix moves the later server to a free port; tunnels that carry the old port follow.":"یک سرور ورودی (ایران) نمی‌تواند یک پورت را به دو سرور تانل کند. «رفع» سرور بعدی را به پورت آزاد می‌برد و تانل‌هایی که پورت قبلی را می‌برند هم خودکار درست می‌شوند.",
 "Fix ports":"رفع تداخل پورت","Ports moved":"پورت‌ها جابه‌جا شدند","No clash":"تداخلی نیست",
 "Users' WireGuard / AmneziaWG files of the moved server must be downloaded again (subscription links and the app update by themselves). Continue?":"فایل‌های WireGuard / AmneziaWG کاربرانِ سروری که پورتش عوض می‌شود باید دوباره دانلود شوند (لینک ساب و اپ خودشان به‌روز می‌شوند). ادامه می‌دهی؟",
 "Server name":"نام سرور","Location":"موقعیت","Inside Iran (relay / tunnel entry)":"داخل ایران (رله / ورودی تانل)","Abroad":"خارج",
 "Domain (optional, for a real SSL certificate)":"دامنه (اختیاری، برای SSL واقعی)",
 "Serve VPN users on this server":"به کاربران VPN از این سرور سرویس بده",
 "Everything is installed on the server (VPN, tunnels, Xray, Kanki DNS) with one command. Off = installed, but no user is sent there (an Iran relay).":"همه‌چیز با یک دستور روی سرور نصب می‌شود (VPN، تانل، Xray، DNS کانکی). خاموش = نصب می‌شود ولی هیچ کاربری به آن فرستاده نمی‌شود (رله‌ی ایران).",
 "Create command":"ساخت دستور","Run this on the new server, as root (Ubuntu / Debian)":"این را روی سرور جدید اجرا کن، با root (اوبونتو / دبیان)","Copy command":"کپی دستور",
 "Ports given to this server (no other server uses them)":"پورت‌هایی که به این سرور داده شد (هیچ سرور دیگری از آن‌ها استفاده نمی‌کند)",
 "Waiting for the server to connect…":"منتظر وصل شدن سرور…","Server agent connected":"ایجنت سرور وصل شد","VPN part installed":"بخش VPN نصب شد",
 "Valid for 6 hours. Run it once; it can be run again on the same server.":"تا ۶ ساعت معتبر است. یک بار اجرا کن؛ روی همان سرور می‌شود دوباره هم اجرا کرد.",
 "Done":"انجام شد","Settings":"تنظیمات","Health":"سلامت","Sync":"همگام‌سازی","Repair":"تعمیر","Update agent":"آپدیت ایجنت","Delete server":"حذف سرور",
 "Add to all users":"افزودن به همه‌ی کاربران","Remove from all users":"حذف از همه‌ی کاربران","Tunnel agent settings":"تنظیمات ایجنت (آدرس، GRE)",
 "Ports":"پورت‌ها","Name":"نام","Address other servers use to reach it (optional)":"آدرسی که سرورهای دیگر با آن به این سرور وصل می‌شوند (اختیاری)",
 "Save":"ذخیره","Cancel":"انصراف","Delete this whole server? Its tunnels must be deleted first. The server removes everything Kanki installed on it (VPN, tunnels, Xray, DNS) and uninstalls itself.":"کل این سرور حذف شود؟ اول تانل‌هایش را حذف کن. سرور هرچه کانکی رویش نصب کرده (VPN، تانل، Xray، DNS) را پاک می‌کند و خودش را حذف می‌کند.",
 "Removed":"حذف شد","users":"کاربر","Last contact":"آخرین ارتباط","this server":"همین سرور","agent":"ایجنت","Details":"جزئیات","Hide":"بستن",
 "Install the VPN part on this server? It runs by itself on the server and takes a few minutes.":"بخش VPN روی این سرور نصب شود؟ خودِ سرور نصبش می‌کند و چند دقیقه طول می‌کشد.",
 "Serve users once installed":"بعد از نصب به کاربران سرویس بده",
 "Install tunnels, Xray and DNS (the server agent) on this server? It starts next to its VPN within seconds.":"تانل، Xray و DNS (ایجنت سرور) روی این سرور نصب شود؟ چند ثانیه‌ای کنار VPN آن راه می‌افتد.",
 "Switch the VPN off on this server? Its users are taken off; it keeps carrying tunnels.":"VPN این سرور خاموش شود؟ کاربرانش برداشته می‌شوند؛ تانل‌ها کار می‌کنند.",
 "Switch the VPN on: users that accept all servers are sent here.":"VPN روشن شود: کاربرانی که همه‌ی سرورها را دارند به این سرور هم فرستاده می‌شوند.",
 "No server here":"سروری اینجا نیست","not installed":"نصب نیست","Add Xray":"افزودن Xray","Add DNS":"افزودن DNS","Emergency chat":"چت اضطراری","Subscription":"لینک ساب",
 "The server is not connected right now":"این سرور الان وصل نیست","CPU":"CPU","RAM":"RAM","Disk":"دیسک","version":"نسخه",
 "Problem":"مشکل دارد","Healthy":"سالم","Under pressure":"تحت فشار","Off":"خاموش","On":"روشن","Planned ports":"پورت‌های رزرو شده",
 "After restore":"بعد از بازگردانی","Restored":"بازگردانی شد","from":"از","Every server is connected":"همه‌ی سرورها وصل‌اند","Not connected yet":"هنوز وصل نیست",
 "The panel on the old server still runs the same Telegram bot: both answer customers and both post to the channel. Stop it there: systemctl disable --now kanki-panel":"پنل روی سرور قبلی هنوز همین ربات تلگرام را اجرا می‌کند: هر دو به مشتری‌ها جواب می‌دهند و هر دو در کانال پست می‌گذارند. آن‌جا خاموشش کن: systemctl disable --now kanki-panel",
 "Include the app files (APK)":"فایل‌های اپ (APK) هم داخل بکاپ باشد",
 "The server agent, VPN and their health in one place: press a service to open its page.":"ایجنت، VPN و سلامت هر سرور یک‌جا؛ روی هر سرویس بزن تا صفحه‌اش باز شود.",
 "Direct domains":"دامنه‌های مستقیم","Domain":"دامنه","Point it at":"آی‌پی که باید روی آن بگذاری","Status":"وضعیت","Through":"مسیر کانفیگ",
 "Tunnel":"تانل","Direct":"مستقیم","Points at this server":"درست است","Not set yet":"هنوز تنظیم نشده","Points elsewhere":"به سرور دیگری اشاره می‌کند",
 "Country not known yet":"کشور هنوز معلوم نیست","Change the base domain":"تغییر دامنه‌ی اصلی",
 "The app's «Amnezia Direct» config of a server behind the tunnel goes straight to the server through its own name. Make each name below an A record pointing at the IP next to it (in Cloudflare: DNS only, grey cloud). Until a name points at the right server, the app is given the server's own address, so a direct config never reaches the wrong server.":"کانفیگ «Amnezia مستقیم» هر سروری که پشت تانل است، با اسم خودش مستقیم به همان سرور وصل می‌شود. برای هر اسم زیر یک رکورد A بساز که به آی‌پی کنارش اشاره کند (در کلادفلر: فقط DNS، ابر خاکستری). تا وقتی اسمی درست تنظیم نشده، آدرس خود سرور به برنامه داده می‌شود؛ پس کانفیگ مستقیم هیچ‌وقت به سرور اشتباه نمی‌رود.",
 "Base domain for the direct names (like example.com); empty = the panel domain without its first part":"دامنه‌ی اصلی اسم‌های مستقیم (مثل example.com)؛ خالی = دامنه‌ی پنل بدون بخش اولش"
};
if(typeof FA!='undefined')Object.assign(FA,SFA);

if(typeof FA!='undefined')Object.assign(FA,{
 "Abroad servers":"سرورهای خارج",
 "Iran servers":"سرورهای ایران",
 "running":"روشن",
 "stopped":"متوقف",
 "off":"خاموش",
 "none":"ندارد",
 "connected":"وصل",
 "Restart VPN services":"ری‌استارت سرویس‌های VPN",
 "UDP port":"پورت UDP",
 "Save port":"ذخیره‌ی پورت",
 "A port is 1-65535":"پورت باید بین ۱ تا ۶۵۵۳۵ باشد",
 "Already used by":"قبلاً استفاده شده توسط",
 "pick another port":"پورت دیگری انتخاب کن",
 "Saving…":"در حال ذخیره…",
 "Saved: the service restarts on the new port":"ذخیره شد: سرویس روی پورت جدید ری‌استارت می‌شود",
 "Users' WireGuard / AmneziaWG files of this server must be downloaded again after a port change; subscription links and the app update by themselves.":"بعد از عوض شدن پورت، فایل‌های WireGuard / AmneziaWG کاربرانِ این سرور باید دوباره دانلود شوند؛ لینک ساب و اپ خودشان به‌روز می‌شوند.",
 "Add this server to all users":"افزودن این سرور به همه‌ی کاربران",
 "Remove this server from all users":"حذف این سرور از همه‌ی کاربران",
 "KANKI MIX on this server":"KANKI MIX روی این سرور",
 "KANKI MIX settings (all servers)":"تنظیمات KANKI MIX (همه‌ی سرورها)",
 "Xray is not on this server yet.":"Xray هنوز روی این سرور نیست.",
 "Kanki DNS is not on this server yet.":"DNS کانکی هنوز روی این سرور نیست.",
 "Install Xray on this server":"نصب Xray روی این سرور",
 "Install Kanki DNS on this server":"نصب DNS کانکی روی این سرور",
 "Inbounds":"اینباندها",
 "Edit":"ویرایش",
 "Restart":"ری‌استارت",
 "Use for all users":"فعال برای همه‌ی کاربران",
 "Take from all users":"غیرفعال برای همه‌ی کاربران",
 "Remove from this server":"حذف از این سرور",
 "Who may use it is also set per user (Users › edit).":"اینکه چه کسی از آن استفاده کند، برای هر کاربر هم قابل تنظیم است (کاربران › ویرایش).",
 "No tunnel uses this server.":"هیچ تانلی از این سرور استفاده نمی‌کند.",
 "Tunnels page":"صفحه‌ی تانل‌ها",
 "New tunnel":"تانل جدید",
 "Turn this on for every user?":"برای همه‌ی کاربران روشن شود؟",
 "Turn this off for every user?":"برای همه‌ی کاربران خاموش شود؟",
 "Remove it from this server? The server stops it and frees its ports.":"از این سرور حذف شود؟ سرور آن را متوقف می‌کند و پورت‌هایش آزاد می‌شود.",
 "Delete this whole server? Everything Kanki installed on it (VPN, tunnels, Xray, DNS) is removed from the server and from the panel, and the server uninstalls itself.":"کل این سرور حذف شود؟ هرچه کانکی رویش نصب کرده (VPN، تانل، Xray، DNS) از روی سرور و از پنل پاک می‌شود و سرور خودش را حذف می‌کند.",
 "These tunnels use this server:":"این تانل‌ها از این سرور استفاده می‌کنند:",
 "Delete them too? The other server drops them and closes their ports.":"آن‌ها هم حذف شوند؟ سرور طرف دیگر هم آن‌ها را برمی‌دارد و پورت‌هایشان را می‌بندد.",
 "Another program uses this bot token (an old panel still running?). Stop it, or make a new token in @BotFather.":"یک برنامه‌ی دیگر هم از توکن این ربات استفاده می‌کند (پنل قبلی هنوز روشن است؟). آن را خاموش کن یا در @BotFather توکن جدید بساز.",
 "Panel server":"سرور پنل",
 "agent":"ایجنت",
 "Removing…":"در حال حذف…",
 "Removed":"حذف شد",
 "Saved":"ذخیره شد"
});
if(typeof FA!='undefined')Object.assign(FA,{
 "Server settings":"تنظیمات سرور","Note":"یادداشت","Users connect to":"کاربرها به این آدرس وصل می‌شوند",
 "This server's own address":"آدرس خود این سرور","Another address":"آدرس دیگر","Through":"از راه",
 "Users without their own server list get this server":"کاربرانی که فهرست سرور جدا ندارند این سرور را هم بگیرند",
 "API address":"آدرس API","Node token":"توکن نود","Self-signed certificate (no domain on the server)":"گواهی خودامضا (بدون دامنه روی سرور)",
 "empty = keep it":"خالی = همان قبلی","Show command":"نمایش دستور","Ports and protocols of this server are in VPN services.":"پورت‌ها و پروتکل‌های این سرور در «سرویس‌های VPN» است.",
 "VPN services":"سرویس‌های VPN","No server yet":"هنوز سروری نیست","Add an Iran server":"افزودن سرور ایران","Add an abroad server":"افزودن سرور خارج",
 "relay":"رله","Not connected":"وصل نیست","Saved":"ذخیره شد","Closed":"بسته شد"
});
var SV={d:null,wait:null};
window.SV=SV;

// ---------------------------------------------------------------- look
(function(){var st=document.createElement('style');st.textContent=
 '.kxp-top{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.kxp-top .sp{flex:1}'+
 '.kxc-tag{font-size:11px;border:1px solid var(--ln);border-radius:8px;padding:1px 7px;color:var(--s);white-space:nowrap;font-weight:600}'+
 '.kxc-tag.main{color:var(--a);border-color:color-mix(in srgb,var(--a) 55%,transparent)}'+
 '.kxc-miss{border:1px dashed color-mix(in srgb,var(--warn) 60%,transparent);border-radius:12px;padding:8px 10px;margin:8px 0 0;font-size:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}'+
 '.kxc-miss span{flex:1;min-width:150px}.kxc-miss pre{width:100%;margin:6px 0 0;white-space:pre-wrap;font-size:11px;max-height:140px;overflow:auto;direction:ltr;text-align:left;background:var(--in);border-radius:8px;padding:6px}'+
 '.kxp-clash{border:1px solid color-mix(in srgb,var(--warn) 55%,transparent);border-radius:16px;padding:12px;margin:0 0 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}'+
 '.kxp-clash div{flex:1;min-width:220px;font-size:12px}.kxp-clash b{color:var(--warn)}'+
 '.kxp-steps{display:grid;gap:6px;margin-top:10px}.kxp-steps div{display:flex;gap:8px;align-items:center;font-size:13px}'+
 '.kxp-ports{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}.kxp-ports span{border:1px solid var(--ln);border-radius:8px;padding:2px 8px;font-size:12px;direction:ltr}'+
 '.kxseg{display:grid;grid-template-columns:1fr 1fr;gap:6px}'+
 '.modal{z-index:60!important}#toast{z-index:70!important}'+
 // boxes (abroad, Iran) of compact rows; one row open at a time
 '.kxbox{border:1px solid var(--ln);border-radius:18px;background:color-mix(in srgb,var(--c1) 55%,transparent);padding:10px;margin:0 0 12px;max-width:980px}'+
 '.kxbox-h{display:flex;align-items:center;gap:8px;padding:2px 4px 8px}.kxbox-h b{font-size:14px}.kxbox-h small{color:var(--s);font-size:12px;border:1px solid var(--ln);border-radius:999px;padding:0 8px}.kxbox-h .sp{flex:1}'+
 '.kxbox-i{display:inline-flex;width:26px;height:26px;border-radius:9px;align-items:center;justify-content:center;background:color-mix(in srgb,var(--a) 12%,transparent);font-size:15px}'+
 '.kxbox-e{margin:4px 6px 6px;font-size:12px}'+
 '.kxl{display:flex;flex-direction:column;gap:6px}'+
 '.kxr{border:1px solid var(--ln);border-radius:14px;background:var(--c1);min-width:0;transition:border-color .2s,box-shadow .2s}'+
 '.kxr:hover{border-color:color-mix(in srgb,var(--a) 30%,var(--ln))}'+
 '.kxr.open{border-color:color-mix(in srgb,var(--a) 55%,var(--ln));box-shadow:0 6px 22px -14px color-mix(in srgb,var(--a) 70%,transparent)}'+
 '.kxr-h{display:flex;align-items:center;gap:8px;width:100%;padding:9px 11px;background:transparent;border:0;color:var(--t);font:inherit;cursor:pointer;text-align:start;min-width:0;border-radius:14px}'+
 '.kxr-h b{font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}.kxr-h .sp{flex:1;min-width:6px}'+
 '.kxr-h small{color:var(--s);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.kxr-h .flg{font-size:16px}'+
 '.kxr-arr{flex:none;display:inline-flex;color:var(--s);transition:transform .2s ease,color .2s}.kxr-arr svg{display:block}'+
 '.kxr-arr{transform:rotate(-90deg)}[dir=rtl] .kxr-arr{transform:rotate(90deg)}.kxr.open .kxr-arr{transform:none;color:var(--a)}'+
 '.kxr-st{font-size:11px;border:1px solid var(--ln);border-radius:8px;padding:1px 7px;white-space:nowrap;color:var(--s)}'+
 '.kxr-st.g{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 45%,transparent)}.kxr-st.r{color:var(--bad);border-color:color-mix(in srgb,var(--bad) 45%,transparent)}.kxr-st.y{color:var(--warn);border-color:color-mix(in srgb,var(--warn) 45%,transparent)}'+
 '.kxr-b{overflow:hidden;transition:height .2s ease,opacity .2s ease}.kxr-b.shut{opacity:0}'+
 '.kxr-in{padding:2px 12px 12px;border-top:1px solid color-mix(in srgb,var(--ln) 70%,transparent)}'+
 '.kxr-line{display:flex;flex-wrap:wrap;gap:4px 12px;color:var(--s);font-size:12px;margin:10px 0 4px}.kxr-line b{color:var(--t);font-weight:600}'+
 '.kxr-sec{font-size:11px;font-weight:700;color:var(--s);margin:12px 0 4px;letter-spacing:.2px}'+
 '.kxf{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px 10px}.kxf>div{min-width:0}.kxf label.f{margin:4px 0 3px;font-size:12px}'+
 '.kxf input,.kxf select{height:36px;padding:0 10px;font-size:13px;border-radius:10px}.kxf .wide{grid-column:1/-1}'+
 '.kxf .seg button{padding:6px 8px;font-size:12px}'+
 '.kxsw{display:flex;align-items:center;justify-content:space-between;gap:10px;border:1px solid var(--ln);border-radius:12px;padding:7px 10px;font-size:13px;margin-top:6px}'+
 '.kxsw span{min-width:0}.kxsw small{display:block;color:var(--s);font-size:11px}'+
 '.kxchips{display:flex;flex-wrap:wrap;gap:5px;margin-top:5px}.kxchips button{border:1px solid var(--ln);background:transparent;color:var(--t);border-radius:999px;padding:3px 9px;font:inherit;font-size:11px;cursor:pointer}'+
 '.kxchips button:hover,.kxchips button.on{border-color:var(--a);color:var(--a)}'+
 '.kxm3{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:6px;margin-top:14px}'+
 '.kxacts{display:flex;flex-wrap:wrap;gap:6px;margin-top:10px}.kxacts button,.kxacts a{flex:0 0 auto}'+
 '.kxsave{display:flex;gap:6px;justify-content:flex-end;margin-top:10px}'+
 '.kxm-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.kxm-row>div{flex:0 1 180px;min-width:120px}.kxm-row input{height:36px;font-size:13px}.kxm-row .btn{height:36px;padding:0 14px;font-size:13px}'+
 '.kxm-warn{color:var(--warn);font-size:12px;margin-top:4px;min-height:14px}'+
 '.kxm-btns{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:12px}.kxm-btns button,.kxm-btns a{width:100%;text-align:center}'+
 '.kxr-in details.box{margin-top:8px;padding:8px 10px}.kxr-in details.box summary{font-size:12px;font-weight:700;cursor:pointer}'+
 '@media(min-width:900px){.side{overflow-y:auto;overscroll-behavior:contain}}'+
 '@media(max-width:600px){.kxf{grid-template-columns:1fr}.kxbox{padding:8px;border-radius:16px}.kxr-h small.kxr-ip{display:none}}';
 document.head.appendChild(st)})();

function fl(cc){return window.flagOf?flagOf(cc):''}
function isIr(s){return s.loc=='iran'||String(s.cc||'').toUpperCase()=='IR'}
function q(id){return encodeURIComponent(id)}

// ---------------------------------------------------------------- one row open at a time (Servers, VPN services)
// A list of rows: the arrow of a row opens it and closes the one open before it. Leaving the page, or
// saving what is in it, closes it. Only the open row's body is drawn; a refresh leaves a row alone
// while something is being typed in it.
var ACC={open:{},draw:{},anim:''};
window.KAcc=ACC;
window.accRow=function(g,key,head,body,cls){var op=ACC.open[g]==key,an=op&&ACC.anim==g+'|'+key;
 return '<div class="kxr'+(op?' open':'')+(cls?' '+cls:'')+'" data-acc="'+esc(g)+'" data-key="'+esc(key)+'">'+
  '<button type="button" class="kxr-h" onclick="accToggle(\''+esc(g)+'\',\''+esc(key)+'\')" aria-expanded="'+op+'"><span class="kxr-arr">'+ic('chev',16)+'</span>'+head+'</button>'+
  (op?'<div class="kxr-b'+(an?' anim':'')+'"><div class="kxr-in">'+body()+'</div></div>':'')+'</div>'};
function accEl(g){return document.querySelector('.kxr.open[data-acc="'+g+'"] .kxr-b')}
window.accToggle=function(g,key){var cur=ACC.open[g]||'',next=cur==key?'':key,old=accEl(g);
 var go=function(){ACC.open[g]=next;ACC.anim=next?g+'|'+next:'';if(ACC.draw[g])ACC.draw[g](true);ACC.anim='';
  var b=accEl(g);if(!b||!b.classList.contains('anim'))return;var h=b.scrollHeight;b.style.height='0px';b.classList.add('shut');b.offsetHeight;
  b.style.height=h+'px';b.classList.remove('shut');setTimeout(function(){b.style.height='';b.classList.remove('anim')},220);
  var r=b.parentNode.getBoundingClientRect();if(r.bottom>window.innerHeight-70)try{b.parentNode.scrollIntoView({block:'nearest',behavior:'smooth'})}catch(e){}};
 if(old){old.style.height=old.scrollHeight+'px';old.offsetHeight;old.classList.add('shut');old.style.height='0px';setTimeout(go,180)}else go()};
window.accClose=function(g){if(ACC.open[g])accToggle(g,ACC.open[g])};
// something typed (or focused) in the open row of group g: a refresh does not redraw it
window.accBusy=function(g){var b=accEl(g);if(!b)return false;return !!(b.dataset.dirty||(document.activeElement&&b.contains(document.activeElement)&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)))};
document.addEventListener('input',function(e){var b=e.target&&e.target.closest&&e.target.closest('.kxr-b');if(b)b.dataset.dirty='1'});
document.addEventListener('keydown',function(e){if(e.key!='Escape'||($('#modal')&&$('#modal').classList.contains('on')))return;Object.keys(ACC.open).forEach(function(g){if(ACC.open[g])accClose(g)})});

// ---------------------------------------------------------------- data
function load(quiet){
 return Promise.all([api('GET','/api/servers'),api('GET','/api/nodes').catch(function(){return null}),api('GET','/api/tunnels').catch(function(){return null})]).then(function(r){
  SV.d=r[0];if(r[1])S.nodes=r[1];if(r[2]){if(window.TN)TN.d=r[2];else window.TN={d:r[2]}}
  if(S.page=='nodes')draw(!quiet);waitTick();return SV.d}).catch(function(e){if(!quiet)fail(e)})}
window.srvLoad=load;

// ---------------------------------------------------------------- page
window.pNodes=function(){ACC.open.srv='';
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Servers')+'</h2><p>'+t('The panel runs on one server. Every other server is a node: add it with one command, then switch on here what it runs.')+'</p></div>'+
  '<div class="kxp-top"><button class="b2" onclick="updateAll()">⇪ '+t('Update all')+'</button><button class="btn" onclick="srvAdd()">'+ic('plus',15)+' '+t('Add server')+'</button></div></div>'+
  '<div id="svp_clash"></div><div id="svp_g">'+t('Loading…')+'</div>';
 load();autoRefresh(function(){load(true)});
 if(S.openAdd){S.openAdd=false;setTimeout(srvAdd,150)}};
ACC.draw.srv=function(){draw(true)};

function draw(force){var g=$('#svp_g');if(!g||!SV.d)return;
 var cl=SV.d.clashes||[];
 $('#svp_clash').innerHTML=cl.length?'<div class="kxp-clash"><div><b>⚠ '+t('Port clash')+'</b><br>'+cl.map(function(c){return 'UDP <b class="ltr">'+N(c.port)+'</b> '+t('is used by')+' '+c.users.map(function(u){return esc(u.name)+' ('+protoName(u.proto)+')'}).join('، ')}).join('<br>')+
  '<p class="muted" style="margin:6px 0 0">'+t('One tunnel entry cannot carry the same port to two servers. Fix moves the later server to a free port; tunnels that carry the old port follow.')+'</p></div><button class="btn" onclick="srvFixPorts()">'+t('Fix ports')+'</button></div>':'';
 if(!force&&accBusy('srv'))return;
 var list=(SV.d.servers||[]).slice(),by=function(x,y){return (y.local?1:0)-(x.local?1:0)||String(x.name).localeCompare(String(y.name))};
 var ab=list.filter(function(x){return !isIr(x)}).sort(by),ir=list.filter(isIr).sort(by);
 g.innerHTML=srvBox('abroad','Abroad servers','🌍',ab)+srvBox('iran','Iran servers',fl('IR'),ir)}
window.srvDraw=draw;
function srvBox(kind,title,icon,rows){
 return '<section class="kxbox '+kind+'"><div class="kxbox-h"><span class="kxbox-i">'+icon+'</span><b>'+t(title)+'</b><small>'+N(rows.length)+'</small><span class="sp"></span>'+
  '<button class="b2 sm" onclick="srvAdd(\''+kind+'\')">'+ic('plus',13)+' '+t(kind=='iran'?'Add an Iran server':'Add an abroad server')+'</button></div>'+
  (rows.length?'<div class="kxl">'+rows.map(row).join('')+'</div>':'<p class="muted kxbox-e">'+t('No server yet')+'</p>')+'</section>'}

function protoName(p){return ({wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2',kmix:'KANKI MIX'})[p]||p}
function online(s){var a=s.agent,n=s.node;return !!(s.local||(a&&a.online)||(n&&n.online))}
function srvIp(s){var a=s.agent||{},n=s.node||{};return a.addr||a.ip||(n.effective_endpoint&&n.effective_endpoint!=n.endpoint?'':n.endpoint)||''}

function row(s){var n=s.node,a=s.agent,on=online(s),h=n&&window.nHealthOf?nHealthOf(n):null,col=!on?'r':h&&h.c=='r'?'y':h?h.c:'g';
 var tags=(s.local?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+(n&&!n.enabled&&!s.local?'<span class="kxc-tag">'+t('relay')+'</span>':'');
 var head='<span class="dot '+col+'"></span>'+fl(s.cc)+'<b>'+esc(s.name)+'</b>'+tags+'<span class="sp"></span>'+
  (on?'':'<span class="kxr-st r">'+t('Not connected')+'</span>')+'<small class="kxr-ip ltr">'+esc(srvIp(s))+'</small>';
 return accRow('srv',s.key,head,function(){return srvBody(s)})}

// the first entries (and their addresses) of the tunnels that bring this server's ports: where its
// users can connect instead of its own address (Iran → Turkey → here: Iran)
function entriesOf(s){var sid=s.agent?s.agent.id:(s.local?'local':''),tl=((window.TN&&TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.enabled!==false&&x.kind!='awg'}),out=[];
 if(!sid)return out;
 var back=function(id,seen){var prev=tl.filter(function(x){return x.exit==id&&seen.indexOf(x.entry)<0});if(!prev.length)return [id];
  var r=[];prev.forEach(function(x){back(x.entry,seen.concat([x.entry])).forEach(function(e){if(r.indexOf(e)<0)r.push(e)})});return r};
 back(sid,[sid]).forEach(function(e){if(e==sid)return;var sv=((TN.d&&TN.d.servers)||[]).filter(function(z){return z.id==e})[0];if(sv&&(sv.host||sv.addr))out.push({id:e,name:sv.name,host:sv.addr||sv.host})});
 return out}

function srvBody(s){var k=esc(s.key),a=s.agent,n=s.node,ni=n?esc(n.id):'';
 var st=[];
 if(!s.local)st.push(t('agent')+': <b>'+(a?(a.online?t('Connected'):t('Not connected')):'—')+'</b>');
 if(n)st.push('VPN: <b>'+(n.enabled?(s.local||n.online?t('On'):t('Not connected')):t('Off'))+'</b>');
 if(n&&n.enabled)st.push(N(n.users||0)+' '+t('users'));
 var ver=(n&&n.info&&n.info.version)||(a&&a.version)||'';if(ver)st.push('v'+esc(ver));
 if(!s.local&&a&&a.last_seen&&!a.online)st.push(t('Last contact')+' '+ago(a.last_seen));
 var miss='';
 if(!n&&a){var su=s.setup||null;
  if(s.pending&&!a.last_seen)miss='<div class="kxc-miss"><span>'+t('Waiting for this server: run its command')+'</span><button class="b2 sm" onclick="srvCmd(\''+k+'\')">'+t('Show command')+'</button></div>';
  else if(su&&su.state=='running')miss='<div class="kxc-miss"><span class="spin"></span><span>'+t('Installing the VPN part…')+'</span>'+(su.tail?'<pre>'+esc(su.tail)+'</pre>':'')+'</div>';
  else miss='<div class="kxc-miss"><span>'+(su&&su.state=='failed'?'<b class="bad2">'+t('VPN install failed')+'</b>':t('VPN is not installed on this server'))+'</span><button class="b2 sm" onclick="srvComplete(\''+k+'\','+(isIr(s)?0:1)+')">'+t(su&&su.state=='failed'?'Try again':'Install VPN')+'</button>'+(su&&su.state=='failed'&&su.tail?'<pre>'+esc(su.tail)+'</pre>':'')+'</div>'}
 if(n&&!a&&!s.local)miss='<div class="kxc-miss"><span>'+t('Tunnels, Xray and DNS are not installed on this server')+'</span><button class="b2 sm" onclick="srvComplete(\''+k+'\',1)">'+t('Install')+'</button></div>';
 // the server itself
 var h='<div class="kxr-line">'+st.join('<span>·</span>')+'</div>'+miss+
  '<div class="kxr-sec">'+t('Server settings')+'</div><div class="kxf">'+
  '<div><label class="f">'+t('Name')+'</label><input id="sx_nm" value="'+esc(s.name)+'" maxlength="40"></div>'+
  '<div><label class="f">'+t('Location')+'</label><div class="seg kxseg" id="sx_loc"><button type="button" data-l="abroad" class="'+(isIr(s)?'':'on')+'">'+t('Abroad')+'</button><button type="button" data-l="iran" class="'+(isIr(s)?'on':'')+'">'+t('Iran')+'</button></div></div>'+
  (a?'<div class="wide"><label class="f">'+t('Address other servers use to reach it (optional)')+'</label><input id="sx_ad" class="ltr" value="'+esc(a.addr||'')+'" placeholder="'+esc(a.ip||'')+'"></div>':'')+
  (n?'<div class="wide"><label class="f">'+t('Note')+'</label><input id="sx_no" value="'+esc(n.note||'')+'"></div>':'')+'</div>';
 // its VPN: who is sent there and where they connect
 if(n){var own=!n.endpoint||n.endpoint_mode=='panel',ents=entriesOf(s);
  h+='<div class="kxr-sec">VPN</div>'+
   '<div class="kxsw"><span>'+t('VPN for users')+'<small>'+t(n.enabled?'VPN serves users':'VPN is installed but serves nobody (a relay)')+'</small></span>'+sw('',n.enabled,"srvVpn('"+k+"',this.checked)")+'</div>'+
   '<label class="kxsw" style="cursor:pointer"><span>'+t('Users without their own server list get this server')+'</span><input type="checkbox" id="sx_acc" style="width:auto"'+(n.accept_all?' checked':'')+'></label>'+
   '<div class="kxf" style="margin-top:4px"><div class="wide"><label class="f">'+t('Users connect to')+'</label><input id="sx_ep" class="ltr" value="'+esc(s.local&&own?'':n.endpoint||'')+'" placeholder="'+esc(n.effective_endpoint||'')+'">'+
   (ents.length?'<div class="kxchips">'+ents.map(function(e){return '<button type="button" class="'+(n.endpoint==e.host?'on':'')+'" onclick="$(\'#sx_ep\').value=\''+esc(e.host)+'\';$(\'#sx_ep\').dispatchEvent(new Event(\'input\',{bubbles:true}))">'+t('Through')+' '+esc(e.name)+' · <span class="ltr">'+esc(e.host)+'</span></button>'}).join('')+
    '<button type="button" onclick="$(\'#sx_ep\').value=\''+esc(srvIp(s))+'\';$(\'#sx_ep\').dispatchEvent(new Event(\'input\',{bubbles:true}))">'+t("This server's own address")+'</button></div>':'')+'</div></div>'+
   (s.local?'':'<details class="box"><summary>'+t('Advanced')+'</summary><div class="kxf"><div class="wide"><label class="f">'+t('API address')+'</label><input id="sx_api" class="ltr" value="'+esc(n.address||'')+'"></div>'+
    '<div><label class="f">'+t('Node token')+'</label><input id="sx_tok" class="ltr" placeholder="'+t('empty = keep it')+'"></div>'+
    '<div style="align-self:end"><label class="chk" style="margin:0"><input type="checkbox" id="sx_ins"'+(n.insecure?' checked':'')+'>'+t('Self-signed certificate (no domain on the server)')+'</label></div></div></details>')+
   '<p class="muted" style="font-size:11px;margin:6px 2px 0">'+t('Ports and protocols of this server are in VPN services.')+' <a href="#vpn">'+t('VPN services')+'</a></p>'}
 h+='<div class="kxsave"><button class="b2 sm" onclick="accClose(\'srv\')">'+t('Cancel')+'</button><button class="btn sm" onclick="srvSave(\''+k+'\')">'+t('Save')+'</button></div>';
 // health and what can be done
 var stt=n&&n.info&&n.info.stats;
 if(stt&&window.nMeter)h+='<div class="kxm3">'+nMeter('CPU',+stt.cpu||0,N(Math.round(+stt.cpu||0))+'%')+nMeter('RAM',pc(stt.mem_used,stt.mem_total),N(Math.round(pc(stt.mem_used,stt.mem_total)))+'%')+nMeter('Disk',pc(stt.disk_used,stt.disk_total),N(Math.round(pc(stt.disk_used,stt.disk_total)))+'%')+'</div>';
 var hh=n&&window.nHealthOf?nHealthOf(n):null;
 if(hh&&hh.r&&hh.r.length&&n.enabled)h+='<ul class="nwhy">'+hh.r.map(function(x){return '<li class="l'+x[0]+'">'+t(x[1])+'</li>'}).join('')+'</ul>';
 var acts=[];
 if(n){acts.push('<button class="b2 sm" onclick="nHealth(\''+ni+'\')">♡ '+t('Health')+'</button>');
  acts.push('<button class="b2 sm" onclick="nAct(\''+ni+'\',\'sync\')">⇄ '+t('Sync')+'</button>');
  acts.push('<button class="b2 sm" onclick="nAct(\''+ni+'\',\'repair\')">↻ '+t('Restart VPN services')+'</button>');
  if(!s.local)acts.push('<button class="b2 sm" onclick="nAct(\''+ni+'\',\'update\')">⇪ '+t('Update agent')+'</button>');
  acts.push('<button class="b2 sm okb" onclick="nAssign(\''+ni+'\',1)">'+ic('plus',13)+' '+t('Add to all users')+'</button>');
  if(!s.local)acts.push('<button class="b2 sm" onclick="nAssign(\''+ni+'\',0)">'+t('Remove from all users')+'</button>')}
 if(a&&!s.local&&window.tunSrvEdit)acts.push('<button class="b2 sm" onclick="tunSrvEdit(\''+esc(a.id)+'\')">'+ic('tunnel',13)+' '+t('Tunnel agent settings')+'</button>');
 if(!s.local)acts.push('<button class="b2 sm" onclick="srvCmd(\''+k+'\')">'+ic('link',13)+' '+t('Show command')+'</button>');
 if(!s.local)acts.push('<button class="b2 sm bd" onclick="srvDel(\''+k+'\')">'+ic('trash',13)+' '+t('Delete server')+'</button>');
 h+='<div class="kxacts">'+acts.join('')+'</div>';
 setTimeout(function(){$$('#sx_loc button').forEach(function(b){b.onclick=function(){$$('#sx_loc button').forEach(function(z){z.classList.toggle('on',z==b)});var bb=b.closest('.kxr-b');if(bb)bb.dataset.dirty='1'}})},0);
 return h}

// Save of the open server: its name, place and address (the server), who gets it and where users connect (its VPN)
window.srvSave=function(key){var s=find(key);if(!s)return;var n=s.node,a=s.agent,jobs=[];
 var loc=(($$('#sx_loc button.on')[0]||{}).dataset||{}).l||(isIr(s)?'iran':'abroad');
 var b={name:$('#sx_nm').value.trim(),loc:loc};if($('#sx_ad'))b.addr=$('#sx_ad').value.trim();
 jobs.push(api('PUT','/api/servers/'+q(key),b));
 if(n){var ep=$('#sx_ep').value.trim(),nb={note:$('#sx_no')?$('#sx_no').value:n.note,accept_all:$('#sx_acc').checked,endpoint_mode:ep?'custom':'panel',endpoint:ep};
  if(!s.local&&!ep){nb.endpoint_mode='custom';nb.endpoint=srvIp(s)||n.endpoint}
  if($('#sx_api')){var ad=$('#sx_api').value.trim();if(ad)nb.address=ad;if($('#sx_tok').value.trim())nb.token=$('#sx_tok').value.trim();nb.insecure=$('#sx_ins').checked}
  jobs.push(api('PUT','/api/nodes/'+q(n.id),nb))}
 Promise.all(jobs).then(function(){toast(t('Saved'));accClose('srv');load(true)}).catch(fail)};

function find(key){var l=(SV.d&&SV.d.servers)||[];for(var i=0;i<l.length;i++)if(l[i].key==key)return l[i]}
window.srvFind=find;

// ---------------------------------------------------------------- add a server (one command)
window.srvAdd=function(loc){loc=loc=='iran'?'iran':'abroad';
 modal(mhead(t('Add server'))+
  '<p class="muted" style="margin:0 0 8px">'+t('Everything is installed on the server (VPN, tunnels, Xray, Kanki DNS) with one command. Off = installed, but no user is sent there (an Iran relay).')+'</p>'+
  '<div id="sa_in"><label class="f">'+t('Server name')+'</label><input id="sa_nm" placeholder="Germany-1" maxlength="40">'+
  '<label class="f">'+t('Location')+'</label><div class="seg kxseg" id="sa_loc"><button type="button" data-l="abroad">'+t('Abroad')+'</button><button type="button" data-l="iran">'+t('Inside Iran (relay / tunnel entry)')+'</button></div>'+
  '<label class="f">'+t('Domain (optional, for a real SSL certificate)')+'</label><input id="sa_dm" class="ltr" placeholder="de1.example.com" autocomplete="off" autocapitalize="off">'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="sa_vpn">'+t('Serve VPN users on this server')+'</label>'+
  '<button class="btn" style="width:100%;margin-top:12px" id="sa_go">'+t('Create command')+'</button></div><div id="sa_out"></div>','wide');
 var setLoc=function(l){loc=l;$$('#sa_loc button').forEach(function(b){b.classList.toggle('on',b.dataset.l==l)});$('#sa_vpn').checked=l!='iran'};
 $$('#sa_loc button').forEach(function(b){b.onclick=function(){setLoc(b.dataset.l)}});setLoc(loc);
 $('#sa_go').onclick=function(){var me=this;me.disabled=true;
  api('POST','/api/servers',{name:$('#sa_nm').value,loc:loc,domain:$('#sa_dm').value,vpn:$('#sa_vpn').checked}).then(function(r){
   $('#sa_in').classList.add('hide');showCmd(r.command,r.ports,r.id);load(true)}).catch(function(e){me.disabled=false;fail(e)})}};

function showCmd(cmd,ports,id){var o=$('#sa_out')||$('#mbox');if(!o)return;
 o.innerHTML='<label class="f">'+t('Run this on the new server, as root (Ubuntu / Debian)')+'</label><pre class="cmd" id="sa_cmd">'+esc(cmd)+'</pre>'+
  '<button class="btn" style="width:100%" id="sa_cp">'+ic('link',16)+' '+t('Copy command')+'</button>'+
  (ports&&ports.length==4?'<p class="muted" style="margin:10px 0 0">'+t('Ports given to this server (no other server uses them)')+'</p><div class="kxp-ports">'+['WireGuard','AmneziaWG','Hysteria2','KANKI MIX'].map(function(x,i){return '<span>'+x+' '+N(ports[i])+'</span>'}).join('')+'</div>':'')+
  '<div class="kxp-steps" id="sa_steps"></div>'+
  '<p class="muted" style="margin:8px 0 0">'+t('Valid for 6 hours. Run it once; it can be run again on the same server.')+'</p>';
 $('#sa_cp').onclick=function(){copy(cmd)};
 SV.wait=id||null;waitTick()}

function waitTick(){var el=$('#sa_steps');if(!el||!SV.wait||!SV.d)return;var s=find(SV.wait);if(!s)return;
 var a=s.agent||{},n=s.node,ok=function(b,l){return '<div>'+(b?'<span class="okc">'+ic('check',16)+'</span>':'<span class="spin"></span>')+'<span>'+t(l)+'</span></div>'};
 el.innerHTML=ok(a.online||a.last_seen,a.online||a.last_seen?'Server agent connected':'Waiting for the server to connect…')+ok(!!n,'VPN part installed');
 clearTimeout(SV.wt);if(!n&&$('#modal').classList.contains('on'))SV.wt=setTimeout(function(){api('GET','/api/servers').then(function(d){SV.d=d;waitTick();if(S.page=='nodes')draw()}).catch(function(){})},4000)}

window.srvCmd=function(key){api('GET','/api/servers/'+q(key)+'/command').then(function(r){var s=find(key)||{};
 modal(mhead(s.name||t('Server'))+'<div id="sa_out"></div>','wide');showCmd(r.command,s.planned,key)}).catch(fail)};

// ---------------------------------------------------------------- one server
window.srvVpn=function(key,on){if(!confirm(t(on?'Switch the VPN on: users that accept all servers are sent here.':'Switch the VPN off on this server? Its users are taken off; it keeps carrying tunnels.'))){draw(true);return}
 api('POST','/api/servers/'+q(key)+'/vpn',{on:on}).then(function(){toast(t('Done'));load(true)}).catch(function(e){fail(e);load(true)})};

window.srvComplete=function(key,vpn){var s=find(key)||{};
 if(String(key).indexOf('node:')==0){if(!confirm(t('Install tunnels, Xray and DNS (the server agent) on this server? It starts next to its VPN within seconds.')))return;
  toast(t('Checking…'));api('POST','/api/servers/'+q(key)+'/complete').then(function(){toast(t('Done'));setTimeout(function(){load(true)},4000)}).catch(fail);return}
 modal(mhead(t('Install VPN'),s.name)+'<p>'+t('Install the VPN part on this server? It runs by itself on the server and takes a few minutes.')+'</p>'+
  '<label class="chk"><input type="checkbox" id="sc_vpn" '+(vpn?'checked':'')+'>'+t('Serve users once installed')+'</label>'+
  '<label class="f">'+t('Domain (optional, for a real SSL certificate)')+'</label><input id="sc_dm" class="ltr" value="'+esc(s.domain||'')+'">'+
  '<div class="g2" style="margin-top:12px"><button class="b2" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn" id="sc_go">'+t('Install VPN')+'</button></div>');
 $('#sc_go').onclick=function(){var me=this;me.disabled=true;api('POST','/api/servers/'+q(key)+'/complete',{vpn:$('#sc_vpn').checked,domain:$('#sc_dm').value}).then(function(){closeModal();toast(t('Installing the VPN part…'));setTimeout(function(){load(true)},6000)}).catch(function(e){me.disabled=false;fail(e)})}};

// Delete the whole server. When tunnels use it, they are named and can go with it (the Iran entry drops
// them too and closes their ports).
window.srvDel=function(key,withTun){var s=find(key)||{};
 if(!withTun&&!confirm(t('Delete this whole server? Everything Kanki installed on it (VPN, tunnels, Xray, DNS) is removed from the server and from the panel, and the server uninstalls itself.')+' ('+(s.name||'')+')'))return;
 toast(t('Removing…'));
 api('DELETE','/api/servers/'+q(key)+(withTun?'?tunnels=1':'')).then(function(){toast(t('Removed'));ACC.open.srv='';load(true)}).catch(function(e){
  var tl=e&&e.data&&e.data.tunnels;
  if(tl&&tl.length){var names=tl.map(function(x){var o=find(x.other)||{};return '• '+x.name+(o.name?' ↔ '+o.name:'')}).join('\n');
   if(confirm(t('These tunnels use this server:')+'\n'+names+'\n\n'+t('Delete them too? The other server drops them and closes their ports.')))srvDel(key,1);return}
  fail(e)})};

window.srvFixPorts=function(){if(!confirm(t("Users' WireGuard / AmneziaWG files of the moved server must be downloaded again (subscription links and the app update by themselves). Continue?")))return;
 toast(t('Checking…'));api('POST','/api/servers/fix-ports').then(function(r){var m=r.moved||[];
  modal(mhead(t(m.length?'Ports moved':'No clash'))+(m.length?'<div class="list">'+m.map(function(x){return '<div class="li"><span><b>'+esc(x.server)+'</b> '+protoName(x.proto)+(x.error?'<small class="bad2">'+esc(x.error)+'</small>':'')+'</span><span class="ltr">'+N(x.old)+' → '+N(x.new)+' '+(x.ok?'✅':'❌')+'</span></div>'}).join('')+'</div>':''));
  load(true);if(window.svcReload)svcReload()}).catch(fail)};

// ---------------------------------------------------------------- a VPN port of one server (used by VPN services)
// another server (or another protocol here) already using the port the admin types
window.srvPortClash=function(key,proto,v){var p=+unN(String(v));if(!(p>0&&p<65536))return t('A port is 1-65535');var hit='';
 ((SV.d&&SV.d.servers)||[]).forEach(function(x){var ps=x.ports||{};Object.keys(ps).forEach(function(k){if(+ps[k]==p&&!(x.key==key&&k==proto))hit=x.name+' ('+protoName(k)+')'})});
 return hit?t('Already used by')+' '+hit+': '+t('pick another port'):''};
window.srvSavePort=function(key,proto,v,done){var b={};b[proto]=+unN(String(v));toast(t('Saving…'));
 return api('POST','/api/servers/'+q(key)+'/ports',b).then(function(r){toast(t('Saved: the service restarts on the new port'));load(true);if(done)done(r);return r}).catch(fail)};
window.srvKmix=function(key,on){return api('POST','/api/servers/'+q(key)+'/kmix',{on:on}).then(function(){toast(t('Saved'));load(true)}).catch(fail)};
window.srvProtoAll=function(pa,add){if(!confirm(t(add?'Turn this on for every user?':'Turn this off for every user?')))return;
 api('POST','/api/protocols/'+pa+'/'+(add?'assign-all':'unassign-all')).then(function(r){toast(t('Done')+' ('+N(r.changed||0)+')')}).catch(fail)};
window.srvSvcOff=function(kind,sid){if(!confirm(t('Remove it from this server? The server stops it and frees its ports.')))return;
 api('DELETE','/api/'+kind+'/servers/'+q(sid)).then(function(){closeModal();toast(t('Removed'));load(true);if(window.svcReload)svcReload()}).catch(fail)};

// Xray / DNS on one server
window.srvAddXray=function(key){if(!window.xrAddNode)return;xrAddNode();var tries=0,iv=setInterval(function(){var sel=$('#xa_sv');if(sel||++tries>40){clearInterval(iv);if(sel){sel.value=key;sel.dispatchEvent(new Event('change'))}}},100)};
window.srvAddDns=function(key,iran){if(!window.dnsAdd)return;dnsAdd(iran?'relay':'exit');var tries=0,iv=setInterval(function(){var sel=$('#dx_sv');if(sel||++tries>40){clearInterval(iv);if(sel){sel.value=key;sel.dispatchEvent(new Event('change'))}}},100)};

// ---------------------------------------------------------------- the old ways in lead here
// Add node (dashboard) and + Server (tunnels) open the one Add server
window.nodeAdd=function(){srvAdd('abroad')};window._nodeAdd=window.nodeAdd;
window.tunServerAdd=function(){srvAdd('iran')};
// "New server" in the Xray / DNS forms makes a whole server too: its command installs everything
if(window.tunCmdBox){var _tcb=window.tunCmdBox;window.tunCmdBox=function(s,d){if(s&&s.command)return '<label class="f">'+t('Run this on the new server, as root (Ubuntu / Debian)')+'</label><pre class="cmd" id="tn_cmd">'+esc(s.command)+'</pre><button class="btn" style="width:100%" id="tn_cp">'+ic('link',16)+' '+t('Copy command')+'</button>';return _tcb(s,d)}}
var _api=window.api;
window.api=function(m,u,b){if(m=='POST'&&u=='/api/tunnels/servers'&&b&&!b.gre_ip&&!b.addr)return _api('POST','/api/servers',{name:b.name,loc:b.loc||'abroad',vpn:b.loc!='iran'});return _api.apply(this,arguments)};
// actions of the node cards refresh this page
if(window.loadNodes){var _ln=window.loadNodes;window.loadNodes=function(){if(S.page=='nodes'&&$('#svp_g'))return load(true);return _ln.apply(this,arguments)}}

// the menu: one Servers page (the separate Tunnel servers page is gone)
if(window.V37&&V37.SECS){V37.SECS.forEach(function(s){s[3]=s[3].filter(function(x){return x[0]!='servers'})})}
var _route=window.route;
if(_route)window.route=function(){var h=(location.hash||'').slice(1).split('/')[0];if(h=='servers'){location.replace('#nodes');return}return _route.apply(this,arguments)};

// ---------------------------------------------------------------- Backup: after a restore, and app files
function restoreBox(){var pg=$('#pg');if(!pg||S.page!='backup'||$('#svp_rs'))return;
 api('GET','/api/restore/check').then(function(r){if((!r.restored_at||Date.now()/1000-r.restored_at>3*86400)&&!r.bot_conflict||$('#svp_rs')||S.page!='backup')return;
  var sv=r.servers||[],bad=sv.filter(function(x){return (x.agent===false)||(x.vpn===false&&x.vpn_on)});
  var c=document.createElement('div');c.className='card';c.id='svp_rs';
  c.innerHTML='<h3>'+t('After restore')+'</h3><p class="sub">'+t('Restored')+' '+ago(r.restored_at)+(r.moved_from?' · '+t('from')+' <span class="ltr">'+esc(r.moved_from)+'</span>':'')+'</p>'+
   (r.bot_conflict?'<div class="warnbox">'+t('The panel on the old server still runs the same Telegram bot: both answer customers and both post to the channel. Stop it there: systemctl disable --now kanki-panel')+'</div>':'')+
   (bad.length?'<div class="list">'+sv.map(function(x){var ok=x.agent!==false&&!(x.vpn===false&&x.vpn_on);return '<div class="li"><span>'+esc(x.name)+'</span><span>'+(ok?'✅':'⏳ '+t('Not connected yet'))+'</span></div>'}).join('')+'</div>':'<p>✅ '+t('Every server is connected')+'</p>');
  var ph=$('#pg .ph');if(ph)ph.parentNode.insertBefore(c,ph.nextSibling)}).catch(function(){})}
if(window.pBackup){var _pb=window.pBackup;window.pBackup=function(){_pb.apply(this,arguments);setTimeout(restoreBox,400)}}
})();
