// Kanki Panel 3.9: Servers — one list, one kind of server.
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
 "Include the app files (APK)":"فایل‌های اپ (APK) هم داخل بکاپ باشد",
 "The server agent, VPN and their health in one place: press a service to open its page.":"ایجنت، VPN و سلامت هر سرور یک‌جا؛ روی هر سرویس بزن تا صفحه‌اش باز شود."
};
if(typeof FA!='undefined')Object.assign(FA,SFA);

var SV={d:null,f:'all',open:{},wait:null};
window.SV=SV;

// ---------------------------------------------------------------- look
(function(){var st=document.createElement('style');st.textContent=
 '.kxp-top{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.kxp-top .sp{flex:1}'+
 '.kxp-f{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px}.kxp-f button{border:1px solid var(--ln);background:transparent;color:var(--t);border-radius:999px;padding:6px 12px;font:inherit;font-size:12px;cursor:pointer}'+
 '.kxp-f button.on{background:var(--a);color:#1a1206;border-color:var(--a);font-weight:700}.kxp-f b{opacity:.75;margin-inline-start:4px}'+
 '.kxp-g{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px;align-items:start}'+
 '.kxc{border:1px solid var(--ln);border-radius:18px;padding:14px;background:var(--c1);min-width:0}'+
 '.kxc.off{opacity:.92}.kxc-h{display:flex;align-items:center;gap:8px;min-width:0}.kxc-h b{font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}'+
 '.kxc-h .sp{flex:1}.kxc-tag{font-size:11px;border:1px solid var(--ln);border-radius:8px;padding:2px 7px;color:var(--s);white-space:nowrap}'+
 '.kxc-tag.main{color:var(--a);border-color:color-mix(in srgb,var(--a) 55%,transparent)}'+
 '.kxc-st{display:flex;flex-wrap:wrap;gap:4px 12px;color:var(--s);font-size:12px;margin:6px 0 10px}.kxc-st b{color:var(--t);font-weight:600}'+
 '.kxc-sv{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}'+
 '.kxs{border:1px solid var(--ln);border-radius:14px;padding:9px 10px;min-width:0;background:transparent;color:var(--t);font:inherit;text-align:start;cursor:pointer;display:flex;flex-direction:column;gap:3px}'+
 '.kxs:hover{border-color:color-mix(in srgb,var(--a) 50%,var(--ln))}.kxs>span{display:flex;align-items:center;gap:6px;font-weight:700;font-size:13px}'+
 '.kxs small{color:var(--s);font-size:11px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.kxs.on{border-color:color-mix(in srgb,var(--ok) 55%,transparent)}'+
 '.kxs.on>span:before,.kxs.no>span:before,.kxs.bad>span:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--ok);flex:none}'+
 '.kxs.no>span:before{background:var(--s);opacity:.5}.kxs.bad>span:before{background:var(--bad)}.kxs.add{border-style:dashed;color:var(--s)}'+
 '.kxs.wide{grid-column:1/-1;flex-direction:row;align-items:center;justify-content:space-between;gap:10px;cursor:default}'+
 '.kxs.wide .sw{flex:none}.kxs .pl{direction:ltr;unicode-bidi:isolate}'+
 '.kxc-miss{border:1px dashed color-mix(in srgb,var(--warn) 60%,transparent);border-radius:14px;padding:10px;margin-top:10px;font-size:12px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}'+
 '.kxc-miss span{flex:1;min-width:150px}.kxc-miss pre{width:100%;margin:6px 0 0;white-space:pre-wrap;font-size:11px;max-height:140px;overflow:auto;direction:ltr;text-align:left;background:var(--in);border-radius:8px;padding:6px}'+
 '.kxc-m{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-top:10px}'+
 '.kxc-more{width:100%;margin-top:10px;border:1px dashed var(--ln);background:transparent;color:var(--s);border-radius:12px;padding:7px;font:inherit;font-size:12px;cursor:pointer}'+
 '.kxc-act{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:6px;margin-top:8px}.kxc-act button{width:100%}'+
 '.kxp-clash{border:1px solid color-mix(in srgb,var(--warn) 55%,transparent);border-radius:16px;padding:12px;margin:0 0 12px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}'+
 '.kxp-clash div{flex:1;min-width:220px;font-size:12px}.kxp-clash b{color:var(--warn)}'+
 '.kxp-steps{display:grid;gap:6px;margin-top:10px}.kxp-steps div{display:flex;gap:8px;align-items:center;font-size:13px}'+
 '.kxp-ports{display:flex;flex-wrap:wrap;gap:6px;margin-top:6px}.kxp-ports span{border:1px solid var(--ln);border-radius:8px;padding:2px 8px;font-size:12px;direction:ltr}'+
 '.kxseg{display:grid;grid-template-columns:1fr 1fr;gap:6px}'+
 // pop-ups above the phone's bottom tab bar (it covered their last buttons: "Create command", "Save"…)
 '.modal{z-index:60!important}#toast{z-index:70!important}'+
 // a short laptop screen: the side menu scrolls instead of cutting off its last items
 '@media(min-width:900px){.side{overflow-y:auto;overscroll-behavior:contain}}'+
 '@media(max-width:520px){.kxp-g{grid-template-columns:1fr}.kxc{padding:12px}.kxc-m{gap:6px}}';
 document.head.appendChild(st)})();

function fl(cc){return window.flagOf?flagOf(cc):''}
function isIr(s){return s.loc=='iran'||String(s.cc||'').toUpperCase()=='IR'}
function q(id){return encodeURIComponent(id)}
function nodeId(s){return s.node?s.node.id:''}

// ---------------------------------------------------------------- data
function load(quiet){
 return Promise.all([api('GET','/api/servers'),api('GET','/api/nodes').catch(function(){return null}),api('GET','/api/tunnels').catch(function(){return null}),
  api('GET','/api/xray').catch(function(){return null}),api('GET','/api/dns').catch(function(){return null})]).then(function(r){
  SV.d=r[0];if(r[1])S.nodes=r[1];if(r[2]){if(window.TN)TN.d=r[2];else window.TN={d:r[2]}}if(r[3]&&window.XR)XR.d=r[3];if(r[4]&&window.DN)DN.d=r[4];
  if(S.page=='nodes')draw();waitTick();return SV.d}).catch(function(e){if(!quiet)fail(e)})}
window.srvLoad=load;

// ---------------------------------------------------------------- page
window.pNodes=function(){
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Servers')+'</h2><p>'+t('The panel runs on one server. Every other server is a node: add it with one command, then switch on here what it runs.')+'</p></div>'+
  '<div class="kxp-top"><button class="b2" onclick="updateAll()">⇪ '+t('Update all')+'</button><button class="btn" onclick="srvAdd()">'+ic('plus',15)+' '+t('Add server')+'</button></div></div>'+
  '<div id="svp_clash"></div><div class="kxp-f" id="svp_f"></div><div class="kxp-g" id="svp_g">'+t('Loading…')+'</div>';
 load();autoRefresh(function(){load(true)});
 if(S.openAdd){S.openAdd=false;setTimeout(srvAdd,150)}};

function draw(){var g=$('#svp_g');if(!g||!SV.d)return;var list=SV.d.servers||[];
 var fs={all:function(){return true},abroad:function(s){return !isIr(s)},iran:isIr};if(!fs[SV.f])SV.f='all';
 $('#svp_f').innerHTML=[['all','All'],['abroad','Abroad'],['iran','Iran']].map(function(f){return '<button class="'+(SV.f==f[0]?'on':'')+'" onclick="SV.f=\''+f[0]+'\';srvDraw()">'+t(f[1])+'<b>'+N(list.filter(fs[f[0]]).length)+'</b></button>'}).join('');
 var cl=SV.d.clashes||[];
 $('#svp_clash').innerHTML=cl.length?'<div class="kxp-clash"><div><b>⚠ '+t('Port clash')+'</b><br>'+cl.map(function(c){return 'UDP <b class="ltr">'+N(c.port)+'</b> '+t('is used by')+' '+c.users.map(function(u){return esc(u.name)+' ('+protoName(u.proto)+')'}).join('، ')}).join('<br>')+
  '<p class="muted" style="margin:6px 0 0">'+t('One tunnel entry cannot carry the same port to two servers. Fix moves the later server to a free port; tunnels that carry the old port follow.')+'</p></div><button class="btn" onclick="srvFixPorts()">'+t('Fix ports')+'</button></div>':'';
 var cards=list.filter(fs[SV.f]).map(card).join('');
 g.innerHTML=cards||'<p class="muted">'+t('No server here')+'</p>'}
window.srvDraw=draw;

function protoName(p){return ({wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2',kmix:'KANKI MIX'})[p]||p}

function card(s){var k=esc(s.key),a=s.agent,n=s.node,j=s.jobs||{},online=s.local||(a&&a.online)||(n&&n.online),h=n&&window.nHealthOf?nHealthOf(n):null;
 var tags='<span class="kxc-tag'+(s.local?' main':'')+'">'+t(s.local?'Panel server':'Node')+'</span><span class="kxc-tag">'+t(isIr(s)?'Iran':'Abroad')+'</span>';
 var st=[];
 if(!s.local)st.push(t('agent')+': <b>'+(a?(a.online?t('Connected'):t('Not connected')):'—')+'</b>');
 if(n)st.push('VPN: <b>'+(n.enabled?(s.local||n.online?t('On'):t('Not connected')):t('Off'))+'</b>');
 if(n&&n.users!=null&&n.enabled)st.push(N(n.users)+' '+t('users'));
 var ver=(n&&n.info&&n.info.version)||(a&&a.version)||'';if(ver)st.push('v'+esc(ver));
 if(!s.local&&a&&a.last_seen&&!a.online)st.push(t('Last contact')+' '+ago(a.last_seen));
 // services
 var cells=[];
 if(n){var p=s.ports||{},pl=['wg','awg','hy2','kmix'].filter(function(x){return p[x]}).map(function(x){return ({wg:'WG',awg:'AWG',hy2:'Hy2',kmix:'MIX'})[x]+' '+N(p[x])}).join(' · ');
  cells.push('<div class="kxs wide '+(n.enabled?'on':'no')+'"><span>'+t('VPN for users')+'</span>'+sw('',n.enabled,"srvVpn('"+k+"',this.checked)")+'</div>');
  if(pl)cells.push('<button class="kxs '+(n.enabled?'on':'no')+'" style="grid-column:1/-1" onclick="srvPorts(\''+k+'\')"><span>'+t('Ports')+'</span><small class="pl">UDP '+pl+'</small></button>')}
 if(a){var xr=j.xray_on;
  cells.push('<button class="kxs '+(j.tunnels?'on':'no')+'" onclick="location.hash=\'#tunnels\'"><span>'+t('Tunnels')+'</span><small>'+N(j.tunnels||0)+'</small></button>');
  cells.push(xr?'<button class="kxs on" onclick="location.hash=\'#xray\'"><span>Xray</span><small>'+N(j.xray||0)+' '+t('inbounds')+'</small></button>':'<button class="kxs add" onclick="srvAddXray(\''+k+'\')"><span>+ '+t('Add Xray')+'</span><small>VLESS · VMess · Trojan</small></button>');
  cells.push(j.dns?'<button class="kxs on" onclick="location.hash=\'#dns/servers\'"><span>'+t('Kanki DNS')+'</span><small>'+t(j.dns=='relay'?'relay':'exit')+'</small></button>':'<button class="kxs add" onclick="srvAddDns(\''+k+'\','+(isIr(s)?1:0)+')"><span>+ '+t('Add DNS')+'</span><small>'+t(isIr(s)?'relay':'exit')+'</small></button>');
  if(j.emergency)cells.push('<button class="kxs on" onclick="location.hash=\'#emergency\'"><span>'+t('Emergency chat')+'</span><small>✓</small></button>');
  if(j.subsrv)cells.push('<button class="kxs on" onclick="location.hash=\'#settings\'"><span>'+t('Subscription')+'</span><small>✓</small></button>')}
 // the part that is missing
 var miss='';
 if(!n&&a){var su=s.setup||null;
  if(s.pending&&!a.last_seen)miss='<div class="kxc-miss"><span>'+t('Waiting for this server: run its command')+'</span><button class="b2 sm" onclick="srvCmd(\''+k+'\')">'+t('Show command')+'</button></div>';
  else if(su&&su.state=='running')miss='<div class="kxc-miss"><span class="spin"></span><span>'+t('Installing the VPN part…')+'</span>'+(su.tail?'<pre>'+esc(su.tail)+'</pre>':'')+'</div>';
  else miss='<div class="kxc-miss"><span>'+(su&&su.state=='failed'?'<b class="bad2">'+t('VPN install failed')+'</b>':t('VPN is not installed on this server'))+'</span><button class="b2 sm" onclick="srvComplete(\''+k+'\','+(isIr(s)?0:1)+')">'+t(su&&su.state=='failed'?'Try again':'Install VPN')+'</button>'+(su&&su.state=='failed'&&su.tail?'<pre>'+esc(su.tail)+'</pre>':'')+'</div>'}
 if(n&&!a&&!s.local)miss='<div class="kxc-miss"><span>'+t('Tunnels, Xray and DNS are not installed on this server')+'</span><button class="b2 sm" onclick="srvComplete(\''+k+'\',1)">'+t('Install')+'</button></div>';
 // health
 var met='';var stt=n&&n.info&&n.info.stats;
 if(stt&&window.nMeter)met='<div class="kxc-m">'+nMeter('CPU',+stt.cpu||0,N(Math.round(+stt.cpu||0))+'%')+nMeter('RAM',pc(stt.mem_used,stt.mem_total),N(Math.round(pc(stt.mem_used,stt.mem_total)))+'%')+nMeter('Disk',pc(stt.disk_used,stt.disk_total),N(Math.round(pc(stt.disk_used,stt.disk_total)))+'%')+'</div>';
 var why=h&&h.r&&h.r.length&&n.enabled?'<ul class="nwhy">'+h.r.map(function(x){return '<li class="l'+x[0]+'">'+t(x[1])+'</li>'}).join('')+'</ul>':'';
 var op=!!SV.open[s.key];
 var acts=[];
 acts.push('<button class="b2" onclick="srvEdit(\''+k+'\')">'+ic('edit',14)+' '+t('Settings')+'</button>');
 if(n){var ni=esc(n.id);
  acts.push('<button class="b2" onclick="nHealth(\''+ni+'\')">♡ '+t('Health')+'</button>');
  acts.push('<button class="b2" onclick="nAct(\''+ni+'\',\'sync\')">⇄ '+t('Sync')+'</button>');
  acts.push('<button class="b2" onclick="nAct(\''+ni+'\',\'repair\')">↻ '+t('Repair')+'</button>');
  if(!s.local)acts.push('<button class="b2" onclick="nAct(\''+ni+'\',\'update\')">⇪ '+t('Update agent')+'</button>');
  acts.push('<button class="b2 okb" onclick="nAssign(\''+ni+'\',1)">'+ic('plus',14)+' '+t('Add to all users')+'</button>');
  if(!s.local)acts.push('<button class="b2" onclick="nAssign(\''+ni+'\',0)">'+t('Remove from all users')+'</button>')}
 if(a&&!s.local&&window.tunSrvEdit)acts.push('<button class="b2" onclick="tunSrvEdit(\''+esc(a.id)+'\')">'+ic('tunnel',14)+' '+t('Tunnel agent settings')+'</button>');
 if(!s.local)acts.push('<button class="b2 bd" onclick="srvDel(\''+k+'\')">'+ic('trash',14)+' '+t('Delete server')+'</button>');
 var col=h?h.c:(online?'g':'r');
 return '<div class="kxc'+(online?'':' off')+'"><div class="kxc-h"><span class="dot '+(online?(col=='r'?'y':col):'r')+'"></span>'+fl(s.cc)+'<b>'+esc(s.name)+'</b><span class="sp"></span>'+tags+'</div>'+
  '<div class="kxc-st">'+st.join('<span>·</span>')+'</div>'+
  (cells.length?'<div class="kxc-sv">'+cells.join('')+'</div>':'')+miss+met+why+
  '<button class="kxc-more" onclick="SV.open[\''+k+'\']=!SV.open[\''+k+'\'];srvDraw()">'+t(op?'Hide':'Details')+' '+(op?'▴':'▾')+'</button>'+
  (op?'<div class="kxc-act">'+acts.join('')+'</div>':'')+'</div>'}

function find(key){var l=(SV.d&&SV.d.servers)||[];for(var i=0;i<l.length;i++)if(l[i].key==key)return l[i]}

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
window.srvVpn=function(key,on){if(!confirm(t(on?'Switch the VPN on: users that accept all servers are sent here.':'Switch the VPN off on this server? Its users are taken off; it keeps carrying tunnels.'))){draw();return}
 api('POST','/api/servers/'+q(key)+'/vpn',{on:on}).then(function(){toast(t('Done'));load(true)}).catch(function(e){fail(e);load(true)})};

window.srvComplete=function(key,vpn){var s=find(key)||{};
 if(String(key).indexOf('node:')==0){if(!confirm(t('Install tunnels, Xray and DNS (the server agent) on this server? It starts next to its VPN within seconds.')))return;
  toast(t('Checking…'));api('POST','/api/servers/'+q(key)+'/complete').then(function(){toast(t('Done'));setTimeout(function(){load(true)},4000)}).catch(fail);return}
 modal(mhead(t('Install VPN'),s.name)+'<p>'+t('Install the VPN part on this server? It runs by itself on the server and takes a few minutes.')+'</p>'+
  '<label class="chk"><input type="checkbox" id="sc_vpn" '+(vpn?'checked':'')+'>'+t('Serve users once installed')+'</label>'+
  '<label class="f">'+t('Domain (optional, for a real SSL certificate)')+'</label><input id="sc_dm" class="ltr" value="'+esc(s.domain||'')+'">'+
  '<div class="g2" style="margin-top:12px"><button class="b2" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn" id="sc_go">'+t('Install VPN')+'</button></div>');
 $('#sc_go').onclick=function(){var me=this;me.disabled=true;api('POST','/api/servers/'+q(key)+'/complete',{vpn:$('#sc_vpn').checked,domain:$('#sc_dm').value}).then(function(){closeModal();toast(t('Installing the VPN part…'));setTimeout(function(){load(true)},6000)}).catch(function(e){me.disabled=false;fail(e)})}};

window.srvEdit=function(key){var s=find(key);if(!s)return;var a=s.agent||{};
 modal(mhead(t('Settings'),s.name)+'<label class="f">'+t('Name')+'</label><input id="se_nm" value="'+esc(s.name)+'" maxlength="40">'+
  '<label class="f">'+t('Location')+'</label><div class="seg kxseg" id="se_loc"><button type="button" data-l="abroad">'+t('Abroad')+'</button><button type="button" data-l="iran">'+t('Iran')+'</button></div>'+
  (s.agent?'<label class="f">'+t('Address other servers use to reach it (optional)')+'</label><input id="se_ad" class="ltr" value="'+esc(a.addr||'')+'" placeholder="'+esc(a.ip||'')+'">':'')+
  (s.node&&window.nodeEdit?'<button class="b2" style="width:100%;margin-top:10px" onclick="closeModal();nodeEdit(\''+esc(s.node.id)+'\')">'+ic('edit',14)+' VPN: '+t('Settings')+'</button>':'')+
  '<div class="g2" style="margin-top:12px"><button class="b2" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn" id="se_go">'+t('Save')+'</button></div>');
 var loc=isIr(s)?'iran':'abroad',set=function(l){loc=l;$$('#se_loc button').forEach(function(b){b.classList.toggle('on',b.dataset.l==l)})};
 $$('#se_loc button').forEach(function(b){b.onclick=function(){set(b.dataset.l)}});set(loc);
 $('#se_go').onclick=function(){var b={name:$('#se_nm').value,loc:loc};if($('#se_ad'))b.addr=$('#se_ad').value;
  api('PUT','/api/servers/'+q(key),b).then(function(){closeModal();toast(t('Done'));load(true)}).catch(fail)}};

window.srvPorts=function(key){var s=find(key);if(!s||!s.node)return;
 if(window.v37NodeMenu)return v37NodeMenu(s.node.id);if(window.nodeEdit)nodeEdit(s.node.id)};

window.srvDel=function(key){if(!confirm(t('Delete this whole server? Its tunnels must be deleted first. The server removes everything Kanki installed on it (VPN, tunnels, Xray, DNS) and uninstalls itself.')))return;
 toast(t('Removing…'));api('DELETE','/api/servers/'+q(key)).then(function(){toast(t('Removed'));load(true)}).catch(fail)};

window.srvFixPorts=function(){if(!confirm(t("Users' WireGuard / AmneziaWG files of the moved server must be downloaded again (subscription links and the app update by themselves). Continue?")))return;
 toast(t('Checking…'));api('POST','/api/servers/fix-ports').then(function(r){var m=r.moved||[];
  modal(mhead(t(m.length?'Ports moved':'No clash'))+(m.length?'<div class="list">'+m.map(function(x){return '<div class="li"><span><b>'+esc(x.server)+'</b> '+protoName(x.proto)+(x.error?'<small class="bad2">'+esc(x.error)+'</small>':'')+'</span><span class="ltr">'+N(x.old)+' → '+N(x.new)+' '+(x.ok?'✅':'❌')+'</span></div>'}).join('')+'</div>':''));
  load(true)}).catch(fail)};

// Xray / DNS on one server, from its card
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
 api('GET','/api/restore/check').then(function(r){if(!r.restored_at||Date.now()/1000-r.restored_at>3*86400||$('#svp_rs')||S.page!='backup')return;
  var sv=r.servers||[],bad=sv.filter(function(x){return (x.agent===false)||(x.vpn===false&&x.vpn_on)});
  var c=document.createElement('div');c.className='card';c.id='svp_rs';
  c.innerHTML='<h3>'+t('After restore')+'</h3><p class="sub">'+t('Restored')+' '+ago(r.restored_at)+(r.moved_from?' · '+t('from')+' <span class="ltr">'+esc(r.moved_from)+'</span>':'')+'</p>'+
   (bad.length?'<div class="list">'+sv.map(function(x){var ok=x.agent!==false&&!(x.vpn===false&&x.vpn_on);return '<div class="li"><span>'+esc(x.name)+'</span><span>'+(ok?'✅':'⏳ '+t('Not connected yet'))+'</span></div>'}).join('')+'</div>':'<p>✅ '+t('Every server is connected')+'</p>');
  var ph=$('#pg .ph');if(ph)ph.parentNode.insertBefore(c,ph.nextSibling)}).catch(function(){})}
if(window.pBackup){var _pb=window.pBackup;window.pBackup=function(){_pb.apply(this,arguments);setTimeout(restoreBox,400)}}
})();
