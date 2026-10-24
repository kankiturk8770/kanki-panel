// Kanki Panel 3.9.3: VPN services, one tab per service (KANKI MIX, Xray, WireGuard, AmneziaWG,
// Hysteria2). Each tab lists the servers that run it (abroad and Iran apart), one row per server; a
// row's arrow opens that service's settings on that server (one row open at a time, closed again on
// leaving the page or after saving). The Servers page keeps only the servers themselves.
(function(){
'use strict';
var ACC=window.KAcc;if(!ACC)return;
if(typeof FA!='undefined')Object.assign(FA,{
 "WireGuard":"WireGuard","AmneziaWG":"AmneziaWG","Hysteria2":"Hysteria2",
 "Plain WireGuard on every VPN server. Inside Iran it works only through a tunnel.":"WireGuard ساده روی همه‌ی سرورهای VPN. داخل ایران فقط از راه تانل کار می‌کند.",
 "WireGuard with obfuscated packets (Jc, S1, S2, H1-H4): passes most filters directly.":"WireGuard با بسته‌های مبهم (Jc، S1، S2، H1-H4): مستقیم از بیشتر فیلترها رد می‌شود.",
 "QUIC-based, fast on lossy internet, with Salamander obfuscation.":"بر پایه‌ی QUIC، سریع روی اینترنت پرافت، با مبهم‌سازی Salamander.",
 "On for all users":"روشن برای همه‌ی کاربران","Off for all users":"خاموش برای همه‌ی کاربران",
 "Running servers":"سرورهای فعال","Users with it":"کاربرانی که دارند","Through a tunnel":"از راه تانل","Direct":"مستقیم",
 "running":"روشن","stopped":"متوقف","not installed":"نصب نیست","relay":"رله","off":"خاموش",
 "UDP port":"پورت UDP","Save port":"ذخیره‌ی پورت","Users connect to":"کاربرها به این آدرس وصل می‌شوند","change in Servers":"تغییر در صفحه‌ی سرورها",
 "Reaches this server through":"از این مسیر به این سرور می‌رسد","No tunnel carries this port: users connect to the server directly":"هیچ تانلی این پورت را نمی‌برد: کاربرها مستقیم به سرور وصل می‌شوند",
 "Obfuscation":"مبهم‌سازی","Obfuscation password":"رمز مبهم‌سازی","Certificate":"گواهی","self-signed":"خودامضا","domain":"دامنه",
 "Direct name":"اسم مستقیم","Points at this server":"درست است","Not set yet":"هنوز تنظیم نشده","Points elsewhere":"به سرور دیگری اشاره می‌کند",
 "Point it at":"به این آی‌پی اشاره کند","Change the base domain":"تغییر دامنه‌ی اصلی",
 "Make each direct name an A record pointing at the server's IP (Cloudflare: DNS only, grey cloud). Until it points right, the app gets the server's own address.":"هر اسم مستقیم را یک رکورد A بساز که به آی‌پی سرور اشاره کند (کلادفلر: فقط DNS، ابر خاکستری). تا وقتی درست نشده، برنامه آدرس خود سرور را می‌گیرد.",
 "No VPN server yet":"هنوز سرور VPN نیست","Add server":"افزودن سرور","Restart VPN services":"ری‌استارت سرویس‌های VPN","Health":"سلامت",
 "Add this server to all users":"افزودن این سرور به همه‌ی کاربران","Remove this server from all users":"حذف این سرور از همه‌ی کاربران",
 "General settings":"تنظیمات کلی","KANKI MIX on this server":"KANKI MIX روی این سرور","Port of this server":"پورت این سرور",
 "Route":"مسیر","Address":"آدرس","automatic":"خودکار","Second config through the tunnel":"کانفیگ دوم از راه تانل","Iran address":"آدرس ایران",
 "Name in the app":"اسم در برنامه","tunnel":"تانل","Users also get":"کاربرها این را هم می‌گیرند",
 "No Kanki tunnel carries this port to the server. Make a tunnel (or a multi-location route) that carries it, or forward it on that address some other way.":"هیچ تانل کانکی این پورت را به این سرور نمی‌برد. یک تانل (یا مسیر چندمرحله‌ای) بساز که آن را ببرد، یا روی آن آدرس به روش دیگری فورواردش کن.",
 "Inbounds":"اینباندها","Inbound":"اینباند","Config":"کانفیگ","Repair":"تعمیر","Edit server":"ویرایش سرور","Remove Xray from this server":"حذف Xray از این سرور",
 "No inbound on this server yet":"هنوز اینباندی روی این سرور نیست","inbounds":"اینباند","Running":"در حال اجرا","Not running":"اجرا نمی‌شود","Waiting for the server…":"منتظر سرور…",
 "Saved":"ذخیره شد","Cancel":"انصراف","Save":"ذخیره","Tunnels page":"صفحه‌ی تانل‌ها","users":"کاربر","Sync":"همگام‌سازی"
});

// ---------------------------------------------------------------- the tabs of VPN services
var P=window.PAGES||[];
[['wg','WireGuard','shield2'],['awg','AmneziaWG','shield2'],['hy2','Hysteria2','shield2']].forEach(function(x){if(!P.some(function(y){return y[0]==x[0]}))P.push(x)});
if(window.V37&&V37.SECS)V37.SECS.forEach(function(s){if(s[0]!='vpnsec')return;
 s[3]=[['vpn','','Overview'],['kmix','','KANKI MIX'],['xray','','Xray'],['wg','','WireGuard'],['awg','','AmneziaWG'],['hy2','','Hysteria2'],['antidpi','','Anti-DPI']]});

// leaving a page closes its open row
var _route=window.route;
window.route=function(){Object.keys(ACC.open).forEach(function(k){ACC.open[k]=''});return _route.apply(this,arguments)};

function fl(cc){return window.flagOf?flagOf(cc):''}
function isIr(s){return s.loc=='iran'||String(s.cc||'').toUpperCase()=='IR'}
function q(id){return encodeURIComponent(id)}
function boxes(g,list,row){var ab=list.filter(function(x){return !isIr(x)}),ir=list.filter(isIr);
 var box=function(kind,title,icon,rows){return rows.length?'<section class="kxbox '+kind+'"><div class="kxbox-h"><span class="kxbox-i">'+icon+'</span><b>'+t(title)+'</b><small>'+N(rows.length)+'</small></div><div class="kxl">'+rows.map(row).join('')+'</div></section>':''};
 return box('abroad','Abroad servers','🌍',ab)+box('iran','Iran servers',fl('IR'),ir)}
function srvByNode(nid){return ((SV.d&&SV.d.servers)||[]).filter(function(s){return s.node&&s.node.id==nid})[0]||null}
function agentOf(s){return s.local?'local':(s.agent?s.agent.id:'')}

// the servers a UDP port of a server comes in through (Iran → Turkey), from the tunnels the panel has
function routeVia(sid,port){var tl=((window.TN&&TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.enabled!==false&&x.kind!='awg'}),names=[],cur=sid,p=+port,seen=[sid];
 if(!sid||!p)return null;
 for(var k=0;k<8;k++){var hit=null;tl.forEach(function(x){if(hit||x.exit!=cur||seen.indexOf(x.entry)>=0)return;
   (Array.isArray(x.udp)?x.udp:String(x.udp||'').split(',')).join(',').split(',').forEach(function(it){it=String(it).trim();if(!it||hit)return;var a=it,b=it;if(it.indexOf(':')>0){a=it.split(':')[0];b=it.split(':')[1]}
    if(+b==p&&/^\d+$/.test(a))hit={e:x.entry,p:+a}})});
  if(!hit)break;seen.push(hit.e);names.unshift((window.tunSrv?tunSrv(hit.e):{name:hit.e}).name);cur=hit.e;p=hit.p}
 return names.length?{via:names,port:p}:null}
function viaLine(r,me){return r?'<span class="kxr-st g">'+t('Through a tunnel')+'</span> <span>'+r.via.map(esc).join(' → ')+' → '+esc(me)+'</span>'+(r.port?' · <span class="ltr">UDP '+N(r.port)+'</span>':''):''}

window.svcReload=function(){var f=ACC.draw['pv_'+S.page]||ACC.draw[S.page=='kmix'?'km':''];if(f)f(true)};

// ---------------------------------------------------------------- WireGuard, AmneziaWG, Hysteria2
var PV={wg:{name:'WireGuard',svc:'wireguard',desc:'Plain WireGuard on every VPN server. Inside Iran it works only through a tunnel.'},
 awg:{name:'AmneziaWG',svc:'amneziawg',desc:'WireGuard with obfuscated packets (Jc, S1, S2, H1-H4): passes most filters directly.'},
 hy2:{name:'Hysteria2',svc:'hysteria2',desc:'QUIC-based, fast on lossy internet, with Salamander obfuscation.'}};
var PD={dir:null,ov:null};
function pvState(p,s){var n=s.node,i=(n&&n.info)||{},sv=(i.services||[]).filter(function(x){return x.key==PV[p].svc})[0],port=(s.ports||{})[p]||i[p+'_port'];
 if(!port&&!sv)return ['n',t('not installed'),port];if(!n.enabled)return ['n',t(s.local?'off':'relay'),port];
 if(sv&&!sv.active)return ['r',t('stopped'),port];return ['g',t('running'),port]}
function protoPage(p){var g='pv_'+p;ACC.open[g]='';
 $('#pg').innerHTML='<div class="ph"><div><h2>'+PV[p].name+'</h2><p>'+t(PV[p].desc)+'</p></div>'+
  '<div class="row" style="gap:6px"><button class="b2" onclick="srvProtoAll(\''+p+'\',0)">'+t('Off for all users')+'</button><button class="btn" onclick="srvProtoAll(\''+p+'\',1)">'+ic('users',15)+' '+t('On for all users')+'</button></div></div>'+
  '<div class="kv k3" id="pv_kv"></div><div id="pv_list">'+t('Loading…')+'</div>'+(p=='awg'?'<div id="pv_dir"></div>':'');
 var go=function(quiet){return Promise.all([srvLoad(true),api('GET','/api/overview').catch(function(){return null}),p=='awg'?api('GET','/api/servers/direct').catch(function(){return null}):null]).then(function(r){PD.ov=r[1]||PD.ov;if(r[2])PD.dir=r[2];if(S.page==p)drawPv(p,!quiet)})};
 ACC.draw[g]=function(){drawPv(p,true)};
 go(false);autoRefresh(function(){go(true)})}
function drawPv(p,force){var g='pv_'+p,el=$('#pv_list');if(!el||!SV.d)return;
 var list=(SV.d.servers||[]).filter(function(s){return !!s.node}),run=list.filter(function(s){return pvState(p,s)[0]=='g'}).length,
  viaT=list.filter(function(s){return routeVia(agentOf(s),pvState(p,s)[2])}).length,ov=PD.ov||{},users=((ov.protocols||{})[p]);
 $('#pv_kv').innerHTML='<div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(list.length)+'</b></div><div><small>'+t('Users with it')+'</small><b>'+(users==null?'—':N(users))+'</b></div><div><small>'+t('Through a tunnel')+'</small><b>'+N(viaT)+'</b></div>';
 if(!force&&accBusy(g))return;
 el.innerHTML=list.length?boxes(g,list,function(s){return pvRow(p,s)}):'<div class="card muted" style="text-align:center">'+t('No VPN server yet')+' · <a href="#nodes">'+t('Add server')+'</a></div>';
 if(p=='awg')dirDraw()}
function pvRow(p,s){var st=pvState(p,s),port=st[2];
 var head='<span class="dot '+(st[0]=='n'?'':st[0])+'"></span>'+fl(s.cc)+'<b>'+esc(s.name)+'</b>'+(s.local?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+'<span class="sp"></span>'+
  '<span class="kxr-st '+st[0]+'">'+esc(st[1])+'</span>'+(port?'<small class="ltr">UDP '+N(port)+'</small>':'');
 return accRow('pv_'+p,s.key,head,function(){return pvBody(p,s)})}
function pvBody(p,s){var n=s.node,i=n.info||{},st=pvState(p,s),port=st[2],k=esc(s.key),ni=esc(n.id),r=routeVia(agentOf(s),port);
 var h='<div class="kxr-line"><span><b>'+esc(st[1])+'</b></span>'+(n.enabled?'<span>·</span><span>'+N(n.users||0)+' '+t('users')+'</span>':'')+
  '<span>·</span><span>'+t('Users connect to')+': <b class="ltr">'+esc(n.effective_endpoint||'—')+'</b> <a href="#nodes" style="font-size:11px">'+t('change in Servers')+'</a></span></div>'+
  '<div class="kxr-line">'+(r?viaLine(r,s.name):'<span>'+t('No tunnel carries this port: users connect to the server directly')+'</span>')+'</div>';
 if(port||st[0]!='n')h+='<div class="kxr-sec">'+t('UDP port')+'</div><div class="kxm-row"><div><input id="pv_p" class="ltr" inputmode="numeric" value="'+esc(String(port||''))+'"></div><button class="btn sm" id="pv_ps">'+t('Save port')+'</button></div><div class="kxm-warn" id="pv_pw"></div>'+
  (p!='hy2'?'<p class="muted" style="font-size:11px;margin:2px">'+t("Users' WireGuard / AmneziaWG files of this server must be downloaded again after a port change; subscription links and the app update by themselves.")+'</p>':'');
 if(p=='awg'&&(i.awg||[]).length)h+='<div class="kxr-sec">'+t('Obfuscation')+'</div><div class="kxp-ports">'+(i.awg||[]).map(function(x){return '<span>'+esc(x[0])+' '+esc(x[1])+'</span>'}).join('')+'</div>';
 if(p=='awg'){var d=((PD.dir&&PD.dir.servers)||[]).filter(function(x){return x.node==n.id})[0];
  if(d)h+='<div class="kxr-sec">'+t('Direct name')+'</div><div class="kxr-line"><b class="ltr">'+esc(d.host||'—')+'</b><span>·</span><span>'+t('Point it at')+' <b class="ltr">'+esc(d.ip||'—')+'</b></span><span>·</span><span>'+dirSt(d)+'</span></div>'}
 if(p=='hy2')h+='<div class="kxr-sec">'+t('Obfuscation')+'</div><div class="kxr-line"><span>'+t('Obfuscation password')+': <b class="ltr" id="pv_ob" data-v="'+esc(i.hy2_obfs||'')+'">'+(i.hy2_obfs?'••••••••':'—')+'</b>'+(i.hy2_obfs?' <a href="javascript:void 0" onclick="var e=$(\'#pv_ob\');e.textContent=e.dataset.v">👁</a>':'')+'</span>'+
  '<span>·</span><span>'+t('Certificate')+': <b class="ltr">'+(i.hy2_insecure?t('self-signed'):esc(i.hy2_sni||t('domain')))+'</b></span></div>';
 h+='<div class="kxacts"><button class="b2 sm" onclick="nAct(\''+ni+'\',\'repair\')">↻ '+t('Restart VPN services')+'</button><button class="b2 sm" onclick="nAct(\''+ni+'\',\'sync\')">⇄ '+t('Sync')+'</button><button class="b2 sm" onclick="nHealth(\''+ni+'\')">♡ '+t('Health')+'</button>'+
  '<button class="b2 sm okb" onclick="nAssign(\''+ni+'\',1)">'+t('Add this server to all users')+'</button>'+(s.local?'':'<button class="b2 sm" onclick="nAssign(\''+ni+'\',0)">'+t('Remove this server from all users')+'</button>')+'</div>';
 setTimeout(function(){var el=$('#pv_p'),w=$('#pv_pw'),b=$('#pv_ps');if(!el)return;var f=function(){var m=srvPortClash(s.key,p,el.value);w.textContent=m;b.disabled=!!m};el.oninput=f;f();
  b.onclick=function(){srvSavePort(s.key,p,el.value,function(){accClose('pv_'+p)})}},0);
 return h}
function dirSt(r){return !r.host?'<span class="muted">'+t('Country not known yet')+'</span>':r.ok?'✅ '+t('Points at this server'):((r.points_to||[]).length?'⚠️ '+t('Points elsewhere')+' <span class="ltr muted">'+esc(r.points_to.join(', '))+'</span>':'⚪ '+t('Not set yet'))}
function dirDraw(){var el=$('#pv_dir'),d=PD.dir;if(!el||!d)return;
 el.innerHTML='<div class="card" style="max-width:980px"><h3>'+t('Direct domains')+'</h3><p class="sub">'+t("Make each direct name an A record pointing at the server's IP (Cloudflare: DNS only, grey cloud). Until it points right, the app gets the server's own address.")+'</p>'+
  '<div class="ptab"><table><thead><tr><th>'+t('Name')+'</th><th>'+t('Domain')+'</th><th>'+t('Point it at')+'</th><th>'+t('Status')+'</th><th>'+t('Through')+'</th></tr></thead><tbody>'+
  (d.servers||[]).map(function(r){return '<tr><td>'+fl(r.cc)+' '+esc(r.name)+'</td><td class="ltr"><b>'+esc(r.host||'—')+'</b></td><td class="ltr">'+esc(r.ip||'—')+'</td><td>'+dirSt(r)+'</td><td>'+t(r.via=='direct'?'Direct':'Tunnel')+'</td></tr>'}).join('')+
  '</tbody></table></div><p class="muted" style="margin:8px 0 0">*.<span class="ltr">'+esc(d.base||'—')+'</span> · <a href="javascript:void 0" onclick="svcDirBase()">'+t('Change the base domain')+'</a></p></div>'}
window.svcDirBase=function(){var v=prompt(t('Base domain for the direct names (like example.com); empty = the panel domain without its first part'),(PD.dir&&PD.dir.base)||'');if(v===null)return;
 api('PUT','/api/servers/direct',{base:v.trim()}).then(function(d){PD.dir=d;dirDraw();drawPv('awg',true)}).catch(fail)};
window.p_wg=function(){protoPage('wg')};window.p_awg=function(){protoPage('awg')};window.p_hy2=function(){protoPage('hy2')};

// ---------------------------------------------------------------- KANKI MIX: a row per server
if(window.kmDraw){
 window.kmServers=function(d){var list=(d.servers||[]).map(function(x){var s=srvByNode(x.id)||{key:'node:'+x.id,name:x.name,cc:'',loc:''};return {k:x,s:s,key:s.key||x.id,name:x.name,cc:s.cc,loc:s.loc,local:x.main}});
  if(!list.length)return '<p class="muted">—</p>';
  return boxes('km',list,function(r){return kmRow(d,r)})};
 function kmRow(d,r){var x=r.k,st=kmState(x),port=x.port||x.want_port;
  var head='<span class="dot '+(st[0]||'')+'"></span>'+fl(r.cc)+'<b>'+esc(x.name)+'</b>'+(x.main?'<span class="kxc-tag main">'+t('Main server')+'</span>':'')+'<span class="sp"></span>'+
   '<span class="kxr-st '+(st[0]||'')+'">'+t(st[1])+'</span>'+(x.second?'<span class="kxr-st g">+ '+t('tunnel')+'</span>':'')+'<small class="ltr">UDP '+N(port)+'</small>';
  return accRow('km',x.id,head,function(){return kmBody(d,r)})}
 function kmBody(d,r){var x=r.k,o=(d.settings.nodes||{})[x.id]||{},id=esc(x.id),port=x.port||x.want_port,tun=o.route=='tunnel',ni=id,via=x.route_via;
  var h='<div class="kxr-line"><span><b>'+t(kmState(x)[1])+'</b></span><span>·</span><span>'+N(x.users)+' '+t('users')+'</span><span>·</span><span class="ltr">'+esc(x.endpoint||'?')+':'+esc(String(port))+(x.parity!=null?' · FEC 10+'+esc(String(x.parity)):'')+'</span></div>'+
   '<div class="kxsw"><span>'+t('KANKI MIX on this server')+'</span>'+sw('',x.on,"kmNodeOn('"+id+"',this.checked)")+'</div>'+
   '<div class="kxr-sec">'+t('Port of this server')+'</div><div class="kxm-row"><div><input id="km_p1" class="ltr" inputmode="numeric" value="'+esc(String(port||''))+'"></div><button class="btn sm" id="km_ps">'+t('Save port')+'</button></div><div class="kxm-warn" id="km_pw"></div>'+
   '<div class="kxr-sec">'+t('Route')+'</div><div class="kxf"><div><select id="km_rt1"><option value=""'+(tun?'':' selected')+'>'+t("Direct (the server's own address)")+' · '+esc(x.direct_host||'?')+'</option><option value="tunnel"'+(tun?' selected':'')+'>'+t('Through the tunnel (Iran server)')+' · '+esc(x.tunnel_host||'?')+'</option></select></div>'+
   '<div><input id="km_ho1" class="ltr" placeholder="'+esc(t('Address'))+': '+esc(t('automatic'))+'" value="'+esc(o.host||'')+'"></div></div>'+
   '<div class="kxr-sec">'+t('Second config through the tunnel')+'</div>'+
   '<label class="kxsw" style="cursor:pointer"><span>'+(x.second?t('Users also get')+' <b class="ltr">'+esc(x.second.host)+':'+esc(String(x.second.port))+'</b>':t('Write the Iran address whose tunnel forwards this UDP port'))+'</span><input type="checkbox" id="km_t21" style="width:auto"'+(o.tun_off?'':' checked')+'></label>'+
   '<div class="kxf" style="margin-top:6px"><div><label class="f">'+t('Iran address')+'</label><input id="km_th1" class="ltr" placeholder="'+esc(t('automatic'))+'" value="'+esc(o.tun_host||'')+'"></div>'+
   '<div><label class="f">'+t('Port')+'</label><input id="km_tp1" class="ltr" inputmode="numeric" placeholder="'+esc(String((via&&via.port)||port||''))+'" value="'+esc(o.tun_port?String(o.tun_port):'')+'"></div>'+
   '<div class="wide"><label class="f">'+t('Name in the app')+'</label><input id="km_tn1" maxlength="40" placeholder="'+esc(x.name+' ('+t('tunnel')+')')+'" value="'+esc(o.tun_name||'')+'"></div></div>'+
   '<div class="kxr-line">'+(via?viaLine(via,x.name):(o.tun_host&&!o.tun_off?'<span class="warnbox" style="margin:0;width:100%">'+t('No Kanki tunnel carries this port to the server. Make a tunnel (or a multi-location route) that carries it, or forward it on that address some other way.')+'</span>':''))+'</div>'+
   (x.on&&x.error?'<div class="warnbox ltr" style="margin:6px 0 0">'+esc(x.error)+'</div>':'')+
   '<div class="kxsave"><button class="b2 sm" onclick="accClose(\'km\')">'+t('Cancel')+'</button><button class="btn sm" onclick="kmSaveOne(\''+id+'\')">'+t('Save')+'</button></div>'+
   '<div class="kxacts"><button class="b2 sm" onclick="nAct(\''+ni+'\',\'repair\')">↻ '+t('Restart VPN services')+'</button><a class="b2 sm" href="#tunnels">'+t('Tunnels page')+'</a></div>';
  setTimeout(function(){var el=$('#km_p1'),w=$('#km_pw'),b=$('#km_ps');if(!el)return;var f=function(){var m=srvPortClash(r.key,'kmix',el.value);w.textContent=m;b.disabled=!!m};el.oninput=f;f();
   b.onclick=function(){if(String(r.key).indexOf('node:')==0&&window.kmSetNodePort)return kmSetNodePort(x.id,+unN(el.value),function(){accClose('km')});srvSavePort(r.key,'kmix',el.value,function(){accClose('km');kmLoad(true)})}},0);
  return h}
 window.kmSaveOne=function(id){var d=KM.d,m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});var o=m[id]||{};
  o.route=$('#km_rt1').value;o.host=$('#km_ho1').value.trim();o.tun_off=!$('#km_t21').checked;o.tun_host=$('#km_th1').value.trim();
  var tp=unN($('#km_tp1').value).trim();o.tun_port=tp?+tp:0;o.tun_name=$('#km_tn1').value.trim();m[id]=o;
  api('PUT','/api/kmix',{nodes:m}).then(function(){toast(t('Saved'));accClose('km');kmLoad(true)}).catch(fail)};
 // the settings of every server, in the list; the page keeps its numbers and the general settings
 var _kd=window.kmDraw;
 window.kmDraw=function(d){_kd(d);var c=$('#km_srv');if(!c)return;var card=c.closest('.card'),g=card&&card.parentNode;
  if(g&&g.classList.contains('g2')){g.style.gridTemplateColumns='minmax(0,1.6fr) minmax(0,1fr)';g.style.alignItems='start'}};
 var _kl=window.kmLoad;
 window.kmLoad=function(quiet){return srvLoad(true).then(function(){return api('GET','/api/kmix')}).then(function(d){KM.d=d;if(S.page!='kmix')return d;
  if($('#km_srv')){$('#km_kv').innerHTML=kmKpis(d);if(!quiet||!accBusy('km'))$('#km_srv').innerHTML=kmServers(d);return d}kmDraw(d);return d}).catch(fail)};
 ACC.draw.km=function(){var c=$('#km_srv');if(c&&KM.d)c.innerHTML=kmServers(KM.d)};
 var _pk=window.p_kmix;window.p_kmix=function(){ACC.open.km='';_pk.apply(this,arguments)};
}

// ---------------------------------------------------------------- Xray: a row per server with its inbounds
if(window.xrServers){
 window.xrServers=function(d){if(!d.servers.length)return '<p class="muted">'+t('No Xray server yet: add one in Servers')+'</p>';
  var list=d.servers.map(function(x){var s=((SV.d&&SV.d.servers)||[]).filter(function(z){return agentOf(z)==x.server})[0]||{};return {x:x,key:x.server,name:x.name||x.server,cc:s.cc,loc:s.loc}});
  return boxes('xr',list,function(r){return xrRow(d,r)})};
 function xrRow(d,r){var x=r.x,st=x.status||{},on=st.active,n=d.inbounds.filter(function(i){return i.server==x.server}).length;
  var head='<span class="dot '+(on?'g':'r')+'"></span>'+fl(r.cc)+'<b>'+esc(r.name)+'</b>'+(x.server=='local'?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+'<span class="sp"></span>'+
   '<span class="kxr-st '+(on?'g':'r')+'">'+(x.status_at?(on?t('Running'):t('Not running')):t('Waiting for the server…'))+'</span><small>'+N(n)+' '+t('inbounds')+'</small>';
  return accRow('xr',x.server,head,function(){return xrBody(d,r)})}
 function xrBody(d,r){var x=r.x,st=x.status||{},sid=esc(x.server),errs=[st.deploy_error,st.error].filter(Boolean),ibs=d.inbounds.filter(function(i){return i.server==x.server});
  return '<div class="kxr-line"><span class="ltr">'+esc(x.effective||'?')+'</span>'+(st.core?'<span>·</span><span>Xray '+esc(st.core)+'</span>':'')+'<span>'+(window.xrCertChip?xrCertChip(x):'')+'</span></div>'+
   (errs.length?'<div class="warnbox ltr" style="margin:6px 0 0">'+errs.map(esc).join('<br>')+'</div>':'')+
   (window.xrCertErr&&xrCertErr(x)?'<div class="warnbox ltr" style="margin:6px 0 0">'+esc(xrCertErr(x))+'</div>':'')+
   '<div class="kxr-sec">'+t('Inbounds')+'</div>'+(ibs.length?ibs.map(function(ib){return '<div style="cursor:pointer" onclick="xrInbound(\''+esc(ib.id)+'\')">'+xrMiniRow(ib)+'</div>'}).join(''):'<p class="muted" style="margin:4px">'+t('No inbound on this server yet')+'</p>')+
   '<div class="kxacts"><button class="btn sm" onclick="xrInbound()">+ '+t('Inbound')+'</button><button class="b2 sm" onclick="xrSrvEdit(\''+sid+'\')">'+ic('edit',13)+' '+t('Edit server')+'</button>'+
   '<button class="b2 sm" onclick="xrPreview(\''+sid+'\')">{ } '+t('Config')+'</button><button class="b2 sm" onclick="srvRepair(\'xray\',\''+sid+'\')">↻ '+t('Repair')+'</button><button class="b2 sm" onclick="srvHealth(\'xray\',\''+sid+'\')">♡ '+t('Health')+'</button>'+
   '<button class="b2 sm bd" onclick="xrSrvDel(\''+sid+'\')">'+ic('trash',13)+' '+t('Remove Xray from this server')+'</button></div>'}
 ACC.draw.xr=function(){var c=$('#xr_srv');if(c&&XR.d)c.innerHTML=xrServers(XR.d)};
 var _px=window.p_xray;window.p_xray=function(){ACC.open.xr='';_px.apply(this,arguments);srvLoad(true);
  var r=$('#pg .ph .row');if(r&&!$('#xr_all1')){var a=document.createElement('button');a.className='b2';a.id='xr_all1';a.textContent=t('Off for all users');a.onclick=function(){srvProtoAll('xray',0)};
   var b=document.createElement('button');b.className='b2';b.textContent=t('On for all users');b.onclick=function(){srvProtoAll('xray',1)};r.insertBefore(b,r.firstChild);r.insertBefore(a,r.firstChild)}};
}
})();
