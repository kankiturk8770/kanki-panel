// ==================================================================== Servers
// Servers: two boxes (abroad, Iran) of compact rows; a row's arrow opens all of that server's settings
// (one at a time). The panel runs on one server; every other server is added with ONE command that
// installs everything (VPN, tunnels, Xray, Kanki DNS), and what it runs is switched on here.
(function(){
'use strict';

var SV={d:null,wait:null,tab:{},reg:(function(){try{return localStorage.getItem('kk_reg')||'all'}catch(e){return 'all'}})(),fwOpen:false};
window.SV=SV;

// ---------------------------------------------------------------- look

function fl(cc){return flagOf(cc)}
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
document.addEventListener('input',function(e){var b=e.target&&e.target.closest&&e.target.closest('.kxr-b,#srvm');if(b)b.dataset.dirty='1'});
document.addEventListener('keydown',function(e){if(e.key!='Escape'||($('#modal')&&$('#modal').classList.contains('on')))return;Object.keys(ACC.open).forEach(function(g){if(ACC.open[g])accClose(g)})});

// ---------------------------------------------------------------- data
function load(quiet){
 return Promise.all([api('GET','/api/servers'),api('GET','/api/nodes').catch(function(){return null}),api('GET','/api/tunnels').catch(function(){return null})]).then(function(r){
  SV.d=r[0];if(r[1])S.nodes=r[1];if(r[2])TN.d=r[2];
  if(S.page=='nodes')draw(!quiet);waitTick();if(S.page=='nodes')fwLoad();return SV.d}).catch(function(e){if(!quiet)fail(e)})}

// ---------------------------------------------------------------- firewall guard (3.38.0)
// One row per server: ufw on with only SSH and Kanki's ports open. The server turns it on, the panel checks
// that the server still works (its VPN part answers, its tunnels come back) and confirms; without that the
// server turns ufw off again by itself within 3 minutes.
var FWD=null;
var FW_NOTE={'rolled back: the panel did not see this server working with the firewall on':'Turned off again: the panel did not see this server working with the firewall on',
 'the panel could not reach this server\'s VPN part with the firewall on':'Turned off again: the panel could not reach this server\'s VPN part with the firewall on',
 'a tunnel of this server did not come back with the firewall on':'Turned off again: a tunnel of this server did not come back with the firewall on',
 'ufw was turned off on the server':'Turned off on the server itself (ufw disable)','ufw is not installed and could not be installed':'ufw could not be installed on this server'};
function fwState(x){var g=x.guard||{};
 if(!x.knows)return ['',t('Update the agent of this server first'),'y'];
 if(x.want&&g.on&&g.confirmed)return ['g',t('On: only SSH and Kanki\'s ports are open'),'g'];
 if(x.want&&g.on)return ['y',t('Checking that everything still works…'),'y'];
 if(x.want)return ['y',t('Turning on…'),'y'];
 if(x.note)return ['r',t(FW_NOTE[x.note]||x.note),'r'];
 if(x.active)return ['',t('ufw is on, set by hand (not by Kanki)'),''];
 return ['',t('Off: every port is reachable'),'']}
function fwLoad(){api('GET','/api/firewall/guard').then(function(d){FWD=d;fwDraw()}).catch(function(){})}
// (3.62) what each open port is for, in plain words
var FW_FOR={ssh:'SSH',wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2',kmix:'KANKI MIX',panel:'Panel (web)',node:'VPN part (panel link)',nat:'Forwarded port (NAT)',kernel:'WireGuard / AmneziaWG',
 tunnels:'Tunnels',dns:'Kanki DNS','kanki-dns':'Kanki DNS',xray:'Xray',subsrv:'Subscription link',acme:'SSL (Let\'s Encrypt)',caddy:'Web (Caddy)','kanki-panel':'Kanki panel',
 'hysteria-server':'Hysteria2','kanki-mix':'KANKI MIX','kanki-mix-server':'KANKI MIX',sshd:'SSH','kanki-tunnel':'Tunnels','kanki-node':'VPN part (panel link)'};
function fwFor(w){w=String(w||'');if(FW_FOR[w])return t(FW_FOR[w]);if(/^kanki-up/.test(w))return 'KANKI-UP';if(/^xray/.test(w))return 'Xray';if(/^kanki-tunnel/.test(w))return t('Tunnels');return w}
// the server of a firewall row (for its flag): the panel's own is "local"
function fwSrv(k){var l=(SV.d&&SV.d.servers)||[];for(var i=0;i<l.length;i++){var s=l[i];if(k=='local'?s.local:(s.agent&&s.agent.id==k))return s}return null}
function fwIds(){return Object.keys(FWD||{}).sort(function(a,b){return (a=='local'?-1:b=='local'?1:0)||String(FWD[a].name).localeCompare(String(FWD[b].name))})}
function fwDraw(){var el=$('#svp_fw');if(!el||!FWD)return;var ids=fwIds();
 var on=ids.filter(function(k){return FWD[k].want}).length;
 var tiles=ids.map(function(k){var x=FWD[k],st=fwState(x),s=fwSrv(k)||{},np=(x.ports||[]).length;
  return '<button type="button" class="svt" onclick="fwOpen(\''+esc(k)+'\')"><span class="dot svt-d '+st[0]+'"></span><span class="svt-f">'+fl(s.cc||(k=='local'?'':''))+'</span><b class="svt-n" dir="auto">'+esc(x.name||k)+'</b>'+
   '<span class="svt-s '+st[2]+'">'+(x.want&&x.guard&&x.guard.on&&x.guard.confirmed?'🛡 '+t('On'):x.want?t('Checking…'):x.knows?t('Off'):t('Update the agent'))+'</span>'+
   (np?'<small class="svt-m">'+N(np)+' '+t('open ports')+'</small>':'')+'</button>'}).join('');
 el.innerHTML=kuGroup('🛡 '+t('Firewall'),on+' / '+ids.length,'<button class="b2 sm" onclick="fwAll('+(on<ids.length)+')">'+t(on<ids.length?'On for every server':'Off for every server')+'</button>',
  '<p class="muted ku-note">'+t('On: every port is closed except SSH and what Kanki uses on that server. Tap a server to see its open ports and what each one is for.')+'</p><div class="svgrid">'+tiles+'</div>')}
// the table of one server's ports: port, protocol and what it is for
function fwTable(k){var x=FWD&&FWD[k];if(!x)return '<p class="muted">'+t('Loading…')+'</p>';
 if(!x.ports)return '<p class="muted">'+t('Update the agent of this server first')+'</p>';
 var rows=x.ports.map(function(p){var r=String(p[0]).split('/');
  return '<tr><td class="ltr"><b>'+esc(r[0].replace(':','–'))+'</b></td><td><span class="fwp '+esc(r[1])+'">'+esc(String(r[1]||'').toUpperCase())+'</span></td><td>'+(p[1]||[]).map(function(w){return '<span class="fww">'+esc(fwFor(w))+'</span>'}).join('')+'</td></tr>'}).join('');
 return '<div class="fwt-w"><table class="fwt"><thead><tr><th>'+t('Port')+'</th><th>'+t('Protocol')+'</th><th>'+t('For')+'</th></tr></thead><tbody>'+rows+'</tbody></table></div>'+
  '<p class="muted ku-note">'+t(x.want?'These ports are open; every other one is closed.':'The firewall is off: every port is reachable. With it on, only these stay open.')+'</p>'}
function fwHead(k){var x=FWD[k],st=fwState(x);
 return kuSwitch(t('Firewall'),x.want,"fwSet('"+esc(k)+"',this.checked,this,1)",'<span class="c-'+(st[2]||'')+'">'+esc(st[1])+'</span>')}
window.fwOpen=function(k){var go=function(){var x=FWD&&FWD[k];if(!x)return;var s=fwSrv(k)||{};
  modal(srvHead(s,x.name||k,'🛡 '+t('Firewall'))+(x.knows?fwHead(k):'<div class="warnbox">'+t('Update the agent of this server first')+'</div>')+fwTable(k),'wide')};
 if(FWD)go();else api('GET','/api/firewall/guard').then(function(d){FWD=d;go()}).catch(fail)};
window.fwSet=function(id,on,box,again){var msg=on?t('Turn the firewall on for this server? Only SSH and Kanki\'s ports stay open; anything else (a website you run there by hand) is closed.'):t('Turn the firewall off for this server?');
 kAsk(msg,t('Firewall')).then(function(ok){var back=function(){if(again)api('GET','/api/firewall/guard').then(function(d){FWD=d;fwDraw();fwOpen(id)}).catch(function(){})};
 if(!ok){if(box)box.checked=!on;back();return}
 api('POST','/api/tunnels/servers/'+q(id)+'/firewall-guard',{on:on}).then(function(){toast(t('Sent: the server does it on its next report (a few seconds)'));if(again)back();else fwLoad()}).catch(function(e){if(box)box.checked=!on;fail(e)})})};
window.fwAll=function(on){kAsk(on?t('Turn the firewall on for EVERY server? On each one only SSH and Kanki\'s ports stay open.'):t('Turn the firewall off for every server?'),t('Firewall')).then(function(ok){if(!ok)return;
 api('POST','/api/firewall/guard',{on:on}).then(function(r){toast(t('Sent')+' · '+N(r.servers)+' '+t('servers'));fwLoad()}).catch(fail)})};
window.srvLoad=load;

// ---------------------------------------------------------------- page
window.pNodes=function(){ACC.open.srv='';
 $('#pg').innerHTML='<div class="ku">'+kuHead('nodes',t('Servers'),t('The panel runs on one server. Every other server is a node: add it with one command, then switch on here what it runs.'),
  '<button class="btn" onclick="updateAll()">⇪ '+t('Update all')+'</button><button class="b2" onclick="srvAdd()">'+ic('plus',15)+' '+t('Server')+'</button>')+
  '<div id="svp_sum">'+kuStats([[t('Online'),'—'],[t('Needs a look'),'—'],[t('Not connected'),'—'],[t('Update ready'),'—']])+'</div>'+
  '<div id="svp_clash"></div><div id="svp_g">'+t('Loading…')+'</div><div id="svp_fw"></div></div>';
 load();autoRefresh(function(){load(true)});
 if(S.openAdd){S.openAdd=false;setTimeout(srvAdd,150)}};
ACC.draw.srv=function(){draw(true)};

function draw(force){var g=$('#svp_g');if(!g||!SV.d)return;
 var cl=SV.d.clashes||[];
 $('#svp_clash').innerHTML=cl.length?'<div class="kxp-clash"><div><b>⚠ '+t('Port clash')+'</b><br>'+cl.map(function(c){return 'UDP <b class="ltr">'+N(c.port)+'</b> '+t('is used by')+' '+c.users.map(function(u){return esc(u.name)+' ('+protoName(u.proto)+')'}).join('، ')}).join('<br>')+
  '<p class="muted" style="margin:6px 0 0">'+t('One tunnel entry cannot carry the same port to two servers. Fix moves the later server to a free port; tunnels that carry the old port follow.')+'</p></div><button class="btn" onclick="srvFixPorts()">'+t('Fix ports')+'</button></div>':'';
 var list=(SV.d.servers||[]).slice(),by=function(x,y){return (y.local?1:0)-(x.local?1:0)||String(x.name).localeCompare(String(y.name))};
 var ab=list.filter(function(x){return !isIr(x)}).sort(by),ir=list.filter(isIr).sort(by);
 g.innerHTML=srvBox('abroad','Abroad servers','🌍',ab)+srvBox('iran','Iran servers',fl('IR'),ir);
 // the numbers on top: every server once
 var cnt={all:list.length,ok:0,warn:0,off:0,upd:0};list.forEach(function(x){var n=x.node,on=online(x),h=n?nHealthOf(n):null;
  if(!on)cnt.off++;else if(h&&h.c!='g')cnt.warn++;else cnt.ok++;if(x.agent&&x.agent.can_update)cnt.upd++});
 var sm=$('#svp_sum');if(sm)sm.innerHTML=kuStats([[t('Online'),N(cnt.all-cnt.off)+' / '+N(cnt.all),cnt.off?'':'g'],[t('Needs a look'),N(cnt.warn),cnt.warn?'y':''],[t('Not connected'),N(cnt.off),cnt.off?'r':''],[t('Update ready'),N(cnt.upd),cnt.upd?'y':'']]);
 // the server open in its window follows the new data (unless something is being typed there)
 var m=$('#srvm');if(m&&$('#modal').classList.contains('on')&&!m.dataset.dirty&&!(document.activeElement&&m.contains(document.activeElement)&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName))){var cur=find(m.dataset.key);if(cur)srvOpen(cur.key,1)}}
window.srvDraw=draw;
window.srvTab=function(key,p){SV.tab[key]=p;var b=$('#srvm');if(!b||b.dataset.key!=key)return;
 $$('.sxt button',b).forEach(function(x){var on=x.dataset.t==p;x.classList.toggle('on',on);x.setAttribute('aria-selected',on)});
 $$('.sxp',b).forEach(function(x){x.hidden=x.dataset.p!=p})};
// the agent of a server without a VPN part: what it said last, and the panel's asks (sync, restart)
window.agHealth=function(id){toast(t('Checking…'));api('GET','/api/tunnels/servers/'+q(id)+'/health').then(function(r){var s=find(id)||{};
 var row=function(l,v){return '<div class="li"><span>'+l+'</span><span class="ltr">'+v+'</span></div>'};
 var h='<div class="list">'+row(t('Agent'),r.online?'✅ '+t('Connected'):'❌ '+t('Not connected'))+(r.seen?row(t('Last report'),N(r.age)+' s')+row(t('Version'),'v'+esc(r.version||'?')):'')+
  (r.stats&&r.stats.cpu!=null?row('CPU',N(Math.round(r.stats.cpu))+'%')+row('RAM',N(Math.round(pc(r.stats.mem_used,r.stats.mem_total)))+'%'):'')+'</div>';
 if((r.tunnels||[]).length)h+='<label class="f">'+t('Tunnels')+'</label><div class="list">'+r.tunnels.map(function(x){return '<div class="li"><span><b>'+esc(x.name)+'</b>'+(x.error?'<small>'+esc(x.error)+'</small>':'')+'</span><span>'+(x.links>0?'✅ '+N(x.links)+'/'+N(x.want):'❌')+'</span></div>'}).join('')+'</div>';
 h+=(r.issues||[]).length?'<div class="warnbox">'+r.issues.map(esc).join('<br>')+'</div>':'<p>'+t('Everything looks fine')+'</p>';
 modal(mhead(t('Health'),s.name||id)+h)}).catch(fail)};
window.agAct=function(id,a){api('POST','/api/tunnels/servers/'+q(id)+'/agent/'+a).then(function(){toast(t(a=='restart'?'Sent: its tunnels start again in a few seconds':'Sent: the server applies everything again in a few seconds'));setTimeout(function(){load(true)},6000)}).catch(fail)};
function srvBox(kind,title,icon,rows){
 return kuGroup(icon+' '+t(title),rows.length,'<button class="b2 sm" onclick="srvAdd(\''+kind+'\')">'+ic('plus',14)+' '+t('Add')+'</button>',
  rows.length?'<div class="svgrid">'+rows.map(tile).join('')+'</div>':'<p class="muted ku-empty">'+t('No server yet')+'</p>')}

function protoName(p){return ({wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2',kmix:'KANKI MIX'})[p]||p}
function online(s){var a=s.agent,n=s.node;return !!(s.local||(a&&a.online)||(n&&n.online))}
function srvIp(s){var a=s.agent||{},n=s.node||{};return a.addr||a.ip||(n.effective_endpoint&&n.effective_endpoint!=n.endpoint?'':n.endpoint)||''}

// (3.62) a server is a tile: its flag, its name, a dot for its state and its cores in short; a tap opens everything
var CORE_SHORT={wg:'WG',awg:'AWG',hy2:'HY2',kmix:'MIX',xray:'XR',dns:'DNS'};
function stOf(s){var n=s.node,on=online(s),h=n?nHealthOf(n):null,col=!on?'r':h&&h.c=='r'?'y':h?h.c:'g';
 return {col:col,txt:!on?t('Not connected'):col=='y'?t('Needs a look'):t('Online')}}
function verOf(s){var n=s.node,a=s.agent;return (a&&a.version)||(n&&n.info&&n.info.version)||''}
function tile(s){var st=stOf(s),cores=coresOf(s),a=s.agent,n=s.node,stt=(n&&n.info&&n.info.stats)||(a&&a.stats)||null;
 var tag=s.local?'<span class="svt-t main">'+t('Panel')+'</span>':a&&a.can_update?'<span class="svt-t upd">'+t('Update')+'</span>':n&&!n.enabled?'<span class="svt-t">'+t('relay')+'</span>':'';
 // the busiest of CPU, RAM and disk, with its name
 var hot=0,hn='';if(stt&&online(s))[['CPU',+stt.cpu||0],['RAM',pc(stt.mem_used,stt.mem_total)],[t('Disk'),pc(stt.disk_used,stt.disk_total)]].forEach(function(z){if(z[1]>=hot){hot=z[1];hn=z[0]}});
 return '<button type="button" class="svt'+(online(s)?'':' off')+'" onclick="srvOpen(\''+esc(s.key)+'\')" title="'+esc(s.name)+' · '+esc(st.txt)+'">'+
  '<span class="dot svt-d '+st.col+'"></span>'+tag+'<span class="svt-f">'+(s.cc?fl(s.cc):isIr(s)?fl('IR'):'🌐')+'</span><b class="svt-n" dir="auto">'+esc(s.name)+'</b>'+
  '<span class="svt-c">'+(cores.length?cores.map(function(c){return '<i class="'+c[2]+'" style="--pc:'+(PCOL[c[0]]||'var(--a)')+'">'+CORE_SHORT[c[0]]+'</i>'}).join(''):'<i>'+t(isIr(s)?'Tunnels':'Agent')+'</i>')+'</span>'+
  '<small class="svt-m">'+(online(s)?(n&&n.enabled&&n.users!=null?ic('users',12)+N(n.users)+' · ':'')+(hn?'<span class="'+(hot>=90?'c-r':hot>=75?'c-y':'')+'">'+hn+' '+N(Math.round(hot))+'%</span>':esc(st.txt)):esc(st.txt))+'</small></button>'}
// the head of a server's window: flag, name, its state and a second line
function srvHead(s,name,sub){var st=s&&s.key?stOf(s):null;
 return '<div class="mh svh"><div><b style="font-size:17px">'+(s&&s.cc?fl(s.cc)+' ':'')+esc(name||(s&&s.name)||'')+'</b><small>'+(st?'<span class="dot '+st.col+'"></span>'+esc(st.txt):'')+(sub?(st?' · ':'')+sub:'')+'</small></div><button class="ib" onclick="closeModal()" aria-label="'+esc(t('Close'))+'">✕</button></div>'}
window.srvOpen=function(key,quiet){var s=find(key);if(!s)return;var m=$('#srvm'),top=quiet&&m?$('#mbox').scrollTop:0;
 var ip=srvIp(s),ver=verOf(s);
 modal(srvHead(s,s.name,(ver?'v'+esc(ver):'')+(ip?' · <span class="ltr">'+esc(ip)+'</span>':''))+'<div id="srvm" data-key="'+esc(s.key)+'">'+srvBody(s)+'</div>','wide');
 if(quiet)$('#mbox').scrollTop=top;
 if(!FWD)fwLoad()};
window.srvClose=function(){closeModal()};
// the first entries (and their addresses) of the tunnels that bring this server's ports: where its
// users can connect instead of its own address (Iran → Turkey → here: Iran)
function entriesOf(s){var sid=s.agent?s.agent.id:(s.local?'local':''),tl=((TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.enabled!==false&&x.kind!='awg'}),out=[];
 if(!sid)return out;
 var back=function(id,seen){var prev=tl.filter(function(x){return x.exit==id&&seen.indexOf(x.entry)<0});if(!prev.length)return [id];
  var r=[];prev.forEach(function(x){back(x.entry,seen.concat([x.entry])).forEach(function(e){if(r.indexOf(e)<0)r.push(e)})});return r};
 back(sid,[sid]).forEach(function(e){if(e==sid)return;var sv=((TN.d&&TN.d.servers)||[]).filter(function(z){return z.id==e})[0];if(sv&&(sv.host||sv.addr))out.push({id:e,name:sv.name,host:sv.addr||sv.host})});
 return out}
// every Iran server a second config can go through, for one-tap chips: the first servers of the
// tunnels that end at server s first (marked), then the other Iran servers by their domain or address
function irHosts(s){var out=[],seen={},add=function(name,host,mine){host=String(host||'').trim();if(!host||seen[host])return;seen[host]=1;out.push({name:name,host:host,mine:!!mine})};
 if(s)entriesOf(s).forEach(function(e){add(e.name,e.host,1)});
 ((SV.d&&SV.d.servers)||[]).forEach(function(x){if(!isIr(x)||(s&&x.key==s.key))return;var a=x.agent||{};add(x.name,x.domain||a.addr||a.ip||(x.node&&x.node.endpoint))});
 return out}
window.srvIrHosts=irHosts;

function coresOf(s){var n=s.node,i=(n&&n.info)||{},j=s.jobs||{},pt=s.ports||{},out=[];
 var svc=function(k){return ((i.services||[]).filter(function(x){return x.key==k})[0])};
 var off=((SV.d&&SV.d.core_off)||{})[n?n.id:'']||[];
 var vpn=function(p,name,key,port){if(!n)return;var sv=svc(key);if(!port&&!sv)return;out.push([p,name,!n.enabled||off.indexOf(p)>=0?'':sv&&!sv.active?'r':'g',port])};
 vpn('wg','WireGuard','wireguard',pt.wg||i.wg_port);vpn('awg','AmneziaWG','amneziawg',i.awg_port);vpn('hy2','Hysteria2','hysteria2',pt.hy2||i.hy2_port);
 if(n&&(pt.kmix||i.kmix_port))out.push(['kmix','KANKI MIX',n.enabled?'g':'',pt.kmix||i.kmix_port]);
 if(j.xray_on)out.push(['xray','Xray','g',j.xray?N(j.xray)+' '+t('inbounds'):'']);
 if(j.dns)out.push(['dns','Kanki DNS','g','']);
 return out}
// (3.64) one switch per core: tick exactly what this server runs. A core that cannot run here (no VPN part, no
// agent, or not allowed by the server's role) is shown off with the reason; a core switched off keeps its settings.
var SW_CORES=[['wg','WireGuard'],['awg','AmneziaWG'],['kmix','KANKI MIX'],['dns','Kanki DNS'],['xray','Xray'],['hy2','Hysteria2']];
function srvCores(s){var sw=(s.switches&&s.switches.cores)||{},live={};coresOf(s).forEach(function(c){live[c[0]]=c});
 return '<div class="kxr-sec">'+t('Cores on this server')+(s.switches&&s.switches.role&&s.switches.role!='hybrid'?'<small>'+t('Role')+': '+esc(t(s.switches.role))+'</small>':'')+'</div>'+
  '<div class="core-sw" role="group" aria-label="'+esc(t('Cores on this server'))+'">'+SW_CORES.map(function(c){var x=sw[c[0]]||{can:false,on:false,why:''},l=live[c[0]];
   return '<label class="csw'+(x.on?' on':'')+(x.can?'':' dis')+'" style="--pc:'+(PCOL[c[0]]||'var(--a)')+'"'+(x.why?' title="'+esc(t(x.why))+'"':'')+'>'+
    '<span class="nm"><b>'+c[1]+'</b><small>'+(x.can?(l&&l[3]?'<span class="ltr">'+esc(String(l[3]))+'</span>':t(x.on?'On':'Off')):esc(t(x.why||'Not available')))+'</small></span>'+
    '<span class="sw"><input type="checkbox" data-csw="'+c[0]+'" data-key="'+esc(s.key)+'"'+(x.on?' checked':'')+(x.can||x.on?'':' disabled')+' aria-label="'+esc(c[1])+'"><span></span></span></label>'}).join('')+'</div>'+
  '<p class="muted" style="font-size:12px;margin:4px 2px 0">'+t('Switched off, a core stops and closes its port; its settings stay for when it is switched on again.')+(s.switches&&s.switches.vpn_part===false&&s.agent?' '+t('WireGuard, AmneziaWG, Hysteria2 and KANKI MIX are not installed here yet: switching one on installs them (a few minutes), inside Iran as abroad.'):'')+'</p>'}
// a core switch was flipped: the panel switches it, the server follows on its next sync
document.addEventListener('change',function(e){var x=e.target;if(!x||!x.dataset||!x.dataset.csw)return;var b={};b[x.dataset.csw]=x.checked;x.disabled=true;
 api('POST','/api/servers/'+encodeURIComponent(x.dataset.key)+'/cores',b).then(function(){toast(t('Saved'));load(true)}).catch(function(err){x.checked=!x.checked;x.disabled=false;fail(err)})});
function srvBody(s){var k=esc(s.key),a=s.agent,n=s.node,ni=n?esc(n.id):'';
 var st=[];
 if(!s.local)st.push(t('agent')+': <b>'+(a?(a.online?t('Connected'):t('Not connected')):'—')+'</b>');
 if(n)st.push('VPN: <b>'+(n.enabled?(s.local||n.online?t('On'):t('Not connected')):t('Off'))+'</b>');
 if(n&&n.enabled)st.push(N(n.users||0)+' '+t('users'));
 var mst=a&&a.stats;if(!n&&mst&&mst.uptime)st.push(t('Up')+' '+N(Math.floor(mst.uptime/86400))+' '+t('days'));
 if(!n&&mst&&mst.tcp!=null)st.push('TCP '+N(mst.tcp)+' · UDP '+N(mst.udp||0));
 if(!s.local&&a&&a.last_seen&&!a.online)st.push(t('Last contact')+' '+ago(a.last_seen));
 var miss='';
 if(!n&&a){var su=s.setup||null;
  if(s.pending&&!a.last_seen)miss='<div class="kxc-miss"><span>'+t('Waiting for this server: run its command')+'</span><button class="b2 sm" onclick="srvCmd(\''+k+'\')">'+t('Show command')+'</button></div>';
  // inside Iran or abroad, the same (3.65): no VPN part yet = a relay; switching a VPN core on (Cores) installs it
  else if(su&&su.state=='running'||(s.switches&&s.switches.installing&&!(su&&su.state=='failed')))miss='<div class="kxc-miss"><span class="spin"></span><span>'+t('Installing the VPN part…')+'</span>'+(su.tail?'<pre>'+esc(su.tail)+'</pre>':'')+'</div>';
  else miss='<div class="kxc-miss"><span>'+(su&&su.state=='failed'?'<b class="bad2">'+t('VPN install failed')+'</b>':t('VPN is not installed on this server'))+'</span><button class="b2 sm" onclick="srvComplete(\''+k+'\',1)">'+t(su&&su.state=='failed'?'Try again':'Install VPN')+'</button>'+(su&&su.state=='failed'&&su.tail?'<pre>'+esc(su.tail)+'</pre>':'')+'</div>'}
 if(n&&!a&&!s.local)miss='<div class="kxc-miss"><span>'+t('Tunnels, Xray and DNS are not installed on this server')+'</span><button class="b2 sm" onclick="srvComplete(\''+k+'\',1)">'+t('Install')+'</button></div>';
 // the server in three parts (one shown at a time): settings, cores and network, control and agent
 var tab=SV.tab[s.key]||'base',part=function(k){return '<div class="sxp" data-p="'+k+'"'+(k==tab?'':' hidden')+'>'};
 var h='<div class="kxr-line">'+st.join('<span>·</span>')+'</div>'+miss+
  '<div class="seg sxt" role="tablist">'+[['base','Settings'],['net','Cores'],['ctl','Control']].concat(s.local||a?[['fw','Firewall']]:[]).map(function(z){return '<button type="button" role="tab" data-t="'+z[0]+'" aria-selected="'+(z[0]==tab)+'" class="'+(z[0]==tab?'on':'')+'" onclick="srvTab(\''+k+'\',\''+z[0]+'\')">'+t(z[1])+'</button>'}).join('')+'</div>'+
  part('base')+'<div class="kxr-sec">'+t('Server settings')+'</div><div class="kxf">'+
  '<div><label class="f">'+t('Name')+'</label><input id="sx_nm" value="'+esc(s.name)+'" maxlength="40"></div>'+
  '<div><label class="f">'+t('Location')+'</label><div class="seg kxseg" id="sx_loc"><button type="button" data-l="abroad" class="'+(isIr(s)?'':'on')+'">'+t('Abroad')+'</button><button type="button" data-l="iran" class="'+(isIr(s)?'on':'')+'">'+t('Iran')+'</button></div></div>'+
  (a?'<div class="wide"><label class="f">'+t('Address other servers use to reach it (optional)')+'</label><input id="sx_ad" class="ltr" value="'+esc(a.addr||'')+'" placeholder="'+esc(a.ip||'')+'"></div>':'')+
  (s.domain&&!s.local?'<div class="wide"><label class="chk" style="margin:0"><input type="checkbox" id="sx_ssl"'+(s.ssl!==false?' checked':'')+'>'+t('Get SSL by itself (Let\'s Encrypt)')+'</label><small class="muted">'+t('Used by its install command (Show command).')+'</small></div>':'')+
  (n?'<div class="wide"><label class="f">'+t('Note')+'</label><input id="sx_no" value="'+esc(n.note||'')+'"></div>':'')+'</div>';
 var netH='';
 // its VPN: who is sent there and where they connect
 if(n){var own=!n.endpoint||n.endpoint_mode=='panel',ents=entriesOf(s);
  netH+='<div class="kxr-sec">VPN</div>'+
   '<div class="kxsw"><span>'+t('VPN for users')+'<small>'+t(n.enabled?'VPN serves users':'VPN is installed but serves nobody (a relay)')+'</small></span>'+sw('',n.enabled,"srvVpn('"+k+"',this.checked)")+'</div>'+
   '<label class="kxsw" style="cursor:pointer"><span>'+t('Users without their own server list get this server')+'</span><input type="checkbox" id="sx_acc" style="width:auto"'+(n.accept_all?' checked':'')+'></label>'+
   '<div class="kxf" style="margin-top:4px"><div class="wide"><label class="f">'+t('Users connect to')+'</label><input id="sx_ep" class="ltr" value="'+esc(s.local&&own?'':n.endpoint||'')+'" placeholder="'+esc(n.effective_endpoint||'')+'">'+
   (ents.length?'<div class="kxchips">'+ents.map(function(e){return '<button type="button" class="'+(n.endpoint==e.host?'on':'')+'" onclick="$(\'#sx_ep\').value=\''+jsa(e.host)+'\';$(\'#sx_ep\').dispatchEvent(new Event(\'input\',{bubbles:true}))">'+t('Through')+' '+esc(e.name)+' · <span class="ltr">'+esc(e.host)+'</span></button>'}).join('')+
    '<button type="button" onclick="$(\'#sx_ep\').value=\''+jsa(srvIp(s))+'\';$(\'#sx_ep\').dispatchEvent(new Event(\'input\',{bubbles:true}))">'+t("This server's own address")+'</button></div>':'')+'</div></div>'+
   (s.local?'':'<details class="box"><summary>'+t('Advanced')+'</summary><div class="kxf"><div class="wide"><label class="f">'+t('API address')+'</label><input id="sx_api" class="ltr" value="'+esc(n.address||'')+'"></div>'+
    '<div><label class="f">'+t('Node token')+'</label><input id="sx_tok" class="ltr" placeholder="'+t('empty = keep it')+'"></div>'+
    '<div style="align-self:end"><label class="chk" style="margin:0"><input type="checkbox" id="sx_ins"'+(n.insecure?' checked':'')+'>'+t('Self-signed certificate (no domain on the server)')+'</label></div></div></details>')+
   ''}
 // its tunnel: a second copy of every config through the Iran address
 if(!isIr(s)&&(n||(s.jobs&&s.jobs.xray))&&s.tunnel)netH+=tunBox(s);
 // the save button is under both parts that hold fields
 var save='<div class="kxsave"><button class="b2 sm" onclick="srvClose()">'+t('Cancel')+'</button><button class="btn sm" onclick="srvSave(\''+k+'\')">'+t('Save')+'</button></div>';
 h+=save+'</div>'+part('net')+srvCores(s);
 // health and what can be done
 var stt=(n&&n.info&&n.info.stats)||(a&&a.stats);
 if(stt)netH+='<div class="kxm3">'+nMeter('CPU',+stt.cpu||0,N(Math.round(+stt.cpu||0))+'%')+nMeter('RAM',pc(stt.mem_used,stt.mem_total),N(Math.round(pc(stt.mem_used,stt.mem_total)))+'%')+nMeter('Disk',pc(stt.disk_used,stt.disk_total),N(Math.round(pc(stt.disk_used,stt.disk_total)))+'%')+'</div>';
 var hh=n?nHealthOf(n):null;
 if(hh&&hh.r&&hh.r.length&&n.enabled)netH+='<ul class="nwhy">'+hh.r.map(function(x){return '<li class="l'+x[0]+'">'+t(x[1])+'</li>'}).join('')+'</ul>';
 h+=netH+(n||(!isIr(s)&&s.tunnel)?save:'')+'</div>'+part('ctl');
 // (3.62) the controls in three short groups, each a grid of buttons: its VPN part, its agent, the server itself
 var grp=function(title,sub,btns){return btns.length?'<div class="svc-g"><div class="kxr-sec">'+title+(sub?'<small>'+sub+'</small>':'')+'</div><div class="svbtns">'+btns.join('')+'</div></div>':''};
 var bt=function(cls,js,icon,label){return '<button class="b2 sm'+(cls?' '+cls:'')+'" onclick="'+js+'">'+icon+'<span>'+t(label)+'</span></button>'};
 var vpnB=[],agB=[],srvB=[];
 if(n){vpnB.push(bt('',"nHealth('"+ni+"')",'♡','Health'),bt('',"nAct('"+ni+"','sync')",'⇄','Sync'),bt('',"nAct('"+ni+"','repair')",'↻','Restart VPN services'));
  if(!s.local)vpnB.push(bt('',"nAct('"+ni+"','update')",'⇪','Update VPN part'));
  vpnB.push(bt('okb',"nAssign('"+ni+"',1)",ic('plus',13),'Add to all users'));
  if(!s.local)vpnB.push(bt('',"nAssign('"+ni+"',0)",'−','Remove from all users'))}
 // every server with an agent (Iran and abroad alike): the same controls on its agent
 if(a&&!s.local){var ai=esc(a.id);
  agB.push(bt('',"agHealth('"+ai+"')",'♡','Health'),bt('',"agAct('"+ai+"','sync')",'⇄','Sync'),bt('',"agAct('"+ai+"','restart')",'↻','Restart services'),
   bt(a.can_update?'okb':'',"srvUpdate('"+k+"')",'⇪',a.can_update?'Update this server':'Update agent'),bt('',"tunSrvEdit('"+ai+"')",ic('tunnel',13),'Tunnel agent settings'))}
 if(!s.local)srvB.push(bt('',"srvCmd('"+k+"')",ic('link',13),'Show command'));
 if(a&&!s.local)srvB.push(bt('',"srvReplace('"+esc(a.id)+"')",ic('move',13),'Replace the machine'));
 // the panel server itself moves with everything it holds (Backup › Move)
 if(s.local)srvB.push(bt('',"srvMovePanel()",ic('move',13),'Move the panel to a new server or IP'));
 h+=grp(t('VPN part'),n?(n.online||s.local?t('Connected'):t('Not connected')):'',vpnB)+grp(t('Agent'),a&&!s.local?(a.online?t('Connected'):t('Not connected'))+(a.version?' · v'+esc(a.version):''):'',agB)+grp(t('Server'),'',srvB);
 if(!s.local)h+='<div class="ku-danger">'+(n&&a?'<button class="b2 sm bd" onclick="srvDropVpn(\''+k+'\')">'+t('Remove the VPN from this server')+'</button> ':'')+'<button class="b2 sm bd" onclick="srvDel(\''+k+'\')">'+ic('trash',13)+' '+t('Delete server')+'</button></div>';
 h+='</div>';
 // its firewall: the switch and every open port with what it is for
 if(s.local||a){var fk=s.local?'local':a.id;h+=part('fw')+(FWD&&FWD[fk]?(FWD[fk].knows?fwHead(fk):'')+fwTable(fk):'<p class="muted">'+t('Loading…')+'</p>')+'</div>'}
 setTimeout(function(){$$('#sx_loc button').forEach(function(b){b.onclick=function(){$$('#sx_loc button').forEach(function(z){z.classList.toggle('on',z==b)});var bb=b.closest('.kxr-b,#srvm');if(bb)bb.dataset.dirty='1'}})},0);
 return h}

// The tunnel of a server: on/off, the Iran address (chips: the first server of each tunnel that ends here)
// and the name; below, each port with the one it gets on that address
// (3.61) the address of the second configs is never typed: each port gets the Iran server of the tunnel that carries it
function tunBox(s){var tn=s.tunnel||{},n=s.node,ents=entriesOf(s);
 var ep=n&&n.endpoint_mode!='panel'?(n.endpoint||''):'',viaIr=ep&&ents.some(function(e){return e.host==ep});
 var rows=(tn.ports||[]).map(function(p){return '<div class="kxtun-p"><b>'+esc(p.proto)+'</b><span class="kxtun-m ltr">'+(p.carried===false?'— · '+(p.tcp?'TCP':'UDP')+' '+p.port:esc(p.host)+':'+p.via+' → '+(p.tcp?'TCP':'UDP')+' '+p.port)+'</span></div>'}).join('');
 return '<div class="kxr-sec">'+t('Tunnel configs')+'</div>'+
  '<p class="muted" style="font-size:12px;margin:0 2px 6px">'+t('Every core gets a second config through the Iran server of the tunnel that carries its port, by itself: change the tunnel and the users get the new address at their next update.')+' '+t('WireGuard comes only this way.')+'</p>'+
  '<div class="kxf"><div class="wide"><label class="f">'+t('Name of these configs in the app (optional)')+'</label><input id="sx_tn" value="'+esc(tn.name||'')+'" maxlength="40" placeholder="'+esc(s.name+' (تانل)')+'"></div></div>'+
  (viaIr?'<p class="kxtun-w">'+t('Users connect to the Iran address already, so the main configs go through the tunnel too. For direct configs set it to this server\'s own address.')+'</p>':'')+
  (rows?'<div class="kxtun"><div class="muted" style="font-size:12px;margin-bottom:4px">'+t('Ports through the tunnel')+'</div>'+rows+'</div>':'')}

// Save of the open server: its name, place and address (the server), who gets it and where users connect (its VPN)
// the VPN part off an Iran server (or all of them): tunnels, Xray and Kanki DNS stay
window.srvDropVpn=function(key){kAsk(t('Remove WireGuard, AmneziaWG, Hysteria2 and KANKI MIX from this server? Its tunnels, Xray and Kanki DNS stay. Install VPN brings them back.'),'',t('Remove'),1).then(function(ok){if(!ok)return;
 api('POST','/api/servers/'+q(key)+'/drop-vpn').then(function(r){if(window.kdFollowRemoval)kdFollowRemoval(r.removal);srvClose();load(true)}).catch(fail)})};
window.srvSave=function(key){var s=find(key);if(!s)return;var n=s.node,a=s.agent,jobs=[];
 var loc=(($$('#sx_loc button.on')[0]||{}).dataset||{}).l||(isIr(s)?'iran':'abroad');
 var b={name:$('#sx_nm').value.trim(),loc:loc};if($('#sx_ad'))b.addr=$('#sx_ad').value.trim();if($('#sx_ssl'))b.ssl=$('#sx_ssl').checked;
 if($('#sx_tn'))b.tunnel={name:$('#sx_tn').value.trim()};
 jobs.push(api('PUT','/api/servers/'+q(key),b));
 if(n){var ep=$('#sx_ep').value.trim(),nb={note:$('#sx_no')?$('#sx_no').value:n.note,accept_all:$('#sx_acc').checked,endpoint_mode:ep?'custom':'panel',endpoint:ep};
  if(!s.local&&!ep){nb.endpoint_mode='custom';nb.endpoint=srvIp(s)||n.endpoint}
  if($('#sx_api')){var ad=$('#sx_api').value.trim();if(ad)nb.address=ad;if($('#sx_tok').value.trim())nb.token=$('#sx_tok').value.trim();nb.insecure=$('#sx_ins').checked}
  jobs.push(api('PUT','/api/nodes/'+q(n.id),nb))}
 Promise.all(jobs).then(function(){toast(t('Saved'));srvClose();load(true)}).catch(fail)};

function find(key){var l=(SV.d&&SV.d.servers)||[];for(var i=0;i<l.length;i++)if(l[i].key==key)return l[i]}
window.srvFind=find;
// one server takes the panel's program (an Iran server too; it never needs GitHub)
window.srvUpdate=function(k){api('POST','/api/servers/'+encodeURIComponent(k)+'/update').then(function(r){toast(t('The server takes the new version in a minute')+' (v'+r.version+')');setTimeout(function(){load(true)},60000)}).catch(fail)};

// ---------------------------------------------------------------- add a server (one command)
var SA_CORES=[['wg','WireGuard',1],['awg','AmneziaWG',1],['kmix','KANKI MIX',1],['dns','Kanki DNS',0],['xray','Xray',0],['hy2','Hysteria2',1]];
window.srvAdd=function(loc){loc=loc=='iran'?'iran':'abroad';
 modal(mhead(t('Add server'))+
  '<p class="muted" style="margin:0 0 8px">'+t('Everything is installed on the server (VPN, tunnels, Xray, Kanki DNS) with one command. Off = installed, but no user is sent there (an Iran relay).')+'</p>'+
  '<div id="sa_in"><label class="f">'+t('Server name')+'</label><input id="sa_nm" placeholder="Germany-1" maxlength="40">'+
  '<label class="f">'+t('Location')+'</label><div class="seg kxseg" id="sa_loc"><button type="button" data-l="abroad">'+t('Abroad')+'</button><button type="button" data-l="iran">'+t('Inside Iran')+'</button></div>'+
  '<label class="f">'+t('Domain (optional, for a real SSL certificate)')+'</label><input id="sa_dm" class="ltr" placeholder="de1.example.com" autocomplete="off" autocapitalize="off">'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="sa_ssl">'+t('Get SSL by itself (Let\'s Encrypt)')+'</label><p class="muted" style="font-size:12px;margin:2px 2px 0">'+t('The domain must point straight at this server (no Cloudflare proxy) and port 80 must be open. Off, or when it fails: a self-signed certificate, the install goes on.')+'</p>'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="sa_vpn">'+t('Serve VPN users on this server')+'</label>'+
  // the six cores: every one is installed, the ticked ones are switched on when the server joins
  '<div id="sa_cw"><label class="f">'+t('Cores switched on')+'</label><div class="core-sw sa-cores">'+SA_CORES.map(function(c){return '<label class="csw" style="--pc:'+(PCOL[c[0]]||'var(--a)')+'" data-vpn="'+c[2]+'"><span class="nm"><b>'+c[1]+'</b><small>'+t(c[2]?'VPN part':'Server agent')+'</small></span><span class="sw"><input type="checkbox" data-core="'+c[0]+'" aria-label="'+esc(c[1])+'"><span></span></span></label>'}).join('')+'</div>'+
  '<p class="muted" style="font-size:12px;margin:4px 2px 0">'+t('All are installed; the ticked ones start as soon as the server joins, the rest stay off until you switch them on (Servers › the server › Cores).')+'</p></div>'+
  '<button class="btn" style="width:100%;margin-top:12px" id="sa_go">'+t('Create command')+'</button></div><div id="sa_out"></div>','wide');
 // without the VPN part only the agent's cores (Xray, Kanki DNS) can be ticked
 var showCores=function(){var v=$('#sa_vpn').checked;$$('#sa_cw .csw').forEach(function(l){var off=l.dataset.vpn=='1'&&!v,x=$('input',l);l.classList.toggle('dis',off);x.disabled=off;if(off)x.checked=false;l.classList.toggle('on',x.checked)})};
 $$('#sa_cw input').forEach(function(x){x.addEventListener('change',showCores)});
 // inside Iran and abroad the same cores and defaults (3.65); only SSL starts off in Iran (port 80 is often closed there)
 var setLoc=function(l){loc=l;$$('#sa_loc button').forEach(function(b){b.classList.toggle('on',b.dataset.l==l)});$('#sa_ssl').checked=l!='iran'};
 $('#sa_vpn').checked=true;$$('#sa_cw input').forEach(function(x){x.checked=x.dataset.core=='wg'||x.dataset.core=='awg'});showCores();
 $('#sa_vpn').onchange=showCores;
 $$('#sa_loc button').forEach(function(b){b.onclick=function(){setLoc(b.dataset.l)}});setLoc(loc);
 $('#sa_go').onclick=function(){var me=this;me.disabled=true;
  api('POST','/api/servers',{name:$('#sa_nm').value,loc:loc,domain:$('#sa_dm').value,vpn:$('#sa_vpn').checked,ssl:$('#sa_ssl').checked,
   cores:$$('#sa_cw input').filter(function(x){return x.checked}).map(function(x){return x.dataset.core})}).then(function(r){
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
 var a=s.agent||{},n=s.node,seen=!!(a.online||a.last_seen),vpn=!!(s.planned&&s.planned.length)||!!n;
 // each step: done, now, or still to come (only the first step not done spins)
 var steps=[[seen,'1. Connect to the server and install the agent'],[vpn?!!n:seen,vpn?'2. Install and start the VPN cores':'2. No VPN core chosen: agent only'],[vpn?!!(n&&(n.online||s.local)):online(s),'3. Firewall and finish']];
 var cur=steps.findIndex(function(x){return !x[0]}),done=cur<0;
 el.innerHTML=steps.map(function(x,i){return '<div class="'+(x[0]?'ok':i==cur?'now':'next')+'">'+(x[0]?'<span class="okc">'+ic('check',16)+'</span>':i==cur?'<span class="spin"></span>':'<span class="kxs-n"></span>')+'<span>'+t(x[1])+'</span></div>'}).join('')+
  (done?'<p class="kxs-done">'+t('The server is ready')+'</p>':'');
 clearTimeout(SV.wt);if(!done&&$('#modal').classList.contains('on'))SV.wt=setTimeout(function(){api('GET','/api/servers').then(function(d){SV.d=d;waitTick();if(S.page=='nodes')draw()}).catch(function(){})},4000)}

// The machine of a server died or its IP was filtered: the same server on a new machine. Its settings stay;
// the command makes the new machine this server again (tunnels, Xray, DNS, its VPN part and SSL come back).
window.srvMovePanel=function(){location.hash='#backup';var n=0,iv=setInterval(function(){var el=$('#v37move');if(el||++n>40){clearInterval(iv);if(el)el.scrollIntoView({behavior:'smooth',block:'start'})}},150)};
window.srvReplace=function(id){var s=find(id)||{},a=s.agent||{};
 modal(mhead(t('Replace the machine'),s.name||id)+'<div id="sr_in"><p class="muted" style="margin:0 0 8px">'+t('For a server that is gone (switched off, or its IP filtered). Nothing is deleted: run the new command on the new machine and this server comes back there with its tunnels, Xray, Kanki DNS, its VPN cores and their ports, its users and SSL.')+'</p>'+
  '<label class="f">'+t('New address (IP or domain) other servers dial')+'</label><input id="sr_addr" class="ltr" placeholder="'+esc(t('empty = the address it connects from'))+'" value="'+esc(a.addr||'')+'">'+
  '<ul class="muted" style="margin:8px 0 0;padding-inline-start:18px;font-size:13px"><li>'+t('A domain on this server: point it to the new IP first, so SSL can be taken again.')+'</li><li>'+t('WireGuard and AmneziaWG get new server keys: the Kanki app takes the new files by itself; files imported by hand must be taken again.')+'</li><li>'+t('Make sure the old machine is off: two machines with one identity take turns.')+'</li></ul>'+
  '<button class="btn" style="width:100%;margin-top:12px" id="sr_go">'+t('Make the new command')+'</button></div><div id="sa_out"></div>','wide');
 $('#sr_go').onclick=function(){var me=this;me.disabled=true;
  api('POST','/api/servers/'+q(id)+'/replace',{addr:$('#sr_addr').value.trim()}).then(function(r){$('#sr_in').classList.add('hide');showCmd(r.command,null,id);load(true)}).catch(function(e){me.disabled=false;fail(e)})}};

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
 api('DELETE','/api/servers/'+q(key)+(withTun?'?tunnels=1':'')).then(function(){toast(t('Removed'));srvClose();load(true)}).catch(function(e){
  var tl=e&&e.data&&e.data.tunnels;
  if(tl&&tl.length){var names=tl.map(function(x){var o=find(x.other)||{};return '• '+x.name+(o.name?' ↔ '+o.name:'')}).join('\n');
   if(confirm(t('These tunnels use this server:')+'\n'+names+'\n\n'+t('Delete them too? The other server drops them and closes their ports.')))srvDel(key,1);return}
  fail(e)})};

window.srvFixPorts=function(){if(!confirm(t("Users' WireGuard / AmneziaWG files of the moved server must be downloaded again (subscription links and the app update by themselves). Continue?")))return;
 toast(t('Checking…'));api('POST','/api/servers/fix-ports').then(function(r){var m=r.moved||[];
  modal(mhead(t(m.length?'Ports moved':'No clash'))+(m.length?'<div class="list">'+m.map(function(x){return '<div class="li"><span><b>'+esc(x.server)+'</b> '+protoName(x.proto)+(x.error?'<small class="bad2">'+esc(x.error)+'</small>':'')+'</span><span class="ltr">'+N(x.old)+' → '+N(x.new)+' '+(x.ok?'✅':'❌')+'</span></div>'}).join('')+'</div>':''));
  load(true);svcReload()}).catch(fail)};

// ---------------------------------------------------------------- a VPN port of one server (used by VPN services)
// another server (or another protocol here) already using the port the admin types
window.srvPortClash=function(key,proto,v){var p=+unN(String(v));if(!(p>0&&p<65536))return t('A port is 1-65535');var hit='';
 ((SV.d&&SV.d.servers)||[]).forEach(function(x){var ps=x.ports||{};Object.keys(ps).forEach(function(k){if(+ps[k]==p&&!(x.key==key&&k==proto))hit=x.name+' ('+protoName(k)+')'})});
 return hit?t('Already used by')+' '+hit+': '+t('pick another port'):''};
window.srvSavePort=function(key,proto,v,done){var b={};b[proto]=+unN(String(v));toast(t('Saving…'));
 return api('POST','/api/servers/'+q(key)+'/ports',b).then(function(r){toast(t('Saved: the service restarts on the new port'));load(true);if(done)done(r);return r}).catch(fail)};
window.srvProtoAll=function(pa,add){if(!confirm(t(add?'Turn this on for every user?':'Turn this off for every user?')))return;
 api('POST','/api/protocols/'+pa+'/'+(add?'assign-all':'unassign-all')).then(function(r){toast(t('Done')+' ('+N(r.changed||0)+')')}).catch(fail)};


// ---------------------------------------------------------------- adding a server
// Add node (dashboard) and + Server (tunnels) open the one Add server
window.nodeAdd=function(){srvAdd('abroad')};
window.tunServerAdd=function(){srvAdd('iran')};
// the servers again (after an action): this page redraws; elsewhere only the data is fetched
window.loadNodes=function(){if(S.page=='nodes'&&$('#svp_g'))return load(true);
 api('GET','/api/nodes').then(function(n){S.nodes=n}).catch(fail);
 api('GET','/api/xray').then(function(d){XR.d=d}).catch(function(){});
 api('GET','/api/dns').then(function(d){DN.d=d}).catch(function(){});
 api('GET','/api/tunnels').then(function(d){TN.d=d}).catch(function(){})};


})();

