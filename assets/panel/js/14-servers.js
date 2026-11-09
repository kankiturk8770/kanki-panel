// ==================================================================== Servers
// Servers: two boxes (abroad, Iran) of compact rows; a row's arrow opens all of that server's settings
// (one at a time). The panel runs on one server; every other server is added with ONE command that
// installs everything (VPN, tunnels, Xray, Kanki DNS), and what it runs is switched on here.
(function(){
'use strict';

var SV={d:null,wait:null};
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
document.addEventListener('input',function(e){var b=e.target&&e.target.closest&&e.target.closest('.kxr-b');if(b)b.dataset.dirty='1'});
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
function fwDraw(){var el=$('#svp_fw');if(!el||!FWD)return;var ids=Object.keys(FWD).sort(function(a,b){return (a=='local'?-1:b=='local'?1:0)||String(FWD[a].name).localeCompare(String(FWD[b].name))});
 var on=ids.filter(function(k){return FWD[k].want}).length;
 var rows=ids.map(function(k){var x=FWD[k],st=fwState(x);
  return kuItem({dot:st[0],name:esc(x.name||k)+(k=='local'?' · '+t('Panel server'):''),tags:kuTag(esc(st[1]),st[2]),
   act:'<label class="sw"><input type="checkbox" '+(x.want?'checked ':'')+(x.knows?'':'disabled ')+'aria-label="'+esc(t('Firewall'))+'" onchange="fwSet(\''+esc(k)+'\',this.checked,this)"><span></span></label>'})}).join('');
 el.innerHTML=kuGroup('🛡 '+t('Firewall'),on,'<button class="b2 sm" onclick="fwAll('+(on<ids.length)+')">'+t(on<ids.length?'On for every server':'Off for every server')+'</button>',
  '<p class="muted ku-note">'+t('On: every port is closed except SSH and what Kanki uses on that server (cores, Kanki DNS, Xray, tunnels, the panel). A new tunnel opens its own port and a deleted one closes it, by themselves. The panel checks the server still works; if not, the server turns the firewall off again within 3 minutes.')+'</p>'+rows)}
window.fwSet=function(id,on,box){var msg=on?t('Turn the firewall on for this server? Only SSH and Kanki\'s ports stay open; anything else (a website you run there by hand) is closed.'):t('Turn the firewall off for this server?');
 if(!confirm(msg)){if(box)box.checked=!on;return}
 api('POST','/api/tunnels/servers/'+q(id)+'/firewall-guard',{on:on}).then(function(){toast(t('Sent: the server does it on its next report (a few seconds)'));fwLoad()}).catch(function(e){if(box)box.checked=!on;fail(e)})};
window.fwAll=function(on){if(!confirm(on?t('Turn the firewall on for EVERY server? On each one only SSH and Kanki\'s ports stay open.'):t('Turn the firewall off for every server?')))return;
 api('POST','/api/firewall/guard',{on:on}).then(function(r){toast(t('Sent')+' · '+N(r.servers)+' '+t('servers'));fwLoad()}).catch(fail)};
window.srvLoad=load;

// ---------------------------------------------------------------- page
window.pNodes=function(){ACC.open.srv='';
 $('#pg').innerHTML='<div class="ku">'+kuHead('nodes',t('Servers'),t('The panel runs on one server. Every other server is a node: add it with one command, then switch on here what it runs.'),'<button class="b2" onclick="updateAll()">⇪ '+t('Update all')+'</button>')+
  '<div id="svp_clash"></div><div id="svp_relay"></div><div id="svp_g">'+t('Loading…')+'</div><div id="svp_fw"></div></div>';
 load();autoRefresh(function(){load(true)});
 if(S.openAdd){S.openAdd=false;setTimeout(srvAdd,150)}};
ACC.draw.srv=function(){draw(true)};

function draw(force){var g=$('#svp_g');if(!g||!SV.d)return;
 var cl=SV.d.clashes||[];
 $('#svp_clash').innerHTML=cl.length?'<div class="kxp-clash"><div><b>⚠ '+t('Port clash')+'</b><br>'+cl.map(function(c){return 'UDP <b class="ltr">'+N(c.port)+'</b> '+t('is used by')+' '+c.users.map(function(u){return esc(u.name)+' ('+protoName(u.proto)+')'}).join('، ')}).join('<br>')+
  '<p class="muted" style="margin:6px 0 0">'+t('One tunnel entry cannot carry the same port to two servers. Fix moves the later server to a free port; tunnels that carry the old port follow.')+'</p></div><button class="btn" onclick="srvFixPorts()">'+t('Fix ports')+'</button></div>':'';
 var rl=SV.d.iran_relays||0;$('#svp_relay').innerHTML=rl?'<div class="warnbox ku-relay"><span>'+t('Iran servers that still run VPN services nobody uses')+': <b>'+N(rl)+'</b></span><button class="b2 sm" onclick="srvDropIranVpn()">'+t('Remove the VPN from them')+'</button></div>':'';
 if(!force&&accBusy('srv'))return;
 var list=(SV.d.servers||[]).slice(),by=function(x,y){return (y.local?1:0)-(x.local?1:0)||String(x.name).localeCompare(String(y.name))};
 var ab=list.filter(function(x){return !isIr(x)}).sort(by),ir=list.filter(isIr).sort(by);
 g.innerHTML=srvBox('abroad','Abroad servers','🌍',ab)+srvBox('iran','Iran servers',fl('IR'),ir)}
window.srvDraw=draw;
function srvBox(kind,title,icon,rows){
 return kuGroup(icon+' '+t(title),rows.length,'<button class="btn sm" onclick="srvAdd(\''+kind+'\')">'+ic('plus',14)+' '+t(kind=='iran'?'Add an Iran server':'Add an abroad server')+'</button>',
  rows.length?'<div class="kxl">'+rows.map(row).join('')+'</div>':'<p class="muted ku-empty">'+t('No server yet')+'</p>')}

function protoName(p){return ({wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2',kmix:'KANKI MIX'})[p]||p}
function online(s){var a=s.agent,n=s.node;return !!(s.local||(a&&a.online)||(n&&n.online))}
function srvIp(s){var a=s.agent||{},n=s.node||{};return a.addr||a.ip||(n.effective_endpoint&&n.effective_endpoint!=n.endpoint?'':n.endpoint)||''}

function row(s){var n=s.node,a=s.agent,on=online(s),h=n?nHealthOf(n):null,col=!on?'r':h&&h.c=='r'?'y':h?h.c:'g';
 var tn=s.tunnel||{},tags=(s.local?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+(n&&!n.enabled&&!s.local?'<span class="kxc-tag">'+t('relay')+'</span>':'')+
  // tunnel: its configs point at the Iran entry; + tunnel: a second config of every protocol through its tunnel domain
  (tn.main_via=='tunnel'?'<span class="kxc-tag tun">'+t('tunnel')+'</span>':tn.on&&tn.uses?'<span class="kxc-tag tun">+ '+t('tunnel')+'</span>':'');
 // a card per server (3.34): line 1 status, flag, name, tags and state; line 2 its cores and address; line 3 CPU, RAM, disk and users
 var st=(n&&n.info&&n.info.stats)||null,cores=coresOf(s),ip=srvIp(s);
 var stl=!on?['r',t('Not connected')]:col=='y'?['y',t('Needs a look')]:['g',t('Online')];
 var meter=function(l,v){v=Math.max(0,Math.min(100,Math.round(v||0)));return '<span class="svm '+(v>=90?'r':v>=75?'y':'g')+'"><small>'+l+'</small><i><u style="width:'+v+'%"></u></i><b class="ltr">'+N(v)+'%</b></span>'};
 var head='<span class="dot '+col+'"></span>'+fl(s.cc)+'<b>'+esc(s.name)+'</b>'+tags+'<span class="sp"></span><span class="kxr-st '+stl[0]+'">'+stl[1]+'</span>'+
  ((cores.length||ip)?'<span class="sv-l2">'+cores.map(function(c){return '<span class="svc" style="--pc:'+(PCOL[c[0]]||'var(--a)')+'"><i class="'+c[2]+'"></i>'+c[1]+'</span>'}).join('')+
   (ip?'<small class="kxr-ip ltr">'+esc(ip)+'</small>':'')+'</span>':'')+
  (on&&st?'<span class="sv-l3">'+meter('CPU',st.cpu)+meter('RAM',pc(st.mem_used,st.mem_total))+meter(t('Disk'),pc(st.disk_used,st.disk_total))+
   (n&&n.users!=null?'<span class="svu">'+ic('users',14)+'<b>'+N(n.users)+'</b></span>':'')+'</span>':'');
 return accRow('srv',s.key,head,function(){return srvBody(s)})}

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
 if(n&&(pt.mtun||i.mt_port))out.push(['mtun','microtun',n.enabled?'g':'',pt.mtun||i.mt_port]);
 if(j.xray_on)out.push(['xray','Xray','g',j.xray?N(j.xray)+' '+t('inbounds'):'']);
 if(j.dns)out.push(['dns','Kanki DNS','g','']);
 return out}
function srvCores(s){var out=coresOf(s);if(!out.length)return '';
 return '<div class="kxr-sec">'+t('Cores on this server')+'</div><div class="ku-cores">'+out.map(function(c){return '<a href="#'+c[0]+'/servers"><span class="dot '+c[2]+'"></span>'+c[1]+(c[3]?'<small class="ltr">'+esc(String(c[3]))+'</small>':'')+'</a>'}).join('')+'</div>'+
  '<p class="muted" style="font-size:12px;margin:4px 2px 0">'+t('Each core is set on its own page: tap one to open it.')+'</p>'}
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
 var h='<div class="kxr-line">'+st.join('<span>·</span>')+'</div>'+miss+srvCores(s)+
  '<div class="kxr-sec">'+t('Server settings')+'</div><div class="kxf">'+
  '<div><label class="f">'+t('Name')+'</label><input id="sx_nm" value="'+esc(s.name)+'" maxlength="40"></div>'+
  '<div><label class="f">'+t('Location')+'</label><div class="seg kxseg" id="sx_loc"><button type="button" data-l="abroad" class="'+(isIr(s)?'':'on')+'">'+t('Abroad')+'</button><button type="button" data-l="iran" class="'+(isIr(s)?'on':'')+'">'+t('Iran')+'</button></div></div>'+
  (a?'<div class="wide"><label class="f">'+t('Address other servers use to reach it (optional)')+'</label><input id="sx_ad" class="ltr" value="'+esc(a.addr||'')+'" placeholder="'+esc(a.ip||'')+'"></div>':'')+
  (s.domain&&!s.local?'<div class="wide"><label class="chk" style="margin:0"><input type="checkbox" id="sx_ssl"'+(s.ssl!==false?' checked':'')+'>'+t('Get SSL by itself (Let\'s Encrypt)')+'</label><small class="muted">'+t('Used by its install command (Show command).')+'</small></div>':'')+
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
   ''}
 // its tunnel: a second copy of every config through the Iran address
 if(!isIr(s)&&(n||(s.jobs&&s.jobs.xray))&&s.tunnel)h+=tunBox(s);
 h+='<div class="kxsave"><button class="b2 sm" onclick="accClose(\'srv\')">'+t('Cancel')+'</button><button class="btn sm" onclick="srvSave(\''+k+'\')">'+t('Save')+'</button></div>';
 // health and what can be done
 var stt=n&&n.info&&n.info.stats;
 if(stt)h+='<div class="kxm3">'+nMeter('CPU',+stt.cpu||0,N(Math.round(+stt.cpu||0))+'%')+nMeter('RAM',pc(stt.mem_used,stt.mem_total),N(Math.round(pc(stt.mem_used,stt.mem_total)))+'%')+nMeter('Disk',pc(stt.disk_used,stt.disk_total),N(Math.round(pc(stt.disk_used,stt.disk_total)))+'%')+'</div>';
 var hh=n?nHealthOf(n):null;
 if(hh&&hh.r&&hh.r.length&&n.enabled)h+='<ul class="nwhy">'+hh.r.map(function(x){return '<li class="l'+x[0]+'">'+t(x[1])+'</li>'}).join('')+'</ul>';
 var acts=[];
 if(n){acts.push('<button class="b2 sm" onclick="nHealth(\''+ni+'\')">♡ '+t('Health')+'</button>');
  acts.push('<button class="b2 sm" onclick="nAct(\''+ni+'\',\'sync\')">⇄ '+t('Sync')+'</button>');
  acts.push('<button class="b2 sm" onclick="nAct(\''+ni+'\',\'repair\')">↻ '+t('Restart VPN services')+'</button>');
  if(!s.local)acts.push('<button class="b2 sm" onclick="nAct(\''+ni+'\',\'update\')">⇪ '+t('Update agent')+'</button>');
  acts.push('<button class="b2 sm okb" onclick="nAssign(\''+ni+'\',1)">'+ic('plus',13)+' '+t('Add to all users')+'</button>');
  if(!s.local)acts.push('<button class="b2 sm" onclick="nAssign(\''+ni+'\',0)">'+t('Remove from all users')+'</button>')}
 if(a&&!s.local)acts.push('<button class="b2 sm" onclick="tunSrvEdit(\''+esc(a.id)+'\')">'+ic('tunnel',13)+' '+t('Tunnel agent settings')+'</button>');
 if(!s.local)acts.push('<button class="b2 sm" onclick="srvCmd(\''+k+'\')">'+ic('link',13)+' '+t('Show command')+'</button>');
 if(a&&!s.local)acts.push('<button class="b2 sm" onclick="srvReplace(\''+esc(a.id)+'\')">'+ic('move',13)+' '+t('Replace the machine')+'</button>');
 h+='<div class="kxacts">'+acts.join('')+'</div>';
 if(!s.local)h+='<div class="ku-danger">'+(n&&a&&isIr(s)?'<button class="b2 sm bd" onclick="srvDropVpn(\''+k+'\')">'+t('Remove the VPN from this server')+'</button> ':'')+'<button class="b2 sm bd" onclick="srvDel(\''+k+'\')">'+ic('trash',13)+' '+t('Delete server')+'</button></div>';
 setTimeout(function(){$$('#sx_loc button').forEach(function(b){b.onclick=function(){$$('#sx_loc button').forEach(function(z){z.classList.toggle('on',z==b)});var bb=b.closest('.kxr-b');if(bb)bb.dataset.dirty='1'}})},0);
 return h}

// The tunnel of a server: on/off, the Iran address (chips: the first server of each tunnel that ends here)
// and the name; below, each port with the one it gets on that address
function tunBox(s){var tn=s.tunnel||{},n=s.node,ents=entriesOf(s),irs=irHosts(s),host=tn.on?(tn.host||tn.uses||''):'';
 var ep=n&&n.endpoint_mode!='panel'?(n.endpoint||''):'',viaIr=ep&&ents.some(function(e){return e.host==ep});
 var rows=(tn.ports||[]).map(function(p){return '<div class="kxtun-p"><b>'+esc(p.proto)+'</b><span class="kxtun-m ltr">'+esc(p.host||tn.uses)+':'+p.via+' → '+(p.tcp?'TCP':'UDP')+' '+p.port+'</span></div>'}).join('');
 return '<div class="kxr-sec">'+t('Tunnel domain')+'</div>'+
  '<p class="muted" style="font-size:12px;margin:0 2px 6px">'+t('If this server has a tunnel, or will have one, write your Iran server\'s domain here. Every protocol then also gets a second config through it, made by itself.')+' '+t('WireGuard comes only this way.')+'</p>'+
  '<div class="kxf"><div class="wide"><input id="sx_th" class="ltr" value="'+esc(host)+'" placeholder="ir.example.com">'+
   (irs.length?'<div class="kxchips">'+irs.map(function(e){return '<button type="button" class="'+(host==e.host?'on':'')+'" onclick="$(\'#sx_th\').value=\''+esc(e.host)+'\';$(\'#sx_th\').dispatchEvent(new Event(\'input\',{bubbles:true}))">'+(e.mine?'✓ ':'')+esc(e.name)+' · <span class="ltr">'+esc(e.host)+'</span></button>'}).join('')+'</div>':'')+'</div>'+
  '<div class="wide"><label class="f">'+t('Name of these configs in the app (optional)')+'</label><input id="sx_tn" value="'+esc(tn.name||'')+'" maxlength="40" placeholder="'+esc(s.name+' (تانل)')+'"></div></div>'+
  (viaIr?'<p class="kxtun-w">'+t('Users connect to the Iran address already, so the main configs go through the tunnel too. For direct configs set it to this server\'s own address.')+'</p>':'')+
  (rows?'<div class="kxtun"><div class="muted" style="font-size:12px;margin-bottom:4px">'+t('Ports through the tunnel')+'</div>'+rows+'</div>':'')}

// Save of the open server: its name, place and address (the server), who gets it and where users connect (its VPN)
// the VPN part off an Iran server (or all of them): tunnels, Xray and Kanki DNS stay
window.srvDropVpn=function(key){if(!confirm(t('Remove WireGuard, AmneziaWG, Hysteria2 and KANKI MIX from this server? Its tunnels, Xray and Kanki DNS stay. Install VPN brings them back.')))return;
 api('POST','/api/servers/'+q(key)+'/drop-vpn').then(function(r){if(window.kdFollowRemoval)kdFollowRemoval(r.removal);accClose('srv');load(true)}).catch(fail)};
window.srvDropIranVpn=function(){if(!confirm(t('Remove WireGuard, AmneziaWG, Hysteria2 and KANKI MIX from every Iran server that serves no VPN user? Their tunnels, Xray and Kanki DNS stay.')))return;
 api('POST','/api/servers/drop-iran-vpn').then(function(r){(r.removals||[]).forEach(function(id){if(window.kdFollowRemoval)kdFollowRemoval(id)});toast(t('Done')+' · '+N(r.count||0));load(true)}).catch(fail)};
window.srvSave=function(key){var s=find(key);if(!s)return;var n=s.node,a=s.agent,jobs=[];
 var loc=(($$('#sx_loc button.on')[0]||{}).dataset||{}).l||(isIr(s)?'iran':'abroad');
 var b={name:$('#sx_nm').value.trim(),loc:loc};if($('#sx_ad'))b.addr=$('#sx_ad').value.trim();if($('#sx_ssl'))b.ssl=$('#sx_ssl').checked;
 if($('#sx_th')){var th=$('#sx_th').value.trim();b.tunnel={on:!!th,host:th,name:$('#sx_tn').value.trim()}}
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
  '<div id="sa_tunw"><label class="f">'+t('Tunnel domain (optional)')+'</label><input id="sa_tun" class="ltr" placeholder="ir.example.com" autocomplete="off" autocapitalize="off">'+
  '<p class="muted" style="font-size:12px;margin:4px 2px 0">'+t('If this server has a tunnel, or will have one, write your Iran server\'s domain here. Every protocol then also gets a second config through it, made by itself.')+'</p></div>'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="sa_ssl">'+t('Get SSL by itself (Let\'s Encrypt)')+'</label><p class="muted" style="font-size:12px;margin:2px 2px 0">'+t('The domain must point straight at this server (no Cloudflare proxy) and port 80 must be open. Off, or when it fails: a self-signed certificate, the install goes on.')+'</p>'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="sa_vpn">'+t('Serve VPN users on this server')+'</label>'+
  '<button class="btn" style="width:100%;margin-top:12px" id="sa_go">'+t('Create command')+'</button></div><div id="sa_out"></div>','wide');
 var setLoc=function(l){loc=l;$$('#sa_loc button').forEach(function(b){b.classList.toggle('on',b.dataset.l==l)});$('#sa_vpn').checked=l!='iran';$('#sa_ssl').checked=l!='iran';$('#sa_tunw').style.display=l=='iran'?'none':''};
 $$('#sa_loc button').forEach(function(b){b.onclick=function(){setLoc(b.dataset.l)}});setLoc(loc);
 $('#sa_go').onclick=function(){var me=this;me.disabled=true;
  api('POST','/api/servers',{name:$('#sa_nm').value,loc:loc,domain:$('#sa_dm').value,vpn:$('#sa_vpn').checked,ssl:$('#sa_ssl').checked,tunnel_host:loc=='iran'?'':$('#sa_tun').value.trim()}).then(function(r){
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

// The machine of a server died or its IP was filtered: the same server on a new machine. Its settings stay;
// the command makes the new machine this server again (tunnels, Xray, DNS, its VPN part and SSL come back).
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
 api('DELETE','/api/servers/'+q(key)+(withTun?'?tunnels=1':'')).then(function(){toast(t('Removed'));ACC.open.srv='';load(true)}).catch(function(e){
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

