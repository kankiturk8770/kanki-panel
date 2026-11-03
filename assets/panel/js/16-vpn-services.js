// ==================================================================== VPN services tabs
// VPN services: one tab per service (KANKI MIX, Xray, WireGuard, AmneziaWG, Hysteria2). Each tab
// lists the servers that run it (abroad and Iran apart); a row's arrow opens that service's settings
// on that server (one row at a time, closed on leaving the page or after saving).
(function(){
'use strict';
var ACC=KAcc;

// ---------------------------------------------------------------- the tabs of VPN services
var P=PAGES;
[['wg','WireGuard','shield2'],['awg','AmneziaWG','shield2'],['hy2','Hysteria2','shield2']].forEach(function(x){if(!P.some(function(y){return y[0]==x[0]}))P.push(x)});

// leaving a page closes its open row

function fl(cc){return flagOf(cc)}
function isIr(s){return s.loc=='iran'||String(s.cc||'').toUpperCase()=='IR'}
function q(id){return encodeURIComponent(id)}
function boxes(g,list,row){var ab=list.filter(function(x){return !isIr(x)}),ir=list.filter(isIr);
 var box=function(kind,title,icon,rows){return rows.length?'<section class="kxbox '+kind+'"><div class="kxbox-h"><span class="kxbox-i">'+icon+'</span><b>'+t(title)+'</b><small>'+N(rows.length)+'</small></div><div class="kxl">'+rows.map(row).join('')+'</div></section>':''};
 return box('abroad','Abroad servers','🌍',ab)+box('iran','Iran servers',fl('IR'),ir)}
function srvByNode(nid){return ((SV.d&&SV.d.servers)||[]).filter(function(s){return s.node&&s.node.id==nid})[0]||null}
function agentOf(s){return s.local?'local':(s.agent?s.agent.id:'')}

// the servers a UDP port of a server comes in through (Iran → Turkey), from the tunnels the panel has
function routeVia(sid,port){var tl=((TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.enabled!==false&&x.kind!='awg'}),names=[],cur=sid,p=+port,seen=[sid];
 if(!sid||!p)return null;
 for(var k=0;k<8;k++){var hit=null;tl.forEach(function(x){if(hit||x.exit!=cur||seen.indexOf(x.entry)>=0)return;
   (Array.isArray(x.udp)?x.udp:String(x.udp||'').split(',')).join(',').split(',').forEach(function(it){it=String(it).trim();if(!it||hit)return;var a=it,b=it;if(it.indexOf(':')>0){a=it.split(':')[0];b=it.split(':')[1]}
    if(+b==p&&/^\d+$/.test(a))hit={e:x.entry,p:+a}})});
  if(!hit)break;seen.push(hit.e);names.unshift(tunSrv(hit.e).name);cur=hit.e;p=hit.p}
 return names.length?{via:names,port:p}:null}
function viaLine(r,me){return r?'<span class="kxr-st g">'+t('Through a tunnel')+'</span> <span>'+r.via.map(esc).join(' → ')+' → '+esc(me)+'</span>'+(r.port?' · <span class="ltr">UDP '+N(r.port)+'</span>':''):''}

window.svcReload=function(){var f=ACC.draw['pv_'+S.page]||ACC.draw[S.page=='kmix'?'km':''];if(f)f(true)};

// ---------------------------------------------------------------- WireGuard, AmneziaWG, Hysteria2
var PV={wg:{name:'WireGuard',svc:'wireguard',desc:'Plain WireGuard on every VPN server. Inside Iran it works only through a tunnel.'},
 awg:{name:'AmneziaWG',svc:'amneziawg',desc:'WireGuard with obfuscated packets (Jc, S1, S2, H1-H4): passes most filters directly.'},
 hy2:{name:'Hysteria2',svc:'hysteria2',desc:'QUIC-based, fast on lossy internet, with Salamander obfuscation.'}};
var PD={dir:null,ov:null};
// a core switched off on one server (Servers tab): stopped there, its port closed, no links
function pvOff(p,s){var n=s&&s.node,o=(SV.d&&SV.d.core_off)||{};return !!(n&&(o[n.id]||[]).indexOf(p)>=0)}
window.pvCore=function(p,key,on){api('POST','/api/servers/'+encodeURIComponent(key)+'/core',{core:p,on:on}).then(function(){toast(t('Saved'));return srvLoad(true)}).then(function(){drawPv(p,true)}).catch(fail)};
function pvState(p,s){var n=s.node,i=(n&&n.info)||{},sv=(i.services||[]).filter(function(x){return x.key==PV[p].svc})[0],port=(s.ports||{})[p]||i[p+'_port'];
 if(!port&&!sv)return ['n',t('not installed'),port];if(pvOff(p,s))return ['n',t('Off on this server'),port];if(!n.enabled)return ['n',t(s.local?'off':'relay'),port];
 if(sv&&!sv.active)return ['r',t('stopped'),port];return ['g',t('running'),port]}
var PVT={};
function protoPage(p){var g='pv_'+p;ACC.open[g]='';ACC.open['tn_'+p]='';
 var k=corePage(p,'pv','shield2',PV[p].name,t(PV[p].desc));if(!k)return;PVT[p]=k;
 var go=function(quiet){return Promise.all([srvLoad(true),api('GET','/api/overview').catch(function(){return null}),p=='awg'?api('GET','/api/servers/direct').catch(function(){return null}):null]).then(function(r){PD.ov=r[1]||PD.ov;if(r[2])PD.dir=r[2];if(S.page==p)drawPv(p,!quiet)})};
 ACC.draw[g]=function(){drawPv(p,true)};ACC.draw['tn_'+p]=function(){var c=$('#pv_tun');if(c)c.innerHTML=pvTunRows(p)};
 go(false);autoRefresh(function(){go(true)})}
['wg','awg','hy2'].forEach(function(p){window['tab_'+p]=function(sub){var k=ctabOf(sub);if(k!=sub){location.replace('#'+p+'/'+k);return}PVT[p]=k;coreTabsMark(p,'pv',k);drawPv(p,true)}});
function pvList(){return ((SV.d&&SV.d.servers)||[]).filter(function(s){return !!s.node&&!srvRelay(s)})}
function pvTunRows(p){return coreTunRows(p,'tn_'+p,pvList())}
function drawPv(p,force){var g='pv_'+p,el=$('#pv'),tab=PVT[p]||'status';if(!el||!SV.d)return;
 var list=pvList(),run=list.filter(function(s){return pvState(p,s)[0]=='g'}).length,
  viaT=list.filter(function(s){return routeVia(agentOf(s),pvState(p,s)[2])||((s.tunnel||{}).ports||[]).some(function(z){return z.core==p})}).length,ov=PD.ov||{},users=((ov.protocols||{})[p]);
 var stats=kuStats([[t('Running servers'),N(run)+' / '+N(list.length),run<list.length?'y':''],[t('Users with it'),users==null?'—':N(users)],[t('Through a tunnel'),N(viaT)],[t('Servers'),N(list.length)]]);
 if(tab=='status'){if(!force&&$('#pv_st')){$('#pv_st').innerHTML=stats;return}
  el.innerHTML='<div id="pv_st">'+stats+'</div>'+kuGroup(PV[p].name,null,'',kuLine(t('Every user'),'<button class="b2 sm" onclick="srvProtoAll(\''+p+'\',0)">'+t('Off for all users')+'</button><button class="b2 sm" onclick="srvProtoAll(\''+p+'\',1)">'+t('On for all users')+'</button>'))+
   '<details class="ku-help"><summary>'+t('How it works')+'</summary><p>'+t(PV[p].desc)+' '+t('This protocol has no settings of its own: the port of each server is in the Servers tab, the second config in the Tunnel tab.')+'</p></details>';return}
 if(tab=='tunnel'){if(!force&&accBusy('tn_'+p))return;
  el.innerHTML=(p=='wg'?'<div class="warnbox">'+t('WireGuard reaches users only through a tunnel: choose its Iran server below.')+'</div>':'')+
   kuGroup(t('Second config through the tunnel'),list.length,'','<p class="muted ku-note">'+t('Only for this core. Empty = the tunnel domain of the server (Servers page).')+'</p><div id="pv_tun">'+pvTunRows(p)+'</div>');return}
 if(tab=='settings'){if(!force)return;
  el.innerHTML=(p=='awg'?'<div id="pv_dir">'+t('Loading…')+'</div>':kuGroup(t('Settings'),null,'','<p class="muted ku-note">'+t('This protocol has no settings of its own: the port of each server is in the Servers tab, the second config in the Tunnel tab.')+'</p>'));
  if(p=='awg')dirDraw();return}
 if(!force&&accBusy(g))return;
 el.innerHTML=kuGroup(t('Servers'),list.length,'',list.length?boxes(g,list,function(s){return pvRow(p,s)}):'<p class="muted ku-empty">'+t('No VPN server yet')+' · <a href="#nodes">'+t('Add server')+'</a></p>')}

// A core's second config through the tunnel, set on the core's own page: its own Iran address (one tap on
// an Iran server), else the server's tunnel domain (Servers page). `fold`: closed until opened.
var CNAME={wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2',mtun:'microtun',xray:'Xray'};
window.coreTun=function(core,s,fold){if(!s)return '';var tn=s.tunnel||{},own=(tn.cores||{})[core]||'',srv=tn.on?(tn.host||tn.uses||''):'',use=own||srv,k=esc(s.key),id='ct_'+core+'_'+String(s.key).replace(/[^a-z0-9]/gi,'');
 var x=(tn.ports||[]).filter(function(z){return z.core==core})[0];
 var line=use?t('Users also get')+' <b class="ltr">'+esc(use)+(x?':'+x.via:'')+'</b>'+(own?'':' <small class="muted">('+t('the tunnel domain of the server')+')</small>'):t('No second config: choose an Iran server below.');
 var chips=srvIrHosts(s).map(function(e){return '<button type="button" class="'+(own==e.host?'on':'')+'" onclick="coreTunSet(\''+core+'\',\''+k+'\',\''+esc(e.host)+'\')">'+(e.mine?'✓ ':'')+esc(e.name)+' · <span class="ltr">'+esc(e.host)+'</span></button>'}).join('');
 var st='<div class="kxr-line"><span class="kxr-st '+(use?'g':'')+'">'+(use?'+ '+t('tunnel'):t('Off'))+'</span><span>'+line+'</span></div>';
 var body='<div class="kxm-row"><div><input id="'+id+'" class="ltr" placeholder="'+esc(srv||'ir.example.com')+'" value="'+esc(own)+'"></div><button class="btn sm" onclick="coreTunSet(\''+core+'\',\''+k+'\',$(\'#'+id+'\').value)">'+t('Save')+'</button>'+
   (own?'<button class="b2 sm" onclick="coreTunSet(\''+core+'\',\''+k+'\',\'\')">'+t('Same as the server')+'</button>':'')+'</div>'+
  (chips?'<div class="kxchips">'+chips+'</div>':'<p class="muted" style="font-size:12px;margin:4px 2px">'+t('Add your Iran servers in Servers to pick them here with one tap.')+'</p>')+
  '<p class="muted" style="font-size:12px;margin:4px 2px 0">'+t('Only for this core. Empty = the tunnel domain of the server (Servers page).')+'</p>';
 var head=t('Second config through the tunnel')+' · '+CNAME[core];
 return fold?'<details class="box" style="margin-top:6px;width:100%"><summary>'+head+(use?' · <span class="ltr">'+esc(use)+'</span>':'')+'</summary>'+st+body+'</details>':'<div class="kxr-sec">'+head+'</div>'+st+body};
window.coreTunSet=function(core,key,host){var r=document.querySelector('.kxr.open[data-acc]'),g=r&&r.dataset.acc;
 // opened from the Tunnel table (coreTunEdit): its window closes and the table is drawn again
 if($('#modal').classList.contains('on')&&window.CTG){g=window.CTG;window.CTG='';closeModal()}
 api('PUT','/api/servers/'+encodeURIComponent(key),{tunnel_core:{core:core,host:String(host||'').trim()}}).then(function(){toast(t('Saved'));
  return srvLoad(true).then(function(){if(g&&/^tn_|^xrt$/.test(g)){if(ACC.draw[g])ACC.draw[g](true);return}if(S.page=='mtun')kcLoad('mtun',true);else if(S.page=='xray'){if(ACC.draw.xr)ACC.draw.xr(true)}else svcReload()})}).catch(fail)};
window.srvByNode=function(nid){return srvByNode(nid)};
function pvRow(p,s){var st=pvState(p,s),port=st[2];
 var head='<span class="dot '+(st[0]=='n'?'':st[0])+'"></span>'+fl(s.cc)+'<b>'+esc(s.name)+'</b>'+(s.local?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+'<span class="sp"></span>'+
  '<span class="kxr-st '+st[0]+'">'+esc(st[1])+'</span>'+tunTag(p,s)+(port?'<small class="ltr">UDP '+N(port)+'</small>':'');
 return accRow('pv_'+p,s.key,head,function(){return pvBody(p,s)})}
// the row's tunnel badge: its configs point at an Iran entry, or it also has a copy through its tunnel domain
function tunTag(p,s){var tn=s.tunnel||{},has=(tn.ports||[]).some(function(z){return z.core==p});
 return tn.main_via=='tunnel'?'<span class="kxr-st g">'+t('tunnel')+'</span>':has?'<span class="kxr-st g">+ '+t('tunnel')+'</span>':''}
function pvBody(p,s){var n=s.node,i=n.info||{},st=pvState(p,s),port=st[2],k=esc(s.key),ni=esc(n.id),r=routeVia(agentOf(s),port);
 var h=kuSwitch(PV[p].name+' '+t('on this server'),!pvOff(p,s),"pvCore('"+p+"','"+k+"',this.checked)",t('Off: stopped on this server, its port closed, no links for it'))+
  '<div class="kxr-line"><span><b>'+esc(st[1])+'</b></span>'+(n.enabled?'<span>·</span><span>'+N(n.users||0)+' '+t('users')+'</span>':'')+
  '<span>·</span><span>'+t('Users connect to')+': <b class="ltr">'+esc(n.effective_endpoint||'—')+'</b> <a href="#nodes" style="font-size:12px">'+t('change in Servers')+'</a></span></div>'+
  '<div class="kxr-line">'+(r?viaLine(r,s.name):'<span>'+t('No tunnel carries this port: users connect to the server directly')+'</span>')+'</div>';
 if(port||st[0]!='n')h+='<div class="kxr-sec">'+t('UDP port')+'</div><div class="kxm-row"><div><input id="pv_p" class="ltr" inputmode="numeric" value="'+esc(String(port||''))+'"></div><button class="btn sm" id="pv_ps">'+t('Save port')+'</button></div><div class="kxm-warn" id="pv_pw"></div>'+
  (p!='hy2'?'<p class="muted" style="font-size:12px;margin:2px">'+t("Users' WireGuard / AmneziaWG files of this server must be downloaded again after a port change; subscription links and the app update by themselves.")+'</p>':'');
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
 el.innerHTML=kuGroup(t('Direct domains'),(d.servers||[]).length,'<button class="b2 sm" onclick="svcDirBase()">'+t('Change the base domain')+'</button>',
  '<p class="muted ku-note">'+t("Make each direct name an A record pointing at the server's IP (Cloudflare: DNS only, grey cloud). Until it points right, the app gets the server's own address.")+' *.<span class="ltr">'+esc(d.base||'—')+'</span></p>'+
  (d.servers||[]).map(function(r){return kuItem({dot:r.ok?'g':r.host?'y':'',flag:fl(r.cc),name:esc(r.name),tags:'<span class="ku-tag">'+dirSt(r)+'</span>'+kuTag(t(r.via=='direct'?'Direct':'Tunnel')),
   addr:'<b>'+esc(r.host||'—')+'</b> → '+esc(r.ip||'—')})}).join(''))}
window.svcDirBase=function(){var v=prompt(t('Base domain for the direct names (like example.com); empty = the panel domain without its first part'),(PD.dir&&PD.dir.base)||'');if(v===null)return;
 api('PUT','/api/servers/direct',{base:v.trim()}).then(function(d){PD.dir=d;dirDraw();drawPv('awg',true)}).catch(fail)};
window.p_wg=function(){protoPage('wg')};window.p_awg=function(){protoPage('awg')};window.p_hy2=function(){protoPage('hy2')};

// ---------------------------------------------------------------- KANKI MIX: a row per server
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
   (x.on&&x.error?'<div class="warnbox'+(x.error=='not running'?'':' ltr')+'" style="margin:6px 0 0">'+esc(t(x.error))+'</div>':'')+
   '<div class="kxsave"><button class="b2 sm" onclick="accClose(\'km\')">'+t('Cancel')+'</button><button class="btn sm" onclick="kmSaveOne(\''+id+'\')">'+t('Save')+'</button></div>'+
   '<div class="kxacts"><button class="b2 sm" onclick="nAct(\''+ni+'\',\'repair\')">↻ '+t('Restart VPN services')+'</button></div>';
  setTimeout(function(){var el=$('#km_p1'),w=$('#km_pw'),b=$('#km_ps');if(!el)return;var f=function(){var m=srvPortClash(r.key,'kmix',el.value);w.textContent=m;b.disabled=!!m};el.oninput=f;f();
   b.onclick=function(){if(String(r.key).indexOf('node:')==0)return kmSetNodePort(x.id,+unN(el.value),function(){accClose('km')});srvSavePort(r.key,'kmix',el.value,function(){accClose('km');kmLoad(true)})}},0);
  return h}
 window.kmSaveOne=function(id){var d=KM.d,m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});var o=m[id]||{};
  o.route=$('#km_rt1').value;o.host=$('#km_ho1').value.trim();m[id]=o;
  api('PUT','/api/kmix',{nodes:m}).then(function(){toast(t('Saved'));accClose('km');kmLoad(true)}).catch(fail)};
 // the settings of every server, in the list; the page keeps its numbers and the general settings
  ACC.draw.km=function(){var c=$('#km_srv');if(c&&KM.d)c.innerHTML=kmServers(KM.d)};
  // the Tunnel tab: the second config of each server through an Iran server
  window.kmTunRows=function(d){var list=(d.servers||[]).map(function(x){var s=srvByNode(x.id)||{key:'node:'+x.id,name:x.name,cc:'',loc:''};return {k:x,s:s,key:s.key||x.id,name:x.name,cc:s.cc,loc:s.loc}});
   if(!list.length)return '<p class="muted ku-empty">'+t('No VPN server yet')+'</p>';
   window.KMT=list;
   return kuTunTable(list.map(function(r){var x=r.k,sc=x.second;
    return {cc:r.cc,name:x.name,direct:srvDirect(r.s)||x.host||'',tun:sc?sc.host+':'+sc.port:'',note:'',
     st:sc?(x.route_via?['g',t('Through a tunnel')]:['y',t('No tunnel carries the port')]):['',t('Off')],edit:"kmTunEdit('"+esc(x.id)+"')"}}))};
  window.kmTunEdit=function(id){var r=(window.KMT||[]).filter(function(z){return z.k.id==id})[0];if(!r||!KM.d)return;
   modal(mhead(t('Second config through the tunnel'),r.k.name)+kmTunBody(KM.d,r))};
  function kmTunBody(d,r){var x=r.k,o=(d.settings.nodes||{})[x.id]||{},id=esc(x.id),port=x.port||x.want_port,via=x.route_via;
   // the server's tunnel domain (Servers page) gives it by itself; the fields below only change it for KANKI MIX
   return ''+
   '<label class="kxsw" style="cursor:pointer"><span>'+(x.second?t('Users also get')+' <b class="ltr">'+esc(x.second.host)+':'+esc(String(x.second.port))+'</b>':t('Write the tunnel domain of this server in Servers: the second config is made by itself.'))+'</span><input type="checkbox" id="km_t21" style="width:auto"'+(o.tun_off?'':' checked')+'></label>'+
   '<details class="box" style="margin-top:6px" open><summary>'+t('Only for KANKI MIX (optional)')+'</summary>'+
   '<div class="kxf"><div class="wide"><label class="f">'+t('Iran address')+'</label><input id="km_th1" class="ltr" placeholder="'+esc(t('the tunnel domain of the server'))+'" value="'+esc(o.tun_host||'')+'">'+
    (function(){var irs=srvIrHosts(r.s&&r.s.key?r.s:null);return irs.length?'<div class="kxchips">'+irs.map(function(e){return '<button type="button" class="'+(o.tun_host==e.host?'on':'')+'" onclick="$(\'#km_th1\').value=\''+esc(e.host)+'\';$$(\'.kxchips button\',this.parentNode.parentNode).forEach(function(b){b.classList.remove(\'on\')});this.classList.add(\'on\')">'+(e.mine?'✓ ':'')+esc(e.name)+' · <span class="ltr">'+esc(e.host)+'</span></button>'}).join('')+'</div>':''})()+'</div>'+
   '<div><label class="f">'+t('Port')+'</label><input id="km_tp1" class="ltr" inputmode="numeric" placeholder="'+esc(String((via&&via.port)||port||''))+'" value="'+esc(o.tun_port?String(o.tun_port):'')+'"></div>'+
   '<div class="wide"><label class="f">'+t('Name in the app')+'</label><input id="km_tn1" maxlength="40" placeholder="'+esc(x.name+' ('+t('tunnel')+')')+'" value="'+esc(o.tun_name||'')+'"></div></div></details>'+
   '<div class="kxr-line">'+(via?viaLine(via,x.name):(o.tun_host&&!o.tun_off?'<span class="warnbox" style="margin:0;width:100%">'+t('No Kanki tunnel carries this port to the server. Make a tunnel (or a multi-location route) that carries it, or forward it on that address some other way.')+'</span>':''))+'</div>'+
    '<div class="kxsave"><button class="b2 sm" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn sm" onclick="kmSaveTun(\''+id+'\')">'+t('Save')+'</button></div>'}
  window.kmSaveTun=function(id){var m=kmNodes(),o=m[id]||{};o.tun_off=!$('#km_t21').checked;o.tun_host=$('#km_th1').value.trim();
   var tp=unN($('#km_tp1').value).trim();o.tun_port=tp?+tp:0;o.tun_name=$('#km_tn1').value.trim();m[id]=o;
   api('PUT','/api/kmix',{nodes:m}).then(function(){toast(t('Saved'));closeModal();kmLoad(true)}).catch(fail)};
  ACC.draw.kmt=function(){var c=$('#km_tun');if(c&&KM.d)c.innerHTML=kmTunRows(KM.d)};
 

// ---------------------------------------------------------------- Xray: a row per server with its inbounds
 window.xrServers=function(d){if(!d.servers.length)return '<p class="muted">'+t('No Xray server yet: add one in Servers')+'</p>';
  var list=d.servers.map(function(x){var s=((SV.d&&SV.d.servers)||[]).filter(function(z){return agentOf(z)==x.server})[0]||{};return {x:x,key:x.server,name:x.name||x.server,cc:s.cc,loc:s.loc}});
  return boxes('xr',list,function(r){return xrRow(d,r)})};
 function xrRow(d,r){var x=r.x,st=x.status||{},on=st.active,n=d.inbounds.filter(function(i){return i.server==x.server}).length;
  var head='<span class="dot '+(on?'g':'r')+'"></span>'+fl(r.cc)+'<b>'+esc(r.name)+'</b>'+(x.server=='local'?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+'<span class="sp"></span>'+
   '<span class="kxr-st '+(on?'g':'r')+'">'+(x.status_at?(on?t('Running'):t('Not running')):t('Waiting for the server…'))+'</span><small>'+N(n)+' '+t('inbounds')+'</small>';
  return accRow('xr',x.server,head,function(){return xrBody(d,r)})}
 function xrBody(d,r){var x=r.x,st=x.status||{},sid=esc(x.server),errs=[st.deploy_error,st.error].filter(Boolean),ibs=d.inbounds.filter(function(i){return i.server==x.server});
  return '<div class="kxr-line"><span class="ltr">'+esc(x.effective||'?')+'</span>'+(st.core?'<span>·</span><span>Xray '+esc(st.core)+'</span>':'')+'<span>'+xrCertChip(x)+'</span></div>'+
   (errs.length?'<div class="warnbox ltr" style="margin:6px 0 0">'+errs.map(esc).join('<br>')+'</div>':'')+
   (xrCertErr(x)?'<div class="warnbox ltr" style="margin:6px 0 0">'+esc(xrCertErr(x))+'</div>':'')+
   '<div class="kxr-sec">'+t('Inbounds')+'</div>'+(ibs.length?ibs.map(function(ib){return '<div style="cursor:pointer" onclick="xrInbound(\''+esc(ib.id)+'\')">'+xrMiniRow(ib)+'</div>'}).join(''):'<p class="muted" style="margin:4px">'+t('No inbound on this server yet')+'</p>')+
   '<div class="kxacts"><button class="b2 sm" onclick="xrSrvEdit(\''+sid+'\')">'+ic('edit',13)+' '+t('Domain and SSL')+'</button>'+
   '<button class="b2 sm" onclick="xrPreview(\''+sid+'\')">{ } '+t('Config')+'</button><button class="b2 sm" onclick="srvRepair(\'xray\',\''+sid+'\')">↻ '+t('Repair')+'</button><button class="b2 sm" onclick="srvHealth(\'xray\',\''+sid+'\')">♡ '+t('Health')+'</button>'+
   '</div><div class="ku-danger"><button class="b2 sm bd" onclick="xrSrvDel(\''+sid+'\')">'+ic('trash',13)+' '+t('Remove Xray from this server')+'</button></div>'}
 ACC.draw.xr=function(){var c=$('#xr_srv');if(c&&XR.d)c.innerHTML=xrServers(XR.d)};
 })();

