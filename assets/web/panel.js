// Kanki Panel: the whole panel script.

// ==================================================================== users form, VPN overview
// the VPN services page (Kanki VPN | Xray), node types and the services part of the user form
// ---- Xray and DNS servers: repair, a quick health view, and the protocol for every user
function srvData(kind){return kind=='xray'?XR.d:DN.d}
function srvReload(kind){if(kind=='xray')xrLoad(true);if(kind=='dns')dnsLoad(true)}
function srvRepair(kind,id){toast(t('Checking…'));
 api('POST','/api/'+kind+'/servers/'+encodeURIComponent(id)+'/repair').then(function(r){
  toast(t(r.waiting?'Repair sent: the server has not reported for a while, it is repaired as soon as it is back':'Repair sent: the server restarts it within a few seconds'));
  setTimeout(function(){srvReload(kind)},9000)}).catch(fail)}
function srvHealth(kind,id){var d=srvData(kind),x=d&&(d.servers||[]).filter(function(s){return s.server==id})[0];if(!x)return;
 var st=x.status||{},age=x.status_at?Math.max(0,Math.floor(Date.now()/1000-x.status_at)):-1,fresh=age>=0&&age<=60,
  errs=[st.deploy_error,st.error].concat(st.errors||[]).filter(Boolean),rows=[];
 rows.push([t('Service'),st.active?'<span class="badge g">'+t('Running')+'</span>':'<span class="badge r">'+t(x.status_at?'Not running':'Waiting for the server…')+'</span>']);
 rows.push([t('Last report'),age<0?t('never'):'<span style="color:'+(fresh?'var(--ok)':'var(--bad)')+'">'+ago(x.status_at)+'</span>']);
 if(kind=='xray'){if(st.core)rows.push(['Xray','<span class="ltr">'+esc(st.core)+'</span>']);
  var ib=(d.inbounds||[]).filter(function(i){return i.server==id}),on=ib.filter(function(i){return i.enabled}).length;
  rows.push([t('Inbounds'),N(on)+' / '+N(ib.length)]);rows.push([t('Online now'),N((st.online||[]).length)]);
  rows.push(['SSL',x.domain?(st.ssl||(st.certs||[]).length?'<span class="badge g">✓</span>':'<span class="badge y">'+t('waiting')+'</span>'):'—'])}
 else{var q=st.q||{};if(st.version)rows.push([t('Version'),'<span class="ltr">v'+esc(st.version)+'</span>']);
  rows.push([t('Queries'),N(q.total||0)]);rows.push([t('Connections'),N(st.conns||0)]);rows.push([t('Allowed addresses'),N(st.allowed||0)]);
  // other sites: answered by the exit through the tunnel (relay), directly from abroad, or by the data center's DNS
  if(q.exit||q.direct||q.local)rows.push([t('Other sites answered by'),[[q.exit,'Exit through the tunnel'],[q.direct,'DNS abroad'],[q.local,'Data center DNS']].filter(function(a){return a[0]}).map(function(a){return t(a[1])+' '+N(a[0])}).join(' · ')]);
  rows.push(['SSL',st.ssl?'<span class="badge g">✓</span>':st.ssl_error?'<span class="badge r">'+t('error')+'</span>':'<span class="badge y">'+t('waiting')+'</span>'])}
 // ports of this service that another program holds (Caddy, nginx … from an earlier setup)
 var tk=st.taken||[],fr=tk.filter(function(p){return p.free}).map(function(p){return p.unit}).filter(function(u,i,a){return a.indexOf(u)==i});
 var tkHtml=tk.length?'<div class="warnbox" style="margin-top:10px"><b>'+t('Ports taken by another program')+'</b><br>'+tk.map(function(p){
   return '<span class="ltr">'+p.port+'/'+p.proto+'</span> · '+esc(p.prog)+(p.unit?' <span class="ltr">('+esc(p.unit)+')</span>':'')+
    ((p.serves||[]).length?'<br><small>'+t('It serves')+': <span class="ltr">'+esc(p.serves.join(', '))+'</span></small>':'')+
    (p.free?'':'<br><small>'+esc(t(p.why||''))+'</small>')}).join('<br>')+'</div>'+
  (fr.length&&x.server!='local'?'<button class="b2 bd" style="width:100%;margin-top:8px" id="hl_free">'+t('Free the ports')+' ('+esc(fr.join(', '))+')</button>':''):'';
 modal(mhead(t('Health'),x.name||x.server)+'<div class="list">'+rows.map(function(r){return '<div class="li"><span>'+r[0]+'</span><span>'+r[1]+'</span></div>'}).join('')+'</div>'+tkHtml+
  (errs.length?'<div class="warnbox ltr" style="margin-top:10px">'+errs.map(esc).join('<br>')+'</div>':'')+
  (!fresh?'<p class="muted" style="margin-top:10px">'+t('The server is not reporting: check that it is on and that its agent runs, then press Repair')+'</p>':'')+
  '<div id="hl_fw"></div>'+
  '<div class="g2" style="margin-top:12px"><button class="btn" onclick="closeModal();srvRepair(\''+kind+'\',\''+esc(id)+'\')">↻ '+t('Repair')+'</button>'+
  '<button class="b2" id="hl_ssl">'+t('Try SSL again')+'</button></div>');
 $('#hl_ssl').onclick=function(){var b=this;b.disabled=true;api('POST','/api/tunnels/servers/'+encodeURIComponent(id)+'/ssl-retry').then(function(){toast(t('Sent: the server tries SSL again within a minute'))}).catch(function(e){b.disabled=false;fail(e)})};
 srvFirewall(id,$('#hl_fw'));
 var fb=$('#hl_free');if(fb)fb.onclick=function(){
  var sites=[];tk.forEach(function(p){if(p.free)(p.serves||[]).forEach(function(s){if(sites.indexOf(s)<0)sites.push(s)})});
  var msg=t('Stop and turn off __U__ on this server? Then __S__ takes its ports.').replace('__U__',fr.join(', ')).replace('__S__',kind=='xray'?'Xray':'Kanki DNS')+
   (sites.length?'\n\n'+t('These sites go down with it')+': '+sites.join(', '):'')+'\n\n'+t('To bring it back')+': systemctl enable --now '+fr.join(' ');
  if(!confirm(msg))return;
  api('POST','/api/tunnels/servers/'+encodeURIComponent(id)+'/free-ports',{units:fr}).then(function(){closeModal();toast(t('Sent: the server frees the ports on its next report (a few seconds)'))}).catch(fail)}}
// the firewall of a server: ports Kanki opened (closed again when what needed them is removed), and open
// ports nothing uses any more (opened by an older version for something deleted since, or by hand)
var FW_NAMES={tunnels:'Tunnels',dns:'Kanki DNS',xray:'Xray',emergency:'Emergency chat',kmix:'KANKI MIX',subsrv:'Subscription link',acme:'SSL (port 80)'};
function srvFirewall(id,box){if(!box)return;api('GET','/api/tunnels/servers/'+encodeURIComponent(id)+'/firewall').then(function(f){if(!f||!box.isConnected)return;
 var own=f.owners||{},un=f.unused||[],keys=Object.keys(own);if(!keys.length&&!un.length)return;
 box.innerHTML='<div class="box" style="margin-top:10px;padding:10px 12px"><b>'+t('Firewall (ufw)')+'</b>'+
  (keys.length?'<div class="list" style="margin-top:6px">'+keys.map(function(k){return '<div class="li"><span>'+esc(t(FW_NAMES[k]||k))+'</span><span class="ltr">'+esc((own[k]||[]).join(' · '))+'</span></div>'}).join('')+'</div>':'')+
  (un.length?'<div class="warnbox" style="margin-top:8px"><b>'+t('Open ports that nothing uses')+'</b><br><span class="ltr">'+esc(un.join(' · '))+'</span><br><small>'+t('Opened earlier for something that was deleted, or by hand. SSH is never closed.')+'</small></div>'+
   '<button class="b2 bd" style="width:100%;margin-top:8px" id="fw_close">'+t('Close these ports')+' ('+N(un.length)+')</button>':'')+'</div>';
 var b=$('#fw_close');if(b)b.onclick=function(){if(!confirm(t('Close these ports in the firewall of this server?')+'\n\n'+un.join(', ')))return;b.disabled=true;
  api('POST','/api/tunnels/servers/'+encodeURIComponent(id)+'/firewall',{rules:un}).then(function(){toast(t('Sent: the server closes them on its next report (a few seconds)'))}).catch(function(e){b.disabled=false;fail(e)})}}).catch(function(){})}
function protoAll(p,add){var nm=p=='xray'?'Xray':'DNS';
 if(!confirm(t(add?'Turn on __P__ for ALL users? Every user gets it in the subscription.':'Turn off __P__ for ALL users? It leaves every subscription.').replace('__P__',nm)))return;
 toast(t('Checking…'));
 api('POST','/api/protocols/'+p+'/'+(add?'assign-all':'unassign-all')).then(function(r){toast(t('Done')+' · '+N(r.changed||0)+' '+t('users changed'));
  srvReload(p);if(S.page=='users')loadUsers()}).catch(fail)}

// ---------------------------------------------------------------- the VPN services page: Kanki VPN | Xray
function p_vpn(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('VPN services')+'</h2><p>'+t('Both kinds of VPN your users get, side by side')+'</p></div></div><div class="vhub"><div class="vside" id="vh_k">'+t('Loading…')+'</div><div class="vside" id="vh_x">'+t('Loading…')+'</div></div>'+
  '<div class="vside" id="vh_d" style="margin-top:14px"></div>';
 var go=function(){Promise.all([api('GET','/api/nodes').catch(function(){return []}),api('GET','/api/overview').catch(function(){return {}}),api('GET','/api/xray').catch(function(){return null}),api('GET','/api/dns').catch(function(){return null})]).then(function(r){if(S.page!='vpn')return;S.nodes=r[0]||[];if(r[2])XR.d=r[2];if(r[3])DN.d=r[3];vhKanki(r[0]||[],r[1]||{});vhXray(r[2]);vhDns(r[3])})};
 go();clearInterval(S.timer);S.timer=setInterval(function(){if(document.visibilityState=='visible'&&!$('#modal').classList.contains('on'))go()},8000)}
function vhHead(icon,title,sub,btns){return '<div class="vh"><span class="phi">'+ic(icon,24)+'</span><div><b>'+t(title)+'</b><small>'+t(sub)+'</small></div><span class="sp"></span><div class="vhb">'+(btns||'')+'</div></div>'}
function vhBtn(href,label,on){return '<a class="b2 sm" href="'+href+'"'+(on?' onclick="'+on+';return false"':'')+'>'+label+'</a>'}
function vhKanki(nodes,o){var up=nodes.filter(function(n){return n.id=='local'||n.online}).length,pr=o.protocols||{};
 // compact: no extra buttons, the protocol counts as a grid, the servers in two columns
 $('#vh_k').innerHTML=vhHead('nodes','Kanki VPN','WireGuard · AmneziaWG · Hysteria2 · KANKI MIX · MIX+\u200e','')+
  '<div class="kv"><div><small>'+t('Nodes online')+'</small><b>'+N(up)+' / '+N(nodes.length)+'</b></div><div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N(o.online||0)+'</b></div><div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(o.traffic_gb||0)+' GB</b></div></div>'+
  '<label class="f">'+t('Users by protocol')+'</label><div class="vhgrid">'+[['wg','WireGuard'],['awg','AmneziaWG'],['hy2','Hysteria2'],['kmix','KANKI MIX'],['kgame','MIX+\u200e']].map(function(p){return '<div class="vhcell"><small>'+p[1]+'</small><b>'+N(pr[p[0]]||0)+'</b></div>'}).join('')+'</div>'+
  '<div class="vhsrv">'+nodes.map(function(n){var s=nState(n),loc=n.id=='local';return '<div class="vhs"><span class="dot '+s.c+'"></span><div class="nm"><b>'+esc(n.name)+'</b><small>'+N(n.users||0)+' '+t('users')+(loc?' · '+t('Main server'):'')+'</small></div></div>'}).join('')+'</div>'}
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
function ufServices(protos,un){var has=function(p){return protos.indexOf(p)>=0},vpnOn=has('wg')||has('awg')||has('hy2')||has('kmix')||has('kgame');
 var card=function(key,icon,title,sub,on,body,head){return '<div class="ufsvc'+(on?' on':'')+'" data-svc="'+key+'"><div class="hd"><span class="ni">'+ic(icon,18)+'</span><div class="nm"><b>'+t(title)+'</b><small>'+t(sub)+'</small></div>'+(head||'')+'</div><div class="bd3">'+body+'</div></div>'};
 var nodes=S.nodes||[];
 var h='<label class="f" style="margin-top:12px">'+t('Services of this user')+'</label><div class="chipset" id="uf_pre"><button type="button" data-pre="all">'+t('Everything')+'</button><button type="button" data-pre="vpn">'+t('Kanki VPN only')+'</button><button type="button" data-pre="xray">'+t('Xray only')+'</button><button type="button" data-pre="dns">'+t('DNS only')+'</button></div>';
 h+=card('vpn','nodes','Kanki VPN','WireGuard · AmneziaWG · Hysteria2 · KANKI MIX',vpnOn,
  '<div class="ckrow">'+[['wg','WireGuard'],['awg','AmneziaWG'],['hy2','Hysteria2'],['kmix','KANKI MIX'],['kgame','MIX+\u200e']].map(function(p){return '<label class="pchk" style="--pc:'+PCOL[p[0]]+'"><input type="checkbox" class="f_pr" value="'+p[0]+'" '+(has(p[0])?'checked':'')+'><i></i>'+p[1]+'</label>'}).join('')+'</div>'+
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
function nodeAddTyped(){var tile=function(k,ico,title,sub){return '<button class="b2" data-nt="'+k+'" style="display:flex;gap:10px;align-items:center;text-align:start;padding:12px;width:100%;margin-bottom:8px"><span class="ni">'+ic(ico,20)+'</span><span><b>'+t(title)+'</b><br><small class="muted">'+t(sub)+'</small></span></button>'};
 modal(mhead(t('Node type'))+tile('vpn','nodes','VPN node','WireGuard · AmneziaWG · Hysteria2')+tile('xray','xray','Xray node','VLESS · VMess · Trojan · Shadowsocks')+tile('dns','dns','DNS exit node','Smart DNS abroad')+tile('relay','dns','DNS relay node','Iran server in front of a DNS exit'));
 $$('[data-nt]').forEach(function(b){b.onclick=function(){var k=b.dataset.nt;if(k=='vpn')return nodeAdd();if(k=='xray'){closeModal();xrAddNode();return}
  dnsLoad().then(function(){dnsAdd(k=='relay'?'relay':'exit')})}})}

// ==================================================================== Xray
// the Xray page. Tabs: servers, inbounds, online clients, routing, settings.
// Every user with Xray ticked is a client of every inbound (or of the inbounds that list them).
var XR={d:null,q:'',srv:'',tab:'overview'};
var XTABS=[['overview','Servers','srv'],['inbounds','Inbounds','xray'],['clients','Online clients','users'],['routing','Routing and outbounds','tunnel'],['settings','Settings','settings']];
var REALITY_TARGETS=['www.microsoft.com:443','www.apple.com:443','dl.google.com:443','www.speedtest.net:443','www.cloudflare.com:443','www.yahoo.com:443','www.amazon.com:443','addons.mozilla.org:443','www.samsung.com:443','www.nvidia.com:443',
 'www.cisco.com:443','www.mozilla.org:443','www.intel.com:443','www.ebay.com:443','www.bing.com:443','www.asus.com:443','www.digikala.com:443','www.aparat.com:443','divar.ir:443','snapp.ir:443','www.filimo.com:443','www.namava.ir:443'];
function p_xray(){KAcc.open.xr='';XR.tab=S.sub||'overview';
 $('#pg').innerHTML='<div class="ph"><div><h2>Xray</h2><p>'+t('Xray inbounds for your users: every user with Xray ticked is a client of every inbound')+'</p></div><div class="row" style="gap:6px"><button class="b2" id="xr_all1" onclick="srvProtoAll(\'xray\',0)">'+t('Off for all users')+'</button><button class="b2" onclick="srvProtoAll(\'xray\',1)">'+t('On for all users')+'</button><button class="b2" onclick="xrAddNode()">'+ic('plus',15)+' '+t('Add server')+'</button><button class="btn" onclick="xrInbound()">+ '+t('Inbound')+'</button></div></div>'+
  '<div class="ptabs" id="xr_tabs"></div><div id="xr">'+t('Loading…')+'</div>';
 xrLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName))&&(XR.tab=='overview'||XR.tab=='inbounds'||XR.tab=='clients'))xrLoad(true)},5000);srvLoad(true)}
function tab_xray(sub){XR.tab=sub||'overview';if(XR.d)xrDraw(XR.d);else xrLoad()}
function xrTabs(d){var el=$('#xr_tabs');if(!el)return;var cnt={inbounds:d.inbounds.length,clients:(d.online||[]).length,routing:(d.rule_list||[]).length+(d.outs||[]).length};
 el.innerHTML=XTABS.map(function(x){return '<a href="#xray/'+x[0]+'" class="'+(XR.tab==x[0]?'on':'')+'">'+ic(x[2],15)+t(x[1])+(cnt[x[0]]?' <em>'+N(cnt[x[0]])+'</em>':'')+'</a>'}).join('')}
function xrLoad(quiet){return api('GET','/api/xray').then(function(d){XR.d=d;if(S.page=='nodes'&&$('#nl_x'))$('#nl_x').innerHTML=xrServers(d);if(S.page!='xray')return d;if(quiet){xrTabs(d);
   if(XR.tab=='overview'&&$('#xr_srv')){$('#xr_srv').innerHTML=xrServers(d);$('#xr_kv').innerHTML=xrKpis(d);return d}
   if(XR.tab=='inbounds'&&$('#xr_ib')){$('#xr_ib').innerHTML=xrInbounds(d);return d}
   if(XR.tab=='clients'&&$('#xr_on')){$('#xr_on').innerHTML=xrOnline(d);return d}
   return d}
  xrDraw(d);return d}).catch(fail)}
function xrName(id){var a=(XR.d&&XR.d.agents)||[];for(var i=0;i<a.length;i++)if(a[i].id==id)return a[i].name;return id}
function xrDraw(d){var el=$('#xr');if(!el)return;xrTabs(d);
 ({overview:xrOverview,inbounds:xrIbTab,clients:xrClientsTab,routing:xrRouting,settings:xrSettings}[XR.tab]||xrOverview)(d,el)}
function xrTot(d){return d.inbounds.reduce(function(a,b){return a+(+b.traffic||0)},0)}
function xrKpis(d){var act=d.inbounds.filter(function(x){return x.enabled&&!x.state}).length;
 return '<div><small>'+t('Status')+'</small><b style="color:'+(d.on?'var(--ok)':'var(--bad)')+'">'+(d.on?t('On'):t('Off'))+'</b></div><div><small>'+t('Users with Xray')+'</small><b>'+N(d.users)+'</b></div>'+
  '<div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N((d.online||[]).length)+'</b></div><div><small>'+t('Working inbounds')+'</small><b>'+N(act)+' / '+N(d.inbounds.length)+'</b></div>'+
  '<div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(bytes(xrTot(d)))+'</b></div>'}
function xrOverview(d,el){
 el.innerHTML=(d.on?'':'<div class="warnbox">'+t('Xray is off: nothing runs on the servers and no links go to the users.')+' <a href="#xray/settings">'+t('Turn it on')+'</a></div>')+
  '<div class="kv k5" id="xr_kv">'+xrKpis(d)+'</div>'+
  '<div class="g2 k310one"><div class="card"><div class="nh"><h3>'+ic('srv',16)+' '+t('Xray servers')+'</h3><a class="b2" href="#nodes">'+t('Servers')+'</a></div><div id="xr_srv" style="margin-top:10px">'+xrServers(d)+'</div></div>'+
  '</div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0">'+t('1) Add a server (the panel server or any tunnel server). 2) Make inbounds on it. 3) Tick Xray for a user: the links of every inbound go into the user\'s subscription, and the traffic counts toward the user\'s volume.')+'</p></div>'}
function xrProtoShort(p){return {vless:'VL',vmess:'VM',trojan:'TR',shadowsocks:'SS'}[p]||p}
function xrMiniRow(ib){var st=xrState(ib);return '<div class="vrow"><span class="dot '+st[0]+'"></span><div class="nm"><b>'+esc(ib.remark||ib.protocol)+'</b><small class="ltr">'+esc(ib.protocol.toUpperCase())+' · '+esc(ib.network)+(ib.security!='none'?' · '+esc(ib.security.toUpperCase()):'')+' · :'+ib.port+'</small></div><span class="chipx '+st[0]+'">'+t(st[1])+'</span><b class="ltr" style="font-size:12px">'+N(bytes(ib.traffic))+'</b></div>'}
function xrState(ib){if(!ib.enabled)return ['r','Off'];if(ib.state=='depleted')return ['y','Traffic used up'];if(ib.state=='expired')return ['y','Expired'];if(ib.state=='nocert')return [ib.cert_err?'r':'y',ib.cert_err?'Certificate error':'Waiting for the certificate'];var s=(XR.d&&XR.d.servers||[]).filter(function(x){return x.server==ib.server})[0];
 if(s&&s.status&&s.status.active)return ['g','Running'];return ['y','Waiting for the server…']}

// ---- inbounds tab
function xrIbTab(d,el){
 el.innerHTML='<div class="row" style="gap:8px;margin-bottom:12px;flex-wrap:nowrap"><input id="xr_q" placeholder="'+t('Search')+'…" value="'+esc(XR.q)+'" style="flex:1;min-width:0">'+
  '<select id="xr_sf" style="width:auto"><option value="">'+t('All servers')+'</option>'+d.servers.map(function(x){return '<option value="'+esc(x.server)+'"'+(XR.srv==x.server?' selected':'')+'>'+esc(x.name||x.server)+'</option>'}).join('')+'</select>'+
  '<button class="btn" onclick="xrInbound()" style="white-space:nowrap">+ '+t('Inbound')+'</button></div><div id="xr_ib">'+xrInbounds(d)+'</div>';
 $('#xr_q').oninput=function(){XR.q=this.value;$('#xr_ib').innerHTML=xrInbounds(XR.d)};$('#xr_sf').onchange=function(){XR.srv=this.value;$('#xr_ib').innerHTML=xrInbounds(XR.d)}}
function xrInbounds(d){var q=(XR.q||'').toLowerCase(),list=d.inbounds.filter(function(ib){return (!XR.srv||ib.server==XR.srv)&&(!q||[ib.remark,ib.protocol,ib.network,ib.security,String(ib.port),ib.server_name].join(' ').toLowerCase().indexOf(q)>=0)});
 if(!d.inbounds.length)return '<div class="card" style="text-align:center;padding:30px"><p class="muted">'+t('No inbound yet.')+'</p><button class="btn" onclick="xrInbound()">+ '+t('Inbound')+'</button></div>';
 if(!list.length)return '<p class="muted">'+t('Nothing found')+'</p>';
 return '<div class="ibl">'+list.map(function(ib){var st=xrState(ib),lim=+ib.total_gb||0,used=+ib.traffic||0,p=lim>0?Math.min(100,100*used/(lim*1073741824)):0,id=esc(ib.id);
  return '<div class="ibc'+(ib.enabled?'':' off')+'"><div class="hd"><span class="pi">'+xrProtoShort(ib.protocol)+'</span><div class="nm"><b>'+esc(ib.remark||ib.protocol)+'</b><small class="ltr">'+esc(ib.server_name||ib.server)+' · '+esc(ib.listen||'0.0.0.0')+':'+ib.port+'</small></div>'+sw('',ib.enabled,"xrToggle('"+id+"')")+'</div>'+
   '<div class="chs"><span class="chipx a">'+esc(ib.protocol.toUpperCase())+'</span><span class="chipx b">'+esc(ib.network.toUpperCase())+'</span>'+(ib.security!='none'?'<span class="chipx g">'+esc(ib.security.toUpperCase())+'</span>':'')+(ib.flow?'<span class="chipx">Vision</span>':'')+(ib.link_tls||ib.link_host?'<span class="chipx">CDN</span>':'')+((ib.fallbacks||[]).length?'<span class="chipx">'+t('Fallbacks')+'</span>':'')+((ib.only||[]).length?'<span class="chipx y">'+N(ib.only.length)+' '+t('users only')+'</span>':'')+'<span class="chipx '+st[0]+'">'+t(st[1])+'</span></div>'+
   '<div><div class="use"><span>'+t('Traffic')+': <b class="ltr">'+N(bytes(used))+'</b>'+(lim>0?' / <b class="ltr">'+N(lim)+' GB</b>':'')+'</span><span>'+t('Clients')+': <b>'+N(ib.clients)+'</b></span></div>'+(lim>0?'<div class="trk"><div class="fil'+(p>=90?' hot':'')+'" style="width:'+p.toFixed(1)+'%"></div></div>':'')+
   (ib.expire?'<div class="use" style="margin-top:4px"><span>'+t('Expires')+': '+xrDate(ib.expire)+'</span></div>':'')+'</div>'+
   '<div class="acts2"><button onclick="xrInbound(\''+id+'\')">'+ic('edit',15)+'<span>'+t('Edit')+'</span></button><button onclick="xrClients(\''+id+'\')">'+ic('users',15)+'<span>'+t('Links')+'</span></button>'+
   '<button onclick="xrClone(\''+id+'\')">'+ic('copy',15)+'<span>'+t('Copy')+'</span></button><button onclick="xrReset(\''+id+'\')">'+ic('reset',15)+'<span>'+t('Reset')+'</span></button>'+
   '<button onclick="xrIbJson(\''+id+'\')"><b style="font-size:12px">{ }</b><span>JSON</span></button><button class="x" onclick="xrIbDel(\''+id+'\')">'+ic('trash',15)+'<span>'+t('Delete')+'</span></button></div></div>'}).join('')+'</div>'}
function xrDate(ts){var d=new Date(ts*1000),left=Math.ceil((ts*1000-Date.now())/86400000);return '<span class="ltr">'+N(d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate()))+'</span> ('+(left>0?N(left)+' '+t('days'):t('Expired'))+')'}

// ---- online clients tab
function xrClientsTab(d,el){el.innerHTML='<div class="card"><div class="nh"><div><h3>'+t('Online clients')+'</h3><p class="sub" style="margin:0">'+t('Users whose Xray traffic moved in the last few seconds')+'</p></div><a class="b2" href="#users">'+t('All users')+'</a></div><div id="xr_on" style="margin-top:8px">'+xrOnline(d)+'</div></div>'}
function xrOnline(d){var on=d.online||[];if(!on.length)return '<p class="muted">'+t('Nobody is online right now')+'</p>';
 return '<div class="mtiles">'+on.map(function(u){return '<div class="vrow" style="margin:0"><span class="dot g"></span><div class="nm"><b><bdi>'+esc(u.name)+'</bdi></b><small>'+esc(u.server)+'</small></div></div>'}).join('')+'</div>'}

// ---- routing tab
function xrRouting(d,el){XR.rules=JSON.parse(JSON.stringify(d.rule_list||[]));XR.outs=JSON.parse(JSON.stringify(d.outs||[]));
 var pre=function(id,on,title,sub){return '<div class="srow"><div class="tx"><b>'+t(title)+'</b><small>'+t(sub)+'</small></div><label class="sw"><input type="checkbox" id="'+id+'" '+(on?'checked':'')+'><span></span></label></div>'};
 el.innerHTML='<div class="card"><h3>'+ic('security',16)+' '+t('Ready-made rules')+'</h3>'+
  pre('xs_bp',d.block_private,'Block private addresses','Users cannot reach the server\'s own network (10.x, 192.168.x …)')+
  pre('xs_bt',d.block_bt,'Block BitTorrent','Torrent traffic gets abuse reports to your servers')+
  pre('xs_ba',d.block_ads,'Block ads','Ad and tracker domains (geosite:category-ads-all)')+
  pre('xs_bi',d.block_ir,'Block Iranian sites','.ir domains and Iranian addresses do not go through the server: they should be opened directly')+'</div>'+
  '<div class="card"><div class="nh"><div><h3>'+ic('tunnel',16)+' '+t('Outbounds')+'</h3><p class="sub" style="margin:0">'+t('Where traffic leaves the server: directly, or on to another server (chain)')+'</p></div><button class="b2" onclick="xrOutEdit(-1)">'+ic('plus',14)+' '+t('Add outbound')+'</button></div><div id="xr_outs" style="margin-top:10px"></div>'+
  '<label class="f">'+t('Default outbound (what no rule catches)')+'</label><select id="xs_def"></select></div>'+
  '<div class="card"><div class="nh"><div><h3>'+ic('ports',16)+' '+t('Routing rules')+'</h3><p class="sub" style="margin:0">'+t('Checked from top to bottom; the first rule that matches decides')+'</p></div><button class="b2" onclick="xrRuleEdit(-1)">'+ic('plus',14)+' '+t('Add rule')+'</button></div><div id="xr_rules" style="margin-top:10px"></div>'+
  '<label class="f">'+t('Domain strategy')+'</label><select id="xs_ds">'+[['AsIs','AsIs — '+t('by name (fastest)')],['IPIfNonMatch','IPIfNonMatch — '+t('resolve when no name rule matched')],['IPOnDemand','IPOnDemand — '+t('always resolve for IP rules')]].map(function(o){return '<option value="'+o[0]+'"'+((d.domain_strategy||'AsIs')==o[0]?' selected':'')+'>'+o[1]+'</option>'}).join('')+'</select></div>'+
  '<details class="secc"><summary>'+ic('term',16)+' '+t('Advanced: raw JSON')+'<span class="chev">'+ic('chev',14)+'</span></summary><div class="bd2"><label class="f">'+t('Advanced: extra routing rules (JSON array)')+'</label><textarea id="xs_r" rows="4" class="ltr" placeholder="[]">'+esc(d.rules)+'</textarea><label class="f">'+t('Advanced: extra outbounds (JSON array, the first one becomes the default)')+'</label><textarea id="xs_o" rows="4" class="ltr" placeholder="[]">'+esc(d.outbounds)+'</textarea></div></details>'+
  '<div class="sbar"><span class="muted">'+t('Changes reach the servers within a few seconds of saving')+'</span><button class="btn" id="xs_rgo">'+t('Save routing')+'</button></div>';
 xrRoutingDraw();
 $('#xs_rgo').onclick=function(){var me=this;me.disabled=true;
  api('PUT','/api/xray',{block_private:$('#xs_bp').checked,block_bt:$('#xs_bt').checked,block_ads:$('#xs_ba').checked,block_ir:$('#xs_bi').checked,outs:XR.outs.map(function(o){var c=Object.assign({},o);delete c.error;return c}),rule_list:XR.rules,default_out:$('#xs_def').value,domain_strategy:$('#xs_ds').value,rules:$('#xs_r').value,outbounds:$('#xs_o').value})
   .then(function(){toast(t('Saved'));XR.d=null;return xrLoad()}).catch(fail).then(function(){me.disabled=false})}}
function xrOutDesc(o){if(o.kind=='socks'||o.kind=='http')return o.kind.toUpperCase()+' '+o.address+':'+o.port;if(o.kind=='link')return (o.link||'').split('://')[0].toUpperCase()+' · '+((o.link||'').split('@')[1]||'').split('?')[0].split('#')[0];if(o.kind=='json')return 'JSON';if(o.kind=='blackhole')return t('Block');return t('Direct')}
function xrRoutingDraw(){var d=XR.d,def=$('#xs_def');
 $('#xr_outs').innerHTML='<div class="rl"><span class="dot g"></span><div class="nm"><b class="ltr" style="text-align:start">direct</b><small>'+t('Straight to the internet from this server')+'</small></div><span class="chipx">'+t('built in')+'</span></div>'+
  '<div class="rl"><span class="dot r"></span><div class="nm"><b class="ltr" style="text-align:start">block</b><small>'+t('Dropped')+'</small></div><span class="chipx">'+t('built in')+'</span></div>'+
  XR.outs.map(function(o,i){return '<div class="rl"><span class="dot '+(o.error?'r':'g')+'"></span><div class="nm"><b><bdi>'+esc(o.tag)+'</bdi></b><small><bdi>'+esc(xrOutDesc(o))+'</bdi></small>'+(o.error?'<small style="color:var(--bad)">'+esc(o.error)+'</small>':'')+'</div>'+
   '<button class="ib" onclick="xrOutEdit('+i+')">'+ic('edit',15)+'</button><button class="ib bd" onclick="xrOutDel('+i+')">'+ic('trash',15)+'</button></div>'}).join('');
 var tags=['direct','block'].concat(XR.outs.map(function(o){return o.tag})),cur=def.value||d.default_out||'';
 def.innerHTML='<option value="">direct</option>'+tags.filter(function(x){return x!='direct'}).map(function(x){return '<option'+(cur==x?' selected':'')+'>'+esc(x)+'</option>'}).join('');
 $('#xr_rules').innerHTML=XR.rules.length?XR.rules.map(function(r,i){var m=[];if(r.domain)m.push(r.domain.split(/[\n,]/).filter(Boolean).slice(0,3).join(', '));if(r.ip)m.push(r.ip.split(/[\n,]/).filter(Boolean).slice(0,3).join(', '));if(r.port)m.push(t('port')+' '+r.port);if(r.network)m.push(r.network);if(r.protocol)m.push(r.protocol);
   if((r.inbound||[]).length)m.push(N(r.inbound.length)+' '+t('inbounds'));if((r.users||[]).length)m.push(N(r.users.length)+' '+t('users'));
   return '<div class="rl"'+(r.off?' style="opacity:.55"':'')+'><span class="muted" style="font-weight:800">'+N(i+1)+'</span><div class="nm"><b>'+esc(r.name||t('Rule')+' '+N(i+1))+'</b><small><bdi>'+esc(m.join(' · ')||'—')+'</bdi></small></div><span class="arrow ltr">→ '+esc(r.outbound||'direct')+'</span>'+
    '<label class="sw"><input type="checkbox" '+(r.off?'':'checked')+' onchange="XR.rules['+i+'].off=!this.checked;xrRoutingDraw()"><span></span></label>'+
    '<button class="ib" '+(i==0?'disabled':'')+' onclick="xrRuleMove('+i+',-1)">↑</button><button class="ib" onclick="xrRuleEdit('+i+')">'+ic('edit',15)+'</button><button class="ib bd" onclick="XR.rules.splice('+i+',1);xrRoutingDraw()">'+ic('trash',15)+'</button></div>'}).join(''):'<p class="muted">'+t('No rules yet: everything goes to the default outbound.')+'</p>'}
function xrRuleMove(i,dir){var j=i+dir;if(j<0||j>=XR.rules.length)return;var x=XR.rules[i];XR.rules[i]=XR.rules[j];XR.rules[j]=x;xrRoutingDraw()}
function xrOutDel(i){var tag=XR.outs[i].tag;if(XR.rules.some(function(r){return r.outbound==tag}))return toast(t('A rule still sends traffic to this outbound'),1);XR.outs.splice(i,1);xrRoutingDraw()}
function xrOutEdit(i){var o=i>=0?Object.assign({},XR.outs[i]):{tag:'',kind:'link',address:'',port:0,user:'',pass:'',link:'',json:''};
 var kinds=[['link',t('Another server (from its link)')],['socks','SOCKS5'],['http','HTTP proxy'],['freedom',t('Direct (freedom)')],['blackhole',t('Block (blackhole)')],['json','JSON']];
 modal(mhead(t(i>=0?'Edit outbound':'Add outbound'))+
  '<div class="g2"><div><label class="f">'+t('Tag (name)')+'</label><input id="xo_tag" class="ltr" placeholder="germany" value="'+esc(o.tag)+'"></div><div><label class="f">'+t('Type')+'</label><select id="xo_k">'+kinds.map(function(k){return '<option value="'+k[0]+'"'+(o.kind==k[0]?' selected':'')+'>'+k[1]+'</option>'}).join('')+'</select></div></div>'+
  '<div id="xo_link"><label class="f">'+t('Link of the other server (vless, vmess, trojan or ss)')+'</label><textarea id="xo_l" rows="3" class="ltr" placeholder="vless://…">'+esc(o.link)+'</textarea><p class="hint">'+t('Typical use: this server is in Iran and the link is of a server abroad, so users connect inside Iran and leave from abroad.')+'</p></div>'+
  '<div id="xo_px" class="g2"><div><label class="f">'+t('Address')+'</label><input id="xo_a" class="ltr" value="'+esc(o.address)+'"></div><div><label class="f">'+t('Port')+'</label><input id="xo_p" type="number" class="ltr" value="'+(o.port||'')+'"></div><div><label class="f">'+t('Username (optional)')+'</label><input id="xo_u" class="ltr" value="'+esc(o.user)+'"></div><div><label class="f">'+t('Password')+'</label><input id="xo_pw" class="ltr" value="'+esc(o.pass)+'"></div></div>'+
  '<div id="xo_js"><label class="f">'+t('The whole outbound (JSON object)')+'</label><textarea id="xo_j" rows="6" class="ltr" placeholder=\'{"protocol":"freedom"}\'>'+esc(o.json)+'</textarea></div>'+
  '<div class="row" style="margin-top:12px;gap:8px"><button class="b2" id="xo_t" style="flex:1">'+t('Check')+'</button><button class="btn" id="xo_go" style="flex:2">'+t('OK')+'</button></div><pre id="xo_out" class="hide" style="max-height:220px;overflow:auto;margin-top:10px"></pre>');
 var ui=function(){var k=$('#xo_k').value;$('#xo_link').style.display=k=='link'?'':'none';$('#xo_px').style.display=k=='socks'||k=='http'?'':'none';$('#xo_js').style.display=k=='json'?'':'none'};$('#xo_k').onchange=ui;ui();
 var read=function(){return {tag:$('#xo_tag').value.trim(),kind:$('#xo_k').value,address:$('#xo_a').value.trim(),port:+$('#xo_p').value||0,user:$('#xo_u').value,pass:$('#xo_pw').value,link:$('#xo_l').value.trim(),json:$('#xo_j').value}};
 $('#xo_t').onclick=function(){var b=read();if(!b.tag)b.tag='test';api('POST','/api/xray/outs/check',b).then(function(v){var p=$('#xo_out');p.classList.remove('hide');p.textContent=JSON.stringify(v,null,2)}).catch(fail)};
 $('#xo_go').onclick=function(){var b=read();if(!/^[A-Za-z0-9_-]+$/.test(b.tag))return toast(t('an outbound tag is English letters, digits, - and _'),1);
  if(['direct','block','api'].indexOf(b.tag)>=0||XR.outs.some(function(x,j){return j!=i&&x.tag==b.tag}))return toast(t('This tag is already used'),1);
  api('POST','/api/xray/outs/check',b).then(function(){var old=i>=0?XR.outs[i].tag:'';if(i>=0)XR.outs[i]=b;else XR.outs.push(b);
   if(old&&old!=b.tag)XR.rules.forEach(function(r){if(r.outbound==old)r.outbound=b.tag});closeModal();xrRoutingDraw();toast(t('Press Save routing to apply'))}).catch(fail)}}
var RULE_PRESETS={domain:['geosite:openai','geosite:google','geosite:youtube','geosite:netflix','geosite:spotify','geosite:telegram','geosite:category-ir','geosite:category-ads-all','domain:ir','regexp:\\.ir$'],ip:['geoip:ir','geoip:private','geoip:us','geoip:de','geoip:cn']};
function xrRuleEdit(i){var d=XR.d,r=i>=0?Object.assign({},XR.rules[i]):{name:'',domain:'',ip:'',port:'',network:'',protocol:'',inbound:[],users:[],outbound:'direct'};
 var chips=function(k){return '<div class="chipset">'+RULE_PRESETS[k].map(function(x){return '<button type="button" data-add="'+k+'" data-v="'+esc(x)+'">+ '+esc(x)+'</button>'}).join('')+'</div>'};
 var tags=['direct','block'].concat(XR.outs.map(function(o){return o.tag}));
 modal(mhead(t(i>=0?'Edit rule':'Add rule'))+'<label class="f">'+t('Name')+'</label><input id="xu_n" value="'+esc(r.name)+'" placeholder="'+t('like: AI sites through Germany')+'">'+
  '<label class="f">'+t('Domains (one per line)')+'</label><textarea id="xu_d" rows="3" class="ltr" placeholder="geosite:openai&#10;domain:example.com">'+esc(r.domain)+'</textarea>'+chips('domain')+
  '<label class="f">'+t('IP addresses and ranges (one per line)')+'</label><textarea id="xu_i" rows="2" class="ltr" placeholder="geoip:ir&#10;1.2.3.0/24">'+esc(r.ip)+'</textarea>'+chips('ip')+
  '<div class="g2"><div><label class="f">'+t('Ports')+'</label><input id="xu_p" class="ltr" placeholder="443, 1000-2000" value="'+esc(r.port)+'"></div><div><label class="f">'+t('Network')+'</label><select id="xu_net">'+[['',t('Any')],['tcp','TCP'],['udp','UDP'],['tcp,udp','TCP + UDP']].map(function(o){return '<option value="'+o[0]+'"'+(r.network==o[0]?' selected':'')+'>'+o[1]+'</option>'}).join('')+'</select></div></div>'+
  '<label class="f">'+t('Sniffed protocol')+'</label><div class="ckrow">'+['http','tls','quic','bittorrent'].map(function(p){return '<label class="chk"><input type="checkbox" class="xu_pr" value="'+p+'" '+((r.protocol||'').split(',').indexOf(p)>=0?'checked':'')+'>'+p+'</label>'}).join('')+'</div>'+
  (d.inbounds.length?'<label class="f">'+t('Only from these inbounds')+'</label><div class="ckrow">'+d.inbounds.map(function(ib){return '<label class="chk"><input type="checkbox" class="xu_ib" value="'+esc(ib.id)+'" '+((r.inbound||[]).indexOf(ib.id)>=0?'checked':'')+'>'+esc(ib.remark||ib.id)+'</label>'}).join('')+'</div>':'')+
  ((d.user_list||[]).length?'<details style="margin-top:8px"'+((r.users||[]).length?' open':'')+'><summary class="muted">'+t('Only for these users')+'</summary><div class="ckrow">'+d.user_list.map(function(u){return '<label class="chk"><input type="checkbox" class="xu_u" value="'+u.id+'" '+((r.users||[]).indexOf(u.id)>=0?'checked':'')+'><span class="ltr">'+esc(u.name)+'</span></label>'}).join('')+'</div></details>':'')+
  '<label class="f">'+t('Send to')+'</label><select id="xu_o">'+tags.map(function(x){return '<option'+(r.outbound==x?' selected':'')+'>'+esc(x)+'</option>'}).join('')+'</select>'+
  '<button class="btn" style="width:100%;margin-top:14px" id="xu_go">'+t('OK')+'</button>');
 $$('[data-add]').forEach(function(b){b.onclick=function(){var ta=$(b.dataset.add=='domain'?'#xu_d':'#xu_i'),v=ta.value.trim();if(v.split(/\n/).indexOf(b.dataset.v)<0)ta.value=(v?v+'\n':'')+b.dataset.v}});
 $('#xu_go').onclick=function(){var nr={name:$('#xu_n').value.trim(),off:!!r.off,domain:$('#xu_d').value.trim(),ip:$('#xu_i').value.trim(),port:$('#xu_p').value.trim(),network:$('#xu_net').value,
   protocol:$$('.xu_pr').filter(function(c){return c.checked}).map(function(c){return c.value}).join(','),inbound:$$('.xu_ib').filter(function(c){return c.checked}).map(function(c){return c.value}),
   users:$$('.xu_u').filter(function(c){return c.checked}).map(function(c){return +c.value}),outbound:$('#xu_o').value};
  if(!nr.domain&&!nr.ip&&!nr.port&&!nr.network&&!nr.protocol&&!nr.inbound.length&&!nr.users.length)return toast(t('Give the rule at least one condition'),1);
  if(i>=0)XR.rules[i]=nr;else XR.rules.push(nr);closeModal();xrRoutingDraw();toast(t('Press Save routing to apply'))}}

// ---- settings tab
function xrSettings(d,el){
 el.innerHTML='<div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
  '<div class="srow"><div class="tx"><b>'+t('Xray is on')+'</b><small>'+t('Off: Xray stops on every server and the links leave the subscriptions')+'</small></div><label class="sw"><input type="checkbox" id="xs_on" '+(d.on?'checked':'')+'><span></span></label></div>'+
  '<div class="srow"><div class="tx"><b>'+t('IPv4 only')+'</b><small>'+t('For servers whose IPv6 does not work well')+'</small></div><label class="sw"><input type="checkbox" id="xs_v4" '+(d.ipv4?'checked':'')+'><span></span></label></div>'+
  '<div class="sgrid"><div><label class="f">'+t('Xray-core version')+'</label><input id="xs_v" class="ltr" placeholder="'+t('empty = latest')+'" value="'+esc(d.version)+'"><p class="hint">'+t('A release tag like v26.3.27')+'</p></div>'+
  '<div><label class="f">'+t('Log level')+'</label><select id="xs_ll">'+['none','error','warning','info','debug'].map(function(x){return '<option'+((d.log_level||'warning')==x?' selected':'')+'>'+x+'</option>'}).join('')+'</select></div>'+
  '</div>'+
  '<div class="sbar"><button class="btn" id="xs_go">'+t('Save')+'</button></div></div>';
 $('#xs_go').onclick=function(){api('PUT','/api/xray',{on:$('#xs_on').checked,ipv4:$('#xs_v4').checked,version:$('#xs_v').value,log_level:$('#xs_ll').value}).then(function(){toast(t('Saved'));xrLoad()}).catch(fail)}}

// ---- servers
function xrAddNode(){var go=function(){var d=XR.d,used=d.servers.map(function(x){return x.server}),ag=d.agents.filter(function(a){return used.indexOf(a.id)<0});
  modal(mhead(t('Add server'),'Xray')+'<p class="muted" style="margin:0 0 6px">'+t('Xray can run on the panel server or on any tunnel server. A new server gets a one-line install command.')+'</p><label class="f">'+t('Agent server')+'</label><select id="xa_sv"><option value="__new">'+t('New server (install command)')+'</option>'+srvOptGroups(ag,function(a){return '<option value="'+esc(a.id)+'">'+esc(a.id=='local'?a.name+' ('+t('Panel server')+')':a.name)+'</option>'})+'</select>'+
   '<div id="xa_nw"><label class="f">'+t('Server name')+'</label><input id="xa_nm" placeholder="Xray-DE"></div>'+xrDomainFields({address:'',ssl:true})+
   '<button class="btn" style="width:100%;margin-top:12px" id="xa_go">'+t('Save')+'</button><div id="xa_out"></div>');
  var sv=function(){$('#xa_nw').style.display=$('#xa_sv').value=='__new'?'':'none'};$('#xa_sv').onchange=sv;sv();xrDomainWire();
  $('#xa_go').onclick=function(){var me=this,nw=$('#xa_sv').value=='__new';me.disabled=true;
   (nw?api('POST','/api/tunnels/servers',{name:$('#xa_nm').value||'Xray'}):Promise.resolve({id:$('#xa_sv').value})).then(function(r){
    return api('POST','/api/xray/servers',{server:r.id,address:$('#xa_ad').value,ssl:$('#xa_ssl').checked}).then(function(){toast(t($('#xa_ssl').checked&&xrIsDomain($('#xa_ad').value)?'Saved: getting SSL (about a minute)':'Saved'));if(nw){me.style.display='none';$('#xa_out').innerHTML=tunCmdBox(r,r);$('#tn_cp').onclick=function(){copy($('#tn_cmd').textContent)}}else closeModal();xrLoad()})}).catch(function(e){me.disabled=false;fail(e)})}};
 if(XR.d)go();else xrLoad().then(go)}
function xrIsDomain(v){v=(v||'').trim();return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v)&&!/^[\d.]+$/.test(v)}
function xrDomainFields(x){
 return '<label class="f">'+t('Domain of this server (or IP)')+'</label><input id="xa_ad" class="ltr" placeholder="de.example.com" value="'+esc(x.address||'')+'"><p class="hint">'+t('Users connect to this address; empty = the IP the server reports from')+'</p>'+
  '<div class="srow" id="xa_sslw"><div class="tx"><b>'+t('Get SSL for this domain by itself')+'</b><small>'+t('certbot on this server gets a Let\'s Encrypt certificate for the domain (no e-mail needed) and renews it by itself; every TLS inbound of this server uses it. The domain must point to this server. Whatever uses port 80 (Caddy, nginx, an inbound …) is set aside for a few seconds and comes back by itself.')+'</small></div><label class="sw"><input type="checkbox" id="xa_ssl" '+(x.ssl!==false?'checked':'')+'><span></span></label></div>'}
function xrDomainWire(){var f=function(){var w=$('#xa_sslw');if(w)w.style.display=xrIsDomain($('#xa_ad').value)?'':'none'};$('#xa_ad').oninput=f;f()}
function xrSrvEdit(id){var x=XR.d.servers.filter(function(s){return s.server==id})[0];if(!x)return;
 modal(mhead(t('Edit'),x.name)+xrDomainFields({address:x.address,ssl:x.ssl||!x.address})+'<button class="btn" style="width:100%;margin-top:12px" id="xe_go">'+t('Save')+'</button>');xrDomainWire();
 $('#xe_go').onclick=function(){var ssl=$('#xa_ssl').checked&&xrIsDomain($('#xa_ad').value);api('POST','/api/xray/servers',{server:id,address:$('#xa_ad').value,ssl:ssl}).then(function(){closeModal();toast(t(ssl?'Saved: getting SSL (about a minute)':'Saved'));xrLoad();setTimeout(function(){xrLoad(true)},5000)}).catch(fail)}}
/** SSL of a server's domain, as the server reports it (certbot runs there) */
function xrCertErr(x){var st=x.status||{};return x.domain&&st.cert_errors&&st.cert_errors[x.domain]&&!(st.certs||[]).includes(x.domain)?st.cert_errors[x.domain]:''}
function xrCertChip(x){if(!x.domain)return '';var st=x.status||{};
 return (st.certs||[]).includes(x.domain)?'<span class="chipx g">SSL ✓</span>':xrCertErr(x)?'<span class="chipx r">SSL · '+t('error')+'</span>':'<span class="chipx y" title="'+esc(t('Taken with certbot on the server'))+'">SSL · '+t('waiting')+'</span>'}
function xrSrvDel(id){confirmDo(function(){api('DELETE','/api/xray/servers/'+encodeURIComponent(id)).then(function(){toast(t('Done'));xrLoad()}).catch(fail)})}
function xrPreview(id){api('GET','/api/xray/config/'+encodeURIComponent(id)).then(function(c){xrJsonModal(t('Config')+' · '+xrName(id),c)}).catch(fail)}
function xrJsonModal(title,v){var tx=JSON.stringify(v,null,2);modal(mhead(title)+'<pre class="ltr" style="max-height:60vh;overflow:auto;white-space:pre">'+esc(tx)+'</pre><button class="b2" style="width:100%;margin-top:8px" id="xj_cp">'+ic('copy',15)+' '+t('Copy')+'</button>','wide');$('#xj_cp').onclick=function(){copy(tx)}}

// ---- inbound actions
function xrIbDel(id){confirmDo(function(){api('DELETE','/api/xray/inbounds/'+encodeURIComponent(id)).then(function(){toast(t('Done'));xrLoad()}).catch(fail)})}
function xrToggle(id){var ib=XR.d.inbounds.filter(function(x){return x.id==id})[0];if(!ib)return;var b=Object.assign({},ib,{enabled:!ib.enabled});api('POST','/api/xray/inbounds',b).then(function(){xrLoad()}).catch(fail)}
function xrClone(id){api('POST','/api/xray/inbounds/'+encodeURIComponent(id)+'/clone').then(function(){toast(t('A copy was made (off until you check it)'));xrLoad()}).catch(fail)}
function xrReset(id){if(!confirm(t('Reset the traffic of this inbound to zero?')))return;api('POST','/api/xray/inbounds/'+encodeURIComponent(id)+'/reset').then(function(){toast(t('Done'));xrLoad()}).catch(fail)}
function xrIbJson(id){api('GET','/api/xray/inbounds/'+encodeURIComponent(id)+'/json').then(function(v){xrJsonModal('JSON',v)}).catch(fail)}
function xrClients(id){var ib=XR.d.inbounds.filter(function(x){return x.id==id})[0]||{};
 modal(mhead(t('Users and links'),ib.remark)+'<input id="xc_q" placeholder="'+t('Search')+'…" style="margin-bottom:8px"><div id="xc_l">'+t('Loading…')+'</div><div id="xc_qr"></div>','wide');
 api('GET','/api/xray/inbounds/'+encodeURIComponent(id)+'/clients').then(function(r){var list=r.clients||[];
  var draw=function(){var q=$('#xc_q').value.toLowerCase();var l=list.filter(function(c){return !q||c.name.toLowerCase().indexOf(q)>=0});
   $('#xc_l').innerHTML=l.length?l.map(function(c,i){return '<div class="vrow"><span class="dot '+(c.online?'g':c.active?'':'r')+'"></span><div class="nm"><b><bdi>'+esc(c.name)+'</bdi></b><small>'+N(bytes(c.used))+(c.limit_gb>0?' / '+N(c.limit_gb)+' GB':'')+(c.active?'':' · '+t('Inactive'))+'</small></div>'+
    (c.link?'<button class="ib" data-cp="'+i+'" title="'+t('Copy')+'">'+ic('copy',15)+'</button><button class="ib" data-qr="'+i+'" title="QR">'+ic('qr',15)+'</button>':'<span class="muted">'+t('No address')+'</span>')+'</div>'}).join(''):'<p class="muted">'+t('No users with Xray yet: tick Xray in a user\'s form')+'</p>';
   $$('#xc_l [data-cp]').forEach(function(b){b.onclick=function(){copy(l[+b.dataset.cp].link)}});
   $$('#xc_l [data-qr]').forEach(function(b){b.onclick=function(){var c=l[+b.dataset.qr];qrInto($('#xc_qr'),c.link);$('#xc_qr').insertAdjacentHTML('afterbegin','<p class="muted ltr" style="margin:10px 0 0;text-align:center">'+esc(c.name)+'</p>')}})};
  $('#xc_q').oninput=draw;draw()}).catch(fail)}

// ---- the inbound form
function xrInbound(id){var d=XR.d;if(!d)return xrLoad().then(function(){xrInbound(id)});if(!d.servers.length){toast(t('Add an Xray server first'),1);return xrAddNode()}
 var ib=d.inbounds.filter(function(x){return x.id==id})[0]||{enabled:true,protocol:'vless',network:'tcp',security:'reality',port:xrFreePort(d.servers[0].server),server:d.servers[0].server,flow:'xtls-rprx-vision',dest:'www.microsoft.com:443',names:'www.microsoft.com',fp:'chrome',sniffing:true,ss_method:'2022-blake3-aes-128-gcm',only:[],fallbacks:[],sniff_dest:[]};
 var opt=function(list,v){return list.map(function(o){o=[].concat(o);return '<option value="'+esc(o[0])+'"'+(String(o[0])==String(v)?' selected':'')+'>'+esc(o[1]||o[0])+'</option>'}).join('')};
 var inp=function(idn,label,v,ph,type){return '<div><label class="f">'+t(label)+'</label><input id="'+idn+'" class="ltr"'+(type?' type="'+type+'"':'')+' value="'+esc(v==null?'':v)+'" placeholder="'+esc(ph||'')+'"></div>'};
 var ck=function(idn,label,on,sub){return '<div class="srow"><div class="tx"><b>'+t(label)+'</b>'+(sub?'<small>'+t(sub)+'</small>':'')+'</div><label class="sw"><input type="checkbox" id="'+idn+'" '+(on?'checked':'')+'><span></span></label></div>'};
 var alpn=(ib.alpn||'').split(',').map(function(x){return x.trim()}).filter(Boolean),sd=ib.sniff_dest&&ib.sniff_dest.length?ib.sniff_dest:['http','tls','quic'];
 var exp=ib.expire?new Date(ib.expire*1000):null,expv=exp?exp.getFullYear()+'-'+p2(exp.getMonth()+1)+'-'+p2(exp.getDate()):'';
 var tabs=[['b','Basic'],['tr','Transport'],['sec','Security'],['sn','Sniffing'],['lk','Link and CDN'],['lim','Limits and users'],['fb','Fallbacks']];
 var h='<div class="ftabs" id="xi_tabs">'+tabs.map(function(x,i){return '<button type="button" data-ft="'+x[0]+'" class="'+(i?'':'on')+'">'+t(x[1])+'</button>'}).join('')+'</div>'+
  // basic
  '<div class="fsec on" data-fs="b"><div class="g2">'+inp('xi_rm','Remark',ib.remark,'DE-Reality')+'<div><label class="f">'+t('Agent server')+'</label><select id="xi_sv">'+opt(d.servers.map(function(x){return [x.server,x.name||x.server]}),ib.server)+'</select></div>'+
   '<div><label class="f">'+t('Protocol')+'</label><select id="xi_pr">'+opt([['vless','VLESS'],['vmess','VMess'],['trojan','Trojan'],['shadowsocks','Shadowsocks']],ib.protocol)+'</select></div>'+
   '<div><label class="f">'+t('Port')+'</label><div class="inl"><input id="xi_pt" class="ltr" type="number" min="1" max="65535" value="'+(ib.port||'')+'"><button type="button" class="ib" id="xi_rp" title="'+t('Random free port')+'">🎲</button></div></div>'+
   inp('xi_ls0','Listen address',ib.listen,'0.0.0.0')+'</div>'+
   '<div id="xi_ss" class="g2"><div><label class="f">'+t('Method')+'</label><select id="xi_sm">'+opt(['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305','chacha20-ietf-poly1305','aes-256-gcm','aes-128-gcm'],ib.ss_method)+'</select></div></div>'+
   '<div class="chipset" style="margin-top:12px"><span class="muted">'+t('Quick setup')+':</span>'+[['vr','VLESS + REALITY'],['vx','VLESS + XHTTP + REALITY'],['vw','VLESS + WS (CDN)'],['vg','VLESS + gRPC + REALITY'],['gc','VLESS + gRPC + TLS (CDN)'],['tt','Trojan + TLS'],['ss','Shadowsocks 2022']].map(function(x){return '<button type="button" data-pre="'+x[0]+'">'+x[1]+'</button>'}).join('')+'</div></div>'+
  // transport
  '<div class="fsec" data-fs="tr"><div class="g2"><div><label class="f">'+t('Transport')+'</label><select id="xi_nw">'+opt([['tcp','TCP (RAW)'],['ws','WebSocket'],['grpc','gRPC'],['httpupgrade','HTTPUpgrade'],['xhttp','XHTTP'],['kcp','mKCP']],ib.network)+'</select></div></div>'+
   '<div id="xi_tp" class="g2">'+inp('xi_pa','Path',ib.path,t('random if empty'))+inp('xi_ho','Host',ib.host,'')+'</div>'+
   '<div id="xi_wsx" class="g2">'+inp('xi_hb','Heartbeat (seconds, 0 = off)',ib.heartbeat||'','0','number')+'</div>'+
   '<div id="xi_xm" class="g2"><div><label class="f">'+t('Mode')+'</label><select id="xi_md">'+opt(['auto','packet-up','stream-up','stream-one'],ib.mode||'auto')+'</select></div>'+inp('xi_xp','Padding (bytes)',ib.x_padding,'100-1000')+'</div>'+
   '<div id="xi_gr"><div class="g2">'+inp('xi_svn','Service name',ib.service,t('random if empty'))+inp('xi_au','Authority (in the link)',ib.authority,'')+'</div>'+ck('xi_mm','Multi mode (in the link)',ib.multi_mode)+'</div>'+
   '<div id="xi_th">'+ck('xi_hh','HTTP header camouflage',ib.header=='http','The TCP stream starts like a plain HTTP request (path and Host above)')+'</div>'+
   '<div id="xi_kc"><div class="g2">'+inp('xi_km','MTU',ib.kcp_mtu||'','1350','number')+inp('xi_kt','TTI (ms)',ib.kcp_tti||'','50','number')+inp('xi_ku','Uplink (MB/s)',ib.kcp_up||'','5','number')+inp('xi_kd','Downlink (MB/s)',ib.kcp_down||'','20','number')+'</div>'+ck('xi_kg2','Congestion control',ib.kcp_cong)+'</div>'+
   '<div id="xi_ppw">'+ck('xi_pp','Accept PROXY protocol',ib.proxy_protocol,'Only when nginx / HAProxy in front sends it')+'</div></div>'+
  // security
  '<div class="fsec" data-fs="sec"><div id="xi_secw" class="g2"><div><label class="f">'+t('Security')+'</label><select id="xi_sc">'+opt([['none','None'],['tls','TLS'],['reality','REALITY']],ib.security)+'</select></div>'+
   '<div id="xi_fl"><label class="f">'+t('Flow')+'</label><select id="xi_flw">'+opt([['','none'],['xtls-rprx-vision','xtls-rprx-vision']],ib.flow||'')+'</select></div></div>'+
   '<div id="xi_tls"><div class="g2">'+inp('xi_sni','SNI',ib.sni,'example.com')+'<div><label class="f">'+t('Lowest TLS version')+'</label><select id="xi_tm">'+opt([['',t('Default')],'1.2','1.3'],ib.tls_min||'')+'</select></div></div>'+
    '<label class="f">ALPN</label><div class="ckrow">'+['h3','h2','http/1.1'].map(function(a){return '<label class="chk"><input type="checkbox" class="xi_al" value="'+a+'" '+((alpn.length?alpn:['h2','http/1.1']).indexOf(a)>=0?'checked':'')+'>'+a+'</label>'}).join('')+'</div>'+
    ck('xi_rs','Refuse unknown SNI',ib.reject_sni,'Only connections for the name above are answered')+
    '<label class="f">'+t('Certificate')+'</label><div class="ftabs" style="margin:0 0 6px"><button type="button" data-cm="auto" class="'+(ib.acme?'on':'')+'">'+t('Automatic (Let\'s Encrypt)')+'</button><button type="button" data-cm="pem" class="'+(ib.cert_file||ib.acme?'':'on')+'">'+t('Paste (PEM)')+'</button><button type="button" data-cm="file" class="'+(ib.cert_file&&!ib.acme?'on':'')+'">'+t('Files on the server')+'</button></div>'+
    '<div id="xi_cauto">'+xrCertAuto(ib)+'</div>'+
    '<div id="xi_cpem"><textarea id="xi_ce" rows="3" class="ltr" placeholder="-----BEGIN CERTIFICATE-----">'+esc(ib.cert||'')+'</textarea><textarea id="xi_ke" rows="3" class="ltr" style="margin-top:6px" placeholder="'+(ib.key=='set'?t('unchanged'):'-----BEGIN PRIVATE KEY-----')+'"></textarea></div>'+
    '<div id="xi_cfile" class="g2">'+inp('xi_cf','Certificate file',ib.cert_file,'/etc/letsencrypt/live/x/fullchain.pem')+inp('xi_kf','Key file',ib.key_file,'/etc/letsencrypt/live/x/privkey.pem')+'</div></div>'+
   '<div id="xi_rl"><label class="f">'+t('Target (dest)')+'</label><div class="inl"><input id="xi_de" class="ltr" value="'+esc(ib.dest||'')+'" placeholder="www.microsoft.com:443"><select id="xi_dp" style="flex:0 0 140px"><option value="">'+t('Suggestions')+'</option>'+REALITY_TARGETS.map(function(x){return '<option>'+x+'</option>'}).join('')+'</select></div>'+
    '<div class="g2">'+inp('xi_na','Server names',ib.names,'www.microsoft.com')+'<div><label class="f">'+t('Short IDs')+'</label><div class="inl"><input id="xi_si" class="ltr" value="'+esc(ib.short_ids||'')+'"><button type="button" class="ib" id="xi_sig" title="'+t('New')+'">🎲</button></div></div>'+
    inp('xi_pk','Private key',ib.private=='set'?'':ib.private,ib.private=='set'?t('unchanged'):'')+inp('xi_pb','Public key',ib.public,'')+inp('xi_sx','spiderX',ib.spx,'/')+
    '<div><label class="f">xver</label><select id="xi_xv">'+opt([0,1,2],ib.xver||0)+'</select></div>'+inp('xi_mt','Largest clock difference (ms, 0 = off)',ib.max_time_diff||'','0','number')+'</div>'+
    '<button type="button" class="b2" style="margin-top:8px" id="xi_kg">'+ic('refresh',14)+' '+t('New keys')+'</button></div>'+
   '<div id="xi_fpw" class="g2"><div><label class="f">'+t('Fingerprint')+'</label><select id="xi_fp">'+opt(['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'],ib.fp||'chrome')+'</select></div></div>'+
   '<p class="hint" id="xi_ssn">'+t('Shadowsocks has no TLS or REALITY: its own encryption is enough.')+'</p></div>'+
  // sniffing
  '<div class="fsec" data-fs="sn">'+ck('xi_sn','Sniffing',ib.sniffing,'Read the site name from the traffic (needed for domain rules)')+
   '<label class="f">'+t('Look at')+'</label><div class="ckrow">'+['http','tls','quic','fakedns'].map(function(x){return '<label class="chk"><input type="checkbox" class="xi_sd" value="'+x+'" '+(sd.indexOf(x)>=0?'checked':'')+'>'+x+'</label>'}).join('')+'</div>'+
   ck('xi_so','Use it for the destination too',ib.sniff_override,'Off = only for routing (recommended)')+ck('xi_sm2','Metadata only',ib.sniff_meta,'Do not read the content, only the connection details')+'</div>'+
  // link
  '<div class="fsec" data-fs="lk"><p class="muted" style="margin:0 0 6px">'+t('What the users\' links say. Leave empty unless a CDN or another address is in front of the server.')+'</p><div class="g2">'+inp('xi_lh','Link address',ib.link_host,t('automatic'))+inp('xi_lp','Link port',ib.link_port||'',String(ib.port||''))+inp('xi_ls','Link SNI',ib.link_sni,'')+'</div>'+
   ck('xi_lt','TLS at the CDN',ib.link_tls,'The CDN has the certificate; the server itself speaks plain WS / gRPC / XHTTP')+'</div>'+
  // limits
  '<div class="fsec" data-fs="lim"><div class="g2">'+inp('xi_tg','Total traffic of the inbound (GB, 0 = unlimited)',ib.total_gb||'','0','number')+'<div><label class="f">'+t('Stops on (empty = never)')+'</label><input id="xi_ex" type="date" class="ltr" value="'+expv+'"></div></div>'+
   '<p class="hint">'+t('When the traffic is used up or the date passes, the inbound stops by itself; users keep their own limits as well.')+'</p>'+
   '<label class="f">'+t('Only these users (empty = everyone with Xray)')+'</label><div class="row" style="gap:6px;flex-wrap:nowrap"><input id="xi_uq" placeholder="'+t('Search')+'…" style="flex:1"><button type="button" class="b2" id="xi_ua">'+t('All')+'</button><button type="button" class="b2" id="xi_un">'+t('None')+'</button></div>'+
   '<div class="ckrow" id="xi_ul" style="max-height:220px;overflow:auto">'+((d.user_list||[]).length?d.user_list.map(function(u){return '<label class="chk" data-un="'+esc(u.name.toLowerCase())+'"><input type="checkbox" class="xi_u" value="'+u.id+'" '+((ib.only||[]).indexOf(u.id)>=0?'checked':'')+'><span class="ltr">'+esc(u.name)+'</span></label>'}).join(''):'<p class="muted">'+t('No users with Xray yet: tick Xray in a user\'s form')+'</p>')+'</div></div>'+
  // fallbacks
  '<div class="fsec" data-fs="fb"><p class="muted" style="margin:0 0 6px">'+t('VLESS / Trojan over TCP with TLS: traffic that is not ours goes to these destinations (a website, another service).')+'</p><div id="xi_fbl"></div><button type="button" class="b2" id="xi_fba">'+ic('plus',14)+' '+t('Add fallback')+'</button></div>'+
  '<button class="btn" style="width:100%;margin-top:14px" id="xi_go">'+t('Save')+'</button>';
 modal(mhead(t(id?'Edit':'New inbound'),id?ib.remark:'Xray')+h,'wide');
 var FB=JSON.parse(JSON.stringify(ib.fallbacks||[]));
 var fbDraw=function(){$('#xi_fbl').innerHTML=FB.map(function(f,i){return '<div class="box" style="margin:0 0 8px"><div class="g2">'+
   ['dest','path','alpn','name'].map(function(k){return '<div><label class="f">'+t({dest:'Destination (port or address:port)',path:'Path',alpn:'ALPN',name:'SNI (name)'}[k])+'</label><input class="ltr xf" data-i="'+i+'" data-k="'+k+'" value="'+esc(f[k]||'')+'"></div>'}).join('')+
   '<div><label class="f">xver</label><select class="xf" data-i="'+i+'" data-k="xver">'+opt([0,1,2],f.xver||0)+'</select></div><div style="display:flex;align-items:flex-end"><button type="button" class="b2 bd" style="width:100%" data-fd="'+i+'">'+ic('trash',14)+' '+t('Delete')+'</button></div></div></div>'}).join('')||'<p class="muted">'+t('No fallbacks')+'</p>';
  $$('#xi_fbl .xf').forEach(function(e){e.oninput=e.onchange=function(){FB[+e.dataset.i][e.dataset.k]=e.dataset.k=='xver'?+e.value:e.value}});
  $$('#xi_fbl [data-fd]').forEach(function(b){b.onclick=function(){FB.splice(+b.dataset.fd,1);fbDraw()}})};
 fbDraw();$('#xi_fba').onclick=function(){FB.push({dest:'',path:'',alpn:'',name:'',xver:0});fbDraw()};
 $$('#xi_tabs [data-ft]').forEach(function(b){b.onclick=function(){$$('#xi_tabs [data-ft]').forEach(function(x){x.classList.toggle('on',x==b)});$$('.fsec').forEach(function(s){s.classList.toggle('on',s.dataset.fs==b.dataset.ft)})}});
 var srvDom=function(){var x=d.servers.filter(function(z){return z.server==$('#xi_sv').value})[0];return x&&x.domain||''};
 var cm=ib.acme?'auto':ib.cert_file?'file':(id?'pem':(srvDom()?'auto':'pem'));
 var sniPh=function(){var dm=srvDom();$('#xi_sni').placeholder=cm=='auto'&&dm?dm:'example.com';var h=$('#xi_cdom');if(h)h.innerHTML=dm?t('Empty SNI = the server\'s domain and certificate')+': <b class="ltr">'+esc(dm)+'</b>':t('This server has no domain: write one in SNI, or give the server a domain (Edit server).')};$$('[data-cm]').forEach(function(x){x.classList.toggle('on',x.dataset.cm==cm)});$$('[data-cm]').forEach(function(b){b.onclick=function(){cm=b.dataset.cm;$$('[data-cm]').forEach(function(x){x.classList.toggle('on',x==b)});ui()}});
 var show=function(i,on){var e=$(i);if(e)e.style.display=on?'':'none'};
 var ui=function(){var pr=$('#xi_pr').value,nw=$('#xi_nw').value,ss=pr=='shadowsocks';if(ss){$('#xi_nw').value='tcp';nw='tcp'}
  if($('#xi_sc').value=='reality'&&(['vless','trojan'].indexOf(pr)<0||['tcp','grpc','xhttp'].indexOf(nw)<0))$('#xi_sc').value='tls';
  var sc=ss?'none':$('#xi_sc').value;
  show('#xi_secw',!ss);show('#xi_ssn',ss);show('#xi_ss',ss);show('#xi_tp',['ws','httpupgrade','xhttp'].indexOf(nw)>=0||nw=='tcp'&&$('#xi_hh').checked);show('#xi_wsx',nw=='ws');show('#xi_xm',nw=='xhttp');show('#xi_gr',nw=='grpc');show('#xi_th',nw=='tcp'&&sc=='none'&&!ss);show('#xi_kc',nw=='kcp');show('#xi_ppw',nw!='kcp');
  show('#xi_fl',pr=='vless'&&nw=='tcp'&&sc!='none');show('#xi_tls',sc=='tls');show('#xi_rl',sc=='reality');show('#xi_fpw',sc!='none'||$('#xi_lt').checked);$('#xi_nw').disabled=ss;
  show('#xi_cpem',cm=='pem');show('#xi_cfile',cm=='file');show('#xi_cauto',cm=='auto');sniPh();
  var fbOk=(pr=='vless'||pr=='trojan')&&nw=='tcp'&&sc!='reality';$('#xi_tabs [data-ft="fb"]').style.display=fbOk?'':'none';
  [].forEach.call($('#xi_sc').options,function(o){if(o.value=='reality')o.disabled=['vless','trojan'].indexOf(pr)<0||['tcp','grpc','xhttp'].indexOf(nw)<0})};
 ['#xi_pr','#xi_nw','#xi_sc','#xi_lt','#xi_hh','#xi_sv'].forEach(function(s){$(s).onchange=ui});ui();
 $('#xi_dp').onchange=function(){if(!this.value)return;$('#xi_de').value=this.value;$('#xi_na').value=this.value.split(':')[0];this.value=''};
 $('#xi_sig').onclick=function(){var r='';for(var i=0;i<8;i++)r+=Math.floor(Math.random()*256).toString(16).padStart(2,'0');$('#xi_si').value=r};
 $('#xi_rp').onclick=function(){$('#xi_pt').value=xrFreePort($('#xi_sv').value,true)};
 $('#xi_kg').onclick=function(){api('POST','/api/xray/keys').then(function(k){$('#xi_pk').value=k.private;$('#xi_pb').value=k.public;if(!$('#xi_si').value)$('#xi_si').value=k.short_id}).catch(fail)};
 $('#xi_uq').oninput=function(){var q=this.value.toLowerCase();$$('#xi_ul [data-un]').forEach(function(l){l.style.display=!q||l.dataset.un.indexOf(q)>=0?'':'none'})};
 $('#xi_ua').onclick=function(){$$('.xi_u').forEach(function(c){if(c.parentNode.style.display!='none')c.checked=true})};$('#xi_un').onclick=function(){$$('.xi_u').forEach(function(c){c.checked=false})};
 $$('[data-pre]').forEach(function(b){b.onclick=function(){var k=b.dataset.pre,set=function(i,v){$(i).value=v};
  var P={vr:['vless','tcp','reality','xtls-rprx-vision',443],vx:['vless','xhttp','reality','',443],vw:['vless','ws','none','',8080],vg:['vless','grpc','reality','',443],gc:['vless','grpc','tls','',443],tt:['trojan','tcp','tls','',443],ss:['shadowsocks','tcp','none','',8388]}[k];
  set('#xi_pr',P[0]);set('#xi_nw',P[1]);set('#xi_sc',P[2]);set('#xi_flw',P[3]);if(!$('#xi_rm').value)$('#xi_rm').value=b.textContent.replace(/\s+/g,'').replace(/\+/g,'-');
  var used=XR.d.inbounds.some(function(x){return x.id!=id&&x.server==$('#xi_sv').value&&x.port==P[4]});$('#xi_pt').value=used?xrFreePort($('#xi_sv').value,true):P[4];
  if(P[2]=='reality'&&!$('#xi_de').value){$('#xi_de').value='www.microsoft.com:443';$('#xi_na').value='www.microsoft.com'}if(k=='vw')$('#xi_lt').checked=false;ui();toast(t('Filled in: check the Security tab'))}});
 $('#xi_go').onclick=function(){var me=this,v=function(i){return $(i).value.trim()};
  var ex=v('#xi_ex'),expire=0;if(ex){var pd=ex.split('-');expire=Math.floor(new Date(+pd[0],+pd[1]-1,+pd[2],23,59,0).getTime()/1000)}
  var b={id:id||'',enabled:ib.enabled!==false,remark:v('#xi_rm'),server:$('#xi_sv').value,protocol:$('#xi_pr').value,port:+v('#xi_pt')||0,listen:v('#xi_ls0'),network:$('#xi_nw').value,security:$('#xi_pr').value=='shadowsocks'?'none':$('#xi_sc').value,
   path:v('#xi_pa'),host:v('#xi_ho'),mode:$('#xi_md').value,service:v('#xi_svn'),header:$('#xi_hh').checked?'http':'',flow:$('#xi_flw').value,ss_method:$('#xi_sm').value,ss_key:ib.ss_key||'',
   heartbeat:+v('#xi_hb')||0,x_padding:v('#xi_xp'),authority:v('#xi_au'),multi_mode:$('#xi_mm').checked,kcp_mtu:+v('#xi_km')||0,kcp_tti:+v('#xi_kt')||0,kcp_up:+v('#xi_ku')||0,kcp_down:+v('#xi_kd')||0,kcp_cong:$('#xi_kg2').checked,proxy_protocol:$('#xi_pp').checked,
   sni:v('#xi_sni'),alpn:$$('.xi_al').filter(function(c){return c.checked}).map(function(c){return c.value}).join(','),tls_min:$('#xi_tm').value,reject_sni:$('#xi_rs').checked,
   acme:cm=='auto',cert:cm=='pem'?$('#xi_ce').value.trim():'',key:cm=='pem'?($('#xi_ke').value.trim()||(ib.key=='set'?'set':'')):'',cert_file:cm=='file'?v('#xi_cf'):'',key_file:cm=='file'?v('#xi_kf'):'',fp:$('#xi_fp').value,
   dest:v('#xi_de'),names:v('#xi_na'),private:v('#xi_pk')||(ib.private=='set'?'set':''),public:v('#xi_pb'),short_ids:v('#xi_si'),spx:v('#xi_sx'),xver:+$('#xi_xv').value||0,max_time_diff:+v('#xi_mt')||0,
   sniffing:$('#xi_sn').checked,sniff_dest:$$('.xi_sd').filter(function(c){return c.checked}).map(function(c){return c.value}),sniff_override:$('#xi_so').checked,sniff_meta:$('#xi_sm2').checked,
   link_host:v('#xi_lh'),link_port:+v('#xi_lp')||0,link_tls:$('#xi_lt').checked,link_sni:v('#xi_ls'),total_gb:+v('#xi_tg')||0,expire:expire,
   only:$$('.xi_u').filter(function(c){return c.checked}).map(function(c){return +c.value}),fallbacks:FB.filter(function(f){return String(f.dest).trim()})};
  if(b.private&&b.private!='set'&&!b.public)return toast(t('Public key'),1);
  if(!b.port)return toast(t('the port is required'),1);
  if(b.acme&&b.security=='tls'&&!b.sni&&!srvDom())return toast(t('Write the domain in SNI'),1);
  me.disabled=true;api('POST','/api/xray/inbounds',b).then(function(){closeModal();toast(t('Saved'));xrLoad()}).catch(function(e){me.disabled=false;fail(e)})}}
function xrCertAuto(ib){
 var st=!ib.acme?'':ib.state=='nocert'?'<div class="vrow"><span class="dot '+(ib.cert_err?'r':'y')+'"></span><div class="nm"><b>'+(ib.cert_err?t('Certificate error'):t('Waiting for the certificate'))+'</b>'+(ib.cert_err?'<small class="ltr" style="color:var(--bad)">'+esc(ib.cert_err)+'</small>':'')+'</div></div>'
  :'<div class="vrow"><span class="dot g"></span><div class="nm"><b>SSL ✓</b><small>'+t('renewed by itself')+'</small></div></div>';
 return '<p class="hint" id="xi_cdom" style="margin-top:0"></p><p class="hint" style="margin-top:0">'+t('certbot on the server gets a Let\'s Encrypt certificate for this domain by itself (no e-mail needed) and renews it. The domain must point to the server; whatever uses port 80 is set aside for a few seconds and comes back by itself. The links use the domain.')+'</p>'+st}
function xrFreePort(sid,random){var used=(XR.d&&XR.d.inbounds||[]).filter(function(x){return x.server==sid}).map(function(x){return +x.port}),bad=[53,80,853,10085,10853,10854];
 if(!random&&used.indexOf(443)<0)return 443;for(var i=0;i<200;i++){var p=10000+Math.floor(Math.random()*50000);if(used.indexOf(p)<0&&bad.indexOf(p)<0)return p}return 20000}

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

// ==================================================================== Kanki DNS
// the Kanki DNS page. Tabs: overview, servers, services, users, settings and SSL.
var DN={d:null,tab:'overview',q:'',users:null};
var DTABS=[['overview','Overview','dash'],['servers','DNS servers','srv'],['pubg','PUBG and games','globe'],['services','Services','globe'],['users','DNS users','users'],['log','Query log','traffic'],['settings','Settings and SSL','settings']];
var UPSTREAMS=[['Cloudflare','1.1.1.1, 1.0.0.1'],['Google','8.8.8.8, 8.8.4.4'],['Quad9','9.9.9.9, 149.112.112.112'],['AdGuard (no ads)','94.140.14.14, 94.140.15.15'],['OpenDNS','208.67.222.222, 208.67.220.220']];
function p_dns(){DN.tab=S.sub||'overview';
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Kanki DNS')+'</h2><p>'+t('Private smart DNS for your subscribers: sanctioned services go through your servers, everything else goes direct')+'</p></div><div class="row" style="gap:6px"><button class="b2" onclick="dnsAdd(\'relay\')">+ '+t('Add relay')+'</button><button class="btn" onclick="dnsAdd(\'exit\')">+ '+t('Add DNS server')+'</button></div></div>'+
  '<div class="ptabs" id="dn_tabs"></div><div id="dn">'+t('Loading…')+'</div>';
 dnsLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName))&&['overview','servers','users'].indexOf(DN.tab)>=0)dnsLoad(true)},5000)}
function tab_dns(sub){DN.tab=sub||'overview';if(DN.d)dnsDraw(DN.d);else dnsLoad()}
function dnsTabs(d){var el=$('#dn_tabs');if(!el)return;var cnt={servers:d.servers.length,users:d.users};
 el.innerHTML=DTABS.map(function(x){return '<a href="#dns/'+x[0]+'" class="'+(DN.tab==x[0]?'on':'')+'">'+ic(x[2],15)+t(x[1])+(cnt[x[0]]?' <em>'+N(cnt[x[0]])+'</em>':'')+'</a>'}).join('')}
function dnsLoad(quiet){return api('GET','/api/dns').then(function(d){DN.d=d;if(S.page=='nodes'&&$('#nl_d'))$('#nl_d').innerHTML=dnsServers(d);if(S.page!='dns')return d;
  if(quiet){dnsTabs(d);if(DN.tab=='overview'&&$('#dn_kv')){$('#dn_kv').innerHTML=dnsKpis(d);$('#dn_top').innerHTML=dnsTop(d);$('#dn_topo').innerHTML=dnsTopo(d);return d}
   if(DN.tab=='servers'&&$('#dn_srv')){$('#dn_srv').innerHTML=dnsServers(d);return d}
   if(DN.tab=='users'&&$('#dn_ul')){dnsUsersLoad();return d}
   if(DN.tab=='settings'&&$('#dn_cert')){$('#dn_cert').innerHTML=dnsCertState(d);return d}return d}
  dnsDraw(d);return d}).catch(fail)}
function dnsName(id){var a=(DN.d&&DN.d.agents)||[];for(var i=0;i<a.length;i++)if(a[i].id==id)return a[i].name;return id}
function dnsDraw(d){var el=$('#dn');if(!el)return;dnsTabs(d);({overview:dnsOverview,servers:dnsServersTab,pubg:dnsPubgTab,services:dnsServicesTab,users:dnsUsersTab,log:dnsLogTab,settings:dnsSettingsTab}[DN.tab]||dnsOverview)(d,el)}
function dnsSum(d,f){return d.servers.reduce(function(a,x){return a+(+f(x.status||{})||0)},0)}
function dnsKpis(d){var run=d.servers.filter(function(x){return x.status&&x.status.active}).length,q=dnsSum(d,function(s){return s.q&&s.q.total}),r=dnsSum(d,function(s){return s.q&&s.q.routed});
 return '<div><small>'+t('Status')+'</small><b style="color:'+(d.on?'var(--ok)':'var(--bad)')+'">'+(d.on?t('On'):t('Off'))+'</b></div><div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(d.servers.length)+'</b></div>'+
  '<div><small>'+t('Users with DNS')+'</small><b>'+N(d.users)+'</b></div><div><small>'+t('Allowed addresses')+'</small><b>'+N(dnsSum(d,function(s){return s.allowed}))+'</b></div>'+
  '<div><small>'+t('Queries')+' / '+t('routed')+'</small><b class="ltr">'+N(q)+' / '+N(r)+'</b></div>'}
function dnsWarn(d){var w=[];if(!d.on)w.push(t('DNS is off: nothing runs on the servers.')+' <a href="#dns/settings">'+t('Turn it on')+'</a>');
 if(!d.base&&!d.servers.some(function(x){return x.host}))w.push(t('No DNS domain yet: encrypted DNS (DoT / DoH) needs one.')+' <a href="#dns/settings">'+t('Settings and SSL')+'</a>');

 if(!d.servers.some(function(x){return x.role=='exit'}))w.push(t('Add an exit DNS server first'));
 return w.map(function(x){return '<div class="warnbox">'+x+'</div>'}).join('')}
function dnsOverview(d,el){
 el.innerHTML=dnsWarn(d)+'<div class="kv k5" id="dn_kv">'+dnsKpis(d)+'</div>'+
  '<div class="g2"><div class="card"><div class="nh"><h3>'+ic('tunnel',16)+' '+t('Path of the traffic')+'</h3><a class="b2" href="#dns/servers">'+t('Manage')+'</a></div><div id="dn_topo" style="margin-top:10px">'+dnsTopo(d)+'</div></div>'+
  '<div class="card"><h3>'+ic('traffic',16)+' '+t('Busiest services')+'</h3><p class="sub">'+t('Routed names asked for most since the DNS services started')+'</p><div id="dn_top">'+dnsTop(d)+'</div></div></div>'+
  '<div class="card"><h3>'+ic('globe',16)+' '+t('Check a domain')+'</h3><p class="sub">'+t('Does this site go through Kanki DNS, and which service lists it?')+'</p>'+dnsCheckBox()+'</div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0;line-height:2">'+t('1) The user taps «Unblock» in the Kanki app: the app registers the phone and uses your DNS. 2) Names of sanctioned services (games, AI, developer sites …) are answered with your server\'s IP and the server passes those connections on (SNI proxy), so games and sites open; everything else goes direct at full speed. 3) A relay inside Iran sends them to an exit abroad through a hidden Kanki tunnel.')+'</p></div>';
 dnsCheckWire()}
function dnsTopo(d){if(!d.servers.length)return '<p class="muted">'+t('Add an exit DNS server first')+'</p>';
 var dot=function(x){var on=x.status&&x.status.active;return '<span class="dot '+(on?'g':x.status_at?'r':'y')+'"></span> '};
 return d.servers.filter(function(x){return x.role=='exit'}).map(function(e){var rl=d.servers.filter(function(x){return x.role=='relay'&&x.exit==e.server});
  return '<div class="topo" style="margin-bottom:10px">'+(rl.length?rl.map(function(r){return '<span class="nd">'+dot(r)+'🇮🇷 '+esc(r.name||r.server)+'</span>'}).join(' ')+' <span class="ar">⟶</span> ':'')+'<span class="nd">'+dot(e)+'🌍 '+esc(e.name||e.server)+'</span> <span class="ar">⟶</span> <span class="nd">'+t('Internet')+'</span></div>'}).join('')}
function dnsTop(d){var m={};d.servers.forEach(function(x){((x.status||{}).top||[]).forEach(function(p){m[p[0]]=(m[p[0]]||0)+(+p[1]||0)})});
 var l=Object.keys(m).map(function(k){return [k,m[k]]}).sort(function(a,b){return b[1]-a[1]}).slice(0,10);if(!l.length)return '<p class="muted">'+t('Nothing yet')+'</p>';var mx=l[0][1]||1;
 return '<div class="bars">'+l.map(function(p){return '<div class="br"><span class="ltr" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+esc(p[0])+'</span><span class="tk"><i style="width:'+(100*p[1]/mx).toFixed(1)+'%"></i></span><b class="ltr">'+N(p[1])+'</b></div>'}).join('')+'</div>'}
function dnsLocked(id){var p=id.split('/'),sv=((DN.d.catalog||{}).services||[]).filter(function(s){return s.key==p[0]})[0],g=sv&&sv.groups.filter(function(g){return g.key==p[1]})[0];return !!(g&&g.locked)}
function dnsCheckBox(){return '<div class="inl"><input id="dn_ck" class="ltr" placeholder="chatgpt.com"><button class="btn" id="dn_ckb" style="flex:none">'+t('Check')+'</button></div><div id="dn_cko" style="margin-top:8px"></div>'}
function dnsCheckWire(){var go=function(){var v=$('#dn_ck').value.trim();if(!v)return;api('POST','/api/dns/check',{name:v}).then(function(r){
  $('#dn_cko').innerHTML='<div class="vrow"><span class="dot '+(r.routed?'g':'')+'"></span><div class="nm"><b><bdi>'+esc(r.name)+'</bdi></b><small>'+(r.routed?t('Goes through Kanki DNS'):t('Goes direct (not routed)'))+
   (r.id&&r.id!='custom'?' · '+esc(r.service)+' › '+esc(r.group)+(r.group_on?'':' ('+t('this group is off')+')'):r.id=='custom'?' · '+t('your extra domains'):'')+'</small></div>'+
   (!r.routed&&r.id&&r.id!='custom'&&!dnsLocked(r.id)?'<button class="b2" id="dn_ckg">'+t('Turn this group on')+'</button>':!r.routed&&!r.id?'<button class="b2" id="dn_cka">'+t('Add to extra domains')+'</button>':'')+'</div>';
  var gb=$('#dn_ckg');if(gb)gb.onclick=function(){var off=DN.d.off.filter(function(x){return x!=r.id}),opt=DN.d.opt.slice();if(opt.indexOf(r.id)<0)opt.push(r.id);api('PUT','/api/dns',{off:off,opt:opt}).then(function(){toast(t('Saved'));dnsLoad(true).then(go)}).catch(fail)};
  var a=$('#dn_cka');if(a)a.onclick=function(){var c=(DN.d.custom||[]).slice();if(c.indexOf(r.name)<0)c.push(r.name);api('PUT','/api/dns',{custom:c}).then(function(){toast(t('Saved'));dnsLoad(true).then(go)}).catch(fail)}}).catch(fail)};
 $('#dn_ckb').onclick=go;$('#dn_ck').onkeydown=function(e){if(e.key=='Enter')go()}}

// ---- servers tab
function dnsServersTab(d,el){el.innerHTML=dnsWarn(d)+'<div class="row" style="gap:8px;margin-bottom:12px"><a class="b2" href="#nodes">'+t('Add or remove DNS servers in Servers')+'</a></div><div id="dn_srv">'+dnsServers(d)+'</div>'}
function dnsCertChip(x){var st=x.status||{};if(!x.host)return '<span class="chipx">SSL · '+t('no name')+'</span>';
 return st.ssl?'<span class="chipx g">SSL ✓</span>':st.ssl_error?'<span class="chipx r" title="'+esc(st.ssl_error)+'">SSL · '+t('error')+'</span>':'<span class="chipx y">SSL · '+t('waiting')+'</span>'}
function dnsCertState(d){var c=d.cert||{};
 return c.present?'<div class="vrow"><span class="dot g"></span><div class="nm"><b>'+t('A pasted certificate is used on every DNS server')+'</b></div><button class="b2 bd" id="dn_crm">'+t('Remove it (back to certbot)')+'</button></div>'
  :'<div class="vrow"><span class="dot g"></span><div class="nm"><b>'+t('Automatic: certbot on each DNS server')+'</b><small>'+t('Each server gets a Let\'s Encrypt certificate for its own name and renews it by itself')+'</small></div></div>'}
function dnsServers(d){if(!d.servers.length)return '<div class="card" style="text-align:center;padding:30px"><p class="muted">'+t('Add an exit DNS server first')+'</p><a class="btn" href="#nodes">'+t('Servers')+'</a></div>';
 return '<div class="ibl">'+d.servers.map(function(x){var st=x.status||{},on=st.active,q=st.q||{},errs=(st.errors||[]).concat(st.deploy_error?[st.deploy_error]:[]).concat(st.error?[st.error]:[]),relay=x.role=='relay';
  var hit=q.total?Math.round(100*(q.cache||0)/q.total):0;
  return '<div class="ibc"><div class="hd"><span class="pi">'+(relay?'IR':'EX')+'</span><div class="nm"><b>'+esc(x.name||x.server)+'</b><small>'+(relay?t('Relay (inside Iran)')+' → '+esc(dnsName(x.exit)):t('Exit (abroad)'))+'</small></div><span class="chipx '+(on?'g':x.status_at?'r':'y')+'">'+(x.status_at?(on?t('Running'):t('Not running')):t('Waiting for the server…'))+'</span></div>'+
   '<div class="chs"><span class="chipx a ltr">'+esc(x.host||t('no name'))+'</span><span class="chipx ltr">IP '+esc(x.answer_ip||'?')+'</span>'+(relay?'<span class="chipx b">'+esc(x.transport||'tcpmux')+' :'+(x.tunnel_port||8446)+'</span>':'')+(x.hidden?'<span class="chipx y">'+t('Hidden from subscribers')+'</span>':'')+(st.version?'<span class="chipx">v'+esc(st.version)+'</span>':'')+'</div>'+
   (x.note?'<p class="muted" style="margin:0">'+esc(x.note)+'</p>':'')+
   '<div class="kv k4" style="margin:0"><div><small>'+t('Queries')+'</small><b>'+N(q.total||0)+'</b></div><div><small>'+t('routed')+'</small><b>'+N(q.routed||0)+'</b></div><div><small>'+t('From cache')+'</small><b>'+N(hit)+'%</b></div><div><small>'+t('Allowed addresses')+'</small><b>'+N(st.allowed||0)+'</b></div></div>'+
   (q.refused?'<p class="muted" style="margin:0">'+t('Refused (not a subscriber)')+': '+N(q.refused)+' · '+t('Connections')+': '+N(st.conns||0)+'</p>':'')+
   (errs.length?'<div class="warnbox ltr" style="margin:0">'+errs.map(esc).join('<br>')+'</div>':'')+
   '<div class="row" style="gap:6px">'+dnsCertChip(x)+'</div>'+(st.ssl_error&&!st.ssl?'<div class="warnbox ltr" style="margin:0">'+esc(st.ssl_error)+'</div>':'')+
   '<div class="g2"><button class="b2" onclick="srvRepair(\'dns\',\''+x.server+'\')">↻ '+t('Repair')+'</button><button class="b2" onclick="srvHealth(\'dns\',\''+x.server+'\')">♡ '+t('Health')+'</button>'+
   '<button class="b2 okb" onclick="protoAll(\'dns\',1)">'+ic('plus',15)+' '+t('Add to all users')+'</button><button class="b2 bd" onclick="protoAll(\'dns\',0)">'+ic('trash',15)+' '+t('Remove from all users')+'</button>'+
   '<button class="b2" onclick="dnsEdit(\''+x.server+'\')">'+ic('edit',15)+' '+t('Edit')+'</button><button class="b2 bd" onclick="dnsDel(\''+x.server+'\')">'+ic('trash',15)+' '+t('Remove from DNS')+'</button></div></div>'}).join('')+'</div>'}

// ---- services tab
function dnsGroupOn(d,id,g){if(g.locked)return false;if(g.opt_in)return d.opt.indexOf(id)>=0;return d.off.indexOf(id)<0}
function dnsServicesTab(d,el){var cat=d.catalog||{},secs=cat.sections||[],svcs=cat.services||[];
 // a group can sit in another section than its service (downloads of a game)
 var items={};secs.forEach(function(s){items[s.key]=[]});
 svcs.forEach(function(s){s.groups.forEach(function(g){var sec=g.section||s.section;if(!items[sec])items[sec]=[];var e=items[sec].filter(function(x){return x.s.key==s.key})[0];if(!e){e={s:s,gs:[]};items[sec].push(e)}e.gs.push(g)})});
 var draw=function(icons){var q=(DN.q||'').toLowerCase();
  el.innerHTML='<div class="card"><div class="inl"><input id="dn_sq" placeholder="'+t('Search services or domains')+'…" value="'+esc(DN.q)+'"><button class="btn" id="dn_svs" style="flex:none">'+t('Save services')+'</button></div><p class="hint">'+t('Groups marked "only on request" stay off until you turn them on. Some names cannot be routed (they check the address).')+'</p></div>'+
   secs.map(function(sec){var list=(items[sec.key]||[]).filter(function(e){return !q||e.s.label.toLowerCase().indexOf(q)>=0||e.gs.some(function(g){return g.label.toLowerCase().indexOf(q)>=0||g.domains.some(function(x){return x.indexOf(q)>=0})})});if(!list.length)return '';
    var all=0,on=0;list.forEach(function(e){e.gs.forEach(function(g){if(g.locked)return;all++;if(dnsGroupOn(d,e.s.key+'/'+g.key,g))on++})});
    return '<details class="secc" data-sec="'+esc(sec.key)+'"'+(q?' open':'')+'><summary>'+esc(sec.label)+'<span class="cnt" data-cnt>'+N(on)+' / '+N(all)+' '+t('on')+'</span><span class="chev">'+ic('chev',14)+'</span></summary><div class="bd2">'+
     '<div class="row" style="gap:6px;margin-bottom:8px"><button type="button" class="b2" data-all="1">'+t('All on')+'</button><button type="button" class="b2" data-all="0">'+t('All off')+'</button></div><div class="svcg">'+
     list.map(function(e){var s=e.s,icn=icons[s.key];return '<div class="svi"><div class="t">'+(icn?'<svg viewBox="0 0 24 24" width="20" height="20"><path fill="#'+esc(icn.hex=='000000'?'888888':icn.hex)+'" d="'+esc(icn.path)+'"/></svg>':ic('globe',18))+esc(s.label)+'</div>'+
      e.gs.map(function(g){var id=s.key+'/'+g.key;return '<label title="'+esc(g.domains.slice(0,12).join('\n'))+'"><input type="checkbox" class="dn_g" data-id="'+esc(id)+'" data-opt="'+(g.opt_in?1:0)+'" '+(dnsGroupOn(d,id,g)?'checked':'')+(g.locked?' disabled':'')+'><span>'+esc(g.label)+' <small>('+N(g.domains.length)+')'+(g.locked?' · '+t('cannot be routed'):g.opt_in?' · '+t('only on request'):'')+'</small>'+(g.note?'<br><small>'+esc(g.note)+'</small>':'')+'</span></label>'}).join('')+'</div>'}).join('')+'</div></div></details>'}).join('')+
   '<div class="card"><h3>'+t('Extra domains')+'</h3><p class="sub">'+t('One per line; their subdomains are routed too')+'</p><textarea id="dn_cu" rows="5" class="ltr" placeholder="example.com">'+esc((d.custom||[]).join('\n'))+'</textarea>'+
   '<div class="sbar"><span class="muted">'+N(d.domains)+' '+t('routed names now')+'</span><button class="btn" id="dn_svs2">'+t('Save services')+'</button></div></div>';
  $('#dn_sq').oninput=function(){DN.q=this.value;var p=this.selectionStart;draw(icons);var i=$('#dn_sq');i.focus();try{i.setSelectionRange(p,p)}catch(e){}};
  $$('.secc [data-all]').forEach(function(b){b.onclick=function(){var v=b.dataset.all=='1';$$('.dn_g',b.closest('.secc')).forEach(function(c){if(!c.disabled)c.checked=v});cnt(b.closest('.secc'))}});
  $$('.dn_g').forEach(function(c){c.onchange=function(){cnt(c.closest('.secc'))}});
  var save=function(){var off=d.off.slice(),opt=d.opt.slice();$$('.dn_g').forEach(function(c){if(c.disabled)return;var id=c.dataset.id;off=off.filter(function(x){return x!=id});opt=opt.filter(function(x){return x!=id});if(c.dataset.opt=='1'){if(c.checked)opt.push(id)}else if(!c.checked)off.push(id)});
   api('PUT','/api/dns',{off:off,opt:opt,custom:$('#dn_cu').value.split('\n').map(function(x){return x.trim()}).filter(Boolean)}).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};
  $('#dn_svs').onclick=save;$('#dn_svs2').onclick=save};
 var cnt=function(sec){var all=0,on=0;$$('.dn_g',sec).forEach(function(c){if(c.disabled)return;all++;if(c.checked)on++});$('[data-cnt]',sec).textContent=N(on)+' / '+N(all)+' '+t('on')};
 if(DN.icons)draw(DN.icons);else fetch('/assets/dns-icons.json').then(function(r){return r.json()}).then(function(j){DN.icons=j.icons||{};draw(DN.icons)}).catch(function(){DN.icons={};draw({})})}

// ---- users tab
function dnsUsersTab(d,el){el.innerHTML='<div class="card"><div class="nh"><div><h3>'+t('DNS users')+'</h3><p class="sub" style="margin:0">'+t('Addresses each user registered (allowed now) and their queries since the DNS services started')+'</p></div><input id="dn_uq" placeholder="'+t('Search')+'…" style="max-width:220px"></div><div id="dn_ul" style="margin-top:10px">'+t('Loading…')+'</div></div>';
 $('#dn_uq').oninput=function(){dnsUsersDraw()};dnsUsersLoad()}
function dnsUsersLoad(){api('GET','/api/dns/users').then(function(r){DN.users=r.users||[];dnsUsersDraw()}).catch(fail)}
function dnsUsersDraw(){var el=$('#dn_ul');if(!el)return;var q=($('#dn_uq')&&$('#dn_uq').value||'').toLowerCase(),l=(DN.users||[]).filter(function(u){return !q||u.name.toLowerCase().indexOf(q)>=0});
 if(!(DN.users||[]).length){el.innerHTML='<p class="muted">'+t('No user has DNS yet: tick DNS in a user\'s form')+'</p>';return}
 var host=((DN.d&&DN.d.servers)||[]).filter(function(x){return x.host&&!x.hidden})[0];
 el.innerHTML=l.map(function(u){var dot=host&&DN.d.cert&&DN.d.cert.present?u.token+'.'+host.host:'';
  return '<div class="vrow" style="flex-wrap:wrap"><span class="dot '+(u.ips.length?'g':u.active?'':'r')+'"></span><div class="nm"><b><bdi>'+esc(u.name)+'</bdi></b><small>'+N(u.queries)+' '+t('queries')+' · '+N(bytes(u.bytes))+' · '+N(u.ips.length)+(u.max>0?' / '+N(u.max):'')+' '+t('addresses')+(u.active?'':' · '+t('Inactive'))+'</small></div>'+
   (dot?'<button class="ib" title="'+t('Copy the Private DNS address')+'" data-dot="'+esc(dot)+'">'+ic('copy',15)+'</button>':'')+
   '<button class="b2" data-kick="'+u.id+'"'+(u.ips.length?'':' disabled')+'>'+t('Forget addresses')+'</button>'+
   (u.ips.length?'<div class="chs" style="width:100%">'+u.ips.map(function(x){return '<span class="chipx ltr">'+esc(x.ip)+' · '+esc(x.server)+'</span>'}).join('')+'</div>':'')+'</div>'}).join('')||'<p class="muted">'+t('Nothing found')+'</p>';
 $$('#dn_ul [data-dot]').forEach(function(b){b.onclick=function(){copy(b.dataset.dot)}});
 $$('#dn_ul [data-kick]').forEach(function(b){b.onclick=function(){if(!confirm(t('The user\'s phone registers again by itself; someone else using the address loses access. Continue?')))return;api('POST','/api/dns/users/'+b.dataset.kick+'/kick').then(function(){toast(t('Done: servers forget them within a few seconds'))}).catch(fail)}})}

// ---- query log tab: every query of the subscribers (newest first, or grouped by name)
DN.lg={user:0,q:'',kind:'',view:'names'};
function dnsLogTab(d,el){var us=(DN.users||[]);
 el.innerHTML='<div class="card"><div class="nh"><div><h3>'+t('Query log')+'</h3><p class="sub" style="margin:0">'+t('Every name your subscribers asked, and whether it went through your server (routed) or straight to the site (direct). Kept in the panel\'s memory; a restart clears it.')+'</p></div><div class="row" style="gap:6px"><button class="b2" id="dl_re">'+t('Refresh')+'</button><button class="b2 bd" id="dl_clr">'+t('Clear')+'</button></div></div>'+
  '<div class="row" style="gap:8px;flex-wrap:wrap;margin-top:10px"><select id="dl_u" style="max-width:200px"><option value="0">'+t('All users')+'</option></select>'+
  '<select id="dl_k" style="max-width:170px"><option value="">'+t('All queries')+'</option><option value="routed">'+t('Routed only')+'</option><option value="direct">'+t('Direct only')+'</option></select>'+
  '<input id="dl_q" class="ltr" placeholder="igamecj.com" style="max-width:220px">'+
  '<select id="dl_v" style="max-width:170px"><option value="names">'+t('Grouped by name')+'</option><option value="items">'+t('Each query')+'</option></select></div>'+
  '<div id="dl_o" style="margin-top:10px">'+t('Loading…')+'</div></div>';
 var f=DN.lg;$('#dl_k').value=f.kind;$('#dl_q').value=f.q;$('#dl_v').value=f.view;
 var fill=function(){var sel=$('#dl_u');if(!sel)return;sel.innerHTML='<option value="0">'+t('All users')+'</option>'+(DN.users||[]).map(function(u){return '<option value="'+u.id+'">'+esc(u.name)+'</option>'}).join('');sel.value=String(f.user)};
 if(us.length)fill();else api('GET','/api/dns/users').then(function(r){DN.users=r.users||[];fill()}).catch(function(){});
 var go=function(){f.user=+$('#dl_u').value||0;f.kind=$('#dl_k').value;f.q=$('#dl_q').value.trim();f.view=$('#dl_v').value;dnsLogLoad()};
 $('#dl_u').onchange=go;$('#dl_k').onchange=go;$('#dl_v').onchange=go;var tm;$('#dl_q').oninput=function(){clearTimeout(tm);tm=setTimeout(go,350)};
 $('#dl_re').onclick=dnsLogLoad;$('#dl_clr').onclick=function(){if(!confirm(t('Clear the whole query log?')))return;api('DELETE','/api/dns/log').then(dnsLogLoad).catch(fail)};
 dnsLogLoad()}
function dnsLogLoad(){var f=DN.lg;api('GET','/api/dns/log?user='+f.user+'&kind='+encodeURIComponent(f.kind)+'&q='+encodeURIComponent(f.q)+'&limit=1000').then(function(r){var el=$('#dl_o');if(!el)return;
 var tag=function(x){return x.routed?'<span class="chipx" style="border-color:var(--gold)">'+t('routed')+(x.service?' · '+esc(x.service):'')+'</span>':'<span class="chipx">'+t('direct')+'</span>'};
 var head='<p class="muted" style="margin:0 0 8px">'+N(r.matched)+' '+t('queries')+' · '+t('kept')+' '+N(r.total)+' / '+N(r.max)+'</p>';
 if(!r.matched){el.innerHTML=head+'<p class="muted">'+t('Nothing yet: queries show up here a few seconds after a subscriber uses DNS (DNS servers must run v3.5.8 or newer).')+'</p>';return}
 if(DN.lg.view=='names'){el.innerHTML=head+r.names.map(function(x){return '<div class="vrow" style="flex-wrap:wrap"><span class="dot '+(x.routed?'g':'')+'"></span><div class="nm"><b class="ltr"><bdi>'+esc(x.name)+'</bdi></b><small>'+N(x.count)+' '+t('times')+' · '+ago(x.last)+' · '+x.users.map(esc).join('، ')+'</small></div>'+tag(x)+'</div>'}).join('')}
 else{el.innerHTML=head+r.items.map(function(x){return '<div class="vrow" style="flex-wrap:wrap"><span class="dot '+(x.routed?'g':'')+'"></span><div class="nm"><b class="ltr"><bdi>'+esc(x.name)+'</bdi> <small>'+esc(x.type)+'</small></b><small>'+esc(x.user)+' · '+esc(x.server)+' · '+ago(x.ts)+'</small></div>'+tag(x)+'</div>'}).join('')}
}).catch(fail)}

// ---- settings tab
function dnsSettingsTab(d,el){
 el.innerHTML='<div class="g2"><div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
  '<div class="srow"><div class="tx"><b>'+t('DNS is on')+'</b><small>'+t('Off: DNS stops on every server and leaves the subscriptions')+'</small></div><label class="sw"><input type="checkbox" id="dn_on" '+(d.on?'checked':'')+'><span></span></label></div>'+
  '<label class="f">'+t('DNS domain')+'</label><input id="dn_base" class="ltr" placeholder="dns.example.com" value="'+esc(d.base)+'"><p class="hint">'+t('Each DNS server gets a name under it, like de.dns.example.com')+'</p>'+
  '<label class="f">'+t('Upstream resolvers')+'</label><input id="dn_up" class="ltr" value="'+esc(d.upstreams.join(', '))+'"><div class="chipset">'+UPSTREAMS.map(function(u){return '<button type="button" data-up="'+u[1]+'">'+esc(t(u[0]))+'</button>'}).join('')+'</div>'+
  '<label class="f">'+t('An allowed address stays open for (hours)')+'</label><input id="dn_h" type="number" min="1" class="ltr" value="'+d.ip_hours+'"><p class="hint">'+t('After this long without the user\'s app registering again, the address is closed')+'</p>'+
  '<div class="sbar"><button class="btn" id="dn_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><h3>'+ic('security',16)+' SSL</h3><div id="dn_cert">'+dnsCertState(d)+'</div>'+
  '<p class="hint">'+t('Nothing to set: write each server\'s domain (or label + DNS domain) and point it to the server. Kanki DNS answers Let\'s Encrypt itself on port 80, so DNS does not stop. The SSL state of every server is on its card.')+'</p>'+
  '<details style="margin-top:8px"><summary class="muted">'+t('Paste a certificate instead (optional)')+'</summary><label class="f">'+t('Certificate (PEM, full chain)')+'</label><textarea id="dn_c" rows="3" class="ltr" placeholder="-----BEGIN CERTIFICATE-----"></textarea><label class="f">'+t('Private key (PKCS#8 PEM)')+'</label><textarea id="dn_k" rows="3" class="ltr" placeholder="-----BEGIN PRIVATE KEY-----"></textarea>'+
  '<div class="sbar"><button class="btn" id="dn_csave">'+t('Save')+'</button></div></details></div></div>';
 var rm=$('#dn_crm');if(rm)rm.onclick=function(){api('PUT','/api/dns',{cert:'',key:''}).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};
 $$('[data-up]').forEach(function(b){b.onclick=function(){$('#dn_up').value=b.dataset.up}});
 $('#dn_save').onclick=function(){api('PUT','/api/dns',{on:$('#dn_on').checked,base:$('#dn_base').value,upstreams:$('#dn_up').value,ip_hours:+$('#dn_h').value||12}).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};
 $('#dn_csave').onclick=function(){var c=$('#dn_c').value.trim();if(!c)return toast(t('Paste the certificate first'),1);
  api('PUT','/api/dns',{cert:c,key:$('#dn_k').value}).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};}

// ---- add / edit a DNS server
function dnsForm(x,role){var d=DN.d,exits=d.servers.filter(function(s){return s.role=='exit'&&s.server!=(x&&x.server)}),agents=d.agents.filter(function(a){return !d.servers.some(function(s){return s.server==a.id&&(!x||s.server!=x.server)})});
 if(role=='relay'&&!exits.length){toast(t('Add an exit DNS server first'),1);return null}
 var h='<p class="muted" style="margin:0 0 6px">'+t('Ports 53, 80, 443 and 853 must be free on this server: give DNS its own server.')+'</p>';
 if(!x)h+='<label class="f">'+t('Agent server')+'</label><select id="dx_sv"><option value="__new">'+t('New server (install command)')+'</option>'+srvOptGroups(agents,function(a){return '<option value="'+esc(a.id)+'">'+esc(a.name)+'</option>'})+'</select><div id="dx_nw"><label class="f">'+t('Server name')+'</label><input id="dx_nm" placeholder="'+(role=='relay'?'Iran-DNS':'DNS-DE')+'"></div>';
 h+='<label class="f">'+t('Domain of this DNS server')+'</label><input id="dx_dm" class="ltr" placeholder="'+(d.base?(role=='relay'?'ir1.':'de.')+esc(d.base):'de.dns.example.com')+'" value="'+esc(x?x.domain||'':'')+'"><p class="hint">'+t('Empty = label + DNS domain. Point the domain to this server: its SSL is taken on the server with certbot by itself.')+'</p>'+

  '<div class="g2"><div><label class="f">'+t('Label')+'</label><input id="dx_lb" class="ltr" placeholder="'+(role=='relay'?'ir1':'de')+'" value="'+esc(x?x.label:'')+'"><p class="hint ltr" id="dx_lbh"></p></div><div><label class="f">'+t('Answer IP')+'</label><input id="dx_ip" class="ltr" placeholder="'+t('automatic')+'" value="'+esc(x?x.ip:'')+'"></div></div>';
 if(role=='relay')h+='<label class="f">'+t('Its exit')+'</label><select id="dx_ex">'+exits.map(function(s){return '<option value="'+esc(s.server)+'"'+(x&&x.exit==s.server?' selected':'')+'>'+esc(s.name)+'</option>'}).join('')+'</select>'+
  '<div class="g2"><div><label class="f">'+t('Transport to the exit')+'</label><select id="dx_tr">'+['tcpmux','dual','h2','hq','wss','ws','kcp','quic','tcp'].map(function(v){return '<option'+((x&&x.transport||'tcpmux')==v?' selected':'')+'>'+v+'</option>'}).join('')+'</select></div><div><label class="f">'+t('Tunnel port on the relay')+'</label><input id="dx_tp" type="number" class="ltr" value="'+((x&&x.tunnel_port)||8446)+'"></div></div>';
 h+='<label class="f">'+t('Note for subscribers')+'</label><input id="dx_nt" value="'+esc(x?x.note:'')+'" placeholder="'+t('like: best on Irancell')+'"><div class="srow"><div class="tx"><b>'+t('Hidden from subscribers')+'</b><small>'+t('For repairs: the server keeps running but is not offered')+'</small></div><label class="sw"><input type="checkbox" id="dx_hd" '+(x&&x.hidden?'checked':'')+'><span></span></label></div>';
 return h+'<button class="btn" style="width:100%;margin-top:12px" id="dx_go">'+t('Save')+'</button><div id="dx_out"></div>'}
function dnsLbHint(){var e=$('#dx_lbh');if(!e)return;var b=DN.d.base;e.textContent=b?(($('#dx_lb').value||'…')+'.'+b):''}
function dnsBody(role,sid){var b={server:sid,role:role,domain:$('#dx_dm').value.trim(),label:$('#dx_lb').value,ip:$('#dx_ip').value,note:$('#dx_nt').value,hidden:$('#dx_hd').checked};
 if(role=='relay'){b.exit=$('#dx_ex').value;b.transport=$('#dx_tr').value;b.tunnel_port=+$('#dx_tp').value||8446}return b}
function dnsAdd(role){var go=function(){var h=dnsForm(null,role);if(h===null)return;modal(mhead(t(role=='relay'?'Add relay':'Add DNS server'),t(role=='relay'?'Relay (inside Iran)':'Exit (abroad)'))+h);
  var sv=function(){$('#dx_nw').style.display=$('#dx_sv').value=='__new'?'':'none'};$('#dx_sv').onchange=sv;sv();$('#dx_lb').oninput=dnsLbHint;dnsLbHint();
  $('#dx_go').onclick=function(){var me=this;me.disabled=true;var nw=$('#dx_sv').value=='__new';
   (nw?api('POST','/api/tunnels/servers',{name:$('#dx_nm').value||((role=='relay'?'DNS-relay-':'DNS-')+($('#dx_lb').value||'')),loc:role=='relay'?'iran':'abroad'}):Promise.resolve({id:$('#dx_sv').value})).then(function(r){
    return api('POST','/api/dns/servers',dnsBody(role,r.id)).then(function(q){toast(t('Saved'));if(nw){$('#dx_go').style.display='none';$('#dx_out').innerHTML=tunCmdBox(r,r);$('#tn_cp').onclick=function(){copy($('#tn_cmd').textContent)}}else closeModal();dnsLoad()})}).catch(function(e){me.disabled=false;fail(e)})}};
 if(DN.d)go();else dnsLoad().then(go)}
function dnsEdit(id){var x=DN.d.servers.filter(function(s){return s.server==id})[0];if(!x)return;var h=dnsForm(x,x.role);if(h===null)return;
 modal(mhead(t('Edit'),x.name)+h);$('#dx_lb').oninput=dnsLbHint;dnsLbHint();$('#dx_go').onclick=function(){api('POST','/api/dns/servers',dnsBody(x.role,id)).then(function(q){toast(t('Saved'));closeModal();dnsLoad()}).catch(fail)}}
function dnsDel(id){confirmDo(function(){api('DELETE','/api/dns/servers/'+encodeURIComponent(id)).then(function(){toast(t('Done'));dnsLoad()}).catch(fail)})}


// ---- PUBG and games tab: every PUBG Mobile name in one place, what each part does, and which to turn on
var PUBG_ART=[
 ['How a PUBG Mobile connection goes','مسیر اتصال پابجی موبایل','<ol style="margin:0;padding-inline-start:18px;line-height:2.1"><li><b>ورود و لابی</b> (TCP، روی HTTPS): بازی اول به سرورهای ورود، حساب و لابی وصل می‌شود. این همان جایی است که تحریم و فیلتر جلویش را می‌گیرد و بازی روی «در حال اتصال» می‌ماند. DNS کانکی این بخش را از سرور تو رد می‌کند.</li><li><b>مسابقه</b> (UDP): بعد از لابی، بازی مستقیم با آی‌پی سرور مسابقه حرف می‌زند. این بخش اصلاً از DNS نمی‌گذرد، پس پینگ بازی بالا نمی‌رود و لازم نیست کاری بکنی.</li><li><b>آپدیت و فایل‌ها</b>: دانلودهای حجیم بازی. فقط وقتی آپدیت از ایران دانلود نمی‌شود از سرور رد کن.</li></ol>'],
 ['I connect straight with my DNS and the game does not open','مستقیم با DNS خودم وصل می‌شوم ولی بازی باز نمی‌شود','<ul style="margin:0;padding-inline-start:18px;line-height:2.1"><li>بخش «ورود، حساب و لابی» به‌صورت پیش‌فرض <b>خاموش</b> است (چون روی بیشتر اپراتورها بازی خودش باز می‌شود). وقتی خاموش است، DNS تو برای پابجی همان آی‌پی واقعی را می‌دهد و بازی مستقیم می‌رود؛ جایی که مستقیم بسته است بازی باز نمی‌شود. حالت <b>«ورود و لابی»</b> را بالا انتخاب کن.</li><li>اگر باز هم روی ورود ماند: حالت <b>«همه»</b> را امتحان کن (ضدتقلب و آپدیت هم رد می‌شوند).</li><li>بعد از عوض کردن، گوشی جواب قبلی DNS را نگه می‌دارد: بازی را کامل ببند، یک بار حالت پرواز را روشن و خاموش کن و دوباره باز کن.</li><li>گوشی باید واقعاً از DNS تو استفاده کند: در اپ کانکی «رفع تحریم» را بزن (یا Private DNS اندروید = آدرس DNS کاربر). اگر کاربر ثبت نشده باشد سرور جواب نمی‌دهد.</li><li>پایین همین صفحه می‌بینی گوشی کاربرها کدام نام‌های پابجی را پرسیده‌اند و کدام <b>مستقیم</b> رفته‌اند. اگر نامی مستقیم رفته که بازی لازمش دارد، «افزودن» را بزن.</li><li>اگر سرور DNS در ایران است (رله)، ترافیک لابی از تانل به سرور خارج می‌رود: تانل رله باید بالا باشد (صفحه‌ی سرورهای DNS).</li></ul>'],
 ['Which one so that everyone can play?','کدام را روشن کنم که همه بتوانند بازی کنند؟','<p style="margin:0;line-height:2.1">برای بیشتر کاربرها <b>«ورود و لابی (پیشنهادی)»</b> کافی است: فقط اتصال اول و فروشگاه از سرور تو رد می‌شود و خود بازی مستقیم و با پینگ کم می‌ماند. «همه» را فقط وقتی بزن که با «ورود و لابی» هنوز مشکل هست؛ ترافیک آپدیت‌ها هم از سرورهای تو رد می‌شود. DNS فقط HTTPS (پورت ۴۴۳) و HTTP (پورت ۸۰) را رد می‌کند؛ UDP مسابقه همیشه مستقیم است و این درست است.</p>']];
var PUBG_MODES=[['direct','Direct',[]],['lobby','Login and lobby (recommended)',['main','store']],['all','Everything',['main','store','anticheat','update']]];
function dnsPubgSvc(d){return ((d.catalog||{}).services||[]).filter(function(s){return s.key=='pubgmobile'})[0]}
function dnsPubgMode(d){var on=(d.opt||[]).filter(function(x){return x.indexOf('pubgmobile/')==0}).map(function(x){return x.split('/')[1]}).sort().join(',');
 for(var i=0;i<PUBG_MODES.length;i++)if(PUBG_MODES[i][2].slice().sort().join(',')==on)return PUBG_MODES[i][0];return 'custom'}
function dnsPubgSave(d,keys){var opt=(d.opt||[]).filter(function(x){return x.indexOf('pubgmobile/')!=0}).concat(keys.map(function(k){return 'pubgmobile/'+k}));
 var off=(d.off||[]).filter(function(x){return x.indexOf('pubgmobile/')!=0});
 return api('PUT','/api/dns',{opt:opt,off:off}).then(function(){toast(t('Saved: the DNS servers use it within a few seconds'));return dnsLoad()})}
function dnsPubgTab(d,el){var sv=dnsPubgSvc(d),mode=dnsPubgMode(d),fa=S.lang!='en';
 if(!sv){el.innerHTML='<div class="card"><p class="muted">PUBG Mobile</p></div>';return}
 var art=PUBG_ART.map(function(a,i){return '<details class="secc"'+(i<2?' open':'')+'><summary>'+esc(fa?a[1]:a[0])+'<span class="chev">'+ic('chev',14)+'</span></summary><div class="bd2" style="font-size:13px">'+a[2]+'</div></details>'}).join('');
 el.innerHTML=dnsWarn(d)+
  '<div class="card"><h3>'+ic('globe',16)+' '+t('PUBG Mobile through Kanki DNS')+'</h3><p class="sub">'+t('Pick one: it changes only the PUBG Mobile names below.')+'</p>'+
  '<div class="g3" id="pg_modes" style="margin-top:10px">'+PUBG_MODES.map(function(m){var on=m[0]==mode;return '<button type="button" class="b2" data-pm="'+m[0]+'" style="text-align:start;display:block;padding:12px;white-space:normal;'+(on?'border-color:var(--a);background:color-mix(in srgb,var(--a) 12%,transparent)':'')+'"><b style="display:flex;gap:6px;align-items:center">'+(on?'<span class="dot g"></span>':'')+esc(t(m[1]))+(on?' <small class="muted">· '+t('Now')+'</small>':'')+'</b><small class="muted" style="display:block;margin-top:4px;line-height:1.8">'+esc(t(m[0]=='direct'?'Nothing of PUBG passes your servers. Fine where the game opens without help.':m[0]=='lobby'?'Login, account, lobby and the UC store go through your server; the match stays direct.':'Also updates and anti-cheat. Use it when the game still stops at login or the update does not download.'))+'</small></button>'}).join('')+'</div>'+
  (mode=='custom'?'<p class="hint">'+t('Now')+': '+t('Custom')+'</p>':'')+'</div>'+
  art+
  '<div class="card"><h3>'+t('Parts of PUBG Mobile')+'</h3><p class="sub">'+t('Every name of a ticked part and all its subdomains go through your server.')+'</p>'+
  sv.groups.map(function(g){var id='pubgmobile/'+g.key,on=(d.opt||[]).indexOf(id)>=0;
   return '<div class="vrow" style="flex-wrap:wrap;align-items:flex-start"><label class="sw" style="flex:none"><input type="checkbox" class="pg_g" data-k="'+esc(g.key)+'" '+(on?'checked':'')+'><span></span></label><div class="nm"><b>'+esc(g.label)+' <small class="muted">('+N(g.domains.length)+')</small></b>'+(g.note?'<small>'+esc(g.note)+'</small>':'')+
    '<div class="chs" style="margin-top:6px">'+g.domains.map(function(x){return '<span class="chipx ltr">*.'+esc(x)+'</span>'}).join('')+'</div></div></div>'}).join('')+
  '<div class="sbar"><button class="btn" id="pg_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><div class="nh"><div><h3>'+t('PUBG names your users asked')+'</h3><p class="sub" style="margin:0">'+t('From the query log: a direct name that the game needs can be added here.')+'</p></div><button class="b2" id="pg_re">'+t('Refresh')+'</button></div><div id="pg_log" style="margin-top:10px">'+t('Loading…')+'</div></div>'+
  '<p class="hint">'+t('PUBG on PC (Krafton)')+': '+t('It is in Services › Games › Other games.')+'</p>';
 $$('#pg_modes [data-pm]').forEach(function(b){b.onclick=function(){var m=PUBG_MODES.filter(function(x){return x[0]==b.dataset.pm})[0];dnsPubgSave(d,m[2]).catch(fail)}});
 $('#pg_save').onclick=function(){dnsPubgSave(d,$$('.pg_g').filter(function(c){return c.checked}).map(function(c){return c.dataset.k})).catch(fail)};
 $('#pg_re').onclick=function(){dnsPubgLog(d)};dnsPubgLog(d)}
// PUBG names in the query log (a few searches merged)
function dnsPubgLog(d){var el=$('#pg_log');if(!el)return;var keys=['pubg','igamecj','intlgame','gcloud','proximabeta','tencent','anticheat','midas','levelinfinite','tdatamaster','amsoveasea','cloudpvp','igamebuy'],seen={},rows=[];
 Promise.all(keys.map(function(k){return api('GET','/api/dns/log?kind=&q='+encodeURIComponent(k)+'&limit=300').catch(function(){return {names:[]}})})).then(function(rs){
  rs.forEach(function(r){(r.names||[]).forEach(function(x){if(seen[x.name])return;seen[x.name]=1;rows.push(x)})});
  rows.sort(function(a,b){return (a.routed-b.routed)||(b.count-a.count)});
  var el2=$('#pg_log');if(!el2)return;
  if(!rows.length){el2.innerHTML='<p class="muted">'+t('No PUBG query in the log yet: open the game on a phone that uses your DNS, then press Refresh.')+'</p>';return}
  el2.innerHTML=rows.map(function(x){return '<div class="vrow"><span class="dot '+(x.routed?'g':'')+'"></span><div class="nm"><b class="ltr"><bdi>'+esc(x.name)+'</bdi></b><small>'+N(x.count)+' '+t('times')+' · '+(x.routed?t('routed')+(x.service?' · '+esc(x.service):''):t('direct'))+'</small></div>'+(x.routed?'':'<button class="b2" data-add="'+esc(x.name)+'">+ '+t('Add')+'</button>')+'</div>'}).join('');
  $$('#pg_log [data-add]').forEach(function(b){b.onclick=function(){var c=(DN.d.custom||[]).slice(),n=b.dataset.add;if(c.indexOf(n)<0)c.push(n);api('PUT','/api/dns',{custom:c}).then(function(){toast(t('Saved'));dnsLoad(true).then(function(){dnsPubgLog(DN.d)})}).catch(fail)}})})}

// ==================================================================== KANKI MIX
// the KANKI MIX page: our own UDP protocol on every VPN server, next to WireGuard, AmneziaWG and
// Hysteria2: game UDP on a raw datagram path (sent twice in gaming mode), TCP on KCP + FEC.
// The agent writes the built-in server to each server by itself; every user has their own key.
var KM={d:null};

function p_kmix(){KAcc.open.km='';
 $('#pg').innerHTML='<div class="ph"><div><h2>KANKI MIX</h2><p>'+t('Our own protocol on every VPN server: game packets go straight (no queue, sent twice in gaming mode), websites over KCP + FEC.')+'</p></div>'+
  '<div class="row" style="gap:6px"><button class="b2" onclick="kmAll(false)">'+t('Disable for all users')+'</button><button class="btn" onclick="kmAll(true)">'+ic('users',15)+' '+t('Enable for all users')+'</button></div></div><div id="km">'+t('Loading…')+'</div>';
 kmLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)))kmLoad(true)},8000)}
function kmLoad(quiet){return srvLoad(true).then(function(){return api('GET','/api/kmix')}).then(function(d){KM.d=d;if(S.page!='kmix')return d;
  if($('#km_srv')){$('#km_kv').innerHTML=kmKpis(d);if(!quiet||!accBusy('km'))$('#km_srv').innerHTML=kmServers(d);return d}kmDraw(d);return d}).catch(fail)}
function kmRun(x){return x.active===true}
function kmKpis(d){var s=d.settings,run=d.servers.filter(kmRun).length,on=d.servers.filter(function(x){return x.on}).length;
 return '<div><small>'+t('Status')+'</small><b style="color:'+(s.on?'var(--ok)':'var(--bad)')+'">'+(s.on?t('On'):t('Off'))+'</b></div>'+
  '<div><small>'+t('Users with KANKI MIX')+'</small><b>'+N(d.users)+' / '+N(d.users_total)+'</b></div>'+
  '<div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N(d.online)+'</b></div>'+
  '<div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(on)+'</b></div>'+
  '<div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(d.traffic_gb)+' GB</b></div>'}
function kmState(x){if(!x.on)return ['','Off on this server'];if(kmRun(x))return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
// direct (the foreign server's own address) or through the Iran tunnel, and an optional address of its own
function kmDraw(d){var el=$('#km');if(!el)return;var s=d.settings;
 var par=[[0,'none'],[2,'light'],[3,'normal'],[5,'strong'],[8,'very strong']];
 el.innerHTML=(s.on?'':'<div class="warnbox">'+t('KANKI MIX is off: it runs on no server and is in no subscription.')+'</div>')+
  '<div class="kv k5" id="km_kv">'+kmKpis(d)+'</div>'+
  '<div class="g2 kmg2"><div class="card"><div class="nh"><h3>'+ic('srv',16)+' '+t('Servers')+'</h3><a class="b2" href="#nodes">'+t('Servers')+'</a></div><div id="km_srv" style="margin-top:10px">'+kmServers(d)+'</div></div>'+
  '<div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
   '<div class="srow"><div class="tx"><b>'+t('KANKI MIX on')+'</b></div><label class="sw"><input type="checkbox" id="km_on" '+(s.on?'checked':'')+'><span></span></label></div>'+
   '<label class="f">'+t('Default UDP port')+'</label><input id="km_port" class="ltr" inputmode="numeric" value="'+esc(String(s.port))+'"><small class="muted">'+t('Every server uses it unless it has its own port below.')+'</small>'+
   '<label class="f">'+t('FEC for websites (TCP)')+'</label><select id="km_par">'+par.map(function(p){return '<option value="'+p[0]+'"'+(s.parity==p[0]?' selected':'')+'>'+t(p[1])+' · 10+'+p[0]+'</option>'}).join('')+
    (par.some(function(p){return p[0]==s.parity})?'':'<option value="'+s.parity+'" selected>10+'+s.parity+'</option>')+'</select><small class="muted">'+t('Extra bytes that rebuild lost packets without asking again. Games do not use it (they have gaming mode).')+'</small>'+
   '<div class="srow" style="margin-top:8px"><div class="tx"><b>'+t('Gaming mode on in the app by default')+'</b><small>'+t('Each game packet is sent twice: at 20% loss 92% arrive instead of 64%. Users can switch it off in the app.')+'</small></div><label class="sw"><input type="checkbox" id="km_gm" '+(s.gaming?'checked':'')+'><span></span></label></div>'+
   '<label class="f">'+t('Extra ports (port range)')+'</label><input id="km_hop" class="ltr" placeholder="4001-4010" value="'+esc(s.hop||'')+'"><small class="muted">'+t('Like 4001-4010. They all lead to the main port; the app picks one at random on every connect, so blocking one port is not enough. Empty = off.')+'</small>'+
   '<button class="btn" style="width:100%;margin-top:12px" id="km_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0 0 6px">'+t('1) Keep it on and pick the port (4000 is fine). 2) Tick KANKI MIX for users (or Enable for all users). 3) Every server installs it by itself within a minute; the Kanki app gets the kanki:// link from the subscription, users see no IP or key.')+'</p>'+
   '<p class="sub" style="margin:0">'+t('Each user has their own key (made from the subscription code): resetting the link gives a new key, disabling or expiring cuts the user off at once. Traffic and devices count like the other protocols.')+'</p>'+
   '<p class="sub" style="margin:6px 0 0">'+t('Direct: the app connects straight to the foreign server, lowest ping. Tunnel: the app connects to the Iran server; the tunnel to this server must forward this UDP port.')+'</p>'+
   '<label class="f">'+t('Coming next')+'</label><div class="chs" style="display:flex;gap:6px;flex-wrap:wrap">'+['Port hopping during the connection (a new port every few minutes)','Look like QUIC / HTTP3 on the wire','Several servers in one link, automatic switch when one is blocked','Speed limit per user'].map(function(x){return '<span class="chipx" style="opacity:.7">'+t(x)+'</span>'}).join('')+'</div></div>';
 $('#km_save').onclick=kmSave}
function kmNodes(){var d=KM.d,m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});
 $$('.km_np').forEach(function(i){var v=unN(i.value).trim(),o=m[i.dataset.id]||{};o.port=v?+v:0;m[i.dataset.id]=o});
 $$('.km_rt').forEach(function(i){var o=m[i.dataset.id]||{};o.route=i.value;m[i.dataset.id]=o});
 $$('.km_host').forEach(function(i){var o=m[i.dataset.id]||{};o.host=i.value.trim();m[i.dataset.id]=o});
 $$('.km_t2').forEach(function(i){var o=m[i.dataset.id]||{};o.tun_off=!i.checked;m[i.dataset.id]=o});
 $$('.km_th').forEach(function(i){var o=m[i.dataset.id]||{};o.tun_host=i.value.trim();m[i.dataset.id]=o});
 $$('.km_tn').forEach(function(i){var o=m[i.dataset.id]||{};o.tun_name=i.value.trim();m[i.dataset.id]=o});
 $$('.km_tp').forEach(function(i){var v=unN(i.value).trim(),o=m[i.dataset.id]||{};o.tun_port=v?+v:0;m[i.dataset.id]=o});return m}
function kmPut(b,done){return api('PUT','/api/kmix',b).then(function(r){toast(t('Saved'));if(done)done(r);return kmLoad()}).catch(fail)}
function kmSave(){var p=unN($('#km_port').value).trim();if(!/^\d+$/.test(p)||+p<1||+p>65535)return toast(t('the port must be 1-65535'),1);
 kmPut({on:$('#km_on').checked,port:+p,parity:+$('#km_par').value,gaming:$('#km_gm').checked,hop:unN($('#km_hop').value).trim(),nodes:kmNodes()})}
function kmNodeOn(id,on){var m=kmNodes(),o=m[id]||{};o.off=!on;m[id]=o;kmPut({nodes:m})}
// from the node edit window: this server's own KANKI MIX port
function kmSetNodePort(id,port,done){var go=function(d){var m={};Object.keys(d.settings.nodes||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});var o=m[id]||{};o.port=+port||0;m[id]=o;kmPut({nodes:m},done)};
 if(!/^\d+$/.test(String(port))||+port<1||+port>65535)return toast(t('the port must be 1-65535'),1);
 api('GET','/api/kmix').then(function(d){KM.d=d;go(d)}).catch(fail)}
function kmAll(on){if(!confirm(t(on?'KANKI MIX for every user?':'Remove KANKI MIX from every user?')))return;
 api('POST','/api/kmix/users',{on:on}).then(function(r){toast(t('Saved')+' · '+N(r.changed)+' '+t('users changed'));kmLoad()}).catch(fail)}

// ==================================================================== MIX+
// the MIX+ page: our own gaming protocol for the Kanki app (KCP at its fastest with Reed-Solomon FEC
// under a mask, the Game-FEC transport of the tunnels), ticked per user like KANKI MIX. It runs on
// every VPN server on a port of its own.
var KC={d:{},meta:{
 kgame:{name:'MIX+\u200e',net:'UDP',desc:'For games (PUBG…): KCP at its fastest with FEC, a lost packet is rebuilt without waiting. Game and websites ride one stream, like the tunnels; «Game optimization» below sends game packets apart. Nothing on the wire looks like a protocol.'}}};

function kcPage(p){var m=KC.meta[p];
 $('#pg').innerHTML='<div class="ph"><div><h2>'+esc(m.name)+'</h2><p>'+t(m.desc)+'</p></div>'+
  '<div class="row" style="gap:6px"><button class="b2" onclick="kcAll(\''+p+'\',false)">'+t('Disable for all users')+'</button><button class="btn" onclick="kcAll(\''+p+'\',true)">'+ic('users',15)+' '+t('Enable for all users')+'</button></div></div><div id="kc">'+t('Loading…')+'</div>';
 kcLoad(p);clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)))kcLoad(p,true)},8000)}
function p_kgame(){kcPage('kgame')}
function kcLoad(p,quiet){return api('GET','/api/kc/'+p).then(function(d){KC.d[p]=d;if(S.page!=p)return d;
  if(quiet&&$('#kc_srv')){$('#kc_kv').innerHTML=kcKpis(d);$('#kc_srv').innerHTML=kcServers(d);return d}kcDraw(d);return d}).catch(fail)}
function kcKpis(d){var s=d.settings,run=d.servers.filter(function(x){return x.port}).length,on=d.servers.filter(function(x){return x.on}).length;
 return '<div><small>'+t('Status')+'</small><b style="color:'+(s.on?'var(--ok)':'var(--bad)')+'">'+(s.on?t('On'):t('Off'))+'</b></div>'+
  '<div><small>'+t('Users with it')+'</small><b>'+N(d.users)+' / '+N(d.users_total)+'</b></div>'+
  '<div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N(d.online)+'</b></div>'+
  '<div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(on)+'</b></div>'+
  '<div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(d.traffic_gb)+' GB</b></div>'}
function kcState(x){if(!x.on)return ['','Off on this server'];if(x.port)return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
function kcServers(d){if(!d.servers.length)return '<p class="muted">—</p>';var p=d.proto,net=KC.meta[p].net;
 return d.servers.map(function(x){var st=kcState(x),id=esc(x.id),o=(d.settings.nodes||{})[x.id]||{};
  return '<div class="vrow" style="flex-wrap:wrap;align-items:flex-start"><span class="dot '+(st[0]||'')+'" style="margin-top:6px"></span>'+
   '<div class="nm"><b>'+esc(x.name)+(x.main?' <span class="rotb">'+t('Main server')+'</span>':'')+'</b><small class="ltr">'+esc(x.host||'?')+':'+esc(String(x.port||x.want_port))+' · '+net+'</small></div>'+
   '<span class="chipx">'+N(x.users)+' '+t('users')+'</span><span class="chipx '+(st[0]||'')+'">'+t(st[1])+'</span>'+
   '<div class="row" style="gap:6px;width:100%;justify-content:flex-end;align-items:center;flex-wrap:wrap"><small class="muted">'+t('Port of this server')+'</small>'+
   '<input class="ltr kc_np" data-id="'+id+'" inputmode="numeric" style="width:90px" placeholder="'+esc(t('default'))+' '+N(d.settings.port)+'" value="'+esc(o.port||'')+'" onchange="kcSaveNodes(\''+p+'\')">'+
   '<small class="muted">'+t('Address the app dials')+'</small><input class="ltr kc_host" data-id="'+id+'" style="width:160px" placeholder="'+esc(t('automatic'))+'" value="'+esc(o.host||'')+'" onchange="kcSaveNodes(\''+p+'\')">'+
   sw('',x.on,"kcNodeOn('"+p+"','"+id+"',this.checked)")+'</div>'+
   (x.on&&x.online&&!x.reports&&d.settings.on?'<div class="warnbox" style="margin:6px 0 0;width:100%">'+t('Update the agent of this server to run it')+'</div>':'')+
   (x.on&&x.error?'<div class="warnbox ltr" style="margin:6px 0 0;width:100%">'+esc(x.error)+'</div>':'')+'</div>'}).join('')}
function kcDraw(d){var el=$('#kc');if(!el)return;var s=d.settings,p=d.proto,m=KC.meta[p];
 var fecs=['off','10:2','8:3','6:3','4:2'];if(fecs.indexOf(s.fec)<0)fecs.push(s.fec);
 var copies='<label class="f">'+t('Copies of each game packet')+' ('+t('Game optimization')+')'+'</label><select id="kc_cp">'+[[1,'1 (no copies)'],[2,'2 (recommended)'],[3,'3 (very lossy internet)']].map(function(c){return '<option value="'+c[0]+'"'+(s.copies==c[0]?' selected':'')+'>'+t(c[1])+'</option>'}).join('')+'</select>'+
  '<small class="muted">'+t('Only packets up to 400 bytes (PUBG: 40-300 bytes) are copied; downloads are sent once. Through 15% loss each way: 1 copy 72%, 2 copies 96%, 3 copies 99.8% of round trips arrive.')+'</small>';
 el.innerHTML=(s.on?'':'<div class="warnbox">'+esc(m.name)+' '+t('is off: it runs on no server and is in no subscription.')+'</div>')+
  '<div class="kv k5" id="kc_kv">'+kcKpis(d)+'</div>'+
  '<div class="g2"><div class="card"><div class="nh"><h3>'+ic('srv',16)+' '+t('Servers')+'</h3><a class="b2" href="#nodes">'+t('Servers')+'</a></div><div id="kc_srv" style="margin-top:10px">'+kcServers(d)+'</div></div>'+
  '<div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
   '<div class="srow"><div class="tx"><b>'+esc(m.name)+'</b></div><label class="sw"><input type="checkbox" id="kc_on" '+(s.on?'checked':'')+'><span></span></label></div>'+
   '<label class="f">'+t('Default port')+' · '+m.net+'</label><input id="kc_port" class="ltr" inputmode="numeric" value="'+esc(String(s.port))+'"><small class="muted">'+t('Every server uses it unless it has its own port below.')+'</small>'+
   (p=='kgame'?'<div class="srow" style="margin-top:8px"><div class="tx"><b>'+t('Game optimization')+'</b><small>'+t('Off: exactly like the tunnels (game UDP inside the stream). On: game packets as datagrams of their own, small ones sent several times.')+'</small></div><label class="sw"><input type="checkbox" id="kc_opt" '+(s.optimize?'checked':'')+'><span></span></label></div>':'')+
   (p=='kgame'?copies+'<label class="f">'+t('FEC of the stream (websites, game lobby)')+'</label><select id="kc_fec">'+fecs.map(function(f){return '<option value="'+esc(f)+'"'+(s.fec==f?' selected':'')+'>'+esc(f=='off'?t('off'):f)+'</option>'}).join('')+'</select>':'')+
   '<button class="btn" style="width:100%;margin-top:12px" id="kc_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0">'+t('Tick it for a user (user form, or Enable for all users). Every server runs it by itself within a minute; the Kanki app gets the link from the subscription. Each user has their own key: a new link is a new key, an expired or disabled user is cut off at once. Open the port at the data center\'s firewall too.')+'</p></div>';
 $('#kc_save').onclick=function(){kcSave(p)}}
function kcNodes(p){var d=KC.d[p],m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});
 $$('.kc_np').forEach(function(i){var v=unN(i.value).trim(),o=m[i.dataset.id]||{};o.port=v?+v:0;m[i.dataset.id]=o});
 $$('.kc_host').forEach(function(i){var o=m[i.dataset.id]||{};o.host=i.value.trim();m[i.dataset.id]=o});return m}
function kcPut(p,b){return api('PUT','/api/kc/'+p,b).then(function(){toast(t('Saved'));return kcLoad(p)}).catch(fail)}
function kcSaveNodes(p){kcPut(p,{nodes:kcNodes(p)})}
function kcNodeOn(p,id,on){var m=kcNodes(p),o=m[id]||{};o.off=!on;m[id]=o;kcPut(p,{nodes:m})}
function kcSave(p){var v=unN($('#kc_port').value).trim();if(!/^\d+$/.test(v)||+v<1||+v>65535)return toast(t('the port must be 1-65535'),1);
 var b={on:$('#kc_on').checked,port:+v,nodes:kcNodes(p)};
 if($('#kc_opt'))b.optimize=$('#kc_opt').checked;if($('#kc_cp'))b.copies=+$('#kc_cp').value;if($('#kc_fec'))b.fec=$('#kc_fec').value;if($('#kc_sni'))b.sni=$('#kc_sni').value.trim();kcPut(p,b)}
function kcAll(p,on){var n=KC.meta[p].name;if(!confirm(on?n+' '+t('for every user?'):n+': '+t('Remove from every user?')))return;
 api('POST','/api/kc/'+p+'/users',{on:on}).then(function(r){toast(t('Saved')+' · '+N(r.changed)+' '+t('users changed'));kcLoad(p)}).catch(fail)}

// ==================================================================== the panel: login, shell, pages
"use strict";
// Persian text of the whole panel
var FA={
 "+ Inbound":"+ دروازه",
 ".ir domains and Iranian addresses do not go through the server: they should be opened directly":"دامنه‌های .ir و IPهای ایران از سرور رد نمی‌شوند: باید مستقیم باز شوند",
 "0 = BBR (adapts by itself). A number turns on Brutal: it keeps that speed even with packet loss. Do not write more than the real speed of the servers.":"۰ = BBR (خودش تنظیم می‌شود). اگر عدد بدهی Brutal روشن می‌شود و حتی با افت بسته همان سرعت را نگه می‌دارد. بیشتر از سرعت واقعی سرورها ننویس.",
 "0 = unlimited":"0 = نامحدود",
 "1 (no copies)":"۱ (بدون نسخه‌ی اضافه)",
 "1 day":"۱ روز",
 "1 hour":"۱ ساعت",
 "1) A user's phone uses your DNS (Private DNS with the user's own address). 2) Names of sanctioned services (games, AI, developer sites …) are answered with your server's IP; everything else is answered normally and goes direct. 3) Your server passes those connections on without opening them. A relay inside Iran sends them to an exit abroad through a hidden Kanki tunnel.":"۱) گوشی کاربر از DNS شما استفاده می‌کند (Private DNS با آدرس اختصاصی خودش). ۲) اسم سرویس‌های تحریمی (بازی، هوش مصنوعی، سایت‌های برنامه‌نویسی …) با IP سرور شما جواب داده می‌شود؛ بقیه عادی جواب می‌گیرند و مستقیم می‌روند. ۳) سرور شما آن اتصال‌ها را بدون باز کردن رمز رد می‌کند. ریلی داخل ایران آن‌ها را با یک تانل مخفی کانکی به خروجی خارج می‌فرستد.",
 "1) Add a server (the panel server or any tunnel server). 2) Make inbounds on it. 3) Tick Xray for a user: the links of every inbound go into the user's subscription, and the traffic counts toward the user's volume.":"۱) یک سرور اضافه کن (سرور پنل یا هر سرور تانل). ۲) روی آن اینباند بساز. ۳) برای کاربر تیک Xray بزن: لینک همه‌ی اینباندها در ساب او می‌آید و ترافیکش از حجم خودش کم می‌شود.",
 "1) Keep it on and pick the port (4000 is fine). 2) Tick KANKI MIX for users (or Enable for all users). 3) Every server installs it by itself within a minute; the Kanki app gets the kanki:// link from the subscription, users see no IP or key.":"۱) روشن بگذار و پورت را انتخاب کن (۴۰۰۰ خوب است). ۲) KANKI MIX را برای کاربران تیک بزن (یا «روشن برای همه‌ی کاربران»). ۳) هر سرور ظرف یک دقیقه خودش نصبش می‌کند؛ اپ کانکی لینک kanki:// را از اشتراک می‌گیرد و کاربر IP یا کلید نمی‌بیند.",
 "1) The user taps «Unblock» in the Kanki app: the app registers the phone and uses your DNS. 2) Names of sanctioned services (games, AI, developer sites …) are answered with your server's IP and the server passes those connections on (SNI proxy), so games and sites open; everything else goes direct at full speed. 3) A relay inside Iran sends them to an exit abroad through a hidden Kanki tunnel.":"۱) کاربر در برنامه‌ی کانکی «رفع تحریم» را می‌زند: برنامه گوشی را ثبت می‌کند و از DNS شما استفاده می‌کند. ۲) اسم سرویس‌های تحریمی (بازی، هوش مصنوعی، سایت‌های برنامه‌نویسی …) با IP سرور شما جواب می‌گیرند و سرور اتصالشان را رد می‌کند (SNI پروکسی)، پس بازی و سایت باز می‌شود؛ بقیه مستقیم و با سرعت کامل می‌روند. ۳) ریلی داخل ایران آن‌ها را با تانل مخفی کانکی به خروجی خارج می‌فرستد.",
 "12 hours":"۱۲ ساعت",
 "2 (recommended)":"۲ (پیشنهادی)",
 "2FA code":"کد دومرحله‌ای",
 "3 (very lossy internet)":"۳ (اینترنت خیلی پرلاس)",
 "3 days":"۳ روز",
 "3 hours":"۳ ساعت",
 "30 min":"۳۰ دقیقه",
 "3X-UI style inbounds":"اینباندها به سبک 3X-UI",
 "6 hours":"۶ ساعت",
 "7 days":"۷ روز",
 "= the IP of the new server, without CDN (DNS only). The old panel keeps working by its IP until the move is done.":"= آی‌پی سرور جدید، بدون CDN (فقط DNS). پنل قدیمی تا پایان انتقال با آی‌پی خودش کار می‌کند.",
 "A Gemini key starts with AQ. or AIza (aistudio.google.com/apikey), a Groq key with gsk_, a Grok key with xai-. Save this one anyway?":"کلید Gemini با AQ. یا AIza شروع می‌شود (aistudio.google.com/apikey)، کلید Groq با gsk_ و کلید Grok با xai-. با این حال ذخیره شود؟",
 "A Groq key starts with gsk_ (console.groq.com/keys), a Grok key with xai- (console.x.ai). Save this one anyway?":"کلید Groq با gsk_ شروع می‌شود (console.groq.com/keys) و کلید Grok با xai- (console.x.ai). همین را ذخیره کنم؟",
 "A JSON file with every panel and sales setting. It holds payment keys too, keep it private. Users are not in it; use Backup for that.":"یک فایل JSON از همه‌ی تنظیمات پنل و فروش. کلیدهای پرداخت هم داخلش هست؛ جایی منتشرش نکن. کاربرها داخلش نیستند؛ برای آن از بکاپ استفاده کن.",
 "A WireGuard-like link with obfuscated packets. The panel makes the keys and the obfuscation numbers and gives both ends the same ones; the agents install AmneziaWG by themselves when it is missing. Inside the link the entry is 10.88.N.1 and the exit 10.88.N.2.":"لینک شبیه وایرگارد با بسته‌های مبهم‌سازی‌شده. پنل کلیدها و اعداد مبهم‌سازی (Jc، S1، H1…) را می‌سازد و دقیقاً یکسان به هر دو سمت می‌دهد؛ اگر AmneziaWG روی سرور نباشد، ایجنت خودش نصبش می‌کند. داخل لینک، ورودی 10.88.N.1 و خروجی 10.88.N.2 است.",
 "A copy was made (off until you check it)":"کپی ساخته شد (تا چکش نکنی خاموش است)",
 "A day with us":"یک روز با ما",
 "A domain or IP the users connect to; empty = the IP the server reports from":"دامنه یا IPی که کاربرها به آن وصل می‌شوند؛ خالی = IPی که سرور از آن گزارش می‌دهد",
 "A domain that points to this server. The panel gets its SSL by itself and serves only the subscription pages on it, so the panel address stays hidden.":"دامنه‌ای که به همین سرور اشاره می‌کند. پنل خودش SSL می‌گیرد و فقط صفحه‌های ساب را روی آن نشان می‌دهد، پس آدرس پنل پنهان می‌ماند.",
 "A new command makes the old one stop working. Continue?":"با ساختن دستور جدید، دستور قبلی دیگر کار نمی‌کند. ادامه بدهم؟",
 "A new signing key is only needed if the server was compromised. Apps learn the new key when they refresh their subscription, so do it while the internet still works.":"کلید امضای جدید فقط وقتی لازم است که سرور لو رفته باشد. اپ‌ها کلید جدید را با به‌روز شدن اشتراک می‌گیرند، پس این کار را تا وقتی اینترنت وصل است انجام بده.",
 "A new version is available.":"نسخه جدید موجود است.",
 "A pasted certificate is used on every DNS server":"یک گواهی دستی روی همه‌ی سرورهای DNS استفاده می‌شود",
 "A plain TLS server with your own domain and certificate; the password lives inside the TLS handshake. Simple and mature, but the SNI is your own domain — a blocked domain kills it.":"سرور TLS ساده با دامنه و گواهی خودت؛ رمز داخل دست‌دادن TLS است. ساده و بالغ، اما SNI همان دامنهٔ خودت است — با مسدودشدن دامنه می‌میرد.",
 "A port is 1-65535":"پورت باید بین ۱ تا ۶۵۵۳۵ باشد",
 "A release tag like v26.3.27":"یک تگ ریلیز مثل v26.3.27",
 "A rule still sends traffic to this outbound":"هنوز قانونی ترافیک را به این خروجی می‌فرستد",
 "A server cannot come twice on the route":"یک سرور نمی‌تواند دو بار در مسیر باشد",
 "A user cannot connect from more devices than his limit.":"کاربر نمی‌تواند با دستگاه‌های بیشتر از سقفش وصل شود.",
 "AI service":"سرویس هوش مصنوعی",
 "AI writer":"نویسنده‌ی هوش مصنوعی",
 "AI writer (Grok)":"نویسنده‌ی هوش مصنوعی (Groq / Grok)",
 "ALPN":"ALPN",
 "API address":"آدرس API",
 "API key":"کلید API",
 "API token":"توکن API",
 "API tokens":"توکن‌های API",
 "About us and how to write":"درباره‌ی ما و لحن نوشتن",
 "Abroad":"خارج",
 "Abroad servers":"سرورهای خارج",
 "Abroad · exit":"خارج · خروجی",
 "Accept PROXY protocol":"پذیرش PROXY protocol",
 "Accept card to card":"پرداخت کارت به کارت فعال باشد",
 "Accept crypto to my wallet":"دریافت ارز به کیف پول خودم",
 "Accepting":"پذیرش فعال",
 "Active":"فعال",
 "Active sessions":"نشست‌های فعال",
 "Ad and tracker domains (geosite:category-ads-all)":"دامنه‌های تبلیغ و ردیاب (geosite:category-ads-all)",
 "AdGuard (no ads)":"AdGuard (بدون تبلیغ)",
 "Add":"افزودن",
 "Add 30 days":"افزودن ۳۰ روز",
 "Add DNS":"افزودن DNS",
 "Add DNS server":"افزودن سرور DNS",
 "Add Xray":"افزودن Xray",
 "Add a stop":"افزودن ایستگاه",
 "Add a tunnel server":"افزودن سرور تانل",
 "Add a tunnel server inside Iran first (Servers), or set its location to Inside Iran.":"اول یک سرور تانل داخل ایران اضافه کن (سرورها)، یا موقعیت سرورت را «داخل ایران» بگذار.",
 "Add an Iran server":"افزودن سرور ایران",
 "Add an Xray server first":"اول یک سرور Xray اضافه کن",
 "Add an abroad server":"افزودن سرور خارج",
 "Add an exit DNS server first":"اول یک سرور DNS خروجی اضافه کن",
 "Add at least one CDN edge address":"حداقل یک آی‌پی لبه CDN بنویس",
 "Add at least one port to carry":"حداقل یک پورت برای عبور اضافه کن",
 "Add by hand (advanced)":"افزودن دستی (پیشرفته)",
 "Add code":"افزودن کد",
 "Add fallback":"افزودن فال‌بک",
 "Add node":"افزودن نود",
 "Add or remove DNS servers in Servers":"افزودن و حذف سرور DNS در «سرورها»",
 "Add outbound":"افزودن خروجی",
 "Add plan":"افزودن پلن",
 "Add relay":"افزودن ریلی",
 "Add rule":"افزودن قانون",
 "Add server":"افزودن سرور",
 "Add these plans":"افزودن این پلن‌ها",
 "Add this node to ALL users?":"این نود به همه کاربران اضافه شود؟",
 "Add this server to all users":"افزودن این سرور به همه‌ی کاربران",
 "Add to all users":"افزودن به همه‌ی کاربران",
 "Add to extra domains":"افزودن به دامنه‌های اضافه",
 "Add your entry server (for example in Iran), then make a tunnel to the panel server or another server.":"اول سرور ورودی (مثلاً سرور ایران) را اضافه کن، بعد یک تانل به سرور پنل یا سرور دیگری بساز.",
 "Address":"آدرس",
 "Address for links":"آدرس در لینک‌ها",
 "Address other servers use to reach it":"آدرسی که سرورهای دیگر با آن وصل می‌شوند",
 "Address other servers use to reach it (optional)":"آدرسی که سرورهای دیگر با آن به این سرور وصل می‌شوند (اختیاری)",
 "Address the app dials":"آدرسی که اپ وصل می‌شود",
 "Address to dial (empty = the server’s address)":"آدرس اتصال (خالی = آدرس خود سرور)",
 "Addresses":"آدرس‌ها",
 "Addresses each user registered (allowed now) and their queries since the DNS services started":"IPهایی که هر کاربر ثبت کرده (الان مجاز) و درخواست‌هایش از شروع سرویس DNS",
 "Admin changes with actor, path, IP and result":"تغییرات مدیریتی با Actor، مسیر، IP و نتیجه",
 "Admin chat address (open it from inside Iran)":"آدرس چت ادمین (از داخل ایران باز کن)",
 "Admin numeric ID(s), comma separated":"آیدی عددی ادمین(ها)، با کاما جدا کن",
 "Admin numeric IDs (comma separated)":"آیدی عددی ادمین‌ها (با کاما)",
 "Admin password of the chat":"رمز ادمین چت",
 "Admins":"ادمین‌ها",
 "Advanced":"پیشرفته",
 "Advanced (hardest to block)":"پیشرفته (سخت‌ترین برای بستن)",
 "Advanced anti-DPI tunnels":"تانل‌های پیشرفته ضد DPI",
 "Advanced settings":"تنظیمات پیشرفته",
 "Advanced: extra outbounds (JSON array, the first one becomes the default)":"پیشرفته: اوت‌باندهای اضافه (آرایه‌ی JSON، اولی پیش‌فرض می‌شود)",
 "Advanced: extra routing rules (JSON array)":"پیشرفته: قوانین مسیریابی اضافه (آرایه‌ی JSON)",
 "Advanced: raw JSON":"پیشرفته: JSON خام",
 "After a failure the server waits (10 minutes, then longer) before it tries again; after fixing the cause press «Try SSL again».":"بعد از هر خطا سرور صبر می‌کند (۱۰ دقیقه، بعد بیشتر) و بعد دوباره امتحان می‌کند؛ بعد از رفع مشکل «دوباره گرفتن SSL» را بزن.",
 "After restore":"بعد از بازگردانی",
 "After this long without the user's app registering again, the address is closed":"اگر تا این مدت اپ کاربر دوباره ثبت نکند، IP بسته می‌شود",
 "Agent is on an older version":"Agent نسخه‌ی قدیمی‌تری دارد",
 "Agent server":"سرور (ایجنت)",
 "All":"همه",
 "All VPN services":"همه‌ی سرویس‌های VPN",
 "All cores at a glance":"همه‌ی هسته‌ها در یک نگاه",
 "All off":"همه خاموش",
 "All on":"همه روشن",
 "All protocols":"همه پروتکل‌ها",
 "All queries":"همه‌ی درخواست‌ها",
 "All servers":"همه‌ی سرورها",
 "All servers connected":"همه سرورها وصل‌اند",
 "All services":"همه سرویس‌ها",
 "All traffic from these networks goes through the link":"کل ترافیکِ این شبکه‌ها (مبدأ) از لینک می‌رود",
 "All tunnels connected":"همه‌ی تانل‌ها وصل‌اند",
 "All users":"همه‌ی کاربران",
 "Allow/Deny for the admin panel, one IP or CIDR per line":"Allow/Deny برای پنل مدیریت؛ هر خط یک IP یا CIDR",
 "Allowed addresses":"IPهای مجاز",
 "Already used by":"قبلاً استفاده شده توسط",
 "Also restore server keys & configs (same/new server migration)":"کلیدها و کانفیگ‌های سرور هم برگردد (انتقال سرور)",
 "Also updates and anti-cheat. Use it when the game still stops at login or the update does not download.":"آپدیت و ضدتقلب هم. وقتی بازی هنوز روی ورود می‌ماند یا آپدیت دانلود نمی‌شود.",
 "Also use this node as a tunnel server":"تانل هم روی این سرور ساخته شود",
 "Also used by the sales bot when it makes an account.":"ربات فروش هم هنگام ساخت اکانت از همین‌ها استفاده می‌کند.",
 "Alternative fronting when WS is throttled; also good for many parallel streams.":"جایگزین فرانتینگ وقتی WS محدود می‌شود؛ برای استریم‌های موازی زیاد هم خوب است.",
 "AmneziaWG":"AmneziaWG",
 "AmneziaWG UDP port":"پورت UDP آمنزیا",
 "AmneziaWG compatibility mode":"حالت سازگاری AmneziaWG",
 "AmneziaWG compatibility mode (only Jc/Jmin/Jmax/S1/S2/H1-H4)":"حالت سازگاری AmneziaWG (فقط Jc/Jmin/Jmax/S1/S2/H1-H4)",
 "An address is written but «Accept crypto to my wallet» is off: buyers will not see it.":"آدرس نوشته شده ولی «دریافت ارز به کیف پول خودم» خاموش است: خریدارها آن را نمی‌بینند.",
 "An allowed address stays open for (hours)":"مدت باز ماندن IP ثبت‌شده (ساعت)",
 "An encrypted full backup is sent to the bot admins once a day.":"روزی یک بار بکاپ کامل رمزدار برای ادمین‌های ربات فرستاده می‌شود.",
 "Another address":"آدرس دیگر",
 "Another one":"یکی دیگر",
 "Another program uses this bot token (an old panel still running?). Stop it, or make a new token in @BotFather.":"یک برنامه‌ی دیگر هم از توکن این ربات استفاده می‌کند (پنل قبلی هنوز روشن است؟). آن را خاموش کن یا در @BotFather توکن جدید بساز.",
 "Another server (from its link)":"سرور دیگر (از لینکش)",
 "Another test is running; it starts when that one ends":"یک تست دیگر در جریان است؛ بعد از تمام شدن آن شروع می‌شود",
 "Answer IP":"IP پاسخ",
 "Anti-DPI":"ضد DPI",
 "Anti-DPI tunnels":"تانل‌های ضد DPI",
 "Any":"همه",
 "App download link":"لینک دانلود اپ",
 "App files":"فایل‌های اپ",
 "App link":"لینک اپ",
 "App message":"پیام اپ",
 "Appearance":"ظاهر و برند",
 "Appearance, web access and public endpoint":"ظاهر، دسترسی وب و Endpoint عمومی",
 "Applied on the server at once: config, service and firewall. Old WireGuard/AmneziaWG files stop working; subscription links update by themselves.":"روی خود سرور همان لحظه اعمال می‌شود: کانفیگ، سرویس و فایروال. فایل‌های قدیمی وایرگارد/آمنزیا کار نمی‌کنند؛ لینک اشتراک خودش به‌روز می‌شود.",
 "Apply":"اعمال",
 "Apply ports":"اعمال پورت‌ها",
 "Apply this endpoint to Main and all nodes":"این Endpoint برای Main و همه Nodeها اعمال شود",
 "Apply to the tunnel":"اعمال روی تانل",
 "Applying…":"در حال اعمال…",
 "Are you sure?":"مطمئنی؟",
 "ArvanCloud shows HTTPS to the users with its own certificate and talks to the server on the port above with HTTP. In ArvanCloud set the origin port to this port.":"ابرآروان با گواهی خودش HTTPS را به کاربر نشان می‌دهد و با HTTP روی پورت بالا با سرور حرف می‌زند. در ابرآروان پورت مبدأ را همین پورت بگذار.",
 "Audit log":"Audit Log",
 "Authority (in the link)":"Authority (در لینک)",
 "Auto after /start (or first bot admin)":"خودکار بعد از /start (یا اولین ادمین ربات)",
 "Auto refresh":"تازه‌سازی",
 "Automatic (Let's Encrypt)":"خودکار (Let's Encrypt)",
 "Automatic (from the key)":"خودکار (از روی کلید)",
 "Automatic SSL (Let’s Encrypt, recommended)":"SSL خودکار (Let’s Encrypt، پیشنهادی)",
 "Automatic certificates":"گواهی خودکار",
 "Automatic discount on occasions (Nowruz, Yalda…)":"تخفیف خودکار در مناسبت‌ها (نوروز، یلدا…)",
 "Automatic update":"آپدیت خودکار",
 "Automatic update is off":"آپدیت خودکار خاموش شد",
 "Automatic update is on":"آپدیت خودکار روشن شد",
 "Automatic: certbot on each DNS server":"خودکار: certbot روی هر سرور DNS",
 "Backup":"بکاپ",
 "Backup file":"بکاپ",
 "Backup interval (hours)":"فاصله بکاپ (ساعت)",
 "Balanced":"متعادل",
 "Base domain for the direct names (like example.com); empty = the panel domain without its first part":"دامنه‌ی اصلی اسم‌های مستقیم (مثل example.com)؛ خالی = دامنه‌ی پنل بدون بخش اولش",
 "Base of the subscription links (for example a CDN domain). Empty = the panel address.":"ابتدای لینک‌های اشتراک (مثلاً دامنه‌ی CDN). خالی = آدرس پنل.",
 "Base price per month":"قیمت پایه هر ماه",
 "Basic":"اصلی",
 "Before and after":"قبل و بعد",
 "Before making the tunnel, every transport (TCP, KCP, WS, WSS, QUIC) is tried in both directions between your two servers. It takes about one to two minutes. Each gets a score from 0 to 100 and the best one is suggested with its reason.":"قبل از ساختن تانل، همهٔ ترنسپورت‌ها (TCP، KCP، WS، WSS، QUIC) در هر دو جهت بین دو سرور امتحان می‌شوند. حدود یک تا دو دقیقه طول می‌کشد. به هر کدام نمرهٔ ۰ تا ۱۰۰ داده می‌شود و بهترین با دلیلش پیشنهاد می‌شود.",
 "Best":"بهترین",
 "Best for UDP (WireGuard / Hysteria2)":"بهترین برای UDP (وایرگارد / هیستریا)",
 "Best for this route":"بهترین برای این مسیر",
 "Big plan discount %":"تخفیف پلن بزرگ ٪",
 "Bind and port are where the panel itself listens; changing them needs a panel restart (edit /etc/kanki/kanki.env).":"Bind و Port فقط آدرس گوش‌دادن خود پنل هستند؛ تغییرشان نیاز به ری‌استارت پنل دارد (فایل /etc/kanki/kanki.env).",
 "Bind and port are where the panel itself listens; changing them needs a panel restart. File:":"Bind و Port فقط آدرس گوش‌دادن خود پنل هستند؛ تغییرشان نیاز به ری‌استارت پنل دارد. فایل:",
 "Block":"مسدود",
 "Block (blackhole)":"مسدود (blackhole)",
 "Block BitTorrent":"مسدود کردن تورنت",
 "Block Iranian sites":"مسدود کردن سایت‌های ایرانی",
 "Block ads":"مسدود کردن تبلیغات",
 "Block private addresses":"مسدود کردن IPهای داخلی",
 "Blocked sites only":"فقط سایت‌های تحریم‌شده",
 "Bot admins":"ادمین‌های ربات",
 "Bot token":"توکن ربات",
 "Bot token (from @BotFather)":"توکن ربات (از ‎@BotFather)",
 "Both a node and a tunnel server (updated once, through the node)":"سرور (یک‌بار آپدیت می‌شود)",
 "Both kinds of VPN your users get, side by side":"هر دو نوع VPN که کاربرها می‌گیرند، کنار هم",
 "Build and manage the sales bot":"ساخت و مدیریت ربات فروش",
 "Build the tunnel with":"ساخت تانل با",
 "Build with":"ساخت با",
 "Bulk actions":"عملیات گروهی",
 "Busiest services":"پرمصرف‌ترین سرویس‌ها",
 "Buyers type the code in the bot. Used-up and expired codes are removed by themselves.":"خریدار کد را در ربات وارد می‌کند. کدهای تمام‌شده و منقضی خودکار پاک می‌شوند.",
 "By node":"بر اساس نود",
 "By protocol":"بر اساس پروتکل",
 "CDN edge addresses (IPs, comma separated)":"آدرس‌های لبه CDN (آی‌پی‌ها، با ویرگول جدا کن)",
 "CDN points to the Iran server: the foreign server connects in (recommended)":"CDN به سرور ایران اشاره می‌کند: سرور خارج وصل می‌شود (پیشنهادی)",
 "CDN points to the foreign server: the Iran server connects out":"CDN به سرور خارج اشاره می‌کند: سرور ایران وصل می‌شود",
 "CPU":"CPU",
 "CPU is busy":"CPU شلوغ است",
 "CPU is full":"CPU پر است",
 "Cancel":"انصراف",
 "Cancel the command":"لغو دستور",
 "Cannot read this image":"این تصویر خوانده نمی‌شود",
 "Card holder":"نام صاحب کارت",
 "Card holder name":"نام صاحب کارت",
 "Card number":"شماره کارت",
 "Card to card":"کارت به کارت",
 "Category":"دسته‌بندی",
 "Category name":"نام دسته‌بندی",
 "Certificate":"گواهی",
 "Certificate (PEM, full chain)":"گواهی (PEM، زنجیره‌ی کامل)",
 "Certificate and records":"گواهی SSL و رکوردها",
 "Certificate changed":"گواهی عوض شده",
 "Certificate error":"خطای گواهی",
 "Certificate file":"فایل گواهی",
 "Change":"تغییر",
 "Change login":"تغییر نام کاربری / رمز",
 "Change the base domain":"تغییر دامنه‌ی اصلی",
 "Changes reach the servers within a few seconds of saving":"تغییرات چند ثانیه بعد از ذخیره به سرورها می‌رسد",
 "Channel":"کانال",
 "Chat ID":"Chat ID",
 "Check":"بررسی",
 "Check a domain":"بررسی یک دامنه",
 "Check for update":"بررسی آپدیت",
 "Check now":"بررسی الان",
 "Checked from top to bottom; the first rule that matches decides":"از بالا به پایین چک می‌شوند؛ اولین قانونی که بخورد تصمیم می‌گیرد",
 "Checking…":"در حال بررسی…",
 "Choose a server inside Iran (one of your tunnel servers) and a domain that points to it (ArvanCloud CDN or plain DNS).":"یک سرور داخل ایران (یکی از سرورهای تانل) و دامنه‌ای که به آن اشاره می‌کند (CDN ابرآروان یا DNS معمولی) را انتخاب کن.",
 "Choose at least one protocol":"حداقل یک پروتکل انتخاب کن",
 "Choose file":"انتخاب فایل",
 "Choose image":"انتخاب تصویر",
 "Choose the .apk file(s) first":"اول فایل(های) .apk را انتخاب کن",
 "Classic (Jc, S1, S2, H1-H4)":"کلاسیک (Jc، S1، S2، H1-H4)",
 "Clean database":"تمیز کردن دیتابیس",
 "Clean now":"تمیز کن",
 "Clear":"پاک کردن",
 "Clear selection":"لغو انتخاب",
 "Clear the whole query log?":"کل لاگ درخواست‌ها پاک شود؟",
 "Clients":"کلاینت‌ها",
 "Clients online":"کلاینت آنلاین",
 "Close":"بستن",
 "Close the AmneziaWG port to the outside":"بستن پورت AmneziaWG به روی بیرون",
 "Close these ports":"بستن این پورت‌ها",
 "Close these ports in the firewall of this server?":"این پورت‌ها در فایروال این سرور بسته شوند؟",
 "Closed":"بسته شد",
 "Code":"کد",
 "Coins":"ارزها",
 "Coming next":"به‌زودی",
 "Command":"دستور",
 "Command for":"دستور برای",
 "Config":"کانفیگ",
 "Config mismatch":"اختلاف کانفیگ",
 "Configs":"کانفیگ‌ها",
 "Confirm":"تأیید",
 "Congestion control":"کنترل ازدحام",
 "Connected":"وصل",
 "Connected now":"وصل الان",
 "Connecting…":"در حال اتصال…",
 "Connection endpoint (empty = panel endpoint)":"آدرس اتصال (خالی = Endpoint پنل)",
 "Connections":"اتصال‌ها",
 "Copied":"کپی شد",
 "Copies of each game packet":"تعداد نسخه‌ی هر بسته‌ی بازی",
 "Copy":"کپی",
 "Copy command":"کپی دستور",
 "Copy it now, it won't be shown again":"همین حالا کپی کن، دوباره نمایش داده نمی‌شود",
 "Copy link":"کپی لینک",
 "Copy the Private DNS address":"کپی آدرس Private DNS",
 "Copy the command":"کپی دستور",
 "Cores":"هسته‌ها",
 "Could not make hop":"مرحله ساخته نشد",
 "Count":"تعداد",
 "Countries (0 = all)":"کشورها (۰ = همه)",
 "Country not known yet":"کشور هنوز معلوم نیست",
 "Create":"ساخت",
 "Create API token":"ساخت توکن API",
 "Create and manage the sales bot":"ساخت و مدیریت ربات فروش",
 "Create bot":"ساخت ربات",
 "Create command":"ساخت دستور",
 "Create join command":"ساخت دستور اتصال",
 "Create the first user":"ساخت اولین کاربر",
 "Created":"ساخته‌شده",
 "Created configs":"کانفیگ‌های ساخته‌شده",
 "Credit & limits":"اعتبار و محدودیت",
 "Crypto (NOWPayments)":"ارزی (NOWPayments)",
 "Crypto payment (TON / USDT)":"پرداخت ارزی (TON / USDT)",
 "Current account":"حساب فعلی",
 "Current password":"رمز فعلی",
 "Current version":"نسخه فعلی",
 "Custom":"دلخواه",
 "Custom IP / domain for this node":"IP / دامنه اختصاصی این نود",
 "Custom inbound":"اینباند سفارشی",
 "Customers":"مشتری‌ها",
 "Customers known to the chat":"مشتری‌های شناخته‌شده در چت",
 "DNS":"DNS",
 "DNS abroad":"DNS خارجی",
 "DNS domain":"دامنه‌ی DNS",
 "DNS exit":"خروجی DNS",
 "DNS exit node":"نود DNS خروجی",
 "DNS is off: nothing runs on the servers.":"DNS خاموش است: روی سرورها چیزی اجرا نمی‌شود.",
 "DNS is on":"DNS روشن است",
 "DNS only":"فقط DNS",
 "DNS provider":"سرویس DNS",
 "DNS relay":"واسط DNS",
 "DNS relay node":"نود ریلی DNS",
 "DNS servers":"سرورهای DNS",
 "DNS servers given to every user config, comma separated.":"DNSهایی که داخل کانفیگ کاربرها قرار می‌گیرند؛ با کاما جدا کن.",
 "DNS users":"کاربران DNS",
 "DNS, MTU and protocol behaviour on every server":"DNS، MTU و رفتار پروتکل‌ها روی همه‌ی سرورها",
 "Daily backup to bot admins":"بکاپ روزانه برای ادمین‌های ربات",
 "Dark":"تیره",
 "Dashboard":"داشبورد",
 "Data":"حجم",
 "Data center DNS":"DNS دیتاسنتر",
 "Database size":"حجم دیتابیس",
 "Date":"تاریخ",
 "Date (Jalali)":"تاریخ شمسی",
 "Day":"روز",
 "Days":"روز",
 "Days to add":"روز اضافه",
 "Debug":"دیباگ",
 "Default":"پیش‌فرض",
 "Default UDP port":"پورت UDP پیش‌فرض",
 "Default backup passphrase":"رمز پیش‌فرض بکاپ",
 "Default choice for everyday filtering. Very fast (xtls-rprx-vision has no inner encryption cost).":"انتخاب پیش‌فرض برای فیلترینگ روزمره. خیلی سریع (xtls-rprx-vision هزینهٔ رمزنگاری داخلی ندارد).",
 "Default outbound (what no rule catches)":"خروجی پیش‌فرض (هر چه قانونی نگیرد)",
 "Default port":"پورت پیش‌فرض",
 "Default protocols for new users":"پروتکل‌های پیش‌فرض کاربر جدید",
 "Delete":"حذف",
 "Delete bot":"حذف ربات",
 "Delete node":"حذف نود",
 "Delete selected users?":"کاربران انتخاب‌شده حذف شوند؟",
 "Delete server":"حذف سرور",
 "Delete the whole route? Every hop stops and its ports are closed.":"کل مسیر حذف شود؟ همه‌ی مرحله‌ها خاموش می‌شوند و پورت‌هایشان بسته می‌شود.",
 "Delete them too? The other server drops them and closes their ports.":"آن‌ها هم حذف شوند؟ سرور طرف دیگر هم آن‌ها را برمی‌دارد و پورت‌هایشان را می‌بندد.",
 "Delete this server? Its users are cut off and the server itself removes WireGuard, AmneziaWG, Hysteria2 and KANKI MIX, closes their ports and uninstalls the node agent.":"این سرور حذف شود؟ کاربرهایش قطع می‌شوند و خود سرور WireGuard، AmneziaWG، Hysteria2 و KANKI MIX را برمی‌دارد، پورت‌هایشان را می‌بندد و ایجنت نود را پاک می‌کند.",
 "Delete this tunnel? It stops on both servers and its ports are closed in their firewalls.":"این تانل حذف شود؟ روی هر دو سرور خاموش می‌شود و پورت‌هایش در فایروال هر دو بسته می‌شود.",
 "Delete this whole server? Everything Kanki installed on it (VPN, tunnels, Xray, DNS) is removed from the server and from the panel, and the server uninstalls itself.":"کل این سرور حذف شود؟ هرچه کانکی رویش نصب کرده (VPN، تانل، Xray، DNS) از روی سرور و از پنل پاک می‌شود و سرور خودش را حذف می‌کند.",
 "Delete this whole server? Its tunnels must be deleted first. The server removes everything Kanki installed on it (VPN, tunnels, Xray, DNS) and uninstalls itself.":"کل این سرور حذف شود؟ اول تانل‌هایش را حذف کن. سرور هرچه کانکی رویش نصب کرده (VPN، تانل، Xray، DNS) را پاک می‌کند و خودش را حذف می‌کند.",
 "Deleted from the panel. The server did not answer (or runs an old version): its VPN services stay until you uninstall them there.":"از پنل حذف شد. سرور جواب نداد (یا نسخه‌اش قدیمی است): سرویس‌های VPN رویش می‌مانند تا خودت آن‌جا پاکشان کنی.",
 "Destination (port or address:port)":"مقصد (پورت یا آدرس:پورت)",
 "Destination networks sent through the link":"شبکه‌های مقصدی که از لینک می‌روند",
 "Details":"جزئیات",
 "Details & settings":"جزئیات و تنظیمات",
 "Devices and IPs logged in to the panel":"دستگاه‌ها و IPهایی که به پنل وارد شده‌اند",
 "Direct":"مستقیم",
 "Direct (freedom)":"مستقیم (freedom)",
 "Direct (the server's own address)":"مستقیم (آدرس خود سرور)",
 "Direct domains":"دامنه‌های مستقیم",
 "Direct name":"اسم مستقیم",
 "Direct only":"فقط مستقیم",
 "Direct: the app connects straight to the foreign server, lowest ping. Tunnel: the app connects to the Iran server; the tunnel to this server must forward this UDP port.":"مستقیم: اپ مستقیم به سرور خارج وصل می‌شود، کمترین پینگ. تانل: اپ به سرور ایران وصل می‌شود؛ تانل این سرور باید همین پورت UDP را فوروارد کند.",
 "Direction":"جهت",
 "Disable":"غیرفعال‌سازی",
 "Disable 2FA":"غیرفعال‌سازی",
 "Disable for all users":"خاموش برای همه‌ی کاربران",
 "Disabled":"غیرفعال",
 "Disconnected":"قطع",
 "Discount campaign":"کمپین تخفیف",
 "Discount code prefix":"پیشوند کد تخفیف",
 "Discount codes":"کدهای تخفیف",
 "Disguise":"پوشش",
 "Disk":"دیسک",
 "Disk is almost full":"دیسک تقریباً پر است",
 "Disk is getting full":"دیسک دارد پر می‌شود",
 "Do not read the content, only the connection details":"محتوا خوانده نشود، فقط مشخصات اتصال",
 "Does this site go through Kanki DNS, and which service lists it?":"این سایت از DNS کانکی رد می‌شود؟ در کدام سرویس است؟",
 "Dollar price (crypto)":"قیمت دلاری (پرداخت ارزی)",
 "Domain":"دامنه",
 "Domain (optional, for a real SSL certificate)":"دامنه (اختیاری، برای SSL واقعی)",
 "Domain of this DNS server":"دامنه‌ی این سرور DNS",
 "Domain of this server (or IP)":"دامنه‌ی این سرور (یا IP)",
 "Domain strategy":"روش دامنه (Domain strategy)",
 "Domain, certificate, upstreams":"دامنه، گواهی، DNS بالادست",
 "Domains (one per line)":"دامنه‌ها (هر خط یکی)",
 "Done":"انجام شد",
 "Done: everything was removed from the server too":"انجام شد: همه چیز از روی خود سرور هم پاک شد",
 "Done: servers forget them within a few seconds":"انجام شد: سرورها تا چند ثانیه‌ی دیگر فراموششان می‌کنند",
 "Downlink (MB/s)":"دانلود (مگابایت/ثانیه)",
 "Download":"دانلود",
 "Download and upload, every 2 seconds":"دانلود و آپلود، هر ۲ ثانیه",
 "Download backup":"دانلود بکاپ",
 "Download config":"دانلود کانفیگ",
 "Download configs":"دانلود کانفیگ‌ها",
 "Download settings":"دانلود تنظیمات",
 "Download speed of the entry, Mbit/s (0 = automatic)":"سرعت دانلود ورودی، مگابیت (۰ = خودکار)",
 "Drain":"Drain",
 "Draining":"در حال تخلیه",
 "Dropped":"دور ریخته می‌شود",
 "Durations (days)":"مدت‌ها (روز)",
 "E-mail for Let's Encrypt (optional)":"ایمیل برای Let's Encrypt (اختیاری)",
 "Each DNS server gets a name under it, like de.dns.example.com":"هر سرور DNS یک اسم زیر آن می‌گیرد، مثل de.dns.example.com",
 "Each extra connection / month":"هر اتصال اضافه / ماه",
 "Each extra country / month":"هر کشور اضافه / ماه",
 "Each game packet is sent twice: at 20% loss 92% arrive instead of 64%. Users can switch it off in the app.":"هر بسته‌ی بازی دو بار فرستاده می‌شود: با ۲۰٪ لاس، ۹۲٪ می‌رسد به جای ۶۴٪. کاربر در اپ می‌تواند خاموشش کند.",
 "Each query":"تک‌تک درخواست‌ها",
 "Each server gets a Let's Encrypt certificate for its own name and renews it by itself":"هر سرور برای اسم خودش از Let's Encrypt گواهی می‌گیرد و خودش تمدید می‌کند",
 "Each user has their own key (made from the subscription code): resetting the link gives a new key, disabling or expiring cuts the user off at once. Traffic and devices count like the other protocols.":"هر کاربر کلید خودش را دارد (از کد اشتراک ساخته می‌شود): ریست لینک کلید تازه می‌دهد، غیرفعال یا منقضی شدن کاربر را فوراً قطع می‌کند. مصرف و دستگاه‌ها مثل بقیه‌ی پروتکل‌ها شمرده می‌شوند.",
 "Easy setup: choose above which server the CDN points to, type your domain here and the tunnel port below. The panel does the rest.":"راه‌اندازی ساده: بالا انتخاب کن CDN به کدام سرور اشاره دارد، دامنه را همین‌جا و پورت تانل را پایین بنویس. بقیه را پنل انجام می‌دهد.",
 "Edit":"ویرایش",
 "Edit bot":"ویرایش ربات",
 "Edit hop":"ویرایش مرحله",
 "Edit node":"ویرایش نود",
 "Edit outbound":"ویرایش خروجی",
 "Edit rule":"ویرایش قانون",
 "Edit server":"ویرایش سرور",
 "Edit tunnel":"ویرایش تانل",
 "Edit user":"ویرایش کاربر",
 "Emerald":"زمردی",
 "Emergency chat":"چت اضطراری",
 "Emergency chat is on":"چت اضطراری روشن است",
 "Empty = automatic":"خالی = خودکار",
 "Empty = every N hours as above. Three times a day: 10:00, 16:00, 21:30":"خالی = هر چند ساعت یک‌بار (بالا). سه بار در روز: ۱۰:۰۰، ۱۶:۰۰، ۲۱:۳۰",
 "Empty = keep the current token":"خالی = همان توکن فعلی بماند",
 "Empty = label + DNS domain. Point the domain to this server: its SSL is taken on the server with certbot by itself.":"خالی = برچسب + دامنه‌ی DNS. دامنه را به همین سرور وصل کن: SSL آن را certbot روی خود سرور می‌گیرد.",
 "Empty = label + DNS domain. The panel points it (and *.) at this server and gets the SSL for it by itself.":"خالی = برچسب + دامنه‌ی DNS. پنل آن را (و *.) به همین سرور وصل می‌کند و SSLش را خودش می‌گیرد.",
 "Empty = panel backup passphrase":"خالی = رمز بکاپ پنل",
 "Empty = the IP it connects from":"خالی = همان آی‌پی که از آن وصل می‌شود",
 "Empty = use the sales bot token":"خالی = همان توکن ربات فروش",
 "Empty SNI = the server's domain and certificate":"SNI خالی = دامنه و گواهی خود سرور",
 "Empty model = the best one of that service; a refused model is replaced by another one of your account.":"مدل خالی = بهترین مدل همان سرویس؛ اگر مدلی قبول نشود، مدل دیگری از حساب خودت امتحان می‌شود.",
 "Enable":"فعال‌سازی",
 "Enable 2FA":"فعال‌سازی 2FA",
 "Enable for all users":"روشن برای همه‌ی کاربران",
 "Enable sales bot features":"قابلیت‌های فروش",
 "Encrypted TCP":"TCP رمزنگاری‌شده",
 "Encrypted archive. File name includes date and time.":"آرشیو کامل و رمزنگاری‌شده. نام فایل شامل تاریخ و ساعت است.",
 "Encrypted backup sent to Telegram on schedule":"بکاپ رمزنگاری‌شده را طبق زمان‌بندی به تلگرام بفرست",
 "Encrypted tunnels between your servers: users connect to the entry, traffic leaves from the exit":"تانل رمزنگاری‌شده بین سرورها: کاربر به سرور ورودی وصل می‌شود و ترافیک از سرور خروجی بیرون می‌رود",
 "Enforce 2FA for admin":"اجبار 2FA برای ادمین",
 "Enforce connection limit (Hysteria2)":"اعمال محدودیت اتصال (Hysteria2)",
 "English letters and digits, 3-12, starting with a letter (like mahtab87). No spaces, emoji or symbols.":"فقط حروف انگلیسی و عدد، ۳ تا ۱۲ حرف و اولش حرف (مثل mahtab87). فاصله، ایموجی و علامت ننویس.",
 "Enter days or GB":"روز یا گیگ را وارد کن",
 "Entry":"ورودی",
 "Entry (users connect here)":"ورودی (کاربرها به این وصل می‌شوند)",
 "Entry public TCP ports sent into the link":"پورت‌های TCP عمومی ورودی که به لینک می‌روند",
 "Entry public UDP ports sent into the link":"پورت‌های UDP عمومی ورودی که به لینک می‌روند",
 "Entry → exit (direct)":"ورودی ← به خروجی وصل شود (مستقیم)",
 "Errors":"خطا",
 "Every UDP packet is masked with a key made from the token, so no KCP signature shows; sizes and timing look random. FEC repairs losses without a retransmit.":"هر بستهٔ UDP با کلید ساخته‌شده از توکن ماسک می‌شود؛ امضای KCP دیده نمی‌شود و اندازه‌ها و زمان‌بندی تصادفی به نظر می‌رسد. FEC لاست‌ها را بدون ارسال مجدد ترمیم می‌کند.",
 "Every UDP packet is masked with a key made from the token: no QUIC signature, random sizes. Unmasked packets get no answer. The QUIC hello carries a site name (default www.cloudflare.com).":"هر بستهٔ UDP با کلیدی که از توکن ساخته می‌شود ماسک می‌شود: بدون امضای QUIC و با اندازه‌های تصادفی. بسته‌ای که ماسک درست نداشته باشد هیچ پاسخی نمی‌گیرد. هلوی QUIC یک نام سایت دارد (پیش‌فرض www.cloudflare.com).",
 "Every name of a ticked part and all its subdomains go through your server.":"همه‌ی نام‌های بخش تیک‌خورده و همه‌ی زیردامنه‌هایشان از سرور تو رد می‌شوند.",
 "Every name your subscribers asked, and whether it went through your server (routed) or straight to the site (direct). Kept in the panel's memory; a restart clears it.":"همه‌ی دامنه‌هایی که مشتری‌ها پرسیده‌اند و اینکه از سرور شما رد شده (مسیردهی‌شده) یا مستقیم به سایت رفته (مستقیم). در حافظه‌ی پنل نگه داشته می‌شود و با ری‌استارت پاک می‌شود.",
 "Every night at":"هر شب ساعت",
 "Every night at 03:30 Tehran time, if GitHub has a new version: the panel, the nodes, the tunnel servers and the emergency chat are updated by themselves.":"هر شب ساعت ۳:۳۰ به وقت تهران، اگر نسخه‌ی جدیدی در گیت‌هاب باشد: پنل، نودها، سرورهای تانل و چت اضطراری خودکار آپدیت می‌شوند.",
 "Every night the database is cleaned and an encrypted backup is sent to Telegram":"هر شب دیتابیس تمیز می‌شود و بکاپ رمزنگاری‌شده به تلگرام فرستاده می‌شود",
 "Every server and what runs on it":"همه‌ی سرورها و سرویس‌هایی که رویشان است",
 "Every server is connected":"همه‌ی سرورها وصل‌اند",
 "Every server of the panel: Kanki VPN, Xray and Kanki DNS":"همه‌ی سرورهای پنل: VPN کانکی، Xray و DNS کانکی",
 "Every server uses it unless it has its own port below.":"همه‌ی سرورها همین را دارند، مگر سروری که پایین پورت خودش را دارد.",
 "Every … hours":"هر چند ساعت",
 "Everything":"همه",
 "Everything about how the panel looks and works, in one place":"همه‌ی تنظیمات ظاهر و کارکرد پنل، یک‌جا",
 "Everything is already up to date":"همه‌چیز آپدیت است",
 "Everything is installed on the server (VPN, tunnels, Xray, Kanki DNS) with one command. Off = installed, but no user is sent there (an Iran relay).":"همه‌چیز با یک دستور روی سرور نصب می‌شود (VPN، تانل، Xray، DNS کانکی). خاموش = نصب می‌شود ولی هیچ کاربری به آن فرستاده نمی‌شود (رله‌ی ایران).",
 "Everything moves: users, servers, tunnels, DNS, Xray, bot and plans, the panel settings, the keys of this server's WireGuard / AmneziaWG / Hysteria2 (users' configs keep working), the certificate and the app files.":"همه‌چیز منتقل می‌شود: کاربرها، سرورها، تانل‌ها، DNS، Xray، ربات و پلن‌ها، تنظیمات پنل، کلیدهای WireGuard / AmneziaWG / Hysteria2 همین سرور (کانفیگ کاربرها کار می‌کند)، گواهی و فایل‌های اپ.",
 "Exit":"خروجی",
 "Exit (abroad)":"خروجی (خارج)",
 "Exit (traffic leaves here)":"خروجی (ترافیک از اینجا بیرون می‌رود)",
 "Exit server (abroad)":"سرور خروجی (خارج)",
 "Exit through the tunnel":"سرور خارج از تانل",
 "Exit → entry (reverse, recommended)":"خروجی ← به ورودی وصل شود (معکوس، پیشنهادی)",
 "Exits abroad and relays in Iran":"خروجی‌های خارج و ریلی‌های ایران",
 "Expired":"منقضی",
 "Expired / out of data":"منقضی / اتمام حجم",
 "Expires":"انقضا",
 "Expiry":"انقضا",
 "Expiry date":"تاریخ انقضا",
 "Expiry warnings":"هشدار اتمام",
 "Export":"خروجی",
 "Export & import":"خروجی و ورودی",
 "Extend":"تمدید",
 "Extra bytes that rebuild lost packets without asking again. Games do not use it (they have gaming mode).":"بایت اضافه که بسته‌ی گم‌شده را بدون درخواست دوباره می‌سازد. بازی‌ها از آن استفاده نمی‌کنند (حالت گیمینگ دارند).",
 "Extra disguise (optional)":"پوشش اضافه (اختیاری)",
 "Extra domains":"دامنه‌های اضافه",
 "Extra ports (port range)":"پورت‌های اضافه (بازه)",
 "Extra text for the buyer (optional)":"متن اضافه برای خریدار (اختیاری)",
 "FEC data:parity":"FEC داده:تکمیلی",
 "FEC for websites (TCP)":"FEC برای سایت‌ها (TCP)",
 "FEC of the stream (websites, game lobby)":"FEC جریان (سایت‌ها، لابی بازی)",
 "FEC sends extra repair packets so a lost packet is rebuilt at the other end instead of being waited for (about 40–100 ms saved per loss). 8:3 means 3 repair packets per 8 data packets (~37% more traffic). Duplication sends every packet twice: best ping, double the traffic. For WireGuard on top of this tunnel, FEC 8:3 is the sweet spot.":"FEC بسته‌های ترمیمی اضافه می‌فرستد تا بستهٔ گمشده به‌جای انتظار، در مقصد بازسازی شود (هر لاست حدود ۴۰ تا ۱۰۰ میلی‌ثانیه صرفه‌جویی). 8:3 یعنی به ازای هر ۸ بستهٔ داده ۳ بستهٔ ترمیمی (حدود ۳۷٪ ترافیک بیشتر). ارسال دوباره هر بسته را دو بار می‌فرستد: بهترین پینگ، دو برابر ترافیک. برای وایرگارد روی این تانل، FEC 8:3 نقطهٔ مطلوب است.",
 "Failed":"ناموفق",
 "Fallback when REALITY is not possible (old clients) and you have a clean domain.":"جایگزین وقتی REALITY ممکن نیست (کلاینت قدیمی) و دامنهٔ تمیز داری.",
 "Fallbacks":"فال‌بک",
 "Fast and steady, several links at once":"سریع و پایدار، چند اتصال هم‌زمان",
 "Fast and steady, several links at once (recommended)":"سریع و پایدار، چند اتصال هم‌زمان (پیشنهادی)",
 "Fast, for games and calls":"سریع، برای بازی و تماس",
 "Files on the server":"فایل روی سرور",
 "Filled in: check the Security tab":"پر شد: تب امنیت را چک کن",
 "Find the best transport":"پیدا کردن بهترین ترنسپورت",
 "Fingerprint":"اثرانگشت (fp)",
 "Finished":"تمام‌شده",
 "Firewall":"فایروال",
 "Firewall (ufw)":"فایروال (ufw)",
 "First add your entry server in the “Tunnel servers” menu.":"اول سرور ورودی را از منوی «سرورهای تانل» اضافه کن.",
 "First set the DNS provider and its API token in Xray › Settings.":"اول سرویس DNS و توکن API را در Xray › تنظیمات بگذار.",
 "Fix ports":"رفع تداخل پورت",
 "Flow":"Flow",
 "Fold the menu":"جمع کردن منو",
 "For":"برای",
 "For ISPs that block the panel domain: a tunnel server inside Iran serves the subscription pages with its own SSL and carries them to the panel through a hidden tunnel. Subscription links use it once it works.":"برای اینترنت‌هایی که دامنه‌ی پنل را بسته‌اند: یک سرور تانل داخل ایران صفحه‌های ساب را با SSL خودش می‌دهد و از راه یک تانل مخفی به پنل می‌رساند. وقتی کار کرد، لینک‌های ساب از آن ساخته می‌شوند.",
 "For SSL by itself, first set the DNS provider and API token (Xray › Settings or Kanki DNS › Settings and SSL).":"برای SSL خودکار، اول سرویس DNS و توکن API را بگذار (Xray › تنظیمات یا DNS کانکی › تنظیمات و SSL).",
 "For SSL by itself, set the DNS provider and API token in Settings and SSL.":"برای SSL خودکار، سرویس DNS و توکن API را در «تنظیمات و SSL» بگذار.",
 "For TLS inbounds with \"Automatic\": the panel sets the domain's A record and gets a Let's Encrypt certificate with a DNS challenge through this API. Empty = the same provider as Kanki DNS.":"برای اینباندهای TLS با حالت «خودکار»: پنل با این API رکورد A دامنه را می‌سازد و با چالش DNS از Let's Encrypt گواهی می‌گیرد. خالی = همان سرویس DNS کانکی.",
 "For example the subnet of the VPN users of the entry: their internet then leaves from the exit. SSH of the entry itself is never touched.":"مثلاً ساب‌نت کاربران VPN سرور ورودی: اینترنتشان از خروجی بیرون می‌رود. به SSH خود سرور ورودی دست زده نمی‌شود.",
 "For example the subnet of the WireGuard users of the entry: their whole internet goes through Hysteria2 and leaves from the exit. SSH and the entry itself are not touched. The ports below are another way: users connect to a port of the entry and land on the same port of the exit.":"مثلاً شبکهٔ کاربران وایرگارد سرور ورودی (10.8.0.0/24): کل اینترنتشان از داخل هیستریا رد می‌شود و از سرور خارج بیرون می‌رود. SSH و خود سرور ورودی دست نمی‌خورد. پورت‌های پایین راه دیگری است: کاربر به پورت سرور ورودی وصل می‌شود و به همان پورت روی سرور خروجی می‌رسد.",
 "For example your Iran server. Only the tunnel agent is installed on it.":"مثلاً سرور ایران. فقط عامل تانل روی آن نصب می‌شود.",
 "For games (PUBG…): KCP at its fastest with FEC, a lost packet is rebuilt without waiting. Game and websites ride one stream, like the tunnels; «Game optimization» below sends game packets apart. Nothing on the wire looks like a protocol.":"برای بازی (پابجی و …): KCP سریع با FEC؛ بسته‌ی گم‌شده بدون انتظار ساخته می‌شود. بازی و سایت‌ها مثل تانل‌ها در یک جریان می‌روند؛ «بهینه‌سازی بازی» پایین بسته‌های بازی را جدا می‌فرستد. روی سیم شبیه هیچ پروتکلی نیست.",
 "For repairs: the server keeps running but is not offered":"برای تعمیر: سرور روشن می‌ماند ولی به مشتری پیشنهاد نمی‌شود",
 "For servers whose IPv6 does not work well":"برای سرورهایی که IPv6 آن‌ها خوب کار نمی‌کند",
 "For strong filtering":"برای فیلترینگ شدید",
 "For the app: games and sanctioned sites":"برای اپ: بازی و سایت‌های تحریمی",
 "For when only domestic addresses open. Put your domain on a CDN that stays reachable (for example ArvanCloud) pointing at the exit server, turn WebSocket on, and set the origin to HTTP on the tunnel port below. The entry (inside) connects to the CDN, never to the exit directly.":"برای وقتی که فقط آدرس‌های داخلی باز می‌شوند. دامنه‌ات را روی یک CDN که در دسترس می‌ماند (مثلاً آروان‌کلود) بگذار و به سرور خروجی وصلش کن، WebSocket را روشن کن و مبدأ را روی HTTP و پورت تانل پایین بگذار. سرور ورودی (داخل ایران) همیشه به CDN وصل می‌شود، نه مستقیم به خروجی.",
 "Forget addresses":"پاک کردن IPها",
 "Forward to (empty = the exit inside the link)":"مقصد (خالی = خروجی داخل لینک)",
 "Free the ports":"آزاد کردن پورت‌ها",
 "Free trial":"تست رایگان",
 "Freeze user":"فریز کاربر",
 "From cache":"از کش",
 "From the file name (arm64 / armeabi-v7a …)":"از روی اسم فایل (arm64 / armeabi-v7a …)",
 "From the query log: a direct name that the game needs can be added here.":"از گزارش پرس‌وجوها: اگر نامی که بازی لازم دارد مستقیم رفته، از همین‌جا اضافه‌اش کن.",
 "Full backup of users, credentials, certificates, VPN settings, nodes and panel state":"بکاپ کامل کاربران، اعتبارنامه‌ها، گواهی‌ها، تنظیمات VPN، نودها و وضعیت پنل",
 "Fully random-looking encrypted traffic with no handshake at all (2022-blake3 methods). Nothing for DPI to fingerprint; carries UDP natively, so it is also a light cover for game/WireGuard UDP.":"ترافیک رمزنگاری‌شدهٔ کاملاً تصادفی به‌نظر بدون هیچ دست‌دادنی (متدهای 2022-blake3). چیزی برای اثرانگشت DPI ندارد؛ UDP را ذاتی حمل می‌کند، پس پوشش سبکی برای UDP گیم/وایرگارد هم هست.",
 "GB to add":"گیگ اضافه",
 "GRE link":"لینک GRE",
 "GRE link: the panel already built its side. The first lines of the command build the other side on the server, then the agent connects to the panel through the link.":"لینک GRE: پنل سمت خودش را ساخته است. خط‌های اول دستور سمت دیگر را روی سرور می‌سازند و بعد ایجنت از راه لینک به پنل وصل می‌شود.",
 "Game (KCP + FEC)":"گیم (KCP + FEC)",
 "Game adds Reed-Solomon FEC and optional duplication on masked KCP — loss is repaired in flight. FakeTCP wraps UDP inside hand-made TCP packets (udp2raw style) so UDP throttling does not apply.":"گیم روی KCP ماسک‌شده FEC رید-سولومون و ارسال دوبارهٔ اختیاری می‌افزاید — لاست در راه ترمیم می‌شود. FakeTCP بسته‌های UDP را داخل TCP دست‌ساز (سبک udp2raw) می‌پیچد تا محدودیت UDP اعمال نشود.",
 "Game optimization":"بهینه‌سازی بازی",
 "Games · low ping":"گیم · پینگ پایین",
 "Gaming":"گیمینگ",
 "Gaming (low ping)":"گیم (پینگ کم)",
 "Gaming / UDP:":"گیمینگ / UDP:",
 "Gaming and WireGuard-over-tunnel: lowest visible loss, and UDP that looks like TCP.":"گیمینگ و وایرگارد روی تانل: کمترین لاست قابل‌مشاهده، و UDP که شبیه TCP است.",
 "Gaming mode on in the app by default":"حالت گیمینگ در اپ پیش‌فرض روشن",
 "Gaming options":"تنظیمات گیمینگ",
 "Gemini (Google AI Studio, key AQ.… / AIza…)":"Gemini (گوگل AI Studio، کلید AQ.… یا AIza…) · رایگان",
 "General":"عمومی",
 "General settings":"تنظیمات کلی",
 "Get SSL for this domain by itself":"گرفتن خودکار SSL برای این دامنه",
 "Get again":"گرفتن دوباره",
 "Get your numeric Telegram ID from @userinfobot.":"آیدی عددی تلگرامت را از ‎@userinfobot بگیر.",
 "Getting the SSL certificate… this can take up to one minute":"در حال گرفتن SSL… تا یک دقیقه طول می‌کشد",
 "Give a free trial":"تست رایگان بده",
 "Give the rule at least one condition":"حداقل یک شرط برای قانون بگذار",
 "Goes direct (not routed)":"مستقیم می‌رود (مسیردهی نمی‌شود)",
 "Goes through Kanki DNS":"از DNS کانکی رد می‌شود",
 "Gold":"طلایی",
 "Gold · day":"طلایی · روز",
 "Gold · night":"طلایی · شب",
 "Grok (x.ai, key xai-…)":"Grok (x.ai، کلید xai-…)",
 "Grok works":"هوش مصنوعی کار می‌کند",
 "Groq (groq.com, key gsk_…)":"Groq (groq.com، کلید gsk_…)",
 "Grouped by name":"گروه‌بندی بر اساس دامنه",
 "Groups marked \"only on request\" stay off until you turn them on. Some names cannot be routed (they check the address).":"گروه‌های «فقط با درخواست» تا روشنشان نکنی خاموش می‌مانند. بعضی اسم‌ها قابل مسیردهی نیستند (آدرس را چک می‌کنند).",
 "HTTP (CDN SSL or no SSL): 8080, 8880, 2052, 2082, 2086, 2095 · HTTPS (own SSL): 2053, 2083, 2087, 2096, 8443. Keep 80 and 443 free when Kanki DNS runs on this server.":"پورت HTTP (SSL از CDN یا بدون SSL): 8080، 8880، 2052، 2082، 2086، 2095 · پورت HTTPS (SSL خودت): 2053، 2083، 2087، 2096، 8443. اگر DNS کانکی روی همین سرور است، 80 و 443 را آزاد بگذار.",
 "HTTP header camouflage":"استتار با هدر HTTP",
 "HTTP/2 does not get through (or the server is older than 2.9): WSS passes but H2 does not":"HTTP/2 رد نمی‌شود (یا نسخهٔ سرور قدیمی‌تر از 2.9 است): WSS رد می‌شود ولی H2 نه",
 "Hardest to block":"سخت‌ترین برای مسدودسازی",
 "Health":"سلامت",
 "Healthy":"سالم",
 "Heartbeat (seconds, 0 = off)":"ضربان (ثانیه، ۰ = خاموش)",
 "Heavy (more junk, bigger padding)":"سنگین (بسته‌ی زائد بیشتر، پدینگ بزرگ‌تر)",
 "Heavy filtering / burned IPs:":"فیلترینگ شدید / آی‌پی سوخته:",
 "Hidden":"مخفی",
 "Hidden from subscribers":"مخفی از مشتری‌ها",
 "Hide":"بستن",
 "Hide details":"بستن جزئیات",
 "Hide it inside a transport":"پنهان کردن داخل یک ترنسپورت",
 "Hides the SNI from filters that do not reassemble packets.":"اسم SNI را از فیلترهایی که بسته‌ها را سرهم نمی‌کنند پنهان می‌کند.",
 "Hides the SNI from filters that do not reassemble packets. Turn it off if the CDN refuses.":"SNI را از فیلترهایی که بسته‌ها را سرهم نمی‌کنند پنهان می‌کند. اگر CDN قبول نکرد خاموشش کن.",
 "Home":"خانه",
 "Hop":"مرحله",
 "Hops":"مرحله‌ها",
 "Host":"هاست",
 "Host / path":"Host / مسیر",
 "Host header (HTTP)":"هدر Host (HTTP)",
 "Host: your domain on the CDN":"Host: دامنه‌ات روی CDN",
 "Hours":"ساعت",
 "Hours (0 = no end)":"ساعت (۰ = بی‌پایان)",
 "How it works":"چطور کار می‌کند",
 "How often lists and the dashboard refresh themselves.":"فاصله‌ی تازه‌سازی خودکار فهرست‌ها و داشبورد.",
 "How the bot sells: trials, payments, referrals and messages.":"نحوه فروش ربات: تست رایگان، پرداخت، دعوت دوستان و پیام‌ها.",
 "How the panel looks and works":"ظاهر و کارکرد پنل",
 "How to connect":"آموزش اتصال",
 "Hysteria2":"Hysteria2",
 "Hysteria2 UDP port (on the exit)":"پورت UDP هیستریا ۲ (روی سرور خروجی)",
 "IP / CIDR allowed, one per line":"IP / CIDR مجاز، هر خط یک مورد",
 "IP / CIDR blocked, one per line":"IP / CIDR مسدود، هر خط یک مورد",
 "IP addresses and ranges (one per line)":"IPها و رنج‌ها (هر خط یکی)",
 "IP of the panel server (empty = automatic)":"آی‌پی سرور پنل (خالی = خودکار)",
 "IP restriction":"محدودیت IP",
 "IPv4 only":"فقط IPv4",
 "If a port is closed, run this on that server as root:":"اگر پورتی بسته است، این را روی همان سرور با root اجرا کن:",
 "If it stays down, it switches by itself: KCP → TCP Mux → QUIC → WS → WSS → TCP (balanced, reverse)":"اگر قطع بماند، خودکار روش بعدی را امتحان می‌کند: KCP ← TCP Mux ← QUIC ← WS ← WSS ← TCP (متعادل، معکوس)",
 "If one direction is closed it says so and suggests the other":"اگر یک جهت بسته باشد، همین را می‌گوید و جهت دیگر را پیشنهاد می‌دهد",
 "If this server has a tunnel, or will have one, write your Iran server's domain here. Every protocol then also gets a second config through it, made by itself.":"اگر برای این سرور تانل زده‌اید یا می‌خواهید بزنید، دامنه‌ی سرور ایرانتان را همین‌جا بنویسید. از همه‌ی پروتکل‌ها (KANKI MIX، امنزیا، وایرگارد، هیستریا، Xray) خودش یک کانفیگ دوم با این دامنه می‌سازد و به برنامه می‌فرستد.",
 "Image is too complex, use a simpler logo":"تصویر خیلی پیچیده است؛ لوگوی ساده‌تری انتخاب کن",
 "Import":"ورودی",
 "In Telegram open @BotFather, send /newbot and copy the token it gives.":"در تلگرام ‎@BotFather را باز کن، ‎/newbot را بفرست و توکنی که می‌دهد را کپی کن.",
 "In line…":"در صف…",
 "In your DNS (Cloudflare / ArvanCloud): the A record of":"در DNS دامنه (کلادفلر / ابرآروان): رکورد A دامنه‌ی",
 "Inactive":"غیرفعال",
 "Inbound":"دروازه",
 "Inbounds":"دروازه‌ها",
 "Include the app files (APK)":"فایل‌های اپ (APK) هم داخل بکاپ باشد",
 "Insecure: plain HTTP. Reinstall the node with the new installer to get TLS.":"ناامن: HTTP ساده. نود را با نصاب جدید دوباره نصب کن تا TLS بگیرد.",
 "Inside Iran":"داخل ایران",
 "Inside Iran (relay / tunnel entry)":"داخل ایران (رله / ورودی تانل)",
 "Install":"نصب",
 "Install Kanki DNS on this server":"نصب DNS کانکی روی این سرور",
 "Install VPN":"نصب VPN",
 "Install Xray on this server":"نصب Xray روی این سرور",
 "Install the VPN part on this server? It runs by itself on the server and takes a few minutes.":"بخش VPN روی این سرور نصب شود؟ خودِ سرور نصبش می‌کند و چند دقیقه طول می‌کشد.",
 "Install the node with the installer (option 2), then paste the API address and token it prints.":"نود را با نصاب (گزینه ۲) نصب کن، بعد آدرس API و توکنی که چاپ می‌کند را اینجا بزن.",
 "Install tunnels, Xray and DNS (the server agent) on this server? It starts next to its VPN within seconds.":"تانل، Xray و DNS (ایجنت سرور) روی این سرور نصب شود؟ چند ثانیه‌ای کنار VPN آن راه می‌افتد.",
 "Install update":"نصب آپدیت",
 "Installing the VPN part…":"در حال نصب بخش VPN…",
 "Internet":"اینترنت",
 "Internet of these networks leaves from the exit":"اینترنت این شبکه‌ها از سرور خروجی خارج شود",
 "Invalid date":"تاریخ نامعتبر",
 "Invite friends":"دعوت دوستان",
 "Iran":"ایران",
 "Iran address":"آدرس ایران",
 "Iran address (domain or IP)":"آدرس ایران (دامنه یا IP)",
 "Iran and abroad servers of the tunnels":"سرورهای ایران و خارج تانل‌ها",
 "Iran server in front of a DNS exit":"سرور ایران جلوی DNS خروجی",
 "Iran servers":"سرورهای ایران",
 "Iran time":"به وقت ایران",
 "Iran · entry":"ایران · ورودی",
 "Is off in the panel":"در پنل خاموش است",
 "It downloads everything straight from this server, puts it back with the same keys and starts the panel there. Then this panel stops by itself.":"همه‌چیز را مستقیم از همین سرور می‌گیرد، با همان کلیدها برمی‌گرداند و پنل را آن‌جا روشن می‌کند. بعد این پنل خودش خاموش می‌شود.",
 "It holds the password: do not share it.":"رمز تانل داخلش است؛ جایی منتشرش نکن.",
 "It installs only the tunnel agent: no VPN, no web panel. The server appears here as Connected within a few seconds.":"فقط عامل تانل نصب می‌شود؛ نه VPN و نه پنل وب. چند ثانیه بعد سرور اینجا «وصل» نشان داده می‌شود.",
 "It is in Services › Games › Other games.":"در «سرویس‌ها › بازی‌ها › بازی‌های دیگر» است.",
 "It serves":"این‌ها را سرو می‌کند",
 "Its exit":"خروجی آن",
 "KANKI MIX for every user?":"KANKI MIX برای همه‌ی کاربران روشن شود؟",
 "KANKI MIX is off: it runs on no server and is in no subscription.":"KANKI MIX خاموش است: روی هیچ سروری اجرا نمی‌شود و در هیچ اشتراکی نیست.",
 "KANKI MIX on":"KANKI MIX روشن",
 "KANKI MIX on this server":"KANKI MIX روی این سرور",
 "KANKI MIX settings (all servers)":"تنظیمات KANKI MIX (همه‌ی سرورها)",
 "KANKI_REPO in /etc/kanki/kanki.env is set; it wins over this field.":"مقدار KANKI_REPO در فایل /etc/kanki/kanki.env تنظیم شده و بر این فیلد مقدم است.",
 "KCP + Reed-Solomon FEC and optional packet duplication: recovers lost packets without waiting, the lowest ping under loss":"KCP به‌همراه FEC (رید-سولومون) و ارسال دوبارهٔ اختیاری بسته‌ها: بستهٔ گمشده بدون انتظار بازسازی می‌شود؛ کمترین پینگ در شبکهٔ پرلاست",
 "KCP is fully encrypted UDP (its header is hidden too); there is no site name to disguise.":"KCP یک UDP کاملاً رمزنگاری‌شده است (حتی هدرش)؛ اسم سایتی برای پوشاندن ندارد.",
 "Kanki DNS":"DNS کانکی",
 "Kanki DNS (sanctions)":"دی‌ان‌اس کانکی (رفع تحریم)",
 "Kanki DNS has no provider yet either":"DNS کانکی هم هنوز سرویس DNS ندارد",
 "Kanki DNS is not on this server yet.":"DNS کانکی هنوز روی این سرور نیست.",
 "Kanki DNS uses":"DNS کانکی از این استفاده می‌کند:",
 "Kanki VPN":"کانکی VPN",
 "Kanki VPN and Xray side by side":"کانکی VPN و Xray کنار هم",
 "Kanki VPN only":"فقط کانکی VPN",
 "Kanki tunnel":"تانل کانکی",
 "Keepalive (seconds)":"Keepalive (ثانیه)",
 "Key file":"فایل کلید",
 "Label":"برچسب",
 "Language":"زبان",
 "Largest clock difference (ms, 0 = off)":"بیشترین اختلاف ساعت (میلی‌ثانیه، ۰ = خاموش)",
 "Last":"آخرین",
 "Last answer":"آخرین جواب",
 "Last cleaned":"آخرین تمیزکاری",
 "Last contact":"آخرین ارتباط",
 "Last error":"آخرین خطا",
 "Last logins to the panel":"آخرین ورودها به پنل",
 "Last report":"آخرین گزارش",
 "Last run":"آخرین اجرا",
 "Last seen":"آخرین اتصال",
 "Last switch":"آخرین تغییر",
 "Latest version":"آخرین نسخه",
 "Legacy API key":"کلید API قدیمی",
 "Let's Encrypt checks from outside Iran: port 80/TCP of the server must be open from abroad. Open it in the data center's firewall panel too; when international traffic is cut, SSL cannot be taken until it is back.":"Let's Encrypt از خارج ایران چک می‌کند: پورت 80/TCP سرور باید از خارج باز باشد. در پنل فایروال دیتاسنتر هم بازش کن؛ وقتی اینترنت بین‌الملل قطع است، تا وصل نشود SSL گرفته نمی‌شود.",
 "Light":"روشن",
 "Light / dark":"روشن / تیره",
 "Like 4001-4010. They all lead to the main port; the app picks one at random on every connect, so blocking one port is not enough. Empty = off.":"مثلاً 4001-4010. همه به پورت اصلی می‌رسند؛ اپ هر بار یکی را تصادفی انتخاب می‌کند تا بستن یک پورت کافی نباشد. خالی = خاموش.",
 "Limited":"اتمام حجم",
 "Limits and users":"محدودیت و کاربرها",
 "Link":"لینک",
 "Link SNI":"SNI لینک",
 "Link address":"آدرس لینک",
 "Link and CDN":"لینک و CDN",
 "Link for your channel":"لینک برای کانال",
 "Link of the other server (vless, vmess, trojan or ss)":"لینک سرور دیگر (vless، vmess، trojan یا ss)",
 "Link port":"پورت تانل",
 "Links":"لینک‌ها",
 "Links between your servers":"اتصال بین سرورهایت",
 "Links of every Xray inbound go into the subscription":"لینک همه‌ی اینباندهای Xray در ساب می‌آید",
 "Listen address":"آدرس listen",
 "Live":"زنده",
 "Live log":"لاگ زنده",
 "Live network traffic":"ترافیک لحظه‌ای شبکه",
 "Live speed":"سرعت لحظه‌ای",
 "Load":"لود",
 "Loading…":"در حال بارگذاری…",
 "Local":"محلی",
 "Location":"موقعیت",
 "Location guessed: confirm it in Edit":"موقعیت حدس زده شده: در «ویرایش» تأییدش کن",
 "Location not set: choose it in Edit":"موقعیت مشخص نیست: در «ویرایش» انتخابش کن",
 "Log level":"سطح لاگ",
 "Log out others":"خروج بقیه",
 "Login":"ورود",
 "Login and lobby (recommended)":"ورود و لابی (پیشنهادی)",
 "Login history":"تاریخچه ورود",
 "Login, 2FA, sessions and IP access":"ورود، دومرحله‌ای، نشست‌ها و دسترسی IP",
 "Login, account, lobby and the UC store go through your server; the match stays direct.":"ورود، حساب، لابی و فروشگاه UC از سرور تو رد می‌شوند؛ خود مسابقه مستقیم می‌ماند.",
 "Login, sessions, 2FA, IP policy and API":"ورود، نشست‌ها، احراز هویت دومرحله‌ای، سیاست IP و API",
 "Logo":"لوگو",
 "Logout":"خروج",
 "Logs are not available":"لاگ در دسترس نیست",
 "Look at":"بررسی",
 "Look like QUIC / HTTP3 on the wire":"شبیه QUIC / HTTP3 روی سیم",
 "Looks like a WebSocket, works behind a CDN":"شبیه وب‌سوکت، پشت CDN هم کار می‌کند",
 "Looks like an HTTPS site, hardest to spot":"شبیه یک سایت HTTPS، سخت‌تر از همه شناسایی می‌شود",
 "Looks like web traffic":"شبیه ترافیک وب",
 "Lower it (1280) if some sites do not open on mobile data.":"اگر بعضی سایت‌ها روی اینترنت موبایل باز نمی‌شوند، کمش کن (1280).",
 "Lowest TLS version":"کمترین نسخه‌ی TLS",
 "MTU":"MTU",
 "MTU (0 = automatic)":"MTU (۰ = خودکار)",
 "MTU must be between 1200 and 1500":"MTU باید بین 1200 تا 1500 باشد",
 "Main":"اصلی",
 "Main panel server · local management":"سرور اصلی پنل · مدیریت محلی",
 "Main server":"سرور اصلی",
 "Main server and extra nodes":"سرور اصلی و نودهای اضافه",
 "Maintenance":"تعمیرات",
 "Make each direct name an A record pointing at the server's IP (Cloudflare: DNS only, grey cloud). Until it points right, the app gets the server's own address.":"هر اسم مستقیم را یک رکورد A بساز که به آی‌پی سرور اشاره کند (کلادفلر: فقط DNS، ابر خاکستری). تا وقتی درست نشده، برنامه آدرس خود سرور را می‌گیرد.",
 "Make the first one":"اولی را بساز",
 "Make the first tunnel":"اولین تانل را بساز",
 "Make the move command":"ساخت دستور انتقال",
 "Make the route":"ساخت مسیر",
 "Make the tunnel":"ساخت تانل",
 "Make this inbound":"ساخت این دروازه",
 "Makes a new code that ends by itself and announces it in the channel.":"یک کد جدید که خودش منقضی می‌شود می‌سازد و در کانال اعلام می‌کند.",
 "Manage":"مدیریت",
 "Manage Xray":"مدیریت Xray",
 "Manage nodes":"مدیریت نودها",
 "Manual (paste a certificate)":"دستی (گواهی را خودت بگذار)",
 "Memory":"حافظه",
 "Merchant ID":"مرچنت",
 "Message":"متن پیام",
 "Metadata only":"فقط متادیتا",
 "Method":"روش",
 "Mimic QUIC (adds I1, needs AmneziaWG tools 1.5+)":"تقلید QUIC (I1 اضافه می‌شود، نیاز به AmneziaWG نسخه ۱.۵ به بالا)",
 "Mode":"حالت",
 "Model":"مدل",
 "More":"بیشتر",
 "Most speed":"بیشترین سرعت",
 "Most used":"بیشترین مصرف",
 "Move all settings to another panel or keep a copy":"انتقال همه‌ی تنظیمات به پنل دیگر یا نگه‌داشتن یک نسخه",
 "Move the panel to a new server":"انتقال کامل پنل به سرور جدید",
 "Move to category":"انتقال به دسته‌بندی",
 "Moved on the entry because they were taken":"روی ورودی عوض شد چون پر بود",
 "Moved: the panel runs on the new server. This one is stopping.":"انتقال تمام شد: پنل روی سرور جدید اجرا می‌شود و این یکی خاموش می‌شود.",
 "Multi mode (in the link)":"حالت Multi (در لینک)",
 "Multi-location":"چندمرحله‌ای",
 "Multi-location tunnel":"تانل چندمرحله‌ای",
 "My own certificate":"گواهی خودم",
 "NOWPayments (crypto)":"NOWPayments (ارز دیجیتال)",
 "NOWPayments API key":"کلید API در NOWPayments",
 "Name":"نام",
 "Name in the app":"اسم در برنامه",
 "Name of these configs in the app (optional)":"اسم این کانفیگ‌ها در برنامه (اختیاری)",
 "Name, logo, language, theme and colour of the panel":"نام، لوگو، زبان، پوسته و رنگ پنل",
 "Names your users asked":"نام‌هایی که کاربرها پرسیده‌اند",
 "Nearest expiry":"نزدیک‌ترین انقضا",
 "Needed so what enters the link can reach the internet from the exit.":"لازم است تا ترافیکی که وارد لینک می‌شود از خروجی به اینترنت برسد.",
 "Network":"شبکه",
 "Network policy":"سیاست شبکه",
 "Network speed":"سرعت شبکه",
 "New":"جدید",
 "New backup passphrase (min 6). Old backups still need the old one.":"رمز جدید بکاپ (حداقل ۶). بکاپ‌های قبلی هنوز با رمز قبلی باز می‌شوند.",
 "New inbound":"اینباند جدید",
 "New keys":"کلیدهای جدید",
 "New link":"لینک جدید",
 "New link (the old one stops working)":"لینک جدید (لینک قبلی از کار می‌افتد)",
 "New obfuscation numbers":"اعداد مبهم‌سازی جدید",
 "New password (min 8)":"رمز جدید (حداقل ۸)",
 "New password and certificate":"رمز و گواهی جدید",
 "New server (install command)":"سرور جدید (دستور نصب)",
 "New signing key":"کلید امضای جدید",
 "New tunnel":"تانل جدید",
 "New user":"کاربر جدید",
 "New username (optional)":"نام کاربری جدید (اختیاری)",
 "New users":"کاربر جدید",
 "Newest":"جدیدترین",
 "Next":"بعدی",
 "Next hop":"مرحله‌ی بعد",
 "Next run":"اجرای بعدی",
 "Night":"شب",
 "Nightly backup to the bot":"بکاپ شبانه به ربات",
 "No DNS domain yet: encrypted DNS (DoT / DoH) needs one.":"هنوز دامنه‌ی DNS نداری: DNS رمزدار (DoT / DoH) به آن نیاز دارد.",
 "No DNS server yet":"هنوز سرور DNS نیست",
 "No Kanki tunnel carries this port to the server. Make a tunnel (or a multi-location route) that carries it, or forward it on that address some other way.":"هیچ تانل کانکی این پورت را به این سرور نمی‌برد. یک تانل (یا مسیر چندمرحله‌ای) بساز که آن را ببرد، یا روی آن آدرس به روش دیگری فورواردش کن.",
 "No PUBG query in the log yet: open the game on a phone that uses your DNS, then press Refresh.":"هنوز پرس‌وجوی پابجی در گزارش نیست: بازی را روی گوشی‌ای که DNS تو را دارد باز کن، بعد «تازه‌سازی» را بزن.",
 "No QUIC / HTTP/3 signature on the wire. Turn it off only if you want it to look like HTTP/3.":"هیچ امضای QUIC / HTTP/3 روی سیم نیست. فقط وقتی خاموشش کن که بخواهی شبیه HTTP/3 دیده شود.",
 "No SSL (HTTP)":"بدون SSL (HTTP)",
 "No VPN server yet":"هنوز سرور VPN نیست",
 "No Xray inbound yet":"هنوز اینباند Xray نیست",
 "No Xray server yet: add one in Servers":"هنوز سرور Xray نیست: در «سرورها» اضافه کن",
 "No address":"آدرس ندارد",
 "No answer":"جوابی نیامد",
 "No certificate yet: DoT / DoH and registering by link do not work without it.":"هنوز گواهی نیست: DoT / DoH و ثبت با لینک بدون آن کار نمی‌کند.",
 "No clash":"تداخلی نیست",
 "No codes yet":"هنوز کدی نیست",
 "No configs: user has no nodes or protocols":"کانفیگی نیست: کاربر نود یا پروتکلی ندارد",
 "No connection":"وصل نشد",
 "No contact for more than 3 minutes":"بیش از ۳ دقیقه ارتباطی نبوده",
 "No debug lines":"خط دیباگی نیست",
 "No errors":"خطایی نیست",
 "No extra nodes yet. Add one with a single command.":"هنوز نود اضافه‌ای نیست. با یک دستور اضافه کن.",
 "No fallbacks":"فال‌بکی نیست",
 "No file chosen":"فایلی انتخاب نشده",
 "No file yet: the bot and the subscription page show the app download link of Sales settings.":"هنوز فایلی نیست: ربات و صفحه‌ی اشتراک همان لینک دانلود اپ تنظیمات فروش را نشان می‌دهند.",
 "No inbound on this server yet":"هنوز دروازه‌ای روی این سرور نیست",
 "No inbound yet.":"هنوز دروازه‌ای نیست.",
 "No log lines yet":"هنوز لاگی نیست",
 "No match":"موردی پیدا نشد",
 "No message is showing in the app right now.":"الان هیچ پیامی در اپ نمایش داده نمی‌شود.",
 "No node found for this server: type the ports by hand":"نودی برای این سرور پیدا نشد: پورت‌ها را دستی بنویس",
 "No plans yet":"هنوز پلنی ساخته نشده",
 "No port changed":"پورتی عوض نشده",
 "No port information yet. Press Check now.":"هنوز اطلاعات پورت نیامده. «بررسی الان» را بزن.",
 "No posts between 1 and 8 in the morning.":"بین ۱ تا ۸ صبح پستی ارسال نمی‌شود.",
 "No rules yet: everything goes to the default outbound.":"هنوز قانونی نیست: همه چیز به خروجی پیش‌فرض می‌رود.",
 "No sales bot yet":"هنوز ربات فروش ساخته نشده",
 "No server here":"سروری اینجا نیست",
 "No server yet":"هنوز سروری نیست",
 "No service on this server yet":"هنوز سرویسی روی این سرور نیست",
 "No swap":"بدون Swap",
 "No transport could connect in either direction. Open the test ports in the cloud firewall of both servers and try again.":"در هیچ جهتی ترنسپورتی وصل نشد. پورت‌های تست را در فایروال هر دو سرور باز کن و دوباره امتحان کن.",
 "No transport could connect in either direction. Open the test ports in the cloud firewall of both servers and try again. If only GRE passes between the two servers, add or edit the server with the “Only GRE passes” option.":"هیچ ترنسپورتی در هیچ جهتی وصل نشد. پورت‌های تست را در فایروال ابری هر دو سرور باز کن و دوباره امتحان کن. اگر بین دو سرور فقط GRE رد می‌شود، سرور را با گزینهٔ «فقط GRE» اضافه یا ویرایش کن.",
 "No transport could connect. Open the test ports in the cloud firewall of the listening server and try again.":"هیچ روشی وصل نشد. پورت‌های تست را در فایروال کلاد سرورِ شنونده باز کن و دوباره تست کن.",
 "No transport passed on this hop":"هیچ روشی روی این مرحله رد نشد",
 "No tunnel carries this port: users connect to the server directly":"هیچ تانلی این پورت را نمی‌برد: کاربرها مستقیم به سرور وصل می‌شوند",
 "No tunnel is made and nothing changes on the servers":"هیچ تانلی ساخته نمی‌شود و چیزی روی سرورها عوض نمی‌شود",
 "No tunnel uses this server.":"هیچ تانلی از این سرور استفاده نمی‌کند.",
 "No tunnels yet":"هنوز تانلی ساخته نشده",
 "No user has DNS yet: tick DNS in a user's form":"هنوز کاربری DNS ندارد: در فرم کاربر تیک DNS را بزن",
 "No users with Xray yet: tick Xray in a user's form":"هنوز کاربری Xray ندارد: در فرم کاربر تیک Xray را بزن",
 "No users yet":"هنوز کاربری نیست",
 "Nobody is connected right now":"الان کسی وصل نیست",
 "Nobody is online right now":"الان کسی آنلاین نیست",
 "Node":"نود",
 "Node API (HTTPS)":"API نود (HTTPS)",
 "Node access & note":"دسترسی نود و یادداشت",
 "Node domain (optional, for a real SSL certificate)":"دامنه نود (اختیاری، برای گواهی SSL واقعی)",
 "Node name":"نام نود",
 "Node token":"توکن نود",
 "Node type":"نوع نود",
 "Nodes":"نودها",
 "Nodes and tunnel servers are updated together with":"نودها و سرورهای تانل با این دکمه با هم آپدیت می‌شوند:",
 "Nodes online":"نودهای آنلاین",
 "Nodes that have their own address switch back to this one when you save.":"نودهایی که آدرس اختصاصی دارند، با ذخیره به همین آدرس برمی‌گردند.",
 "None":"هیچ",
 "Normal filtering:":"فیلترینگ عادی:",
 "Not connected":"وصل نیست",
 "Not connected right now":"الان وصل نیست",
 "Not connected yet":"هنوز وصل نیست",
 "Not connected yet: run its command on the server":"هنوز وصل نشده: دستورش را روی سرور اجرا کن",
 "Not in a tunnel":"بدون تانل",
 "Not needed":"لازم نیست",
 "Not reachable":"در دسترس نیست",
 "Not reachable: check the server, its agent and the firewall":"در دسترس نیست: سرور، Agent و فایروال را چک کن",
 "Not running":"اجرا نمی‌شود",
 "Not set yet":"هنوز تنظیم نشده",
 "Not tested, an agent is too old (update it first)":"تست نشد، ایجنت قدیمی است (اول آپدیتش کن)",
 "Note":"یادداشت",
 "Note for subscribers":"یادداشت برای مشتری‌ها",
 "Nothing found":"چیزی پیدا نشد",
 "Nothing of PUBG passes your servers. Fine where the game opens without help.":"هیچ چیز پابجی از سرورهای تو رد نمی‌شود. برای جاهایی که بازی بدون کمک باز می‌شود.",
 "Nothing passes in this direction":"در این جهت هیچ چیز رد نمی‌شود",
 "Nothing to set: write each server's domain (or label + DNS domain) and point it to the server. Kanki DNS answers Let's Encrypt itself on port 80, so DNS does not stop. The SSL state of every server is on its card.":"تنظیمی لازم نیست: دامنه‌ی هر سرور را بنویس (یا برچسب + دامنه‌ی DNS) و به همان سرور وصل کن. خود سرویس DNS روی پورت ۸۰ جواب Let's Encrypt را می‌دهد، پس DNS قطع نمی‌شود. وضعیت SSL هر سرور روی کارت خودش است.",
 "Nothing yet":"هنوز چیزی نیست",
 "Nothing yet: queries show up here a few seconds after a subscriber uses DNS (DNS servers must run v3.5.8 or newer).":"هنوز چیزی نیست: چند ثانیه بعد از اینکه مشتری از DNS استفاده کند اینجا می‌آید (سرورهای DNS باید نسخه‌ی ۳.۵.۸ یا جدیدتر باشند).",
 "Notifications":"اعلان‌ها",
 "Now":"الان",
 "OK":"تأیید",
 "Obfuscated WireGuard":"WireGuard مبهم",
 "Obfuscation":"مبهم‌سازی",
 "Obfuscation (Salamander)":"مبهم‌سازی (Salamander)",
 "Obfuscation password":"رمز مبهم‌سازی",
 "Obfuscation profile":"پروفایل مبهم‌سازی",
 "Occasion greeting":"تبریک مناسبت",
 "Off":"خاموش",
 "Off = only for routing (recommended)":"خاموش = فقط برای مسیریابی (پیشنهادی)",
 "Off for all users":"خاموش برای همه‌ی کاربران",
 "Off on this server":"روی این سرور خاموش",
 "Off when you manage the A record yourself (for example behind a CDN)":"اگر رکورد A را خودت مدیریت می‌کنی (مثلاً پشت CDN) خاموش کن",
 "Off: DNS stops on every server and leaves the subscriptions":"خاموش: DNS روی همه‌ی سرورها می‌ایستد و از ساب‌ها حذف می‌شود",
 "Off: Xray stops on every server and the links leave the subscriptions":"خاموش: Xray روی همه‌ی سرورها می‌ایستد و لینک‌ها از ساب‌ها حذف می‌شوند",
 "Off: exactly like the tunnels (game UDP inside the stream). On: game packets as datagrams of their own, small ones sent several times.":"خاموش: دقیقاً مثل تانل‌ها (UDP بازی داخل همان جریان). روشن: بسته‌های بازی دیتاگرام جدا و بسته‌های کوچک چند بار.",
 "Offline":"آفلاین",
 "Oldest":"قدیمی‌ترین",
 "On":"روشن",
 "On filtered networks WSS and WS usually pass; plain TCP, TCP Mux, QUIC and KCP are often cut. Use “Find the best transport” to test them between these two servers.":"در شبکه‌های فیلترشده معمولاً WSS و WS رد می‌شوند و TCP، TCP Mux، QUIC و KCP اغلب قطع‌اند. با «پیدا کردن بهترین روش» همه را بین همین دو سرور تست کن.",
 "On for all users":"روشن برای همه‌ی کاربران",
 "On the CDN: add the domain, point it to the Iran (entry) server IP, turn WebSocket on, origin = HTTP on the tunnel port below. Open that port on the Iran server.":"در پنل CDN: دامنه را اضافه کن، به آی‌پی سرور ایران (ورودی) بده، WebSocket را روشن کن، مبدأ = HTTP روی پورت تانل پایین. آن پورت را روی سرور ایران باز کن.",
 "On the CDN: add the domain, point it to the foreign (exit) server IP, turn WebSocket on, origin = HTTP on the tunnel port below. Open that port on the exit server.":"در پنل CDN: دامنه را اضافه کن، به آی‌پی سرور خارج (خروجی) بده، WebSocket را روشن کن، مبدأ = HTTP روی پورت تانل پایین. آن پورت را روی سرور خروجی باز کن.",
 "One click applies it in making or editing a tunnel":"با یک کلیک در ساخت یا ویرایش تانل اعمال می‌شود",
 "One per line; their subdomains are routed too":"هر خط یکی؛ زیردامنه‌هایشان هم مسیردهی می‌شوند",
 "One plain link":"یک اتصال ساده",
 "One tunnel entry cannot carry the same port to two servers. Fix moves the later server to a free port; tunnels that carry the old port follow.":"یک سرور ورودی (ایران) نمی‌تواند یک پورت را به دو سرور تانل کند. «رفع» سرور بعدی را به پورت آزاد می‌برد و تانل‌هایی که پورت قبلی را می‌برند هم خودکار درست می‌شوند.",
 "One-click inbounds with the methods that resist DPI: REALITY, WS/gRPC behind a CDN, Shadowsocks 2022 — plus the server-link transports":"اینباند یک‌کلیکی با روش‌های مقاوم در برابر DPI: REALITY، WS/gRPC پشت CDN، Shadowsocks 2022 — به‌همراه انتقال‌های سرور‌به‌سرور",
 "Online":"آنلاین",
 "Online clients":"کلاینت‌های آنلاین",
 "Online now":"آنلاین الان",
 "Online payments":"درگاه‌های پرداخت آنلاین",
 "Only GRE passes to this server":"فقط GRE به این سرور رد می‌شود",
 "Only Jc/Jmin/Jmax/S1/S2/H1-H4, for old AmneziaWG apps.":"فقط Jc/Jmin/Jmax/S1/S2/H1-H4؛ برای اپ‌های قدیمی AmneziaWG.",
 "Only connections for the name above are answered":"فقط به اتصال‌های همین اسم جواب داده می‌شود",
 "Only for KANKI MIX (optional)":"فقط برای KANKI MIX (اختیاری)",
 "Only for these users":"فقط برای این کاربرها",
 "Only for these users (empty = everyone)":"فقط برای این کاربرها (خالی = همه)",
 "Only from these inbounds":"فقط از این اینباندها",
 "Only packets up to 400 bytes (PUBG: 40-300 bytes) are copied; downloads are sent once. Through 15% loss each way: 1 copy 72%, 2 copies 96%, 3 copies 99.8% of round trips arrive.":"فقط بسته‌های تا ۴۰۰ بایت (پابجی: ۴۰ تا ۳۰۰ بایت) چندتایی می‌روند؛ دانلودها یک بار. با ۱۵٪ لاس در هر طرف: ۱ نسخه ۷۲٪، ۲ نسخه ۹۶٪، ۳ نسخه ۹۹٫۸٪ رفت‌وبرگشت‌ها می‌رسند.",
 "Only restart is allowed for this service":"این سرویس فقط ری‌استارت می‌شود",
 "Only the transport can reach it; scanners cannot probe the port.":"فقط ترنسپورت به آن می‌رسد؛ اسکنرها نمی‌توانند پورت را کاوش کنند.",
 "Only these users (empty = everyone with Xray)":"فقط این کاربرها (خالی = همه‌ی دارندگان Xray)",
 "Only when nginx / HAProxy in front sends it":"فقط وقتی nginx / HAProxy جلوی سرور آن را می‌فرستد",
 "Open":"باز کردن",
 "Open page":"باز کردن صفحه",
 "Open ports that nothing uses":"پورت‌های بازی که هیچ‌چیز از آن‌ها استفاده نمی‌کند",
 "Open the tunnels":"باز کردن تانل‌ها",
 "Open this port on":"این پورت را باز کن روی",
 "Opened earlier for something that was deleted, or by hand. SSH is never closed.":"قبلاً برای چیزی که حذف شده یا دستی باز شده‌اند. پورت SSH هیچ‌وقت بسته نمی‌شود.",
 "Optional, created if empty":"خالی بماند: خودکار USER1، USER2 و…",
 "Other":"بدون دسته",
 "Other sites answered by":"جواب سایت‌های دیگر از",
 "Our own protocol on every VPN server: game packets go straight (no queue, sent twice in gaming mode), websites over KCP + FEC.":"پروتکل خودمان روی همه‌ی سرورهای VPN: بسته‌های بازی مستقیم می‌روند (بدون صف، در حالت گیمینگ دوتایی)، سایت‌ها روی KCP + FEC.",
 "Our own protocol: games, low ping":"پروتکل خودمان: بازی، پینگ کم",
 "Our own protocols on the nodes":"پروتکل‌های خودمان روی نودها",
 "Outbounds":"خروجی‌ها (اوت‌باند)",
 "Over KCP (UDP), good on weak/lossy internet":"روی KCP (UDP)، مناسب اینترنت ضعیف و پرافت",
 "Over QUIC (UDP), fast and encrypted":"روی QUIC (UDP)، سریع و رمزنگاری‌شده",
 "Over TCP (steady)":"روی TCP (پایدار)",
 "Over UDP":"روی UDP",
 "Over UDP (fast, games)":"روی UDP (سریع، بازی)",
 "Overview":"نمای کلی",
 "PUBG Mobile through Kanki DNS":"پابجی موبایل با DNS کانکی",
 "PUBG and games":"پابجی و بازی‌ها",
 "PUBG names your users asked":"نام‌های پابجی که کاربرهایت پرسیده‌اند",
 "PUBG on PC (Krafton)":"پابجی کامپیوتر (Krafton)",
 "Padding (bytes)":"پدینگ (بایت)",
 "Page":"صفحه",
 "Panel":"پنل",
 "Panel (HTTPS)":"پنل (HTTPS)",
 "Panel (internal)":"پنل (داخلی)",
 "Panel / API":"پنل / API",
 "Panel address":"آدرس پنل",
 "Panel address, the public VPN address and subscription links":"آدرس پنل، آدرس عمومی VPN و لینک‌های اشتراک",
 "Panel and VPN services on this server":"پنل و سرویس‌های VPN همین سرور",
 "Panel backup passphrase (needed to restore)":"رمز بکاپ پنل (برای ریستور لازم است)",
 "Panel color":"رنگ پنل",
 "Panel is restarting…":"پنل در حال ری‌استارت…",
 "Panel name":"نام پنل",
 "Panel server":"سرور پنل",
 "Parts of PUBG Mobile":"بخش‌های پابجی موبایل",
 "Passes through":"از این رد می‌شود",
 "Passphrase (min 6)":"Passphrase (حداقل ۶)",
 "Password":"رمز",
 "Password, 2FA, sessions":"رمز، تأیید دومرحله‌ای، نشست‌ها",
 "Paste (PEM)":"چسباندن (PEM)",
 "Paste a certificate instead (optional)":"به‌جایش گواهی دستی بگذار (اختیاری)",
 "Paste a certificate you already have.":"گواهی‌ای که داری را بچسبان.",
 "Paste a new key to replace it":"برای عوض کردن، کلید جدید را بچسبان",
 "Paste the certificate first":"اول گواهی را بچسبان",
 "Path":"مسیر (path)",
 "Path of the traffic":"مسیر ترافیک",
 "Pause":"توقف",
 "Paused":"متوقف",
 "Peak":"پیک",
 "Phone type":"نوع گوشی",
 "Pick a backup file; if encrypted, enter its passphrase.":"فایل بکاپ را انتخاب کن؛ اگر رمز دارد وارد کن.",
 "Pick a method: the inbound editor opens with the right settings filled in. Then press Save — the panel makes keys, certificates and user links by itself.":"یک روش را انتخاب کن: ویرایشگر اینباند با تنظیمات درست باز می‌شود. بعد ذخیره را بزن — پنل خودش کلیدها، گواهی‌ها و لینک کاربران را می‌سازد.",
 "Pick a settings file exported from a Kanki panel. Only known settings are taken; users, nodes and keys are not touched.":"فایل تنظیماتی که از یک پنل کانکی گرفته‌ای را انتخاب کن. فقط تنظیمات شناخته‌شده خوانده می‌شوند؛ به کاربرها، نودها و کلیدها دست نمی‌خورد.",
 "Pick at least one method":"حداقل یک روش را انتخاب کن",
 "Pick at least three servers: the first, one in the middle and the last":"حداقل سه سرور انتخاب کن: اولی، یکی وسط و آخری",
 "Pick every server":"همه‌ی سرورها را انتخاب کن",
 "Pick one: it changes only the PUBG Mobile names below.":"یکی را انتخاب کن: فقط نام‌های پابجی موبایل پایین عوض می‌شوند.",
 "Ping":"پینگ",
 "Plain HTTP looks filtered: WSS passes but WebSocket does not":"HTTP ساده احتمالاً فیلتر شده: WSS رد می‌شود ولی WebSocket نه",
 "Plain WireGuard on every VPN server. Inside Iran it works only through a tunnel.":"WireGuard ساده روی همه‌ی سرورهای VPN. داخل ایران فقط از راه تانل کار می‌کند.",
 "Plain and fast":"ساده و سریع",
 "Plan name":"نام پلن",
 "Planned ports":"پورت‌های رزرو شده",
 "Plans":"پلن‌ها",
 "Plans, payments, Telegram":"پلن‌ها، پرداخت، تلگرام",
 "Plans, prices and payments can also be managed inside the bot (Admin panel button).":"پلن‌ها، قیمت‌ها و پرداخت‌ها را داخل خود ربات هم می‌شود مدیریت کرد (دکمه پنل ادمین).",
 "Point it at":"به این آی‌پی اشاره کند",
 "Point the domain at the server":"وصل کردن دامنه به سرور",
 "Point the panel's domain to the new server's IP":"دامنه‌ی پنل را روی آی‌پی سرور جدید بگذار",
 "Points at this server":"درست است",
 "Points elsewhere":"به سرور دیگری اشاره می‌کند",
 "Port":"پورت",
 "Port 80 busy: the error names the program. A Kanki tunnel that forwards port 80 holds it: take 80 out of that tunnel. Caddy / nginx are set aside by themselves for a few seconds.":"پورت ۸۰ پر: اسم برنامه در خطا هست. اگر یک تانل کانکی پورت ۸۰ را عبور می‌دهد، پورت دست خود اوست: ۸۰ را از آن تانل بردار. Caddy / nginx خودشان چند ثانیه کنار می‌روند.",
 "Port clash":"تداخل پورت",
 "Port conflict: another service on this server uses the same port":"تداخل پورت: سرویس دیگری روی همین سرور همین پورت را دارد",
 "Port hopping during the connection (a new port every few minutes)":"پورت‌هاپینگ وسط اتصال (هر چند دقیقه پورت تازه)",
 "Port management":"مدیریت پورت‌ها",
 "Port of this server":"پورت این سرور",
 "Ports":"پورت‌ها",
 "Ports 53, 80, 443 and 853 must be free on this server: give DNS its own server.":"پورت‌های ۵۳، ۸۰، ۴۴۳ و ۸۵۳ روی این سرور باید آزاد باشند: برای DNS سرور جدا بگذار.",
 "Ports and protocols of this server are in VPN services.":"پورت‌ها و پروتکل‌های این سرور در «سرویس‌های VPN» است.",
 "Ports given to this server (no other server uses them)":"پورت‌هایی که به این سرور داده شد (هیچ سرور دیگری از آن‌ها استفاده نمی‌کند)",
 "Ports moved":"پورت‌ها جابه‌جا شدند",
 "Ports of":"پورت‌های",
 "Ports of the exit server":"پورت‌های سرور خروجی",
 "Empty = Iran server-abroad server":"خالی = اسم سرور ایران-اسم سرور خارج",
 "Ports of the panel server were filled in":"پورت‌های سرور پنل وارد شد",
 "Ports taken by another program":"پورت‌هایی که برنامه‌ی دیگری گرفته",
 "Ports through the tunnel":"پورت‌ها از راه تانل",
 "Ports to carry":"پورت‌هایی که از مسیر رد می‌شوند",
 "Ports used on the main server and on every node":"پورت‌های سرور اصلی و همه نودها",
 "Post every (hours)":"هر چند ساعت یک پست",
 "Post preview":"پیش‌نمایش پست",
 "Post types":"نوع پست‌ها",
 "Posting times (Iran time)":"ساعت‌های انتشار (به وقت ایران)",
 "Posts are written by Grok from your real plans, prices and codes, in the tone you describe. When Grok does not answer (it is tried again, and another model is tried), the built-in writer posts instead.":"پست‌ها را هوش مصنوعی (Groq یا Grok) از روی پلن‌ها، قیمت‌ها و کدهای واقعی‌ات با لحنی که می‌نویسی می‌نویسد. اگر جواب ندهد (چند بار دوباره امتحان می‌شود و مدل دیگری هم امتحان می‌شود)، نویسنده‌ی داخلی پست را می‌گذارد.",
 "Posts are written by the AI from your real plans, prices and codes, in the tone you describe. When it does not answer (it is tried again, and another model is tried), the built-in writer posts instead.":"پست‌ها را هوش مصنوعی از روی پلن‌ها، قیمت‌ها و کدهای واقعی و با لحنی که می‌گویی می‌نویسد. اگر جواب ندهد (دوباره تلاش می‌شود و مدل دیگری امتحان می‌شود)، نویسنده‌ی داخلی پنل پست می‌گذارد.",
 "Posts sent":"پست‌های ارسال‌شده",
 "Press Create bot and paste both.":"«ساخت ربات» را بزن و هر دو را وارد کن.",
 "Press Save routing to apply":"برای اعمال، «ذخیره‌ی روتینگ» را بزن",
 "Press Update agent to see CPU, RAM and disk of this node":"برای دیدن CPU، رم و دیسک این نود «آپدیت Agent» را بزن",
 "Press a service to open its settings":"روی هر سرویس بزن تا تنظیمات و تعمیرش باز شود",
 "Prev":"قبلی",
 "Price (Toman)":"قیمت (تومان)",
 "Price (USD)":"قیمت (دلار)",
 "Price list":"لیست قیمت",
 "Price per GB (Toman)":"قیمت هر گیگ (تومان)",
 "Private DNS for sanctioned sites":"DNS اختصاصی برای سایت‌های تحریمی",
 "Private key":"کلید خصوصی",
 "Private key (PKCS#8 PEM)":"کلید خصوصی (PEM)",
 "Private smart DNS for your subscribers: sanctioned services go through your servers, everything else goes direct":"DNS هوشمند اختصاصی مشتری‌ها: سرویس‌های تحریمی از سرورهای شما رد می‌شوند و بقیه مستقیم",
 "Problem":"مشکل دارد",
 "Profile":"پروفایل",
 "Protocol":"پروتکل",
 "Protocol access":"دسترسی پروتکل‌ها",
 "Protocols":"پروتکل‌ها",
 "Provider":"سرویس DNS دامنه",
 "Public IP of this server":"آی‌پی عمومی این سرور",
 "Public VPN host or IP":"هاست یا IP عمومی VPN",
 "Public endpoint":"Endpoint عمومی",
 "Public host used inside user configs.":"Public Host داخل کانفیگ‌های کاربر استفاده می‌شود.",
 "Public key":"کلید عمومی",
 "Publish now":"انتشار الان",
 "Published":"منتشر شد",
 "Purple · day":"بنفش · روز",
 "Purple · night":"بنفش · شب",
 "Put it on a “Download the app” button: the bot opens straight on the download menu.":"این لینک را روی دکمه‌ی «دانلود اپ» کانال بگذار: ربات مستقیم روی منوی دانلود باز می‌شود.",
 "Q&A":"پرسش و پاسخ",
 "QUIC under a random mask: no QUIC signature, packet sizes hidden":"QUIC زیر یک ماسک تصادفی: بدون امضای QUIC و با اندازهٔ بستهٔ پنهان",
 "QUIC · lossy internet":"QUIC · اینترنت پرافت",
 "QUIC-based with Salamander obfuscation: brutal congestion control keeps speed even with loss. In the tunnel wizard pick “Hysteria2” — the panel makes password, certificate and fingerprint pinning itself.":"مبتنی بر QUIC با مبهم‌سازی Salamander: کنترل ازدحام brutal سرعت را حتی با لاست نگه می‌دارد. در ویزارد تانل «Hysteria2» را انتخاب کن — پنل خودش رمز، گواهی و پین اثرانگشت را می‌سازد.",
 "QUIC-based, fast on lossy internet, with Salamander obfuscation.":"بر پایه‌ی QUIC، سریع روی اینترنت پرافت، با مبهم‌سازی Salamander.",
 "Queries":"درخواست‌ها",
 "Query log":"لاگ درخواست‌ها",
 "Question for the audience":"سؤال از مخاطب",
 "Quick actions":"کارهای سریع",
 "Quick add days":"افزودن روز سریع",
 "Quick add volume":"افزودن حجم سریع",
 "Quick setup":"ساخت سریع",
 "Quota of limited users":"مجموع سهمیه کاربران محدود",
 "RAM":"RAM",
 "RAM is almost full":"رم تقریباً پر است",
 "RAM is getting full":"رم دارد پر می‌شود",
 "REALITY with the XHTTP transport: requests are split and padded, so traffic volume and timing look like ordinary web downloads. Survives traffic-shape analysis better than raw TCP.":"REALITY با انتقال XHTTP: درخواست‌ها تکه‌تکه و پد می‌شوند تا حجم و زمان‌بندی ترافیک شبیه دانلودهای معمولی وب به نظر برسد. در برابر تحلیل شکل ترافیک بهتر از TCP خام دوام می‌آورد.",
 "Random free port":"پورت آزاد تصادفی",
 "Raw ping":"پینگ خام",
 "Raw ping (no tunnel)":"پینگ خام (بدون تانل)",
 "Reaches this server through":"از این مسیر به این سرور می‌رسد",
 "Read the site name from the traffic (needed for domain rules)":"اسم سایت را از ترافیک بخوان (برای قانون‌های دامنه لازم است)",
 "Ready values for the “New user” form":"مقدارهای آماده‌ی فرم «کاربر جدید»",
 "Ready-made rules":"قانون‌های آماده",
 "Recommended":"پیشنهادی",
 "Reconnect":"اتصال دوباره",
 "Reconnect all":"اتصال دوباره‌ی همه",
 "Reconnecting…":"در حال اتصال مجدد…",
 "Referral gift GB":"هدیه دعوت (GB)",
 "Referral gift days":"هدیه دعوت (روز)",
 "Referral reward":"هدیه دعوت دوستان",
 "Refresh":"بروزرسانی",
 "Refuse unknown SNI":"رد SNI ناشناس",
 "Refused (not a subscriber)":"رد شده (غیر مشتری)",
 "Regenerate":"ساخت دوباره",
 "Registered addresses and use":"IPهای ثبت‌شده و مصرف",
 "Relay (Iran)":"ریلی (ایران)",
 "Relay (inside Iran)":"ریلی (داخل ایران)",
 "Releases of this repository are used for updates, for “Update all” and for new tunnel servers.":"Releaseهای همین مخزن برای آپدیت پنل، «آپدیت همه» و نصب سرورهای تانل استفاده می‌شود.",
 "Remark":"نام",
 "Remove":"حذف",
 "Remove KANKI MIX from every user?":"KANKI MIX از همه‌ی کاربران برداشته شود؟",
 "Remove Xray from this server":"حذف Xray از این سرور",
 "Remove from DNS":"حذف از DNS",
 "Remove from all users":"حذف از همه‌ی کاربران",
 "Remove from every user?":"از همه‌ی کاربران برداشته شود؟",
 "Remove from this server":"حذف از این سرور",
 "Remove it (back to certbot)":"حذفش کن (برگشت به certbot)",
 "Remove it from this server? The server stops it and frees its ports.":"از این سرور حذف شود؟ سرور آن را متوقف می‌کند و پورت‌هایش آزاد می‌شود.",
 "Remove now":"همین الان پاک کن",
 "Remove the certificate (use HTTP)":"حذف گواهی (استفاده از HTTP)",
 "Remove the key":"حذف کلید",
 "Remove this node from ALL users?":"این نود از همه کاربران حذف شود؟",
 "Remove this server from all users":"حذف این سرور از همه‌ی کاربران",
 "Remove this server from the panel? Within a few seconds it removes everything Kanki installed there (tunnels, Kanki DNS, Xray, emergency chat, subscription link), closes the ports Kanki opened and uninstalls its agent.":"این سرور از پنل حذف شود؟ تا چند ثانیه‌ی دیگر هر چه کانکی رویش نصب کرده (تانل‌ها، DNS کانکی، Xray، چت اضطراری، لینک اشتراک) پاک می‌شود، پورت‌هایی که کانکی باز کرده بسته می‌شود و ایجنتش حذف می‌شود.",
 "Remove this stop":"حذف این ایستگاه",
 "Removed":"حذف شد",
 "Removes old logs, expired sessions and abandoned unpaid orders, then compacts the file. Users and plans are not touched.":"لاگ‌های قدیمی، نشست‌های منقضی و سفارش‌های پرداخت‌نشده‌ی رهاشده را پاک و فایل را فشرده می‌کند. به کاربران و پلن‌ها دست نمی‌زند.",
 "Removing…":"در حال حذف…",
 "Rename category":"تغییر نام دسته",
 "Repair":"تعمیر",
 "Repair agent":"تعمیر Agent",
 "Repair sent: the server has not reported for a while, it is repaired as soon as it is back":"تعمیر فرستاده شد: سرور مدتی است گزارش نداده؛ به محض برگشتن تعمیر می‌شود",
 "Repair sent: the server restarts it within a few seconds":"تعمیر فرستاده شد: سرور تا چند ثانیه‌ی دیگر سرویس را دوباره راه می‌اندازد",
 "Replace all plans":"جایگزینی همه‌ی پلن‌ها",
 "Replace the current settings with the file?":"تنظیمات فعلی با فایل جایگزین شود؟",
 "Replace the message":"جایگزین کردن پیام",
 "Replaces TUIC for users: same family (QUIC, UDP, 0-RTT). For a user-facing Hysteria2 service use the Kanki VPN page.":"جایگزین TUIC برای کاربران: همان خانواده (QUIC، UDP، ‏0-RTT). برای سرویس Hysteria2 روبه‌کاربر از صفحهٔ Kanki VPN استفاده کن.",
 "Reports":"گزارش",
 "Required channel":"کانال اجباری",
 "Required channel (empty = none)":"کانال اجباری (خالی = ندارد)",
 "Reset":"صفر کردن",
 "Reset the traffic of this inbound to zero?":"ترافیک این اینباند صفر شود؟",
 "Reset traffic":"ریست ترافیک",
 "Restart":"ری‌استارت",
 "Restart VPN services":"ری‌استارت سرویس‌های VPN",
 "Restore":"ریستور",
 "Restore backup":"ریستور بکاپ",
 "Restore done, panel is restarting…":"ریستور انجام شد، پنل در حال ری‌استارت است…",
 "Restored":"بازگردانی شد",
 "Restricted":"محدود",
 "Resume":"ادامه",
 "Revoke":"باطل کردن",
 "Reward days":"روزهای هدیه",
 "Reward volume (GB)":"حجم هدیه (گیگ)",
 "Rose":"صورتی",
 "Rotating":"چرخشی",
 "Rotating tunnel":"تانل چرخشی",
 "Round to":"گرد کردن به",
 "Route":"مسیر",
 "Route name":"اسم مسیر",
 "Route saved":"مسیر ذخیره شد",
 "Routed names asked for most since the DNS services started":"دامنه‌هایی که از شروع سرویس DNS بیشتر از همه پرسیده شده‌اند",
 "Routed only":"فقط مسیردهی‌شده",
 "Routing and outbounds":"روتینگ و خروجی‌ها",
 "Routing rules":"قانون‌های مسیریابی",
 "Routing through the link":"مسیریابی از داخل لینک",
 "Rule":"قانون",
 "Run one command on the new server (Ubuntu / Debian, as root). It installs only what a node needs and joins this panel by itself.":"روی سرور جدید (اوبونتو / دبیان، با کاربر root) فقط یک دستور بزن. فقط چیزهایی که نود لازم دارد نصب می‌شود و خودش به این پنل وصل می‌شود.",
 "Run this on the new server":"این را روی سرور جدید اجرا کن",
 "Run this on the new server (Ubuntu / Debian, as root)":"این را روی سرور جدید اجرا کن (اوبونتو / دبیان، با root)",
 "Run this on the new server, as root (Ubuntu / Debian)":"این را روی سرور جدید اجرا کن، با root (اوبونتو / دبیان)",
 "Run this on the server, as root (Ubuntu / Debian)":"این را روی سرور با کاربر root اجرا کن (اوبونتو / دبیان)",
 "Running":"در حال اجرا",
 "Running servers":"سرورهای فعال",
 "Runs inside the panel":"داخل خود پنل اجرا می‌شود",
 "SNI":"SNI",
 "SNI (TLS name)":"SNI (اسم TLS)",
 "SNI (name)":"SNI (اسم)",
 "SNI names (TLS hello)":"اسم‌های SNI (داخل دست‌دادن TLS)",
 "SNI names (comma separated, empty = same as Host)":"نام‌های SNI (با ویرگول؛ خالی = همان Host)",
 "SNI spoof":"SNI اسپوف",
 "SNI spoof / Host (wss, quic, ws)":"جعل SNI / Host (wss، quic، ws)",
 "SNI spoof: the TLS hello shows another site name. It only helps when the filter decides by name; it does nothing if the IP is blocked.":"SNI اسپوف: در دست‌دادن TLS اسم یک سایت دیگر نشان داده می‌شود. فقط وقتی کمک می‌کند که فیلتر بر اساس اسم تصمیم بگیرد؛ اگر خود آی‌پی بسته باشد اثری ندارد.",
 "SSL (port 80)":"SSL (پورت ۸۰)",
 "SSL certificate (optional, recommended)":"گواهی SSL (اختیاری، پیشنهادی)",
 "SSL from the CDN (ArvanCloud)":"SSL از CDN (ابرآروان)",
 "Sales & support":"فروش و پشتیبانی",
 "Sales bot":"ربات فروش",
 "Sales enabled":"فروش فعال باشد",
 "Sales on":"فروش فعال",
 "Sales panels are added from inside Telegram":"پنل‌های فروش از داخل تلگرام اضافه می‌شوند",
 "Sales settings":"تنظیمات فروش",
 "Same as Kanki DNS":"همان DNS کانکی",
 "Same fronting idea over HTTP/2 gRPC: many streams inside long-lived HTTP/2 connections, which matches API traffic patterns. Needs a CDN that passes gRPC to the origin over HTTPS (ArvanCloud and Cloudflare do); the server uses its own certificate.":"همان ایدهٔ فرانتینگ روی gRPC با HTTP/2: استریم‌های زیاد داخل اتصال‌های HTTP/2 طولانی، شبیه الگوی ترافیک API. به CDN‌ای نیاز دارد که gRPC را با HTTPS به مبدأ برساند (ابرآروان و Cloudflare می‌رسانند)؛ سرور از گواهی خودش استفاده می‌کند.",
 "Save":"ذخیره",
 "Save & apply":"ذخیره و اعمال",
 "Save and restore everything":"ذخیره و بازگردانی همه چیز",
 "Save changes":"ذخیره تغییرات",
 "Save it as the file below in /etc/amnezia/amneziawg/ and run awg-quick up. It holds a private key: do not share it.":"با همین نام فایل در /etc/amnezia/amneziawg/ ذخیره کن و awg-quick up بزن. کلید خصوصی دارد؛ جایی منتشرش نکن.",
 "Save port":"ذخیره‌ی پورت",
 "Save routing":"ذخیره‌ی روتینگ",
 "Save sales settings":"ذخیره تنظیمات فروش",
 "Save security policy":"ذخیره سیاست امنیت",
 "Save services":"ذخیره سرویس‌ها",
 "Save settings":"ذخیره تنظیمات",
 "Save the route":"ذخیره‌ی مسیر",
 "Saved":"ذخیره شد",
 "Saved at once. Shown in the header, the menu, the login page and the subscription page.":"همان لحظه ذخیره می‌شود. در بالای پنل، منو، صفحه‌ی ورود و صفحه‌ی اشتراک دیده می‌شود.",
 "Saved: getting SSL (about a minute)":"ذخیره شد: در حال گرفتن SSL (حدود یک دقیقه)",
 "Saved: the DNS servers use it within a few seconds":"ذخیره شد: سرورهای DNS تا چند ثانیه‌ی دیگر از آن استفاده می‌کنند",
 "Saved: the server sets it up in a few seconds":"ذخیره شد: سرور تا چند ثانیه‌ی دیگر راه‌اندازی‌اش می‌کند",
 "Saved: the service restarts on the new port":"ذخیره شد: سرویس روی پورت جدید ری‌استارت می‌شود",
 "Saved: the tunnel restarts with the new settings":"ذخیره شد: تانل با تنظیمات جدید دوباره وصل می‌شود",
 "Saving…":"در حال ذخیره…",
 "Scan with your authenticator app, then enter the 6-digit code":"با برنامه احراز هویت اسکن کن و کد ۶ رقمی را وارد کن",
 "Scopes":"دسترسی‌ها",
 "Score":"امتیاز",
 "Scores follow your profile (gaming, balanced, ultra speed)":"نمره‌ها بر اساس پروفایل شما (گیمینگ، متعادل، اولترا اسپید) حساب می‌شوند",
 "Search":"جستجو",
 "Search by name or note…":"جستجو بر اساس نام یا یادداشت…",
 "Search services or domains":"جستجوی سرویس یا دامنه",
 "Second config through the tunnel":"کانفیگ دوم از راه تانل",
 "Security":"امنیت",
 "Select":"انتخاب",
 "Select all":"انتخاب همه",
 "Self-signed certificate (no domain on node)":"گواهی خودامضا (نود بدون دامنه)",
 "Self-signed certificate (no domain on the server)":"گواهی خودامضا (بدون دامنه روی سرور)",
 "Send backup now":"ارسال بکاپ الان",
 "Send every packet twice":"هر بسته دو بار فرستاده شود",
 "Send to":"بفرست به",
 "Send to the app":"ارسال به اپ",
 "Sent":"ارسال شد",
 "Sent: the server closes them on its next report (a few seconds)":"فرستاده شد: سرور در گزارش بعدی (چند ثانیه) آن‌ها را می‌بندد",
 "Sent: the server frees the ports on its next report (a few seconds)":"فرستاده شد: سرور در گزارش بعدی (چند ثانیه) پورت‌ها را آزاد می‌کند",
 "Sent: the server tries SSL again within a minute":"فرستاده شد: سرور تا یک دقیقه‌ی دیگر دوباره SSL می‌گیرد",
 "Separate backup bot (optional)":"ربات جدا برای بکاپ (اختیاری)",
 "Separate subscription domain":"دامنه‌ی جدا برای لینک ساب",
 "Serve VPN users on this server":"به کاربران VPN از این سرور سرویس بده",
 "Serve the subscription from an Iran server":"لینک ساب روی سرور ایران",
 "Serve users once installed":"بعد از نصب به کاربران سرویس بده",
 "Server":"سرور",
 "Server agent connected":"ایجنت سرور وصل شد",
 "Server alerts":"هشدار سرورها",
 "Server inside Iran":"سرور داخل ایران",
 "Server name":"نام سرور",
 "Server names":"نام‌های سرور",
 "Server resources":"منابع سرور",
 "Server settings":"تنظیمات سرور",
 "Server-to-server transports":"انتقال‌های سرور‌به‌سرور",
 "Servers":"سرورها",
 "Servers & network":"سرورها و شبکه",
 "Servers online":"سرورهای آنلاین",
 "Servers that only carry tunnels get a small agent: no VPN is installed on them":"روی سرورهایی که فقط تانل دارند یک عامل کوچک نصب می‌شود؛ هیچ VPN نصب نمی‌شود",
 "Service":"سرویس",
 "Service name":"نام سرویس",
 "Service stopped":"سرویس خاموش است",
 "Services":"سرویس‌ها",
 "Services of this user":"سرویس‌های این کاربر",
 "Session lifetime (hours)":"عمر Session (ساعت)",
 "Set records and get the certificate now":"الان رکوردها را بساز و گواهی بگیر",
 "Set the price rules once; every plan gets a fair price automatically.":"قوانین قیمت را یک‌بار تعیین کن؛ هر پلن خودکار قیمت منصفانه می‌گیرد.",
 "Set the update source (GitHub repo) in Settings first, or replace USER/REPO in the command.":"اول منبع آپدیت (مخزن گیت‌هاب) را در تنظیمات بگذار، یا USER/REPO را در دستور عوض کن.",
 "Set up SSL and use it":"گرفتن SSL و استفاده",
 "Settings":"تنظیمات",
 "Settings and SSL":"تنظیمات و SSL",
 "Settings are filled in: check the port and press Save":"تنظیمات پر شد: پورت را چک کن و ذخیره را بزن",
 "Several names, comma separated: every link uses another one and a link that fails moves to the next. Empty = the server address.":"چند اسم با کاما: هر اتصال یکی را برمی‌دارد و اتصالی که قطع شود سراغ بعدی می‌رود. خالی = آدرس خود سرور.",
 "Several servers in one link, automatic switch when one is blocked":"چند سرور در یک لینک، تعویض خودکار وقتی یکی بسته شد",
 "Shadowsocks has no TLS or REALITY: its own encryption is enough.":"Shadowsocks نیازی به TLS یا REALITY ندارد: رمزنگاری خودش کافی است.",
 "Short IDs":"Short ID ها",
 "Short punch":"جمله‌ی کوتاه و جذاب",
 "Show":"نمایش",
 "Show all":"نمایش همه",
 "Show command":"نمایش دستور",
 "Show for":"مدت نمایش",
 "Show the config of the entry":"نمایش کانفیگ ورودی",
 "Show the config of the exit":"نمایش کانفیگ خروجی",
 "Show the last result":"نمایش نتیجه‌ی قبلی",
 "Showing in the app":"در حال نمایش در اپ",
 "Shown in the bot":"در ربات نمایش داده می‌شود",
 "Shown in the header, the side menu, the login page and the subscription page.":"در هدر، منو، صفحه ورود و صفحه اشتراک نمایش داده می‌شود.",
 "Shown in the menu, the browser tab and the login page.":"در منو، تب مرورگر و صفحه‌ی ورود نشان داده می‌شود.",
 "Side menu":"منوی کنار",
 "Sign in to continue":"برای ادامه وارد شو",
 "Signature (empty = bot link)":"امضا (خالی = لینک ربات)",
 "Signing key":"کلید امضا",
 "Site shown to strangers (without obfuscation)":"سایتی که به غریبه‌ها نشان داده می‌شود (بدون مبهم‌سازی)",
 "Smart DNS abroad":"DNS هوشمند در خارج",
 "Smart channel":"کانال هوشمند",
 "Smart choice":"انتخاب هوشمند",
 "Smart plan builder":"سازنده‌ی پلن هوشمند",
 "Smart tunnel":"تانل هوشمند",
 "Sniffed protocol":"پروتکل تشخیص‌داده‌شده",
 "Sniffing":"Sniffing",
 "Soft light":"روشن ملایم",
 "Some users are not on this server yet (config mismatch): press Sync":"بعضی کاربرها هنوز روی این سرور نیستند (اختلاف کانفیگ): همگام‌سازی را بزن",
 "Sort":"مرتب‌سازی",
 "Speed limit per user":"محدودیت سرعت برای هر کاربر",
 "Split the TLS hello into tiny pieces":"تکه‌تکه کردن TLS hello",
 "Start":"روشن",
 "Start the campaign":"شروع کمپین",
 "Start the test":"شروع تست",
 "Start, stop or restart the VPN services":"سرویس‌های VPN را روشن، خاموش یا ری‌استارت کن",
 "Starting…":"در حال شروع…",
 "Status":"وضعیت",
 "Status of the DNS servers":"وضعیت سرورهای DNS",
 "Steady, works almost everywhere":"پایدار، تقریباً همه‌جا",
 "Stop":"ایستگاه",
 "Stop and turn off __U__ on this server? Then __S__ takes its ports.":"__U__ روی این سرور خاموش و غیرفعال شود؟ بعد __S__ پورت‌هایش را می‌گیرد.",
 "Stop the test":"توقف تست",
 "Stopped":"متوقف",
 "Stops on (empty = never)":"تاریخ توقف (خالی = هرگز)",
 "Storage":"فضای ذخیره",
 "Story":"داستان کوتاه",
 "Straight to the internet from this server":"مستقیم از همین سرور به اینترنت",
 "Subscription":"لینک ساب",
 "Subscription base URL":"آدرس پایه اشتراک",
 "Subscription link":"لینک اشتراک",
 "Successful / failed logins (secrets never stored)":"ورود موفق/ناموفق بدون ثبت رمز یا Secret",
 "Suggestions":"پیشنهادها",
 "Support ID":"آیدی پشتیبانی",
 "Swap":"Swap",
 "Switch the VPN off on this server? Its users are taken off; it keeps carrying tunnels.":"VPN این سرور خاموش شود؟ کاربرانش برداشته می‌شوند؛ تانل‌ها کار می‌کنند.",
 "Switch the VPN on: users that accept all servers are sent here.":"VPN روشن شود: کاربرانی که همه‌ی سرورها را دارند به این سرور هم فرستاده می‌شوند.",
 "Sync":"همگام‌سازی",
 "Sync users without a specific node to this node":"کاربران بدون نود مشخص را روی این نود همگام کن",
 "Synced":"همگام",
 "System":"سیستم",
 "TCP / UDP connections":"اتصال‌های TCP / UDP",
 "TCP Mux has no site name: it is encrypted from the first byte, so there is nothing to disguise.":"TCP Mux اسم سایت ندارد: از اولین بایت رمزنگاری‌شده است، پس چیزی برای پوشاندن ندارد.",
 "TCP has no site name: it is encrypted from the first byte, so there is nothing to disguise.":"TCP اسم سایت ندارد: از اولین بایت رمزنگاری‌شده است، پس چیزی برای پوشاندن ندارد.",
 "TCP listening":"TCP در حال گوش‌دادن",
 "TCP works but UDP does not pass well: WireGuard / Hysteria2 may suffer":"TCP کار می‌کند ولی UDP خوب رد نمی‌شود: وایرگارد و هیستریا۲ ممکن است ضعیف شوند",
 "TLS 1.3 with the ALPN, ciphers and HTTP/2 settings of a browser; a stranger who opens the site gets an ordinary web page. Use port 443.":"TLS 1.3 با ALPN، رمزها و تنظیمات HTTP/2 شبیه مرورگر؛ کسی که سایت را باز کند یک صفحهٔ وب معمولی می‌بیند. از پورت 443 استفاده کن.",
 "TLS at the CDN":"TLS در CDN",
 "TLS looks filtered: plain WebSocket passes but WSS does not":"TLS احتمالاً فیلتر شده: WebSocket ساده رد می‌شود ولی WSS نه",
 "TLS name":"نام TLS",
 "TON wallet address (Tonkeeper…)":"آدرس کیف پول TON (تون‌کیپر…)",
 "TOTP with apps like Google Authenticator / 2FAS":"TOTP با برنامه‌هایی مثل Google Authenticator / 2FAS",
 "TTI (ms)":"TTI (میلی‌ثانیه)",
 "TUIC and ShadowTLS are not in Xray-core; Hysteria2 (QUIC + obfs) and the hq transport cover the same ground.":"TUIC و ShadowTLS در هستهٔ Xray نیستند؛ Hysteria2 (QUIC + obfs) و انتقال hq همان کار را می‌کنند.",
 "Tag (name)":"تگ (اسم)",
 "Take from all users":"غیرفعال برای همه‌ی کاربران",
 "Taken with certbot on the server":"با certbot روی خود سرور گرفته می‌شود",
 "Takes about 2 minutes. Ports":"حدود ۲ دقیقه طول می‌کشد. پورت‌های",
 "Takes about a minute. Ports":"حدود یک دقیقه طول می‌کشد. پورت‌های",
 "Talk to users when the internet is cut":"گفتگو با کاربرها وقتی اینترنت قطع است",
 "Talk to your customers and send them configs when the international internet is cut":"وقتی اینترنت بین‌الملل قطع است با مشتری‌ها حرف بزن و کانفیگ بفرست",
 "Target (dest)":"مقصد (dest)",
 "Target on the exit":"مقصد روی سرور خروجی",
 "Telegram alert when a node or tunnel goes offline":"هشدار تلگرام وقتی نود یا تانل آفلاین شد",
 "Telegram auto backup":"بکاپ خودکار تلگرام",
 "Telegram message to the bot admins when a node, tunnel server or tunnel goes offline, and when it is back.":"وقتی نود، سرور تانل یا تانلی قطع و دوباره وصل شود، به ادمین‌های ربات پیام می‌رود.",
 "Telegram messages for you and for your buyers":"پیام‌های تلگرامی برای خودت و خریدارها",
 "Telegram sales bot":"ربات فروش تلگرام",
 "Tells which ones did not pass and probably why":"می‌گوید کدام‌ها رد نشدند و احتمالاً چرا",
 "Test":"تست",
 "Test again":"تست دوباره",
 "Test connection":"تست اتصال",
 "Test every hop":"تست همه‌ی مرحله‌ها",
 "Test ports (first of six)":"پورت تست (اولینِ شش پورت)",
 "Test ports (first of sixteen)":"پورت‌های تست (اولی از شانزده)",
 "Test ports (first of the range)":"پورت‌های تست (اول محدوده)",
 "Test ports (first of twelve)":"پورت‌های تست (اولی از دوازده)",
 "Test the key":"تست کلید",
 "Test the sites":"تست سایت‌ها",
 "Tested from the panel server: TLS 1.3, a valid certificate and HTTP/2. Tap one to use it.":"از سرور پنل تست شد: TLS 1.3، گواهی معتبر و HTTP/2. روی یکی بزن تا انتخاب شود.",
 "Testing…":"در حال تست…",
 "Tests all six transports between two servers (ping, TCP download / upload, UDP loss) and tells you which one is best for this route.":"هر شش روش تانل را بین دو سرور تست می‌کند (پینگ، دانلود و آپلود TCP، افت UDP) و می‌گوید کدام برای این مسیر بهترین است.",
 "Tests every transport (TCP, KCP, WS, WSS, QUIC) in both directions between two servers, scores each one from 0 to 100 for your profile and tells you which is best and why. No tunnel is created and nothing changes on the servers.":"همه‌ی ترنسپورت‌ها (TCP، KCP، WS، WSS، QUIC) در هر دو جهت بین دو سرور امتحان می‌شوند، برای پروفایل تو از ۰ تا ۱۰۰ نمره می‌گیرند و بهترین با دلیلش پیشنهاد می‌شود. تانلی ساخته نمی‌شود و چیزی روی سرورها عوض نمی‌شود.",
 "Text shown to the buyer":"متنی که به خریدار نشان داده می‌شود",
 "The AI works":"هوش مصنوعی کار می‌کند",
 "The AmneziaWG packets travel inside the transport chosen below (WebSocket, WSS, CDN, QUIC, KCP, TCP Mux), so the network only sees that transport. Best for strong filtering.":"بسته‌های AmneziaWG داخل ترنسپورتی که پایین انتخاب می‌کنی (وب‌سوکت، WSS، CDN، QUIC، KCP، TCP Mux) رد می‌شوند و شبکه فقط همان ترنسپورت را می‌بیند. برای فیلترینگ سنگین بهترین است.",
 "The CDN has the certificate; the server itself speaks plain WS / gRPC / XHTTP":"گواهی دست CDN است؛ خود سرور WS / gRPC / XHTTP ساده دارد",
 "The QUIC hello carries a site name too (default www.cloudflare.com).":"دست‌دادن QUIC هم اسم سایت دارد (پیش‌فرض www.cloudflare.com).",
 "The TCP stream starts like a plain HTTP request (path and Host above)":"اتصال TCP مثل یک درخواست HTTP ساده شروع می‌شود (path و Host بالا)",
 "The agent of this server is old: press “Update all” in Tunnel servers first.":"ایجنت این سرور قدیمی است: اول در «سرورهای تانل» دکمه‌ی «آپدیت همه» را بزن.",
 "The app picks the message up when it is opened, then every 30 seconds while connected (every 5 minutes when not). A user who closes the message will not see it again; a new message is shown again.":"اپ پیام را موقع باز شدن می‌گیرد؛ بعد وقتی وصل است هر ۳۰ ثانیه و وقتی وصل نیست هر ۵ دقیقه. کاربری که پیام را ببندد دیگر آن را نمی‌بیند؛ پیام جدید دوباره نشان داده می‌شود.",
 "The app's «Amnezia Direct» config of a server behind the tunnel goes straight to the server through its own name. Make each name below an A record pointing at the IP next to it (in Cloudflare: DNS only, grey cloud). Until a name points at the right server, the app is given the server's own address, so a direct config never reaches the wrong server.":"کانفیگ «Amnezia مستقیم» هر سروری که پشت تانل است، با اسم خودش مستقیم به همان سرور وصل می‌شود. برای هر اسم زیر یک رکورد A بساز که به آی‌پی کنارش اشاره کند (در کلادفلر: فقط DNS، ابر خاکستری). تا وقتی اسمی درست تنظیم نشده، آدرس خود سرور به برنامه داده می‌شود؛ پس کانفیگ مستقیم هیچ‌وقت به سرور اشتباه نمی‌رود.",
 "The backup above is complete too: it can also be restored by hand on a new server (Restore with «Also restore server keys»).":"بکاپ بالا هم کامل است: می‌شود آن را دستی هم روی سرور جدید برگرداند (بازگردانی با تیک «کلیدها و تنظیمات سرور»).",
 "The bot writes and publishes posts in your channel by itself: prices, offers, tips, guides, trials and occasion greetings. Make the bot an admin of the channel.":"ربات خودش در کانالت پست می‌نویسد و منتشر می‌کند: قیمت‌ها، تخفیف‌ها، نکته‌ها، آموزش، تست رایگان و تبریک مناسبت‌ها. ربات را ادمین کانال کن.",
 "The buyer gets a message before his time or data runs out.":"قبل از تمام شدن زمان یا حجم، به خریدار پیام می‌رود.",
 "The buyer sees the amount in dollars and in TON (at today's price), your addresses to copy and a Tonkeeper button, then sends the receipt or TXID for you to approve. Plans without a dollar price get it from the toman price at this rate; with no rate and no dollar price, crypto is not offered for that plan.":"خریدار مبلغ را به دلار و به TON (با قیمت امروز)، آدرس‌هایت را برای کپی و دکمه‌ی تون‌کیپر می‌بیند و بعد رسید یا TXID را می‌فرستد تا تأیید کنی. پلنی که قیمت دلاری ندارد، قیمتش از روی تومان با همین نرخ حساب می‌شود؛ بدون نرخ و بدون قیمت دلاری، پرداخت ارزی برای آن پلن نشان داده نمی‌شود.",
 "The command expired. Create a new one.":"دستور منقضی شد. یکی جدید بساز.",
 "The direct direction (entry → exit) is closed: the entry cannot dial the exit. Use the reverse direction.":"جهت مستقیم (ورودی ← خروجی) بسته است: ورودی نمی‌تواند به خروجی وصل شود. از جهت معکوس استفاده کن.",
 "The domain fronts through a CDN (ArvanCloud, Cloudflare, …). The filter only sees HTTPS to the CDN edge — the real server IP never appears. Works in whitelist mode if the CDN edge is reachable.":"دامنه از پشت CDN (ابرآروان، کلادفلر و…) عبور می‌کند. فیلتر فقط HTTPS به لبهٔ CDN را می‌بیند — آی‌پی واقعی سرور هرگز دیده نمی‌شود. اگر لبهٔ CDN در دسترس باشد، در حالت لیست سفید هم کار می‌کند.",
 "The domain's A record must point to this Iran server's IP (not to a CDN while the certificate is taken: in ArvanCloud / Cloudflare set it to DNS only).":"رکورد A دامنه باید به آی‌پی همین سرور ایران اشاره کند (موقع گرفتن گواهی پشت CDN نباشد: در ابرآروان / کلادفلر روی «فقط DNS» بگذار).",
 "The domain's A record must point to this server's IP":"رکورد A دامنه باید به IP این سرور اشاره کند",
 "The entry and the exit must be different":"ورودی و خروجی باید دو سرور متفاوت باشند",
 "The exit does NAT (masquerade)":"خروجی NAT می‌کند (masquerade)",
 "The exit runs a Hysteria2 server, the entry connects to it (QUIC over UDP, fast on lossy internet). The panel makes the password and a certificate and the entry checks its fingerprint. The agents install Hysteria2 by themselves; your VPN Hysteria2 is not touched.":"سرور خروجی یک سرور هیستریا ۲ اجرا می‌کند و سرور ورودی به آن وصل می‌شود (QUIC روی UDP، روی اینترنت پرافت هم سریع). پنل رمز و گواهی را می‌سازد و ورودی اثر انگشت گواهی را چک می‌کند. ایجنت‌ها هیستریا را خودشان نصب می‌کنند؛ به هیستریای کاربران VPN دست نمی‌زند.",
 "The first copy that arrives wins; near-zero visible loss, double traffic":"اولین نسخه‌ای که برسد برنده است؛ لاست تقریباً صفر، ترافیک دو برابر",
 "The full token is shown only once.":"توکن کامل فقط یک بار نمایش داده می‌شود.",
 "The lightweight stealth UDP cover: no TLS overhead, no handshake, minimal per-packet cost.":"پوشش سبک و مخفی UDP: بدون سربار TLS، بدون دست‌دادن، کمترین هزینهٔ هر بسته.",
 "The new server downloaded the backup":"سرور جدید بکاپ را گرفت",
 "The node's certificate changed (reinstalled?): run its join command again, or remove and add the node":"گواهی نود عوض شده (دوباره نصب شده؟): دستور اتصال نود را دوباره اجرا کن، یا نود را حذف و دوباره اضافه کن",
 "The panel IP could not be found from its address. Type it in the GRE box (Edit server) and make the command again.":"آی‌پی پنل از روی آدرسش پیدا نشد. آن را در کادر GRE (ویرایش سرور) بنویس و دوباره دستور بساز.",
 "The panel address is an IP, so the agent keeps using it. To send the agent through the link make a new command (Command button of the server).":"آدرس پنل آی‌پی است و ایجنت همان را نگه می‌دارد. برای عبور ایجنت از لینک، دستور تازه بساز (دکمهٔ دستور سرور).",
 "The panel installs the emergency chat on that server by itself and keeps the list of your customers there while the internet works.":"پنل خودش چت اضطراری را روی همان سرور نصب می‌کند و تا وقتی اینترنت وصل است، لیست مشتری‌ها را آن‌جا به‌روز نگه می‌دارد.",
 "The panel makes the A records of every server (and *.) with this API token, then gets a wildcard certificate from Let's Encrypt with a DNS challenge and renews it every 60 days. Works for servers inside Iran too.":"پنل با این توکن API رکورد A هر سرور (و *.) را می‌سازد، بعد با چالش DNS از Let's Encrypt گواهی Wildcard می‌گیرد و هر ۶۰ روز تمدید می‌کند. برای سرورهای داخل ایران هم کار می‌کند.",
 "The panel on the old server still runs the same Telegram bot: both answer customers and both post to the channel. Stop it there: systemctl disable --now kanki-panel":"پنل روی سرور قبلی هنوز همین ربات تلگرام را اجرا می‌کند: هر دو به مشتری‌ها جواب می‌دهند و هر دو در کانال پست می‌گذارند. آن‌جا خاموشش کن: systemctl disable --now kanki-panel",
 "The panel points the domain at this server and gets a Let's Encrypt certificate; every TLS inbound of this server uses it. Renewed every 60 days.":"پنل دامنه را به همین سرور وصل می‌کند و از Let's Encrypt گواهی می‌گیرد؛ همه‌ی اینباندهای TLS این سرور از آن استفاده می‌کنند. هر ۶۰ روز تمدید می‌شود.",
 "The panel restarts for a few seconds after saving.":"بعد از ذخیره، پنل چند ثانیه ری‌استارت می‌شود.",
 "The panel runs on one server. Every other server is a node: add it with one command, then switch on here what it runs.":"پنل روی یک سرور نصب است. هر سرور دیگر یک نود است: با یک دستور اضافه‌اش کن و بعد همین‌جا روشن کن که چه چیزی رویش اجرا شود.",
 "The port is closed or this direction is blocked: check the cloud firewall":"پورت بسته است یا این جهت مسدود است: فایروال سرویس‌دهنده را چک کن",
 "The ports are free on the servers":"پورت‌ها روی سرورها آزادند",
 "The reverse direction (exit → entry) is closed: the entry cannot be reached from the exit. Use the direct direction.":"جهت معکوس (خروجی ← ورودی) بسته است: خروجی نمی‌تواند به ورودی برسد. از جهت مستقیم استفاده کن.",
 "The route is made: it connects in a few seconds":"مسیر ساخته شد: تا چند ثانیه‌ی دیگر وصل می‌شود",
 "The same ports on every hop: users reach them on the first server and land on the same ports of the last one.":"روی همه‌ی مرحله‌ها همین پورت‌ها: کاربر به این پورت‌ها روی سرور اول وصل می‌شود و به همان پورت‌ها روی سرور آخر می‌رسد.",
 "The server agent, VPN and their health in one place: press a service to open its page.":"ایجنت، VPN و سلامت هر سرور یک‌جا؛ روی هر سرویس بزن تا صفحه‌اش باز شود.",
 "The server gets and renews a free certificate by itself. Do it before the internet is cut. Port 80 of the server must be free and the domain must point to it (ArvanCloud: DNS or CDN both work).":"سرور خودش گواهی رایگان می‌گیرد و تمدید می‌کند. قبل از قطعی اینترنت انجامش بده. پورت ۸۰ سرور باید آزاد باشد و دامنه به آن اشاره کند (ابرآروان: هم DNS هم CDN کار می‌کند).",
 "The server has not said which ports are free yet (update it to 3.7)":"سرور هنوز نگفته کدام پورت‌ها آزادند (آن را به ۳.۷ آپدیت کن)",
 "The server is not connected right now":"این سرور الان وصل نیست",
 "The server is not reporting: check that it is on and that its agent runs, then press Repair":"سرور گزارش نمی‌دهد: روشن بودن سرور و اجرای Agent آن را چک کن، بعد «تعمیر» را بزن",
 "The strongest known anti-DPI method. The server borrows the TLS certificate of a real site (Microsoft, Apple, …) in real time: to the filter the connection IS a TLS session to that site. No domain, no certificate of your own, nothing to block by name.":"قوی‌ترین روش شناخته‌شده ضد DPI. سرور گواهی TLS یک سایت واقعی (مایکروسافت، اپل و…) را لحظه‌ای قرض می‌گیرد: برای فیلتر، اتصال همان نشست TLS به آن سایت است. نه دامنه لازم است، نه گواهی خودت؛ چیزی برای مسدودکردن با اسم نیست.",
 "The tunnel is made: it connects in a few seconds":"تانل ساخته شد: تا چند ثانیه‌ی دیگر وصل می‌شود",
 "The tunnel reconnects in a few seconds":"تانل تا چند ثانیه‌ی دیگر دوباره وصل می‌شود",
 "The user's phone registers again by itself; someone else using the address loses access. Continue?":"گوشی کاربر خودش دوباره ثبت می‌کند؛ اگر کس دیگری از این IP استفاده می‌کند دسترسی‌اش قطع می‌شود. ادامه بدهم؟",
 "The whole outbound (JSON object)":"کل اوت‌باند (آبجکت JSON)",
 "Theme":"پوسته",
 "These agents are too old to update remotely. Run the command kanki on them and choose 3 (Update) once:":"این ایجنت‌ها برای آپدیت از راه دور قدیمی‌اند. روی آن‌ها دستور kanki را بزن و گزینهٔ 3 (Update) را انتخاب کن (فقط یک‌بار):",
 "These live in the tunnel wizard; they carry whole VPNs between your Iran and foreign servers.":"این‌ها در ویزارد تانل هستند؛ VPN کامل را بین سرور ایران و خارج حمل می‌کنند.",
 "These messages are sent by the sales bot; set it up first in":"این پیام‌ها را ربات فروش می‌فرستد؛ اول آن را راه بینداز در",
 "These ports are already taken on the server":"این پورت‌ها روی سرور گرفته شده‌اند",
 "These sites go down with it":"این سایت‌ها هم از دسترس خارج می‌شوند",
 "These tunnels use this server:":"این تانل‌ها از این سرور استفاده می‌کنند:",
 "This is not a settings file":"این فایل تنظیمات نیست",
 "This is the base ping of the route; a good tunnel stays close to it.":"این پینگ پایه‌ی مسیر است؛ تانل خوب نزدیک به همین می‌ماند.",
 "This port is already used by another tunnel":"این پورت را تانل دیگری دارد",
 "This server has no domain: write one in SNI, or give the server a domain (Edit server).":"این سرور دامنه ندارد: یا در SNI دامنه بنویس، یا برای سرور دامنه بگذار (ویرایش سرور).",
 "This server's IP (empty = found by itself)":"آی‌پی همین سرور (خالی = خودکار)",
 "This server's own address":"آدرس خود این سرور",
 "This tag is already used":"این تگ قبلاً استفاده شده",
 "This transport is filtered on the route while others pass":"این ترنسپورت روی مسیر فیلتر شده در حالی که بقیه رد می‌شوند",
 "Through":"از راه",
 "Through a tunnel":"از راه تانل",
 "Through the tunnel (Iran server)":"از تانل (سرور ایران)",
 "Through the tunnels":"عبوری از تانل‌ها",
 "Tick it for a user (user form, or Enable for all users). Every server runs it by itself within a minute; the Kanki app gets the link from the subscription. Each user has their own key: a new link is a new key, an expired or disabled user is cut off at once. Open the port at the data center's firewall too.":"برای کاربر تیکش را بزن (فرم کاربر، یا «روشن برای همه‌ی کاربران»). هر سرور ظرف یک دقیقه خودش اجرایش می‌کند؛ اپ کانکی لینک را از اشتراک می‌گیرد. هر کاربر کلید خودش را دارد: لینک تازه یعنی کلید تازه، کاربر منقضی یا غیرفعال فوراً قطع می‌شود. پورت را در فایروال دیتاسنتر هم باز کن.",
 "Tip":"نکته",
 "To bring it back":"برای برگرداندن",
 "Token":"توکن",
 "Token is required":"توکن لازم است",
 "Token name":"نام توکن",
 "Toman":"تومان",
 "Toman per dollar (for plans without a dollar price)":"نرخ دلار به تومان (برای پلن‌های بدون قیمت دلاری)",
 "Too big for the bot (over 50 MB): only on the subscription page":"برای ربات بزرگ است (بیش از ۵۰ مگ): فقط در صفحه‌ی اشتراک",
 "Top menu":"منوی بالا",
 "Torrent traffic gets abuse reports to your servers":"تورنت برای سرورهایت گزارش تخلف می‌آورد",
 "Total ping":"پینگ کل",
 "Total recorded usage":"مصرف کل ثبت‌شده",
 "Total since boot":"مجموع از بوت",
 "Total traffic":"ترافیک کل",
 "Total traffic of the inbound (GB, 0 = unlimited)":"حجم کل اینباند (گیگ، ۰ = نامحدود)",
 "Total users":"کل کاربران",
 "Total volume (0 = unlimited)":"حجم کل (صفر = نامحدود)",
 "Traffic":"ترافیک",
 "Traffic & stats":"ترافیک و آمار",
 "Traffic leaves here":"ترافیک از اینجا بیرون می‌رود",
 "Traffic used up":"حجم تمام شد",
 "Transport":"ترنسپورت",
 "Transport to the exit":"ترنسپورت تا خروجی",
 "Trial GB":"حجم تست (GB)",
 "Trial days":"روز تست",
 "Trial volume (GB)":"حجم تست (گیگ)",
 "Tries masked QUIC first and switches to HTTP/2 over TLS by itself when UDP does not pass. Open the port on UDP and TCP; port 443 is best.":"اول QUIC ماسک‌شده را امتحان می‌کند و اگر UDP رد نشد خودکار به HTTP/2 روی TLS می‌رود. پورت را هم روی UDP و هم روی TCP باز کن؛ پورت 443 بهترین است.",
 "Try SSL again":"دوباره گرفتن SSL",
 "Try again":"دوباره",
 "Try now":"الان امتحان کن",
 "Tunnel":"تانل",
 "Tunnel agent settings":"تنظیمات ایجنت (آدرس، GRE)",
 "Tunnel domain":"دامنه‌ی تانل",
 "Tunnel domain (optional)":"دامنه‌ی تانل (اختیاری)",
 "Tunnel port":"پورت تانل",
 "Tunnel port on the relay":"پورت تانل روی ریلی",
 "Tunnel server":"سرور تانل",
 "Tunnel servers":"سرورهای تانل",
 "Tunnel servers (updating by themselves)":"سرورها (خودشان آپدیت می‌شوند)",
 "Tunnel to the panel":"تانل به پنل",
 "Tunnel type":"نوع تانل",
 "Tunnels":"تانل‌ها",
 "Tunnels connected":"تانل‌های وصل",
 "Tunnels count":"تانل",
 "Tunnels page":"صفحه‌ی تانل‌ها",
 "Tunnels up":"تانل‌های وصل",
 "Tunnels, Xray and DNS are not installed on this server":"تانل، Xray و DNS روی این سرور نصب نیست",
 "Turn it on":"روشنش کن",
 "Turn off __P__ for ALL users? It leaves every subscription.":"__P__ برای همه‌ی کاربران خاموش شود؟ از اشتراک همه برداشته می‌شود.",
 "Turn on __P__ for ALL users? Every user gets it in the subscription.":"__P__ برای همه‌ی کاربران روشن شود؟ در اشتراک همه اضافه می‌شود.",
 "Turn this group on":"روشن کردن این گروه",
 "Turn this off for every user?":"برای همه‌ی کاربران خاموش شود؟",
 "Turn this on for every user?":"برای همه‌ی کاربران روشن شود؟",
 "Turquoise":"فیروزه‌ای",
 "Two-step login":"ورود دومرحله‌ای",
 "Type":"نوع",
 "Type the public IP of the server":"آی‌پی عمومی سرور را بنویس",
 "Typical use: this server is in Iran and the link is of a server abroad, so users connect inside Iran and leave from abroad.":"کاربرد معمول: این سرور در ایران است و لینک مال سرور خارج؛ کاربر داخل ایران وصل می‌شود و از خارج بیرون می‌رود.",
 "UDP first (masked QUIC); if UDP is cut, HTTP/2 over TLS on the same port number":"اول UDP (QUIC ماسک‌شده)؛ اگر UDP قطع بود، HTTP/2 روی TLS با همان شمارهٔ پورت",
 "UDP is probably blocked on this route: the TCP transports pass":"احتمالاً UDP روی این مسیر بسته است: ترنسپورت‌های TCP رد می‌شوند",
 "UDP loss":"افت UDP",
 "UDP port":"پورت UDP",
 "UDP traffic inside fake TCP packets (udp2raw style): passes where UDP is cut or slowed; needs root on both servers":"ترافیک UDP داخل بسته‌های TCP ساختگی (سبک udp2raw): جایی که UDP قطع یا محدود است رد می‌شود؛ روی هر دو سرور root لازم است",
 "UDP travels inside hand-crafted TCP packets with a fake handshake: to DPI it is an ordinary TCP session, but with the speed of UDP. Both servers need root and the port on TCP.":"UDP داخل بسته‌های TCP دست‌ساز با دست‌دادن ساختگی حرکت می‌کند: برای DPI یک نشست TCP معمولی است، اما با سرعت UDP. هر دو سرور به root و پورت روی TCP نیاز دارند.",
 "USDT address (TRC20)":"آدرس USDT (شبکه‌ی TRC20)",
 "Under maintenance":"در تعمیر",
 "Under maintenance: new users are not sent here":"در تعمیر: کاربر جدید به اینجا فرستاده نمی‌شود",
 "Under pressure":"تحت فشار",
 "Undo":"برگرداندن",
 "Unfreeze user":"رفع فریز",
 "Unknown":"نامشخص",
 "Unlimited":"نامحدود",
 "Unlimited data":"حجم نامحدود",
 "Unread messages":"پیام‌های خوانده‌نشده",
 "Unsaved changes":"تغییرات ذخیره‌نشده",
 "Until I remove it":"تا وقتی خودم پاکش کنم",
 "Update":"آپدیت",
 "Update & version":"آپدیت و نسخه",
 "Update agent":"آپدیت ایجنت",
 "Update all":"آپدیت همه",
 "Update every node, every tunnel server and the panel itself to the latest version?":"همهٔ نودها، سرورهای تانل و خود پنل به آخرین نسخه آپدیت شوند؟",
 "Update source (GitHub repo)":"منبع آپدیت (مخزن گیت‌هاب)",
 "Update source (GitHub repo) is not set: replace USER/REPO in the command.":"منبع آپدیت (مخزن گیت‌هاب) تنظیم نشده: USER/REPO را در دستور عوض کن.",
 "Update source not set":"منبع آپدیت تنظیم نشده",
 "Update the agent of this server (Servers › Update agent) to run KANKI MIX":"عامل این سرور را به‌روز کن (سرورها › به‌روزرسانی عامل) تا KANKI MIX اجرا شود",
 "Update the agent of this server to run it":"عامل این سرور را به‌روز کن تا اجرا شود",
 "Updates come from the GitHub releases of your repo.":"آپدیت از Releases مخزن گیت‌هاب شما دریافت می‌شود.",
 "Updating…":"در حال آپدیت…",
 "Uplink (MB/s)":"آپلود (مگابایت/ثانیه)",
 "Upload":"آپلود",
 "Upload failed":"آپلود ناموفق بود",
 "Upload files":"آپلود فایل",
 "Upload speed of the entry, Mbit/s (0 = automatic)":"سرعت آپلود ورودی، مگابیت (۰ = خودکار)",
 "Upload the Kanki app (.apk) here, one file per phone type. The bot sends the file itself (📱 Download app) and the subscription page shows a download button for each. A new file of the same type replaces the old one.":"فایل نصبی اپ کانکی (.apk) را اینجا آپلود کن، برای هر نوع گوشی یک فایل. ربات خودش فایل را می‌فرستد (📱 دانلود اپ) و صفحه‌ی اشتراک برای هرکدام دکمه‌ی دانلود نشان می‌دهد. فایل جدیدِ همان نوع جای قبلی را می‌گیرد.",
 "Upstream resolvers":"DNSهای بالادست",
 "Uptime":"آپتایم",
 "Use":"استفاده از",
 "Use 3 times a day":"سه بار در روز",
 "Use for all users":"فعال برای همه‌ی کاربران",
 "Use it for the destination too":"برای مقصد هم استفاده شود",
 "Use the panel endpoint":"استفاده از Endpoint پنل",
 "Use this address on every node too":"همین آدرس روی همه‌ی نودها هم استفاده شود",
 "Used":"مصرف",
 "Used volume, limit and percent":"حجم مصرفی، سقف و درصد مصرف",
 "User inbounds (Xray)":"دروازه‌های کاربران (Xray)",
 "User link":"لینک کاربر",
 "Username":"نام کاربری",
 "Username (optional)":"نام کاربری (اختیاری)",
 "Users":"کاربران",
 "Users & sales":"کاربران و فروش",
 "Users also get":"کاربرها این را هم می‌گیرند",
 "Users and links":"کاربرها و لینک‌ها",
 "Users by protocol":"کاربران هر پروتکل",
 "Users cannot reach the server's own network (10.x, 192.168.x …)":"کاربرها به شبکه‌ی داخلی سرور (10.x، 192.168.x …) دسترسی ندارند",
 "Users connect here":"کاربرها به این وصل می‌شوند",
 "Users connect to":"کاربرها به این آدرس وصل می‌شوند",
 "Users connect to the Iran address already, so the main configs go through the tunnel too. For direct configs set it to this server's own address.":"«کاربرها به این آدرس وصل می‌شوند» الان آدرس ایران است، پس کانفیگ‌های اصلی هم از تانل می‌روند. برای کانفیگ مستقیم آن را آدرس خود این سرور بگذار.",
 "Users connect to the first server; the traffic goes through each next server and leaves from the last. Every hop is a tunnel of its own with its own transport.":"کاربر به سرور اول وصل می‌شود؛ ترافیک از سرورهای بعدی رد می‌شود و از آخری بیرون می‌رود. هر مرحله یک تانل جدا با روش انتقال خودش است.",
 "Users connect to these ports on the entry; they reach the same ports on the exit. Use 8443:443 to change the port, 1000-1010 for a range.":"کاربرها به این پورت‌ها روی سرور ورودی وصل می‌شوند و به همان پورت‌ها روی خروجی می‌رسند. برای تغییر پورت 8443:443 و برای بازه 1000-1010 بنویس.",
 "Users connect to this address; empty = the IP the server reports from":"کاربرها به این آدرس وصل می‌شوند؛ خالی = IPی که سرور از آن گزارش می‌دهد",
 "Users connection endpoint":"Endpoint اتصال کاربران",
 "Users of the last server connect through the first one":"کاربرهای سرور آخر از راه سرور اول وصل شوند",
 "Users online":"کاربران آنلاین",
 "Users usage":"مصرف کاربران",
 "Users usage and live network traffic":"مصرف کاربران و ترافیک زنده شبکه",
 "Users whose Xray traffic moved in the last few seconds":"کاربرهایی که در چند ثانیه‌ی اخیر ترافیک Xray داشته‌اند",
 "Users with DNS":"کاربران دارای DNS",
 "Users with KANKI MIX":"کاربران KANKI MIX",
 "Users with Xray":"کاربران دارای Xray",
 "Users with it":"کاربران این پروتکل",
 "Users without their own server list get this server":"کاربرانی که فهرست سرور جدا ندارند این سرور را هم بگیرند",
 "Users' WireGuard / AmneziaWG files of the moved server must be downloaded again (subscription links and the app update by themselves). Continue?":"فایل‌های WireGuard / AmneziaWG کاربرانِ سروری که پورتش عوض می‌شود باید دوباره دانلود شوند (لینک ساب و اپ خودشان به‌روز می‌شوند). ادامه می‌دهی؟",
 "Users' WireGuard / AmneziaWG files of this server must be downloaded again after a port change; subscription links and the app update by themselves.":"بعد از عوض شدن پورت، فایل‌های WireGuard / AmneziaWG کاربرانِ این سرور باید دوباره دانلود شوند؛ لینک ساب و اپ خودشان به‌روز می‌شوند.",
 "Uses":"تعداد استفاده",
 "Using a lot of swap: the server needs more RAM":"از Swap زیاد استفاده می‌کند: سرور رم بیشتری لازم دارد",
 "VLESS / Trojan over TCP with TLS: traffic that is not ours goes to these destinations (a website, another service).":"VLESS / Trojan روی TCP با TLS: ترافیکی که مال ما نیست به این مقصدها می‌رود (یک سایت، سرویس دیگر).",
 "VLESS · VMess · Trojan · Shadowsocks":"VLESS · VMess · Trojan · Shadowsocks",
 "VPN":"VPN",
 "VPN & protocols":"VPN و پروتکل‌ها",
 "VPN for users":"VPN برای کاربران",
 "VPN install failed":"نصب VPN نشد",
 "VPN is installed but serves nobody (a relay)":"VPN نصب است ولی به هیچ کاربری سرویس نمی‌دهد (رله)",
 "VPN is not installed on this server":"VPN روی این سرور نصب نیست",
 "VPN management":"مدیریت وی‌پی‌ان",
 "VPN management panel":"پنل مدیریت VPN",
 "VPN node":"نود VPN",
 "VPN part installed":"بخش VPN نصب شد",
 "VPN ports (UDP)":"پورت‌های VPN (UDP)",
 "VPN ports of the panel server":"پورت‌های VPN سرور پنل",
 "VPN server":"سرور VPN",
 "VPN serves users":"VPN به کاربران سرویس می‌دهد",
 "VPN services":"سرویس‌های VPN",
 "Valid for 3 hours, one time. It holds the key of the backup: do not share it.":"۳ ساعت و یک‌بار اعتبار دارد. کلید بکاپ داخلش است: به کسی نده.",
 "Valid for 6 hours. Run it once; it can be run again on the same server.":"تا ۶ ساعت معتبر است. یک بار اجرا کن؛ روی همان سرور می‌شود دوباره هم اجرا کرد.",
 "Valid for one hour and one node. Create a new command for the next node.":"یک ساعت و فقط برای یک نود اعتبار دارد. برای نود بعدی دستور جدید بساز.",
 "Version":"نسخه",
 "Version, update source and installing updates":"نسخه، منبع آپدیت و نصب آپدیت",
 "Violet":"بنفش",
 "Volume (GB)":"حجم (گیگ)",
 "Volume, time, connections, nodes and configs":"حجم، زمان، اتصال، نود و کانفیگ‌ها",
 "Volumes (GB, 0 = unlimited)":"حجم‌ها (گیگ، ۰ = نامحدود)",
 "WS has no TLS, so there is no SNI: only the Host header and the path of the WebSocket request can be changed.":"WS رمزنگاری TLS ندارد، پس SNI هم ندارد؛ فقط هدر Host و مسیر درخواست WebSocket قابل تغییرند.",
 "Waiting":"در صف",
 "Waiting for the certificate":"در انتظار گواهی",
 "Waiting for the new server…":"منتظر سرور جدید…",
 "Waiting for the node to connect…":"منتظر اتصال نود…",
 "Waiting for the server to connect…":"منتظر وصل شدن سرور…",
 "Waiting for the server: getting SSL and starting the listener…":"در انتظار سرور: گرفتن SSL و راه‌اندازی…",
 "Waiting for the server…":"منتظر سرور…",
 "Waiting for this server: run its command":"منتظر این سرور: دستورش را اجرا کن",
 "Wallet / manual payment":"کیف پول / پرداخت دستی",
 "Warn buyers":"هشدار به خریدارها",
 "Warn buyers before expiry / end of data":"هشدار به خریدار قبل از پایان زمان یا حجم",
 "Web (Caddy)":"وب (Caddy)",
 "Web bind":"Web Bind",
 "Web panel":"وب پنل",
 "Web port":"پورت وب",
 "WebSocket over HTTP/2, TLS 1.3 like a browser, many links in one connection":"وب‌سوکت روی HTTP/2 با TLS 1.3 مثل مرورگر؛ چند لینک در یک اتصال",
 "Welcome message":"پیام خوش‌آمد",
 "Welcome text":"متن خوش‌آمد",
 "What buyers can choose in the bot":"پلن‌هایی که خریدار در ربات می‌بیند",
 "What goes through the DNS":"چه چیزهایی از DNS رد می‌شود",
 "What the users' links say. Leave empty unless a CDN or another address is in front of the server.":"چیزی که در لینک کاربرها نوشته می‌شود. خالی بگذار مگر CDN یا آدرس دیگری جلوی سرور باشد.",
 "When":"زمان",
 "When TCP to the panel is blocked but GRE passes, the panel builds a GRE link to the server and the agent connects through it. Needs root on both servers.":"وقتی TCP به پنل بسته است ولی GRE رد می‌شود، پنل خودش لینک GRE را تا سرور می‌سازد و ایجنت از روی آن وصل می‌شود. روی هر دو سرور باید root باشی.",
 "When plain REALITY works but you also want padding against shape analysis.":"وقتی REALITY ساده کار می‌کند اما پدینگ ضد تحلیل شکل ترافیک هم می‌خواهی.",
 "When the internet is cut, customers tap the emergency button in the Kanki app and write to you; you answer and send configs from the address below, from inside Iran.":"وقتی اینترنت قطع شد، مشتری در اپ کانکی دکمه‌ی اضطراری را می‌زند و به تو پیام می‌دهد؛ تو از داخل ایران با آدرس پایین جواب می‌دهی و کانفیگ می‌فرستی.",
 "When the server IP is burned, or in whitelist mode with a reachable CDN edge. Set “Link and CDN” in the editor: link address = your CDN domain, TLS at the CDN = on.":"وقتی آی‌پی سرور سوخته، یا در حالت لیست سفید با لبهٔ CDN در دسترس. در ویرایشگر «لینک و CDN» را تنظیم کن: آدرس لینک = دامنهٔ CDN، «TLS روی CDN» = روشن.",
 "When the traffic is used up or the date passes, the inbound stops by itself; users keep their own limits as well.":"وقتی حجم تمام شود یا تاریخ برسد، اینباند خودش می‌ایستد؛ محدودیت‌های خود کاربرها هم سر جایش است.",
 "When you need a real VPN interface (TUN) between servers or for users.":"وقتی رابط VPN واقعی (TUN) بین سرورها یا برای کاربران لازم است.",
 "Where traffic leaves the server: directly, or on to another server (chain)":"ترافیک از کجا خارج شود: مستقیم، یا ادامه به یک سرور دیگر (زنجیره)",
 "Which methods to test":"کدام روش‌ها تست شوند",
 "Which one, when?":"کدام، چه موقع؟",
 "Which part of the game goes through":"کدام بخش بازی از سرور رد شود",
 "Which port each service uses":"هر سرویس کدام پورت را دارد",
 "Whitelist":"لیست سفید",
 "Whitelist mode (CDN)":"حالت لیست سفید (CDN)",
 "Whitelist mode (only domestic sites open):":"حالت لیست سفید (فقط سایت‌های داخلی باز است):",
 "Whitelist mode: through a CDN (ArvanCloud), for when only domestic sites open":"حالت لیست سفید: از طریق CDN (آروان‌کلود)، وقتی فقط سایت‌های داخلی باز است",
 "Who connects":"چه کسی وصل شود",
 "Who may use it is also set per user (Users › edit).":"اینکه چه کسی از آن استفاده کند، برای هر کاربر هم قابل تنظیم است (کاربران › ویرایش).",
 "Who you are, what to stress, the tone, words to avoid…":"چه کسی هستید، روی چه چیزی تأکید شود، لحن، کلماتی که نباید بیاید…",
 "Why SSL is not taken":"چرا SSL گرفته نمی‌شود",
 "Why us":"چرا ما",
 "WireGuard":"WireGuard",
 "WireGuard comes only this way.":"وایرگارد فقط همین کانفیگ را دارد.",
 "WireGuard reaches users only through a tunnel: write the tunnel domain of this server in Servers.":"وایرگارد فقط از راه تانل به کاربر می‌رسد: در «سرورها» دامنه‌ی تانل این سرور را بنویس.",
 "WireGuard with junk packets and scrambled headers (Jc/S1/S2/H1-H4): the WG handshake no longer matches the DPI signature. Can itself ride inside WSS / CDN / QUIC / KCP / Game / FakeTCP.":"وایرگارد با بسته‌های جانبی و هدرهای به‌هم‌ریخته (Jc/S1/S2/H1-H4): دست‌دادن WG دیگر با امضای DPI نمی‌خواند. خودش هم می‌تواند داخل WSS / CDN / QUIC / KCP / Game / FakeTCP سوار شود.",
 "WireGuard with obfuscated packets (Jc, S1, S2, H1-H4): passes most filters directly.":"WireGuard با بسته‌های مبهم (Jc، S1، S2، H1-H4): مستقیم از بیشتر فیلترها رد می‌شود.",
 "WireGuard · AmneziaWG · Hysteria2":"WireGuard · AmneziaWG · Hysteria2",
 "WireGuard, AmneziaWG and Hysteria2 configs of the last server get the address of the first server; KANKI MIX gets its second config through the route by itself.":"کانفیگ‌های WireGuard، AmneziaWG و Hysteria2 سرور آخر آدرس سرور اول را می‌گیرند؛ کانفیگ دوم KANKI MIX خودش از همین مسیر ساخته می‌شود.",
 "With ArvanCloud CDN use a port it forwards (80, 8080, 443, 2053, 8443 …). Open the port on the server.":"با CDN ابرآروان پورتی بگذار که ابرآروان رد می‌کند (80، 8080، 443، 2053، 8443 …). پورت را روی سرور باز کن.",
 "With WSS the handshake looks like an HTTPS connection to this domain. QUIC and KCP are fully encrypted (KCP’s header is hidden too), so they look like plain UDP.":"با WSS، دست‌دادن اتصال شبیه یک اتصال HTTPS به این دامنه دیده می‌شود. QUIC و KCP کاملاً رمزند (هدر KCP هم مخفی است) و شبیه UDP ساده‌اند.",
 "Without a certificate (HTTP) the chat works, but messages and your password are not encrypted on the way. Get an SSL certificate before the internet is cut and paste it below. Your configs stay safe: they are signed.":"بدون گواهی (HTTP) چت کار می‌کند، ولی پیام‌ها و رمز تو در مسیر رمزنگاری نمی‌شوند. قبل از قطعی اینترنت گواهی SSL بگیر و پایین بگذار. کانفیگ‌هایت امن می‌مانند چون امضا می‌شوند.",
 "Working inbounds":"دروازه‌های فعال",
 "Working…":"در حال انجام…",
 "Working… about a minute":"در حال انجام… حدود یک دقیقه",
 "Works, but messages and your password travel unencrypted. Configs stay safe: they are signed.":"کار می‌کند، ولی پیام‌ها و رمزت رمزنگاری‌نشده می‌روند. کانفیگ‌ها امن می‌مانند چون امضا می‌شوند.",
 "Write a message; the robot on the first screen of the Kanki app shows it to users, and it disappears by itself when the time is over.":"یک پیام بنویس؛ ربات صفحه‌ی اول اپ کانکی آن را به کاربرها نشان می‌دهد و وقتی زمانش تمام شد خودش پاک می‌شود.",
 "Write it as owner/repo":"به شکل owner/repo بنویس",
 "Write the Iran address whose tunnel forwards this UDP port":"آدرس سرور ایرانی را بنویس که تانلش این پورت UDP را عبور می‌دهد",
 "Write the domain in SNI":"دامنه را در SNI بنویس",
 "Write the domain in SNI above. The panel points the domain at this server and gets a Let's Encrypt certificate with a DNS challenge (works for servers inside Iran too, nothing has to be open on the server), and renews it every 60 days. The links use the domain.":"دامنه را در SNI بالا بنویس. پنل دامنه را به همین سرور وصل می‌کند و با چالش DNS از Let's Encrypt گواهی می‌گیرد (برای سرورهای داخل ایران هم کار می‌کند و لازم نیست چیزی روی سرور باز باشد) و هر ۶۰ روز تمدید می‌کند. لینک‌ها با همین دامنه ساخته می‌شوند.",
 "Write the message first":"اول متن پیام را بنویس",
 "Write the tunnel domain of this server in Servers: the second config is made by itself.":"دامنه‌ی تانل این سرور را در «سرورها» بنویس: کانفیگ دوم خودش ساخته می‌شود.",
 "Written by Grok":"نوشته‌ی Grok",
 "Written by the built-in writer":"نوشته‌ی نویسنده‌ی داخلی",
 "Written inside every user config. Empty = the panel domain.":"داخل کانفیگ همه‌ی کاربرها نوشته می‌شود. خالی = دامنه‌ی پنل.",
 "Xray":"Xray",
 "Xray DNS servers (comma separated, empty = the server's own)":"DNSهای Xray (با کاما، خالی = DNS خود سرور)",
 "Xray can run on the panel server or on any tunnel server. A new server gets a one-line install command.":"Xray روی سرور پنل یا هر سرور تانل اجرا می‌شود. سرور جدید یک دستور نصب یک‌خطی می‌گیرد.",
 "Xray inbounds for your users: every user with Xray ticked is a client of every inbound":"اینباندهای Xray برای کاربرهای خودت: هر کاربری که تیک Xray دارد کلاینت همه‌ی اینباندهاست",
 "Xray is not on this server yet.":"Xray هنوز روی این سرور نیست.",
 "Xray is off":"Xray خاموش است",
 "Xray is off: nothing runs on the servers and no links go to the users.":"Xray خاموش است: روی سرورها چیزی اجرا نمی‌شود و لینکی به کاربرها نمی‌رسد.",
 "Xray is on":"Xray روشن است",
 "Xray node":"نود Xray",
 "Xray only":"فقط Xray",
 "Xray page is not loaded yet":"صفحه Xray هنوز بارگذاری نشده",
 "Xray servers":"سرورهای Xray",
 "Xray-core version":"نسخه‌ی Xray-core",
 "You are on the latest version.":"نسخه فعلی بروز است.",
 "Your IP":"IP شما",
 "Your messages are signed: the app only trusts messages that really come from you, even over plain HTTP.":"پیام‌های تو امضا می‌شوند: اپ فقط پیامی را قبول می‌کند که واقعاً از طرف تو باشد، حتی روی HTTP.",
 "ZarinPal":"زرین‌پال",
 "ZarinPal callback URL":"آدرس بازگشت زرین‌پال",
 "ZarinPal merchant ID":"مرچنت زرین‌پال",
 "a Docker container: stop it by hand":"کانتینر داکر است: دستی متوقفش کن",
 "a system service":"سرویس سیستمی است",
 "add at least one TCP or UDP port to forward":"حداقل یک پورت TCP یا UDP اضافه کن",
 "address unknown yet":"آدرس هنوز معلوم نیست",
 "address: a domain or an IP, like de.example.com":"آدرس: یک دامنه یا IP، مثل de.example.com",
 "addresses":"IP",
 "agent":"ایجنت",
 "all running":"همه روشن",
 "always resolve for IP rules":"برای قانون‌های IP همیشه IP بگیر",
 "an outbound tag is English letters, digits, - and _":"تگ خروجی فقط حروف انگلیسی، عدد، - و _",
 "and":"و",
 "another Kanki service":"یک سرویس دیگر کانکی",
 "at least 10 characters":"حداقل ۱۰ کاراکتر",
 "automatic":"خودکار",
 "between the servers":"بین سرورها",
 "built in":"پیش‌ساخته",
 "by name (fastest)":"با اسم (سریع‌ترین)",
 "cannot be routed":"قابل مسیردهی نیست",
 "certbot on the server gets a Let's Encrypt certificate for this domain by itself (no e-mail needed) and renews it. The domain must point to the server; whatever uses port 80 is set aside for a few seconds and comes back by itself. The links use the domain.":"certbot روی سرور خودش برای این دامنه از Let's Encrypt گواهی می‌گیرد (ایمیل لازم نیست) و تمدید می‌کند. دامنه باید به سرور وصل باشد؛ هر چه روی پورت ۸۰ باشد چند ثانیه کنار می‌رود و خودش برمی‌گردد. لینک‌ها با همین دامنه ساخته می‌شوند.",
 "certbot on this server gets a Let's Encrypt certificate for the domain (no e-mail needed) and renews it by itself; every TLS inbound of this server uses it. The domain must point to this server. Whatever uses port 80 (Caddy, nginx, an inbound …) is set aside for a few seconds and comes back by itself.":"certbot روی همین سرور برای دامنه از Let's Encrypt گواهی می‌گیرد (ایمیل لازم نیست) و خودش تمدید می‌کند؛ همه‌ی اینباندهای TLS این سرور از آن استفاده می‌کنند. دامنه باید به همین سرور وصل باشد. هر چه روی پورت ۸۰ باشد (Caddy، nginx، یک اینباند …) چند ثانیه کنار می‌رود و خودش برمی‌گردد.",
 "change in Servers":"تغییر در صفحه‌ی سرورها",
 "choose the entry and the exit server":"سرور ورودی و خروجی را انتخاب کن",
 "choose the phone type of this file (arm64, armv7 or universal)":"نوع گوشیِ این فایل را انتخاب کن (arm64، armv7 یا universal)",
 "connected":"وصل",
 "connections":"اتصال",
 "cores":"هسته",
 "countries":"کشور",
 "current":"فعلی",
 "days":"روز",
 "days left":"روز مانده",
 "default":"پیش‌فرض",
 "direct":"مستقیم",
 "domain":"دامنه",
 "down":"قطع",
 "e.g. The Germany server is under maintenance for one hour.":"مثلاً: سرور آلمان تا یک ساعت در حال تعمیر است.",
 "empty = keep it":"خالی = همان قبلی",
 "empty = latest":"خالی = آخرین نسخه",
 "empty = same as the SNI":"خالی = همان SNI",
 "empty = use the domain":"خالی = از خود دامنه استفاده شود",
 "enter the domain you put on the CDN":"دامنه‌ای که روی CDN گذاشتی را بنویس",
 "error":"خطا",
 "every phone":"همه‌ی گوشی‌ها",
 "exit":"خروجی",
 "fastest, nothing to maintain":"سریع‌ترین، بدون نیاز به نگهداری",
 "for UDP":"برای UDP",
 "for every user?":"برای همه‌ی کاربران روشن شود؟",
 "for users":"برای کاربران",
 "from":"از",
 "from the file name, e.g. 1.15.1":"از روی اسم فایل، مثلاً 1.15.1",
 "from the toman price at the dollar rate":"از روی قیمت تومان با نرخ دلار",
 "hours":"ساعت",
 "hours ago":"ساعت پیش",
 "inbounds":"اینباند",
 "is off: it runs on no server and is in no subscription.":"خاموش است: روی هیچ سروری اجرا نمی‌شود و در هیچ اشتراکی نیست.",
 "is used by":"استفاده شده توسط",
 "issued":"صادر شده",
 "joined the panel":"به پنل پیوست",
 "kept":"نگه‌داشته",
 "last used":"آخرین استفاده",
 "left":"مانده",
 "less than a day":"کمتر از یک روز",
 "light":"سبک",
 "like: AI sites through Germany":"مثلاً: سایت‌های هوش مصنوعی از آلمان",
 "like: best on Irancell":"مثلاً: روی ایرانسل بهتر است",
 "link between the two servers":"لینک بین دو سرور",
 "local only (127.0.0.1)":"فقط داخلی (127.0.0.1)",
 "loss":"افت",
 "match":"نتیجه",
 "min":"دقیقه",
 "minutes ago":"دقیقه پیش",
 "more inbounds":"اینباند دیگر",
 "must be open in the cloud firewall":"باید در فایروال سرویس‌دهنده باز باشند",
 "must be open in the cloud firewall of":"باید در فایروال کلاد این سرور باز باشند:",
 "name: English letters and digits only, 3-12 characters, starting with a letter (like mahtab87)":"نام فقط حروف انگلیسی و عدد، ۳ تا ۱۲ حرف و اولش حرف باشد (مثل mahtab87)",
 "never":"هرگز",
 "new phones (64-bit)":"گوشی‌های جدید (۶۴ بیتی)",
 "no answer: update it once with the kanki command":"جواب نداد: یک‌بار با دستور kanki آپدیتش کن",
 "no name":"بدون اسم",
 "no tunnels":"بدون تانل",
 "none":"ندارد",
 "none yet":"هنوز ندارد",
 "normal":"معمولی",
 "not a service: stop it by hand":"سرویس نیست: دستی متوقفش کن",
 "not installed":"نصب نیست",
 "not running":"KANKI MIX روی این سرور اجرا نمی‌شود: «ری‌استارت سرویس‌های VPN» را بزن",
 "of it used":"از آن مصرف شده",
 "off":"خاموش",
 "older phones (32-bit)":"گوشی‌های قدیمی (۳۲ بیتی)",
 "on":"روشن",
 "on the entry":"روی ورودی",
 "on the exit":"روی خروجی",
 "only on request":"فقط با درخواست",
 "panel":"پنل",
 "passed":"رد شد",
 "per page":"در هر صفحه",
 "pick another port":"پورت دیگری انتخاب کن",
 "plans":"پلن",
 "port":"پورت",
 "press Update agent":"آپدیت Agent را بزن",
 "queries":"درخواست",
 "random if empty":"خالی = تصادفی",
 "relay":"رله",
 "renewed by itself":"خودش تمدید می‌شود",
 "renewed by itself every 60 days":"هر ۶۰ روز خودش تمدید می‌شود",
 "resolve when no name rule matched":"اگر قانون اسمی نخورد، IP بگیر",
 "reverse":"معکوس",
 "rotating tunnel, address to dial, target":"تانل چرخشی، آدرس اتصال، مقصد",
 "routed":"مسیردهی‌شده",
 "routed names now":"دامنه‌ی مسیردهی‌شده",
 "running":"روشن",
 "saved":"ذخیره شده",
 "seconds":"ثانیه",
 "seconds ago":"ثانیه پیش",
 "see the whitelist guide in the tunnel wizard":"راهنمای لیست سفید را در ویزارد تانل ببین",
 "selected":"انتخاب‌شده",
 "self-signed":"خودامضا",
 "server(s) disconnected":"سرور قطع است",
 "set":"گذاشته شده",
 "stopped":"متوقف",
 "strong":"قوی",
 "taken by":"گرفته شده توسط",
 "the CDN transport of the tunnels + an ArvanCloud domain":"انتقال CDN تانل‌ها + یک دامنهٔ ابرآروان",
 "the entry and the exit must be two different servers":"ورودی و خروجی باید دو سرور متفاوت باشند",
 "the hops made so far were taken back":"مرحله‌هایی که ساخته شده بودند برداشته شدند",
 "the panel server cannot be removed":"سرور پنل حذف نمی‌شود",
 "the plain ping between the two servers, as a reference":"پینگ ساده‌ی بین دو سرور، به‌عنوان مرجع",
 "the port is required":"پورت لازم است",
 "the port must be 1-65535":"پورت باید ۱ تا ۶۵۵۳۵ باشد",
 "the same as Kanki DNS":"همان DNS کانکی",
 "the server IP hides behind the edge":"آی‌پی سرور پشت لبه پنهان می‌شود",
 "the tunnel domain of the server":"دامنه‌ی تانل سرور",
 "the tunnel port is also in the forwarded TCP ports":"پورت تانل نباید جزو پورت‌های عبوری TCP باشد",
 "the tunnel port is also in the forwarded UDP ports":"پورت تانل نباید جزو پورت‌های عبوری UDP باشد",
 "the tunnel port is required":"پورت تانل لازم است",
 "this group is off":"این گروه خاموش است",
 "this is not an Android app (.apk)":"این فایل اپ اندروید (.apk) نیست",
 "this name is already used by another user":"این نام را کاربر دیگری دارد",
 "this server":"همین سرور",
 "times":"بار",
 "tunnel":"تانل",
 "tunnel address: a domain or IP only (like ir.example.com)":"آدرس تانل: فقط دامنه یا IP (مثل ir.example.com)",
 "tunnel name: up to 40 letters, no < > \"":"اسم تانل: حداکثر ۴۰ حرف، بدون < > \"",
 "tunnel(s) not connected":"تانل وصل نیست",
 "unchanged":"بدون تغییر",
 "unknown phone type":"نوع گوشی نامعتبر است",
 "until":"تا",
 "users":"کاربر",
 "users changed":"کاربر تغییر کرد",
 "users only":"کاربر خاص",
 "users total":"کاربر",
 "uses left":"بار مانده",
 "version":"نسخه",
 "very strong":"خیلی قوی",
 "waiting":"در انتظار",
 "were filled in":"وارد شد",
 "your extra domains":"دامنه‌های اضافه‌ی خودت"
};
var S={lang:localStorage.getItem('kk_lang')||'fa',theme:localStorage.getItem('kk_theme')||'dark',color:localStorage.getItem('kk_color')||'gold',token:localStorage.getItem('kk_tok')||'',me:null,page:'dash',users:[],nodes:[],ov:null,sel:{},q:'',filter:'all',pf:'all',sort:'new',size:12,pg:1,timer:null,timer2:null};
// a server is one word everywhere: nodes and tunnel servers are the same servers
var WFA=[[/سرورهای تانل/g,'سرورها'],[/سرور تانل/g,'سرور'],[/Nodeها/g,'سرورها'],[/نودهای/g,'سرورهای'],[/نودها/g,'سرورها'],[/نودی/g,'سروری'],[/نود/g,'سرور']],
 WEN=[[/\bTunnel servers\b/g,'Servers'],[/\btunnel servers\b/g,'servers'],[/\bTunnel server\b/g,'Server'],[/\btunnel server\b/g,'server'],[/\bNodes\b/g,'Servers'],[/\bnodes\b/g,'servers'],[/\bNode\b/g,'Server'],[/\bnode\b/g,'server']];
function t(k){var s=S.lang=='fa'&&FA[k]?FA[k]:k;if(typeof s!='string')return s;(S.lang=='fa'?WFA:WEN).forEach(function(r){s=s.replace(r[0],r[1])});return s}
function $(s,r){return (r||document).querySelector(s)}
// ---------------------------------------------------------------- calm refreshes
// The pages redraw their lists every few seconds. Swapping in new HTML rebuilt every element: an open
// drawer jumped back to its top, rows lost their scroll, entrance animations ran again and the page
// blinked. Inside a page, new HTML is now laid over what is there: an element that stays is kept and
// only what changed is touched. (A whole new page, a dialog or an emptied box is still built afresh.)
(function(){
var D=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');if(!D||!D.set)return;
// what the look layers add after a draw (drawer header, chips, pencils, edges …): left where it is
var DECO=/(^|\s)(k310dh|kd-crail|kd-pen|kd-edge|k310ki|k310sub|k38qa|k310strip|k310dash|k310res|k310orb|k310brand|kd-lay)(\s|$)/;
function deco(n){return n.nodeType==1&&DECO.test(n.getAttribute('class')||'')}
function key(n){return n.nodeType==1?(n.id||'')+'|'+(n.getAttribute('data-key')||'')+'|'+(n.getAttribute('data-acc')||''):''}
function same(a,b){return a.nodeType==b.nodeType&&a.nodeName==b.nodeName&&key(a)==key(b)}
function attrs(o,n){var i,a;
 for(i=o.attributes.length-1;i>=0;i--){a=o.attributes[i].name;if(!n.hasAttribute(a)&&!(o.nodeName=='CANVAS'&&(a=='width'||a=='height')))o.removeAttribute(a)}
 for(i=0;i<n.attributes.length;i++){a=n.attributes[i];if(o.getAttribute(a.name)!==a.value)o.setAttribute(a.name,a.value)}}
function node(o,n){if(o.nodeType!=1){if(o.nodeValue!==n.nodeValue)o.nodeValue=n.nodeValue;return}
 attrs(o,n);if(o.nodeName=='CANVAS'||o.nodeName=='TEXTAREA'&&o===document.activeElement)return;kids(o,n)}
function kids(o,n){var nk=Array.prototype.slice.call(n.childNodes),i=0;
 nk.forEach(function(c){while(o.childNodes[i]&&deco(o.childNodes[i]))i++;var cur=o.childNodes[i],m=null;
  if(cur&&same(cur,c))m=cur;
  else if(c.nodeType==1&&key(c)!='||')for(var j=i+1;j<o.childNodes.length;j++)if(same(o.childNodes[j],c)){m=o.childNodes[j];break}
  if(m){if(m!==cur)o.insertBefore(m,cur||null);node(m,c)}else o.insertBefore(c,cur||null);i=Array.prototype.indexOf.call(o.childNodes,m||c)+1});
 for(var k=o.childNodes.length-1;k>=i;k--){var x=o.childNodes[k];if(!deco(x))o.removeChild(x)}}
function calm(el){var pg=document.getElementById('pg');
 return pg&&el!==pg&&el.isConnected&&el.firstChild&&pg.contains(el)&&!el.closest('#modal,.msheet')}
Object.defineProperty(Element.prototype,'innerHTML',{configurable:true,enumerable:D.enumerable,get:D.get,set:function(h){
 if(h===''||h==null||this.namespaceURI!='http://www.w3.org/1999/xhtml'||!calm(this))return D.set.call(this,h);
 var tp=document.createElement('template');D.set.call(tp,h);kids(this,tp.content)}});
})();
function $$(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function toast(m,e){var x=$('#toast');x.textContent=m;x.className=e?'e':'';x.style.display='block';clearTimeout(x._t);x._t=setTimeout(function(){x.style.display='none'},2600)}
// a delete that leaves work on servers shows its progress (kdFollowRemoval)
var DELRX=/^\/api\/(tunnels\/servers\/[^/?]+|tunnels\/(?!servers|probe|cdntest)[^/?]+|servers\/[^/?]+|nodes\/[^/?]+|xray\/servers\/[^/?]+|dns\/servers\/[^/?]+)(\?.*)?$/;
function api(m,p,b,raw){var u=p;
 // a tunnel server is made in Servers
 if(m=='POST'&&p=='/api/tunnels/servers'&&b&&!b.gre_ip&&!b.addr){p='/api/servers';b={name:b.name,loc:b.loc||'abroad',vpn:b.loc!='iran'};raw=undefined}
 var o={method:m,headers:{}};if(S.token)o.headers.Authorization='Bearer '+S.token;
 if(b!==undefined&&!(b instanceof Blob)&&!(b instanceof ArrayBuffer)){o.headers['Content-Type']='application/json';o.body=JSON.stringify(b)}else if(b!==undefined)o.body=b;
 if(raw&&raw.headers)for(var k in raw.headers)o.headers[k]=raw.headers[k];
 var pr=fetch(p,o).then(function(r){if(r.status==401&&p!='/api/login'){logout(true);throw new Error('unauthorized')}
  if(raw&&raw.blob)return r.ok?r.blob().then(function(bl){return{blob:bl,name:((r.headers.get('content-disposition')||'').match(/filename="([^"]+)"/)||[])[1]}}):r.json().then(function(j){throw new Error(j.error||r.status)});
  return r.text().then(function(x){var j;try{j=x?JSON.parse(x):{}}catch(e){j={error:x}}if(!r.ok){var er=new Error(j.error||('HTTP '+r.status));er.data=j;throw er}return j})});
 if(m=='DELETE'&&DELRX.test(u||''))pr.then(function(r){if(r&&r.removal)kdFollowRemoval(r.removal)},function(){});
 return pr}
function fail(e){if(!e||e.message=='unauthorized')return;
 // a page drawn after the admin already left it: nothing to tell
 if(e instanceof TypeError&&/of (null|undefined)/.test(e.message)){console.warn(e);return}
 toast(t(e.message||String(e)),1)}
function copy(s){if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(s).then(function(){toast(t('Copied'))});else{var a=document.createElement('textarea');a.value=s;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();toast(t('Copied'))}}
function bytes(n){n=+n||0;var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(i>=3?2:0)+' '+u[i]}
function gbtxt(g){g=+g||0;return g<1?Math.round(g*1024)+' MB':g.toFixed(2)+' GB'}

// ---------------------------------------------------------------- Persian digits + Jalali (Shamsi) calendar
var PD='۰۱۲۳۴۵۶۷۸۹',AD='٠١٢٣٤٥٦٧٨٩';
function N(x){x=String(x==null?'':x);return S.lang=='fa'?x.replace(/\d/g,function(d){return PD.charAt(+d)}):x}
function unN(s){return String(s==null?'':s).replace(/[۰-۹]/g,function(d){return PD.indexOf(d)}).replace(/[٠-٩]/g,function(d){return AD.indexOf(d)})}
function dv(a,b){return Math.floor(a/b)}
function g2j(gy,gm,gd){var gdm=[0,31,59,90,120,151,181,212,243,273,304,334],gy2=gm>2?gy+1:gy,days=355666+365*gy+dv(gy2+3,4)-dv(gy2+99,100)+dv(gy2+399,400)+gd+gdm[gm-1],jy=-1595+33*dv(days,12053);
 days%=12053;jy+=4*dv(days,1461);days%=1461;if(days>365){jy+=dv(days-1,365);days=(days-1)%365}
 return [jy,days<186?1+dv(days,31):7+dv(days-186,30),1+(days<186?days%31:(days-186)%30)]}
function j2g(jy,jm,jd){jy+=1595;var days=-355668+365*jy+dv(jy,33)*8+dv(jy%33+3,4)+jd+(jm<7?(jm-1)*31:(jm-7)*30+186),gy=400*dv(days,146097);
 days%=146097;if(days>36524){days--;gy+=100*dv(days,36524);days%=36524;if(days>=365)days++}
 gy+=4*dv(days,1461);days%=1461;if(days>365){gy+=dv(days-1,365);days=(days-1)%365}
 var gd=days+1,leap=(gy%4==0&&gy%100!=0)||gy%400==0,sa=[0,31,leap?29:28,31,30,31,30,31,31,30,31,30,31],gm;
 for(gm=0;gm<13&&gd>sa[gm];gm++)gd-=sa[gm];return [gy,gm,gd]}
function p2(n){return (n<10?'0':'')+n}
// Jalali "1405/07/11" in Persian mode, "2026-10-03" in English mode (+ " HH:MM")
function jdate(ts,time){if(!ts)return '∞';var d=new Date(ts*1000),s;
 if(S.lang=='fa'){var j=g2j(d.getFullYear(),d.getMonth()+1,d.getDate());s=j[0]+'/'+p2(j[1])+'/'+p2(j[2])}else s=d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate());
 if(time)s+=' '+p2(d.getHours())+':'+p2(d.getMinutes());return N(s)}
function fmtDate(ts,withTime){return jdate(ts,withTime)}
function ago(ts){if(!ts)return t('never');var s=Math.max(0,Math.floor(Date.now()/1000-ts));if(s<60)return N(s)+' '+t('seconds ago');if(s<3600)return N(Math.floor(s/60))+' '+t('minutes ago');if(s<86400)return N(Math.floor(s/3600))+' '+t('hours ago');return jdate(ts,true)}
function leftTxt(ts){if(!ts)return t('Unlimited');var sec=ts-Date.now()/1000;if(sec<=0)return t('Expired');var d=Math.ceil(sec/86400);return sec<86400?t('less than a day'):N(d)+' '+t('days left')}

// ---------------------------------------------------------------- icons (stroke = currentColor)
var ICO={
 edit:'<path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M14 6l4 4"/>',
 link:'<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
 qr:'<rect x="3.5" y="3.5" width="6.5" height="6.5" rx="1.2"/><rect x="14" y="3.5" width="6.5" height="6.5" rx="1.2"/><rect x="3.5" y="14" width="6.5" height="6.5" rx="1.2"/><path d="M14 14h3v3M20.5 14v.01M14 20.5h3.5M20.5 17.5v3"/>',
 reset:'<path d="M4 12a8 8 0 1 0 2.6-5.9"/><path d="M4 4v4.5h4.5"/>',
 trash:'<path d="M5 7h14M10 7V5h4v2M7 7l1 12h8l1-12"/>',
 dl:'<path d="M12 4v10M8 10.5l4 4 4-4M5 19h14"/>',
 ext:'<path d="M14 5h5v5M19 5l-8 8M17 14v4a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1h4"/>',
 refresh:'<path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20 4v4.5h-4.5"/>',
 dash:'<rect x="3.5" y="3.5" width="7" height="8.5" rx="2"/><rect x="13.5" y="3.5" width="7" height="5.5" rx="2"/><rect x="13.5" y="12" width="7" height="8.5" rx="2"/><rect x="3.5" y="15.5" width="7" height="5" rx="2"/>',
 users:'<circle cx="9" cy="8.2" r="3.3"/><path d="M3.2 19.5c.4-3.3 2.7-5.2 5.8-5.2s5.4 1.9 5.8 5.2"/><path d="M15.6 5.2a3.2 3.2 0 0 1 0 6"/><path d="M17.4 14.6c2 .5 3.2 2.2 3.4 4.4"/>',
 nodes:'<rect x="3.5" y="4" width="17" height="6.5" rx="2.2"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="2.2"/><path d="M7.2 7.25h.01M7.2 16.75h.01M11 7.25h6M11 16.75h6"/>',
 backup:'<ellipse cx="12" cy="6" rx="7.5" ry="3"/><path d="M4.5 6v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6"/><path d="M4.5 12v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6"/>',
 security:'<path d="M12 3.4l7 2.8v5.3c0 4.4-2.9 7.7-7 9-4.1-1.3-7-4.6-7-9V6.2l7-2.8z"/><path d="M8.9 12.1l2.2 2.2 4-4.3"/>',
 settings:'<path d="M4 7h8.5M17.5 7H20M4 17h3M12 17h8"/><circle cx="15" cy="7" r="2.5"/><circle cx="9.5" cy="17" r="2.5"/>',
 logout:'<path d="M9.5 4H6.5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3"/><path d="M15 8l4 4-4 4M19 12H9.5"/>',
 menu:'<path d="M4 7h16M4 12h16M4 17h10"/>',
 moon:'<path d="M20 14.2A8 8 0 1 1 9.8 4a6.6 6.6 0 0 0 10.2 10.2z"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',
 check:'<path d="M5 12.5l4.2 4.2L19 7"/>',
 sel:'<rect x="4" y="4" width="16" height="16" rx="4.5"/><path d="M8.5 12.2l2.5 2.5 4.5-5"/>',
 cpu:'<rect x="6" y="6" width="12" height="12" rx="2.5"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"/>',
 ram:'<rect x="3" y="7.5" width="18" height="8.5" rx="2"/><path d="M7 7.5v8.5M11 7.5v8.5M15 7.5v8.5M6.5 16v2.5M17.5 16v2.5"/>',
 disk:'<rect x="3.5" y="5" width="17" height="14" rx="3"/><path d="M3.5 12h17"/><path d="M8 15.5h.01M11.5 15.5h5"/>',
 swap:'<path d="M6 8h12l-3.2-3.2M18 16H6l3.2 3.2"/>',
 image:'<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><circle cx="9" cy="10" r="1.6"/><path d="M4 17l5-4.5 3.5 3 3-2.5 4.5 4"/>',
 chev:'<path d="M6 9l6 6 6-6"/>',
 sos:'<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3.5"/><path d="M6 6l3.5 3.5M18 6l-3.5 3.5M6 18l3.5-3.5M18 18l-3.5-3.5"/>',
 bell:'<path d="M6 16.5V11a6 6 0 1 1 12 0v5.5l1.5 2H4.5z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
 globe:'<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.6 2.6 3.8 5.4 3.8 8.5S14.6 17.9 12 20.5C9.4 17.9 8.2 15.1 8.2 12S9.4 6.1 12 3.5z"/>',
 shield2:'<path d="M12 3.4l7 2.8v5.3c0 4.4-2.9 7.7-7 9-4.1-1.3-7-4.6-7-9V6.2l7-2.8z"/><path d="M9 12h6M12 9v6"/>',
 brush:'<path d="M14.5 4.5l5 5-8.2 8.2a3 3 0 0 1-4.3 0l-.7-.7a3 3 0 0 1 0-4.3z"/><path d="M6.3 13l4.7 4.7M3.5 20.5c1.8 0 3-1 3-2.5"/>',
 box:'<path d="M4 7.5l8-4 8 4v9l-8 4-8-4z"/><path d="M4 7.5l8 4 8-4M12 11.5v9"/>',
 copy:'<rect x="8.5" y="8.5" width="11.5" height="11.5" rx="2.5"/><path d="M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5"/>',
 play:'<path d="M8 5.5v13l10.5-6.5z"/>',
 pause:'<path d="M8.5 5.5v13M15.5 5.5v13"/>',
 bot:'<rect x="4.5" y="8" width="15" height="11" rx="3.5"/><path d="M12 8V5"/><circle cx="12" cy="4" r="1.2"/><circle cx="9.3" cy="13.2" r="1.2"/><circle cx="14.7" cy="13.2" r="1.2"/><path d="M9.5 16.5h5M2.5 12.5v3M21.5 12.5v3"/>',
 traffic:'<path d="M4 19.5h16"/><path d="M7 16v-5M11 16V7M15 16v-7.5M19 16V4.5"/>',
 ports:'<path d="M9 3.5v4.5M15 3.5v4.5"/><path d="M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0z"/><path d="M12 17v3.5"/>',
 send:'<path d="M20.5 3.5L3.5 10.5l7 2.5 2.5 7z"/><path d="M10.5 13l5-5"/>',
 term:'<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><path d="M7.5 9.5l3 2.5-3 2.5M12.5 15h4"/>',
 gift:'<rect x="4" y="9" width="16" height="11" rx="2"/><path d="M4 13h16M12 9v11"/><path d="M12 9c-2.5 0-4.5-1-4.5-2.7S9.6 3.8 12 9zM12 9c2.5 0 4.5-1 4.5-2.7S14.4 3.8 12 9z"/>',
 card:'<rect x="3" y="6" width="18" height="12.5" rx="2.5"/><path d="M3 10.5h18M7 15h3.5"/>',
 move:'<path d="M4 8h13.5l-3.5-3.5M20 16H6.5l3.5 3.5"/>',
 tunnel:'<path d="M3 19v-7a9 9 0 0 1 18 0v7"/><path d="M7.5 19v-6.5a4.5 4.5 0 0 1 9 0V19"/><path d="M1.5 19h21"/>',
 srv:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5"/>',
 dns:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
 xray:'<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
 game:'<path d="M6 11h4M8 9v4"/><circle cx="15.5" cy="12.5" r=".6"/><circle cx="17.5" cy="10.5" r=".6"/><path d="M7.5 6h9a5 5 0 0 1 4.8 6.3l-1 3.6a2.6 2.6 0 0 1-4.6.9L14.5 15h-5l-1.2 1.8a2.6 2.6 0 0 1-4.6-.9l-1-3.6A5 5 0 0 1 7.5 6z"/>',
 more38:'<circle cx="5" cy="12" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="19" cy="12" r="1.7"/>',
 sun38:'<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4"/>',
 k310sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4"/>',
 k310online:'<path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 15.8a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.2"/>',
 k310ok:'<circle cx="12" cy="12" r="8.5"/><path d="M8.5 12.3l2.4 2.4 4.6-4.9"/>',
 k310warn:'<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5.2l3 1.8"/>',
 k310off:'<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
 k310traffic:'<path d="M7 4v14M3.5 14.5L7 18l3.5-3.5"/><path d="M17 20V6M13.5 9.5L17 6l3.5 3.5"/>',
 cores:'<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>'
};
function ic(n,sz){sz=sz||18;return '<svg viewBox="0 0 24 24" width="'+sz+'" height="'+sz+'" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+ICO[n]+'</svg>'}
// logo: the uploaded image (Settings > Logo) or the first letter; cached so the login page can show it too
function logoOk(s){return /^data:image\/(png|jpeg|webp|gif|svg\+xml);base64,[A-Za-z0-9+\/=]+$/.test(s||'')}
function curLogo(){var l=(S.me&&S.me.logo)||(S.me?'':localStorage.getItem('kk_logo'))||'';return logoOk(l)?l:''}
function logoCls(){return 'logo'+(curLogo()?' has-img':' svgl')}
function logoInner(letter){var l=curLogo();return l?'<img src="'+l+'" alt="">':kLogo()}

// ---------------------------------------------------------------- tiny live-chart renderer (SVG, newest point on the right edge)
function smoothPath(pts){var i,d;if(pts.length<3){d='';for(i=0;i<pts.length;i++)d+=(i?'L':'M')+pts[i][0].toFixed(1)+' '+pts[i][1].toFixed(1);return d}
 d='M'+pts[0][0].toFixed(1)+' '+pts[0][1].toFixed(1);
 for(i=1;i<pts.length-1;i++)d+='Q'+pts[i][0].toFixed(1)+' '+pts[i][1].toFixed(1)+' '+((pts[i][0]+pts[i+1][0])/2).toFixed(1)+' '+((pts[i][1]+pts[i+1][1])/2).toFixed(1);
 var l=pts[pts.length-1];return d+'L'+l[0].toFixed(1)+' '+l[1].toFixed(1)}
// series: [{v:[numbers],c:'a'|'b'}]  o:{h,max,cap}
function areaChart(series,o){var W=300,H=o.h||100,cap=o.cap||60,mx=o.max||0,i,j,s;
 if(!o.max){for(i=0;i<series.length;i++)for(j=0;j<series[i].v.length;j++)if(series[i].v[j]>mx)mx=series[i].v[j];mx=mx>0?mx*1.2:1}
 var out='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" aria-hidden="true">',step=W/(cap-1);
 for(i=1;i<4;i++)out+='<path class="gridl" d="M0 '+(H*i/4).toFixed(1)+'H'+W+'"/>';
 for(i=0;i<series.length;i++){s=series[i];if(!s.v.length)continue;var pts=[],n=s.v.length;
  for(j=0;j<n;j++)pts.push([W-(n-1-j)*step,H-2-Math.min(1,s.v[j]/mx)*(H-6)]);
  var line=smoothPath(pts),first=pts[0][0];
  out+='<path class="ar-'+s.c+'" d="'+line+'L'+W+' '+H+'L'+first.toFixed(1)+' '+H+'Z"/><path class="ln-'+s.c+'" d="'+line+'"/>'}
 return out+'</svg>'}

function applyLook(){document.documentElement.lang=S.lang;document.documentElement.dir=S.lang=='fa'?'rtl':'ltr';
 var b=document.body.classList;b.toggle('light',S.theme=='light');
 Array.prototype.slice.call(b).forEach(function(c){if(c.indexOf('c-')==0)b.remove(c)});if(S.color&&S.color!='gold')b.add('c-'+S.color);
 b.add('k38');if($('#side'))b.add('v37');V37.drawLooks()}
var PROTOS=[['wg','WireGuard'],['awg','AmneziaWG'],['hy2','Hysteria2'],['kmix','KANKI MIX'],['kgame','MIX+\u200e'],['xray','Xray'],['dns','DNS']];
function pname(p){for(var i=0;i<PROTOS.length;i++)if(PROTOS[i][0]==p)return PROTOS[i][1];return p}
function modal(html,cls){var b=$('#mbox');b.className='mbox'+(cls?' '+cls:'');b.innerHTML=html;b.scrollTop=0;$('#modal').classList.add('on');document.body.style.overflow='hidden'}
function closeModal(){$('#modal').classList.remove('on');document.body.style.overflow=''}
document.addEventListener('keydown',function(e){if(e.key=='Escape'&&$('#modal').classList.contains('on'))closeModal()});
$('#modal').addEventListener('click',function(e){if(e.target.id=='modal')closeModal()});
function mhead(title,sub){return '<div class="mh"><div><b style="font-size:17px">'+esc(title)+'</b>'+(sub?'<small class="ltr">'+esc(sub)+'</small>':'')+'</div><button class="ib" onclick="closeModal()">✕</button></div>'}
function sw(id,on,cb){return '<label class="sw"><input type="checkbox" '+(on?'checked':'')+' onchange="'+cb+'"><span></span></label>'}
function confirmDo(fn){if(confirm(t('Are you sure?')))fn()}
function dl(blobRes){var a=document.createElement('a');a.href=URL.createObjectURL(blobRes.blob);a.download=blobRes.name||'download';document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},2000)}

// ---------------------------------------------------------------- login
function loginView(otp){$('#app').innerHTML='';document.body.className='';applyLook();clearInterval(S.timer);clearInterval(S.timer2);clearInterval(S.timer3);
 var sun=function(){return ic(document.body.classList.contains('light')?'moon':'k310sun',17)};
 $('#app').innerHTML='<div class="login k310login"><i class="k310orb a"></i><i class="k310orb b"></i><div class="'+logoCls()+'">'+logoInner('K')+'</div><div class="k310brand">'+t('VPN management panel')+'</div>'+
 '<div class="card"><h3>'+esc(document.title)+'</h3><p class="k310sub">'+t('Sign in to continue')+'</p>'+
 '<label class="f">'+t('Username')+'</label><input id="lu" autocomplete="username" class="ltr">'+
 '<label class="f">'+t('Password')+'</label><input id="lp" type="password" autocomplete="current-password" class="ltr">'+
 '<div id="otpw" class="'+(otp?'':'hide')+'"><label class="f">'+t('2FA code')+'</label><input id="lo" inputmode="numeric" maxlength="6" class="ltr" autocomplete="one-time-code"></div>'+
 '<button class="btn" style="width:100%;margin-top:14px" id="lb">'+t('Login')+'</button>'+
 '<div class="row" style="justify-content:center;margin-top:10px"><button class="ib" id="ll" title="'+t('Language')+'" aria-label="'+t('Language')+'">'+(S.lang=='fa'?'EN':'FA')+'</button><button class="ib" id="lt" title="'+t('Light / dark')+'" aria-label="'+t('Light / dark')+'">'+sun()+'</button></div></div></div>';
 function go(){api('POST','/api/login',{username:$('#lu').value,password:$('#lp').value,otp:$('#lo').value}).then(function(r){S.token=r.token;localStorage.setItem('kk_tok',r.token);boot()}).catch(function(e){if(e.data&&e.data.need_otp){$('#otpw').classList.remove('hide');$('#lo').focus()}fail(e)})}
 $('#lb').onclick=go;$$('#lu,#lp,#lo').forEach(function(i){i.onkeydown=function(e){if(e.key=='Enter')go()}});
 $('#ll').onclick=function(){S.lang=S.lang=='fa'?'en':'fa';localStorage.setItem('kk_lang',S.lang);loginView(!$('#otpw').classList.contains('hide'))};
 $('#lt').onclick=function(){S.theme=S.theme=='light'?'dark':'light';localStorage.setItem('kk_theme',S.theme);applyLook();this.innerHTML=sun()};
}
function logout(silent){if(!silent&&S.token)api('POST','/api/logout').catch(function(){});S.token='';localStorage.removeItem('kk_tok');loginView()}

// ---------------------------------------------------------------- shell
var PAGES=[['dash','Dashboard','dash'],['users','Users','users'],['vpn','VPN services','shield2'],['nodes','Servers','nodes'],['kmix','KANKI MIX','game'],['kgame','MIX+\u200e','game'],['xray','Xray','xray'],['antidpi','Anti-DPI tunnels','security'],['dns','Kanki DNS','dns'],['servers','Tunnel servers','srv'],['tunnels','Tunnels','tunnel'],['traffic','Traffic & stats','traffic'],['ports','Port management','ports'],['bot','Sales bot','bot'],['emergency','Emergency chat','sos'],['backup','Backup','backup'],['security','Security','security'],['settings','Settings','settings']];
function pgOf(k){for(var i=0;i<PAGES.length;i++)if(PAGES[i][0]==k)return PAGES[i];return PAGES[0]}
function decoratePh(){var ph=$('#pg .ph');if(!ph||ph.querySelector('.phi'))return;var d=ph.firstElementChild;if(!d||d.tagName!='DIV')return;
 var inner=document.createElement('div');while(d.firstChild)inner.appendChild(d.firstChild);
 var i=document.createElement('span');i.className='phi';i.innerHTML=ic(pgOf(S.page)[2],22);d.appendChild(i);d.appendChild(inner)}
window.addEventListener('hashchange',function(){if(!S.token||!S.me)return;var h=(location.hash||'#dash').slice(1).split('/');
 // moving between the tabs of the page already open: only the tab changes
 if(h[0]==S.page&&window['tab_'+S.page]&&$('#pg .ptabs')){S.sub=h[1]||'';navMark(S.page,S.sub);window['tab_'+S.page](S.sub);return}route()});
function autoRefresh(fn){clearInterval(S.timer);var sec=Math.max(5,(S.me&&S.me.refresh)||10);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible')fn()},sec*1000)}
function boot(){api('GET','/api/me').then(function(me){S.me=me;try{localStorage.setItem('kk_logo',me.logo||'')}catch(e){}if(me.panel_name)document.title=me.panel_name;
  if(!localStorage.getItem('kk_color')&&me.color)S.color=me.color;if(!localStorage.getItem('kk_lang')&&me.lang)S.lang=me.lang;if(!localStorage.getItem('kk_theme')&&me.theme)S.theme=me.theme;
  applyLook();shell();route()}).catch(function(e){if(e.message!='unauthorized')loginView()})}

// ---------------------------------------------------------------- dashboard (live)
var DB={h:{},last:null,iv:+localStorage.getItem('kk_div')||2,paused:false,cpu:0,max:60,peak:{rx:0,tx:0},sys:null,ov:null};
var SVN={wireguard:'WireGuard',amneziawg:'AmneziaWG',hysteria2:'Hysteria2',kankimix:'KANKI MIX',web:'Web (Caddy)',panel:'Kanki Panel',node:'Node agent'};
function dbReset(){DB.h={cpu:[],ram:[],swap:[],disk:[],rx:[],tx:[],tcp:[],udp:[]};DB.last=null;DB.cpu=0;DB.peak={rx:0,tx:0};DB.sys=null;DB.paused=false;DB.dp=null}
function pushH(k,v){var a=DB.h[k];a.push(v);if(a.length>DB.max)a.shift()}
function pc(u,tt){return tt>0?Math.max(0,Math.min(100,100*u/tt)):0}
function rate(b){b=+b||0;var u=['B/s','KB/s','MB/s','GB/s'],i=0;while(b>=1024&&i<3){b/=1024;i++}return (i==0||b>=100?Math.round(b):b.toFixed(b>=10?1:2))+' '+u[i]}
function upt(s){s=Math.floor(+s||0);var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?N(d)+' '+t('days')+' ':'')+N(p2(h))+':'+N(p2(m))}
function gcard(id,title,icon){return '<div class="gc" id="gc_'+id+'"><div class="gh"><span>'+icon+'</span><b>'+t(title)+'</b></div><div class="gb">'+
 '<svg class="ring" viewBox="0 0 80 80" aria-hidden="true"><circle class="rb" cx="40" cy="40" r="34"/><circle class="rf" id="rf_'+id+'" cx="40" cy="40" r="34" transform="rotate(-90 40 40)" stroke-dasharray="0 213.6"/><text class="rt" id="rt_'+id+'" x="40" y="46" text-anchor="middle">—</text></svg>'+
 '<div class="gi"><b id="gv_'+id+'">—</b><small id="gs_'+id+'"></small></div></div><div class="ch" id="ch_'+id+'"></div></div>'}
function setRing(id,p,val,sub){var f=$('#rf_'+id);if(!f)return;f.setAttribute('stroke-dasharray',(p*2.136).toFixed(1)+' 213.6');
 $('#gc_'+id).className='gc'+(p>=90?' hot':p>=70?' warm':'');$('#rt_'+id).textContent=N(Math.round(p))+'%';
 $('#gv_'+id).innerHTML=/^[\d۰-۹]/.test(val)?'<bdi class="ltr">'+esc(val)+'</bdi>':esc(val);$('#gs_'+id).textContent=sub||''}
function dashTimers(){clearInterval(S.timer);clearInterval(S.timer2);S.timer=setInterval(dashTick,DB.iv*1000);S.timer2=setInterval(dashSys,10000)}
function dashLive(state){var l=$('#d_live');if(!l)return;l.className='live'+(state?' '+state:'');$('#d_lt').textContent=state=='bad'?t('Reconnecting…'):state=='off'?t('Paused'):t('Live')}
function goUsers(f){S.filter=f;S.q='';S.pg=1;S.pf='all';location.hash='#users'}
function dashTick(){if(S.page!='dash'||DB.paused||document.visibilityState!='visible')return;
 api('GET','/api/live').then(function(l){if(S.page!='dash')return;var p=DB.last,cpu=DB.cpu,rxs=0,txs=0;
  if(p&&l.cpu_total>p.cpu_total){var dT=l.cpu_total-p.cpu_total,dI=l.cpu_idle-p.cpu_idle;cpu=Math.max(0,Math.min(100,100*(1-dI/dT)))}
  else if(!p)cpu=Math.min(100,100*((l.load&&l.load[0])||0)/(l.cores||1));
  if(p&&l.ts>p.ts){var sec=(l.ts-p.ts)/1000;rxs=Math.max(0,(l.net_rx-p.net_rx)/sec);txs=Math.max(0,(l.net_tx-p.net_tx)/sec)}
  DB.last=l;DB.cpu=cpu;
  pushH('cpu',cpu);pushH('ram',pc(l.mem_used,l.mem_total));pushH('swap',pc(l.swap_used,l.swap_total));
  if(p){pushH('rx',rxs);pushH('tx',txs);if(rxs>DB.peak.rx)DB.peak.rx=rxs;if(txs>DB.peak.tx)DB.peak.tx=txs}
  pushH('tcp',l.tcp_est);pushH('udp',l.udp);if(DB.dp!=null)pushH('disk',DB.dp);
  dashLive('');dashDraw(rxs,txs)}).catch(function(){dashLive('bad')})}
function dashDraw(rxs,txs){var l=DB.last;if(!l||!$('#d_sub'))return;
 $('#d_sub').textContent=(l.host||'server')+' · '+(l.kernel||'')+' · '+t('Uptime')+' '+upt(l.uptime);
 var cpu=DB.cpu,rp=pc(l.mem_used,l.mem_total),sp=pc(l.swap_used,l.swap_total);
 setRing('cpu',cpu,N((l.load||[0])[0]),t('Load')+' · '+N(l.cores)+' '+t('Cores'));
 setRing('ram',rp,N(bytes(l.mem_used))+' / '+N(bytes(l.mem_total)),'');
 setRing('swap',sp,l.swap_total>0?N(bytes(l.swap_used))+' / '+N(bytes(l.swap_total)):t('No swap'),'');
 $('#ch_cpu').innerHTML=areaChart([{v:DB.h.cpu,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#ch_ram').innerHTML=areaChart([{v:DB.h.ram,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#ch_swap').innerHTML=areaChart([{v:DB.h.swap,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#ch_disk').innerHTML=areaChart([{v:DB.h.disk,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#n_if').textContent=l.iface||'';$('#n_rx').textContent=N(rate(rxs));$('#n_tx').textContent=N(rate(txs));
 $('#n_prx').textContent=N(rate(DB.peak.rx));$('#n_ptx').textContent=N(rate(DB.peak.tx));$('#n_trx').textContent=N(bytes(l.net_rx));$('#n_ttx').textContent=N(bytes(l.net_tx));
 $('#ch_net').innerHTML=areaChart([{v:DB.h.rx,c:'a'},{v:DB.h.tx,c:'b'}],{h:132,cap:DB.max});
 $('#c_tcp').textContent=N(l.tcp_est);$('#c_udp').textContent=N(l.udp);$('#c_sub').textContent=t('TCP listening')+': '+N(l.tcp_listen);
 $('#ch_con').innerHTML=areaChart([{v:DB.h.tcp,c:'a'},{v:DB.h.udp,c:'b'}],{h:132,cap:DB.max})}
function dashSys(){if(S.page!='dash'||document.visibilityState!='visible')return;
 Promise.all([api('GET','/api/system'),api('GET','/api/overview'),api('GET','/api/nodes').catch(function(){return null})]).then(function(r){if(S.page!='dash')return;DB.sys=r[0];DB.ov=r[1];if(r[2]){S.nodes=r[2];drawNodesCard(r[2])}
  var s=r[0],dp=pc(s.disk_used,s.disk_total);DB.dp=dp;if(!DB.h.disk.length)for(var i=0;i<DB.max;i++)DB.h.disk.push(dp);
  setRing('disk',dp,N(bytes(s.disk_used))+' / '+N(bytes(s.disk_total)),'');$('#ch_disk').innerHTML=areaChart([{v:DB.h.disk,c:'a'}],{h:54,max:100,cap:DB.max});
  drawKpis(r[1]);drawSvcs(s.services||[])}).catch(function(){})}

function goNodes(add){S.openAdd=!!add;if(location.hash=='#nodes')route();else location.hash='#nodes'}

function drawSvcs(list){var el=$('#svcs');if(!el)return;list=(list||[]);
 if(!list.length){el.innerHTML='<span class="muted">—</span>';return}
 el.innerHTML=list.map(function(x){var fixed=['web','panel','node'].indexOf(x.key)>=0,k=esc(x.key);
  return '<div class="svc"><div class="sn"><span class="dot '+(x.active?'g':'r')+'"></span><div><b>'+esc(SVN[x.key]||x.key)+'</b><small class="ltr">'+esc(x.unit)+'</small></div></div>'+
  '<span class="badge '+(x.active?'g':'r')+'">'+(x.active?t('Running'):t('Stopped'))+'</span>'+
  '<div class="sbtn"><button class="sb on" data-svc="'+k+'" data-act="start" '+(x.active||fixed?'disabled':'')+'>▶ '+t('Start')+'</button>'+
  '<button class="sb off" data-svc="'+k+'" data-act="stop" '+(!x.active||fixed?'disabled':'')+' title="'+(fixed?t('Only restart is allowed for this service'):'')+'">■ '+t('Stop')+'</button>'+
  '<button class="sb" data-svc="'+k+'" data-act="restart">↻ '+t('Restart')+'</button></div></div>'}).join('')}
function svc(k,a){var go=function(){toast(t('Checking…'));api('POST','/api/services/'+encodeURIComponent(k)+'/'+a).then(function(r){toast(r.ok===false?t('Failed'):t('Done'),r.ok===false);setTimeout(dashSys,1500)}).catch(fail)};
 if(a=='start')go();else confirmDo(go)}

// ---------------------------------------------------------------- users
var PCOL={wg:'#1fa36b',awg:'#7c5cf0',hy2:'#d1497a',kmix:'#ff7a1a',kgame:'#e0b04a',xray:'#e0a020',dns:'#2a9df4'};
var SORTS={new:function(a,b){return b.id-a.id},old:function(a,b){return a.id-b.id},name:function(a,b){return a.username.toLowerCase()<b.username.toLowerCase()?-1:1},
 usage:function(a,b){return usageVal(b)-usageVal(a)},expiry:function(a,b){return expVal(a)-expVal(b)},seen:function(a,b){return (b.last_seen_ts||0)-(a.last_seen_ts||0)}};
function usageVal(u){return u.traffic_limit_gb>0?u.traffic_used_gb/u.traffic_limit_gb:-1}
function expVal(u){return u.expires_ts>0?u.expires_ts:9e15}
function hasP(u,p){return (','+u.protocols+',').indexOf(','+p+',')>=0}
function ustate(u){if(!u.enabled)return 'disabled';if(u.status!='Active')return 'finished';return 'active'}
function usage(u){var lim=u.traffic_limit_gb;return lim>0?Math.min(100,Math.round(100*u.traffic_used_gb/lim)):-1}
function findU(id){for(var i=0;i<S.users.length;i++)if(S.users[i].id==id)return S.users[i]}
function pUsers(){var pg=$('#pg');
 S.size=+localStorage.getItem('kk_size2')||48;S.sort=localStorage.getItem('kk_sort')||'new';S.pf=S.pf||'all';S.filter=S.filter||'all';S.q=S.q||'';S.pg=1;S.sel={};S.selMode=false;
 var fo=[['all','All'],['online','Online'],['offline','Offline'],['active','Active'],['finished','Expired / out of data'],['disabled','Disabled']],
  so=[['new','Newest'],['old','Oldest'],['name','Name'],['usage','Most used'],['expiry','Nearest expiry'],['seen','Last seen']],
  po=[['all','All protocols']].concat(PROTOS);
 var opt=function(a,cur,tr){return a.map(function(x){return '<option value="'+x[0]+'"'+(x[0]==cur?' selected':'')+'>'+(tr===false?esc(x[1]):t(x[1]))+'</option>'}).join('')};
 pg.innerHTML='<div class="ph"><div><h2>'+t('Users')+'</h2><p id="ucount"></p></div><div class="row" style="gap:6px;flex-wrap:nowrap"><button class="ib" id="selm" title="'+t('Select')+'" aria-label="'+t('Select')+'">'+ic('sel',18)+'</button><button class="ib" id="rf" title="'+t('Refresh')+'">'+ic('refresh',17)+'</button><button class="btn" onclick="newUser()">+ '+t('New user')+'</button></div></div>'+
 '<div class="card strip" id="ust"></div><div class="lvbar" id="ulv"></div>'+
 '<div class="utools"><div class="srch"><input id="q" type="search" autocomplete="off" placeholder="'+t('Search by name or note…')+'" value="'+esc(S.q)+'"><button id="qx" class="'+(S.q?'':'hide')+'" aria-label="clear">✕</button></div>'+
  '<select id="flt" aria-label="'+t('Status')+'">'+opt(fo,S.filter)+'</select><select id="pf" aria-label="'+t('Protocol')+'">'+opt(po,S.pf,false).replace('>All protocols<','>'+t('All protocols')+'<')+'</select><select id="srt" aria-label="'+t('Sort')+'">'+opt(so,S.sort)+'</select></div>'+
 '<div class="selbar hide" id="selbar"><label><span class="ck"><input type="checkbox" id="sall"><i></i></span><span>'+t('Select all')+' (<span id="sallc">0</span>)</span></label></div>'+
 '<div class="uchips" id="ul"><div class="empty2">'+t('Loading…')+'</div></div><div class="pager2" id="pager"></div>'+
 '<div class="bulk hide" id="bulk"><span class="cnt" id="bcnt"></span><button class="b2" data-b="enable">'+t('Enable')+'</button><button class="b2" data-b="disable">'+t('Disable')+'</button><button class="b2" data-b="reset">'+t('Reset traffic')+'</button><button class="b2" data-b="extend">'+t('Extend')+'</button><button class="b2 bd" data-b="delete">'+t('Delete')+'</button><button class="ib" data-b="clear" title="'+t('Clear selection')+'">✕</button></div>';
 $('#q').oninput=function(){S.q=this.value;$('#qx').classList.toggle('hide',!this.value);S.pg=1;pruneSel();drawUsers()};
 $('#qx').onclick=function(){$('#q').value='';S.q='';this.classList.add('hide');S.pg=1;pruneSel();drawUsers()};
 $('#flt').onchange=function(){S.filter=this.value;S.pg=1;pruneSel();drawUsers();drawStats()};
 $('#pf').onchange=function(){S.pf=this.value;S.pg=1;pruneSel();drawUsers()};
 $('#srt').onchange=function(){S.sort=this.value;localStorage.setItem('kk_sort',S.sort);S.pg=1;drawUsers()};
 $('#rf').onclick=function(){loadUsers()};
 $('#selm').onclick=function(){S.selMode=!S.selMode;if(!S.selMode)S.sel={};this.classList.toggle('on',S.selMode);drawUsers()};
 $('#sall').onchange=function(){var all=this.checked;filtered().forEach(function(u){if(all)S.sel[u.id]=1;else delete S.sel[u.id]});drawUsers()};
 $('#ust').onclick=function(e){var b=e.target.closest('[data-f]');if(!b)return;S.filter=b.dataset.f;S.pg=1;$('#flt').value=S.filter;pruneSel();drawUsers();drawStats()};
 $('#ul').onclick=function(e){var b=e.target.closest('[data-id]');if(b){var id=+b.dataset.id;
   if(S.selMode){if(S.sel[id])delete S.sel[id];else S.sel[id]=1;b.classList.toggle('sel',!!S.sel[id]);drawSelBar(filtered());drawBulk()}else editUser(id);return}
  if(e.target.closest('[data-a=new]'))newUser()};
 $('#pager').onclick=function(e){var b=e.target.closest('[data-pg]');if(b&&!b.disabled){S.pg=+b.dataset.pg;drawUsers();window.scrollTo(0,0)}};
 $('#pager').onchange=function(e){if(e.target.id=='psz'){S.size=+e.target.value;localStorage.setItem('kk_size2',S.size);S.pg=1;drawUsers()}};
 $('#bulk').onclick=function(e){var b=e.target.closest('[data-b]');if(b)bulkDo(b.dataset.b)};
 loadUsers();api('GET','/api/nodes').then(function(n){S.nodes=n}).catch(function(){});autoRefresh(loadUsers)}
function loadUsers(){return Promise.all([api('GET','/api/users'),api('GET','/api/overview')]).then(function(r){S.users=r[0];S.ov=r[1];
 var live={};S.users.forEach(function(u){live[u.id]=1});Object.keys(S.sel).forEach(function(k){if(!live[k])delete S.sel[k]});drawStats();drawUsers()}).catch(fail)}
function drawStats(){var o=S.ov;if(!o||!$('#ust'))return;
 var c=[['g',o.online,'Online','online'],['',o.offline,'Offline','offline'],['g',o.active,'Active','active'],['y',o.expired,'Finished','finished'],['r',o.disabled,'Disabled','disabled']];
 $('#ust').innerHTML='<button class="sc tot'+(S.filter=='all'?' act':'')+'" data-f="all">'+ic('users',14)+' <b>'+N(o.users)+'</b></button>'+
  c.map(function(x){return '<button class="sc'+(S.filter==x[3]?' act':'')+'" data-f="'+x[3]+'"><span class="dot '+x[0]+'"></span>'+t(x[2])+' <b>'+N(x[1])+'</b></button>'}).join('')+
  '<span class="sc pr" style="border:0;padding:0 2px">|</span>'+PROTOS.map(function(p){return '<span class="sc pr">'+p[1]+' <b>'+N((o.protocols||{})[p[0]]||0)+'</b></span>'}).join('');
 drawLive()}
// connected right now, by protocol: a count per protocol, a tap filters the list to it
function liveOf(u){return u.live||[]}
function drawLive(){var el=$('#ulv');if(!el)return;var cnt={},any=0;
 S.users.forEach(function(u){var seen={};liveOf(u).forEach(function(c){if(!seen[c.p]){seen[c.p]=1;cnt[c.p]=(cnt[c.p]||0)+1}});if(liveOf(u).length)any++});
 if(!any){el.innerHTML='<span class="muted" style="font-size:12px">'+t('Nobody is connected right now')+'</span>';if(S.lv){S.lv='';drawUsers()}return}
 el.innerHTML='<span class="muted" style="font-size:12px;font-weight:700">'+t('Connected now')+':</span>'+
  '<button class="sc'+(S.lv?'':' act')+'" data-lv=""><span class="dot g"></span>'+t('All')+' <b>'+N(any)+'</b></button>'+
  PROTOS.filter(function(p){return cnt[p[0]]}).map(function(p){return '<button class="sc'+(S.lv==p[0]?' act':'')+'" data-lv="'+p[0]+'" style="--pc:'+(PCOL[p[0]]||'#999')+'"><i></i><bdi dir="ltr">'+p[1]+'</bdi> <b>'+N(cnt[p[0]])+'</b></button>'}).join('');
 el.onclick=function(e){var b=e.target.closest('[data-lv]');if(!b)return;S.lv=b.dataset.lv;S.pg=1;drawLive();drawUsers()}}
function liveShort(p){return {wg:'WG',awg:'AWG',hy2:'HY2',kmix:'MIX',kgame:'MIX+\u200e',xray:'XR',dns:'DNS'}[p]||p.toUpperCase()}
// what a user is connected with: one badge per protocol, the flag of the server's exit country and a small
// Iran flag when that config goes through an Iran tunnel
function liveBadges(lv){var by={},order=[];lv.forEach(function(c){if(!by[c.p]){by[c.p]=[];order.push(c.p)}by[c.p].push(c)});
 return order.slice(0,3).map(function(p){var fl='',seen={};by[p].forEach(function(c){var k=(c.cc||'')+(c.t?'+':'');if(seen[k])return;seen[k]=1;
   if(c.cc)fl+='<span class="lvf">'+flagOf(c.cc)+'</span>';if(c.t)fl+='<span class="lvf lvir">'+flagOf('IR')+'</span>'});
  return '<i dir="ltr" style="--pc:'+(PCOL[p]||'#888')+'">'+liveShort(p)+(fl?' '+fl:'')+'</i>'}).join('')}
function filtered(){var q=S.q.trim().toLowerCase(),f=S.filter;
 var out=S.users.filter(function(u){
  if(q&&(u.username+' '+u.notes+' '+(u.tg_id||'')).toLowerCase().indexOf(q)<0)return false;
  if(S.pf&&S.pf!='all'&&!hasP(u,S.pf))return false;
  if(S.lv&&!liveOf(u).some(function(c){return c.p==S.lv}))return false;
  if(f=='online')return u.online_connections>0||liveOf(u).length>0;if(f=='offline')return !(u.online_connections>0||liveOf(u).length>0);if(f!='all')return ustate(u)==f;return true});
 out.sort(SORTS[S.sort]||SORTS.new);return out}
function pruneSel(){var ok={};filtered().forEach(function(u){ok[u.id]=1});Object.keys(S.sel).forEach(function(k){if(!ok[k])delete S.sel[k]})}
function drawUsers(){var el=$('#ul');if(!el)return;var list=filtered(),pages=Math.max(1,Math.ceil(list.length/S.size));if(S.pg>pages)S.pg=pages;if(S.pg<1)S.pg=1;
 var part=list.slice((S.pg-1)*S.size,S.pg*S.size);
 el.className='uchips'+(S.selMode?' selmode':'');
 el.innerHTML=part.length?part.map(uchip).join(''):'<div class="empty2">'+(S.users.length?t('No match'):t('No users yet')+'<br><button class="btn" data-a="new">+ '+t('Create the first user')+'</button>')+'</div>';
 drawPager(pages);drawSelBar(list);drawBulk();
 $('#ucount').textContent=N(S.users.length)+' '+t('users total')+(list.length!=S.users.length?' · '+N(list.length)+' '+t('match'):'')}
function drawSelBar(list){var c=$('#sall');if(!c)return;var n=0;list.forEach(function(u){if(S.sel[u.id])n++});
 $('#selbar').classList.toggle('hide',!S.selMode);
 c.checked=list.length>0&&n==list.length;c.indeterminate=n>0&&n<list.length;$('#sallc').textContent=N(list.length)}
function drawBulk(){var b=$('#bulk');if(!b)return;var n=Object.keys(S.sel).length;b.classList.toggle('hide',!n);$('#bcnt').textContent=N(n)+' '+t('selected')}
function drawPager(pages){var el=$('#pager');if(!el)return;var h='',i,nums=[];
 if(pages>1){for(i=1;i<=pages;i++){if(i==1||i==pages||Math.abs(i-S.pg)<=1)nums.push(i);else if(nums[nums.length-1]!=='…')nums.push('…')}
  h+='<button class="b2" data-pg="'+(S.pg-1)+'" '+(S.pg<=1?'disabled':'')+'>'+t('Prev')+'</button>';
  nums.forEach(function(n){h+=n==='…'?'<span class="dots">…</span>':'<button class="b2'+(n==S.pg?' on':'')+'" data-pg="'+n+'">'+N(n)+'</button>'});
  h+='<button class="b2" data-pg="'+(S.pg+1)+'" '+(S.pg>=pages?'disabled':'')+'>'+t('Next')+'</button>'}
 h+='<select id="psz" aria-label="'+t('per page')+'">'+[24,48,96,200].map(function(n){return '<option value="'+n+'"'+(n==S.size?' selected':'')+'>'+N(n)+' '+t('per page')+'</option>'}).join('')+'</select>';
 el.innerHTML=h}
// ---- single-user actions
function resetU(id){confirmDo(function(){api('POST','/api/users/'+id+'/reset').then(function(){toast(t('Done'));loadUsers()}).catch(fail)})}
function delU(id){confirmDo(function(){api('DELETE','/api/users/'+id).then(function(){closeModal();toast(t('Done'));loadUsers()}).catch(fail)})}

// ---- bulk actions
function bulkDo(a){var ids=Object.keys(S.sel).map(Number);if(a=='clear'){S.sel={};drawUsers();return}if(!ids.length)return;if(a=='extend')return bulkExtend(ids);
 var run=function(){api('POST','/api/bulk/users',{ids:ids,action:a}).then(function(){S.sel={};toast(t('Done'));loadUsers()}).catch(fail)};
 if(a=='delete'){if(confirm(t('Delete selected users?')+' ('+N(ids.length)+')'))run()}else if(a=='reset')confirmDo(run);else run()}
function bulkExtend(ids){modal(mhead(t('Extend'),N(ids.length)+' '+t('selected'))+'<div class="g2f"><div><label class="f">'+t('Days to add')+'</label><input type="number" id="x_d" min="0" value="30"></div><div><label class="f">'+t('GB to add')+'</label><input type="number" id="x_g" min="0" step="0.5" value="0"></div></div>'+
 '<button class="btn" style="width:100%;margin-top:12px" id="x_go">'+t('Apply')+'</button>');
 $('#x_go').onclick=function(){var d=+$('#x_d').value||0,g=+$('#x_g').value||0;if(d<=0&&g<=0)return toast(t('Enter days or GB'),1);
  api('POST','/api/bulk/users',{ids:ids,action:'extend',days:d,gb:g}).then(function(){closeModal();S.sel={};toast(t('Done'));loadUsers()}).catch(fail)}}

// ---- QR / configs
function qrInto(el,text){el.innerHTML='<div class="qr" style="margin:8px 0"></div>';api('GET','/api/qr?text='+encodeURIComponent(text),undefined,{blob:1}).then(function(r){var i=new Image();i.alt='QR';i.src=URL.createObjectURL(r.blob);el.querySelector('.qr').appendChild(i)}).catch(fail)}
function sheetCfg(id){var u=findU(id);if(!u)return;var un=u.nodes.split(',').filter(Boolean),pr=u.protocols.split(','),map={wg:'wireguard',awg:'amneziawg',hy2:'hysteria2',kmix:'kankimix'},rows='';
 S.nodes.forEach(function(n){if(un.length&&un.indexOf(n.id)<0)return;if(!un.length&&!n.accept_all)return;var inf=n.info||{},b='';
  pr.forEach(function(p){if(!map[p])return;var base='/api/config/'+u.id+'/'+map[p]+'?sub='+encodeURIComponent(u.code)+'&node='+encodeURIComponent(n.id);
   var cb=function(nm,tg){return '<a class="cfgb" style="--pc:'+PCOL[p]+'"'+(tg?' target="_blank"':'')+' href="'+base+'">'+ic('dl',14)+nm+'</a>'};
   if(p=='wg'&&inf.wg_pub)b+=cb('WireGuard');if(p=='awg'&&inf.awg_pub)b+=cb('AmneziaWG');
   if(p=='hy2'&&inf.hy2_port)b+=cb('Hysteria2',1);if(p=='kmix'&&inf.kmix_port)b+=cb('KANKI MIX',1)});
  if(b)rows+='<div class="li" style="flex-wrap:wrap"><b>'+esc(n.name)+'</b><span class="row">'+b+'</span></div>'});
 $('#sx').innerHTML='<div class="list" style="margin:8px 0">'+(rows||'<p class="muted">'+t('No configs: user has no nodes or protocols')+'</p>')+'</div>'}

// ---- form (create + edit): Jalali expiry, quick add days / GB
function dateVal(ts){return ts?jdate(ts):''}
function timeVal(ts){if(!ts)return '23:59';var d=new Date(ts*1000);return p2(d.getHours())+':'+p2(d.getMinutes())}
function readExp(){var s=unN(($('#f_date').value||'').trim());if(!s)return 0;var m=s.match(/^(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})$/);if(!m)return NaN;
 var y=+m[1],mo=+m[2],d=+m[3];if(mo<1||mo>12||d<1||d>31)return NaN;var g=y<1700?j2g(y,mo,d):[y,mo,d],tm=($('#f_time').value||'23:59').split(':'),
  ts=Math.floor(new Date(g[0],g[1]-1,g[2],+tm[0]||0,+tm[1]||0,0).getTime()/1000);return isNaN(ts)?NaN:ts}
function setExp(ts){$('#f_date').value=dateVal(ts);$('#f_time').value=timeVal(ts);prevExp()}
function prevExp(){var el=$('#f_prev');if(!el)return;var ts=readExp();
 if(isNaN(ts)){el.innerHTML='<span class="bad2">'+t('Invalid date')+'</span>';return}
 if(!ts){el.textContent='∞ '+t('Unlimited');return}
 var d=new Date(ts*1000);el.innerHTML=leftTxt(ts)+' · <span class="ltr muted">'+d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate())+' '+p2(d.getHours())+':'+p2(d.getMinutes())+'</span>'}
function qDays(n){var cur=readExp(),now=Math.floor(Date.now()/1000);if(isNaN(cur)||!cur||cur<now)cur=now;setExp(cur+n*86400)}
function qGB(n,u){var cur=+$('#f_gb').value||0,used=u?u.traffic_used_gb:0,base=cur>0?(used>=cur?used:cur):0;$('#f_gb').value=Math.round((base+n)*100)/100}
// user / config names: English letters and digits, 3-12, starting with a letter (WireGuard apps refuse other names)
var NAME_ERR='name: English letters and digits only, 3-12 characters, starting with a letter (like mahtab87)';
function nameOk(v){return /^[A-Za-z][A-Za-z0-9]{2,11}$/.test(v)}
function ufForm(u){var protos=u?u.protocols.split(','):((S.me&&S.me.default_protocols)||'wg,awg,hy2').split(','),un=u?u.nodes.split(',').filter(Boolean):[],
  me0=S.me||{},dd=Math.max(1,+me0.def_days||30),exp=u?u.expires_ts:Math.floor(Date.now()/1000)+dd*86400,h='<div class="g2f">';
 h+='<div class="full"><label class="f">'+t('Username')+'</label><input id="f_name" class="ltr" autocomplete="off" value="'+esc(u?u.username:'')+'" placeholder="'+(u?'':t('Optional, created if empty'))+'" maxlength="12"><small class="muted">'+t('English letters and digits, 3-12, starting with a letter (like mahtab87). No spaces, emoji or symbols.')+'</small></div>';
 h+='<div class="full"><label class="f">'+t('Expiry date')+' <small>('+t(S.lang=='fa'?'Date (Jalali)':'Date')+')</small></label><div class="jd"><input id="f_date" class="ltr" inputmode="numeric" autocomplete="off" placeholder="'+N(S.lang=='fa'?'1405/01/01':'2026-01-31')+'" value="'+esc(dateVal(exp))+'"><input id="f_time" type="time" value="'+timeVal(exp)+'"><button type="button" class="ib" id="f_inf" title="'+t('Unlimited')+'">∞</button></div><div class="muted" id="f_prev" style="margin-top:5px"></div>'+
  '<div class="qchips" id="qd"><span class="muted">'+t('Quick add days')+'</span>'+[7,30,60,90,180,365].map(function(n){return '<button type="button" data-qd="'+n+'">+'+N(n)+'</button>'}).join('')+'</div></div>';
 h+='<div><label class="f">'+t('Total volume (0 = unlimited)')+'</label><div class="row" style="flex-wrap:nowrap"><input type="number" min="0" step="0.5" id="f_gb" value="'+(u?u.traffic_limit_gb:(me0.def_gb!=null&&me0.def_gb!==''?+me0.def_gb:30))+'"><button type="button" class="ib" id="f_gbinf" title="'+t('Unlimited')+'">∞</button></div></div>';
 h+='<div><label class="f">'+t('Connections')+'</label><input type="number" min="0" id="f_conn" value="'+(u?u.max_connections:Math.max(1,+me0.def_conns||1))+'"></div>';
 h+='<div class="full"><div class="qchips" id="qg" style="margin-top:0"><span class="muted">'+t('Quick add volume')+'</span>'+[5,10,20,50,100].map(function(n){return '<button type="button" data-qg="'+n+'">+'+N(n)+' GB</button>'}).join('')+'</div></div>';
 if(!u)h+='<div><label class="f">'+t('Count')+'</label><input type="number" min="1" max="200" id="f_count" value="1"></div><div></div>';
 h+='</div>'+ufServices(protos,un);
 return h+'<input id="f_note" placeholder="'+t('Note')+'" value="'+esc(u?u.notes:'')+'" style="margin-top:8px">'}
function wireForm(u){$('#f_date').oninput=prevExp;$('#f_time').oninput=prevExp;
 $('#f_inf').onclick=function(){$('#f_date').value='';prevExp()};$('#f_gbinf').onclick=function(){$('#f_gb').value=0};
 $('#qd').onclick=function(e){var b=e.target.closest('[data-qd]');if(b)qDays(+b.dataset.qd)};
 $('#qg').onclick=function(e){var b=e.target.closest('[data-qg]');if(b)qGB(+b.dataset.qg,u)};prevExp()}
function formBody(){var ts=readExp();if(isNaN(ts)){toast(t('Invalid date'),1);return null}
 var pr=$$('.f_pr').filter(function(x){return x.checked}).map(function(x){return x.value}),nd=$$('.f_nd'),ns=nd.filter(function(x){return x.checked}).map(function(x){return x.value});if(ns.length==nd.length)ns=[];
 return {expires_ts:ts,traffic_limit_gb:+$('#f_gb').value||0,max_connections:+$('#f_conn').value||0,protocols:pr,nodes:ns,notes:$('#f_note').value}}
function newUser(){modal(mhead(t('New user'))+ufForm(null)+'<button class="btn" style="width:100%;margin-top:12px" id="f_save">'+t('Create')+'</button>','wide');wireForm(null);
 $('#f_save').onclick=function(){var b=formBody();if(!b)return;b.username=$('#f_name').value.trim();if(b.username&&!nameOk(b.username))return toast(t(NAME_ERR),1);b.count=+$('#f_count').value||1;var me=this;me.disabled=true;
  api('POST','/api/users',b).then(function(r){toast(t('Saved'));return loadUsers().then(function(){var u=r&&r.length==1&&findU(r[0].id);if(u)editUser(u.id,'link');else closeModal()})}).catch(function(e){me.disabled=false;fail(e)})}}

// ---------------------------------------------------------------- nodes
// ---- node health: judged from the last sync and the CPU / RAM / disk the node reports
// the version the panel really runs (an older saved one of its own server made every up-to-date agent look old)
function panelVer(){if(S.me&&S.me.version)return S.me.version;var l=(S.nodes||[]).filter(function(x){return x.id=='local'})[0];return l&&l.info&&l.info.version||''}

function nHealthOf(n){var loc=n.id=='local',i=n.info||{},st=i.stats,r=[],lv=0,bump=function(l,m){r.push([l,m]);if(l>lv)lv=l};
 if(!loc&&n.sync_state=='pin mismatch')return{lv:2,c:'r',l:'Problem',r:[[2,'The node\'s certificate changed (reinstalled?): run its join command again, or remove and add the node']]};
 if(!loc&&!n.online)return{lv:2,c:'r',l:'Problem',r:[[2,'Not reachable: check the server, its agent and the firewall']]};
 if(!loc&&n.last_sync&&Date.now()/1000-n.last_sync>180)bump(1,'No contact for more than 3 minutes');
 if(n.sync_state=='mismatch')bump(1,'Some users are not on this server yet (config mismatch): press Sync');
 (i.services||[]).forEach(function(s){if(!s.active)bump(2,t('Service stopped')+': '+s.key+' ('+s.state+')')});
 if(st){var cpu=+st.cpu||0,mem=pc(st.mem_used,st.mem_total),dk=pc(st.disk_used,st.disk_total),sw=pc(st.swap_used,st.swap_total);
  if(cpu>=90)bump(2,t('CPU is full')+' ('+N(Math.round(cpu))+'%)');else if(cpu>=70)bump(1,t('CPU is busy')+' ('+N(Math.round(cpu))+'%)');
  if(mem>=92)bump(2,t('RAM is almost full')+' ('+N(Math.round(mem))+'%)');else if(mem>=80)bump(1,t('RAM is getting full')+' ('+N(Math.round(mem))+'%)');
  if(dk>=95)bump(2,t('Disk is almost full')+' ('+N(Math.round(dk))+'%)');else if(dk>=85)bump(1,t('Disk is getting full')+' ('+N(Math.round(dk))+'%)');
  if(st.swap_total>0&&sw>=50)bump(1,t('Using a lot of swap: the server needs more RAM')+' ('+N(Math.round(sw))+'%)');
 }else if(!loc)bump(0,'Press Update agent to see CPU, RAM and disk of this node');
 var pv=panelVer();if(!loc&&pv&&i.version&&verLt(i.version,pv))bump(1,t('Agent is on an older version')+' (v'+i.version+'): '+t('press Update agent'));
 if(n.maint)bump(1,'Under maintenance: new users are not sent here');
 return lv==2?{lv:2,c:'r',l:'Problem',r:r}:lv==1?{lv:1,c:'y',l:'Under pressure',r:r}:{lv:0,c:'g',l:'Healthy',r:r}}
function nMeter(lbl,p,txt){var c=p>=90?'var(--bad)':p>=70?'var(--warn)':'var(--ok)';
 return '<div class="nm"><div class="nmh"><small>'+t(lbl)+'</small><b class="ltr">'+txt+'</b></div><i><s style="width:'+Math.round(p)+'%;background:'+c+'"></s></i></div>'}
S.nopen=S.nopen||{};
function findN(id){for(var i=0;i<S.nodes.length;i++)if(S.nodes[i].id==id)return S.nodes[i]}
function nAct(id,a){toast(t('Checking…'));api('POST','/api/nodes/'+encodeURIComponent(id)+'/'+a).then(function(r){toast(r.ok===false?(r.result&&r.result.error||'failed'):t('Done'),r.ok===false);loadNodes()}).catch(fail)}
function nHealth(id){toast(t('Checking…'));api('POST','/api/nodes/'+encodeURIComponent(id)+'/health').then(function(r){var n=findN(id);
 modal(mhead(t('Health'),n?n.name:'')+'<p>'+(r.ok?'<span class="badge g">OK</span>':'<span class="badge r">'+t('Offline')+'</span>')+' <span class="ltr">'+r.ms+' ms</span> '+(r.version?'· v'+esc(r.version):'')+(r.load?' · load '+esc(r.load):'')+'</p>'+
 '<div class="list">'+((r.services||[]).map(function(s){return '<div class="li"><span>'+esc(s.key)+' <small class="ltr">'+esc(s.unit)+'</small></span><span class="badge '+(s.active?'g':'r')+'">'+esc(s.state)+'</span></div>'}).join(''))+'</div>')}).catch(fail)}
function nAssign(id,add){var n=findN(id);if(!confirm(t(add?'Add this node to ALL users?':'Remove this node from ALL users?')+(n?' ('+n.name+')':'')))return;
 toast(t('Checking…'));api('POST','/api/nodes/'+encodeURIComponent(id)+'/'+(add?'assign-all':'unassign-all')).then(function(){toast(t('Done'));loadNodes()}).catch(fail)}
function updateAll(){if(!confirm(t('Update every node, every tunnel server and the panel itself to the latest version?')))return;toast(t('Updating…'));
 api('POST','/api/update-all').then(function(r){var h='';
  h+='<p><b>'+t('Panel')+':</b> '+esc(String(r.panel))+(r.latest?' · '+esc(r.latest):'')+'</p>';
  if((r.nodes||[]).length)h+='<label class="f">'+t('Nodes')+'</label><div class="list">'+r.nodes.map(function(z){return '<div class="li"><span><b>'+esc(z.name)+'</b>'+(z.ok?'':'<small>'+esc(z.error||t('no answer: update it once with the kanki command'))+'</small>')+'</span><span>'+(z.ok?'✅':'❌')+'</span></div>'}).join('')+'</div>';
  if((r.agents||[]).length)h+='<label class="f">'+t('Tunnel servers (updating by themselves)')+'</label><p class="muted">'+esc(r.agents.join(', '))+'</p>';
  if((r.also_nodes||[]).length)h+='<label class="f">'+t('Both a node and a tunnel server (updated once, through the node)')+'</label><p class="muted">'+esc(r.also_nodes.join(', '))+'</p>';
  if((r.manual||[]).length)h+='<div class="warnbox">'+t('These agents are too old to update remotely. Run the command kanki on them and choose 3 (Update) once:')+' <b>'+esc(r.manual.join(', '))+'</b></div>';
  if(!(r.nodes||[]).length&&!(r.agents||[]).length&&!(r.manual||[]).length&&String(r.panel)=='current')h+='<p>'+t('Everything is already up to date')+'</p>';
  modal(mhead(t('Update all'),'')+h);setTimeout(function(){if(S.page=='nodes')loadNodes()},8000)}).catch(fail)}

// ---------------------------------------------------------------- backup
function pBackup(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Backup')+'</h2><p>'+t('Full backup of users, credentials, certificates, VPN settings, nodes and panel state')+'</p></div></div>'+
 '<div class="g2"><div class="card" style="margin:0"><h3>'+t('Backup file')+'</h3><p class="sub">'+t('Encrypted archive. File name includes date and time.')+'</p><div class="row" style="flex-wrap:nowrap"><input id="bk_p" type="password" placeholder="'+t('Empty = panel backup passphrase')+'"><button class="btn" id="bk_go">'+t('Download backup')+'</button></div></div>'+
 '<div class="card" style="margin:0"><h3>'+t('Restore')+'</h3><p class="sub">'+t('Pick a backup file; if encrypted, enter its passphrase.')+'</p><div class="row" style="flex-wrap:nowrap"><label class="b2" style="white-space:nowrap">'+t('Choose file')+'<input type="file" id="rs_f" class="hide"></label><input id="rs_p" type="password" placeholder="'+t('Empty = panel backup passphrase')+'"></div><small class="muted" id="rs_n">'+t('No file chosen')+'</small>'+
 '<label class="chk" style="margin-top:8px"><input type="checkbox" id="rs_full">'+t('Also restore server keys & configs (same/new server migration)')+'</label><div style="text-align:center;margin-top:8px"><button class="btn" id="rs_go">'+t('Restore backup')+'</button></div></div></div>'+moveCard()+
 '<div class="card" style="margin-top:12px"><div class="row" style="justify-content:space-between"><div><h3>🌙 '+t('Nightly backup to the bot')+'</h3><p class="sub">'+t('Every night the database is cleaned and an encrypted backup is sent to Telegram')+'</p></div><label class="sw"><input type="checkbox" id="tg_on"><span></span></label></div>'+
 '<div class="g2"><div><label class="f">'+t('When')+'</label><div class="row" style="flex-wrap:nowrap;gap:6px"><select id="tg_m" style="width:auto"><option value="nightly">'+t('Every night at')+'</option><option value="hours">'+t('Every … hours')+'</option></select><input id="tg_at" class="ltr" style="max-width:90px" placeholder="03:00"><input id="tg_h" type="number" min="1" style="max-width:90px"></div><small class="muted">'+t('Iran time')+'</small></div>'+
 '<div><label class="f">'+t('Chat ID')+'</label><input id="tg_chat" class="ltr" placeholder="'+t('Auto after /start (or first bot admin)')+'"></div></div>'+
 '<div class="bkpass"><div><small class="muted">'+t('Panel backup passphrase (needed to restore)')+'</small><b class="ltr" id="tg_pw">••••••••</b></div><div class="row" style="gap:6px;flex-wrap:nowrap"><button class="ib" id="tg_eye" title="'+t('Show')+'">👁</button><button class="ib" id="tg_cp">'+ic('link',14)+'</button><button class="b2" id="tg_pch">'+t('Change')+'</button></div></div>'+
 '<details class="box" style="margin-top:8px"><summary><b>'+t('Separate backup bot (optional)')+'</b></summary><label class="f">'+t('Bot token')+'</label><input id="tg_tok" class="ltr" placeholder="123456789:AA…"><small class="muted" id="tg_tn"></small></details>'+
 '<div class="g2" style="margin-top:10px"><button class="b2" id="tg_test">✈ '+t('Test connection')+'</button><button class="b2" id="tg_send">⇪ '+t('Send backup now')+'</button></div><button class="btn" style="width:100%;margin-top:8px" id="tg_save">'+t('Save settings')+'</button><div class="li" style="margin-top:10px" id="tg_st"></div></div>'+
 '<div class="card"><div class="row" style="justify-content:space-between"><div><h3>🧹 '+t('Clean database')+'</h3><p class="sub">'+t('Removes old logs, expired sessions and abandoned unpaid orders, then compacts the file. Users and plans are not touched.')+'</p></div><button class="b2" id="db_cl">'+t('Clean now')+'</button></div><small class="muted" id="db_inf"></small></div>';
 $('#bk_go').onclick=function(){var p=$('#bk_p').value,me=this;me.disabled=true;api('POST','/api/backup',{passphrase:p},{blob:1}).then(function(r){dl(r);me.disabled=false}).catch(function(e){me.disabled=false;fail(e)})};
 $('#rs_f').onchange=function(){$('#rs_n').textContent=this.files[0]?this.files[0].name:t('No file chosen')};
 $('#rs_go').onclick=function(){var f=$('#rs_f').files[0];if(!f)return toast(t('No file chosen'),1);confirmDo(function(){
  api('POST','/api/restore',f,{headers:{'X-Passphrase':$('#rs_p').value,'X-Full':$('#rs_full').checked?'1':'0','Content-Type':'application/octet-stream'}}).then(function(){toast(t('Restore done, panel is restarting…'));setTimeout(function(){location.reload()},4000)}).catch(fail)})};
 var tg={},showPw=false,kb=function(n){return n>1048576?N((n/1048576).toFixed(1))+' MB':N(Math.round(n/1024))+' KB'};
 function tgDraw(){if(!$('#tg_on'))return;$('#tg_on').checked=!!tg.on;$('#tg_chat').value=tg.chat||'';$('#tg_h').value=tg.hours||24;$('#tg_at').value=tg.at||'03:00';$('#tg_m').value=tg.mode||'nightly';
  var hrs=tg.mode=='hours';$('#tg_at').style.display=hrs?'none':'';$('#tg_h').style.display=hrs?'':'none';
  $('#tg_pw').textContent=showPw?(tg.pass||''):'••••••••••';
  $('#tg_tn').textContent=tg.token_set?'✓':(tg.uses_bot_token?t('Empty = use the sales bot token'):'');
  $('#tg_st').innerHTML='<span><span class="dot '+(tg.status=='ok'?'g':tg.status?'r':'')+'"></span> '+(tg.on?t('On'):t('Off'))+'</span><small class="ltr">'+(tg.last?t('Last')+': '+fmtDate(tg.last,1)+' · '+esc(tg.status):'')+'</small>';
  $('#db_inf').textContent=t('Database size')+': '+kb(tg.db_size||0)+(tg.cleaned?' · '+t('Last cleaned')+': '+ago(tg.cleaned):'')}
 function tgLoad(){api('GET','/api/tgbackup').then(function(r){tg=r;tgDraw()}).catch(fail)}
 function tgBody(){return{token:$('#tg_tok').value,chat:$('#tg_chat').value,hours:+$('#tg_h').value||24,at:$('#tg_at').value||'03:00',mode:$('#tg_m').value,on:$('#tg_on').checked}}
 $('#tg_m').onchange=function(){tg.mode=this.value;tgDraw()};
 $('#tg_on').onchange=function(){api('PUT','/api/tgbackup',tgBody()).then(function(){toast(t('Saved'));tgLoad()}).catch(fail)};
 $('#tg_eye').onclick=function(){showPw=!showPw;tgDraw()};$('#tg_cp').onclick=function(){copy(tg.pass||'')};
 $('#tg_pch').onclick=function(){var p=prompt(t('New backup passphrase (min 6). Old backups still need the old one.'));if(!p)return;api('PUT','/api/tgbackup',{pass:p}).then(function(){toast(t('Saved'));tgLoad()}).catch(fail)};
 $('#tg_save').onclick=function(){api('PUT','/api/tgbackup',tgBody()).then(function(){toast(t('Saved'));tgLoad()}).catch(fail)};
 $('#tg_test').onclick=function(){api('PUT','/api/tgbackup',tgBody()).then(function(){return api('POST','/api/tgbackup/test')}).then(function(r){toast(r.ok?'✓ @'+r.bot+' → '+r.chat:'failed',!r.ok);tgLoad()}).catch(fail)};
 $('#tg_send').onclick=function(){toast(t('Checking…'));api('POST','/api/tgbackup/send').then(function(){toast(t('Done'));tgLoad()}).catch(function(e){fail(e);tgLoad()})};
 $('#db_cl').onclick=function(){var me=this;me.disabled=true;api('POST','/api/db/clean').then(function(r){me.disabled=false;var x=r.result||{};toast(t('Done')+' · '+kb(x.before||0)+' → '+kb(x.after||0));tgLoad()}).catch(function(e){me.disabled=false;fail(e)})};
 tgLoad();restoreBox();
 moveLoad();clearInterval(S.timer4);S.timer4=setInterval(function(){if(S.page=='backup'&&$('#v37move')&&!$('#modal').classList.contains('on'))moveLoad()},5000)}
// move the whole panel to a new server
function moveCard(){return '<div class="card" id="v37move"><h3>🚚 '+t('Move the panel to a new server')+'</h3><p class="sub">'+t("Everything moves: users, servers, tunnels, DNS, Xray, bot and plans, the panel settings, the keys of this server's WireGuard / AmneziaWG / Hysteria2 (users' configs keep working), the certificate and the app files.")+'</p><div id="mv_in">'+t('Loading…')+'</div></div>'}
function moveDraw(m){var el=$('#mv_in');if(!el)return;
 var steps='<ol class="steps" style="margin:6px 0 10px;line-height:2"><li><b>'+t("Point the panel's domain to the new server's IP")+'</b><br><small class="muted">'+t('In your DNS (Cloudflare / ArvanCloud): the A record of')+' <span class="ltr">'+esc(m.domain||'')+'</span> '+t('= the IP of the new server, without CDN (DNS only). The old panel keeps working by its IP until the move is done.')+'</small></li>'+
  '<li><b>'+t('Run this on the new server (Ubuntu / Debian, as root)')+'</b><br><small class="muted">'+t('It downloads everything straight from this server, puts it back with the same keys and starts the panel there. Then this panel stops by itself.')+'</small></li></ol>';
 if(m.done>0){el.innerHTML='<div class="okbox" style="padding:10px;border-radius:12px;border:1px solid var(--ok)">✓ '+t('Moved: the panel runs on the new server. This one is stopping.')+'</div>';return}
 if(!m.active){el.innerHTML=steps+'<label class="f">'+t("This server's IP (empty = found by itself)")+'</label><div class="inl"><input id="mv_ip" class="ltr" value="'+esc(m.ip||'')+'" placeholder="1.2.3.4"><button class="btn" id="mv_go" style="flex:none">'+t('Make the move command')+'</button></div>'+
   '<p class="hint">'+t('The backup above is complete too: it can also be restored by hand on a new server (Restore with «Also restore server keys»).')+'</p>';
  $('#mv_go').onclick=function(){var b=this;b.disabled=true;api('POST','/api/migrate/start',{ip:$('#mv_ip').value.trim()}).then(moveLoad).catch(function(e){b.disabled=false;fail(e)})};return}
 el.innerHTML=steps+'<pre class="ltr" id="mv_cmd" style="white-space:pre-wrap;word-break:break-all;font-size:11.5px;padding:10px;border-radius:12px;background:var(--in);border:1px solid var(--gb2);margin:0">'+esc(m.command)+'</pre>'+
  '<p class="hint">'+t('Valid for 3 hours, one time. It holds the key of the backup: do not share it.')+'</p>'+
  '<p style="margin:6px 0">'+(m.fetched>0?'<span class="okt">✓ '+t('The new server downloaded the backup')+(m.new_ip?' (<span class="ltr">'+esc(m.new_ip)+'</span>)':'')+'</span>':'<span class="muted">⏳ '+t('Waiting for the new server…')+'</span>')+'</p>'+
  '<div class="g2"><button class="btn" id="mv_cp">'+t('Copy the command')+'</button><button class="b2 bd" id="mv_x">'+t('Cancel the command')+'</button></div>';
 $('#mv_cp').onclick=function(){copy(m.command)};$('#mv_x').onclick=function(){api('DELETE','/api/migrate').then(moveLoad).catch(fail)}}
function moveLoad(){return api('GET','/api/migrate').then(moveDraw).catch(function(e){var el=$('#mv_in');if(el)el.textContent=e.message||''})}
// after a restore: which servers are back
function restoreBox(){var pg=$('#pg');if(!pg||S.page!='backup'||$('#svp_rs'))return;
 api('GET','/api/restore/check').then(function(r){if((!r.restored_at||Date.now()/1000-r.restored_at>3*86400)&&!r.bot_conflict||$('#svp_rs')||S.page!='backup')return;
  var sv=r.servers||[],bad=sv.filter(function(x){return (x.agent===false)||(x.vpn===false&&x.vpn_on)});
  var c=document.createElement('div');c.className='card';c.id='svp_rs';
  c.innerHTML='<h3>'+t('After restore')+'</h3><p class="sub">'+t('Restored')+' '+ago(r.restored_at)+(r.moved_from?' · '+t('from')+' <span class="ltr">'+esc(r.moved_from)+'</span>':'')+'</p>'+
   (r.bot_conflict?'<div class="warnbox">'+t('The panel on the old server still runs the same Telegram bot: both answer customers and both post to the channel. Stop it there: systemctl disable --now kanki-panel')+'</div>':'')+
   (bad.length?'<div class="list">'+sv.map(function(x){var ok=x.agent!==false&&!(x.vpn===false&&x.vpn_on);return '<div class="li"><span>'+esc(x.name)+'</span><span>'+(ok?'✅':'⏳ '+t('Not connected yet'))+'</span></div>'}).join('')+'</div>':'<p>✅ '+t('Every server is connected')+'</p>');
  var ph=$('#pg .ph');if(ph)ph.parentNode.insertBefore(c,ph.nextSibling)}).catch(function(){})}

// ---------------------------------------------------------------- security
function pSecurity(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Security')+'</h2><p>'+t('Login, 2FA, sessions and IP access')+'</p></div></div><div id="sec">'+t('Loading…')+'</div>';loadSec()}
function loadSec(){api('GET','/api/security').then(function(s){S.sec=s;var el=$('#sec');if(!el)return;
 var open=!s.ip_allow&&!s.ip_deny,lg=(s.logins||[]).slice(0,8);
 el.innerHTML='<div class="g4"><div class="stat"><div><small>'+t('Current account')+'</small><b style="font-size:15px">'+esc(s.admin_user)+'</b></div><i>◈</i></div><div class="stat"><div><small>2FA</small><b style="font-size:15px">'+(s.totp_on?'ON':'OFF')+'</b></div><i>◎</i></div><div class="stat"><div><small>'+t('Active sessions')+'</small><b style="font-size:15px">'+N(s.sessions.length)+'</b></div><i>⌁</i></div><div class="stat"><div><small>'+t('Network policy')+'</small><b style="font-size:15px">'+(open?t('Open'):t('Restricted'))+'</b></div><i>⬡</i></div></div>'+
 '<div class="g2" style="margin-top:12px"><div class="card" style="margin:0"><h3>'+t('Change login')+'</h3><label class="f">'+t('Current password')+'</label><input type="password" id="cp_cur"><label class="f">'+t('New username (optional)')+'</label><input id="cp_u" class="ltr" placeholder="'+esc(s.admin_user)+'"><label class="f">'+t('New password (min 8)')+'</label><input type="password" id="cp_p"><button class="btn" style="margin-top:10px;width:100%" onclick="chPass()">'+t('Save')+'</button></div>'+
 '<div class="card" style="margin:0"><div class="row" style="justify-content:space-between"><h3>'+t('Two-step login')+'</h3><span class="badge '+(s.totp_on?'g':'')+'">'+(s.totp_on?'ON':'OFF')+'</span></div><p class="sub">'+t('TOTP with apps like Google Authenticator / 2FAS')+'</p>'+
 '<div class="row"><button class="b2" onclick="totpSetup()" '+(s.totp_on?'disabled':'')+'>'+t('Enable 2FA')+'</button><button class="b2 bd" onclick="totpOff()" '+(s.totp_on?'':'disabled')+'>'+t('Disable 2FA')+'</button></div>'+
 '<label class="chk" style="margin-top:10px"><input type="checkbox" id="ip_f" '+(s.force_2fa?'checked':'')+'>'+t('Enforce 2FA for admin')+'</label>'+
 '<label class="f">'+t('Session lifetime (hours)')+'</label><input type="number" id="ip_h" min="1" value="'+esc(s.session_hours)+'"></div></div>'+
 '<div class="card" style="margin-top:12px"><div class="row" style="justify-content:space-between"><div><h3>'+t('Active sessions')+'</h3><p class="sub">'+t('Devices and IPs logged in to the panel')+'</p></div><button class="b2 bd" onclick="revokeOthers()">'+t('Log out others')+'</button></div><div class="list">'+
 s.sessions.map(function(x){var cur=x.id==s.current_session;return '<div class="li"><span><b class="ltr">'+esc(x.ip)+'</b> '+(cur?'<span class="badge g">'+t('current')+'</span>':'')+'<small class="ltr">'+esc(x.ua.slice(0,60))+' · '+ago(x.last_seen)+'</small></span>'+(cur?'':'<button class="b2 bd" onclick="sessDel(\''+x.id+'\')">✕</button>')+'</div>'}).join('')+'</div></div>'+
 '<details class="card secx"'+(open?'':' open')+'><summary><b>'+t('IP restriction')+'</b> <small class="muted">'+t('Your IP')+': <span class="ltr">'+esc(s.my_ip)+'</span></small></summary><p class="sub" style="margin-top:8px">'+t('Allow/Deny for the admin panel, one IP or CIDR per line')+'</p>'+
 '<div class="g2"><div><label class="f">Allow</label><textarea id="ip_a" class="ltr" rows="3" placeholder="'+t('IP / CIDR allowed, one per line')+'">'+esc(s.ip_allow)+'</textarea></div><div><label class="f">Deny</label><textarea id="ip_d" class="ltr" rows="3" placeholder="'+t('IP / CIDR blocked, one per line')+'">'+esc(s.ip_deny)+'</textarea></div></div></details>'+
 '<div style="text-align:center;margin:4px 0 12px"><button class="btn" onclick="savePolicy()">'+t('Save security policy')+'</button></div>'+
 '<div class="card"><h3>'+t('Login history')+'</h3><p class="sub">'+t('Last logins to the panel')+'</p><div class="list">'+(lg.map(function(l){return '<div class="li"><span><b>'+esc(l.username||'—')+'</b><small class="ltr">'+esc(l.ip)+' · '+fmtDate(l.ts,1)+'</small></span><span class="badge '+(l.ok?'g':'r')+'">'+(l.ok?'OK':'FAIL')+'</span></div>'}).join('')||'<span class="muted">—</span>')+'</div></div>'}).catch(fail)}
function totpSetup(){api('POST','/api/security/2fa/setup').then(function(r){modal(mhead(t('Enable 2FA'))+'<p class="muted">'+t('Scan with your authenticator app, then enter the 6-digit code')+'</p><div class="qr">'+r.qr+'</div><pre>'+esc(r.secret)+'</pre><input id="tf_c" inputmode="numeric" maxlength="6" class="ltr" placeholder="123456"><button class="btn" style="width:100%;margin-top:10px" id="tf_go">'+t('Confirm')+'</button>');
 $('#tf_go').onclick=function(){api('POST','/api/security/2fa/enable',{code:$('#tf_c').value}).then(function(){closeModal();toast(t('Done'));loadSec()}).catch(fail)}}).catch(fail)}
function totpOff(){var c=prompt(t('2FA code'));if(!c)return;api('POST','/api/security/2fa/disable',{code:c}).then(function(){toast(t('Done'));loadSec()}).catch(fail)}
function revokeOthers(){confirmDo(function(){api('POST','/api/security/revoke-others').then(loadSec).catch(fail)})}
function sessDel(id){api('DELETE','/api/security/sessions/'+id).then(loadSec).catch(fail)}
function chPass(){api('POST','/api/security/password',{current:$('#cp_cur').value,username:$('#cp_u').value,password:$('#cp_p').value}).then(function(){toast(t('Saved'));loadSec()}).catch(fail)}
function savePolicy(){api('POST','/api/security/policy',{ip_allow:$('#ip_a').value,ip_deny:$('#ip_d').value,session_hours:+$('#ip_h').value||24,force_2fa:$('#ip_f').checked}).then(function(){toast(t('Saved'));loadSec()}).catch(fail)}

// ---------------------------------------------------------------- settings
function setLogo(data){return api('PUT','/api/settings',{logo:data}).then(function(){S.me.logo=data;try{localStorage.setItem('kk_logo',data)}catch(e){}toast(t('Saved'));shell();route()})}
function wireLogo(){var f=$('#lg_file');if(!f)return;
 f.onchange=function(){var file=f.files&&f.files[0];if(!file)return;var rd=new FileReader();
  rd.onload=function(){var im=new Image();im.onload=function(){var best='',sz=[256,192,128],iw=im.width||256,ih=im.height||256;
    for(var i=0;i<sz.length&&!best;i++){var cv=document.createElement('canvas');cv.width=cv.height=sz[i];var cx=cv.getContext('2d'),r=Math.min(sz[i]/iw,sz[i]/ih),w=iw*r,h=ih*r;
     cx.drawImage(im,(sz[i]-w)/2,(sz[i]-h)/2,w,h);var d=cv.toDataURL('image/png');if(d.length<150000)best=d}
    if(!best)return toast(t('Image is too complex, use a simpler logo'),1);setLogo(best).catch(fail)};
   im.onerror=function(){toast(t('Cannot read this image'),1)};im.src=rd.result};
  rd.readAsDataURL(file)};
 var rm=$('#lg_rm');if(rm)rm.onclick=function(){confirmDo(function(){setLogo('').catch(fail)})}}
// ---------------------------------------------------------------- settings: sections, each saved on its own
var STSEC=[
 ['look','Appearance','brush','Name, logo, language, theme and colour of the panel',['panel_name','lang','theme','color','refresh']],
 ['net','Addresses','globe','Panel address, the public VPN address and subscription links',['endpoint','sub_base']],
 ['vpn','VPN & protocols','shield2','DNS, MTU and protocol behaviour on every server',['dns','mtu','awg_compat','conn_limit_on']],
 ['newu','New users','users','Ready values for the “New user” form',['default_protocols','def_gb','def_days','def_conns']],
 ['ntf','Notifications','bell','Telegram messages for you and for your buyers',['tg_alerts','warn_on','backup_on']],
 ['upd','Update & version','refresh','Version, update source and installing updates',['update_repo']],
 ['io','Export & import','box','Move all settings to another panel or keep a copy',[]]];
var ST_SKIP=['web_bind','web_port','domain','https_port','repo_env'];
function stSw(k,title,desc){return '<div class="srow"><div class="tx"><b>'+t(title)+'</b><small>'+t(desc)+'</small></div><label class="sw"><input type="checkbox" data-k="'+k+'"><span></span></label></div>'}
function stIn(k,label,ph,hint,cls,type){return '<div class="'+(cls||'')+'"><label class="f">'+t(label)+'</label><input data-k="'+k+'"'+(type?' type="'+type+'" min="0"':'')+' class="'+(type?'':'ltr')+'" placeholder="'+esc(ph||'')+'">'+(hint?'<div class="hint">'+t(hint)+'</div>':'')+'</div>'}
function stPick(k,items,cls){return '<input type="hidden" data-k="'+k+'"><div class="'+cls+'" data-pick="'+k+'">'+items.join('')+'</div>'}
function stBody(id,s){var addr='https://'+(s.domain||'')+(s.https_port&&s.https_port!='443'?':'+s.https_port:'')+'/admin';
 switch(id){
 case 'look':return '<div class="sgrid">'+stIn('panel_name','Panel name','Kanki Panel','Shown in the menu, the browser tab and the login page.')+
  '<div><label class="f">'+t('Auto refresh')+'</label><select data-k="refresh">'+[5,10,30,60].map(function(n){return '<option value="'+n+'">'+N(n)+' '+t('seconds')+'</option>'}).join('')+'</select><div class="hint">'+t('How often lists and the dashboard refresh themselves.')+'</div></div>'+
  '<div class="full"><label class="f">'+t('Logo')+'</label><div class="row" style="gap:10px"><div class="'+logoCls()+'" id="lg_prev" style="width:52px;height:52px;border-radius:15px">'+logoInner(((S.me&&S.me.panel_name)||'K').charAt(0))+'</div>'+
  '<label class="b2" for="lg_file" style="cursor:pointer;display:inline-flex;align-items:center;gap:6px">'+ic('image',16)+' '+t('Choose image')+'</label><input type="file" id="lg_file" accept="image/*" class="hide">'+
  '<button class="b2 bd'+(curLogo()?'':' hide')+'" id="lg_rm">'+t('Remove')+'</button></div><div class="hint">'+t('Saved at once. Shown in the header, the menu, the login page and the subscription page.')+'</div></div>'+
  '<div class="full"><label class="f">'+t('Language')+'</label>'+stPick('lang',['<button type="button" data-v="fa">فارسی<small class="muted" style="display:block;font-weight:500">راست به چپ</small></button>','<button type="button" data-v="en">English<small class="muted" style="display:block;font-weight:500">Left to right</small></button>'],'thc')+'</div>'+
  '<div class="full"><label class="f">'+t('Theme')+'</label>'+stPick('theme',['<button type="button" data-v="dark"><i style="background:linear-gradient(135deg,#1c160d,#070604)"></i>'+t('Dark')+'</button>','<button type="button" data-v="light"><i style="background:linear-gradient(135deg,#fffaf0,#e6dcc6)"></i>'+t('Soft light')+'</button>'],'thc')+'</div>'+
  '<div class="full"><label class="f">'+t('Panel color')+'</label>'+stPick('color',[['gold','#F5C451'],['turquoise','#2fd6d6'],['violet','#a78bfa'],['emerald','#34d399'],['rose','#fb7185']].map(function(c){return '<button type="button" data-v="'+c[0]+'" style="--sc:'+c[1]+'" title="'+t(c[0].charAt(0).toUpperCase()+c[0].slice(1))+'"></button>'}),'swc')+'</div></div>';
 case 'net':return '<div class="sgrid"><div class="full"><label class="f">'+t('Panel address')+'</label><div class="cpy"><input class="ltr" readonly value="'+esc(addr)+'"><button class="b2" type="button" onclick="copy(\''+esc(addr)+'\')">'+ic('copy',15)+'</button></div></div>'+
  stIn('endpoint','Public VPN host or IP',s.domain||'vpn.example.com','Written inside every user config. Empty = the panel domain.','full')+
  stIn('sub_base','Subscription base URL','https://sub.example.com','Base of the subscription links (for example a CDN domain). Empty = the panel address.','full')+
  '<div class="full box"><b>'+t('Separate subscription domain')+'</b><div class="hint">'+t('A domain that points to this server. The panel gets its SSL by itself and serves only the subscription pages on it, so the panel address stays hidden.')+'</div><div class="cpy"><input class="ltr" id="sd_in" placeholder="sub.example.ir" value="'+esc(s.sub_domain||'')+'"><button class="btn" type="button" id="sd_go">'+t('Set up SSL and use it')+'</button>'+(s.sub_domain?'<button class="b2 bd" type="button" id="sd_rm">'+t('Remove')+'</button>':'')+'</div><div class="hint" id="sd_msg">'+(s.sub_domain?'✓ https://'+esc(s.sub_domain)+'/sub/…':'')+'</div></div>'+
  '<div class="full box" id="si_box"><b>'+t('Serve the subscription from an Iran server')+'</b><div class="hint">'+t('For ISPs that block the panel domain: a tunnel server inside Iran serves the subscription pages with its own SSL and carries them to the panel through a hidden tunnel. Subscription links use it once it works.')+'</div><div id="si_in">'+t('Loading…')+'</div></div>'+
  '<div class="full">'+'<div class="srow"><div class="tx"><b>'+t('Use this address on every node too')+'</b><small>'+t('Nodes that have their own address switch back to this one when you save.')+'</small></div><label class="sw"><input type="checkbox" id="st_all"><span></span></label></div></div>'+
  '<div class="full box"><b>'+t('Web panel')+'</b><div class="g2"><div><label class="f">'+t('Web bind')+'</label><input class="ltr" readonly value="'+esc(s.web_bind)+'"></div><div><label class="f">'+t('Web port')+'</label><input class="ltr" readonly value="'+esc(s.web_port)+'"></div></div><div class="hint">'+t('Bind and port are where the panel itself listens; changing them needs a panel restart. File:')+' <span class="ltr">/etc/kanki/kanki.env</span></div></div></div>';
 case 'vpn':return '<div class="sgrid"><div><label class="f">DNS</label><input data-k="dns" class="ltr" placeholder="1.1.1.1, 8.8.8.8"><div class="chipset" data-fill="dns">'+
  [['Cloudflare','1.1.1.1, 1.0.0.1'],['Google','8.8.8.8, 8.8.4.4'],['Quad9','9.9.9.9, 149.112.112.112'],['AdGuard','94.140.14.14, 94.140.15.15']].map(function(d){return '<button type="button" data-v="'+d[1]+'">'+d[0]+'</button>'}).join('')+'</div><div class="hint">'+t('DNS servers given to every user config, comma separated.')+'</div></div>'+
  '<div><label class="f">MTU</label><input data-k="mtu" class="ltr" inputmode="numeric" placeholder="1380"><div class="chipset" data-fill="mtu">'+['1280','1380','1420'].map(function(m){return '<button type="button" data-v="'+m+'">'+m+'</button>'}).join('')+'</div><div class="hint">'+t('Lower it (1280) if some sites do not open on mobile data.')+'</div></div>'+
  '<div class="full" style="margin-top:6px">'+stSw('awg_compat','AmneziaWG compatibility mode','Only Jc/Jmin/Jmax/S1/S2/H1-H4, for old AmneziaWG apps.')+stSw('conn_limit_on','Enforce connection limit (Hysteria2)','A user cannot connect from more devices than his limit.')+'</div></div>';
 case 'newu':return '<label class="f" style="margin-top:0">'+t('Default protocols for new users')+'</label><input type="hidden" data-k="default_protocols"><div class="pgs" data-multi="default_protocols">'+
  PROTOS.map(function(x){return '<label style="--pc:'+((PCOL[x[0]]))+'"><input type="checkbox" value="'+x[0]+'" class="hide"><i></i>'+x[1]+'</label>'}).join('')+'</div><div class="hint">'+t('Also used by the sales bot when it makes an account.')+'</div>'+
  '<div class="g3" style="margin-top:6px">'+stIn('def_gb','Volume (GB)','30','0 = unlimited','', 'number')+stIn('def_days','Days','30','','', 'number')+stIn('def_conns','Connections','1','','', 'number')+'</div>';
 case 'ntf':return stSw('tg_alerts','Server alerts','Telegram message to the bot admins when a node, tunnel server or tunnel goes offline, and when it is back.')+
  stSw('warn_on','Warn buyers','The buyer gets a message before his time or data runs out.')+stSw('backup_on','Daily backup to bot admins','An encrypted full backup is sent to the bot admins once a day.')+
  '<div class="hint" style="margin-top:8px">'+t('These messages are sent by the sales bot; set it up first in')+' <a href="#bot">'+t('Sales bot')+'</a>.</div>';
 case 'upd':return '<div class="vcard"><div><small>'+t('Current version')+'</small><b>v'+esc(S.me.version)+'</b></div><div><small>'+t('Latest version')+'</small><b id="st_lv">…</b></div></div><div class="vmsg" id="st_um">'+t('Checking…')+'</div>'+autoUpdBox()+
  '<div class="row" style="margin-top:10px"><button class="b2" type="button" id="st_chk">'+ic('refresh',15)+' '+t('Check for update')+'</button><button class="btn hide" type="button" id="st_go">'+t('Install update')+'</button></div>'+
  '<div class="sgrid" style="margin-top:8px">'+stIn('update_repo','Update source (GitHub repo)','owner/kanki-panel','Releases of this repository are used for updates, for “Update all” and for new tunnel servers.','full')+'</div>'+
  (s.repo_env?'<div class="warnbox">'+t('KANKI_REPO in /etc/kanki/kanki.env is set; it wins over this field.')+'</div>':'')+
  '<div class="hint">'+t('Nodes and tunnel servers are updated together with')+' <a href="#nodes">'+t('Nodes')+' › '+t('Update all')+'</a>.</div>';
 case 'io':return '<div class="ioc"><div><b>'+ic('dl',18)+' '+t('Export')+'</b><p>'+t('A JSON file with every panel and sales setting. It holds payment keys too, keep it private. Users are not in it; use Backup for that.')+'</p><button class="btn" type="button" id="st_exp">'+t('Download settings')+'</button></div>'+
  '<div><b>'+ic('refresh',18)+' '+t('Import')+'</b><p>'+t('Pick a settings file exported from a Kanki panel. Only known settings are taken; users, nodes and keys are not touched.')+'</p><label class="b2" for="st_imf" style="cursor:pointer;display:inline-flex;gap:6px;align-items:center">'+ic('dl',15)+' '+t('Choose file')+'</label><input type="file" id="st_imf" accept=".json,application/json" class="hide"></div></div>';
 }return ''}
function pSettings(){var cur=S.stsec||'look';
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Settings')+'</h2><p>'+t('Everything about how the panel looks and works, in one place')+'</p></div></div><div id="st">'+t('Loading…')+'</div>';
 api('GET','/api/settings').then(function(s){if(!$('#st'))return;S.st=s;if(!STSEC.some(function(x){return x[0]==cur}))cur='look';
  $('#st').innerHTML='<div class="stw"><div class="stn" role="tablist">'+STSEC.map(function(x){return '<button type="button" data-sec="'+x[0]+'" class="'+(x[0]==cur?'on':'')+'"><span class="si">'+ic(x[2],17)+'</span>'+t(x[1])+'<em></em></button>'}).join('')+'</div><div>'+
  STSEC.map(function(x){return '<section class="sts card'+(x[0]==cur?' on':'')+'" data-sec="'+x[0]+'"><div class="sth"><span class="phi">'+ic(x[2],20)+'</span><div><b>'+t(x[1])+'</b><small>'+t(x[3])+'</small></div></div>'+stBody(x[0],s)+
   (x[4].length?'<div class="sbar"><span class="muted" data-msg></span><button class="b2" type="button" data-undo disabled>'+t('Undo')+'</button><button class="btn" type="button" data-save disabled>'+t('Save')+'</button></div>':'')+'</section>'}).join('')+'</div></div>';
  stFill(s);stWire();wireLogo();stUpdate(false);stIran()}).catch(fail)}
function stVal(el){return el.type=='checkbox'?(el.checked?'1':'0'):el.value}
function stFill(s){$$('#st [data-k]').forEach(function(el){var k=el.dataset.k,v=s[k]==null?'':String(s[k]);
  if(k=='refresh'&&!v)v='10';if(k=='lang'&&!v)v='fa';if(k=='theme'&&!v)v='dark';if(k=='color'&&!v)v='gold';
  if(k=='conn_limit_on'||k=='tg_alerts')v=v=='0'?'0':'1';
  if(el.type=='checkbox')el.checked=v=='1';else el.value=v;el._orig=stVal(el)});
 stSync($('#st'))}
// pickers and protocol chips follow their hidden input
function stSync(root){$$('[data-pick]',root).forEach(function(g){var h=$('#st [data-k="'+g.dataset.pick+'"]');$$('button',g).forEach(function(b){b.classList.toggle('on',b.dataset.v==h.value)})});
 $$('[data-multi]',root).forEach(function(g){var h=$('#st [data-k="'+g.dataset.multi+'"]'),on=h.value.split(',');$$('input',g).forEach(function(c){c.checked=on.indexOf(c.value)>=0})})}
function stDirty(sec){var any=false;$$('[data-k]',sec).forEach(function(el){if(stVal(el)!==el._orig)any=true});
 $$('[data-save],[data-undo]',sec).forEach(function(b){b.disabled=!any});var m=$('[data-msg]',sec);if(m)m.textContent=any?t('Unsaved changes'):'';
 var nb=$('.stn button[data-sec="'+sec.dataset.sec+'"]');if(nb)nb.classList.toggle('dirty',any)}
function stWire(){
 $$('.stn button').forEach(function(b){b.onclick=function(){S.stsec=b.dataset.sec;$$('.stn button').forEach(function(x){x.classList.toggle('on',x==b)});$$('.sts').forEach(function(x){x.classList.toggle('on',x.dataset.sec==b.dataset.sec)});if(b.dataset.sec=='upd')stUpdate(false)}});
 $$('.sts').forEach(function(sec){sec.addEventListener('input',function(){stDirty(sec)});sec.addEventListener('change',function(){stDirty(sec)})});
 $$('#st [data-pick] button').forEach(function(b){b.onclick=function(){var g=b.parentNode,h=$('#st [data-k="'+g.dataset.pick+'"]');h.value=b.dataset.v;$$('button',g).forEach(function(x){x.classList.toggle('on',x==b)});stDirty(g.closest('.sts'))}});
 $$('#st [data-multi] input').forEach(function(c){c.onchange=function(){var g=c.closest('[data-multi]'),h=$('#st [data-k="'+g.dataset.multi+'"]');h.value=$$('input',g).filter(function(x){return x.checked}).map(function(x){return x.value}).join(',');stDirty(g.closest('.sts'))}});
 $$('#st [data-fill] button').forEach(function(b){b.onclick=function(){var g=b.parentNode,i=$('#st [data-k="'+g.dataset.fill+'"]');i.value=b.dataset.v;stDirty(g.closest('.sts'))}});
 $$('.sts [data-undo]').forEach(function(b){b.onclick=function(){var sec=b.closest('.sts');
  $$('[data-k]',sec).forEach(function(el){if(el.type=='checkbox')el.checked=el._orig=='1';else el.value=el._orig});stSync(sec);stDirty(sec)}});
 $$('.sts [data-save]').forEach(function(b){b.onclick=function(){stSave(b.closest('.sts'),b)}});
 var ck=$('#st_chk');if(ck)ck.onclick=function(){stUpdate(true)};
 var go=$('#st_go');if(go)go.onclick=function(){go.disabled=true;api('POST','/api/update/apply').then(function(r){toast('v'+r.version+' ✓');setTimeout(function(){location.reload()},5000)}).catch(function(e){go.disabled=false;fail(e)})};
 var ex=$('#st_exp');if(ex)ex.onclick=stExport;
 var sg=$('#sd_go');if(sg)sg.onclick=function(){stSub($('#sd_in').value.trim())};var sr=$('#sd_rm');if(sr)sr.onclick=function(){confirmDo(function(){stSub('')})};
 var im=$('#st_imf');if(im)im.onchange=function(){stImport(im)}}
function stSave(sec,btn){var id=sec.dataset.sec,body={};$$('[data-k]',sec).forEach(function(el){body[el.dataset.k]=stVal(el)});
 if(id=='newu'&&!body.default_protocols)return toast(t('Choose at least one protocol'),1);
 if(id=='upd'&&body.update_repo&&!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(body.update_repo))return toast(t('Write it as owner/repo'),1);
 if(id=='vpn'&&body.mtu&&!(+body.mtu>=1200&&+body.mtu<=1500))return toast(t('MTU must be between 1200 and 1500'),1);
 var all=id=='net'&&$('#st_all')&&$('#st_all').checked;btn.disabled=true;
 api('PUT','/api/settings',body).then(function(){return all?api('POST','/api/settings/apply-endpoint'):null}).then(function(){
  Object.assign(S.st,body);$$('[data-k]',sec).forEach(function(el){el._orig=stVal(el)});stDirty(sec);toast(t('Saved'));
  if(id=='newu'&&S.me){S.me.default_protocols=body.default_protocols;S.me.def_gb=body.def_gb;S.me.def_days=body.def_days;S.me.def_conns=body.def_conns}
  if(id=='look'){S.lang=body.lang;S.theme=body.theme;S.color=body.color;localStorage.setItem('kk_lang',S.lang);localStorage.setItem('kk_theme',S.theme);localStorage.setItem('kk_color',S.color);S.stsec='look';boot()}
  if(id=='upd')stUpdate(true)}).catch(function(e){btn.disabled=false;fail(e)})}
// subscription served from a tunnel server inside Iran
function stIran(){var box=$('#si_in');if(!box)return;api('GET','/api/sub-iran').then(function(r){if(!$('#si_in'))return;
 var st=r.status||{},msg='';
 if(r.server){if(r.ready&&st.active!==false)msg='✓ '+esc(r.link)+'/sub/…';else if(st.error)msg='<span style="color:var(--bad,#e5484d)">'+esc(st.error)+'</span>';else msg=t('Waiting for the server: getting SSL and starting the listener…');
  if(r.tunnel=='down')msg+='<br>'+t('Tunnel to the panel')+': '+t('down');}
 box.innerHTML='<div class="g3"><div><label class="f">'+t('Tunnel server')+'</label><select id="si_srv"><option value="">—</option>'+(r.agents||[]).filter(function(a){return a.loc=='iran'||a.id==r.server}).map(function(a){return '<option value="'+esc(a.id)+'"'+(a.id==r.server?' selected':'')+'>'+esc(a.name)+(a.ip?' ('+esc(a.ip)+')':'')+'</option>'}).join('')+'</select></div>'+
  '<div><label class="f">'+t('Domain')+'</label><input class="ltr" id="si_dom" placeholder="sub.example.com" value="'+esc(r.domain||'')+'"></div>'+
  '<div><label class="f">'+t('Port')+'</label><input class="ltr" id="si_port" inputmode="numeric" value="'+esc(String(r.port||2053))+'"></div></div>'+
  '<div class="hint" id="si_ip"></div><div class="row" style="margin-top:8px"><button class="btn" type="button" id="si_go">'+t('Save')+'</button>'+(r.server&&st.error?'<button class="b2" type="button" id="si_re">↻ '+t('Try SSL again')+'</button>':'')+(r.server?'<button class="b2 bd" type="button" id="si_rm">'+t('Remove')+'</button>':'')+'</div><div class="hint">'+msg+'</div>'+
  (r.server&&st.error?'<details class="secc" style="margin-top:8px" open><summary>'+t('Why SSL is not taken')+'</summary><div class="bd2"><ul style="margin:0;padding-inline-start:18px;line-height:2">'+
   ['The domain\'s A record must point to this Iran server\'s IP (not to a CDN while the certificate is taken: in ArvanCloud / Cloudflare set it to DNS only).',
    'Let\'s Encrypt checks from outside Iran: port 80/TCP of the server must be open from abroad. Open it in the data center\'s firewall panel too; when international traffic is cut, SSL cannot be taken until it is back.',
    'Port 80 busy: the error names the program. A Kanki tunnel that forwards port 80 holds it: take 80 out of that tunnel. Caddy / nginx are set aside by themselves for a few seconds.',
    'After a failure the server waits (10 minutes, then longer) before it tries again; after fixing the cause press «Try SSL again».'].map(function(x){return '<li>'+esc(t(x))+'</li>'}).join('')+'</ul></div></details>':'');
 var ipHint=function(){var a=(r.agents||[]).filter(function(x){return x.id==$('#si_srv').value})[0];$('#si_ip').textContent=a?t('The domain\'s A record must point to this server\'s IP')+(a.ip?': '+a.ip:''):((r.agents||[]).some(function(x){return x.loc=='iran'})?'':t('Add a tunnel server inside Iran first (Servers), or set its location to Inside Iran.'))};
 ipHint();$('#si_srv').onchange=ipHint;
 $('#si_go').onclick=function(){var b=this;b.disabled=true;api('PUT','/api/sub-iran',{server:$('#si_srv').value,domain:$('#si_dom').value.trim(),port:+$('#si_port').value||2053}).then(function(){toast(t('Saved'));stIran()}).catch(function(e){b.disabled=false;fail(e)})};
 var rm=$('#si_rm');if(rm)rm.onclick=function(){confirmDo(function(){api('PUT','/api/sub-iran',{server:'',domain:''}).then(function(){toast(t('Done'));stIran()}).catch(fail)})};
 var re=$('#si_re');if(re)re.onclick=function(){re.disabled=true;api('POST','/api/tunnels/servers/'+encodeURIComponent(r.server)+'/ssl-retry').then(function(){toast(t('Sent: the server tries SSL again within a minute'));setTimeout(stIran,8000)}).catch(function(e){re.disabled=false;fail(e)})}}).catch(function(e){box.textContent=e.message||''})}
function stSub(d){var g=$('#sd_go'),m=$('#sd_msg');g.disabled=true;m.textContent=d?t('Getting the SSL certificate… this can take up to one minute'):'…';
 api('POST','/api/sub-domain',{domain:d}).then(function(r){S.st.sub_domain=r.domain||'';toast(t('Done'));pSettings()}).catch(function(e){g.disabled=false;m.textContent=e.message||'';fail(e)})}
function stUpdate(force){autoUpdWire();var m=$('#st_um');if(!m||(!force&&m._done))return;m._done=1;m.className='vmsg';m.textContent=t('Checking…');
 api('GET','/api/update/check').then(function(r){$('#st_lv').textContent=r.latest?'v'+r.latest:'—';
  m.className='vmsg '+(r.error?'er':(r.available?'up':'ok'));m.textContent=r.error?t(r.error):(r.available?t('A new version is available.'):t('You are on the latest version.'));
  $('#st_go').classList.toggle('hide',!r.available)}).catch(function(e){m.className='vmsg er';m.textContent=t(e.message||'')})}
function stExport(){api('GET','/api/settings').then(function(s){var o={};Object.keys(s).forEach(function(k){if(ST_SKIP.indexOf(k)<0)o[k]=s[k]});
 var d=new Date(),name='kanki-settings-'+d.getFullYear()+p2(d.getMonth()+1)+p2(d.getDate())+'.json';
 dl({blob:new Blob([JSON.stringify({kanki_settings:1,version:S.me.version,settings:o},null,2)],{type:'application/json'}),name:name});toast(t('Done'))}).catch(fail)}
function stImport(inp){var f=inp.files&&inp.files[0];if(!f)return;var rd=new FileReader();
 rd.onload=function(){var j;try{j=JSON.parse(rd.result)}catch(e){inp.value='';return toast(t('This is not a settings file'),1)}
  var o=j&&j.settings&&typeof j.settings=='object'?j.settings:null;if(!o){inp.value='';return toast(t('This is not a settings file'),1)}
  ST_SKIP.forEach(function(k){delete o[k]});var n=Object.keys(o).length;
  if(!confirm(t('Replace the current settings with the file?')+' ('+N(n)+')')){inp.value='';return}
  api('PUT','/api/settings',o).then(function(){toast(t('Saved'));S.stsec='io';boot()}).catch(fail)};
 rd.readAsText(f)}

// ---------------------------------------------------------------- update
// automatic update every night at 03:30 Tehran time (the same as “Update all”)
function autoUpdBox(){return '<label class="chk" style="margin:10px 0"><input type="checkbox" id="au_on"><span><b>🌙 '+t('Automatic update')+'</b><small id="au_txt" style="display:block;margin-top:2px">'+t('Every night at 03:30 Tehran time, if GitHub has a new version: the panel, the nodes, the tunnel servers and the emergency chat are updated by themselves.')+'</small></span></label>'}
function auTxt(r){var el=$('#au_txt');if(!el||!r)return;var f=function(ts,o){return new Date(ts*1000).toLocaleString(S.lang=='fa'?'fa-IR':'en-GB',Object.assign({timeZone:'Asia/Tehran',hour:'2-digit',minute:'2-digit'},o))};
 var x=t('Every night at 03:30 Tehran time, if GitHub has a new version: the panel, the nodes, the tunnel servers and the emergency chat are updated by themselves.');
 if(r.on)x+=' · '+t('Next run')+': '+f(r.next,{weekday:'short'});
 if(r.last&&r.last.ts)x+=' · '+t('Last run')+': '+f(r.last.ts,{month:'short',day:'numeric'})+' — '+r.last.msg;el.textContent=x}
function autoUpdWire(){var c=$('#au_on');if(!c||c._w)return;c._w=1;
 api('GET','/api/auto-update').then(function(r){c.checked=r.on;auTxt(r)}).catch(function(){c.closest('label').style.display='none'});
 c.onchange=function(){var on=c.checked;api('PUT','/api/auto-update',{on:on}).then(function(){toast(on?t('Automatic update is on'):t('Automatic update is off'));return api('GET','/api/auto-update').then(auTxt)}).catch(function(e){c.checked=!on;fail(e)})}}
function updateModal(){modal(mhead(t('Update')+' '+((S.me&&S.me.panel_name)||''))+'<div class="g2"><div class="pc" style="flex-direction:column"><small class="muted">'+t('Current version')+'</small><b class="ltr" id="u_c">v'+esc(S.me.version)+'</b></div><div class="pc" style="flex-direction:column"><small class="muted">'+t('Latest version')+'</small><b class="ltr" id="u_l">…</b></div></div><p id="u_m" class="muted"></p>'+autoUpdBox()+
 '<div class="row" style="justify-content:center"><button class="btn" id="u_chk">'+t('Check for update')+'</button><button class="btn hide" id="u_go">'+t('Install update')+'</button></div><p class="muted">'+t('Updates come from the GitHub releases of your repo.')+'</p>');
 function chk(){$('#u_m').textContent=t('Checking…');api('GET','/api/update/check').then(function(r){$('#u_l').textContent=r.latest?'v'+r.latest:'—';$('#u_m').textContent=r.error?r.error:(r.available?t('A new version is available.'):t('You are on the latest version.'));$('#u_go').classList.toggle('hide',!r.available)}).catch(fail)}
 autoUpdWire();$('#u_chk').onclick=chk;$('#u_go').onclick=function(){this.disabled=true;api('POST','/api/update/apply').then(function(r){toast('v'+r.version+' ✓');setTimeout(function(){location.reload()},5000)}).catch(fail)};chk()}

// ==================================================================== dashboard, users, bot, chat, traffic, ports, tunnels

// ---- built-in logo: a K made of one stem and two links that end in nodes
function kLogo(){return '<svg class="klogo" viewBox="0 0 64 64" aria-hidden="true"><rect x="2.5" y="2.5" width="59" height="59" rx="17" fill="url(#gLbg)" stroke="url(#gGold)" stroke-width="2.2"/>'+
 '<path d="M23 17v30M42 17.5L25.5 32.5 42.5 47" fill="none" stroke="url(#gGold)" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round"/>'+
 '<circle cx="43" cy="16.5" r="4.4" style="fill:var(--al)"/><circle cx="43.5" cy="47.5" r="4.4" style="fill:var(--al)"/></svg>'}

// ---- dashboard: nodes say connected / disconnected
function nState(n){if(n.id=='local')return{c:'g',l:'Connected'};if(!n.online)return{c:'r',l:'Disconnected'};if(n.maint)return{c:'y',l:'Under maintenance'};if(n.drain)return{c:'y',l:'Draining'};return{c:'g',l:'Connected'}}
function drawNodesCard(list){var el=$('#nc');if(!el)return;
 var up=list.filter(function(n){return n.id=='local'||n.online}).length,all=up==list.length;
 el.innerHTML='<div class="nh"><div><h3>'+t('Nodes')+'</h3><small class="'+(all?'okt':'bad2')+'">'+(all?'✓ '+t('All servers connected'):N(list.length-up)+' '+t('server(s) disconnected'))+' · '+N(up)+' / '+N(list.length)+'</small></div>'+
  '<div class="row" style="gap:6px;flex-wrap:nowrap"><button class="b2" data-nd="add">'+ic('plus',15)+' '+t('Add node')+'</button><button class="b2" data-nd="all">'+t('Manage')+'</button></div></div>'+
  '<div class="nds">'+list.map(function(n){var s=nState(n),loc=n.id=='local',sy=loc?null:n.sync_state=='synced'?['g','Synced']:n.sync_state=='mismatch'?['y','Config mismatch']:n.sync_state=='pin mismatch'?['r','Certificate changed']:null;
   var hh=nHealthOf(n),stt=(n.info||{}).stats;if(s.c=='g'&&hh.c!='g')s={c:hh.c,l:hh.l};
   return '<button class="nd" data-nd="all"><span class="dot '+s.c+'"></span><span class="nn"><b>'+esc(n.name)+'</b><small class="ltr">'+esc(loc?'local':String(n.address||'').replace(/^https?:\/\//,''))+'</small></span>'+
    '<span class="nb"><span class="badge '+s.c+' cn">'+(s.c=='g'?ic('check',12)+' ':'')+t(s.l)+'</span>'+(loc?'<span class="badge">'+t('Main server')+'</span>':'')+(sy?'<span class="badge '+sy[0]+'">'+t(sy[1])+'</span>':'')+'</span>'+
    '<span class="nxw"><span class="nx"><small>'+t('Users')+'</small> <b>'+N(n.users)+'</b></span><span class="nx"><small>'+t('Last contact')+'</small> <b>'+(loc?t('this server'):ago(n.last_sync))+'</b></span>'+(stt?'<span class="nx"><small>CPU</small> <b>'+N(Math.round(+stt.cpu||0))+'%</b></span><span class="nx"><small>RAM</small> <b>'+N(Math.round(pc(stt.mem_used,stt.mem_total)))+'%</b></span>':'')+'</span></button>'}).join('')+'</div>'+
  (list.length<2?'<p class="muted" style="margin:10px 0 0">'+t('No extra nodes yet. Add one with a single command.')+'</p>':'');
 el.onclick=function(e){var b=e.target.closest('[data-nd]');if(!b)return;goNodes(b.dataset.nd=='add')}}

// ---- dashboard: live log with All / Errors / Debug
var LG={src:localStorage.getItem('kk_lsrc')||'all',lv:'all',paused:false,lines:[],err:''};
var LSRC=[['all','All services'],['panel','Kanki Panel'],['wireguard','WireGuard'],['amneziawg','AmneziaWG'],['hysteria2','Hysteria2'],['kankimix','KANKI MIX'],['web','Web (Caddy)']];
function lgLevel(x){var m=x.m||'';
 if(x.p<=3||/\b(error|err|fatal|panic|fail(ed|ure)?|critical|denied|refused)\b|"level":"(error|fatal)"/i.test(m))return 'e';
 if(x.p>=7||/\b(debug|dbg|trace)\b|"level":"debug"/i.test(m))return 'd';return 'i'}
function logCard(){return '<div class="card" id="lgc"><div class="nh"><div><h3>'+ic('term',16)+' '+t('Live log')+'</h3><small class="muted">'+t('Panel and VPN services on this server')+'</small></div>'+
 '<div class="row" style="gap:6px;flex-wrap:nowrap"><select id="lg_src" style="width:auto;padding:6px 9px;font-size:12px">'+LSRC.map(function(s){return '<option value="'+s[0]+'"'+(s[0]==LG.src?' selected':'')+'>'+t(s[1])+'</option>'}).join('')+'</select>'+
 '<button class="ib" id="lg_pause" title="'+t(LG.paused?'Resume':'Pause')+'">'+ic(LG.paused?'play':'pause',15)+'</button><button class="ib" id="lg_copy" title="'+t('Copy')+'">'+ic('copy',15)+'</button><button class="ib" id="lg_rf" title="'+t('Refresh')+'">'+ic('refresh',15)+'</button></div></div>'+
 '<div class="lgt" id="lg_tabs"></div><div class="lgb" id="lg_box"><span class="muted">'+t('Loading…')+'</span></div></div>'}
function logWire(){if(!$('#lgc'))return;
 $('#lg_src').onchange=function(){LG.src=this.value;localStorage.setItem('kk_lsrc',LG.src);logLoad()};
 $('#lg_pause').onclick=function(){LG.paused=!LG.paused;this.innerHTML=ic(LG.paused?'play':'pause',15);this.title=t(LG.paused?'Resume':'Pause')};
 $('#lg_rf').onclick=logLoad;
 $('#lg_copy').onclick=function(){copy(logRows().map(function(x){return logTime(x.ts)+' '+x.u+' '+x.m}).join('\n'))};
 $('#lg_tabs').onclick=function(e){var b=e.target.closest('[data-lv]');if(!b)return;LG.lv=b.dataset.lv;logDraw()};
 logLoad();clearInterval(S.timer3);S.timer3=setInterval(function(){if(S.page=='dash'&&!LG.paused&&document.visibilityState=='visible')logLoad()},5000)}
function logLoad(){return api('GET','/api/logs?src='+encodeURIComponent(LG.src)+'&n=300').then(function(r){LG.lines=r.lines||[];LG.err='';logDraw()}).catch(function(e){LG.err=e.message||'error';logDraw()})}
function logRows(){return LG.lines.filter(function(x){return LG.lv=='all'||lgLevel(x)==LG.lv})}
function logTime(ts){var d=new Date(ts*1000);return p2(d.getHours())+':'+p2(d.getMinutes())+':'+p2(d.getSeconds())}
function logDraw(){var tb=$('#lg_tabs'),bx=$('#lg_box');if(!tb||!bx)return;
 var c={all:LG.lines.length,e:0,d:0};LG.lines.forEach(function(x){var l=lgLevel(x);if(l!='i')c[l]++});
 tb.innerHTML=[['all','All'],['e','Errors'],['d','Debug']].map(function(x){return '<button data-lv="'+x[0]+'" class="lv-'+x[0]+(LG.lv==x[0]?' on':'')+'">'+t(x[1])+' <b>'+N(c[x[0]])+'</b></button>'}).join('');
 if(LG.err){bx.innerHTML='<span class="bad2">'+t('Logs are not available')+' ('+esc(LG.err)+')</span>';return}
 var rows=logRows(),stick=bx.scrollHeight-bx.scrollTop-bx.clientHeight<40;
 bx.innerHTML=rows.length?rows.map(function(x){return '<div class="lr '+lgLevel(x)+'"><span class="lt">'+logTime(x.ts)+'</span><span class="lu">'+esc(String(x.u||'').replace(/\.service$/,''))+'</span><span class="lm">'+esc(x.m)+'</span></div>'}).join(''):
  '<span class="muted">'+t(LG.lv=='e'?'No errors':LG.lv=='d'?'No debug lines':'No log lines yet')+'</span>';
 if(stick)bx.scrollTop=bx.scrollHeight}

// ---- user sheet: small, one panel at a time (edit / link / QR), five quick buttons
function editUser(id,tab){var u=findU(id);if(!u)return;var p=usage(u),st=ustate(u),
  tg=(u.protocols||'').split(',').filter(function(x){return x}).map(function(x){return '<span class="ptag" style="--pc:'+(PCOL[x]||'#999')+'">'+esc(pname(x))+'</span>'}).join(''),
  cls=st=='active'?'g':st=='finished'?'y':'r',lbl=t(st=='active'?'Active':st=='finished'?(u.status=='Limited'?'Limited':'Expired'):'Disabled'),cur='';
 modal('<div class="us-h"><span class="dot '+((u.online_connections>0||liveOf(u).length)?'g':'')+'"></span><b class="ltr nm">'+esc(u.username)+'</b><span class="u-st '+cls+'" id="e_badge">'+lbl+'</span><span class="sp"></span>'+
  '<label class="sw"><input type="checkbox" id="e_sw" '+(u.enabled?'checked':'')+' aria-label="'+t('Enable')+'"><span></span></label><button class="ib" onclick="closeModal()" aria-label="close">✕</button></div>'+
  '<div class="us-tags">'+(tg||'<span class="ptag none">—</span>')+'</div>'+
  (liveOf(u).length?'<div class="lvlist"><small class="muted" style="width:100%">'+t('Connected now')+'</small>'+liveOf(u).map(function(c){return '<span style="--pc:'+(PCOL[c.p]||'#888')+'"><b>'+esc(pname(c.p))+'</b>'+esc(c.s)+'</span>'}).join('')+'</div>':'<div class="lvlist"><small class="muted">'+t('Not connected right now')+'</small></div>')+
  '<div class="us-st"><div><small>'+t('Used')+'</small><b class="ltr">'+N(gbtxt(u.traffic_used_gb))+' / '+(u.traffic_limit_gb>0?N(gbtxt(u.traffic_limit_gb)):'∞')+'</b><div class="trk"><div class="fil '+(p>85?'hot':'')+'" style="width:'+(p<0?100:Math.max(2,p))+'%"></div></div></div>'+
  '<div><small>'+t('Expiry')+'</small><b>'+jdate(u.expires_ts)+'</b><small>'+leftTxt(u.expires_ts)+'</small></div>'+
  '<div><small>'+t('Connections')+'</small><b class="ltr">'+N(u.online_connections)+' / '+(u.max_connections?N(u.max_connections):'∞')+'</b><small>'+(u.last_seen_ts?ago(u.last_seen_ts):t('never'))+'</small></div></div>'+
  '<div class="qb5 us-q" id="us_q"><button data-t="edit">'+ic('edit',18)+'<span>'+t('Edit')+'</span></button><button data-t="link">'+ic('link',18)+'<span>'+t('Link')+'</span></button><button data-t="qr">'+ic('qr',18)+'<span>QR</span></button>'+
  '<button data-t="reset">'+ic('reset',18)+'<span>'+t('Reset')+'</span></button><button data-t="del" class="x">'+ic('trash',18)+'<span>'+t('Delete')+'</span></button></div>'+
  '<div id="us_p"></div>','usheet');
 function show(k){var el=$('#us_p');cur=k;$$('#us_q [data-t]').forEach(function(b){b.classList.toggle('on',b.dataset.t==k)});
  if(!k){el.innerHTML='';return}
  if(k=='edit'){el.innerHTML=ufForm(u)+'<button class="btn" style="width:100%;margin-top:10px" id="f_save">'+t('Save changes')+'</button><button class="lnk" id="s_rg">'+ic('refresh',14)+' '+t('New link (the old one stops working)')+'</button>';wireForm(u);
   $('#f_save').onclick=function(){var b=formBody();if(!b)return;var nm=$('#f_name').value.trim();if(nm&&nm!=u.username){if(!nameOk(nm))return toast(t(NAME_ERR),1);b.username=nm}var me=this;me.disabled=true;
    api('PUT','/api/users/'+u.id,b).then(function(){toast(t('Saved'));closeModal();loadUsers()}).catch(function(e){me.disabled=false;fail(e)})};
   $('#s_rg').onclick=function(){confirmDo(function(){api('POST','/api/users/'+u.id+'/regen').then(function(){toast(t('Done'));return loadUsers()}).then(function(){editUser(id,'link')}).catch(fail)})};return}
  if(k=='link'){el.innerHTML='<small class="muted">'+t('Subscription link')+' · '+t('Created')+' '+(u.created_at?jdate(Date.parse(u.created_at)/1000):'—')+'</small><div class="lk">'+esc(u.link)+'</div>'+
    '<div class="g2" style="gap:8px"><button class="btn" id="s_cp">'+ic('copy',16)+' '+t('Copy link')+'</button><a class="b2" style="text-decoration:none;text-align:center" target="_blank" rel="noopener" href="'+esc(u.link)+'">'+ic('ext',16)+' '+t('Open page')+'</a></div>'+
    '<div class="us-cfg"><small class="muted">'+t('Configs')+'</small><div id="sx"></div></div>';
   $('#s_cp').onclick=function(){copy(u.link)};sheetCfg(u.id);return}
  if(k=='qr')qrInto(el,u.link)}
 $('#us_q').onclick=function(e){var b=e.target.closest('[data-t]');if(!b)return;var k=b.dataset.t;
  if(k=='reset')return resetU(u.id);if(k=='del')return delU(u.id);show(cur==k?'':k)};
 $('#e_sw').onchange=function(){var cb=this;cb.disabled=true;api('POST','/api/users/'+u.id+'/toggle').then(function(r){cb.disabled=false;u.enabled=r.enabled;u.status=r.status;var s2=ustate(u),b=$('#e_badge');
   if(b){b.className='u-st '+(s2=='active'?'g':s2=='finished'?'y':'r');b.textContent=t(s2=='active'?'Active':s2=='finished'?(u.status=='Limited'?'Limited':'Expired'):'Disabled')}toast(t('Done'));loadUsers()}).catch(function(e){cb.checked=!cb.checked;cb.disabled=false;fail(e)})};
 if(tab)show(tab)}

// ---- Telegram sales bot page
// ---- the Kanki app's install files: uploaded here, sent by the bot and offered on the subscription page
function botApk(){var el=$('#bt_apk');if(!el)return;
 api('GET','/api/apps').then(function(r){var f=r.files||[];
  var mb=function(n){return (n/1e6).toFixed(1)+' MB'};
  var row=function(x,i){return '<div class="box" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
    '<span class="bav" style="width:40px;height:40px;font-weight:900">K</span>'+
    '<div style="flex:1;min-width:180px"><b>'+esc(x.title)+(i==0&&f.length>1?' <span class="badge g">'+t('Recommended')+'</span>':'')+'</b>'+
     '<div class="ltr" style="font-size:12px;margin-top:2px">'+esc(x.name)+' · '+mb(x.size)+'</div>'+
     '<small class="muted">'+esc(x.hint)+' · '+ago(x.at)+(x.bot?'':' · <span style="color:var(--bad)">'+t('Too big for the bot (over 50 MB): only on the subscription page')+'</span>')+'</small></div>'+
    '<button class="b2" data-apv="'+esc(x.abi)+'" data-v="'+esc(x.version||'')+'">'+ic('edit',15)+' '+t('Version')+'</button>'+
    '<button class="b2 bd" data-apd="'+esc(x.abi)+'">'+ic('trash',15)+'</button></div>'};
  el.innerHTML='<div class="card"><h3>'+ic('dl',16)+' '+t('App files')+'</h3>'+
   '<p class="sub">'+t('Upload the Kanki app (.apk) here, one file per phone type. The bot sends the file itself (📱 Download app) and the subscription page shows a download button for each. A new file of the same type replaces the old one.')+'</p>'+
   ((S.bot||{}).username?'<div class="box"><b>'+t('Link for your channel')+'</b><small class="muted" style="display:block;margin:4px 0 6px">'+t('Put it on a “Download the app” button: the bot opens straight on the download menu.')+'</small>'+
    '<div class="row" style="gap:8px"><input readonly class="ltr" style="flex:1" id="ap_dl" value="https://t.me/'+esc(S.bot.username)+'?start=app"><button class="b2" id="ap_cp">'+ic('copy',15)+'</button></div></div>':'')+
   (f.length?f.map(row).join(''):'<p class="muted">'+t('No file yet: the bot and the subscription page show the app download link of Sales settings.')+'</p>')+
   '<div class="box"><b>'+ic('plus',15)+' '+t('Upload files')+'</b>'+
    '<input type="file" id="ap_f" accept=".apk,application/vnd.android.package-archive" multiple style="margin:8px 0;width:100%">'+
    '<div class="g2f"><div><label class="f">'+t('Phone type')+'</label><select id="ap_abi"><option value="">'+t('From the file name (arm64 / armeabi-v7a …)')+'</option>'+
     '<option value="arm64-v8a">arm64-v8a · '+t('new phones (64-bit)')+'</option><option value="armeabi-v7a">armeabi-v7a · '+t('older phones (32-bit)')+'</option><option value="universal">universal · '+t('every phone')+'</option></select></div>'+
     '<div><label class="f">'+t('Version')+'</label><input id="ap_v" class="ltr" placeholder="'+t('from the file name, e.g. 1.15.1')+'"></div></div>'+
    '<div id="ap_prog" class="muted" style="margin-top:6px"></div>'+
    '<button class="btn" id="ap_go" style="width:100%;margin-top:8px">'+ic('dl',15)+' '+t('Upload')+'</button></div></div>';
  $('#ap_go').onclick=function(){var files=[].slice.call($('#ap_f').files||[]);if(!files.length)return toast(t('Choose the .apk file(s) first'),1);
   var me=this;me.disabled=true;var i=0;
   var next=function(){if(i>=files.length){me.disabled=false;toast(t('Done'));return botApk()}
    var file=files[i++],q='?name='+encodeURIComponent(file.name)+'&abi='+encodeURIComponent($('#ap_abi').value)+'&version='+encodeURIComponent($('#ap_v').value);
    var x=new XMLHttpRequest();x.open('POST','/api/apps'+q);if(S.token)x.setRequestHeader('Authorization','Bearer '+S.token);
    x.setRequestHeader('Content-Type','application/octet-stream');
    x.upload.onprogress=function(e){if(e.lengthComputable)$('#ap_prog').textContent=file.name+' · '+Math.round(100*e.loaded/e.total)+'%'};
    x.onload=function(){var j={};try{j=JSON.parse(x.responseText||'{}')}catch(e){}
     if(x.status>=300){me.disabled=false;$('#ap_prog').textContent='';return toast(file.name+': '+t(j.error||('HTTP '+x.status)),1)}
     $('#ap_prog').textContent='✓ '+file.name;next()};
    x.onerror=function(){me.disabled=false;toast(t('Upload failed'),1)};x.send(file)};
   next()};
  var cp=$('#ap_cp');if(cp)cp.onclick=function(){var i=$('#ap_dl');i.select();try{navigator.clipboard.writeText(i.value)}catch(e){document.execCommand('copy')}toast(t('Copied'))};
  $$('[data-apd]').forEach(function(b){b.onclick=function(){confirmDo(function(){api('DELETE','/api/apps/'+b.dataset.apd).then(function(){toast(t('Done'));botApk()}).catch(fail)})}});
  $$('[data-apv]').forEach(function(b){b.onclick=function(){var v=prompt(t('Version'),b.dataset.v);if(v===null)return;
   api('PUT','/api/apps/'+b.dataset.apv,{version:v}).then(function(){toast(t('Saved'));botApk()}).catch(fail)}});
 }).catch(fail)}
function pBot(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Telegram sales bot')+'</h2><p>'+t('Create and manage the sales bot')+'</p></div><div id="bt_top"></div></div><div id="bt">'+t('Loading…')+'</div>';botLoad()}
function botLoad(){return Promise.all([api('GET','/api/bot'),api('GET','/api/settings'),api('GET','/api/plans').catch(function(){return []})]).then(function(r){S.bot=r[0];S.bset=r[1];S.plans=r[2]||[];botDraw()}).catch(fail)}
function bsChk(k,label){return '<label class="chk"><input type="checkbox" data-bs="'+k+'" '+((S.bset||{})[k]=='1'?'checked':'')+'>'+t(label)+'</label>'}
function bsIn(k,label,ph,typ,ltr){return '<div><label class="f">'+t(label)+'</label><input data-bs="'+k+'"'+(typ?' type="'+typ+'"':'')+(ltr?' class="ltr"':'')+' value="'+esc((S.bset||{})[k]||'')+'" placeholder="'+esc(ph||'')+'"></div>'}
function botDraw(){var b=S.bot||{},el=$('#bt');if(!el)return;var has=!!b.token_set;
 $('#bt_top').innerHTML=has?'':'<button class="btn" id="bt_new">+ '+t('Create bot')+'</button>';
 var st=b.paused?['y','Paused']:b.online?['g','Online']:['r','Offline'];
 var head=has?'<div class="card bcard"><div class="bh"><span class="bav">'+ic('bot',24)+'</span><div class="bn2"><b>'+esc(b.name||t('Sales bot'))+'</b>'+(b.username?'<a class="ltr" target="_blank" rel="noopener" href="https://t.me/'+encodeURIComponent(b.username)+'">@'+esc(b.username)+'</a>':'')+'</div>'+
   '<span class="badge '+st[0]+'"><span class="dot '+st[0]+'"></span> '+t(st[1])+'</span></div>'+
   (!b.paused&&!b.online&&b.error?'<div class="warnbox ltr" style="margin:10px 0">'+esc(b.error)+'</div>':'')+(b.conflict?'<div class="warnbox">'+t('Another program uses this bot token (an old panel still running?). Stop it, or make a new token in @BotFather.')+'</div>':'')+
   '<p class="muted" style="margin:10px 0">'+t('Plans, prices and payments can also be managed inside the bot (Admin panel button).')+'</p><div class="bmeta"><span>'+t('Bot admins')+': <b class="ltr">'+esc(b.admins||'—')+'</b></span><span>'+t('Token')+': <b class="ltr">'+esc(b.token_masked||'')+'</b></span></div>'+
   '<div class="g4b"><button class="b2" id="bt_test">'+ic('send',15)+' '+t('Test connection')+'</button><button class="b2" id="bt_pause">'+ic(b.paused?'play':'pause',15)+' '+t(b.paused?'Resume':'Pause')+'</button><button class="b2" id="bt_edit">'+ic('edit',15)+' '+t('Edit')+'</button><button class="b2 bd" id="bt_del">'+ic('trash',15)+' '+t('Delete bot')+'</button></div></div>'
  :'<div class="card bempty"><span class="bav big">'+ic('bot',30)+'</span><h3>'+t('No sales bot yet')+'</h3><ol class="steps"><li>'+t('In Telegram open @BotFather, send /newbot and copy the token it gives.')+'</li><li>'+t('Get your numeric Telegram ID from @userinfobot.')+'</li><li>'+t('Press Create bot and paste both.')+'</li></ol><button class="btn" id="bt_new2">+ '+t('Create bot')+'</button></div>';
 S.btab=S.btab||'sales';
 var tabs=[['sales','Sales settings'],['plans','Plans'],['apk','App files'],['disc','Discount codes'],['chan','Smart channel'],['appmsg','App message']];
 el.innerHTML=head+'<div class="seg btabs" id="bt_tabs">'+tabs.map(function(x){return '<button data-bt="'+x[0]+'" class="'+(S.btab==x[0]?'on':'')+'">'+t(x[1])+'</button>'}).join('')+'</div>'+
  '<div data-btp="sales"><div class="card"><h3>'+ic('settings',16)+' '+t('Sales settings')+'</h3><p class="sub">'+t('How the bot sells: trials, payments, referrals and messages.')+'</p>'+
   '<div class="chips">'+bsChk('sales_on','Sales enabled')+bsChk('warn_on','Warn buyers before expiry / end of data')+'</div>'+
   '<div class="g2f">'+bsIn('support','Support ID','@support',0,1)+bsIn('app_link','App download link','https://…',0,1)+bsIn('channel','Required channel (empty = none)','@channel',0,1)+'<div></div></div>'+
   '<label class="f">'+t('Welcome message')+'</label><textarea data-bs="welcome" rows="3">'+esc((S.bset||{}).welcome||'')+'</textarea>'+
   '<div class="box"><b>'+ic('gift',15)+' '+t('Free trial')+'</b><div class="chips">'+bsChk('trial_on','Give a free trial')+'</div><div class="g2f">'+bsIn('trial_gb','Trial volume (GB)','1','number')+bsIn('trial_days','Trial days','1','number')+'</div></div>'+
   '<div class="box"><b>'+ic('users',15)+' '+t('Referral reward')+'</b><div class="g2f">'+bsIn('ref_gb','Reward volume (GB)','5','number')+bsIn('ref_days','Reward days','3','number')+'</div></div>'+
   '<div class="box"><b>'+ic('card',15)+' '+t('Card to card')+'</b><div class="chips">'+bsChk('card_on','Accept card to card')+'</div><div class="g2f">'+bsIn('card_number','Card number','6037 ....',0,1)+bsIn('card_holder','Card holder name','')+'</div></div>'+
   '<div class="box"><b>💎 '+t('Crypto payment (TON / USDT)')+'</b><div class="chips">'+bsChk('wallet_on','Accept crypto to my wallet')+'</div>'+
    '<div class="g2f">'+bsIn('ton_address','TON wallet address (Tonkeeper…)','UQ…',0,1)+bsIn('usdt_address','USDT address (TRC20)','T…',0,1)+'</div>'+
    '<div class="g2f">'+bsIn('usd_rate','Toman per dollar (for plans without a dollar price)','100000','number')+'<div></div></div>'+
    '<p class="hint">'+t('The buyer sees the amount in dollars and in TON (at today\'s price), your addresses to copy and a Tonkeeper button, then sends the receipt or TXID for you to approve. Plans without a dollar price get it from the toman price at this rate; with no rate and no dollar price, crypto is not offered for that plan.')+'</p>'+
    '<label class="f">'+t('Extra text for the buyer (optional)')+'</label><textarea data-bs="wallet_text" rows="2">'+esc((S.bset||{}).wallet_text||'')+'</textarea>'+
    '<p class="r" id="bs_wwarn" style="display:none;font-size:12px;margin:6px 0 0">'+t('An address is written but «Accept crypto to my wallet» is off: buyers will not see it.')+'</p></div>'+
   '<details class="box"><summary><b>'+ic('globe',15)+' '+t('Online payments')+'</b></summary>'+
    '<div class="chips">'+bsChk('np_on','NOWPayments (crypto)')+'</div><div class="g2f">'+bsIn('np_key','NOWPayments API key','',0,1)+bsIn('np_coins','Coins','usdttrc20,trx,ton',0,1)+'</div>'+
    '<div class="chips">'+bsChk('zp_on','ZarinPal')+'</div><div class="g2f">'+bsIn('zp_merchant','ZarinPal merchant ID','',0,1)+bsIn('zp_callback','ZarinPal callback URL','https://…',0,1)+'</div>'+
    '</details>'+
   '<button class="btn" style="width:100%;margin-top:10px" id="bs_save">'+t('Save sales settings')+'</button></div></div>'+
  '<div data-btp="plans">'+botSmart()+botPlans()+'</div><div data-btp="apk"><div id="bt_apk"></div></div><div data-btp="disc"><div id="bt_disc"></div></div><div data-btp="chan"><div id="bt_chan"></div></div><div data-btp="appmsg"><div id="bt_am"></div></div>';
 var showTab=function(k){S.btab=k;$$('#bt_tabs [data-bt]').forEach(function(b){b.classList.toggle('on',b.dataset.bt==k)});$$('[data-btp]').forEach(function(d){d.style.display=d.dataset.btp==k?'':'none'});
  if(k=='disc')botDisc();if(k=='chan')botChan();if(k=='appmsg')botAppMsg();if(k=='apk')botApk()};
 $('#bt_tabs').onclick=function(e){var b=e.target.closest('[data-bt]');if(b)showTab(b.dataset.bt)};showTab(S.btab);smartWire();
 // crypto: typing an address switches «accept crypto» on; a written address with the switch off is warned about
 (function(){var on=$('[data-bs="wallet_on"]'),ww=$('#bs_wwarn');if(!on)return;var has=function(){return ['ton_address','usdt_address'].some(function(k){var x=$('[data-bs="'+k+'"]');return x&&x.value.trim()})};
  var chk=function(){if(ww)ww.style.display=has()&&!on.checked?'':'none'};
  ['ton_address','usdt_address'].forEach(function(k){var x=$('[data-bs="'+k+'"]');if(x)x.addEventListener('input',function(){if(this.value.trim())on.checked=true;chk()})});on.addEventListener('change',chk);chk()})();
 var w=function(id,fn){var x=$(id);if(x)x.onclick=fn};
 w('#bt_new',function(){botModal(false)});w('#bt_new2',function(){botModal(false)});w('#bt_edit',function(){botModal(true)});
 w('#bt_test',function(){toast(t('Checking…'));api('POST','/api/bot/test').then(function(r){toast(r.ok?'✓ @'+(r.username||''):(r.error||t('Failed')),!r.ok)}).catch(fail)});
 w('#bt_pause',function(){api('POST','/api/bot/pause').then(function(){toast(t('Done'));botLoad()}).catch(fail)});
 w('#bt_del',function(){confirmDo(function(){api('DELETE','/api/bot').then(waitRestart).catch(fail)})});
 w('#bs_save',function(){var body={};$$('[data-bs]').forEach(function(x){body[x.dataset.bs]=x.type=='checkbox'?(x.checked?'1':'0'):x.value});
  api('PUT','/api/settings',body).then(function(){toast(t('Saved'));botLoad()}).catch(fail)});
 w('#pl_add',function(){var n=$('#pl_n').value.trim();if(!n)return toast(t('Plan name'),1);
  api('POST','/api/plans',{name:n,days:+$('#pl_d').value||30,gb:+$('#pl_g').value||0,toman:+$('#pl_t').value||0,usd:+$('#pl_u').value||0,conns:+$('#pl_c').value||1,category:($('#pl_cat').value||'').trim()}).then(function(){toast(t('Saved'));botLoad()}).catch(fail)});
 var pl=$('#pl_list');if(pl)pl.onclick=function(e){var a=e.target.closest('[data-pact]');if(a){api('PUT','/api/plans/'+a.dataset.pact,{active:a.dataset.a=='1'}).then(botLoad).catch(fail);return}var pu=e.target.closest('[data-pusd]');if(pu){var x1=(S.plans||[]).filter(function(z){return z.id==pu.dataset.pusd})[0]||{},v1=prompt(t('Dollar price (crypto)')+' · 0 = '+t('from the toman price at the dollar rate'),x1.usd||0);if(v1!==null)api('PUT','/api/plans/'+pu.dataset.pusd,{usd:+unN(v1)||0}).then(botLoad).catch(fail);return}var m=e.target.closest('[data-pcat]');if(m){var x0=(S.plans||[]).filter(function(z){return z.id==m.dataset.pcat})[0]||{},v=prompt(t('Category name'),x0.category||'');if(v!==null)api('PUT','/api/plans/'+m.dataset.pcat,{category:v.trim()}).then(botLoad).catch(fail);return}
 var rn=e.target.closest('[data-crn]');if(rn){var v2=prompt(t('Category name'),rn.dataset.crn);if(v2!==null)api('PUT','/api/plans/category',{from:rn.dataset.crn,to:v2.trim()}).then(botLoad).catch(fail);return}
 var b=e.target.closest('[data-pdel]');if(b)confirmDo(function(){api('DELETE','/api/plans/'+b.dataset.pdel).then(function(){toast(t('Done'));botLoad()}).catch(fail)})}}
function plCats(p){var o=[];(p||[]).forEach(function(x){if(x.category&&o.indexOf(x.category)<0)o.push(x.category)});return o.sort()}
function plRow(x){return '<div class="li"><span><b>'+esc(x.name)+'</b><small>'+N(x.days)+' '+t('days')+' · '+(x.gb>0?N(x.gb)+' GB':'∞')+' · '+N(x.conns)+' '+t('connections')+(x.countries>0?' · '+N(x.countries)+' '+t('countries'):'')+(x.active?'':' · '+t('Hidden'))+'</small></span>'+
  '<span class="row" style="gap:8px;flex-wrap:nowrap"><span class="pprice"><b>'+N(Number(x.toman||0).toLocaleString('en-US'))+' '+t('Toman')+'</b>'+(x.usd?'<small class="ltr">$'+x.usd+'</small>':'')+'</span><button class="ib" data-pusd="'+x.id+'" title="'+t('Dollar price (crypto)')+'">$</button><button class="ib" data-pcat="'+x.id+'" title="'+t('Move to category')+'">📂</button><button class="ib'+(x.active?' on':'')+'" data-pact="'+x.id+'" data-a="'+(x.active?0:1)+'" title="'+t(x.active?'Shown in the bot':'Hidden')+'">'+(x.active?'👁':'—')+'</button><button class="ib" data-pdel="'+x.id+'" aria-label="'+t('Delete')+'">'+ic('trash',14)+'</button></span></div>'}
function plGroups(p){if(!p.length)return '<span class="muted">'+t('No plans yet')+'</span>';var g={},ord=[];p.forEach(function(x){var k=x.category||'';if(!g[k]){g[k]=[];ord.push(k)}g[k].push(x)});
 if(ord.length==1&&ord[0]==='')return '<div class="list">'+p.map(plRow).join('')+'</div>';
 ord.sort(function(a,b){return a===''?1:b===''?-1:a.localeCompare(b)});
 return ord.map(function(k){return '<div class="pcat"><div class="pch"><b>📂 '+esc(k||t('Other'))+'</b><small class="muted">'+N(g[k].length)+'</small>'+(k?'<button class="ib" data-crn="'+esc(k)+'" title="'+t('Rename category')+'">'+ic('edit',14)+'</button>':'')+'</div><div class="list">'+g[k].map(plRow).join('')+'</div></div>'}).join('')}
function botPlans(){var p=S.plans||[];return '<div class="card"><h3>'+ic('traffic',16)+' '+t('Plans')+'</h3><p class="sub">'+t('What buyers can choose in the bot')+'</p>'+
 '<div id="pl_list">'+plGroups(p)+'</div>'+
 '<label class="f">'+t('Category')+'</label><input id="pl_cat" list="pl_cats" placeholder="'+t('Category name')+'"><datalist id="pl_cats">'+plCats(p).map(function(c){return '<option value="'+esc(c)+'">'}).join('')+'</datalist><div style="height:6px"></div>'+
 '<div class="g3p"><input id="pl_n" placeholder="'+t('Plan name')+'"><input id="pl_d" type="number" min="1" placeholder="'+t('Days')+'"><input id="pl_g" type="number" min="0" placeholder="GB (0 = ∞)"><input id="pl_t" type="number" min="0" placeholder="'+t('Price (Toman)')+'"><input id="pl_u" type="number" min="0" step="0.1" placeholder="'+t('Price (USD)')+'"><input id="pl_c" type="number" min="1" placeholder="'+t('Connections')+'"></div>'+
 '<button class="btn" style="width:100%;margin-top:8px" id="pl_add">+ '+t('Add plan')+'</button></div>'}

// ---- smart plan builder: price per GB + per extra country + per extra connection (+ monthly base)
function smartRules(){var d={gb:3000,base:20000,country:15000,conn:20000,round:5000,vols:'10,20,30,50,100',days:'30',conns:'1,2',countries:'0',bulk:10};try{var r=JSON.parse((S.bset||{}).price_rules||'{}');for(var k in r)d[k]=r[k]}catch(e){}return d}
function smartPrice(r,gb,days,conns,cn){var m=Math.max(1,days/30),p=(+r.base||0)*m+gb*(+r.gb||0)+Math.max(0,conns-1)*(+r.conn||0)*m+Math.max(0,cn-1)*(+r.country||0)*m;
 if(gb>=50&&+r.bulk>0)p=p*(1-Math.min(40,+r.bulk*(gb>=100?2:1))/100);var rd=+r.round||1000;return Math.max(rd,Math.round(p/rd)*rd)}
function smartList(r){var L=function(x){return String(x).split(/[,،\s]+/).map(Number).filter(function(n){return n>=0&&!isNaN(n)})},out=[];
 L(r.days).forEach(function(d){if(!d)return;L(r.countries).forEach(function(cn){L(r.conns).forEach(function(c){if(!c)return;L(r.vols).forEach(function(g){
  var nm=(g>0?g+' گیگ':'نامحدود')+' · '+(d%30?d+' روزه':(d/30==1?'یک ماهه':(d/30)+' ماهه'))+(c>1?' · '+c+' کاربره':'')+(cn>0?' · '+cn+' کشور':'');
  out.push({category:String(r.category||'').trim(),name:nm,gb:g,days:d,conns:c,countries:cn,toman:smartPrice(r,g,d,c,cn||1)})})})})});return out.slice(0,60)}
function botSmart(){var r=smartRules(),f=function(k,l,typ){return '<div><label class="f">'+t(l)+'</label><input data-sr="'+k+'"'+(typ?' type="number" min="0"':' class="ltr"')+' value="'+esc(r[k])+'"></div>'};
 return '<div class="card"><h3>✨ '+t('Smart plan builder')+'</h3><p class="sub">'+t('Set the price rules once; every plan gets a fair price automatically.')+'</p>'+
  '<div class="g3f">'+f('gb','Price per GB (Toman)',1)+f('base','Base price per month',1)+f('country','Each extra country / month',1)+f('conn','Each extra connection / month',1)+f('round','Round to',1)+f('bulk','Big plan discount %',1)+'</div>'+
  '<div class="g3f">'+f('vols','Volumes (GB, 0 = unlimited)')+f('days','Durations (days)')+f('conns','Connections')+f('countries','Countries (0 = all)')+'<div><label class="f">'+t('Category')+'</label><input data-sr="category" value="'+esc(r.category||'')+'" placeholder="'+t('Category name')+'"></div></div>'+
  '<div id="sp_prev" class="sprev"></div><div class="row" style="gap:8px;margin-top:8px"><button class="btn" id="sp_add" style="flex:1">'+t('Add these plans')+'</button><button class="b2 bd" id="sp_rep">'+t('Replace all plans')+'</button></div></div>'}
function smartRead(){var r={};$$('[data-sr]').forEach(function(x){r[x.dataset.sr]=x.type=='number'?(+x.value||0):x.value});return r}
function smartWire(){var pv=function(){var el=$('#sp_prev');if(!el)return;var l=smartList(smartRead());
  el.innerHTML=l.length?'<small class="muted">'+N(l.length)+' '+t('plans')+'</small>'+l.map(function(x){return '<div class="spi"><span>'+esc(x.name)+'</span><b>'+N(x.toman.toLocaleString('en-US'))+'</b></div>'}).join(''):'<span class="muted">—</span>'};
 $$('[data-sr]').forEach(function(x){x.oninput=pv});pv();
 var send=function(rep){var r=smartRead(),l=smartList(r);if(!l.length)return;var go=function(){api('POST','/api/plans/bulk',{plans:l,replace:rep,rules:r}).then(function(x){toast(t('Saved')+' · '+N(x.added));botLoad()}).catch(fail)};rep?confirmDo(go):go()};
 var a=$('#sp_add'),b=$('#sp_rep');if(a)a.onclick=function(){send(false)};if(b)b.onclick=function(){send(true)}}


// ---- Emergency chat: a small chat server on a server inside Iran, for when the international internet is cut
function pEmergency(){$('#pg').innerHTML='<div class="ph"><div><h2>'+ic('sos',22)+' '+t('Emergency chat')+'</h2><p>'+t('Talk to your customers and send them configs when the international internet is cut')+'</p></div></div><div id="em">'+t('Loading…')+'</div>';emLoad()}
function emLoad(){Promise.all([api('GET','/api/emergency'),api('GET','/api/tunnels')]).then(function(r){var e=r[0],sv=(r[1].servers||[]),el=$('#em');if(!el)return;
 var srvOpt=srvOptGroups(sv,function(x){return '<option value="'+esc(x.id)+'"'+(x.id==e.server?' selected':'')+'>'+esc(x.name+(x.local?' ('+t('panel')+')':''))+(x.online?'':' · '+t('Disconnected'))+'</option>'});
 var cur=sv.filter(function(x){return x.id==e.server})[0],old=cur&&!cur.local&&cur.version&&verLt(cur.version,'3.3.0');
 var st=e.status||null,stHtml=!e.on?'<span class="badge">'+t('Off')+'</span>':!st?'<span class="badge r">'+t('Waiting for the server…')+'</span>':st.active?'<span class="badge g"><span class="dot g"></span> '+t('Running')+'</span>':'<span class="badge r">'+t('Not running')+'</span>';
 el.innerHTML='<div class="card"><h3>'+t('How it works')+'</h3><ol class="sub" style="margin:6px 0;padding-inline-start:18px;line-height:2">'+
   '<li>'+t('Choose a server inside Iran (one of your tunnel servers) and a domain that points to it (ArvanCloud CDN or plain DNS).')+'</li>'+
   '<li>'+t('The panel installs the emergency chat on that server by itself and keeps the list of your customers there while the internet works.')+'</li>'+
   '<li>'+t('When the internet is cut, customers tap the emergency button in the Kanki app and write to you; you answer and send configs from the address below, from inside Iran.')+'</li>'+
   '<li>'+t('Your messages are signed: the app only trusts messages that really come from you, even over plain HTTP.')+'</li></ol></div>'+
  '<div class="card"><div class="row" style="justify-content:space-between"><h3 style="margin:0">'+t('Status')+'</h3>'+stHtml+'</div>'+
   (e.on&&e.url?'<p style="margin:10px 0 4px">'+t('Admin chat address (open it from inside Iran)')+':</p><p class="ltr"><a href="'+esc(e.url)+'/admin" target="_blank" rel="noopener">'+esc(e.url)+'/admin</a></p>':'')+
   (st&&st.active?'<p>'+t('Unread messages')+': <b>'+N(st.unread||0)+'</b></p>':'')+
   (st&&st.error?'<div class="warnbox ltr">'+esc(st.error)+'</div>':'')+
   (old?'<div class="warnbox">'+t('The agent of this server is old: press “Update all” in Tunnel servers first.')+'</div>':'')+
   (e.on&&e.ssl=='http'?'<div class="warnbox">'+t('Without a certificate (HTTP) the chat works, but messages and your password are not encrypted on the way. Get an SSL certificate before the internet is cut and paste it below. Your configs stay safe: they are signed.')+'</div>':'')+
   '<p class="hint">'+t('Customers known to the chat')+': '+N(e.customers||0)+(e.key?' · '+t('Signing key')+' …<span class="ltr">'+esc(e.key)+'</span>':'')+'</p></div>'+
  '<div class="card"><h3>'+t('Settings')+'</h3>'+
   '<label class="chk"><input type="checkbox" id="em_on" '+(e.on?'checked':'')+'><span><b>'+t('Emergency chat is on')+'</b></span></label>'+
   '<label class="f">'+t('Server inside Iran')+'</label><select id="em_sv">'+srvOpt+'</select>'+
   '<div class="g2"><div><label class="f">'+t('Domain')+'</label><input id="em_d" class="ltr" placeholder="chat.kanki.pro" value="'+esc(e.domain||'')+'"></div>'+
   '<div><label class="f">'+t('Port')+'</label><input id="em_p" type="number" class="ltr" list="em_pl" value="'+(e.port||8080)+'">'+
    '<datalist id="em_pl">'+[8080,8880,2052,2082,2086,2095,2053,2083,2087,2096,8443,80,443].map(function(p){return '<option value="'+p+'">'}).join('')+'</datalist></div></div>'+
   '<small class="muted">'+t('With ArvanCloud CDN use a port it forwards (80, 8080, 443, 2053, 8443 …). Open the port on the server.')+' '+
    t('HTTP (CDN SSL or no SSL): 8080, 8880, 2052, 2082, 2086, 2095 · HTTPS (own SSL): 2053, 2083, 2087, 2096, 8443. Keep 80 and 443 free when Kanki DNS runs on this server.')+'</small>'+
   '<label class="f">'+t('Admin password of the chat')+'</label><input id="em_pw" type="password" autocomplete="new-password" placeholder="'+(e.has_password?t('unchanged'):t('at least 10 characters'))+'">'+
   '<label class="f">SSL</label><select id="em_ssl">'+[['auto','Automatic SSL (Let’s Encrypt, recommended)'],['cdn','SSL from the CDN (ArvanCloud)'],['manual','My own certificate'],['http','No SSL (HTTP)']].map(function(o){return '<option value="'+o[0]+'"'+(e.ssl==o[0]?' selected':'')+'>'+t(o[1])+'</option>'}).join('')+'</select>'+
   '<small class="muted" id="em_sslh"></small>'+
   '<div id="em_pem" style="display:none"><label class="f">'+t('Certificate (PEM, full chain)')+'</label><textarea id="em_c" rows="4" class="ltr" placeholder="-----BEGIN CERTIFICATE-----"></textarea>'+
    '<label class="f">'+t('Private key (PKCS#8 PEM)')+'</label><textarea id="em_k" rows="4" class="ltr" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>'+
   '<button class="btn" style="width:100%;margin-top:12px" id="em_go">'+t('Save')+'</button>'+
   '<button class="b2 bd" style="width:100%;margin-top:8px" id="em_rk">'+t('New signing key')+'</button>'+
   '<p class="hint">'+t('A new signing key is only needed if the server was compromised. Apps learn the new key when they refresh their subscription, so do it while the internet still works.')+'</p></div>';
 $('#em_go').onclick=function(){var me=this,b={on:$('#em_on').checked,server:$('#em_sv').value,domain:$('#em_d').value,port:+$('#em_p').value||0,password:$('#em_pw').value,cert:$('#em_c').value,key:$('#em_k').value,ssl:$('#em_ssl').value};
  me.disabled=true;api('PUT','/api/emergency',b).then(function(){toast(t('Saved: the server sets it up in a few seconds'));emLoad()}).catch(function(x){me.disabled=false;fail(x)})};
 var sslH={auto:'The server gets and renews a free certificate by itself. Do it before the internet is cut. Port 80 of the server must be free and the domain must point to it (ArvanCloud: DNS or CDN both work).',cdn:'ArvanCloud shows HTTPS to the users with its own certificate and talks to the server on the port above with HTTP. In ArvanCloud set the origin port to this port.',manual:'Paste a certificate you already have.',http:'Works, but messages and your password travel unencrypted. Configs stay safe: they are signed.'};
 var sslUi=function(){var v=$('#em_ssl').value;$('#em_pem').style.display=v=='manual'?'':'none';$('#em_sslh').textContent=t(sslH[v]||'')};$('#em_ssl').onchange=sslUi;sslUi();
 $('#em_rk').onclick=function(){confirmDo(function(){api('POST','/api/emergency/rekey').then(function(){toast(t('Done'));emLoad()}).catch(fail)})};
 clearTimeout(S.emT);S.emT=setTimeout(function(){if($('#em')&&!$('#modal').classList.contains('on')&&document.activeElement.tagName!='INPUT'&&document.activeElement.tagName!='TEXTAREA')emLoad()},8000)
}).catch(fail)}
function verLt(a,b){var p=function(v){return String(v).replace(/^v/,'').split('.').map(function(x){return +x||0})},x=p(a),y=p(b);for(var i=0;i<3;i++){if((x[i]||0)!=(y[i]||0))return (x[i]||0)<(y[i]||0)}return false}

// ---- message shown by the robot inside the Kanki app (read from the subscription page, so no extra address is needed)
var AM_DUR=[[30,'30 min'],[60,'1 hour'],[180,'3 hours'],[360,'6 hours'],[720,'12 hours'],[1440,'1 day'],[4320,'3 days'],[10080,'7 days'],[0,'Until I remove it']];
function amLeft(until,now){if(!until)return t('Until I remove it');var s=Math.max(0,until-now),h=Math.floor(s/3600),m=Math.ceil(s%3600/60);
 return (h?N(h)+' '+t('hours')+' ':'')+N(m)+' '+t('min')+' '+t('left')}
function botAppMsg(){var el=$('#bt_am');if(!el)return;S.amDur=S.amDur==null?60:S.amDur;
 api('GET','/api/app-msg').then(function(m){
  var cur=m.active?'<div class="amcur on"><div class="row" style="justify-content:space-between;gap:8px"><span class="badge g"><span class="dot g"></span> '+t('Showing in the app')+'</span><small class="muted">'+amLeft(m.until,m.now)+'</small></div>'+
    '<p style="margin:8px 0">'+esc(m.text)+'</p><small class="muted">'+t('For')+': '+(m.users?'<span class="ltr">'+esc(m.users)+'</span>':t('All users'))+'</small>'+
    '<button class="b2 bd" style="width:100%;margin-top:8px" id="am_del">'+ic('trash',15)+' '+t('Remove now')+'</button></div>'
   :'<div class="amcur"><span class="muted">'+t('No message is showing in the app right now.')+'</span></div>';
  el.innerHTML='<div class="card"><h3>'+ic('bot',16)+' '+t('App message')+'</h3><p class="sub">'+t('Write a message; the robot on the first screen of the Kanki app shows it to users, and it disappears by itself when the time is over.')+'</p>'+cur+
   '<label class="f">'+t('Message')+'</label><textarea id="am_t" rows="3" maxlength="500" placeholder="'+t('e.g. The Germany server is under maintenance for one hour.')+'"></textarea><small class="muted" id="am_c"></small>'+
   '<label class="f">'+t('Show for')+'</label><div class="amdur" id="am_d">'+AM_DUR.map(function(x){return '<button data-m="'+x[0]+'" class="'+(S.amDur==x[0]?'on':'')+'">'+t(x[1])+'</button>'}).join('')+'</div>'+
   '<label class="f">'+t('Only for these users (empty = everyone)')+'</label><input id="am_u" class="ltr" placeholder="user1, user2">'+
   '<button class="btn" style="width:100%;margin-top:10px" id="am_go">'+ic('send',15)+' '+t(m.active?'Replace the message':'Send to the app')+'</button>'+
   '<p class="hint" style="margin-top:8px">'+t('The app picks the message up when it is opened, then every 30 seconds while connected (every 5 minutes when not). A user who closes the message will not see it again; a new message is shown again.')+'</p></div>';
  var ta=$('#am_t'),cnt=function(){$('#am_c').textContent=N(ta.value.length)+' / '+N(500)};ta.oninput=cnt;cnt();
  $('#am_d').onclick=function(e){var b=e.target.closest('[data-m]');if(!b)return;S.amDur=+b.dataset.m;$$('#am_d [data-m]').forEach(function(x){x.classList.toggle('on',x==b)})};
  $('#am_go').onclick=function(){var tx=ta.value.trim();if(!tx)return toast(t('Write the message first'),1);
   api('PUT','/api/app-msg',{text:tx,minutes:S.amDur,users:$('#am_u').value}).then(function(){toast(t('Sent'));botAppMsg()}).catch(fail)};
  var d=$('#am_del');if(d)d.onclick=function(){confirmDo(function(){api('DELETE','/api/app-msg').then(function(){toast(t('Done'));botAppMsg()}).catch(fail)})}
 }).catch(fail)}

// ---- discount codes
function botDisc(){var el=$('#bt_disc');if(!el)return;api('GET','/api/discounts').then(function(l){
 el.innerHTML='<div class="card"><h3>🎟 '+t('Discount codes')+'</h3><p class="sub">'+t('Buyers type the code in the bot. Used-up and expired codes are removed by themselves.')+'</p><div class="list">'+
  (l.length?l.map(function(d){return '<div class="li"><span><b class="ltr">'+esc(d.code)+'</b><small>'+N(d.percent)+'% · '+N(d.uses)+' '+t('uses left')+(d.expires?' · '+t('until')+' '+fmtDate(d.expires,1):'')+'</small></span><span class="row" style="gap:6px;flex-wrap:nowrap"><button class="ib" data-dcp="'+esc(d.code)+'">'+ic('link',14)+'</button><button class="ib" data-ddel="'+esc(d.code)+'">'+ic('trash',14)+'</button></span></div>'}).join(''):'<span class="muted">'+t('No codes yet')+'</span>')+'</div>'+
  '<div class="g4f" style="margin-top:10px"><input id="dc_c" class="ltr" placeholder="'+t('Code')+' (NOWRUZ)"><input id="dc_p" type="number" min="1" max="90" placeholder="%"><input id="dc_u" type="number" min="1" placeholder="'+t('Uses')+'"><input id="dc_h" type="number" min="0" placeholder="'+t('Hours (0 = no end)')+'"></div>'+
  '<button class="btn" style="width:100%;margin-top:8px" id="dc_add">+ '+t('Add code')+'</button></div>';
 $('#dc_add').onclick=function(){var c=$('#dc_c').value.trim();if(!c)return toast(t('Code'),1);api('POST','/api/discounts',{code:c,percent:+$('#dc_p').value||10,uses:+$('#dc_u').value||100,hours:+$('#dc_h').value||0}).then(function(){toast(t('Saved'));botDisc()}).catch(fail)};
 el.querySelector('.list').onclick=function(e){var d=e.target.closest('[data-ddel]'),c=e.target.closest('[data-dcp]');if(c)copy(c.dataset.dcp);if(d)confirmDo(function(){api('DELETE','/api/discounts/'+encodeURIComponent(d.dataset.ddel)).then(botDisc).catch(fail)})}}).catch(fail)}

// ---- smart channel
function botChan(){var el=$('#bt_chan');if(!el)return;api('GET','/api/channel').then(function(c){var ks=(c.kinds||'').split(',');
 el.innerHTML='<div class="card"><div class="nh"><div><h3>📢 '+t('Smart channel')+'</h3><p class="sub">'+t('The bot writes and publishes posts in your channel by itself: prices, offers, tips, guides, trials and occasion greetings. Make the bot an admin of the channel.')+'</p></div>'+
  '<label class="sw"><input type="checkbox" id="ch_on" '+(c.on?'checked':'')+'><span></span></label></div>'+
  '<div class="g2f"><div><label class="f">'+t('Channel')+'</label><input id="ch_id" class="ltr" value="'+esc(c.id)+'" placeholder="@mychannel"></div><div><label class="f">'+t('Post every (hours)')+'</label><input id="ch_h" type="number" min="1" max="72" value="'+(+c.hours||8)+'"></div>'+
  '<div><label class="f">'+t('Signature (empty = bot link)')+'</label><input id="ch_sg" value="'+esc(c.sign)+'" placeholder="@'+esc(c.bot||'bot')+'"></div><div><label class="f">'+t('Discount code prefix')+'</label><input id="ch_cd" class="ltr" value="'+esc(c.code)+'" placeholder="KANKI"></div></div>'+
  '<label class="f">'+t('Post types')+'</label><div class="chips">'+(c.all_kinds||[]).map(function(k){return '<label class="chk"><input type="checkbox" class="ch_k" value="'+k.id+'" '+(ks.indexOf(k.id)>=0?'checked':'')+'>'+t(k.name)+'</label>'}).join('')+'</div>'+
  '<div class="chips">'+'<label class="chk"><input type="checkbox" id="ch_ao" '+(c.auto_offer?'checked':'')+'>'+t('Automatic discount on occasions (Nowruz, Yalda…)')+'</label></div>'+
  '<p class="muted" style="font-size:12px">'+t('No posts between 1 and 8 in the morning.')+' · '+t('Posts sent')+': '+N(c.count)+(c.last?' · '+t('Last')+': '+ago(c.last):'')+(c.occasion?' · 🎉 '+esc(c.occasion):'')+(String(c.status||'').indexOf('error')==0?'<br><span class="r">'+esc(c.status)+'</span>':'')+'</p>'+
  '<button class="btn" style="width:100%" id="ch_save">'+t('Save')+'</button></div>'+aiCard(c)+
  '<div class="card"><div class="nh"><h3>👁 '+t('Post preview')+'</h3><select id="ch_kind" style="width:auto"><option value="auto">'+t('Smart choice')+'</option>'+(c.all_kinds||[]).map(function(k){return '<option value="'+k.id+'">'+t(k.name)+'</option>'}).join('')+'</select></div>'+
  '<div class="chpv" id="ch_pv"><span class="muted">…</span></div><div class="row" style="gap:8px;margin-top:8px"><button class="b2" id="ch_new" style="flex:1">🔄 '+t('Another one')+'</button><button class="btn" id="ch_pub" style="flex:1">📤 '+t('Publish now')+'</button></div></div>'+
  '<div class="card"><h3>🔥 '+t('Discount campaign')+'</h3><p class="sub">'+t('Makes a new code that ends by itself and announces it in the channel.')+'</p><div class="g3f"><div><label class="f">%</label><input id="cc_p" type="number" min="1" max="90" value="20"></div><div><label class="f">'+t('Hours')+'</label><input id="cc_h" type="number" min="1" value="48"></div><div><label class="f">'+t('Uses')+'</label><input id="cc_u" type="number" min="1" value="200"></div></div>'+
  '<button class="btn" style="width:100%;margin-top:8px" id="cc_go">🔥 '+t('Start the campaign')+'</button></div>';
 var draft={};var pv=function(){api('POST','/api/channel/preview',{kind:$('#ch_kind').value}).then(function(r){draft=r;$('#ch_pv').innerHTML=r.text.replace(/\n/g,'<br>')}).catch(fail)};pv();
 $('#ch_kind').onchange=pv;$('#ch_new').onclick=pv;
 $('#ch_pub').onclick=function(){var me=this;me.disabled=true;api('POST','/api/channel/post',{text:draft.text,kind:draft.kind}).then(function(){me.disabled=false;toast(t('Published'));botChan()}).catch(function(e){me.disabled=false;fail(e)})};
 $('#ch_save').onclick=function(){api('PUT','/api/channel',{on:$('#ch_on').checked,id:$('#ch_id').value,hours:+unN($('#ch_h').value)||8,sign:$('#ch_sg').value,code:$('#ch_cd').value,auto_offer:$('#ch_ao').checked,
  kinds:$$('.ch_k').filter(function(x){return x.checked}).map(function(x){return x.value}).join(',')}).then(function(){toast(t('Saved'));botChan()}).catch(fail)};
 $('#ch_on').onchange=function(){api('PUT','/api/channel',{on:this.checked}).then(function(){toast(t('Saved'))}).catch(fail)};
 $('#cc_go').onclick=function(){var me=this;me.disabled=true;api('POST','/api/channel/campaign',{percent:+$('#cc_p').value||20,hours:+$('#cc_h').value||48,uses:+$('#cc_u').value||200}).then(function(r){me.disabled=false;
  toast(r.posted?t('Published')+' · '+r.code:r.code+' · '+(r.error||''),!r.posted);botChan()}).catch(function(e){me.disabled=false;fail(e)})};
 aiWire()}).catch(fail)}
// the smart channel's AI writer
function aiCard(c){var st=String(c.ai_status||''),ok=st.indexOf('ok:')==0;
 return '<div class="card" id="v37ai"><div class="nh"><div><h3>🤖 '+t('AI writer')+'</h3><p class="sub">'+t('Posts are written by the AI from your real plans, prices and codes, in the tone you describe. When it does not answer (it is tried again, and another model is tried), the built-in writer posts instead.')+'</p></div>'+
  '<label class="sw"><input type="checkbox" id="ai_on" '+(c.ai_on?'checked':'')+'><span></span></label></div>'+
  '<div class="g2f"><div><label class="f">'+t('API key')+(c.ai_has_key?' · <span class="okt">'+t('saved')+' <span class="ltr">'+esc(c.ai_key_hint||'')+'</span></span>':'')+'</label><input id="ai_key" class="ltr aikey" type="text" name="kk-grok-api" autocomplete="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore placeholder="'+esc(c.ai_has_key?t('Paste a new key to replace it'):'AQ.… / gsk_… / xai-…')+'"></div>'+
  '<div><label class="f">'+t('Model')+'</label><input id="ai_model" class="ltr" value="'+esc(c.ai_model||'')+'" placeholder="'+esc(c.ai_provider_used=='gemini'?'gemini-flash-latest':c.ai_provider_used=='xai'?'grok-4':'openai/gpt-oss-120b')+'"></div></div>'+
  '<label class="f">'+t('AI service')+'</label><select id="ai_pv">'+[['','Automatic (from the key)'],['gemini','Gemini (Google AI Studio, key AQ.… / AIza…)'],['groq','Groq (groq.com, key gsk_…)'],['xai','Grok (x.ai, key xai-…)']].map(function(o){return '<option value="'+o[0]+'"'+((c.ai_provider||'')==o[0]?' selected':'')+'>'+t(o[1])+'</option>'}).join('')+'</select>'+
  '<small class="muted">'+t('Now')+': <b class="ltr">'+esc(c.ai_provider_used=='xai'?'Grok · api.x.ai/v1':c.ai_provider_used=='gemini'?'Gemini · generativelanguage.googleapis.com':'Groq · api.groq.com/openai/v1')+'</b> · '+t('Empty model = the best one of that service; a refused model is replaced by another one of your account.')+'</small>'+
  '<label class="f">'+t('About us and how to write')+'</label><textarea id="ai_brief" rows="4" placeholder="'+esc(t('Who you are, what to stress, the tone, words to avoid…'))+'">'+esc(c.ai_brief||'')+'</textarea>'+
  '<label class="f">'+t('Posting times (Iran time)')+'</label><div class="inl"><input id="ch_times" class="ltr" value="'+esc(c.times||'')+'" placeholder="10:00, 16:00, 21:30"><button type="button" class="b2" id="ai_3x" style="flex:none">'+t('Use 3 times a day')+'</button></div><small class="muted">'+t('Empty = every N hours as above. Three times a day: 10:00, 16:00, 21:30')+'</small>'+
  (st?'<p class="'+(ok?'okt':'r')+'" style="font-size:12px;margin:8px 0 0">'+t('Last answer')+': <span class="ltr">'+esc(ok?st.slice(3):st)+'</span></p>':'')+
  '<div class="g3" style="margin-top:12px"><button class="btn" id="ai_save">'+t('Save')+'</button><button class="b2" id="ai_test">⚡ '+t('Test the key')+'</button>'+(c.ai_has_key?'<button class="b2 bd" id="ai_rm">'+t('Remove the key')+'</button>':'<span></span>')+'</div>'+
  '<div id="ai_out" class="chpv" style="display:none;margin-top:10px"></div></div>'}
function aiWire(){var g=function(id){return $('#'+id)};
 g('ai_3x').onclick=function(){g('ch_times').value='10:00, 16:00, 21:30'};
 var keyOk=function(){var k=g('ai_key').value.trim();if(k&&!/^(gsk_|xai-|AQ\.|AIza)/.test(k)&&!confirm(t('A Gemini key starts with AQ. or AIza (aistudio.google.com/apikey), a Groq key with gsk_, a Grok key with xai-. Save this one anyway?')))return false;return true};
 g('ai_save').onclick=function(){if(!keyOk())return;var b=this;b.disabled=true;api('PUT','/api/channel',{ai_on:g('ai_on').checked,ai_key:g('ai_key').value.trim(),ai_provider:g('ai_pv').value,ai_model:g('ai_model').value.trim(),ai_brief:g('ai_brief').value,times:g('ch_times').value.trim()})
  .then(function(){toast(t('Saved'));botChan()}).catch(function(e){b.disabled=false;fail(e)})};
 g('ai_test').onclick=function(){if(!keyOk())return;var b=this,o=g('ai_out');b.disabled=true;o.style.display='';o.innerHTML='<span class="muted">…</span>';
  var save=api('PUT','/api/channel',{ai_key:g('ai_key').value.trim(),ai_provider:g('ai_pv').value,ai_model:g('ai_model').value.trim()});
  save.then(function(){return api('POST','/api/channel/ai-test')}).then(function(r){o.innerHTML='<b class="okt">✓ '+t('The AI works')+' · <span class="ltr">'+esc(r.model)+'</span></b><br><br>'+String(r.text||'').replace(/\n/g,'<br>');b.disabled=false})
   .catch(function(e){o.innerHTML='<span class="r">'+esc(e.message||'')+'</span>';b.disabled=false})};
 var rm=g('ai_rm');if(rm)rm.onclick=function(){if(!confirm(t('Remove the key')+'?'))return;api('PUT','/api/channel',{ai_key:'-',ai_on:false}).then(function(){toast(t('Done'));botChan()}).catch(fail)}}
function botModal(edit){var b=S.bot||{};modal(mhead(t(edit?'Edit bot':'Create bot'))+
 '<label class="f">'+t('Bot token (from @BotFather)')+'</label><input id="bm_t" class="ltr" autocomplete="off" placeholder="'+(edit?t('Empty = keep the current token'):'123456789:AA…')+'">'+
 '<label class="f">'+t('Admin numeric ID(s), comma separated')+'</label><input id="bm_a" class="ltr" value="'+esc(b.admins||'')+'" placeholder="123456789">'+
 '<p class="muted">'+t('The panel restarts for a few seconds after saving.')+'</p><button class="btn" style="width:100%" id="bm_go">'+t('Save')+'</button>');
 $('#bm_go').onclick=function(){var tok=$('#bm_t').value.trim(),ad=$('#bm_a').value.trim();if(!edit&&!tok)return toast(t('Token is required'),1);var me=this,body={admins:ad};if(tok)body.token=tok;me.disabled=true;
  api('PUT','/api/bot',body).then(function(){closeModal();waitRestart()}).catch(function(e){me.disabled=false;fail(e)})}}
function waitRestart(){toast(t('Panel is restarting…'));var n=0;setTimeout(function(){var iv=setInterval(function(){n++;api('GET','/api/me').then(function(){clearInterval(iv);toast(t('Done'));if(S.page=='bot')botLoad()}).catch(function(){if(n>24){clearInterval(iv);location.reload()}})},2500)},3000)}

// ---- traffic & stats page
var TR={h:{rx:[],tx:[]},last:null,max:40,q:'',all:false};
function pTraffic(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Traffic & stats')+'</h2><p>'+t('Users usage and live network traffic')+'</p></div><button class="ib" id="tr_rf" title="'+t('Refresh')+'">'+ic('refresh',17)+'</button></div><div id="tr">'+t('Loading…')+'</div>';
 TR={h:{rx:[],tx:[]},last:null,max:40,q:'',all:false};if(DB.h&&DB.h.rx&&DB.h.rx.length>1){TR.h.rx=DB.h.rx.slice(-TR.max);TR.h.tx=(DB.h.tx||[]).slice(-TR.max)}$('#tr_rf').onclick=trLoad;trLoad();trTick();setTimeout(trTick,900);
 clearInterval(S.timer3);S.timer3=setInterval(function(){if(S.page=='traffic'&&document.visibilityState=='visible')trTick()},2000)}
function trLoad(){Promise.all([api('GET','/api/users'),api('GET','/api/nodes').catch(function(){return S.nodes||[]})]).then(function(r){S.users=r[0];S.nodes=r[1];trDraw()}).catch(fail)}
function trTick(){api('GET','/api/live').then(function(l){var p=TR.last;TR.last=l;if(!p)return;var sec=Math.max(.5,(l.ts-p.ts)/1000),v={rx:Math.max(0,(l.net_rx-p.net_rx)/sec),tx:Math.max(0,(l.net_tx-p.net_tx)/sec)};
  ['rx','tx'].forEach(function(k){TR.h[k].push(v[k]);if(TR.h[k].length>TR.max)TR.h[k].shift()});
  var a=$('#tr_rx'),b=$('#tr_tx'),c=$('#tr_ch');if(a)a.textContent=N(rate(v.rx));if(b)b.textContent=N(rate(v.tx));if(c)c.innerHTML=areaChart([{v:TR.h.rx,c:'a'},{v:TR.h.tx,c:'b'}],{h:132,cap:TR.max})}).catch(function(){})}
function trDraw(){var el=$('#tr');if(!el)return;var us=S.users||[],tot=0,lim=0,lu=0,pc={};
 us.forEach(function(u){var used=+u.traffic_used_gb||0;tot+=used;if(u.traffic_limit_gb>0){lim+=+u.traffic_limit_gb;lu+=Math.min(used,+u.traffic_limit_gb)}(u.protocols||'').split(',').forEach(function(p){pc[p]=(pc[p]||0)+1})});
 var pl=lim>0?Math.round(lu/lim*1000)/10:0,bar=function(lbl,v,col){var w=us.length?Math.round(v/us.length*100):0;return '<div class="brow">'+lbl+'<span class="trk"><span class="fil" style="width:'+w+'%'+(col?';background:'+col:'')+'"></span></span><b>'+N(v)+'</b></div>'};
 el.innerHTML='<div class="tr3"><div class="card tk"><small>'+t('Total recorded usage')+'</small><b class="ltr">'+N(gbtxt(tot))+'</b><span class="muted">'+N(us.length)+' '+t('users')+'</span></div>'+
  '<div class="card tk"><small>'+t('Quota of limited users')+'</small><b class="ltr">'+N(gbtxt(lim))+'</b><span class="muted">'+N(pl)+'% '+t('of it used')+'</span><span class="trk"><span class="fil" style="width:'+Math.min(100,pl)+'%"></span></span></div>'+
  '<div class="card tk"><small>'+t('Live speed')+' · '+t('this server')+'</small><div class="trs"><span>↓ <b id="tr_rx" class="ltr">—</b></span><span>↑ <b id="tr_tx" class="ltr">—</b></span></div></div></div>'+
  '<div class="card"><h3>'+t('Live network traffic')+'</h3><small class="muted">'+t('Download and upload, every 2 seconds')+'</small><div class="ch tall" id="tr_ch"></div></div>'+
  '<div class="g2 trg"><div class="card" style="margin:0"><h3>'+t('By protocol')+'</h3>'+PROTOS.map(function(p){return bar('<span class="ptag" style="--pc:'+PCOL[p[0]]+'">'+p[1]+'</span>',pc[p[0]]||0,PCOL[p[0]])}).join('')+'</div>'+
  '<div class="card" style="margin:0"><h3>'+t('By node')+'</h3>'+((S.nodes||[]).map(function(n){return bar('<span class="nmn">'+esc(n.name)+'</span>',n.users||0)}).join('')||'<span class="muted">—</span>')+'</div></div>'+
  '<div class="card" style="margin-top:12px"><div class="nh"><div><h3>'+t('Users usage')+'</h3><small class="muted">'+t('Used volume, limit and percent')+'</small></div><input id="tr_q" type="search" autocomplete="off" placeholder="'+t('Search')+'" style="max-width:190px"></div><div id="tr_ul" class="trul"></div></div>';
 $('#tr_q').value=TR.q;$('#tr_q').oninput=function(){TR.q=this.value.toLowerCase();trUsers()};trUsers();if(TR.h.rx.length>1)$('#tr_ch').innerHTML=areaChart([{v:TR.h.rx,c:'a'},{v:TR.h.tx,c:'b'}],{h:132,cap:TR.max})}
function trUsers(){var el=$('#tr_ul');if(!el)return;var l=(S.users||[]).filter(function(u){return !TR.q||u.username.toLowerCase().indexOf(TR.q)>=0}).sort(function(a,b){return b.traffic_used_gb-a.traffic_used_gb}),max=TR.all?l.length:30;
 el.innerHTML=l.slice(0,max).map(function(u){var p=usage(u),st=ustate(u);return '<button class="urow" data-u="'+u.id+'"><span class="dot '+(st=='disabled'?'r':st=='finished'?'y':(u.online_connections>0||liveOf(u).length)?'g':'')+'"></span><b class="ltr nm">'+esc(u.username)+'</b>'+
  '<span class="uu ltr">'+N(gbtxt(u.traffic_used_gb))+' / '+(u.traffic_limit_gb>0?N(gbtxt(u.traffic_limit_gb)):'∞')+'</span><span class="ub"><span class="trk"><span class="fil '+(p>85?'hot':'')+'" style="width:'+(p<0?0:Math.max(1,p))+'%"></span></span></span><span class="up ltr">'+(p<0?'∞':N(p)+'%')+'</span></button>'}).join('')+
  (l.length>max?'<button class="b2" style="width:100%;margin-top:8px" id="tr_more">'+t('Show all')+' ('+N(l.length)+')</button>':'')+(l.length?'':'<span class="muted">'+t('No match')+'</span>');
 el.onclick=function(e){var b=e.target.closest('[data-u]');if(b){editUser(+b.dataset.u);return}if(e.target.closest('#tr_more')){TR.all=true;trUsers()}}}

// ---- port management page
var PSEL='local';
function pPorts(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Port management')+'</h2><p>'+t('Ports used on the main server and on every node')+'</p></div><button class="ib" id="pt_rf" title="'+t('Refresh')+'">'+ic('refresh',17)+'</button></div><div id="pt">'+t('Loading…')+'</div>';
 $('#pt_rf').onclick=ptLoad;ptLoad()}
function ptLoad(){Promise.all([api('GET','/api/nodes'),api('GET','/api/settings').catch(function(){return {}}),api('GET','/api/system').catch(function(){return null})]).then(function(r){S.nodes=r[0];S.pset=r[1]||{};S.psys=r[2];ptDraw()}).catch(fail)}
function svcOf(list,k){for(var i=0;i<(list||[]).length;i++)if(list[i].key==k)return list[i];return null}
function ptRows(n){var loc=n.id=='local',inf=n.info||{},sv=loc&&S.psys?S.psys.services:(inf.services||[]),rows=[],ps=S.pset||{};
 var add=function(k,name,proto,port,svk){if(!port)return;var s=svcOf(sv,svk);rows.push({k:k,name:name,proto:proto,port:String(port),st:s?(s.active?'run':'stop'):'none'})};
 add('wg','WireGuard','UDP',inf.wg_port,'wireguard');add('awg','AmneziaWG','UDP',inf.awg_port,'amneziawg');add('hy2','Hysteria2','UDP',inf.hy2_port,'hysteria2');add('kmix','KANKI MIX','UDP',inf.kmix_port,'kankimix');
 if(loc){add('web',t('Panel (HTTPS)'),'TCP',ps.https_port||'443','web');add('panel',t('Panel (internal)'),'TCP',ps.web_port,'panel')}
 else{var m=String(n.address||'').match(/:(\d+)(\/|$)/);add('api',t('Node API (HTTPS)'),'TCP',m?m[1]:'443','web')}
 return rows}
function fwCmd(rows){var p=rows.filter(function(r){return r.k!='panel'}).map(function(r){return 'ufw allow '+r.port+'/'+r.proto.toLowerCase()}).filter(function(x,i,a){return a.indexOf(x)==i});return p.length?p.join(' && '):'—'}
function ptDraw(){var el=$('#pt');if(!el)return;var ns=S.nodes||[];if(!ns.some(function(n){return n.id==PSEL}))PSEL=(ns[0]||{}).id||'local';
 var n=ns.filter(function(x){return x.id==PSEL})[0]||{id:'local',info:{}},rows=ptRows(n),loc=n.id=='local',ps=S.pset||{},host=loc?(ps.endpoint||ps.domain||''):(n.effective_endpoint||''),cnt={};
 rows.forEach(function(r){cnt[r.proto+r.port]=(cnt[r.proto+r.port]||0)+1});
 el.innerHTML='<div class="psel">'+ns.map(function(x){var on=x.id=='local'||x.online;return '<button class="'+(x.id==PSEL?'on':'')+'" data-ps="'+esc(x.id)+'"><span class="dot '+(on?'g':'r')+'"></span>'+esc(x.name)+(x.id=='local'?' <small>'+t('Main')+'</small>':'')+'</button>'}).join('')+'</div>'+
  '<div class="pgrid">'+(rows.length?rows.map(function(r){var bad=cnt[r.proto+r.port]>1,sl=r.st=='run'?['g','Running']:r.st=='stop'?['r','Stopped']:['','Unknown'];
   return '<div class="card pcard'+(bad?' pbad':'')+'"><div class="ph2"><b>'+esc(r.name)+'</b><span class="pp '+r.proto.toLowerCase()+'">'+r.proto+'</span><span class="sp"></span><span class="badge '+sl[0]+'">'+t(sl[1])+'</span></div>'+
    '<button class="pnum ltr" data-cp="'+esc(r.port)+'" title="'+t('Copy')+'">'+esc(r.port)+'</button>'+
    '<small class="muted ltr pub">'+(r.k=='panel'?t('local only (127.0.0.1)'):esc((host||'?')+':'+r.port))+'</small>'+
    (bad?'<div class="warnbox">'+t('Port conflict: another service on this server uses the same port')+'</div>':'')+'</div>'}).join(''):'<p class="muted">'+t('No port information yet. Press Check now.')+'</p>')+'</div>'+
  '<div class="row" style="gap:8px;margin:2px 0 12px"><button class="b2" id="pt_chk">'+ic('check',15)+' '+t('Check now')+'</button>'+(!loc&&n.last_sync?'<small class="muted">'+t('Last contact')+': '+ago(n.last_sync)+'</small>':'')+'</div>'+
  '<div class="card"><h3>'+t('Firewall')+'</h3><p class="sub">'+t('If a port is closed, run this on that server as root:')+'</p><pre class="cmd ltr">'+esc(fwCmd(rows))+'</pre><button class="b2" id="pt_fwc">'+ic('copy',15)+' '+t('Copy command')+'</button></div>'+
  '<div class="card"><h3>'+t('All servers')+'</h3><div class="ptab"><table><thead><tr><th>'+t('Server')+'</th><th>WireGuard</th><th>AmneziaWG</th><th>Hysteria2</th><th>KANKI MIX</th><th>'+t('Panel / API')+'</th></tr></thead><tbody>'+
   ns.map(function(x){var rr=ptRows(x),g=function(k){var r=rr.filter(function(y){return y.k==k})[0];return r?'<span class="ltr">'+esc(r.port)+'</span> <span class="dot '+(r.st=='run'?'g':r.st=='stop'?'r':'')+'"></span>':'<span class="muted">—</span>'};
    return '<tr><td><b>'+esc(x.name)+'</b></td><td>'+g('wg')+'</td><td>'+g('awg')+'</td><td>'+g('hy2')+'</td><td>'+g('kmix')+'</td><td>'+(x.id=='local'?g('web'):g('api'))+'</td></tr>'}).join('')+'</tbody></table></div></div>';
 el.onclick=function(e){var b=e.target.closest('[data-ps]');if(b){PSEL=b.dataset.ps;ptDraw();return}var c=e.target.closest('[data-cp]');if(c){copy(c.dataset.cp);return}
  if(e.target.closest('#pt_fwc'))copy(fwCmd(rows));if(e.target.closest('#pt_chk'))ptCheck(n)}}
function ptCheck(n){toast(t('Checking…'));if(n.id=='local'){api('GET','/api/system').then(function(s){S.psys=s;ptDraw();toast(t('Done'))}).catch(fail);return}
 api('POST','/api/nodes/'+encodeURIComponent(n.id)+'/health').then(function(r){if(r.services){n.info=n.info||{};n.info.services=r.services}toast(r.ok?t('Done'):t('Offline'),!r.ok);ptDraw()}).catch(fail)}

// ---------------------------------------------------------------- tunnels
var TN={d:null};
function tunLoad(){return api('GET','/api/tunnels').then(function(d){TN.d=d;return d})}
// servers in two groups, inside Iran and abroad (a server without a location counts as abroad)
var SRV_GROUPS=[['iran','Iran servers'],['abroad','Abroad servers']];
function srvLoc(s){return s.loc=='iran'?'iran':'abroad'}
function srvOptGroups(list,fn){return SRV_GROUPS.map(function(g){var l=list.filter(function(s){return srvLoc(s)==g[0]});return l.length?'<optgroup label="'+esc(t(g[1]))+'">'+l.map(fn).join('')+'</optgroup>':''}).join('')}
function srvLocSel(id,v){return '<label class="f">'+t('Location')+'</label><select id="'+id+'">'+(v?'':'<option value="">—</option>')+[['iran','Inside Iran'],['abroad','Abroad']].map(function(o){return '<option value="'+o[0]+'"'+(o[0]==v?' selected':'')+'>'+t(o[1])+'</option>'}).join('')+'</select>'}
function tunSrv(id){var l=(TN.d&&TN.d.servers)||[];for(var i=0;i<l.length;i++)if(l[i].id==id)return l[i];return {id:id,name:id}}
function tunStateTxt(s){return {up:t('Connected'),partial:t('Connecting…'),down:t('Disconnected'),off:t('Off')}[s]||s}
function tunCol(s){return s=='up'?'#3ddc97':s=='partial'?'#f5b942':s=='off'?'#8a8f98':'#ff6b6b'}
function tunTr(x){return {tcpmux:'TCP Mux',tcp:'TCP',ws:'WebSocket',wss:'WSS (TLS)',quic:'QUIC',kcp:'KCP',hq:'HQ (masked QUIC)',h2:'H2 (HTTP/2 + TLS)',dual:'Dual (HQ + H2)',cdn:'CDN (whitelist)',game:t('Game (KCP + FEC)'),faketcp:'FakeTCP (UDP→TCP)',awg:'AmneziaWG',hy2:'Hysteria2',baseline:t('Raw ping')}[x]||x}
var TS_TR=[['tcpmux','TCP Mux'],['tcp','TCP'],['ws','WebSocket'],['wss','WSS (TLS)'],['quic','QUIC'],['kcp','KCP'],['hq','HQ (masked QUIC)'],['h2','H2 (HTTP/2 + TLS)'],['game',t('Game (KCP + FEC)')],['faketcp','FakeTCP (UDP→TCP)']];
// GRE: the panel builds its side by itself; this script builds the other side on the server
// (a systemd service, so it comes back after a reboot) and, when the panel has a domain, points that
// domain at the panel's address inside the GRE link so the agent talks to the panel through it
function tunGreScript(g){var n=g.n,hosts=!g.is_ip,
 ex='ip link del kgre0 2>/dev/null; ip tunnel add kgre0 mode gre remote '+g.panel_ip+' ttl 255 && ip addr add 10.77.'+n+'.2/30 dev kgre0 && ip link set kgre0 mtu 1400 up'+(hosts?'; grep -q "# kanki-gre" /etc/hosts || echo "10.77.'+n+'.1 '+g.domain+' # kanki-gre" >> /etc/hosts':''),
 xs='ip link del kgre0 2>/dev/null'+(hosts?'; sed -i "/# kanki-gre/d" /etc/hosts':'');
 return ['# GRE link to the panel',"cat >/etc/systemd/system/kanki-gre.service <<'EOF'",'[Unit]','Description=Kanki GRE link to the panel','After=network-online.target','Wants=network-online.target',
  '[Service]','Type=oneshot','RemainAfterExit=yes',"ExecStart=/bin/sh -c '"+ex+"'","ExecStop=/bin/sh -c '"+xs+"'",'[Install]','WantedBy=multi-user.target','EOF',
  '(ufw allow from '+g.panel_ip+' proto gre >/dev/null 2>&1 || true)','systemctl daemon-reload && systemctl enable --now kanki-gre'].join('\n')}
function tunCmd(s,d){var repo=(d&&d.repo)||'',panel=(d&&d.panel)||location.origin,g=d&&d.gre,pre='';
 if(g&&g.panel_ip){pre=tunGreScript(g)+'\n';if(g.is_ip)panel='https://10.77.'+g.n+'.1'+(g.port?':'+g.port:'')}
 return pre+(repo?'KANKI_REPO='+repo+' ':'')+'KANKI_TUNNEL='+s.id+':'+s.token+' KANKI_PANEL='+panel+' bash <(curl -fsSL https://raw.githubusercontent.com/'+(repo||'kankiturk8770/kanki-panel')+'/main/install.sh)'}

// ---- the live map (canvas): entries on one side, exits on the other.
// Each connected tunnel is a glowing fibre: packets leave the entry plain, pass the lock in the middle
// and arrive encrypted (tunnel colour); smaller return packets flow back. More traffic = more packets,
// higher ping = slower packets. The animation keeps running between data refreshes.
var TM={reg:{},raf:0,t0:(window.performance?performance.now():Date.now())};
function tmStart(){if(TM.raf)return;
 var loop=function(){var cs=document.querySelectorAll('canvas.tmapcv');if(!cs.length){TM.raf=0;return}TM.raf=requestAnimationFrame(loop);
  if(document.visibilityState!='visible')return;var T=((window.performance?performance.now():Date.now())-TM.t0)/1000;
  if(TM.still)T=12.3;for(var i=0;i<cs.length;i++)tmDraw(cs[i],T)};
 TM.still=window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches;TM.raf=requestAnimationFrame(loop)}
function tmRgb(hex){hex=String(hex||'').trim();if(hex.charAt(0)!='#')return [245,196,81];if(hex.length==4)hex='#'+hex[1]+hex[1]+hex[2]+hex[2]+hex[3]+hex[3];return [parseInt(hex.substr(1,2),16),parseInt(hex.substr(3,2),16),parseInt(hex.substr(5,2),16)]}
function tmA(c,a){return 'rgba('+c[0]+','+c[1]+','+c[2]+','+a+')'}
function tmMix(c1,c2,k){return [Math.round(c1[0]+(c2[0]-c1[0])*k),Math.round(c1[1]+(c2[1]-c1[1])*k),Math.round(c1[2]+(c2[2]-c1[2])*k)]}
function tmTheme(){var cs=getComputedStyle(document.body),g=function(v,d){return (cs.getPropertyValue(v)||d).trim()||d},light=document.body.classList.contains('light');
 return {a:tmRgb(g('--a','#F5C451')),al:tmRgb(g('--al','#FFE9A6')),ad:tmRgb(g('--ad','#B8862B')),t:g('--t','#F7F1E3'),s:g('--s','#A89C82'),light:light,disc:light?'#fbf6ec':'#120e08'}}
// short tunnel names for the map: HQ-QUIC, KCP, WSS, AWG+WS …
function tunShort(x){var S={tcpmux:'TCP-Mux',tcp:'TCP',ws:'WS',wss:'WSS',quic:'QUIC',kcp:'KCP',hq:'HQ-QUIC',h2:'H2',dual:'Dual',cdn:'CDN',game:'Game-FEC',faketcp:'FakeTCP'};
 if(x.kind=='hy2')return 'Hy2';if(x.kind=='awg')return 'AWG'+(x.awg&&x.awg.wrap?'+'+(S[x.transport]||x.transport):'');return S[x.transport]||x.transport||'?'}
function tmRound(c,x,y,w,h,r){c.beginPath();c.moveTo(x+r,y);c.arcTo(x+w,y,x+w,y+h,r);c.arcTo(x+w,y+h,x,y+h,r);c.arcTo(x,y+h,x,y,r);c.arcTo(x,y,x+w,y,r);c.closePath()}

// ---- the page
function pTunnels(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Tunnels')+'</h2><p>'+t('Encrypted tunnels between your servers: users connect to the entry, traffic leaves from the exit')+'</p></div>'+
 '<div class="row" style="gap:6px"><button class="b2" onclick="updateAll()">⇪ '+t('Update all')+'</button><button class="b2 smartb" onclick="tunSmart()">⚡ '+t('Smart tunnel')+'</button><button class="b2" id="rt_new" onclick="routeEdit()">⛓ '+t('Multi-location tunnel')+'</button><button class="btn" onclick="tunEdit()">+ '+t('Tunnel')+'</button></div></div>'+
 '<div class="card tmapc"><div id="tn_map"><span class="muted">'+t('Loading…')+'</span></div><div class="tkpi" id="tn_kpi"></div></div>'+
 '<div class="nh" style="margin-top:4px"><h3>'+t('Tunnels')+'</h3></div><div id="tn_list"></div>'+
 '';
 tunRefresh();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible')tunRefresh(true)},3000)}
function tunRefresh(quiet){return tunLoad().then(tunDraw).catch(function(e){if(!quiet)fail(e)})}
function tunDraw(d){var m=$('#tn_map'),sl=$('#tn_srv');if(!m&&!sl)return;var sv=d.servers||[],tl=d.tunnels||[];
 var up=tl.filter(function(x){return x.state=='up'}).length,on=sv.filter(function(s){return s.online}).length,rx=0,tx=0;
 tl.forEach(function(x){var s=x.entry_status;if(s){rx+=s.rx_bytes||0;tx+=s.tx_bytes||0}});
 if(m){var sig=JSON.stringify([sv.map(function(s){return [s.id,s.name,s.online,s.local]}),tl.map(function(x){return [x.id,x.entry,x.exit,x.state,x.transport,Math.round(((x.entry_status||{}).rtt_ms||0)/10)]})]);
  var mh=tunMap(d);if(m.dataset.sig!==sig||!m.querySelector('canvas')){m.dataset.sig=sig;m.innerHTML=mh}
  $('#tn_kpi').innerHTML='<div><small>'+t('Tunnels connected')+'</small><b style="color:'+(up==tl.length&&tl.length?'var(--ok)':'inherit')+'">'+N(up)+' / '+N(tl.length)+'</b></div><div><small>'+t('Servers online')+'</small><b>'+N(on)+' / '+N(sv.length)+'</b></div><div><small>'+t('Through the tunnels')+'</small><b class="ltr">↑ '+bytes(tx)+' · ↓ '+bytes(rx)+'</b></div>';
  $('#tn_list').innerHTML=tl.length?tl.map(tunCard).join(''):'<div class="card muted" style="text-align:center">'+t('No tunnels yet')+' · <a href="javascript:tunEdit()">'+t('Make the first tunnel')+'</a></div>'}
 if(sl){var k=$('#tn_skpi');if(k)k.innerHTML='<div><small>'+t('Servers online')+'</small><b style="color:'+(on==sv.length&&sv.length?'var(--ok)':'inherit')+'">'+N(on)+' / '+N(sv.length)+'</b></div><div><small>'+t('Tunnels connected')+'</small><b>'+N(up)+' / '+N(tl.length)+'</b></div><div><small>'+t('Through the tunnels')+'</small><b class="ltr">↑ '+bytes(tx)+' · ↓ '+bytes(rx)+'</b></div>';
  sl.innerHTML=SRV_GROUPS.map(function(g){var l=sv.filter(function(s){return srvLoc(s)==g[0]});return l.length?'<h3 style="grid-column:1/-1;margin:6px 0 0">'+t(g[1])+' <small class="muted">'+N(l.length)+'</small></h3>'+l.map(tunSrvCard).join(''):''}).join('')}}
function pServers(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Tunnel servers')+'</h2><p>'+t('Servers that only carry tunnels get a small agent: no VPN is installed on them')+'</p></div><div class="row" style="gap:6px"><button class="b2" onclick="updateAll()">⇪ '+t('Update all')+'</button><button class="btn" onclick="tunServerAdd()">+ '+t('Server')+'</button></div></div><div class="card" style="padding:10px"><div class="tkpi" id="tn_skpi" style="margin:0"></div></div><div class="ncards" id="tn_srv">'+t('Loading…')+'</div>';
 tunRefresh();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible')tunRefresh(true)},3000)}
function tunCard(x){if(x.chain)return routeCardOf(x);var e=tunSrv(x.entry),xs=tunSrv(x.exit),es=x.entry_status||{},xx=x.exit_status||{},col=tunCol(x.state),err=es.error?e.name+': '+es.error:xx.error?xs.name+': '+xx.error:'',aw=x.kind=='awg'?(x.awg||{}):null,hy=x.kind=='hy2'?(x.hy2||{}):null;
 if(aw)err=err||(x.wrap_entry||{}).error||(x.wrap_exit||{}).error||'';
 var ports=[];if(x.tcp&&x.tcp.length)ports.push('TCP '+x.tcp.join(', '));if(x.udp&&x.udp.length)ports.push('UDP '+x.udp.join(', '));
 return '<div class="card tcard" style="border-inline-start:3px solid '+col+'"><div class="row" style="justify-content:space-between;align-items:flex-start;gap:8px">'+
  '<div style="min-width:0"><b>'+esc(x.name)+'</b>'+(aw?' <span class="rotb">🛡 AmneziaWG'+(aw.wrap?' + '+esc(tunTr(x.transport)):'')+'</span>':'')+(hy?' <span class="rotb">⚡ Hysteria2'+(hy.obfs_on?' + Salamander':'')+'</span>':'')+(x.auto?' <span class="rotb" title="'+esc(x.switch_note?t('Last switch')+': '+x.switch_note+' · '+ago(x.switched):t('Rotating tunnel'))+'">🔁 '+t('Rotating')+(x.switch_note?' · '+esc(x.switch_note):'')+'</span>':'')+'<div class="tpath"><span>'+esc(e.name)+'</span><i class="tflow" style="--c:'+col+'"><em></em></i><span>'+esc(xs.name)+'</span></div></div>'+
  '<div class="row" style="gap:8px;flex-wrap:nowrap"><span class="tst" style="color:'+col+';border-color:'+col+'"><i style="background:'+col+'"></i>'+tunStateTxt(x.state)+'</span>'+sw('',x.enabled,"tunAct('"+x.id+"','"+(x.enabled?'disable':'enable')+"')")+'</div></div>'+
  '<div class="tgrid"><div><small>'+t('Transport')+'</small><b>'+esc(aw?('AWG'+(aw.wrap?' ⟶ '+tunTr(x.transport):'')):tunTr(x.transport))+'</b></div><div><small>'+t('Ping')+'</small><b class="ltr">'+(es.rtt_ms?es.rtt_ms+' ms':'—')+'</b></div>'+
  '<div><small>'+t('Links')+'</small><b class="ltr">'+N(es.links||0)+' / '+N(es.want||x.conns||1)+'</b></div></div>'+
  '<p class="muted ltr tmeta">↑'+bytes(es.tx_bytes||0)+' ↓'+bytes(es.rx_bytes||0)+' · '+esc((x.mode=='direct'?t('direct'):t('reverse'))+' · '+t('port')+' '+(aw?aw.port:x.port)+' · '+(x.dial_host||'?')+' · '+(aw?('🔗 '+aw.entry_ip+' ⇄ '+aw.exit_ip+(aw.routes&&aw.routes.length?' · → '+aw.routes.join(' '):'')+(aw.src_routes&&aw.src_routes.length?' · ⇠ '+aw.src_routes.join(' '):'')+(aw.fwd_tcp&&aw.fwd_tcp.length?' · TCP '+aw.fwd_tcp.join(','):'')+(aw.fwd_udp&&aw.fwd_udp.length?' · UDP '+aw.fwd_udp.join(','):'')):ports.concat(hy&&hy.src_routes&&hy.src_routes.length?['⇠ '+hy.src_routes.join(' ')]:[]).join(' · ')))+'</p>'+
  (err&&x.state!='up'?'<div class="warnbox ltr" style="margin:6px 0 0">'+esc(err)+'</div>':'')+
  '<div class="g3" style="margin-top:10px"><button class="b2" onclick="tunEdit(\''+x.id+'\')">'+ic('edit',15)+' '+t('Edit')+'</button><button class="b2" onclick="tunAct(\''+x.id+'\',\'restart\')">'+ic('refresh',15)+' '+t('Reconnect')+'</button><button class="b2 bd" onclick="tunDel(\''+x.id+'\')">'+ic('trash',15)+' '+t('Delete')+'</button></div></div>'}
function tunSrvCard(s){var nt=((TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.entry==s.id||x.exit==s.id}).length,col=s.online?'var(--ok)':'var(--bad)';
 return '<div class="card" style="margin:0;border-inline-start:3px solid '+col+'"><div class="row" style="justify-content:space-between;align-items:flex-start"><div class="row"><div class="logo" style="width:34px;height:34px;font-size:14px">'+esc(s.local?'★':s.name.charAt(0).toUpperCase())+'</div><div><b>'+flag(s.cc)+' '+esc(s.name)+'</b><div class="muted ltr">'+esc(s.host||t('address unknown yet'))+'</div></div></div>'+
  '<span class="badge '+(s.online?'g':'r')+'">'+(s.local?t('Panel server'):s.online?t('Connected'):t('Disconnected'))+'</span></div>'+
  '<p class="muted" style="margin:8px 0">'+(s.local?t('Runs inside the panel'):(s.last_seen?t('Last contact')+': '+ago(s.last_seen):t('Not connected yet: run its command on the server')))+(s.version?' · v'+esc(s.version):'')+' · '+t('Tunnels')+' '+N(nt)+'</p>'+
  (s.local?'':!s.loc?'<p class="hint">'+t('Location not set: choose it in Edit')+'</p>':s.loc_guess?'<p class="hint">'+t('Location guessed: confirm it in Edit')+'</p>':'')+
  '<div class="g'+(s.local?'1':'3')+'"><button class="b2" onclick="tunSrvEdit(\''+s.id+'\')">'+ic('edit',15)+' '+t('Edit')+'</button>'+(s.local?'':'<button class="b2" onclick="tunSrvCmd(\''+s.id+'\')">'+ic('link',15)+' '+t('Command')+'</button><button class="b2 bd" onclick="tunSrvDel(\''+s.id+'\')">'+ic('trash',15)+' '+t('Delete')+'</button>')+'</div></div>'}
function tunAct(id,a){api('POST','/api/tunnels/'+id+'/'+a).then(function(){toast(a=='restart'?t('The tunnel reconnects in a few seconds'):t('Done'));tunRefresh()}).catch(fail)}
function tunDel(id){if(!confirm(t('Delete this tunnel? It stops on both servers and its ports are closed in their firewalls.')))return;api('DELETE','/api/tunnels/'+id).then(function(){toast(t('Done'));tunRefresh()}).catch(fail)}
function tunSrvDel(id){if(!confirm(t('Remove this server from the panel? Within a few seconds it removes everything Kanki installed there (tunnels, Kanki DNS, Xray, emergency chat, subscription link), closes the ports Kanki opened and uninstalls its agent.')))return;api('DELETE','/api/tunnels/servers/'+id).then(function(){toast(t('Done'));tunRefresh()}).catch(fail)}

// ---- servers
function tunCmdBox(s,d){
 // a server made in Servers has its own command that installs everything
 if(s&&s.command)return '<label class="f">'+t('Run this on the new server, as root (Ubuntu / Debian)')+'</label><pre class="cmd" id="tn_cmd">'+esc(s.command)+'</pre><button class="btn" style="width:100%" id="tn_cp">'+ic('link',16)+' '+t('Copy command')+'</button>';
 var cmd=tunCmd(s,d);
 return '<label class="f">'+t('Run this on the server, as root (Ubuntu / Debian)')+'</label><pre class="cmd" id="tn_cmd">'+esc(cmd)+'</pre><button class="btn" style="width:100%" id="tn_cp">'+ic('link',16)+' '+t('Copy command')+'</button>'+
  '<p class="muted" style="margin:10px 0 0">'+t('It installs only the tunnel agent: no VPN, no web panel. The server appears here as Connected within a few seconds.')+'</p>'+
  tunGreNote(d&&d.gre)+((d&&d.repo)?'':'<div class="warnbox">'+t('Set the update source (GitHub repo) in Settings first, or replace USER/REPO in the command.')+'</div>')}
function tunGreNote(g){if(!g)return '';return '<p class="muted" style="margin:10px 0 0">🔗 '+t('GRE link: the panel already built its side. The first lines of the command build the other side on the server, then the agent connects to the panel through the link.')+'</p>'+(g.panel_ip?'':'<div class="warnbox">'+t('The panel IP could not be found from its address. Type it in the GRE box (Edit server) and make the command again.')+'</div>')}
function tunGreBox(pre,s){s=s||{};return '<label style="display:flex;gap:8px;align-items:center;margin-top:12px;cursor:pointer"><input type="checkbox" id="'+pre+'_gre" style="width:auto"'+(s.gre_ip?' checked':'')+'><span>'+t('Only GRE passes to this server')+'</span></label>'+
 '<div id="'+pre+'_gx" class="'+(s.gre_ip?'':'hide')+'"><small class="muted">'+t('When TCP to the panel is blocked but GRE passes, the panel builds a GRE link to the server and the agent connects through it. Needs root on both servers.')+'</small>'+
 '<label class="f">'+t('Public IP of this server')+'</label><input id="'+pre+'_gi" class="ltr" placeholder="1.2.3.4" value="'+esc(s.gre_ip||'')+'">'+
 '<label class="f">'+t('IP of the panel server (empty = automatic)')+'</label><input id="'+pre+'_gp" class="ltr" placeholder="5.6.7.8" value="'+esc(s.gre_panel_ip||'')+'"></div>'}
function tunGreWire(pre){$('#'+pre+'_gre').onchange=function(){$('#'+pre+'_gx').classList.toggle('hide',!this.checked)}}
function tunGreBody(pre,b){var on=$('#'+pre+'_gre').checked;b.gre_ip=on?$('#'+pre+'_gi').value.trim():'';b.gre_panel_ip=on?$('#'+pre+'_gp').value.trim():'';return b}
function tunSrvCmd(id){if(!confirm(t('A new command makes the old one stop working. Continue?')))return;
 api('PUT','/api/tunnels/servers/'+id,{new_token:true}).then(function(r){var s=tunSrv(id);modal(mhead(t('Command for')+' '+s.name)+tunCmdBox({id:id,token:r.token},r));$('#tn_cp').onclick=function(){copy($('#tn_cmd').textContent)}}).catch(fail)}
function tunSrvEdit(id){var s=tunSrv(id);
 modal(mhead(t('Edit server'))+(s.local?'':'<label class="f">'+t('Server name')+'</label><input id="ts_nm" value="'+esc(s.name)+'">')+
  '<label class="f">'+t('Address other servers use to reach it')+'</label><input id="ts_ad" class="ltr" value="'+esc(s.addr||'')+'" placeholder="'+esc(s.host||'')+'"><small class="muted">'+t('Empty = automatic')+'</small>'+srvLocSel('ts_lc',s.loc||'')+(s.local?'':tunGreBox('te',s))+
  '<div class="g2" style="margin-top:12px"><button class="b2" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn" id="ts_go">'+t('Save')+'</button></div>');
 if(!s.local)tunGreWire('te');
 $('#ts_go').onclick=function(){var b={addr:$('#ts_ad').value};if($('#ts_lc').value)b.loc=$('#ts_lc').value;if($('#ts_nm'))b.name=$('#ts_nm').value;
  if(!s.local){tunGreBody('te',b);if($('#te_gre').checked&&!b.gre_ip){toast(t('Type the public IP of the server'),1);return}}
  api('PUT','/api/tunnels/servers/'+id,b).then(function(r){tunRefresh();
   if(r.gre){modal(mhead(t('GRE link'))+'<label class="f">'+t('Run this on the server, as root (Ubuntu / Debian)')+'</label><pre class="cmd" id="tn_cmd">'+esc(tunGreScript(r.gre))+'</pre><button class="btn" style="width:100%" id="tn_cp">'+ic('link',16)+' '+t('Copy command')+'</button>'+tunGreNote(r.gre)+
    (r.gre.is_ip?'<div class="warnbox">'+t('The panel address is an IP, so the agent keeps using it. To send the agent through the link make a new command (Command button of the server).')+'</div>':''));$('#tn_cp').onclick=function(){copy($('#tn_cmd').textContent)}}
   else{closeModal();toast(t('Done'))}}).catch(fail)}}

// ---- tunnel wizard
var TNP={balanced:4,speed:8,gaming:2};
function tunUdpTr(tr){return tr=='quic'||tr=='kcp'||tr=='hq'||tr=='hy2'||tr=='game'}
// dual listens on UDP and TCP of the same port number
function tunBoth(tr){return tr=='dual'}
// entry-side ports written in a list: "443", "8443:443", "1000-1010", comma separated
function tunEntryPorts(list){var out=[];(Array.isArray(list)?list:String(list||'').split(/[\s,]+/)).forEach(function(it){String(it).split(',').forEach(function(q){q=q.trim();if(!q)return;var m;
 if((m=q.match(/^(\d+)\s*:\s*\d+$/)))out.push(+m[1]);else if((m=q.match(/^(\d+)\s*-\s*(\d+)$/))){for(var i=+m[1];i<=+m[2]&&i-m[1]<512;i++)out.push(i)}else if(/^\d+$/.test(q))out.push(+q)})});return out}
// ports already taken on a server by the other enabled tunnels (tunnel port + ports opened on the entry)
function tunPortUse(sid,skip){var u={tcp:{},udp:{}};((TN.d&&TN.d.tunnels)||[]).forEach(function(x){if(x.id==skip||x.enabled===false)return;var l=x.mode=='direct'?x.exit:x.entry;
 if(l==sid){if(tunBoth(x.transport)){u.udp[x.port]=1;u.tcp[x.port]=1}else(tunUdpTr(x.transport)?u.udp:u.tcp)[x.port]=1}
 if(x.entry==sid){tunEntryPorts(x.tcp).forEach(function(p){u.tcp[p]=1});tunEntryPorts(x.udp).forEach(function(p){u.udp[p]=1})}
 if(x.kind=='awg'&&x.awg){if(x.entry==sid||x.exit==sid)u.udp[x.awg.port]=1;if(x.awg.wrap&&x.entry==sid)u.udp[x.awg.wrap_port]=1}});return u}
function tunFreePort(listener,skip,udp,both){var U=tunPortUse(listener,skip),u=U[udp?'udp':'tcp'];
 for(var p=3080;p<3500;p++)if(!u[p]&&(!both||!(U.udp[p]||U.tcp[p])))return p;return 3080}
// the node (from Nodes) that lives on a tunnel server: same address / IP, or the same name
function tunNodeFor(sid){return api('GET','/api/nodes').then(function(ns){
 if(sid=='local')return ns.filter(function(z){return z.id=='local'})[0]||null;
 var sv=tunSrv(sid),hs=function(a){return String(a||'').toLowerCase().replace(/^https?:\/\//,'').replace(/[:\/].*$/,'')},
  keys=[sv.addr,sv.ip,sv.host].map(hs).filter(Boolean),nm=String(sv.name||'').trim().toLowerCase(),f=ns.filter(function(n){return n.id!='local'});
 return f.filter(function(n){return keys.indexOf(hs(n.address))>=0||keys.indexOf(hs(n.effective_endpoint))>=0})[0]||f.filter(function(n){return String(n.name||'').trim().toLowerCase()==nm})[0]||null})}
// the VPN ports a node serves (from the node info the panel already keeps)
// the ports of the Xray inbounds and of Kanki DNS that run on a server (Tunnel servers id, or "local"):
// KCP on UDP, Shadowsocks on both, the rest on TCP; DNS 53 (UDP + TCP), DoT 853, DoH 443
function tunSvcPorts(sid){var o={tcp:[],udp:[]},add=function(l,v){v=parseInt(v,10);if(v>0&&v<65536&&o[l].indexOf(v)<0)o[l].push(v)},none=function(){return null};
 return Promise.all([api('GET','/api/xray').catch(none),api('GET','/api/dns').catch(none)]).then(function(r){var x=r[0],d=r[1];
  ((x&&x.on&&x.inbounds)||[]).forEach(function(ib){if(ib.enabled===false||ib.server!=sid)return;
   if(ib.network=='kcp')add('udp',ib.port);else{add('tcp',ib.port);if(ib.protocol=='shadowsocks')add('udp',ib.port)}});
  if(d&&d.on&&(d.servers||[]).some(function(z){return z.server==sid})){add('udp',53);add('tcp',53);add('tcp',853);add('tcp',443)}
  return o})}
function tunMerge(a,b){[['tcp'],['udp']].forEach(function(k){k=k[0];(b[k]||[]).forEach(function(p){if(a[k].indexOf(p)<0)a[k].push(p)})});return a}
function tunEdit(id,pre){if(!TN.d)return tunLoad().then(function(){tunEdit(id,pre)});
 var x=id?Object.assign({},(TN.d.tunnels||[]).filter(function(z){return z.id==id})[0]||{},pre||{}):(pre||{}),sv=TN.d.servers||[];
 var remote=sv.filter(function(s){return !s.local});
 var dE=x.entry||(remote[0]&&remote[0].id)||'',dX=x.exit||'local';
 var opt=function(sel){return srvOptGroups(sv,function(s){return '<option value="'+esc(s.id)+'"'+(s.id==sel?' selected':'')+'>'+esc(s.name+(s.local?' ('+t('panel')+')':''))+'</option>'})};
 var prof=x.conns==8?'speed':x.conns==2?'gaming':'balanced',tr=x.transport||'tcpmux',mode=x.mode||'reverse',kind=(x.kind=='awg'||x.kind=='hy2')?x.kind:'',A=x.awg||{},Y=x.hy2||{};if(tr=='awg'||tr=='hy2')tr='tcpmux';
 var awp=A.params||{},awpt=Object.keys(awp).map(function(k){return k+'='+awp[k]}).join('  ');
 var TRD={dual:[t('UDP first (masked QUIC); if UDP is cut, HTTP/2 over TLS on the same port number'),['UDP','TCP','TLS']],h2:[t('WebSocket over HTTP/2, TLS 1.3 like a browser, many links in one connection'),['TLS','SNI','H2']],faketcp:[t('UDP traffic inside fake TCP packets (udp2raw style): passes where UDP is cut or slowed; needs root on both servers'),['TCP','UDP']],
  wss:[t('Looks like an HTTPS site, hardest to spot'),['TLS','SNI']],ws:[t('Looks like a WebSocket, works behind a CDN'),['HTTP']],tcpmux:[t('Fast and steady, several links at once'),['TCP']],tcp:[t('One plain link'),['TCP']],
  quic:[t('Over QUIC (UDP), fast and encrypted'),['UDP','SNI']],kcp:[t('Over KCP (UDP), good on weak/lossy internet'),['UDP']],hq:[t('QUIC under a random mask: no QUIC signature, packet sizes hidden'),['UDP','SNI','Mask']],
  game:[t('KCP + Reed-Solomon FEC and optional packet duplication: recovers lost packets without waiting, the lowest ping under loss'),['UDP','FEC']],cdn:[t('Whitelist mode: through a CDN (ArvanCloud), for when only domestic sites open'),['TLS','SNI','CDN']]};
 // three groups: over UDP (fast, games), over TCP (steady), advanced (hardest to block / whitelist)
 var trs=[['Over UDP (fast, games)',['game','kcp','quic','hq']],['Over TCP (steady)',['tcpmux','wss','ws','tcp']],['Advanced (hardest to block)',['dual','h2','faketcp','cdn']]].map(function(g){return [g[0],g[1].map(function(k){return [k,TRD[k][0],TRD[k][1]]})]});
 var advOpen=!!(id&&((x.transport!='cdn'&&(x.sni||x.host||x.path||x.frag||x.dial))||x.auto||x.target||prof!='balanced'));
 var sec=function(n,title,extra){return '<div class="tws"><h4>'+(n?'<i>'+N(n)+'</i>':'')+t(title)+(extra||'')+'</h4>'};
 modal(mhead(id?t('Edit tunnel'):t('New tunnel'))+
  (sv.length<2?'<div class="warnbox">'+t('First add your entry server in the “Tunnel servers” menu.')+'</div>':'')+
  sec(1,'Route')+'<label class="f">'+t('Name')+'</label><input id="tw_nm" value="'+esc(x.name||'')+'" placeholder="'+esc(t('Empty = Iran server-abroad server'))+'">'+
  '<div class="trte"><div><label class="f">'+t('Entry (users connect here)')+'</label><select id="tw_en">'+opt(dE)+'</select></div><span class="arr">'+ic('swap',18)+'</span><div><label class="f">'+t('Exit (traffic leaves here)')+'</label><select id="tw_ex">'+opt(dX)+'</select></div></div>'+
  '<label class="f">'+t('Who connects')+'</label><div class="seg" id="tw_md"><button data-v="reverse" class="'+(mode=='reverse'?'on':'')+'">'+t('Exit → entry (reverse, recommended)')+'</button><button data-v="direct" class="'+(mode=='direct'?'on':'')+'">'+t('Entry → exit (direct)')+'</button></div></div>'+
  sec(2,'Tunnel type')+'<div class="seg" id="tw_kd"><button data-v="" class="'+(kind!='awg'?'on':'')+'">'+t('Kanki tunnel')+'</button><button data-v="awg" class="'+(kind=='awg'?'on':'')+'">🛡 AmneziaWG</button><button data-v="hy2" class="'+(kind=='hy2'?'on':'')+'">⚡ Hysteria2</button></div>'+
  '<div id="tw_hy" class="box" style="display:none;margin-top:10px"><b>⚡ Hysteria2 '+t('link between the two servers')+'</b>'+
  '<small class="muted" style="display:block;margin:4px 0 8px">'+t('The exit runs a Hysteria2 server, the entry connects to it (QUIC over UDP, fast on lossy internet). The panel makes the password and a certificate and the entry checks its fingerprint. The agents install Hysteria2 by themselves; your VPN Hysteria2 is not touched.')+'</small>'+
  '<div class="g2"><div><label class="f">'+t('Hysteria2 UDP port (on the exit)')+'</label><input id="tw_hy_pt" type="number" class="ltr" value="'+(Y.port||'')+'"></div><div><label class="f">'+t('SNI (TLS name)')+'</label><input id="tw_hy_sni" class="ltr" value="'+esc(Y.sni||'www.bing.com')+'"></div></div>'+
  '<label class="chk"><input type="checkbox" id="tw_hy_ob" '+(id&&Y.obfs_on===false?'':'checked')+'><span><b>'+t('Obfuscation (Salamander)')+'</b><small>'+t('No QUIC / HTTP/3 signature on the wire. Turn it off only if you want it to look like HTTP/3.')+'</small></span></label>'+
  '<div class="g2"><div><label class="f">'+t('Upload speed of the entry, Mbit/s (0 = automatic)')+'</label><input id="tw_hy_up" type="number" class="ltr" value="'+(Y.up_mbps||0)+'"></div><div><label class="f">'+t('Download speed of the entry, Mbit/s (0 = automatic)')+'</label><input id="tw_hy_dn" type="number" class="ltr" value="'+(Y.down_mbps||0)+'"></div></div>'+
  '<small class="muted" style="display:block">'+t('0 = BBR (adapts by itself). A number turns on Brutal: it keeps that speed even with packet loss. Do not write more than the real speed of the servers.')+'</small>'+
  '<label class="f">'+t('Internet of these networks leaves from the exit')+'</label><input id="tw_hy_sr" class="ltr" value="'+esc((Y.src_routes||[]).join(', '))+'" placeholder="10.8.0.0/24">'+
  '<small class="muted" style="display:block">'+t('For example the subnet of the WireGuard users of the entry: their whole internet goes through Hysteria2 and leaves from the exit. SSH and the entry itself are not touched. The ports below are another way: users connect to a port of the entry and land on the same port of the exit.')+'</small>'+
  '<details class="box" style="margin-top:10px"><summary><b>'+t('Advanced')+'</b></summary>'+
  '<div class="g2"><div><label class="f">'+t('Site shown to strangers (without obfuscation)')+'</label><input id="tw_hy_mq" class="ltr" value="'+esc(Y.masq==null?'https://www.bing.com/':Y.masq)+'" placeholder="https://www.bing.com/"></div><div><label class="f">MTU (TUN)</label><input id="tw_hy_mtu" type="number" class="ltr" value="'+(Y.mtu||1400)+'"></div></div>'+
  (id?'<label class="chk"><input type="checkbox" id="tw_hy_rg"><span><b>'+t('New password and certificate')+'</b></span></label>':'')+'</details>'+
  (id?'<div class="g2" style="margin-top:10px"><button type="button" class="b2 sm" id="tw_hy_c1">'+t('Show the config of the entry')+'</button><button type="button" class="b2 sm" id="tw_hy_c2">'+t('Show the config of the exit')+'</button></div>':'')+
  '</div>'+
  '<div id="tw_awg" class="box" style="display:none;margin-top:10px"><b>🛡 AmneziaWG '+t('link between the two servers')+'</b>'+
  '<small class="muted" style="display:block;margin:4px 0 8px">'+t('A WireGuard-like link with obfuscated packets. The panel makes the keys and the obfuscation numbers and gives both ends the same ones; the agents install AmneziaWG by themselves when it is missing. Inside the link the entry is 10.88.N.1 and the exit 10.88.N.2.')+'</small>'+
  '<label class="chk"><input type="checkbox" id="tw_aw_wrap" '+(A.wrap?'checked':'')+'><span><b>'+t('Hide it inside a transport')+'</b><small>'+t('The AmneziaWG packets travel inside the transport chosen below (WebSocket, WSS, CDN, QUIC, KCP, TCP Mux), so the network only sees that transport. Best for strong filtering.')+'</small></span></label>'+
  '<div class="g2"><div><label class="f">'+t('AmneziaWG UDP port')+'</label><input id="tw_aw_pt" type="number" class="ltr" value="'+(A.port||'')+'"></div><div><label class="f">'+t('Obfuscation profile')+'</label><select id="tw_aw_pf"><option value="classic"'+((A.profile||'classic')=='classic'?' selected':'')+'>'+t('Classic (Jc, S1, S2, H1-H4)')+'</option><option value="heavy"'+(A.profile=='heavy'?' selected':'')+'>'+t('Heavy (more junk, bigger padding)')+'</option><option value="mimic"'+(A.profile=='mimic'?' selected':'')+'>'+t('Mimic QUIC (adds I1, needs AmneziaWG tools 1.5+)')+'</option></select></div></div>'+
  '<div class="g2"><div><label class="f">'+t('MTU (0 = automatic)')+'</label><input id="tw_aw_mtu" type="number" class="ltr" value="'+(A.mtu||0)+'"></div><div><label class="f">'+t('Keepalive (seconds)')+'</label><input id="tw_aw_ka" type="number" class="ltr" value="'+(A.keepalive==null?25:A.keepalive)+'"></div></div>'+
  (id&&awpt?'<small class="muted ltr" style="display:block;margin-top:6px;word-break:break-all">'+esc(awpt)+'</small><div class="g2"><label class="chk"><input type="checkbox" id="tw_aw_rp"><span><b>'+t('New obfuscation numbers')+'</b></span></label><label class="chk"><input type="checkbox" id="tw_aw_rk"><span><b>'+t('New keys')+'</b></span></label></div>':'')+
  '<label class="chk" id="tw_aw_lkw"><input type="checkbox" id="tw_aw_lk" '+(A.lockdown===false?'':'checked')+'><span><b>'+t('Close the AmneziaWG port to the outside')+'</b><small>'+t('Only the transport can reach it; scanners cannot probe the port.')+'</small></span></label>'+
  '<details class="box" style="margin-top:10px" '+((A.routes&&A.routes.length)||(A.src_routes&&A.src_routes.length)||(A.fwd_tcp&&A.fwd_tcp.length)||(A.fwd_udp&&A.fwd_udp.length)?'open':'')+'><summary><b>'+t('Routing through the link')+'</b></summary>'+
  '<label class="chk"><input type="checkbox" id="tw_aw_nat" '+(A.nat_exit===false?'':'checked')+'><span><b>'+t('The exit does NAT (masquerade)')+'</b><small>'+t('Needed so what enters the link can reach the internet from the exit.')+'</small></span></label>'+
  '<label class="f">'+t('Destination networks sent through the link')+'</label><input id="tw_aw_rt" class="ltr" value="'+esc((A.routes||[]).join(', '))+'" placeholder="1.1.1.1, 8.8.0.0/16">'+
  '<label class="f">'+t('All traffic from these networks goes through the link')+'</label><input id="tw_aw_sr" class="ltr" value="'+esc((A.src_routes||[]).join(', '))+'" placeholder="10.8.0.0/24">'+
  '<small class="muted" style="display:block">'+t('For example the subnet of the VPN users of the entry: their internet then leaves from the exit. SSH of the entry itself is never touched.')+'</small>'+
  '<div class="nh" style="margin-top:8px"><span></span><button type="button" class="b2 sm" id="tw_aw_vpn">'+ic('ports',14)+' '+t('Ports of the exit server')+'</button></div><p class="muted" id="tw_aw_pn" style="font-size:11.5px;margin:2px 0 0"></p>'+
  '<div class="g2"><div><label class="f">'+t('Entry public TCP ports sent into the link')+'</label><input id="tw_aw_ft" class="ltr" value="'+esc((A.fwd_tcp||[]).join(', '))+'" placeholder="443, 8443:443"></div><div><label class="f">'+t('Entry public UDP ports sent into the link')+'</label><input id="tw_aw_fu" class="ltr" value="'+esc((A.fwd_udp||[]).join(', '))+'" placeholder="51820"></div></div>'+
  '<label class="f">'+t('Forward to (empty = the exit inside the link)')+'</label><input id="tw_aw_tg" class="ltr" value="'+esc(A.fwd_target||'')+'" placeholder="10.88.N.2"></details>'+
  (id?'<div class="g2" style="margin-top:10px"><button type="button" class="b2 sm" id="tw_aw_c1">'+t('Show the config of the entry')+'</button><button type="button" class="b2 sm" id="tw_aw_c2">'+t('Show the config of the exit')+'</button></div>':'')+
  '</div>'+
  '</div>'+
  '<div id="tw_trw">'+sec(3,'Transport','<button type="button" class="b2 sm" id="tw_smart">⚡ '+t('Find the best transport')+'</button>')+
  '<div id="tw_tr" class="trcols">'+trs.map(function(g,gi){return '<div class="trcol trc'+gi+'"><div class="trgl">'+t(g[0])+'</div><div class="tropt">'+g[1].map(function(o){return '<button data-v="'+o[0]+'" class="'+(tr==o[0]?'on':'')+'"><b>'+tunTr(o[0])+o[2].map(function(z){return '<em class="ttg">'+z+'</em>'}).join('')+'</b><small>'+o[1]+'</small></button>'}).join('')+'</div></div>'}).join('')+'</div>'+
  '<small class="muted" style="display:block;margin-top:8px">'+t('On filtered networks WSS and WS usually pass; plain TCP, TCP Mux, QUIC and KCP are often cut. Use “Find the best transport” to test them between these two servers.')+'</small>'+
  '<div id="tw_gm" class="box" style="display:none;margin-top:10px"><b>🎮 '+t('Gaming options')+'</b>'+
  '<small class="muted" style="display:block;margin:4px 0 8px">'+t('FEC sends extra repair packets so a lost packet is rebuilt at the other end instead of being waited for (about 40–100 ms saved per loss). 8:3 means 3 repair packets per 8 data packets (~37% more traffic). Duplication sends every packet twice: best ping, double the traffic. For WireGuard on top of this tunnel, FEC 8:3 is the sweet spot.')+'</small>'+
  '<div class="g2"><div><label class="f">'+t('FEC data:parity')+'</label><input id="tw_fec" class="ltr" value="'+esc(x.fec||'8:3')+'" placeholder="8:3 · off"></div>'+
  '<div style="align-self:end"><label class="chk"><input type="checkbox" id="tw_dup" '+(x.dup?'checked':'')+'><span><b>'+t('Send every packet twice')+'</b><small>'+t('The first copy that arrives wins; near-zero visible loss, double traffic')+'</small></span></label></div></div></div></div>'+
  '<div id="tw_cdn" class="box" style="display:none;margin-top:10px"><b>'+t('Whitelist mode (CDN)')+'</b>'+
  '<small class="muted" style="display:block;margin:4px 0 8px">'+t('Easy setup: choose above which server the CDN points to, type your domain here and the tunnel port below. The panel does the rest.')+'</small>'+
  '<label class="f">'+t('Host: your domain on the CDN')+'</label><input id="tw_chost" class="ltr" value="'+esc(x.host||'')+'" placeholder="tun.example.com">'+
  '<small class="muted" id="tw_cdh" style="display:block;margin-top:6px"></small>'+
  '<details class="box" id="tw_cdx" style="margin-top:10px"><summary><b>'+t('Extra disguise (optional)')+'</b></summary>'+
  '<label class="f">'+t('CDN edge addresses (IPs, comma separated)')+'</label><input id="tw_cdl" class="ltr" value="'+esc(x.dial||'')+'" placeholder="'+t('empty = use the domain')+'">'+
  '<label class="f">'+t('SNI names (comma separated, empty = same as Host)')+'</label><input id="tw_csni" class="ltr" value="'+esc(x.sni||'')+'" placeholder="tun.example.com, www.aparat.com">'+
  '<div class="spoofc" id="tw_cspoof">'+['www.aparat.com','www.telewebion.com','www.rubika.ir','www.digikala.com','divar.ir'].map(function(d){return '<button type="button" data-sp="'+d+'">'+d+'</button>'}).join('')+'</div>'+
  '<label class="chk"><input type="checkbox" id="tw_frag" '+(x.frag!==false?'checked':'')+'><span><b>'+t('Split the TLS hello into tiny pieces')+'</b><small>'+t('Hides the SNI from filters that do not reassemble packets. Turn it off if the CDN refuses.')+'</small></span></label></details>'+
  cdnTools()+'</div></div>'+
  sec(4,'Ports')+'<div id="tw_ptrow"><label class="f">'+t('Tunnel port')+'</label><input id="tw_pt" type="number" class="ltr" value="'+(x.port||'')+'"></div>'+
  '<small class="muted" id="tw_ph"></small>'+
  '<div id="tw_pc"><div class="nh" style="margin-top:12px"><b>'+t('Ports to carry')+'</b><button class="b2 sm" id="tw_vpn">'+ic('ports',14)+' '+t('Ports of the exit server')+'</button></div>'+
  '<small class="muted" id="tw_pn" style="display:block;margin-bottom:6px"></small>'+
  '<div class="g2"><div><label class="f">TCP</label><input id="tw_tcp" class="ltr" value="'+esc((x.tcp||[]).join(', '))+'" placeholder="443, 2053"></div><div><label class="f">UDP</label><input id="tw_udp" class="ltr" value="'+esc((x.udp||[]).join(', '))+'" placeholder="51820, 51821, 8443"></div></div>'+
  '<small class="muted">'+t('Users connect to these ports on the entry; they reach the same ports on the exit. Use 8443:443 to change the port, 1000-1010 for a range.')+'</small></div></div>'+
  // everything that is not needed to run the tunnel: folded under «Advanced settings»
  '<div class="adv'+(advOpen?' on':'')+'" id="tw_adv"><button type="button" class="advh" aria-expanded="'+advOpen+'">'+ic('settings',16)+'<span>'+t('Advanced settings')+'</span><i>▾</i></button><div class="advb"><div class="advi">'+
  '<div id="tw_dsg">'+sec(0,'Disguise','<small id="tw_camt"></small>')+
  '<div class="camn" id="tw_camn"></div>'+
  '<div id="tw_cam"><div id="tw_snw"><label class="f">'+t('SNI names (TLS hello)')+'</label><input id="tw_sni" class="ltr" value="'+esc(x.transport=='cdn'?'':(x.sni||''))+'" placeholder="www.google.com, www.bing.com">'+
  '<div class="spoofc" id="tw_spoof">'+['www.google.com','www.cloudflare.com','www.bing.com','www.microsoft.com','www.apple.com','cdn.jsdelivr.net'].map(function(d){return '<button type="button" data-sp="'+d+'">'+d+'</button>'}).join('')+'</div>'+
  '<small class="muted" style="display:block;margin-top:5px">'+t('Several names, comma separated: every link uses another one and a link that fails moves to the next. Empty = the server address.')+'</small></div>'+
  '<label class="chk" id="tw_fragw"><input type="checkbox" id="tw_frag2" '+(x.transport!='cdn'&&x.frag?'checked':'')+'><span><b>'+t('Split the TLS hello into tiny pieces')+'</b><small>'+t('Hides the SNI from filters that do not reassemble packets.')+'</small></span></label>'+
  '<div class="g2" id="tw_hpw"><div id="tw_hw"><label class="f">'+t('Host header (HTTP)')+'</label><input id="tw_host" class="ltr" value="'+esc(x.transport=='cdn'?'':(x.host||''))+'" placeholder="'+t('empty = same as the SNI')+'"></div><div id="tw_pw"><label class="f">'+t('Path')+'</label><input id="tw_pa" class="ltr" value="'+esc(x.path||'')+'" placeholder="/"></div></div>'+
  '<div id="tw_spg"></div></div>'+
  '</div></div>'+
  '<div class="tws" id="tw_pfw"><h4>'+t('Profile')+'</h4><select id="tw_pf"><option value="balanced"'+(prof=='balanced'?' selected':'')+'>'+t('Balanced')+'</option><option value="speed"'+(prof=='speed'?' selected':'')+'>'+t('Most speed')+'</option><option value="gaming"'+(prof=='gaming'?' selected':'')+'>'+t('Gaming (low ping)')+'</option></select></div>'+
  '<div class="tws" id="tw_more"><h4>'+t('More')+' <small class="muted" style="font-weight:600">'+t('rotating tunnel, address to dial, target')+'</small></h4><label class="chk rotk"><input type="checkbox" id="tw_au" '+(x.auto?'checked':'')+'><span><b>🔁 '+t('Rotating tunnel')+'</b><small>'+t('If it stays down, it switches by itself: KCP → TCP Mux → QUIC → WS → WSS → TCP (balanced, reverse)')+'</small></span></label>'+
  '<div class="g2"><div><label class="f">'+t('Address to dial (empty = the server’s address)')+'</label><input id="tw_dl" class="ltr" value="'+esc(x.transport=='cdn'?'':(x.dial||''))+'"></div>'+
  '<div><label class="f">'+t('Target on the exit')+'</label><input id="tw_tg" class="ltr" value="'+esc(x.target||'')+'" placeholder="127.0.0.1"></div></div></div>'+
  '</div></div></div>'+
  '<div class="g2" style="margin-top:14px"><button class="b2" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn" id="tw_go">'+(id?t('Save'):t('Make the tunnel'))+'</button></div>','wide');
 var st={mode:mode,tr:tr,kind:kind,wrap:!!A.wrap};
 $('#tw_adv .advh').onclick=function(){var a=$('#tw_adv'),on=a.classList.toggle('on');this.setAttribute('aria-expanded',on)};
 function hint(){var en=$('#tw_en').value,ex=$('#tw_ex').value,l=st.mode=='direct'?ex:en,pt=$('#tw_pt');
  // fill the port by itself only until the person types one; a field they cleared or typed stays theirs
  if(!pt.dataset.touched&&!(id&&pt.value))pt.value=(st.tr=='cdn'?8080:tunFreePort(l,id,tunUdpTr(st.tr),tunBoth(st.tr)));
  var ls=tunSrv(l),port=pt.value,udp=tunUdpTr(st.tr),both=tunBoth(st.tr),PU=tunPortUse(l,id),busy=port&&(both?(PU.udp[+port]||PU.tcp[+port]):PU[udp?'udp':'tcp'][+port]);
  $('#tw_ph').textContent=t('Open this port on')+' '+ls.name+': '+port+(both?'/UDP + '+port+'/TCP':udp?'/UDP':'/TCP')+(en==ex?' · '+t('The entry and the exit must be different'):'')+(busy?' · ⚠ '+t('This port is already used by another tunnel'):'');
  $('#tw_ph').style.color=busy?'var(--bad)':'';
  var hp=$('#tw_hy_pt');if(hp&&!hp.dataset.touched&&!(id&&hp.value)){var hx=tunPortUse(ex,id).udp,hq=4443;while(hx[hq]&&hq<65000)hq++;hp.value=hq}
  var ap=$('#tw_aw_pt');if(ap&&!ap.dataset.touched&&!(id&&ap.value)){var ue=tunPortUse(en,id).udp,ux=tunPortUse(ex,id).udp,q=51900;while((ue[q]||ux[q])&&q<65000)q++;ap.value=q}}
 $('#tw_pt').oninput=function(){this.dataset.touched=1;hint()};
 $('#tw_tcp').oninput=function(){this.dataset.touched=1};$('#tw_udp').oninput=function(){this.dataset.touched=1};
 // writes the VPN ports of the chosen exit server (from Nodes) into the TCP / UDP boxes; a port that the
 // entry already uses for another tunnel (or for its own VPN) is moved to a free one: 51821:51820
 function fillPorts(manual){var en=$('#tw_en').value,ex=$('#tw_ex').value,pn=$('#tw_pn');if(en==ex||st.kind=='awg')return;
  if(!manual&&($('#tw_tcp').dataset.touched||$('#tw_udp').dataset.touched))return;
  Promise.all([tunNodeFor(ex),tunNodeFor(en),tunSvcPorts(ex),tunSvcPorts(en)]).then(function(r){var n=r[0],m=r[1],sx=r[2];
   var P=tunMerge(n?tunNodePorts(n):{tcp:[],udp:[]},sx),E=tunMerge(m?tunNodePorts(m):{tcp:[],udp:[]},r[3]);
   if(!P.tcp.length&&!P.udp.length){if(manual)toast(t('No node found for this server: type the ports by hand'));return}
   var use=tunPortUse(en,id),l=st.mode=='direct'?ex:en,pt=+$('#tw_pt').value,moved=[];
   E.tcp.forEach(function(p){use.tcp[p]=1});E.udp.forEach(function(p){use.udp[p]=1});
   if(l==en&&pt){if(tunBoth(st.tr)){use.udp[pt]=1;use.tcp[pt]=1}else(tunUdpTr(st.tr)?use.udp:use.tcp)[pt]=1}
   var mp=function(arr,u){return arr.map(function(p){var q=p;while(u[q]&&q<65535)q++;u[q]=1;if(q!=p)moved.push(q+'→'+p);return q==p?String(p):q+':'+p})};
   $('#tw_tcp').value=mp(P.tcp,use.tcp).join(', ');$('#tw_udp').value=mp(P.udp,use.udp).join(', ');
   var what=[n?'VPN':'',sx.tcp.length||sx.udp.length?'Xray / DNS':''].filter(Boolean).join(' + ');
   if(pn)pn.textContent=t('Ports of')+' '+(n?n.name:tunSrv(ex).name)+' ('+what+') '+t('were filled in')+(moved.length?' · '+t('Moved on the entry because they were taken')+': '+moved.join(', '):'')}).catch(function(e){if(manual)fail(e)})}
 $('#tw_en').onchange=function(){hint();if(!id)fillPorts(false)};$('#tw_ex').onchange=function(){hint();if(!id)fillPorts(false)};
 $('#tw_md').onclick=function(e){var b=e.target.closest('button');if(!b)return;st.mode=b.dataset.v;$$('#tw_md button').forEach(function(z){z.classList.toggle('on',z==b)});cdnUi()};
 function kindUi(){var aw=st.kind=='awg',hy=st.kind=='hy2',tr=(!aw||st.wrap)&&!hy;$('#tw_awg').style.display=aw?'block':'none';$('#tw_hy').style.display=hy?'block':'none';
  if(hy)st.mode='direct';var md=$('#tw_md');md.style.display=hy?'none':'';if(md.previousElementSibling)md.previousElementSibling.style.display=hy?'none':'';$('#tw_trw').style.display=tr?'':'none';$('#tw_ptrow').style.display=tr?'':'none';$('#tw_pfw').style.display=tr?'':'none';$('#tw_dsg').style.display=tr?'':'none';$('#tw_ph').style.display=tr?'':'none';$('#tw_pc').style.display=aw?'none':'';$('#tw_aw_lkw').style.display=st.wrap?'':'none';var s5=$('#tw_ptrow').closest('.tws');if(s5)s5.style.display=(!aw||st.wrap)?'':'none';$$('#tw_kd button').forEach(function(z){z.classList.toggle('on',z.dataset.v==st.kind)});cdnUi()}
 // what each transport can disguise: SNI (TLS name), split hello, Host header, path
 var CAM={tcpmux:{n:'TCP Mux has no site name: it is encrypted from the first byte, so there is nothing to disguise.'},tcp:{n:'TCP has no site name: it is encrypted from the first byte, so there is nothing to disguise.'},
  kcp:{n:'KCP is fully encrypted UDP (its header is hidden too); there is no site name to disguise.'},
  ws:{host:1,path:1,n:'WS has no TLS, so there is no SNI: only the Host header and the path of the WebSocket request can be changed.'},
  wss:{sni:1,frag:1,host:1,path:1,n:'SNI spoof: the TLS hello shows another site name. It only helps when the filter decides by name; it does nothing if the IP is blocked.'},
  quic:{sni:1,n:'The QUIC hello carries a site name too (default www.cloudflare.com).'},
  hq:{sni:1,n:'Every UDP packet is masked with a key made from the token: no QUIC signature, random sizes. Unmasked packets get no answer. The QUIC hello carries a site name (default www.cloudflare.com).'},
  h2:{sni:1,frag:1,host:1,path:1,n:'TLS 1.3 with the ALPN, ciphers and HTTP/2 settings of a browser; a stranger who opens the site gets an ordinary web page. Use port 443.'},
  dual:{sni:1,frag:1,host:1,path:1,n:'Tries masked QUIC first and switches to HTTP/2 over TLS by itself when UDP does not pass. Open the port on UDP and TCP; port 443 is best.'},
  game:{n:'Every UDP packet is masked with a key made from the token, so no KCP signature shows; sizes and timing look random. FEC repairs losses without a retransmit.'},
  faketcp:{n:'UDP travels inside hand-crafted TCP packets with a fake handshake: to DPI it is an ordinary TCP session, but with the speed of UDP. Both servers need root and the port on TCP.'},cdn:{cdn:1}};
 function camUi(){var c=CAM[st.tr]||{},sh=function(i,v){var e=$(i);if(e)e.style.display=v?'':'none'};
  sh('#tw_snw',c.sni);sh('#tw_fragw',c.frag);sh('#tw_hw',c.host);sh('#tw_pw',c.path||c.cdn);sh('#tw_hpw',c.host||c.path||c.cdn);sh('#tw_gm',st.tr=='game');
  var n=$('#tw_camn');n.innerHTML=c.n?ic(c.sni||c.host?'security':'check',16)+'<span>'+t(c.n)+'</span>':'';n.style.display=c.n?'':'none';
  $('#tw_camt').textContent=c.sni?t('SNI spoof'):c.host?t('Host / path'):c.cdn?t('CDN'):t('Not needed');
  var g=$('#tw_spg');if(g)g.innerHTML=c.sni?spGuide():'';
  var hp=$('#tw_hpw');if(hp)hp.style.gridTemplateColumns=c.host?'':'1fr';if(hp&&c.cdn){if(hp.parentNode!=$('#tw_cdn'))$('#tw_cdn').insertBefore(hp,$('#tw_cdx'))}else if(hp&&hp.parentNode!=$('#tw_cam'))$('#tw_cam').insertBefore(hp,$('#tw_spg'))}
 function cdnUi(){var on=st.tr=='cdn'&&(st.kind!='awg'||st.wrap);$('#tw_cdn').style.display=on?'block':'none';camUi();var rk=document.querySelector('.rotk');if(rk)rk.style.display=(on||st.kind=='awg'||st.kind=='hy2')?'none':'';
  $$('#tw_md button').forEach(function(z){var v=z.dataset.v;z.textContent=on?(v=='reverse'?t('CDN points to the Iran server: the foreign server connects in (recommended)'):t('CDN points to the foreign server: the Iran server connects out')):(v=='reverse'?t('Exit → entry (reverse, recommended)'):t('Entry → exit (direct)'));z.classList.toggle('on',v==st.mode)});
  var h=$('#tw_cdh');if(h)h.textContent=on?(st.mode=='reverse'?t('On the CDN: add the domain, point it to the Iran (entry) server IP, turn WebSocket on, origin = HTTP on the tunnel port below. Open that port on the Iran server.'):t('On the CDN: add the domain, point it to the foreign (exit) server IP, turn WebSocket on, origin = HTTP on the tunnel port below. Open that port on the exit server.')):'';hint()}
 $('#tw_tr').onclick=function(e){var b=e.target.closest('button');if(!b)return;st.tr=b.dataset.v;$$('#tw_tr button').forEach(function(z){z.classList.toggle('on',z==b)});cdnUi()};
 $('#tw_vpn').onclick=function(){fillPorts(true)};
 // AmneziaWG: the same ports go into its forward fields (VPN, KANKI MIX, MIX+, Xray, DNS of the exit); a port the
 // entry itself uses moves to the next free one there ("4101:4100")
 if($('#tw_aw_vpn'))$('#tw_aw_vpn').onclick=function(){var en=$('#tw_en').value,ex=$('#tw_ex').value,pn=$('#tw_aw_pn');if(en==ex)return;
  Promise.all([tunNodeFor(ex),tunNodeFor(en),tunSvcPorts(ex),tunSvcPorts(en)]).then(function(r){var n=r[0],m=r[1];
   var P=tunMerge(n?tunNodePorts(n):{tcp:[],udp:[]},r[2]),E=tunMerge(m?tunNodePorts(m):{tcp:[],udp:[]},r[3]);
   if(!P.tcp.length&&!P.udp.length){toast(t('No node found for this server: type the ports by hand'));return}
   var use={tcp:{},udp:{}},moved=[],apt=+(($('#tw_aw_pt')||{}).value||0);E.tcp.forEach(function(p){use.tcp[p]=1});E.udp.forEach(function(p){use.udp[p]=1});if(apt)use.udp[apt]=1;
   var mp=function(arr,u){return arr.map(function(p){var q=p;while(u[q]&&q<65535)q++;u[q]=1;if(q!=p)moved.push(q+'→'+p);return q==p?String(p):q+':'+p})};
   $('#tw_aw_ft').value=mp(P.tcp,use.tcp).join(', ');$('#tw_aw_fu').value=mp(P.udp,use.udp).join(', ');
   if(pn)pn.textContent=t('Ports of')+' '+(n?n.name:tunSrv(ex).name)+' '+t('were filled in')+(moved.length?' · '+t('Moved on the entry because they were taken')+': '+moved.join(', '):'')}).catch(fail)};
 $('#tw_kd').onclick=function(e){var b=e.target.closest('button');if(!b)return;st.kind=b.dataset.v;kindUi()};
 $('#tw_aw_wrap').onchange=function(){st.wrap=this.checked;kindUi()};$('#tw_aw_pt').oninput=function(){this.dataset.touched=1};
 $('#tw_hy_pt').oninput=function(){this.dataset.touched=1};var h1=$('#tw_hy_c1'),h2=$('#tw_hy_c2');if(h1)h1.onclick=function(){hy2Conf(id,'entry')};if(h2)h2.onclick=function(){hy2Conf(id,'exit')};
 var c1=$('#tw_aw_c1'),c2=$('#tw_aw_c2');if(c1)c1.onclick=function(){awgConf(id,'entry')};if(c2)c2.onclick=function(){awgConf(id,'exit')};
 $('#tw_smart').onclick=function(){if($('#tw_en').value==$('#tw_ex').value){toast(t('The entry and the exit must be different'),1);return}
  var L=function(v){return String(v||'').split(/[\s,]+/).filter(Boolean)},g=function(k){var e=$(k);return e?e.value:''};
  tunSmart({entry:$('#tw_en').value,exit:$('#tw_ex').value,prof:$('#tw_pf').value,apply:{id:id,snap:{name:$('#tw_nm').value,mode:st.mode,transport:st.tr,port:+$('#tw_pt').value||0,conns:TNP[$('#tw_pf').value]||4,tcp:L($('#tw_tcp').value),udp:L($('#tw_udp').value),dial:g('#tw_dl'),target:g('#tw_tg'),sni:g('#tw_sni'),host:g('#tw_host'),frag:!!($('#tw_frag2')&&$('#tw_frag2').checked),path:g('#tw_pa'),auto:!!($('#tw_au')&&$('#tw_au').checked),fec:st.tr=='game'?g('#tw_fec'):'',dup:st.tr=='game'&&!!($('#tw_dup')&&$('#tw_dup').checked)}}})};
 hint();kindUi();if(!id&&!(x.tcp||[]).length&&!(x.udp||[]).length&&st.kind!='awg')fillPorts(false);livePorts(id);
 // the name it gets when left empty: Iran server-abroad server
 var nmHint=function(){var e=tunSrv($('#tw_en').value),x2=tunSrv($('#tw_ex').value),ir=function(v){return v.loc=='iran'},a=ir(x2)&&!ir(e)?[x2,e]:[e,x2];$('#tw_nm').placeholder=a[0].name+'-'+a[1].name};
 nmHint();$('#tw_en').addEventListener('change',nmHint);$('#tw_ex').addEventListener('change',nmHint);
 var ct=$('#tw_ctest');if(ct)ct.onclick=cdnTest;var cn=$('#tw_cscan');if(cn)cn.onclick=cdnScan;
 var sp=$('#tw_spoof');if(sp)sp.onclick=function(e){var b=e.target.closest('[data-sp]');if(!b)return;var i=$('#tw_sni'),v=i.value.trim();i.value=v?(v.split(/[\s,]+/).indexOf(b.dataset.sp)<0?v+', '+b.dataset.sp:v):b.dataset.sp};
 var cs=$('#tw_cspoof');if(cs)cs.onclick=function(e){var b=e.target.closest('[data-sp]');if(!b)return;var i=$('#tw_csni'),v=i.value.trim();i.value=v?(v.split(/[\s,]+/).indexOf(b.dataset.sp)<0?v+', '+b.dataset.sp:v):b.dataset.sp};
 $('#tw_go').onclick=function(){var me=this,b={name:$('#tw_nm').value,entry:$('#tw_en').value,exit:$('#tw_ex').value,mode:st.mode,transport:st.tr,port:+$('#tw_pt').value||0,conns:TNP[$('#tw_pf').value]||4,
  tcp:$('#tw_tcp').value,udp:$('#tw_udp').value,dial:st.tr=='cdn'?$('#tw_cdl').value:$('#tw_dl').value,target:$('#tw_tg').value,sni:st.tr=='cdn'?$('#tw_csni').value:$('#tw_sni').value,path:$('#tw_pa').value,auto:st.tr!='cdn'&&$('#tw_au').checked,host:st.tr=='cdn'?$('#tw_chost').value:$('#tw_host').value,frag:st.tr=='cdn'?$('#tw_frag').checked:$('#tw_frag2').checked,fec:st.tr=='game'?($('#tw_fec').value||'8:3'):'',dup:st.tr=='game'&&$('#tw_dup').checked};if(id)b.id=id;
  if(st.kind=='awg'){var g2=function(k){var e=$(k);return e?e.value:''};b.kind='awg';b.auto=false;b.awg={wrap:st.wrap,port:+g2('#tw_aw_pt')||0,profile:g2('#tw_aw_pf'),mtu:+g2('#tw_aw_mtu')||0,keepalive:+g2('#tw_aw_ka')||0,lockdown:!!($('#tw_aw_lk')&&$('#tw_aw_lk').checked),nat_exit:!!$('#tw_aw_nat').checked,routes:g2('#tw_aw_rt'),src_routes:g2('#tw_aw_sr'),fwd_tcp:g2('#tw_aw_ft'),fwd_udp:g2('#tw_aw_fu'),fwd_target:g2('#tw_aw_tg'),regen_params:!!($('#tw_aw_rp')&&$('#tw_aw_rp').checked),regen_keys:!!($('#tw_aw_rk')&&$('#tw_aw_rk').checked)};if(!st.wrap)b.port=0}
  else if(st.kind=='hy2'){var g3=function(k){var e=$(k);return e?e.value:''};b.kind='hy2';b.auto=false;b.mode='direct';b.transport='tcpmux';b.hy2={port:+g3('#tw_hy_pt')||0,sni:g3('#tw_hy_sni'),obfs:!!$('#tw_hy_ob').checked,up_mbps:+g3('#tw_hy_up')||0,down_mbps:+g3('#tw_hy_dn')||0,src_routes:g3('#tw_hy_sr'),masq:g3('#tw_hy_mq'),mtu:+g3('#tw_hy_mtu')||0,regen:!!($('#tw_hy_rg')&&$('#tw_hy_rg').checked)};b.port=b.hy2.port}else b.kind='';
  me.disabled=true;api('POST','/api/tunnels',b).then(function(){closeModal();toast(id?t('Saved: the tunnel restarts with the new settings'):t('The tunnel is made: it connects in a few seconds'));tunRefresh()}).catch(function(e){me.disabled=false;fail(e)})}}


// ---- the tunnel form: live port check
// what the servers themselves say is listening, shown while the ports are typed
var PC={};
function portsOf(sid){var c=PC[sid];if(c&&Date.now()-c.at<8000)return Promise.resolve(c.v);
 return api('GET','/api/tunnels/servers/'+encodeURIComponent(sid)+'/ports').then(function(v){PC[sid]={at:Date.now(),v:v};return v}).catch(function(){return {known:false,used:[]}})}
function portNums(v){var o=[];String(v||'').split(/[\s,]+/).forEach(function(x){var a=x.split(':')[0];var r=a.split('-');if(r.length==2){for(var i=+r[0];i<=+r[1]&&i-+r[0]<2000;i++)o.push(i)}else if(+a>0)o.push(+a)});return o}
function liveCheck(id){var en=$('#tw_en'),ex=$('#tw_ex');if(!en||!ex)return;var box=$('#v37pc');if(!box){box=document.createElement('div');box.id='v37pc';var ph=$('#tw_ph');if(!ph)return;ph.parentNode.insertBefore(box,ph.nextSibling)}
 var mode=($('#tw_md button.on')||{dataset:{v:'reverse'}}).dataset.v,trb=$('#tw_tr button.on'),tr=trb?trb.dataset.v:'tcpmux',listener=mode=='direct'?ex.value:en.value;
 var udp=['quic','kcp','hq','game'].indexOf(tr)>=0,both=tr=='dual',port=+(($('#tw_pt')||{}).value||0);
 var old=id?((TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.id==id})[0]:null;
 var mine=function(sid,p,u){if(!old||!old.enabled)return false;var ol=old.mode=='direct'?old.exit:old.entry;var ou=['quic','kcp','hq','game','dual'].indexOf(old.transport)>=0,ot=['quic','kcp','hq','game'].indexOf(old.transport)<0;
  return (sid==ol&&p==old.port&&(u?ou:ot))||(sid==old.entry&&portNums((u?old.udp:old.tcp)||[]).indexOf(p)>=0)};
 var need=[];if(port){if(!udp||both)need.push([listener,port,false]);if(udp||both)need.push([listener,port,true])}
 portNums(($('#tw_tcp')||{}).value).forEach(function(p){need.push([en.value,p,false])});portNums(($('#tw_udp')||{}).value).forEach(function(p){need.push([en.value,p,true])});
 var sids=need.map(function(x){return x[0]}).filter(function(v,i,a){return v&&a.indexOf(v)==i});
 Promise.all(sids.map(function(sid){return portsOf(sid).then(function(v){return [sid,v]})})).then(function(rs){var msg=[],unknown=[];
  rs.forEach(function(r){var sid=r[0],v=r[1];if(!v.known){unknown.push(sid);return}
   need.filter(function(n){return n[0]==sid}).forEach(function(n){var hit=(v.used||[]).filter(function(u){return u.port==n[1]&&(u.proto=='udp')==n[2]})[0];
    if(hit&&!(hit.kanki&&mine(sid,n[1],n[2])))msg.push((n[2]?'UDP ':'TCP ')+n[1]+' · '+(tunSrv(sid).name||sid)+': '+t('taken by')+' '+hit.by)})});
  box.className=msg.length?'warnbox':'';box.innerHTML=msg.length?'<b>⚠ '+t('These ports are already taken on the server')+'</b><br>'+msg.map(esc).join('<br>'):(unknown.length?'<small class="muted">'+t('The server has not said which ports are free yet (update it to 3.7)')+'</small>':(need.length?'<small class="okt">✓ '+t('The ports are free on the servers')+'</small>':''))})}
function livePorts(id){var tm,go=function(){clearTimeout(tm);tm=setTimeout(function(){liveCheck(id)},350)};
 ['#tw_pt','#tw_tcp','#tw_udp'].forEach(function(s){var e=$(s);if(e)e.addEventListener('input',go)});['#tw_en','#tw_ex'].forEach(function(s){var e=$(s);if(e)e.addEventListener('change',go)});
 ['#tw_tr','#tw_md'].forEach(function(s){var e=$(s);if(e)e.addEventListener('click',go)});setTimeout(go,600)}

// ---- Hysteria2: show the config of one side
function hy2Conf(id,side){api('GET','/api/tunnels/'+id+'/hy2conf/'+side).then(function(r){modal(mhead(t('Config')+' · '+(side=='exit'?t('Exit'):t('Entry')))+'<p class="muted">'+'hysteria '+(side=='exit'?'server':'client')+' -c … · '+t('It holds the password: do not share it.')+' <span class="ltr">'+esc(r.file)+'</span></p><pre class="ltr" style="white-space:pre-wrap;word-break:break-all;font-size:11px;max-height:50vh;overflow:auto">'+esc(r.conf)+'</pre><button class="btn" id="hy_cp" style="width:100%;margin-top:8px">'+t('Copy')+'</button>');$('#hy_cp').onclick=function(){copy(r.conf)}}).catch(fail)}

// ---- AmneziaWG: show the config of one side (for a server that does not run the agent)
function awgConf(id,side){api('GET','/api/tunnels/'+id+'/awgconf/'+side).then(function(r){modal(mhead(t('Config')+' · '+(side=='exit'?t('Exit'):t('Entry')))+'<p class="muted">'+t('Save it as the file below in /etc/amnezia/amneziawg/ and run awg-quick up. It holds a private key: do not share it.')+' <span class="ltr">'+esc(r.file)+'</span></p><pre class="ltr" id="aw_cf" style="white-space:pre-wrap;word-break:break-all;font-size:11px;max-height:50vh;overflow:auto">'+esc(r.conf)+'</pre><button class="btn" id="aw_cp" style="width:100%;margin-top:8px">'+t('Copy')+'</button>');$('#aw_cp').onclick=function(){copy(r.conf)}}).catch(fail)}

// ---- SNI spoof / CDN guide, panel-side CDN test and an edge scanner script for the entry server
function spGuide(){var fa=S.lang=='fa';
 var h=fa?[
 ['سرور ایران «آفلاین» است؟','یعنی پنل نمی‌تواند به آن برسد یا ایران نمی‌تواند به خارج وصل شود (آی‌پی سفید / لیست سفید). سه راه: ① آی‌پی سفید: سرور داخلی که به خارج راه دارد. ② حالت معکوس (Reverse): سرور خارج به ایران وصل می‌شود؛ وقتی ایران نمی‌تواند به بیرون درخواست بفرستد ولی ورودی از بیرون باز است (پورت تانل روی ایران باز باشد). ③ حالت CDN: دامنه را روی CDN بگذار. اگر CDN داخلی است (آروان‌کلود) و به سرور ایران اشاره می‌کند، «سرور خارج وصل می‌شود» را بزن؛ اگر به سرور خارج اشاره می‌کند، «سرور ایران وصل می‌شود». فقط دامنه و پورت را بنویس. اول تانل را ذخیره کن، بعد «تست CDN» را بزن.'],
 ['SNI اسپوف چیست؟','تانل جدا نیست؛ فقط یک پوشش روی WSS / QUIC / CDN است و اسم سایت دیگری را در دست‌دادن TLS می‌نویسد. فقط وقتی کمک می‌کند که فیلتر روی نام SNI تصمیم بگیرد. اگر آی‌پی را ببندند، SNI کمکی نمی‌کند. جعل آی‌پی مبدأ (بستهٔ خام) روی تانل TCP کار نمی‌کند و در پنل نیست.'],
 ['با وایرگارد و بقیه کار می‌کند؟','بله. پورت‌های وایرگارد / آمنزیا / هیستریا۲ را در UDP و TCP تانل بگذار؛ تانل فقط ترافیک را حمل می‌کند و پروتکل VPN عوض نمی‌شود.'],
 ['CDN فرانتینگ چه بود؟','قبلاً (مثل گوگل و آمازون): SNI نام یک سایت مجاز، ولی هدر Host دامنهٔ خودت؛ CDN با Host مسیر می‌داد و فیلتر فقط SNI مجاز را می‌دید. بیشتر CDNهای بزرگ بستند؛ بعضی هنوز می‌پذیرند و باید تست شود. در حالت CDN پنل، SNI و Host جدا نوشته می‌شوند، یعنی همین کار.'],
 ['وقتی اینترنت به‌هم ریخت','دامنه را روی CDN بگذار (WebSocket روشن)، چند آی‌پی لبه بنویس، «تست CDN» را بزن (از سرور پنل، سلامت CDN و مبدأ)، و برای پیدا کردن آی‌پی بازِ یک رنج، «اسکریپت اسکن» را روی سرور ایران اجرا کن.'],
 ['قدم‌به‌قدم با ابرآروان','① در پنل ابرآروان، CDN را برای دامنه روشن کن (رکورد پروکسی‌دار) و رکورد A را به آی‌پی سرور ایران اشاره بده. ② در تنظیمات CDN گزینهٔ WebSocket را فعال کن؛ TLS را روی Full بگذار؛ پروتکل مبدأ HTTP و پورت مبدأ = پورت تانل (پیش‌فرض ۸۰۸۰). ③ اینجا تانل جدید بساز: روش «CDN (لیست سفید)»، حالت «سرور خارج وصل می‌شود (توصیه‌شده)»، Host = دامنهٔ خودت، پورت ۸۰۸۰. پورت ۸۰۸۰/TCP روی سرور ایران باز باشد. ④ تانل را ذخیره کن و «تست CDN» را بزن. ⑤ اختیاری ولی توصیه‌شده: چند SNI داخلی مثل www.aparat.com و www.digikala.com بنویس و «تکه‌تکه کردن دست‌دادن TLS» روشن باشد. ⑥ اگر بعضی آی‌پی‌های لبه بسته‌اند، «اسکریپت اسکن» را روی سرور ایران اجرا کن و آی‌پی‌های باز را در «آدرس‌های لبهٔ CDN» بگذار.'],
 ['وایرگارد پشت چه تانلی؟','دست‌دادن وایرگارد خام خیلی زود توسط DPI شناسایی می‌شود. راه‌حل: پورت UDP وایرگارد (مثلاً 51820) را در لیست UDP یک تانل game (FEC 8:3) یا faketcp بگذار و Endpoint کاربران را آدرس سرور ایران بزن. روی تانل game بستهٔ گمشده با FEC بازسازی می‌شود (بدون تأخیر ارسال مجدد)؛ روی faketcp کل ترافیک شبیه TCP دیده می‌شود و محدودیت UDP اپراتور دور زده می‌شود. AmneziaWG هم اگر امضای WG بسته باشد، همین کار را با پوشش داخلی خودش می‌کند.']
 ]:[
 ['Iran server shows offline?','The panel cannot reach it, or Iran cannot reach abroad (whitelist / white IP). Three ways: (1) a white IP: an inside server that can reach abroad. (2) Reverse mode: the foreign server dials Iran; use it when Iran cannot send requests out but inbound works (open the tunnel port on Iran). (3) CDN mode: put your domain on a CDN. If the CDN (for example ArvanCloud) points to the Iran server, choose “the foreign server connects in”; if it points to the foreign server, choose “the Iran server connects out”. Just type the domain and the port. Save the tunnel first, then press “Test CDN”.'],
 ['What is SNI spoofing?','Not a separate tunnel: a disguise on WSS / QUIC / CDN that puts another site name in the TLS hello. It only helps when the filter decides by SNI name. If the IP itself is blocked it does nothing. Real source-IP spoofing (raw packets) does not work for a TCP tunnel and is not in the panel.'],
 ['Does it work with WireGuard etc.?','Yes. Put the WireGuard / AmneziaWG / Hysteria2 ports in the tunnel TCP and UDP lists; the tunnel only carries the traffic, the VPN protocol stays the same.'],
 ['What was CDN fronting?','Old trick (Google, Amazon): SNI = an allowed site, HTTP Host = your own domain; the CDN routed by Host and the filter saw only the allowed SNI. Big CDNs closed it; some still allow it and it must be tested. In the panel CDN mode SNI and Host are separate, which is exactly this.'],
 ['When everything breaks','Put your domain on a CDN (WebSocket on), list several edge IPs, press “Test CDN” (runs from the panel server: checks CDN and origin), and run the “Scan script” on the Iran server to find open IPs inside a range.'],
 ['Step by step with ArvanCloud','(1) In ArvanCloud turn CDN on for your domain (proxied record) and point the A record at the Iran server IP. (2) In the CDN settings turn WebSocket on; TLS = Full; origin protocol HTTP, origin port = the tunnel port (default 8080). (3) Here: new tunnel, transport “CDN (whitelist)”, mode “the foreign server connects in (recommended)”, Host = your domain, port 8080. Port 8080/TCP must be open on the Iran server. (4) Save the tunnel, then press “Test CDN”. (5) Optional but recommended: write a few domestic SNIs (www.aparat.com, www.digikala.com) and keep “Split the TLS hello” on. (6) If some edge IPs are blocked, run the “Scan script” on the Iran server and put the open ones in “CDN edge addresses”.'],
 ['WireGuard behind which tunnel?','A raw WireGuard handshake is spotted by DPI quickly. The fix: put the WireGuard UDP port (for example 51820) in the UDP list of a game (FEC 8:3) or faketcp tunnel and set the users’ Endpoint to the Iran server address. On game, lost packets are rebuilt by FEC (no retransmit delay); on faketcp the whole flow looks like TCP and operator UDP throttling does not apply. AmneziaWG does the same with its built-in disguise when the WG signature itself is blocked.']
 ];
 return '<details class="box" style="margin-top:10px"><summary><b>'+(fa?'راهنمای SNI اسپوف و CDN':'SNI spoof & CDN guide')+'</b></summary>'+h.map(function(r){return '<small class="muted" style="display:block;margin:7px 0 0"><b>'+r[0]+'</b> '+r[1]+'</small>'}).join('')+'</details>'}
function cdnTools(){var fa=S.lang=='fa';
 return '<div class="nh" style="margin-top:10px"><b>'+(fa?'تست و ابزار':'Test & tools')+'</b><span><button type="button" class="b2 sm" id="tw_ctest">'+(fa?'تست CDN':'Test CDN')+'</button> <button type="button" class="b2 sm" id="tw_cscan">'+(fa?'اسکریپت اسکن':'Scan script')+'</button></span></div>'+
 '<small class="muted" style="display:block;margin-top:4px">'+(fa?'تست از سرور پنل انجام می‌شود و نشان می‌دهد CDN و سرور خروجی درست وصل‌اند. اتصال از داخل ایران را اسکریپت اسکن روی سرور ایران نشان می‌دهد.':'The test runs from the panel server and shows that the CDN and the exit are wired correctly. The scan script run on the Iran server shows what works from inside.')+'</small>'+
 '<div id="tw_ctres" class="list" style="margin-top:6px"></div><div id="tw_scres"></div>'+spGuide()}
function cdnTest(){var b={edges:$('#tw_cdl').value.trim()||$('#tw_chost').value.trim(),host:$('#tw_chost').value.trim(),sni:$('#tw_csni').value,path:$('#tw_pa').value||'/',frag:$('#tw_frag').checked},o=$('#tw_ctres'),me=$('#tw_ctest');
 if(!b.edges.trim()){toast(t('Add at least one CDN edge address'),1);return}
 me.disabled=true;o.innerHTML='<small class="muted">'+t('Testing…')+'</small>';
 api('POST','/api/tunnels/cdntest',b).then(function(r){me.disabled=false;var l=r.results||[];
  o.innerHTML=l.map(function(z){return '<div class="li"><span><b class="ltr">'+esc(z.edge)+'</b><small>'+(z.sni?'SNI '+esc(z.sni)+' · ':'')+N(z.ms)+' ms'+(z.ok?'':' · '+esc(z.error||''))+'</small></span><span>'+(z.ok?'✅':'❌')+'</span></div>'}).join('')||'—'}).catch(function(e){me.disabled=false;o.innerHTML='';fail(e)})}
function cdnScan(){var fa=S.lang=='fa',tp=document.getElementById('scanTpl');if(!tp)return;
 var host=$('#tw_chost').value.trim(),sni=$('#tw_csni').value.trim().split(/[\s,]+/).filter(Boolean).join(' ')||host||'www.aparat.com',
  edges=$('#tw_cdl').value.trim().split(/[\s,]+/).filter(Boolean).map(function(e){return e.split(':')[0]}).join(' ')||'185.143.232.0/24',path=$('#tw_pa').value||'/';
 var sc=tp.textContent.replace(/^\n/,'').split('@@HOST@@').join(host||'tun.example.com').split('@@SNIS@@').join(sni).split('@@EDGES@@').join(edges).split('@@PATH@@').join(path);
 $('#tw_scres').innerHTML='<small class="muted" style="display:block;margin-top:6px">'+(fa?'این را روی سرور ایران (ورودی) اجرا کن: bash scan.sh   یا با رنج دیگر: bash scan.sh 185.143.233.0/24. خروجی OK-WS یعنی آن آی‌پی WebSocket تو را رد کرد؛ REACH یعنی لبهٔ CDN باز است ولی مسیر/Host درست نیست.':'Run this on the Iran (entry) server: bash scan.sh   or with another range: bash scan.sh 185.143.233.0/24. OK-WS means that IP passed your WebSocket; REACH means the CDN edge is open but the path/Host is not right.')+'</small><textarea id="tw_scta" class="ltr" rows="9" style="width:100%;font-size:11px" readonly></textarea><button type="button" class="b2 sm" id="tw_sccp">'+t('Copy')+'</button>';
 $('#tw_scta').value=sc;$('#tw_sccp').onclick=function(){copy($('#tw_scta').value)}}

// ---- smart tunnel: test every transport in BOTH directions between two servers, score them for the
// chosen profile, and apply the best one in the tunnel form. Nothing is created on the servers.
var TS={timer:0,prof:'balanced',ctx:{},j:null};
function tunSmart(o){if(!TN.d)return tunLoad().then(function(){tunSmart(o)});if(o)TS.ctx=o;var c=TS.ctx||{},sv=TN.d.servers||[],remote=sv.filter(function(s){return !s.local});
 if(c.prof)TS.prof=c.prof;
 api('GET','/api/tunnels/probe').then(function(r){if(r.job&&!r.job.finished)return tunSmartRun();
 var opt=function(sel){return srvOptGroups(sv,function(s){return '<option value="'+esc(s.id)+'"'+(s.id==sel?' selected':'')+'>'+esc(s.name+(s.local?' ('+t('panel')+')':''))+'</option>'})},
  po=function(k,l){return '<option value="'+k+'"'+(TS.prof==k?' selected':'')+'>'+l+'</option>'};
 modal(mhead('⚡ '+t('Smart tunnel'))+'<p class="sub"><b>'+t('Find the best transport')+'</b><br>'+t('Before making the tunnel, every transport (TCP, KCP, WS, WSS, QUIC) is tried in both directions between your two servers. It takes about one to two minutes. Each gets a score from 0 to 100 and the best one is suggested with its reason.')+'</p>'+
  '<ul class="sub" style="margin:4px 0 8px;padding-inline-start:18px;line-height:1.7"><li>'+t('Scores follow your profile (gaming, balanced, ultra speed)')+'</li><li>'+t('Tells which ones did not pass and probably why')+'</li><li>'+t('If one direction is closed it says so and suggests the other')+'</li><li>'+t('One click applies it in making or editing a tunnel')+'</li><li>'+t('No tunnel is made and nothing changes on the servers')+'</li></ul>'+
  (sv.length<2?'<div class="warnbox">'+t('First add your entry server in the “Tunnel servers” menu.')+'</div>':'')+
  '<div class="g2"><div><label class="f">'+t('Entry (users connect here)')+'</label><select id="ts_en">'+opt(c.entry||(remote[0]||{}).id)+'</select></div><div><label class="f">'+t('Exit (traffic leaves here)')+'</label><select id="ts_ex">'+opt(c.exit||'local')+'</select></div></div>'+
  '<div class="g2"><div><label class="f">'+t('Profile')+'</label><select id="ts_pf">'+po('balanced',t('Balanced'))+po('speed',t('Most speed'))+po('gaming',t('Gaming (low ping)'))+'</select></div><div><label class="f">'+t('Test ports (first of the range)')+'</label><input id="ts_pt" type="number" class="ltr" value="3990"></div></div>'+
  '<label class="f" style="margin-top:10px">'+t('Which methods to test')+'</label>'+
  '<div class="tschk" id="ts_tr">'+TS_TR.map(function(x){return '<label class="chk sm"><input type="checkbox" value="'+x[0]+'" checked><span>'+x[1]+'</span></label>'}).join('')+'</div>'+
  '<label class="chk sm" style="margin-top:4px"><input type="checkbox" id="ts_base" checked><span><b>'+t('Raw ping (no tunnel)')+'</b> · '+t('the plain ping between the two servers, as a reference')+'</span></label>'+
  '<p class="muted" id="ts_note" style="font-size:12px;margin:8px 0 0"></p>'+
  (r.job&&r.job.finished?'<button class="b2" style="width:100%;margin-top:10px" onclick="tunSmartRun()">'+t('Show the last result')+'</button>':'')+
  '<button class="btn" style="width:100%;margin-top:10px" id="ts_go">'+t('Start the test')+'</button>');
 var note=function(){var p=+$('#ts_pt').value||3990,n=document.querySelectorAll('#ts_tr input:checked').length||TS_TR.length;
  $('#ts_note').textContent=t('Takes about a minute. Ports')+' '+N(p)+'–'+N(p+n-1)+' '+t('on the entry')+' · '+N(p+n)+'–'+N(p+2*n-1)+' '+t('on the exit')+' (TCP + UDP) '+t('must be open in the cloud firewall')+'.'};
 ['ts_pt'].forEach(function(k){$('#'+k).onchange=note;$('#'+k).oninput=note});$('#ts_tr').onchange=note;note();
 $('#ts_pf').onchange=function(){TS.prof=this.value};
 $('#ts_go').onclick=function(){var me=this;me.disabled=true;TS.prof=$('#ts_pf').value;var trs=[].map.call(document.querySelectorAll('#ts_tr input:checked'),function(x){return x.value});if(!trs.length){me.disabled=false;return toast(t('Pick at least one method'),1)}api('POST','/api/tunnels/probe',{entry:$('#ts_en').value,exit:$('#ts_ex').value,port:+$('#ts_pt').value||3990,transports:trs,baseline:$('#ts_base').checked}).then(function(r){if(r&&r.note)toast(t('Not tested, an agent is too old (update it first)')+': '+(r.skipped||[]).join(', '),1);tunSmartRun()}).catch(function(e){me.disabled=false;fail(e)})}}).catch(fail)}
function tunSmartRun(){modal(mhead('⚡ '+t('Smart tunnel'))+'<div id="ts_box"><span class="muted">'+t('Loading…')+'</span></div>');clearInterval(TS.timer);
 $('#ts_box').onclick=function(e){var b=e.target.closest('[data-use],[data-prof],[data-ts]');if(!b)return;
  if(b.dataset.prof){TS.prof=b.dataset.prof;if(TS.j)tunSmartDraw(TS.j)}
  else if(b.dataset.use){var u=b.dataset.use.split('|');tunSmartUse(u[0],u[1])}
  else if(b.dataset.ts=='again')tunSmart();
  else if(b.dataset.ts=='stop')api('DELETE','/api/tunnels/probe').then(function(){closeModal()})};
 var go=function(){if(!$('#ts_box')){clearInterval(TS.timer);return}api('GET','/api/tunnels/probe').then(function(r){var j=r.job;if(!j||!$('#ts_box'))return;TS.j=j;tunSmartDraw(j);if(j.finished)clearInterval(TS.timer)}).catch(function(){})};
 go();TS.timer=setInterval(go,2000)}
function tunOk(r){return !!(r&&r.done&&!r.failed&&r.down_mbps>0)}
function tunScore(r,P){return tunOk(r)&&r.scores?(r.scores[P]||0):0}
// the likely reason a transport did not pass (or passes badly), from what the other transports did
function tunWhy(r,j){var L=j.results||[],same=L.filter(function(z){return z.mode==r.mode&&z.transport!=r.transport}),
 okTr=function(n){return same.some(function(z){return z.transport==n&&tunOk(z)})},
 anyTcp=same.some(function(z){return z.transport!='quic'&&z.transport!='kcp'&&z.transport!='hq'&&tunOk(z)}),udpTr=r.transport=='quic'||r.transport=='kcp'||r.transport=='hq';
 if(!tunOk(r)){
  if(udpTr)return anyTcp?t('UDP is probably blocked on this route: the TCP transports pass'):t('Nothing passes in this direction');
  if(r.transport=='wss'&&okTr('ws'))return t('TLS looks filtered: plain WebSocket passes but WSS does not');
  if(r.transport=='ws'&&okTr('wss'))return t('Plain HTTP looks filtered: WSS passes but WebSocket does not');
  if(r.transport=='h2'&&okTr('wss'))return t('HTTP/2 does not get through (or the server is older than 2.9): WSS passes but H2 does not');
  if(!anyTcp)return t('The port is closed or this direction is blocked: check the cloud firewall');
  return t('This transport is filtered on the route while others pass')}
 if(r.udp_error||(r.udp_loss!=null&&r.udp_loss>=50))return t('TCP works but UDP does not pass well: WireGuard / Hysteria2 may suffer');
 return ''}
function tunDirName(m){return m=='direct'?t('Entry → exit (direct)'):t('Exit → entry (reverse, recommended)')}
function tunSmartDraw(j){var P=TS.prof||'balanced',stg={starting:t('Starting…'),connecting:t('Connecting…'),waiting:t('In line…'),testing:t('Testing…')},
 pct=Math.min(100,Math.round(j.elapsed*100/60)),L=j.results||[],pick=function(m){var c=L.filter(function(r){return(!m||r.mode==m)&&tunOk(r)});
  c.sort(function(a,b){return tunScore(b,P)-tunScore(a,P)||(b.down_mbps||0)-(a.down_mbps||0)});return c[0]||null},
 best=pick(),bR=pick('reverse'),bD=pick('direct'),
 row=function(r){var ok=tunOk(r),isb=best&&r===best&&j.finished,cls=isb?'best':ok?'':r.done?'bad':'run',
  st=!r.done?'<span class="muted">'+(stg[r.stage]||stg.starting)+'</span>':r.failed?'<span class="r">'+esc(t('No connection'))+'</span>':'',
  nums=r.done&&!r.failed?'<span class="ltr">'+(r.ping_ms!=null?N(r.ping_ms)+' ms':'—')+'</span><span class="ltr">↓ '+(r.down_mbps!=null?N(r.down_mbps):'—')+'</span><span class="ltr">↑ '+(r.up_mbps!=null?N(r.up_mbps):'—')+'</span><span class="ltr">'+(r.udp_loss!=null?N(r.udp_loss)+'%':'✕')+'</span>':'',
  why=r.done?tunWhy(r,j):'',raw=r.done&&!ok?(r.error||r.tcp_error||r.last_error||''):'';
  return '<div class="tsr '+cls+'"><b>'+(isb?'🏆 ':'')+tunTr(r.transport)+'</b>'+(st||nums)+'<em class="ltr">'+(ok?N(tunScore(r,P)):'')+'</em></div>'+
   (why?'<small class="tse">'+esc(why)+'</small>':'')+(raw?'<small class="tse ltr">'+esc(raw)+'</small>':'')};
 var base=L.filter(function(r){return r.baseline})[0];
 var baseRow=base?'<div class="tsbase"><b>📡 '+t('Raw ping (no tunnel)')+'</b>'+(!base.done?'<span class="muted">'+(stg[base.stage]||stg.testing)+'</span>':base.failed?'<span class="r">'+esc(base.error||t('No answer'))+'</span>':'<span class="ltr">'+(base.ping_ms!=null?N(base.ping_ms)+' ms':'—')+(base.loss?' · '+N(base.loss)+'% '+t('loss'):'')+'</span>')+'</div>'+(base&&base.done&&!base.failed?'<small class="tse">'+t('This is the base ping of the route; a good tunnel stays close to it.')+'</small>':''):'';
 var h='<p class="sub">'+esc(tunSrv(j.entry).name)+' ⇄ '+esc(tunSrv(j.exit).name)+'</p>'+baseRow+
  '<div class="seg" style="margin:6px 0">'+[['balanced',t('Balanced')],['speed',t('Most speed')],['gaming',t('Gaming (low ping)')]].map(function(o){return '<button data-prof="'+o[0]+'" class="'+(P==o[0]?'on':'')+'">'+o[1]+'</button>'}).join('')+'</div>'+
  (j.finished?'':'<div class="tsbar"><i style="width:'+pct+'%"></i></div>');
 ['reverse','direct'].forEach(function(m){var rs=L.filter(function(r){return r.mode==m&&!r.baseline}),n=rs.filter(tunOk).length,done=rs.every(function(r){return r.done});
  h+='<div class="nh" style="margin-top:12px"><b>'+tunDirName(m)+'</b><small class="muted">'+(done||j.finished?N(n)+' / '+N(rs.length)+' '+t('passed'):'')+'</small></div>'+
   '<div class="tsh"><b>'+t('Transport')+'</b><span>'+t('Ping')+'</span><span>↓ Mbps</span><span>↑ Mbps</span><span>'+t('UDP loss')+'</span><em>'+t('Score')+'</em></div>'+rs.map(row).join('')});
 if(j.finished){var nR=L.filter(function(r){return r.mode=='reverse'&&tunOk(r)}).length,nD=L.filter(function(r){return r.mode=='direct'&&tunOk(r)}).length;
  if(!best)h+='<div class="warnbox">'+t('No transport could connect in either direction. Open the test ports in the cloud firewall of both servers and try again. If only GRE passes between the two servers, add or edit the server with the “Only GRE passes” option.')+'</div>';
  else{
   if(!nR||!nD)h+='<div class="warnbox">'+(!nR?t('The reverse direction (exit → entry) is closed: the entry cannot be reached from the exit. Use the direct direction.'):t('The direct direction (entry → exit) is closed: the entry cannot dial the exit. Use the reverse direction.'))+'</div>';
   var d=function(r){return r.mode=='direct'?t('direct'):t('reverse')};
   h+='<div class="tsbest">🏆 '+t('Best for this route')+': <b>'+tunTr(best.transport)+'</b> · '+d(best)+' · <span class="ltr">'+N(tunScore(best,P))+' / 100</span><br><small>'+
    (best.ping_ms!=null?N(best.ping_ms)+' ms · ':'')+'↓ '+N(best.down_mbps||0)+' · ↑ '+N(best.up_mbps||0)+' Mbps · UDP '+(best.udp_loss!=null?N(best.udp_loss)+'%':'✕')+'</small></div>'+
    '<button class="btn" style="width:100%;margin-top:10px" data-use="'+best.mode+'|'+best.transport+'">'+(TS.ctx&&TS.ctx.apply?t('Apply to the tunnel'):t('Build the tunnel with'))+' '+tunTr(best.transport)+' ('+d(best)+')</button>';
   var other=best.mode=='direct'?bR:bD;
   if(other)h+='<button class="b2" style="width:100%;margin-top:8px" data-use="'+other.mode+'|'+other.transport+'">'+t('Use')+' '+tunTr(other.transport)+' ('+d(other)+') · '+N(tunScore(other,P))+'</button>'}
  h+='<button class="b2" style="width:100%;margin-top:8px" data-ts="again">'+t('Test again')+'</button>'}
 else h+='<button class="b2 bd" style="width:100%;margin-top:10px" data-ts="stop">'+t('Stop the test')+'</button>';
 $('#ts_box').innerHTML=h}
function tunSmartUse(mode,tr){api('GET','/api/tunnels/probe').then(function(r){var j=r.job||{},c=TS.ctx||{};closeModal();
 if(c.apply)tunEdit(c.apply.id,Object.assign({},c.apply.snap,{entry:j.entry,exit:j.exit,mode:mode,transport:tr}));
 else tunEdit(null,{entry:j.entry,exit:j.exit,mode:mode,transport:tr});TS.ctx={}}).catch(fail)}

// ---- dashboard card
function tunDashCard(){return '<div class="card" id="tdc"><div class="nh"><div><h3>'+ic('tunnel',16)+' '+t('Tunnels')+'</h3><p class="sub" id="tdc_s">…</p></div><a class="b2 sm" href="#tunnels">'+t('Manage')+'</a></div><div id="tdc_m"></div></div>'}
function tunDashWire(){if(!$('#tdc'))return;var go=function(){tunLoad().then(function(d){if(!$('#tdc'))return;var tl=d.tunnels||[],up=tl.filter(function(x){return x.state=='up'}).length;
  $('#tdc_s').textContent=tl.length?(up==tl.length?t('All tunnels connected'):N(tl.length-up)+' '+t('tunnel(s) not connected'))+' · '+N(up)+' / '+N(tl.length):t('No tunnels yet');
  var mh=tunMap(d,true),mb=$('#tdc_m');if(mb&&(!mb.querySelector('canvas')||mh.indexOf('<canvas')<0))mb.innerHTML=mh}).catch(function(){})};go();clearInterval(S.timer4);S.timer4=setInterval(function(){if(document.visibilityState=='visible')go()},5000)}


// ==================================================================== menu and sections
// the shell: a short menu of sections; a section with several pages shows them as tabs at the top.
// Also here: country flags, the AI writer of the smart channel, moving the panel to a new server.
(function(){
'use strict';

// ---------------------------------------------------------------- sections and menu
// [section key, label, icon, [[page, sub page, tab label], ...], menu group]
var SECS=[
 ['dash','Dashboard','dash',[['dash','','Dashboard']],'Home'],
 ['users','Users','users',[['users','','Users']],'Customers'],
 ['bot','Sales bot','bot',[['bot','','Sales bot']],'Customers'],
 ['emergency','Emergency chat','sos',[['emergency','','Emergency chat']],'Customers'],
 ['nodes','Servers','nodes',[['nodes','','Servers']],'Servers & network'],
 ['netsec','Tunnels','tunnel',[['tunnels','','Tunnels']],'Servers & network'],
 ['ports','Ports','ports',[['ports','','Ports']],'Servers & network'],
 ['vpnsec','Cores','cores',[['vpn','','Overview'],['kmix','','KANKI MIX'],['kgame','','MIX+\u200e'],['xray','overview','Xray'],['wg','','WireGuard'],['awg','','AmneziaWG'],['hy2','','Hysteria2'],['antidpi','','Anti-DPI'],['dns','','Kanki DNS']],'Services'],
 ['traffic','Traffic & stats','traffic',[['traffic','','Traffic & stats']],'Reports'],
 ['syssec','System','settings',[['settings','','Settings'],['security','','Security'],['backup','','Backup']],'System']];
function secOf(p){for(var i=0;i<SECS.length;i++)if(SECS[i][3].some(function(x){return x[0]==p}))return SECS[i];return SECS[0]}
window.V37={secOf:secOf,SECS:SECS,watchPg:watchPg,drawSecTabs:drawSecTabs};


// the tabs of the section, always the first thing of the page
function secTabsHtml(p){var s=secOf(p);if(s[3].length<2)return '';
 return '<div class="sectabs" id="sectabs"><div class="sth2"><span class="sti">'+ic(s[2],18)+'</span><b>'+t(s[1])+'</b></div><div class="stl">'+
  s[3].map(function(x){return '<a href="#'+x[0]+(x[1]?'/'+x[1]:'')+'" class="'+(x[0]==p?'on':'')+'">'+t(x[2])+'</a>'}).join('')+'</div></div>'}
function drawSecTabs(p){var pg=$('#pg');if(!pg)return;var old=$('#sectabs'),h=secTabsHtml(p);
 if(!h){if(old)old.remove();return}
 if(old&&old.parentNode==pg&&pg.firstChild==old&&old.dataset.p==p)return;
 if(old)old.remove();var d=document.createElement('div');d.innerHTML=h;var el=d.firstChild;el.dataset.p=p;pg.insertBefore(el,pg.firstChild)}
// a page that redraws itself (innerHTML) loses the tabs: put them back
var mo=null;
function watchPg(){var pg=$('#pg');if(!pg||pg._v37)return;pg._v37=1;if(mo)mo.disconnect();
 mo=new MutationObserver(function(){if(S&&S.page&&secOf(S.page)[3].length>1&&(!$('#sectabs')||pg.firstChild!=$('#sectabs')))drawSecTabs(S.page)});
 mo.observe(pg,{childList:true})}

// ---------------------------------------------------------------- flags
function flag(cc){cc=String(cc||'').toUpperCase();if(!/^[A-Z]{2}$/.test(cc))return '<span class="flg nf" title="?">🌐</span>';
 return '<span class="flg" title="'+cc+'">'+String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65,0x1F1E6+cc.charCodeAt(1)-65)+'</span>'}
window.flagOf=flag;


// ---------------------------------------------------------------- the look

})();

// ==================================================================== phone bar, night/day
// the look: night (pure black) and day (pure white) from one button in the top bar, the menu in
// groups, and on phones a bar of every section at the bottom.
(function(){
'use strict';
var V=V37;

// ---------------------------------------------------------------- menu: groups of what belongs together
// [section key, label, icon, [[page, sub page, tab label], ...], group]
var DNSSEC=['dnssec','Kanki DNS','dns',[['dns','','Kanki DNS']],'Services'];
function secBy(k){if(k=='dnssec')return DNSSEC;for(var i=0;i<V.SECS.length;i++)if(V.SECS[i][0]==k)return V.SECS[i];return V.SECS[0]}
window.grpOf=function(p){return V.secOf(p)[4]||''};


// phones: every section in the bottom bar, swiped sideways, in this order from the right
var BAR=[['dash','Home'],['users','Users'],['nodes','Servers'],['netsec','Tunnels'],['vpnsec','VPN services'],['dnssec','Kanki DNS'],['bot','Sales bot'],['emergency','Emergency chat'],['ports','Ports'],['traffic','Traffic & stats'],['syssec','System']];
window.navBar=function(){
 return '<div class="mbar k38bar k39bar" id="mbar">'+BAR.map(function(b){var s=secBy(b[0]),f=s[3][0];
  return '<a href="#'+f[0]+'" data-p="'+f[0]+'" data-sec="'+s[0]+'">'+ic(s[2],21)+'<span>'+t(b[1])+'</span></a>'}).join('')+'</div>'+
  '<div class="k38scrim" id="k38scrim" onclick="k38More(0)"></div><div class="msheet k38sheet" id="msheet"></div>'};


// ---------------------------------------------------------------- night / day in the top bar
// The top bar has only one button: night or day. The panel's colors are chosen in Settings ›
// Look, not in the bar.
function drawLooks(){var b=$('#thm');if(!b)return;var night=(S.theme||'dark')!='light';
 b.innerHTML=ic(night?'sun38':'moon',17)+'<span>'+t(night?'Day':'Night')+'</span>';b.title=t(night?'Day':'Night');b.setAttribute('aria-label',b.title);b.classList.add('k38dn')}
V.drawLooks=drawLooks;


// ---------------------------------------------------------------- the look
})();

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

function row(s){var n=s.node,a=s.agent,on=online(s),h=n?nHealthOf(n):null,col=!on?'r':h&&h.c=='r'?'y':h?h.c:'g';
 var tn=s.tunnel||{},tags=(s.local?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+(n&&!n.enabled&&!s.local?'<span class="kxc-tag">'+t('relay')+'</span>':'')+
  // tunnel: its configs point at the Iran entry; + tunnel: a second config of every protocol through its tunnel domain
  (tn.main_via=='tunnel'?'<span class="kxc-tag tun">'+t('tunnel')+'</span>':tn.on&&tn.uses?'<span class="kxc-tag tun">+ '+t('tunnel')+'</span>':'');
 var head='<span class="dot '+col+'"></span>'+fl(s.cc)+'<b>'+esc(s.name)+'</b>'+tags+'<span class="sp"></span>'+
  (on?'':'<span class="kxr-st r">'+t('Not connected')+'</span>')+'<small class="kxr-ip ltr">'+esc(srvIp(s))+'</small>';
 return accRow('srv',s.key,head,function(){return srvBody(s)})}

// the first entries (and their addresses) of the tunnels that bring this server's ports: where its
// users can connect instead of its own address (Iran → Turkey → here: Iran)
function entriesOf(s){var sid=s.agent?s.agent.id:(s.local?'local':''),tl=((TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.enabled!==false&&x.kind!='awg'}),out=[];
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
 if(!s.local)acts.push('<button class="b2 sm bd" onclick="srvDel(\''+k+'\')">'+ic('trash',13)+' '+t('Delete server')+'</button>');
 h+='<div class="kxacts">'+acts.join('')+'</div>';
 setTimeout(function(){$$('#sx_loc button').forEach(function(b){b.onclick=function(){$$('#sx_loc button').forEach(function(z){z.classList.toggle('on',z==b)});var bb=b.closest('.kxr-b');if(bb)bb.dataset.dirty='1'}})},0);
 return h}

// The tunnel of a server: on/off, the Iran address (chips: the first server of each tunnel that ends here)
// and the name; below, each port with the one it gets on that address
function tunBox(s){var tn=s.tunnel||{},n=s.node,ents=entriesOf(s),host=tn.on?(tn.host||tn.uses||''):'';
 var ep=n&&n.endpoint_mode!='panel'?(n.endpoint||''):'',viaIr=ep&&ents.some(function(e){return e.host==ep});
 var rows=tn.on&&tn.uses?(tn.ports||[]).map(function(p){return '<div class="kxtun-p"><b>'+esc(p.proto)+'</b><span class="kxtun-m ltr">'+esc(tn.uses)+':'+p.via+' → '+(p.tcp?'TCP':'UDP')+' '+p.port+'</span></div>'}).join(''):'';
 return '<div class="kxr-sec">'+t('Tunnel domain')+'</div>'+
  '<p class="muted" style="font-size:11.5px;margin:0 2px 6px">'+t('If this server has a tunnel, or will have one, write your Iran server\'s domain here. Every protocol then also gets a second config through it, made by itself.')+' '+t('WireGuard comes only this way.')+'</p>'+
  '<div class="kxf"><div class="wide"><input id="sx_th" class="ltr" value="'+esc(host)+'" placeholder="ir.example.com">'+
   (ents.length?'<div class="kxchips">'+ents.map(function(e){return '<button type="button" class="'+(host==e.host?'on':'')+'" onclick="$(\'#sx_th\').value=\''+esc(e.host)+'\';$(\'#sx_th\').dispatchEvent(new Event(\'input\',{bubbles:true}))">'+esc(e.name)+' · <span class="ltr">'+esc(e.host)+'</span></button>'}).join('')+'</div>':'')+'</div>'+
  '<div class="wide"><label class="f">'+t('Name of these configs in the app (optional)')+'</label><input id="sx_tn" value="'+esc(tn.name||'')+'" maxlength="40" placeholder="'+esc(s.name+' (تانل)')+'"></div></div>'+
  (viaIr?'<p class="kxtun-w">'+t('Users connect to the Iran address already, so the main configs go through the tunnel too. For direct configs set it to this server\'s own address.')+'</p>':'')+
  (rows?'<div class="kxtun"><div class="muted" style="font-size:11px;margin-bottom:4px">'+t('Ports through the tunnel')+'</div>'+rows+'</div>':'')}

// Save of the open server: its name, place and address (the server), who gets it and where users connect (its VPN)
window.srvSave=function(key){var s=find(key);if(!s)return;var n=s.node,a=s.agent,jobs=[];
 var loc=(($$('#sx_loc button.on')[0]||{}).dataset||{}).l||(isIr(s)?'iran':'abroad');
 var b={name:$('#sx_nm').value.trim(),loc:loc};if($('#sx_ad'))b.addr=$('#sx_ad').value.trim();
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
  '<p class="muted" style="font-size:11px;margin:4px 2px 0">'+t('If this server has a tunnel, or will have one, write your Iran server\'s domain here. Every protocol then also gets a second config through it, made by itself.')+'</p></div>'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="sa_vpn">'+t('Serve VPN users on this server')+'</label>'+
  '<button class="btn" style="width:100%;margin-top:12px" id="sa_go">'+t('Create command')+'</button></div><div id="sa_out"></div>','wide');
 var setLoc=function(l){loc=l;$$('#sa_loc button').forEach(function(b){b.classList.toggle('on',b.dataset.l==l)});$('#sa_vpn').checked=l!='iran';$('#sa_tunw').style.display=l=='iran'?'none':''};
 $$('#sa_loc button').forEach(function(b){b.onclick=function(){setLoc(b.dataset.l)}});setLoc(loc);
 $('#sa_go').onclick=function(){var me=this;me.disabled=true;
  api('POST','/api/servers',{name:$('#sa_nm').value,loc:loc,domain:$('#sa_dm').value,vpn:$('#sa_vpn').checked,tunnel_host:loc=='iran'?'':$('#sa_tun').value.trim()}).then(function(r){
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

// ==================================================================== multi-location routes
// multi-location tunnels: a route is several servers in a row (Iran → Turkey → Germany). Users connect
// to the first one, the traffic goes through each next one and leaves from the last. Every hop is a
// tunnel of its own with its own transport, made, tested, changed and deleted together; the ports
// carried are the same on every hop, so the configs of the last server work through the first one.
(function(){
'use strict';


// ---------------------------------------------------------------- ports of a server, KANKI MIX too
window.tunNodePorts=function(n){var i=(n&&n.info)||{},tcp=[],udp=[],add=function(l,v){v=parseInt(v,10);if(v>0&&v<65536&&l.indexOf(v)<0)l.push(v)};
 [i.wg_port,i.awg_port,i.hy2_port,i.kmix_port,(i.kc_ports||{}).game].forEach(function(v){add(udp,v)});return {tcp:tcp,udp:udp}};

// ---------------------------------------------------------------- data
function tl(){return (TN.d&&TN.d.tunnels)||[]}
function hopsOf(chain){return tl().filter(function(x){return x.chain==chain}).sort(function(a,b){return (a.hop||0)-(b.hop||0)})}
function sname(id){return tunSrv(id).name}
function uid(){var s='abcdefghijkmnpqrstuvwxyz23456789',r='';for(var i=0;i<8;i++)r+=s.charAt(Math.floor(Math.random()*s.length));return r}
var TRS=[['Over UDP (fast, games)',['game','kcp','quic','hq']],['Over TCP (steady)',['tcpmux','wss','ws','tcp']],['Advanced (hardest to block)',['dual','h2','faketcp']]];
function trOpts(sel){return TRS.map(function(g){return '<optgroup label="'+esc(t(g[0]))+'">'+g[1].map(function(k){return '<option value="'+k+'"'+(k==sel?' selected':'')+'>'+esc(tunTr(k))+'</option>'}).join('')+'</optgroup>'}).join('')+
 (TRS.some(function(g){return g[1].indexOf(sel)>=0})||!sel?'':'<option value="'+esc(sel)+'" selected>'+esc(tunTr(sel))+'</option>')}

// ---------------------------------------------------------------- the list: the hops of a route are one card
window.routeCardOf=function(x){var hs=hopsOf(x.chain);if(hs.length&&hs[0].id!=x.id)return '';return routeCard(hs)};
function routeCard(hs){var first=hs[0],name=first.chain_name||first.name,states=hs.map(function(x){return x.state}),
 all=states.every(function(s){return s=='up'}),any=states.some(function(s){return s=='up'}),st=all?'up':!hs.some(function(x){return x.enabled})?'off':any?'partial':'down',col=tunCol(st),
 ping=hs.reduce(function(a,x){var r=(x.entry_status||{}).rtt_ms;return a==null||!r?null:a+r},0),ch=esc(first.chain);
 var line='<span class="rt-n">'+fl(first.entry)+esc(sname(first.entry))+'</span>';
 hs.forEach(function(x){var r=(x.entry_status||{}).rtt_ms;line+='<span class="rt-l" style="--c:'+tunCol(x.state)+'"><span>'+esc(tunTr(x.transport))+'</span><i></i><span class="ltr">'+(r?N(r)+' ms':tunStateTxt(x.state))+'</span></span><span class="rt-n">'+fl(x.exit)+esc(sname(x.exit))+'</span>'});
 var ports=[];if(first.tcp&&first.tcp.length)ports.push('TCP '+first.tcp.join(', '));if(first.udp&&first.udp.length)ports.push('UDP '+first.udp.join(', '));
 var err=hs.map(function(x){var e=(x.entry_status||{}).error||(x.exit_status||{}).error;return e&&x.state!='up'?sname(x.entry)+' → '+sname(x.exit)+': '+e:''}).filter(Boolean);
 return '<div class="card tcard rtc" style="border-inline-start:3px solid '+col+'"><div class="row" style="justify-content:space-between;align-items:flex-start;gap:8px">'+
  '<div style="min-width:0"><b>'+esc(name)+'</b><span class="rt-badge">⛓ '+t('Multi-location')+' · '+N(hs.length)+' '+t('Hops')+'</span><div class="rt-line">'+line+'</div></div>'+
  '<div class="row" style="gap:8px;flex-wrap:nowrap"><span class="tst" style="color:'+col+';border-color:'+col+'"><i style="background:'+col+'"></i>'+tunStateTxt(st)+'</span></div></div>'+
  '<div class="tgrid"><div><small>'+t('Total ping')+'</small><b class="ltr">'+(ping?N(ping)+' ms':'—')+'</b></div><div><small>'+t('Hops')+'</small><b>'+N(hs.filter(function(x){return x.state=='up'}).length)+' / '+N(hs.length)+'</b></div>'+
  '<div><small>'+t('Traffic')+'</small><b class="ltr">↑'+bytes((first.entry_status||{}).tx_bytes||0)+' ↓'+bytes((first.entry_status||{}).rx_bytes||0)+'</b></div></div>'+
  '<p class="muted ltr tmeta">'+esc(ports.join(' · '))+'</p>'+
  '<div class="rt-hops">'+hs.map(function(x){return '<div class="rt-h"><span class="dot" style="background:'+tunCol(x.state)+'"></span><b>'+esc(sname(x.entry))+' → '+esc(sname(x.exit))+'</b><small class="muted ltr">'+esc(tunTr(x.transport))+' · '+t('port')+' '+N(x.port)+'</small>'+
   '<button class="ib" title="'+esc(t('Edit hop'))+'" onclick="tunEdit(\''+esc(x.id)+'\')">'+ic('edit',14)+'</button></div>'}).join('')+'</div>'+
  (err.length?'<div class="warnbox ltr" style="margin:6px 0 0">'+err.map(esc).join('<br>')+'</div>':'')+
  '<div class="g4" style="margin-top:10px;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px">'+
  '<button class="b2" onclick="routeEdit(\''+ch+'\')">'+ic('edit',15)+' '+t('Edit')+'</button>'+
  '<button class="b2" onclick="routeAct(\''+ch+'\',\'restart\')">'+ic('refresh',15)+' '+t('Reconnect all')+'</button>'+
  '<button class="b2" onclick="routeAct(\''+ch+'\',\''+(hs.some(function(x){return x.enabled})?'disable':'enable')+'\')">'+t(hs.some(function(x){return x.enabled})?'Pause':'Resume')+'</button>'+
  '<button class="b2 bd" onclick="routeDel(\''+ch+'\')">'+ic('trash',15)+' '+t('Delete')+'</button></div></div>'}
function fl(sid){var s=tunSrv(sid);return s&&s.cc?flagOf(s.cc):''}
window.routeAct=function(ch,a){var hs=hopsOf(ch);Promise.all(hs.map(function(x){return api('POST','/api/tunnels/'+x.id+'/'+a)})).then(function(){toast(a=='restart'?t('The tunnel reconnects in a few seconds'):t('Done'));tunRefresh()}).catch(fail)};
window.routeDel=function(ch){if(!confirm(t('Delete the whole route? Every hop stops and its ports are closed.')))return;var hs=hopsOf(ch);
 Promise.all(hs.map(function(x){return api('DELETE','/api/tunnels/'+x.id)})).then(function(){toast(t('Done'));tunRefresh()}).catch(fail)};


// ---------------------------------------------------------------- make / edit a route
var R=null;
window.routeEdit=function(ch){var go=function(){Promise.all([api('GET','/api/servers').catch(function(){return null}),api('GET','/api/xray').catch(function(){return null})]).then(function(r){routeOpen(ch,r[0],r[1])})};
 if(!window.TN||!TN.d)return tunLoad().then(go);go()};
function routeOpen(ch,srvs,xr){var sv=TN.d.servers||[],remote=sv.filter(function(s){return !s.local}),hs=ch?hopsOf(ch):[];
 R={chain:ch||'',srvs:srvs,xr:xr,hops:[],stops:[],name:'',use:!ch};
 if(hs.length){R.name=hs[0].chain_name||hs[0].name;R.stops=[hs[0].entry].concat(hs.map(function(x){return x.exit}));
  R.hops=hs.map(function(x){return {id:x.id,transport:x.transport,mode:x.mode||'reverse',port:x.port,prof:x.conns==8?'speed':x.conns==2?'gaming':'balanced',fec:x.fec,dup:x.dup}});
  R.tcp=(hs[0].tcp||[]).join(', ');R.udp=(hs[0].udp||[]).join(', ')}
 else{var ir=sv.filter(function(s){return srvLocOf(s)=='iran'}),ab=sv.filter(function(s){return srvLocOf(s)!='iran'});
  // first an Iran server, then an abroad one to pass through, the last abroad one as the exit
  ab=ab.filter(function(s){return !s.local});
  R.stops=[(ir[0]||remote[0]||{}).id||'',ab.length>1?ab[0].id:'',(ab[ab.length-1]||{}).id||'local'];
  R.hops=[{},{}];R.tcp='';R.udp=''}
 R.hops.forEach(function(h){h.transport=h.transport||'kcp';h.mode=h.mode||'reverse';h.prof=h.prof||'balanced'});
 modal(mhead('⛓ '+t('Multi-location tunnel'))+'<p class="sub" style="margin:0 0 8px">'+t('Users connect to the first server; the traffic goes through each next server and leaves from the last. Every hop is a tunnel of its own with its own transport.')+'</p>'+
  '<label class="f">'+t('Route name')+'</label><input id="rt_nm" value="'+esc(R.name)+'" placeholder="Iran → Turkey → Germany" maxlength="40">'+
  '<div class="rt-path" id="rt_path"></div><button type="button" class="rt-add" id="rt_add">+ '+t('Add a stop')+'</button>'+
  '<div class="nh" style="margin-top:14px"><b>'+t('Ports to carry')+'</b><button class="b2 sm" id="rt_vpn">'+ic('ports',14)+' <span id="rt_vpnl"></span></button></div>'+
  '<small class="muted" style="display:block;margin-bottom:6px">'+t('The same ports on every hop: users reach them on the first server and land on the same ports of the last one.')+'</small>'+
  '<div class="g2"><div><label class="f">TCP</label><input id="rt_tcp" class="ltr" value="'+esc(R.tcp)+'" placeholder="443, 2053"></div><div><label class="f">UDP</label><input id="rt_udp" class="ltr" value="'+esc(R.udp)+'" placeholder="51820, 51821, 8443, 4000"></div></div>'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="rt_use"'+(R.use?' checked':'')+'><span><b>'+t('Users of the last server connect through the first one')+'</b><small>'+t('WireGuard, AmneziaWG and Hysteria2 configs of the last server get the address of the first server; KANKI MIX gets its second config through the route by itself.')+'</small></span></label>'+
  '<div class="g2" style="margin-top:14px"><button class="b2" id="rt_test">⚡ '+t('Test every hop')+'</button><button class="btn" id="rt_go">'+t(ch?'Save the route':'Make the route')+'</button></div>','wide');
 drawPath();
 $('#rt_add').onclick=function(){readForm();R.stops.splice(R.stops.length-1,0,'');R.hops.push({transport:'tcpmux',mode:'reverse',prof:'balanced'});drawPath()};
 $('#rt_vpn').onclick=function(){fillPorts(true)};
 $('#rt_test').onclick=function(){readForm();testAll()};
 $('#rt_go').onclick=function(){save(this)};
 if(!ch)fillPorts(false)}
function srvLocOf(s){return srvLoc(s)}
function srvOpts(sel){var sv=TN.d.servers||[];return '<option value="">—</option>'+srvOptGroups(sv,function(s){return '<option value="'+esc(s.id)+'"'+(s.id==sel?' selected':'')+'>'+esc(s.name+(s.local?' ('+t('panel')+')':''))+'</option>'})}
function drawPath(){var el=$('#rt_path');if(!el)return;var n=R.stops.length,h='';
 R.stops.forEach(function(sid,i){
  h+='<div class="rt-stop"><i>'+N(i+1)+'</i><select class="rt-s" data-i="'+i+'">'+srvOpts(sid)+'</select><small>'+t(i==0?'Users connect here':i==n-1?'Traffic leaves here':'Passes through')+'</small>'+
   (i>0&&i<n-1?'<button type="button" class="ib bd" title="'+esc(t('Remove this stop'))+'" data-rm="'+i+'">✕</button>':'')+'</div>';
  if(i<n-1){var hp=R.hops[i]||{};
   h+='<div class="rt-hop" data-h="'+i+'"><div class="rt-hg">'+
    '<div><label>'+t('Transport')+'</label><select class="rt-tr" data-h="'+i+'">'+trOpts(hp.transport)+'</select></div>'+
    '<div><label>'+t('Direction')+'</label><select class="rt-md" data-h="'+i+'"><option value="reverse"'+(hp.mode!='direct'?' selected':'')+'>'+t('reverse')+'</option><option value="direct"'+(hp.mode=='direct'?' selected':'')+'>'+t('direct')+'</option></select></div>'+
    '<div><label>'+t('Link port')+'</label><input class="rt-pt ltr" data-h="'+i+'" inputmode="numeric" value="'+esc(hp.port?String(hp.port):'')+'"></div>'+
    '<div><label>'+t('Profile')+'</label><select class="rt-pf" data-h="'+i+'"><option value="balanced"'+(hp.prof=='balanced'?' selected':'')+'>'+t('Balanced')+'</option><option value="speed"'+(hp.prof=='speed'?' selected':'')+'>'+t('Most speed')+'</option><option value="gaming"'+(hp.prof=='gaming'?' selected':'')+'>'+t('Gaming (low ping)')+'</option></select></div>'+
    '<div><button type="button" class="b2" data-t="'+i+'">⚡ '+t('Test')+'</button></div></div><div class="rt-res" id="rt_res'+i+'">'+(hp.res||'')+'</div></div>'}});
 el.innerHTML=h;
 $$('#rt_path [data-rm]').forEach(function(b){b.onclick=function(){readForm();var i=+b.dataset.rm;R.stops.splice(i,1);R.hops.splice(i,1);drawPath()}});
 $$('#rt_path [data-t]').forEach(function(b){b.onclick=function(){readForm();testHop(+b.dataset.t)}});
 $$('#rt_path .rt-s').forEach(function(s){s.onchange=function(){readForm();autoPorts();if(+s.dataset.i==R.stops.length-1)fillPorts(false);drawPath()}});
 $$('#rt_path .rt-tr,#rt_path .rt-md').forEach(function(s){s.onchange=function(){var i=+s.dataset.h;readForm();R.hops[i].auto=true;R.hops[i].port=0;autoPorts();drawPath()}});
 $$('#rt_path .rt-pt').forEach(function(s){s.oninput=function(){R.hops[+s.dataset.h].typed=1}});
 autoPorts(true);
 var last=R.stops[n-1],l=$('#rt_vpnl');if(l)l.textContent=t('Ports of')+' '+(last?sname(last):'—')}
function readForm(){$$('#rt_path .rt-s').forEach(function(s){R.stops[+s.dataset.i]=s.value});
 $$('#rt_path .rt-tr').forEach(function(s){R.hops[+s.dataset.h].transport=s.value});
 $$('#rt_path .rt-md').forEach(function(s){R.hops[+s.dataset.h].mode=s.value});
 $$('#rt_path .rt-pf').forEach(function(s){R.hops[+s.dataset.h].prof=s.value});
 $$('#rt_path .rt-pt').forEach(function(s){var v=+unN(s.value)||0;R.hops[+s.dataset.h].port=v});
 if($('#rt_nm'))R.name=$('#rt_nm').value;if($('#rt_tcp'))R.tcp=$('#rt_tcp').value;if($('#rt_udp'))R.udp=$('#rt_udp').value}
// a free link port for each hop on the server that listens (two hops of this route never share one)
function autoPorts(paint){var taken={};
 R.hops.forEach(function(h,i){var en=R.stops[i],ex=R.stops[i+1];if(!en||!ex)return;var l=h.mode=='direct'?ex:en,udp=tunUdpTr(h.transport),both=tunBoth(h.transport),k=l+'|'+(both?'b':udp?'u':'t');
  taken[k]=taken[k]||{};
  if(h.port&&(h.typed||h.id)&&!h.auto){taken[k][h.port]=1;return}
  var p=tunFreePort(l,h.id||null,udp,both);while(taken[k][p]&&p<3500)p++;taken[k][p]=1;h.port=p;h.auto=false});
 if(paint)$$('#rt_path .rt-pt').forEach(function(s){var h=R.hops[+s.dataset.h];if(h&&h.port&&!s.value)s.value=h.port})}
// the ports of the last server: its VPN ports (UDP), its Xray inbounds and its Kanki DNS (tunSvcPorts)
function fillPorts(manual){readForm();var last=R.stops[R.stops.length-1];if(!last)return;
 var s=((R.srvs&&R.srvs.servers)||[]).filter(function(x){return (x.agent&&x.agent.id==last)||(last=='local'&&x.local)})[0],n=s&&s.node,i=(n&&n.info)||{},udp=[],tcp=[];
 var add=function(l,v){v=parseInt(v,10);if(v>0&&v<65536&&l.indexOf(v)<0)l.push(v)};
 [i.wg_port,i.awg_port,i.hy2_port,i.kmix_port].forEach(function(v){add(udp,v)});
 tunSvcPorts(last).then(function(o){
  o.tcp.forEach(function(v){add(tcp,v)});o.udp.forEach(function(v){add(udp,v)});
  if(!udp.length&&!tcp.length){if(manual)toast(t('No node found for this server: type the ports by hand'),1);return}
  if(!manual&&(R.tcp||R.udp))return;
  $('#rt_tcp').value=tcp.join(', ');$('#rt_udp').value=udp.join(', ');readForm()})}

// ---------------------------------------------------------------- smart test, hop by hop
function probeWait(){return new Promise(function(res){var iv=setInterval(function(){api('GET','/api/tunnels/probe').then(function(r){var j=r.job;if(!j||j.finished){clearInterval(iv);res(j)}else{var p=Math.min(99,Math.round(j.elapsed*100/60));R.onp&&R.onp(p)}}).catch(function(){})},2000)})}
function bestOf(j,prof){var L=(j&&j.results)||[],ok=L.filter(function(r){return !r.baseline&&r.done&&!r.failed&&r.down_mbps>0});
 ok.sort(function(a,b){return ((b.scores||{})[prof]||0)-((a.scores||{})[prof]||0)||(b.down_mbps||0)-(a.down_mbps||0)});
 var b=ok[0];if(!b)return null;return {transport:b.transport,mode:b.mode,score:(b.scores||{})[prof]||0,ping:b.ping_ms}}
function testHop(i){var en=R.stops[i],ex=R.stops[i+1],res=function(h){var el=$('#rt_res'+i);if(el)el.innerHTML=h;R.hops[i].res=h};
 if(!en||!ex||en==ex){toast(t('Pick every server'),1);return Promise.resolve(null)}
 res('<span class="spin"></span> '+t('Testing…'));R.onp=function(p){res('<span class="spin"></span> '+t('Testing…')+' '+N(p)+'%')};
 return api('GET','/api/tunnels/probe').then(function(r){if(r.job&&!r.job.finished){res(t('Another test is running; it starts when that one ends'));return probeWait()}}).then(function(){
  return api('POST','/api/tunnels/probe',{entry:en,exit:ex,port:3990,transports:TS_TR.map(function(x){return x[0]}),baseline:true})}).then(function(){return probeWait()}).then(function(j){
  var b=bestOf(j,R.hops[i].prof||'balanced');
  if(!b){res('<span class="r">'+t('No transport passed on this hop')+'</span>');return null}
  R.hops[i].transport=b.transport;R.hops[i].mode=b.mode;R.hops[i].auto=true;R.hops[i].port=0;
  var h='🏆 '+t('Best')+': <b>'+esc(tunTr(b.transport))+'</b> · '+t(b.mode=='direct'?'direct':'reverse')+' · '+N(b.score)+'/100'+(b.ping!=null?' · <span class="ltr">'+N(b.ping)+' ms</span>':'');
  R.hops[i].res=h;readFormSafe();autoPorts();drawPath();return b}).catch(function(e){res('<span class="r">'+esc(e.message||String(e))+'</span>');return null})}
function readFormSafe(){var keep=R.hops.map(function(h){return {transport:h.transport,mode:h.mode,auto:h.auto,port:h.port,res:h.res}});readForm();keep.forEach(function(k,i){if(k.auto){R.hops[i].transport=k.transport;R.hops[i].mode=k.mode;R.hops[i].port=k.port}R.hops[i].res=k.res})}
function testAll(){var i=0,next=function(){if(!$('#rt_path')||i>=R.hops.length)return;var k=i++;testHop(k).then(next)};next()}

// ---------------------------------------------------------------- save: one tunnel per hop
function save(btn){readForm();var st=R.stops,n=st.length;
 if(n<3)return toast(t('Pick at least three servers: the first, one in the middle and the last'),1);
 if(st.some(function(x){return !x}))return toast(t('Pick every server'),1);
 if(st.some(function(x,i){return st.indexOf(x)!=i}))return toast(t('A server cannot come twice on the route'),1);
 if(!R.tcp.trim()&&!R.udp.trim())return toast(t('Add at least one port to carry'),1);
 autoPorts();
 var ch=R.chain||uid(),name=R.name.trim()||st.map(sname).join(' → '),old=R.chain?hopsOf(R.chain):[],made=[];
 btn.disabled=true;
 var body=function(i){var h=R.hops[i],b={name:name+' · '+N(i+1)+'/'+N(n-1),entry:st[i],exit:st[i+1],mode:h.mode,transport:h.transport,port:h.port,conns:TNP[h.prof]||4,
   tcp:R.tcp,udp:R.udp,chain:ch,hop:i,chain_name:name,kind:'',auto:false};
  if(h.transport=='game'){b.fec=h.fec||'8:3';b.dup=!!h.dup}
  if(old[i])b.id=old[i].id;return b};
 var step=function(i){if(i>=n-1)return Promise.resolve();return api('POST','/api/tunnels',body(i)).then(function(r){if(!old[i])made.push(r.id);return step(i+1)},function(e){
   var m=t('Could not make hop')+' '+N(i+1)+' ('+sname(st[i])+' → '+sname(st[i+1])+'): '+(e.message||e);throw new Error(m)})};
 step(0).then(function(){
  // hops of the old route past the new end go away
  return Promise.all(old.slice(n-1).map(function(x){return api('DELETE','/api/tunnels/'+x.id)}))}).then(function(){
  if(!$('#rt_use').checked)return;
  var last=st[n-1],first=st[0],s=((R.srvs&&R.srvs.servers)||[]).filter(function(x){return (x.agent&&x.agent.id==last)||(last=='local'&&x.local)})[0],f=tunSrv(first);
  if(!s||!s.node||!(f.addr||f.host))return;
  return api('PUT','/api/nodes/'+encodeURIComponent(s.node.id),{endpoint_mode:'custom',endpoint:f.addr||f.host})}).then(function(){
  closeModal();toast(t(R.chain?'Route saved':'The route is made: it connects in a few seconds'));tunRefresh();srvLoad(true)}).catch(function(e){
  btn.disabled=false;
  if(made.length)Promise.all(made.map(function(id){return api('DELETE','/api/tunnels/'+id)})).then(function(){tunRefresh()});
  toast((e.message||String(e))+(made.length?' · '+t('the hops made so far were taken back'):''),1)})}
})();

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
  viaT=list.filter(function(s){return routeVia(agentOf(s),pvState(p,s)[2])||(s.tunnel&&s.tunnel.on&&s.tunnel.uses)}).length,ov=PD.ov||{},users=((ov.protocols||{})[p]);
 $('#pv_kv').innerHTML='<div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(list.length)+'</b></div><div><small>'+t('Users with it')+'</small><b>'+(users==null?'—':N(users))+'</b></div><div><small>'+t('Through a tunnel')+'</small><b>'+N(viaT)+'</b></div>';
 if(!force&&accBusy(g))return;
 el.innerHTML=list.length?boxes(g,list,function(s){return pvRow(p,s)}):'<div class="card muted" style="text-align:center">'+t('No VPN server yet')+' · <a href="#nodes">'+t('Add server')+'</a></div>';
 if(p=='awg')dirDraw()}
// the copy of this protocol through the server's tunnel (Servers page › Tunnel), or why there is none
function tunCopy(p,s,r){var tn=s.tunnel||{},name={wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2',kmix:'KANKI MIX'}[p],x=(tn.ports||[]).filter(function(z){return z.proto==name})[0];
 if(tn.on&&tn.uses&&x)return '<div class="kxr-line"><span class="kxr-st g">+ '+t('tunnel')+'</span><span>'+t('Users also get')+' <b class="ltr">'+esc(tn.uses)+':'+x.via+'</b></span> <a href="#nodes" style="font-size:11px">'+t('change in Servers')+'</a></div>';
 if(p=='wg'&&!r)return '<div class="kxr-line"><span class="warnbox" style="margin:0;width:100%">'+t('WireGuard reaches users only through a tunnel: write the tunnel domain of this server in Servers.')+'</span></div>';
 return ''}
function pvRow(p,s){var st=pvState(p,s),port=st[2];
 var head='<span class="dot '+(st[0]=='n'?'':st[0])+'"></span>'+fl(s.cc)+'<b>'+esc(s.name)+'</b>'+(s.local?'<span class="kxc-tag main">'+t('Panel server')+'</span>':'')+'<span class="sp"></span>'+
  '<span class="kxr-st '+st[0]+'">'+esc(st[1])+'</span>'+tunTag(p,s)+(port?'<small class="ltr">UDP '+N(port)+'</small>':'');
 return accRow('pv_'+p,s.key,head,function(){return pvBody(p,s)})}
// the row's tunnel badge: its configs point at an Iran entry, or it also has a copy through its tunnel domain
function tunTag(p,s){var tn=s.tunnel||{},has=(tn.ports||[]).some(function(z){return z.proto=={wg:'WireGuard',awg:'AmneziaWG',hy2:'Hysteria2'}[p]});
 return tn.main_via=='tunnel'?'<span class="kxr-st g">'+t('tunnel')+'</span>':tn.on&&tn.uses&&has?'<span class="kxr-st g">+ '+t('tunnel')+'</span>':''}
function pvBody(p,s){var n=s.node,i=n.info||{},st=pvState(p,s),port=st[2],k=esc(s.key),ni=esc(n.id),r=routeVia(agentOf(s),port);
 var h='<div class="kxr-line"><span><b>'+esc(st[1])+'</b></span>'+(n.enabled?'<span>·</span><span>'+N(n.users||0)+' '+t('users')+'</span>':'')+
  '<span>·</span><span>'+t('Users connect to')+': <b class="ltr">'+esc(n.effective_endpoint||'—')+'</b> <a href="#nodes" style="font-size:11px">'+t('change in Servers')+'</a></span></div>'+
  '<div class="kxr-line">'+(r?viaLine(r,s.name):'<span>'+t('No tunnel carries this port: users connect to the server directly')+'</span>')+'</div>'+tunCopy(p,s,r);
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
   // the server's tunnel domain (Servers page) gives it by itself; the fields below only change it for KANKI MIX
   '<label class="kxsw" style="cursor:pointer"><span>'+(x.second?t('Users also get')+' <b class="ltr">'+esc(x.second.host)+':'+esc(String(x.second.port))+'</b>':t('Write the tunnel domain of this server in Servers: the second config is made by itself.'))+'</span><input type="checkbox" id="km_t21" style="width:auto"'+(o.tun_off?'':' checked')+'></label>'+
   '<details class="box" style="margin-top:6px"'+(o.tun_host||o.tun_port||o.tun_name?' open':'')+'><summary>'+t('Only for KANKI MIX (optional)')+'</summary>'+
   '<div class="kxf"><div><label class="f">'+t('Iran address')+'</label><input id="km_th1" class="ltr" placeholder="'+esc(t('the tunnel domain of the server'))+'" value="'+esc(o.tun_host||'')+'"></div>'+
   '<div><label class="f">'+t('Port')+'</label><input id="km_tp1" class="ltr" inputmode="numeric" placeholder="'+esc(String((via&&via.port)||port||''))+'" value="'+esc(o.tun_port?String(o.tun_port):'')+'"></div>'+
   '<div class="wide"><label class="f">'+t('Name in the app')+'</label><input id="km_tn1" maxlength="40" placeholder="'+esc(x.name+' ('+t('tunnel')+')')+'" value="'+esc(o.tun_name||'')+'"></div></div></details>'+
   '<div class="kxr-line">'+(via?viaLine(via,x.name):(o.tun_host&&!o.tun_off?'<span class="warnbox" style="margin:0;width:100%">'+t('No Kanki tunnel carries this port to the server. Make a tunnel (or a multi-location route) that carries it, or forward it on that address some other way.')+'</span>':''))+'</div>'+
   (x.on&&x.error?'<div class="warnbox'+(x.error=='not running'?'':' ltr')+'" style="margin:6px 0 0">'+esc(t(x.error))+'</div>':'')+
   '<div class="kxsave"><button class="b2 sm" onclick="accClose(\'km\')">'+t('Cancel')+'</button><button class="btn sm" onclick="kmSaveOne(\''+id+'\')">'+t('Save')+'</button></div>'+
   '<div class="kxacts"><button class="b2 sm" onclick="nAct(\''+ni+'\',\'repair\')">↻ '+t('Restart VPN services')+'</button><a class="b2 sm" href="#tunnels">'+t('Tunnels page')+'</a></div>';
  setTimeout(function(){var el=$('#km_p1'),w=$('#km_pw'),b=$('#km_ps');if(!el)return;var f=function(){var m=srvPortClash(r.key,'kmix',el.value);w.textContent=m;b.disabled=!!m};el.oninput=f;f();
   b.onclick=function(){if(String(r.key).indexOf('node:')==0)return kmSetNodePort(x.id,+unN(el.value),function(){accClose('km')});srvSavePort(r.key,'kmix',el.value,function(){accClose('km');kmLoad(true)})}},0);
  return h}
 window.kmSaveOne=function(id){var d=KM.d,m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});var o=m[id]||{};
  o.route=$('#km_rt1').value;o.host=$('#km_ho1').value.trim();o.tun_off=!$('#km_t21').checked;o.tun_host=$('#km_th1').value.trim();
  var tp=unN($('#km_tp1').value).trim();o.tun_port=tp?+tp:0;o.tun_name=$('#km_tn1').value.trim();m[id]=o;
  api('PUT','/api/kmix',{nodes:m}).then(function(){toast(t('Saved'));accClose('km');kmLoad(true)}).catch(fail)};
 // the settings of every server, in the list; the page keeps its numbers and the general settings
  ACC.draw.km=function(){var c=$('#km_srv');if(c&&KM.d)c.innerHTML=kmServers(KM.d)};
 

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
   '<div class="kxacts"><button class="btn sm" onclick="xrInbound()">+ '+t('Inbound')+'</button><button class="b2 sm" onclick="xrSrvEdit(\''+sid+'\')">'+ic('edit',13)+' '+t('Edit server')+'</button>'+
   '<button class="b2 sm" onclick="xrPreview(\''+sid+'\')">{ } '+t('Config')+'</button><button class="b2 sm" onclick="srvRepair(\'xray\',\''+sid+'\')">↻ '+t('Repair')+'</button><button class="b2 sm" onclick="srvHealth(\'xray\',\''+sid+'\')">♡ '+t('Health')+'</button>'+
   '<button class="b2 sm bd" onclick="xrSrvDel(\''+sid+'\')">'+ic('trash',13)+' '+t('Remove Xray from this server')+'</button></div>'}
 ACC.draw.xr=function(){var c=$('#xr_srv');if(c&&XR.d)c.innerHTML=xrServers(XR.d)};
 })();

// ==================================================================== colors and cards
// cards and colors: the sign-in screen, an icon per dashboard number, data used and days left on
// every user tile, a clear focus ring, and no motion for those who ask their system for less.
(function(){
'use strict';


// ---------------------------------------------------------------- dashboard numbers: an icon per number
var KICO={all:'users',online:'k310online',active:'k310ok',finished:'k310warn',disabled:'k310off'};
function kpiIcons(){$$('#kpis .kpi').forEach(function(k){if(k.querySelector('.k310ki'))return;
 k.insertAdjacentHTML('afterbegin','<span class="k310ki">'+ic(KICO[k.dataset.go]||'k310traffic',18)+'</span>')})}
V37.kpiIcons=kpiIcons;

// the sign-in screen may already be drawn before this file ran
if($('.login')&&!$('.k310login'))loginView(!($('#otpw')||{classList:{contains:function(){return true}}}).classList.contains('hide'));
})();

// ==================================================================== tunnel map, drawers
// where things live: KANKI MIX and Xray servers as cards with a side drawer; the dashboard (a status
// line, the numbers, then live traffic beside server resources, servers beside tunnels, services beside
// connections, the log last); the tunnel map (Iran entries in one column, exits in the next, each
// tunnel on its own curve with its protocol and live ping).
(function(){
'use strict';
var V=V37;

// ---------------------------------------------------------------- the menu
// [section key, label, icon, [[page, sub page, tab label], ...], group]
function secBy(k){for(var i=0;i<V.SECS.length;i++)if(V.SECS[i][0]==k)return V.SECS[i];return V.SECS[0]}
function href(f){return '#'+f[0]+(f[1]?'/'+f[1]:'')}
function sheetHtml(){var g='',h='<i class="k38grab"></i>',open=false,cur=V.secOf(S.page)[0];
 V.SECS.forEach(function(s){if(s[4]!=g){if(open)h+='</div>';g=s[4];h+='<div class="k38g">'+t(g)+'</div><div class="k38tiles">';open=true}
  h+='<a class="k38tile'+(cur==s[0]?' on':'')+'" href="'+href(s[3][0])+'">'+ic(s[2],22)+'<span>'+t(s[1])+'</span></a>'});
 return h+(open?'</div>':'')}
window.k38More=function(on){var sh=$('#msheet'),sc=$('#k38scrim');if(!sh)return;if(on===undefined)on=!sh.classList.contains('on');
 if(on)sh.innerHTML=sheetHtml();sh.classList.toggle('on',!!on);if(sc)sc.classList.toggle('on',!!on)};
// a section whose tabs are sub pages of one page (Xray): mark the tab of the sub page, not all of them
function markTabs(){var el=$('#sectabs');if(!el)return;var as=$$('.stl a',el),h=location.hash||'',hit=as.filter(function(a){return a.getAttribute('href')==h});
 if(!hit.length){var p='#'+S.page;hit=as.filter(function(a){return a.getAttribute('href').split('/')[0]==p}).slice(0,1)}
 as.forEach(function(a){a.classList.toggle('on',hit.indexOf(a)>=0)})}
V.markTabs=markTabs;



// ---------------------------------------------------------------- server cards with a side drawer
// KANKI MIX (km) and Xray (xr) rows become cards; the open one shows its settings in a drawer
var DRW={km:'#km_srv',xr:'#xr_srv'};
function drawerDress(){Object.keys(DRW).forEach(function(g){var box=$(DRW[g]);if(box)box.classList.add('k310cards')});
 var open=$('.k310cards .kxr.open'),sc=$('#k310scrim');
 if(!open){if(sc)sc.classList.remove('on');document.body.classList.remove('k310drw');return}
 if(!sc){sc=document.createElement('div');sc.id='k310scrim';sc.className='k310scrim';document.body.appendChild(sc)}
 var g=open.dataset.acc;sc.onclick=function(){accClose(g)};sc.classList.add('on');document.body.classList.add('k310drw');
 var b=$('.kxr-b',open);if(b&&!$('.k310dh',b)){var h=$('.kxr-h',open),nm=h&&$('b',h);
  b.insertAdjacentHTML('afterbegin','<div class="k310dh"><b>'+(nm?esc(nm.textContent):'')+'</b><button type="button" class="ib" aria-label="'+esc(t('Close'))+'" onclick="accClose(\''+g+'\')">✕</button></div>')}}
V.drawerDress=function(){if($('.k310cards')||$(DRW.km)||$(DRW.xr)||$('#k310scrim.on'))drawerDress()};
window.addEventListener('hashchange',function(){var sc=$('#k310scrim');if(sc)sc.classList.remove('on');document.body.classList.remove('k310drw')});

// ---------------------------------------------------------------- dashboard
function chip(c,label,val){return '<span class="k310st '+c+'"><i></i>'+t(label)+'<b class="ltr">'+val+'</b></span>'}
// the dashboard: a status line, the numbers, then live traffic beside server resources, servers beside tunnels,
// services beside connections, the activity log last
window.pDash=function(){dbReset();
$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Dashboard')+'</h2><p class="ltr" id="d_sub" style="text-align:start">…</p></div>'+
 '<div class="row" style="gap:6px;flex-wrap:nowrap"><button class="btn sm" onclick="newUser()">'+ic('plus',15)+' '+t('New user')+'</button><button class="b2 sm" onclick="nodeAddTyped()">'+ic('nodes',15)+' '+t('Add server')+'</button><span class="live" id="d_live"><i></i><span id="d_lt">'+t('Live')+'</span></span>'+
 '<select id="d_iv" style="width:auto;padding:6px 9px;font-size:12px">'+[1,2,5,10].map(function(n){return '<option value="'+n+'"'+(n==DB.iv?' selected':'')+'>'+N(n)+' '+t('seconds')+'</option>'}).join('')+'</select>'+
 '<button class="ib" id="d_pause" title="'+t('Pause')+'">❚❚</button></div></div>'+
 '<div class="k310strip" id="k310strip"></div><div class="kpis" id="kpis"></div>'+
 '<div class="k310dash" id="k310dash">'+
  '<div class="k310c w8">'+'<div class="card" style="margin-bottom:12px"><div class="nh"><div><h3>'+t('Network speed')+'</h3><small class="muted ltr" id="n_if"></small></div>'+
  '<div class="nbig"><div class="dn"><small>↓ '+t('Download')+'</small><b id="n_rx" class="ltr">—</b></div><div class="upl"><small>↑ '+t('Upload')+'</small><b id="n_tx" class="ltr">—</b></div></div></div>'+
  '<div class="ch tall" id="ch_net"></div>'+
  '<div class="nf ltr"><span>'+t('Peak')+' ↓ <b id="n_prx">—</b></span><span>'+t('Peak')+' ↑ <b id="n_ptx">—</b></span><span>'+t('Total since boot')+' ↓ <b id="n_trx">—</b></span><span>↑ <b id="n_ttx">—</b></span></div></div>'+'</div>'+
  '<div class="k310c w4"><div class="card k310res"><h3>'+ic('cpu',16)+' '+t('Server resources')+'</h3>'+'<div class="gg">'+gcard('cpu','CPU',ic('cpu',16))+gcard('ram','RAM',ic('ram',16))+gcard('disk','Storage',ic('disk',16))+gcard('swap','Swap',ic('swap',16))+'</div>'+'</div></div>'+
  '<div class="k310c w6">'+'<div class="card" id="nc" style="margin-bottom:12px"></div>'+'</div>'+
  '<div class="k310c w6">'+tunDashCard()+'</div>'+
  '<div class="k310c w6">'+'<div class="card"><h3>'+t('Services')+'</h3><p class="sub">'+t('Start, stop or restart the VPN services')+'</p><div id="svcs" class="svcs"><span class="muted">'+t('Loading…')+'</span></div></div>'+'</div>'+
  '<div class="k310c w6">'+'<div class="card" style="margin-bottom:12px"><div class="nh"><div><h3>'+t('TCP / UDP connections')+'</h3><small class="muted" id="c_sub"></small></div>'+
  '<div class="nbig"><div class="dn"><small>TCP</small><b id="c_tcp" class="ltr">—</b></div><div class="upl"><small>UDP</small><b id="c_udp" class="ltr">—</b></div></div></div>'+
  '<div class="ch tall" id="ch_con"></div></div>'+'</div>'+
 '</div>'+logCard();
 $('#d_iv').onchange=function(){DB.iv=+this.value;localStorage.setItem('kk_div',DB.iv);dashTimers()};
 $('#d_pause').onclick=function(){DB.paused=!DB.paused;if(!DB.paused)DB.last=null;this.textContent=DB.paused?'▶':'❚❚';this.title=DB.paused?t('Resume'):t('Pause');dashLive(DB.paused?'off':'')};
 $('#svcs').onclick=function(e){var b=e.target.closest('[data-svc]');if(b&&!b.disabled)svc(b.dataset.svc,b.dataset.act)};logWire();tunDashWire();
 $('#kpis').onclick=function(e){var b=e.target.closest('[data-go]');if(b)goUsers(b.dataset.go)};
 dashTick();dashSys();dashTimers();
 strip();clearInterval(S.timer4);S.timer4=setInterval(function(){if(S.page!='dash'){clearInterval(S.timer4);return}strip()},3000)};
window.drawKpis=function(o){var el=$('#kpis');if(el&&o){
 var it=[['a','Total users',o.users,'all'],['g','Online',o.online,'online'],['g','Active',o.active,'active'],['y','Expired / out of data',o.expired,'finished'],['r','Disabled',o.disabled,'disabled'],['a','Total traffic',N(o.traffic_gb)+' GB','']];
 el.innerHTML=it.map(function(x){return '<button class="kpi '+x[0]+'" '+(x[3]?'data-go="'+x[3]+'"':'')+'><small>'+t(x[1])+'</small><b class="ltr">'+(typeof x[2]=='number'?N(x[2]):x[2])+'</b></button>'}).join('')}
 strip()};
function strip(){var el=$('#k310strip');if(!el)return;var h='';
 var ns=S.nodes||[];if(ns.length){var on=ns.filter(function(n){return n.online}).length;h+=chip(on==ns.length?'g':on?'y':'r','Servers online',N(on)+' / '+N(ns.length))}
 var tl=(TN.d&&TN.d.tunnels)||[];if(tl.length){var up=tl.filter(function(x){return x.state=='up'}).length;h+=chip(up==tl.length?'g':up?'y':'r','Tunnels up',N(up)+' / '+N(tl.length))}
 var sv=((DB.sys||{}).services||[]);if(sv.length){var bad=sv.filter(function(x){return !x.active}).length;h+=chip(bad?'y':'g','Services',bad?N(bad)+' '+t('stopped'):t('all running'))}
 if(DB.ov)h+=chip(DB.ov.online?'g':'','Users online',N(DB.ov.online));
 h=h||'<span class="muted">…</span>';if(el._h!==h){el._h=h;el.innerHTML=h}}  // unchanged: leave it, so its turning edges keep turning

// ---------------------------------------------------------------- tunnel map
// The neon map (glowing fibres, packets that turn into the tunnel colour at the lock, cyan packets
// coming back, servers with a turning ring and a little satellite), laid out so nothing overlaps:
// Iran entries in one column, exits abroad in the next (a third for second hops; rows on phones),
// the columns ordered to cut crossings, every tunnel leaving and reaching its server at its own point,
// and its label (short name · ping) in the middle of its own line, never over a server or another label.
// on the map: the tunnel's shortest name (HQ-QUIC → HQ-Q, Game-FEC → GFEC …)
var TMS={'HQ-QUIC':'HQ-Q','Game-FEC':'GFEC','TCP-Mux':'TMUX','FakeTCP':'FTCP','QUIC':'Q'};
function tmShort(x){var n=tunShort(x);return TMS[n]||n.replace('AWG+','A+')}
// on the map: a server's short name, its country's short code (Germany GR, England UK …) and its number,
// numbered when two share a code (GR1, GR2); a name with no known country gives its first two letters
var TMC=[[/german|آلمان|^de$/i,'GR'],[/england|brit|^uk$|united king|انگلیس|بریتانیا|^gb$/i,'UK'],[/nether|holland|هلند|^nl$/i,'NL'],[/swed|سوئد|^se$/i,'SE'],
 [/turk|ترکیه|^tr$/i,'TR'],[/iran|tehran|tabriz|mashhad|shiraz|isfahan|ایران|تهران|تبریز|مشهد|شیراز|اصفهان|^ir$/i,'IR'],[/finl|فنلاند|^fi$/i,'FI'],[/fran|فرانسه|^fr$/i,'FR'],
 [/usa|america|united states|آمریکا|^us$/i,'US'],[/canad|کانادا|^ca$/i,'CA'],[/poland|لهستان|^pl$/i,'PL'],[/russia|روسیه|^ru$/i,'RU'],[/emirat|dubai|uae|امارات|دبی|^ae$/i,'AE'],
 [/armen|ارمنستان|^am$/i,'AM'],[/austria|اتریش|^at$/i,'AT'],[/switz|سوئیس|^ch$/i,'CH'],[/ital|ایتالیا|^it$/i,'IT'],[/spain|اسپانیا|^es$/i,'ES'],[/japan|ژاپن|^jp$/i,'JP'],[/singap|سنگاپور|^sg$/i,'SG']];
function tmCode(s){var nm=String(s.name||'');for(var i=0;i<TMC.length;i++)if(TMC[i][0].test(nm)||TMC[i][0].test(String(s.cc||'')))return TMC[i][1];
 var w=nm.match(/[A-Za-z]+/);return (w?w[0].slice(0,2):(s.cc||nm.slice(0,2))).toUpperCase()}
function tmAbbr(sv){var out={},by={};
 sv.forEach(function(s){var code=tmCode(s),num=(String(s.name||'').match(/\d+/)||[''])[0];(by[code]=by[code]||[]).push({s:s,num:num})});
 Object.keys(by).forEach(function(c){var l=by[c],own=l.every(function(y){return y.num})&&new Set(l.map(function(y){return y.num})).size==l.length;
  l.forEach(function(x,i){out[x.s.id]=c+(l.length>1?(own?x.num:String(i+1)):x.num)})});
 return out}
function tmLayout(d,small){var sv=d.servers||[],byId={};sv.forEach(function(s){byId[s.id]=s});
 var tl=(d.tunnels||[]).filter(function(x){return x.entry!=x.exit&&byId[x.entry]&&byId[x.exit]});
 var lay={};sv.forEach(function(s){lay[s.id]=srvLoc(s)=='iran'?0:1});
 for(var it=0;it<3;it++)tl.forEach(function(x){if(lay[x.entry]>=1&&lay[x.exit]>=1&&lay[x.exit]<=lay[x.entry]&&!tl.some(function(z){return z.exit==x.exit&&lay[z.entry]==0}))lay[x.exit]=Math.min(2,lay[x.entry]+1)});
 var cols=[[],[],[]];sv.forEach(function(s){cols[lay[s.id]].push(s)});while(cols.length>1&&!cols[cols.length-1].length)cols.pop();if(!cols[0].length&&cols.length>1)cols.shift();
 var pos={},setPos=function(){cols.forEach(function(c){c.forEach(function(s,i){pos[s.id]=c.length>1?i/(c.length-1):.5})})};setPos();
 var bary=function(s){var nb=[];tl.forEach(function(x){if(x.entry==s.id)nb.push(pos[x.exit]);if(x.exit==s.id)nb.push(pos[x.entry])});return nb.length?nb.reduce(function(a,b){return a+b},0)/nb.length:pos[s.id]};
 for(it=0;it<6;it++){cols.forEach(function(c){c.sort(function(a,b){return bary(a)-bary(b)})});setPos()}
 var cross=function(){var n=0;for(var i=0;i<tl.length;i++)for(var j=i+1;j<tl.length;j++){var x=tl[i],y=tl[j];
   if(x.entry==y.entry||x.exit==y.exit||x.entry==y.exit||x.exit==y.entry)continue;
   if(lay[x.entry]==lay[y.entry]&&lay[x.exit]==lay[y.exit]&&(pos[x.entry]-pos[y.entry])*(pos[x.exit]-pos[y.exit])<0)n++}return n};
 var best=cross(),more=best>0;for(it=0;it<20&&more;it++){more=false;
  cols.forEach(function(c){for(var i=0;i+1<c.length;i++){var s0=c[i];c[i]=c[i+1];c[i+1]=s0;setPos();var n=cross();if(n<best){best=n;more=true}else{c[i+1]=c[i];c[i]=s0;setPos()}}})}
 // always across: Iran on the left, the servers abroad on the right (phones too, a little narrower)
 var phone=window.innerWidth<640,nc=cols.length,maxN=Math.max.apply(null,cols.map(function(c){return c.length}).concat([1]));
 var W,H,P={},R=26,mg=78;
 {W=phone?Math.max(460,250*(nc-1)+140):small?680:820;if(phone)mg=62;var step=Math.max(118,Math.max.apply(null,sv.map(function(s){return tl.filter(function(x){return x.entry==s.id||x.exit==s.id}).length*14+40}).concat([0])));
  H=Math.max(small?330:380,maxN*step+70);
  cols.forEach(function(c,ci){var x=mg+ci*((W-2*mg)/Math.max(1,nc-1));c.forEach(function(s,i){P[s.id]={x:x,y:40+(H-70)/c.length*(i+.5),c:ci}})})}
 // a trunk from each entry: a short stem, one line across, then a straight branch down (or across) to every
 // server it reaches. Branches into one server sit side by side; entries of one column get their own trunk
 // level, so trunks never lie on each other
 var E={},lvl={},arr={},has={};tl.forEach(function(x){has[x.entry]=1;(arr[x.exit]=arr[x.exit]||[]).push(x)});
 cols.forEach(function(c){var k=0;c.forEach(function(s){if(has[s.id])lvl[s.id]=k++})});
 Object.keys(arr).forEach(function(id){arr[id].sort(function(a,b){return P[a.entry].y-P[b.entry].y})});
 tl.forEach(function(x){var a=P[x.entry],b=P[x.exit],l=arr[x.exit],j=l.indexOf(x),off=l.length>1?(j/(l.length-1)-.5)*2*(R-5):0,stem=R+20+(lvl[x.entry]||0)*14,r2=Math.sqrt(Math.max(0,R*R-off*off)),pts;
  var d2=b.x>=a.x?1:-1,tx=a.x+d2*stem;pts=[{x:a.x+d2*R,y:a.y},{x:tx,y:a.y},{x:tx,y:b.y+off},{x:b.x-d2*r2,y:b.y+off}];
  E[x.id]={pts:pts}});
 // labels (short name, ping under it) on each branch, moved along it until they cover no server, name or
 // other label: neighbouring branches end up with their labels at different heights
 var boxes=[],L={};
 sv.forEach(function(s){var p=P[s.id];boxes.push({x:p.x-44,y:p.y-44,w:88,h:110})});
 tl.forEach(function(x){var pts=E[x.id].pts,p0=pts[pts.length-2],p1=pts[pts.length-1],rt=(x.entry_status||{}).rtt_ms||0,
  w=Math.max(tmShort(x).length,(rt+'ms').length)*6.8+18,h=32,spot=null;
  var at=function(f){return {x:p0.x+(p1.x-p0.x)*f,y:p0.y+(p1.y-p0.y)*f}};
  [.5,.3,.7,.18,.82,.4,.6,.1,.9].some(function(f){var q=at(f),r={x:q.x-w/2,y:q.y-h/2,w:w,h:h};
   if(!boxes.some(function(o){return r.x<o.x+o.w+3&&o.x<r.x+r.w+3&&r.y<o.y+o.h+3&&o.y<r.y+r.h+3})){spot=q;boxes.push(r);return true}});
  L[x.id]=spot||at(.5);if(!spot)boxes.push({x:L[x.id].x-w/2,y:L[x.id].y-h/2,w:w,h:h})});
 return {ab:tmAbbr(sv),W:W,H:H,small:!!small,pos:P,sv:sv,tl:tl,hub:'',cx:W/2,cy:H/2,R:0,n:sv.length,cols:true,E:E,L:L,mx:16}}
window.tunMap=function(d,small){var sv=d.servers||[],tl=d.tunnels||[];
 if(!tl.length&&sv.length<2)return '<div class="tempty">'+ic('tunnel',34)+'<b>'+t('No tunnels yet')+'</b><span class="muted">'+t('Add your entry server (for example in Iran), then make a tunnel to the panel server or another server.')+'</span></div>';
 var key=small?'s':'m',st=TM.reg[key]||(TM.reg[key]={rate:{},last:{}}),now=Date.now();
 tl.forEach(function(x){var es=x.entry_status||{},by=(es.rx_bytes||0)+(es.tx_bytes||0),l=st.last[x.id];
  if(l&&now-l.t>500){var r=(by-l.b)/((now-l.t)/1000);if(r>=0)st.rate[x.id]=r}if(!l||now-l.t>500)st.last[x.id]={b:by,t:now}});
 st.m=tmLayout(d,small);tmStart();
 return '<canvas class="tmapcv" data-tm="'+key+'" style="aspect-ratio:'+st.m.W+'/'+st.m.H+'" role="img" aria-label="'+esc(t('Tunnels'))+'"></canvas>'};
// the drawing; where things sit comes from tmLayout
window.tmDraw=function(cv,T){var st=TM.reg[cv.dataset.tm];if(!st||!st.m)return;var m=st.m,w=cv.clientWidth;if(!w)return;
 var dpr=Math.min(2,window.devicePixelRatio||1),pw=Math.round(w*dpr),ph=Math.round(w*m.H/m.W*dpr);if(cv.width!=pw||cv.height!=ph){cv.width=pw;cv.height=ph}
 var c=cv.getContext('2d'),k=pw/m.W,th=(T%1<.02||!st.th)?(st.th=tmTheme()):st.th,W=m.W,H=m.H,TAU=Math.PI*2;
 c.setTransform(k,0,0,k,0,0);c.clearRect(0,0,W,H);
 // ---- background: soft side glows, dot grid, drifting dust
 var bg=c.createRadialGradient(m.cx,m.cy,10,m.cx,m.cy,Math.max(W,H)*.6);bg.addColorStop(0,tmA(th.a,th.light?.13:.11));bg.addColorStop(.55,tmA(th.a,th.light?.04:.03));bg.addColorStop(1,'rgba(61,220,151,'+(th.light?.07:.05)+')');
 c.fillStyle=bg;tmRound(c,0,0,W,H,16);c.fill();
 c.fillStyle=tmA(th.a,th.light?.18:.13);for(var gx=11;gx<W;gx+=22)for(var gy=11;gy<H;gy+=22){c.beginPath();c.arc(gx,gy,.9,0,TAU);c.fill()}
 for(var q=0;q<22;q++){var sx=(q*97.3+T*(6+q%5*3))%W,sy=(q*53.7+Math.sin(T*.4+q)*14+H)%H,sa=.25+.25*Math.sin(T*1.3+q*2.1);c.fillStyle=tmA(th.al,(sa*(th.light?.5:.7)).toFixed(3));c.beginPath();c.arc(sx,sy,q%4?0.9:1.5,0,TAU);c.fill()}
 // the orbit the servers sit on (slowly turning) and a faint inner shell
 if(m.n&&!m.cols){c.strokeStyle=tmA(th.a,.28);c.lineWidth=1.2;c.setLineDash([4,7]);c.lineDashOffset=-T*6;c.beginPath();c.arc(m.cx,m.cy,m.R,0,TAU);c.stroke();
  c.strokeStyle=tmA(th.a,.12);c.setLineDash([2,9]);c.lineDashOffset=T*4;c.beginPath();c.arc(m.cx,m.cy,m.R*.55,0,TAU);c.stroke();c.setLineDash([])}
 // ---- tunnels (their labels are drawn after all of them, on top)
 var labs=[];
 m.tl.forEach(function(x,i){var G=m.E[x.id];if(!G)return;var pts=G.pts,A=pts[0],B=pts[pts.length-1],col=tmRgb(tunCol(x.state)),es=x.entry_status||{},k=0,same=[x];
  var segs=[],tot=0;for(var q=0;q+1<pts.length;q++){var sl=Math.hypot(pts[q+1].x-pts[q].x,pts[q+1].y-pts[q].y);segs.push(sl);tot+=sl}
  var bz=function(u){var d=Math.max(0,Math.min(1,u))*tot;for(var q=0;q<segs.length;q++){if(d<=segs[q]||q==segs.length-1){var f=segs[q]?Math.min(1,d/segs[q]):0;return {x:pts[q].x+(pts[q+1].x-pts[q].x)*f,y:pts[q].y+(pts[q+1].y-pts[q].y)*f}}d-=segs[q]}return B};
  var path=function(){c.beginPath();c.moveTo(A.x,A.y);for(var q=1;q+1<pts.length;q++)c.arcTo(pts[q].x,pts[q].y,pts[q+1].x,pts[q+1].y,10);c.lineTo(B.x,B.y)};
  var ls=tot?(tot-segs[segs.length-1])/tot:0,lt=ls+(1-ls)*.22,up=x.state=='up',part=x.state=='partial',down=!up&&!part,flick=part?(.65+.35*Math.sin(T*7+i)):1;
  c.lineCap='round';
  // fibre: wide halo, body, bright core
  path();c.strokeStyle=tmA(col,(.07*flick).toFixed(3));c.lineWidth=18;c.stroke();
  path();c.strokeStyle=tmA(col,(.16*flick).toFixed(3));c.lineWidth=8;c.stroke();
  if(down){path();c.setLineDash([5,8]);c.lineDashOffset=0;c.strokeStyle=tmA(col,.75);c.lineWidth=2;c.stroke();c.setLineDash([]);
   var mp=bz(lt),fl=.45+.55*Math.abs(Math.sin(T*5+i));c.strokeStyle=tmA(col,fl.toFixed(3));c.lineWidth=2.4;
   c.beginPath();c.moveTo(mp.x-6,mp.y-6);c.lineTo(mp.x+6,mp.y+6);c.moveTo(mp.x+6,mp.y-6);c.lineTo(mp.x-6,mp.y+6);c.stroke();
   for(var z=0;z<5;z++){var ang=z*1.26+T*3,rr=7+((T*18+z*5)%12);c.fillStyle=tmA(col,((1-(rr-7)/12)*.8).toFixed(3));c.beginPath();c.arc(mp.x+Math.cos(ang)*rr,mp.y+Math.sin(ang)*rr,1.3,0,TAU);c.fill()}}
  else{path();var gr=c.createLinearGradient(A.x,A.y,B.x,B.y);gr.addColorStop(0,tmA(th.al,.85));gr.addColorStop(.5,tmA(col,.9));gr.addColorStop(1,tmA(col,.9));c.strokeStyle=gr;c.lineWidth=2.6;c.stroke();
   path();c.setLineDash([2,16]);c.lineDashOffset=-T*46;c.strokeStyle='rgba(255,255,255,'+(.55*flick).toFixed(3)+')';c.lineWidth=1.4;c.stroke();c.setLineDash([])}
  // packets: forward (plain -> encrypted at the lock) and return
  var rtt=es.rtt_ms||0,dur=up?Math.max(1.5,Math.min(4.6,1.5+rtt/110)):5.4,rate=st.rate[x.id]||0,n=up?Math.max(3,Math.min(9,Math.round(3+Math.log(1+rate/2048)/Math.log(10)*1.6))):part?2:0,lockHot=0;
  for(var j=0;j<n;j++){var u=((T/dur)+j/n+i*.13)%1;lockHot=Math.max(lockHot,1-Math.min(1,Math.abs(u-lt)*12));
   for(var tr=7;tr>=0;tr--){var uu=u-tr*.011;if(uu<0)continue;var p=bz(uu),enc=Math.max(0,Math.min(1,(uu-lt+.03)/.06)),pc=tmMix(th.al,col,enc),ra=(tr?2.9*(1-tr*.1):3.6),al=(tr?(1-tr/8)*.55:1)*flick;
    if(!tr){c.fillStyle=tmA(pc,.28*flick);c.beginPath();c.arc(p.x,p.y,8,0,TAU);c.fill()}
    c.fillStyle=tr?tmA(pc,al.toFixed(3)):'rgba(255,255,255,'+al.toFixed(3)+')';c.beginPath();c.arc(p.x,p.y,ra,0,TAU);c.fill()}}
  var nb=up?Math.max(1,Math.floor(n/2)):0;
  for(j=0;j<nb;j++){u=1-(((T/(dur*1.3))+j/nb+.31+i*.07)%1);for(tr=4;tr>=0;tr--){uu=u+tr*.012;if(uu>1)continue;p=bz(uu);c.fillStyle='rgba(111,231,255,'+(tr?(.45*(1-tr/5)).toFixed(3):'.95')+')';c.beginPath();c.arc(p.x,p.y,tr?1.8:2.2,0,TAU);c.fill()}}
  // arrival ripples at the exit, launch ring at the entry
  if(up||part){var ph=((T/dur)*Math.max(1,n))%1;c.strokeStyle=tmA(col,((1-ph)*.55*flick).toFixed(3));c.lineWidth=1.6;c.beginPath();c.arc(m.pos[x.exit].x,m.pos[x.exit].y,25+ph*22,0,TAU);c.stroke();
   var ph2=((T/dur)*Math.max(1,n)+.5)%1;c.strokeStyle=tmA(th.al,((1-ph2)*.35*flick).toFixed(3));c.beginPath();c.arc(m.pos[x.entry].x,m.pos[x.entry].y,25+ph2*12,0,TAU);c.stroke()}
  // the lock in the middle (encryption), lights up when a packet passes
  var L0=bz(lt);if(!down){var hr=10+lockHot*2.5;c.save();c.translate(L0.x,L0.y);
   if(lockHot>0){c.fillStyle=tmA(col,(.3*lockHot).toFixed(3));c.beginPath();c.arc(0,0,hr+9,0,TAU);c.fill()}
   c.beginPath();for(var hx=0;hx<6;hx++){var aa=Math.PI/6+hx*Math.PI/3;c[hx?'lineTo':'moveTo'](Math.cos(aa)*hr,Math.sin(aa)*hr)}c.closePath();c.fillStyle=th.disc;c.fill();c.strokeStyle=tmA(col,(.6+.4*lockHot).toFixed(3));c.lineWidth=1.6;c.stroke();
   c.strokeStyle=tmA(tmMix(col,[255,255,255],lockHot*.6),.95);c.lineWidth=1.4;c.beginPath();c.arc(0,-1.5,2.6,Math.PI,0);c.stroke();c.fillStyle=c.strokeStyle;c.fillRect(-3.6,-1.2,7.2,5.2);c.restore()}
  // label: transport · ping
  // label: short name • ping in the middle of the line; tunnels between the same two servers share one
  // stacked label (drawn once, by the first of them) so their texts never cover each other
  if(m.L[x.id]){var bp=m.L[x.id];
   labs.push(function(){var zr=es.rtt_ms||0,zc=tmRgb(tunCol(x.state)),l1=tmShort(x),l2=x.state=='down'||x.state=='off'?t('down'):zr?zr+'ms':'…';
    c.direction='ltr';c.textAlign='center';c.font='800 10.5px Vazirmatn,sans-serif';var lw=Math.max(c.measureText(l1).width,c.measureText(l2).width)+16,lh=31;
    c.fillStyle=th.disc;tmRound(c,bp.x-lw/2,bp.y-lh/2,lw,lh,9);c.fill();c.strokeStyle=tmA(zc,.7);c.lineWidth=1;c.stroke();
    c.fillStyle=th.t;c.fillText(l1,bp.x,bp.y-2);c.font='700 10px Vazirmatn,sans-serif';c.fillStyle=tmA(zc,1);c.fillText(l2,bp.x,bp.y+11)})}});
 labs.forEach(function(f){f()});
 // ---- servers
 m.sv.forEach(function(s,i){var P=m.pos[s.id];if(!P)return;var col=tmRgb(s.online?'#3ddc97':'#ff6b6b'),br=.5+.5*Math.sin(T*2.1+i),Z=s.id==m.hub?1.25:1;c.save();c.translate(P.x,P.y);c.scale(Z,Z);c.translate(-P.x,-P.y);
  if(s.online){var hg=c.createRadialGradient(P.x,P.y,10,P.x,P.y,46);hg.addColorStop(0,tmA(col,(.16+.08*br).toFixed(3)));hg.addColorStop(1,tmA(col,0));c.fillStyle=hg;c.beginPath();c.arc(P.x,P.y,46,0,TAU);c.fill();
   c.setLineDash([3,9]);c.lineDashOffset=-T*9;c.strokeStyle=tmA(col,.5);c.lineWidth=1.4;c.beginPath();c.arc(P.x,P.y,33,0,TAU);c.stroke();c.setLineDash([]);
   c.save();c.translate(P.x,P.y);c.rotate(-.35);c.strokeStyle=tmA(th.a,.35);c.lineWidth=1;c.beginPath();c.ellipse(0,0,39,13,0,0,TAU);c.stroke();
   var sa=T*1.15+i;c.fillStyle=tmA(th.al,.95);c.beginPath();c.arc(Math.cos(sa)*39,Math.sin(sa)*13,2.2,0,TAU);c.fill();c.restore()}
  else{var fo=.4+.4*Math.abs(Math.sin(T*3+i));c.strokeStyle=tmA(col,fo.toFixed(3));c.lineWidth=1.4;c.setLineDash([2,5]);c.beginPath();c.arc(P.x,P.y,31,0,TAU);c.stroke();c.setLineDash([])}
  c.save();c.shadowColor=tmA(col,.7);c.shadowBlur=12;c.fillStyle=th.disc;c.beginPath();c.arc(P.x,P.y,24,0,TAU);c.fill();c.restore();
  c.strokeStyle=tmA(col,.95);c.lineWidth=2;c.beginPath();c.arc(P.x,P.y,24,0,TAU);c.stroke();
  var cg=c.createRadialGradient(P.x-5,P.y-6,2,P.x,P.y,18);cg.addColorStop(0,'#fff7d6');cg.addColorStop(.45,tmA(th.al,1));cg.addColorStop(1,tmA(th.ad,1));c.fillStyle=s.online?cg:'rgba(140,140,150,.55)';c.beginPath();c.arc(P.x,P.y,17,0,TAU);c.fill();
  c.fillStyle='#2a1d06';c.font='900 14px Vazirmatn,sans-serif';c.textAlign='center';c.fillText((s.local?'★':s.name.charAt(0)).toUpperCase(),P.x,P.y+5);
  c.fillStyle=tmA(col,1);c.strokeStyle=th.disc;c.lineWidth=2;c.beginPath();c.arc(P.x+18,P.y-18,5,0,TAU);c.fill();c.stroke();c.restore();
  var mx=m.mx||(m.n>9?10:14),nm0=(m.ab&&m.ab[s.id])||s.name,nm=nm0.length>mx?nm0.slice(0,mx-1)+'…':nm0;c.font='700 12.5px Vazirmatn,sans-serif';var nw=c.measureText(nm).width+12,ny=s.id!=m.hub&&P.y<m.cy-20?P.y-24*Z-14:P.y+24*Z+19; // the name on the outer side, away from the lines
  c.fillStyle=tmA(tmRgb(th.disc),.72);tmRound(c,P.x-nw/2,ny-13,nw,18,9);c.fill();c.fillStyle=th.t;c.textAlign='center';c.direction=/[\u0600-\u06FF]/.test(nm)?'rtl':'ltr';c.fillText(nm,P.x,ny)})};

})();

// ==================================================================== the look: menu, rails, cards
// the menu and motion: side menu groups that open and close (or the whole menu in one row across the
// top), the Cores rail of cards with a server's settings right below its chip, users in two columns
// of slim cards, and pages that come in card by card.
(function(){
'use strict';
var V=V37;
var CHEV='<svg class="kd-chev" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>';
function store(k,v){try{if(v===undefined)return localStorage.getItem(k);localStorage.setItem(k,v)}catch(e){}return null}

// ---------------------------------------------------------------- side menu: groups that open and close
var GOPEN={};try{GOPEN=JSON.parse(store('kk_navg')||'{}')||{}}catch(e){}
function groups(){var gs=[];V.SECS.forEach(function(s){var g=gs[gs.length-1];if(!g||g.l!=s[4])gs.push(g={l:s[4],s:[]});g.s.push(s)});return gs}
function href(f){return '#'+f[0]+(f[1]?'/'+f[1]:'')}
window.navSide=function(){var cur=V.secOf(S.page)[0];
 return groups().map(function(g){var open=GOPEN[g.l]!==false||g.s.some(function(x){return x[0]==cur});
  return '<div class="kd-g'+(open?' open':'')+'" data-g="'+esc(g.l)+'"><button type="button" class="kd-gh" aria-expanded="'+open+'"><span>'+t(g.l)+'</span>'+CHEV+'</button>'+
   '<div class="kd-gb"><div class="kd-gbi">'+g.s.map(function(s,i){var f=s[3][0];
    return '<a href="'+href(f)+'" data-p="'+f[0]+'" data-sec="'+s[0]+'" class="kd-it d'+Math.min(5,i+1)+'" title="'+esc(t(s[1]))+'"><span class="ni">'+ic(s[2],18)+'</span><span class="kd-l">'+t(s[1])+'</span></a>'}).join('')+
   '</div></div></div>'}).join('')};
document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('.kd-gh');if(!b)return;
 var g=b.parentNode,o=!g.classList.contains('open');g.classList.toggle('open',o);b.setAttribute('aria-expanded',o);GOPEN[g.dataset.g]=o;store('kk_navg',JSON.stringify(GOPEN))});

// ---------------------------------------------------------------- the menu across the top
function topNav(){return '<nav class="kd-top" id="kdtop" aria-label="'+esc(t('Top menu'))+'">'+groups().map(function(g){
  return '<span class="kd-sep">'+t(g.l)+'</span>'+g.s.map(function(s){var f=s[3][0];return '<a href="'+href(f)+'" data-sec="'+s[0]+'" class="kd-tn"><span class="ni">'+ic(s[2],17)+'</span>'+t(s[1])+'</a>'}).join('')}).join('')+'</nav>'}
// drag a row sideways with the mouse (fingers scroll it by themselves); a drag is not a click
function dragRow(el){if(!el||el._kd)return;el._kd=1;var d=null,moved=false;
 el.addEventListener('pointerdown',function(e){if(e.pointerType!='mouse')return;d={x:e.clientX,l:el.scrollLeft};moved=false});
 el.addEventListener('pointermove',function(e){if(!d)return;var dx=e.clientX-d.x;if(Math.abs(dx)>5)moved=true;if(moved){el.scrollLeft=d.l-dx;el.classList.add('kd-drag')}});
 var up=function(){d=null;setTimeout(function(){el.classList.remove('kd-drag')},0)};el.addEventListener('pointerup',up);el.addEventListener('pointerleave',up);
 el.addEventListener('click',function(e){if(moved){e.preventDefault();e.stopPropagation();moved=false}},true)}
function look(){document.body.classList.add('kd');document.body.classList.toggle('kd-mini',store('kk_mini')=='1');document.body.classList.toggle('kd-topm',store('kk_menu')=='top');
 $$('.kd-lay button').forEach(function(b){b.classList.toggle('on',(b.dataset.m=='top')==(store('kk_menu')=='top'))})}
window.kdMenu=function(m){store('kk_menu',m);look();markAll()};
window.kdMini=function(){store('kk_mini',store('kk_mini')=='1'?'0':'1');look()};
window.shell=function(){var me=S.me||{},nm=me.panel_name||'Kanki Panel',L=nm.charAt(0);
 $('#app').innerHTML='<header class="top"><div class="'+logoCls()+'" id="mlogo">'+logoInner(L)+'</div>'+
 '<div class="tb-title"><small><span>'+esc(nm)+'</span><span>›</span><span id="tbsec"></span></small><b id="tbt"></b></div><div class="sp"></div>'+
 '<div class="tb-act"><div class="kd-lay" role="group" aria-label="'+esc(t('Top menu'))+'"><button type="button" data-m="side" onclick="kdMenu(\'side\')">'+t('Side menu')+'</button><button type="button" data-m="top" onclick="kdMenu(\'top\')">'+t('Top menu')+'</button></div><div class="segl"><button data-l="fa" class="'+(S.lang=='fa'?'on':'')+'">FA</button><button data-l="en" class="'+(S.lang=='en'?'on':'')+'">EN</button></div>'+
 '<button class="ib" id="thm" title="'+t('Theme')+'" aria-label="theme">'+ic('moon',17)+'</button>'+
 '<button class="ib" id="upd" title="'+t('Update')+'"><span class="dot" id="updot"></span><span class="uv ltr">v'+esc(me.version||'')+'</span></button>'+
 '<div class="uchip2" title="'+esc(me.user||'')+'"><i>'+esc((me.user||'A').charAt(0).toUpperCase())+'</i><span>'+esc(me.user||'')+'</span></div>'+
 '<button class="ib" id="lo" title="'+t('Logout')+'" aria-label="logout">'+ic('logout',17)+'</button></div></header>'+topNav()+
 '<nav class="side" id="side"><div class="sbrand"><div class="'+logoCls()+'">'+logoInner(L)+'</div><div style="min-width:0"><b>'+esc(nm)+'</b><small>'+t('VPN management')+'</small></div>'+
  '<button type="button" class="kd-fold" onclick="kdMini()" aria-label="'+esc(t('Fold the menu'))+'" title="'+esc(t('Fold the menu'))+'">'+CHEV+'</button></div>'+
 '<div class="snav">'+navSide()+'</div>'+
 '<div class="sfoot"><button class="sver" id="upd2"><span class="dot" id="updot2"></span><span><b class="ltr">v'+esc(me.version||'')+'</b><small id="updt">'+t('Check for update')+'</small></span></button>'+
 '<a href="#" id="lo2" class="lo2"><span class="ni">'+ic('logout',18)+'</span>'+t('Logout')+'</a></div></nav><div class="shade" id="shade"></div>'+navBar()+'<main id="pg"></main>';
 $('#shade').onclick=function(){$('#side').classList.remove('on');$('#shade').classList.remove('on')};
 $('#msheet').onclick=function(e){if(e.target.closest('a'))navMark(S.page,S.sub)};
 if(!window._navDoc){window._navDoc=1;document.addEventListener('click',function(e){var sh=$('#msheet');if(sh&&sh.classList.contains('on')&&!e.target.closest('#msheet,#mbar'))navMark(S.page,S.sub)})}
 $$('[data-l]').forEach(function(b){b.onclick=function(){S.lang=b.dataset.l;localStorage.setItem('kk_lang',S.lang);applyLook();shell();route()}});
 $('#thm').onclick=function(){S.theme=S.theme=='light'?'dark':'light';localStorage.setItem('kk_theme',S.theme);applyLook()};
 $('#lo').onclick=function(){logout()};$('#lo2').onclick=function(e){e.preventDefault();logout()};
 $('#upd').onclick=updateModal;$('#upd2').onclick=function(){$('#shade').click();location.hash='#settings';S.stsec='upd';if(S.page=='settings')route()};
 // page headers get the page icon, whenever a page draws (or redraws) its header
 new MutationObserver(decoratePh).observe($('#pg'),{childList:true,subtree:true});
 api('GET','/api/update/check').then(function(r){var c='dot '+(r.available?'y':(r.error?'':'g'));
  ['#updot','#updot2'].forEach(function(x){var d=$(x);if(d)d.className=c});
  var u=$('#updt');if(u)u.textContent=r.available?t('A new version is available.'):(r.error?t('Update source not set'):t('You are on the latest version.'))}).catch(function(){});
 document.body.classList.add('v37','k38');V.watchPg();V.drawLooks();dragRow($('#kdtop'));look()};
function markAll(){var sk=V.secOf(S.page)[0];
 $$('#kdtop a[data-sec]').forEach(function(a){a.classList.toggle('on',a.dataset.sec==sk)});
 var on=$('#kdtop a.on');if(on&&document.body.classList.contains('kd-topm'))try{on.scrollIntoView({block:'nearest',inline:'center'})}catch(e){}
 var a=$('#side a.on'),g=a&&a.closest('.kd-g');if(g&&!g.classList.contains('open')){g.classList.add('open');var b=$('.kd-gh',g);if(b)b.setAttribute('aria-expanded','true')}}
// the open section lit in every menu, its tabs on top of the page
window.navMark=function(p){var sk=V.secOf(p)[0];
 $$('#side a[data-sec],#mbar a[data-sec]').forEach(function(a){a.classList.toggle('on',a.dataset.sec==sk)});
 V.drawSecTabs(p);k38More(0);
 // the open section stays in sight in the scrolling bar
 var a=document.querySelector('#mbar a[data-sec="'+sk+'"]');if(a&&a.scrollIntoView)try{a.scrollIntoView({block:'nearest',inline:'center'})}catch(e){}
 V.markTabs();markAll()};

// ---------------------------------------------------------------- pages
window.route=function(){var hs=location.hash||'';
 // old addresses
 if(hs=='#xray'){location.replace('#xray/overview');return}
 if(hs.slice(1).split('/')[0]=='servers'){location.replace('#nodes');return}
 Object.keys(KAcc.open).forEach(function(k){KAcc.open[k]=''});
 var h=(hs||'#dash').slice(1).split('/'),p=h[0];S.sub=h[1]||'';if(!PAGES.some(function(x){return x[0]==p})){p='dash';S.sub=''}S.page=p;
 var tb=$('#tbt');if(tb){tb.textContent=t(pgOf(p)[1]);$('#tbsec').textContent=t(grpOf(p))}
 navMark(p,S.sub);clearInterval(S.timer);clearInterval(S.timer2);clearInterval(S.timer3);clearInterval(S.timer4);window.scrollTo(0,0);
 (({dash:pDash,users:pUsers,nodes:pNodes,servers:pServers,tunnels:pTunnels,traffic:pTraffic,ports:pPorts,bot:pBot,emergency:pEmergency,backup:pBackup,security:pSecurity,settings:pSettings})[p]||window['p_'+p])();
 V.watchPg();V.drawSecTabs(S.page);
 // every page comes in card by card
 var pg=$('#pg');if(pg){pg.classList.remove('kd-enter');void pg.offsetWidth;pg.classList.add('kd-enter');clearTimeout(pg._kd);pg._kd=setTimeout(function(){pg.classList.remove('kd-enter')},1400)}
 document.body.classList.toggle('kd-vpn',V.secOf(S.page)[0]=='vpnsec')};

// ---------------------------------------------------------------- Cores: a rail of cards
var CORE={vpn:['dash','All cores at a glance','#F5C451'],kmix:['game','Games · low ping','#ff8a2a'],xray:['xray','VLESS · VMess · Trojan','#6fb6ff'],wg:['shield2','Plain and fast','#3ddc97'],
 awg:['shield2','Obfuscated WireGuard','#a78bfa'],hy2:['shield2','QUIC · lossy internet','#f472b6'],antidpi:['security','REALITY · CDN','#2fd6d6'],dns:['dns','Blocked sites only','#F5C451']};
function dressRail(){var st=$('#sectabs');if(!st||V.secOf(S.page)[0]!='vpnsec')return;
 if(!st.classList.contains('kd-rail')){st.classList.add('kd-rail');
  $$('.stl a',st).forEach(function(a){var p=(a.getAttribute('href')||'').slice(1).split('/')[0],m=CORE[p]||['cores','',''],name=a.textContent;
   a.style.setProperty('--cc',m[2]||'#F5C451');a.innerHTML='<span class="kd-ci">'+ic(m[0],20)+'</span><b>'+esc(name)+'</b><small>'+esc(t(m[1]))+'</small>'});
  dragRow($('.stl',st))}
 var on=$('.stl a.on',st);if(on&&on!==st._on){st._on=on;try{on.scrollIntoView({block:'nearest',inline:'center',behavior:st._seen?'smooth':'auto'})}catch(e){}st._seen=1}}
// under a core: its servers are a row of country chips you swipe sideways; the picked one's settings
// show below the row (the list itself keeps only the open server, without its header)
var AUTO={};
function railSig(rows){return rows.map(function(r){return r.dataset.key+(r.classList.contains('open')?'*':'')+$('.kxr-h',r).textContent}).join('|')}
// a chip: the flag (with 1, 2 … when one country has more servers), and three small letters: P the panel
// server (green), VPN this core runs there (green) or not (grey), T it has a tunnel (green) or not (grey)
function chipsHtml(rows){var cnt={},seen={};
 var info=rows.map(function(r){var h=$('.kxr-h',r),f=$('.flg',h),cc=f?(f.getAttribute('title')||''):'',st=$$('.kxr-st',h),tw=t('tunnel');
  cnt[cc]=(cnt[cc]||0)+1;return {r:r,f:f?f.outerHTML:'',cc:cc,name:(($('b',h)||{}).textContent||'').trim(),main:!!$('.kxc-tag.main',h),
   run:!!(st[0]&&st[0].classList.contains('g')&&st[0].textContent.indexOf(tw)<0),tun:st.some(function(x){return x.textContent.indexOf(tw)>=0})}});
 return info.map(function(x){var n='';if(cnt[x.cc]>1){seen[x.cc]=(seen[x.cc]||0)+1;n='<sup>'+N(seen[x.cc])+'</sup>'}
  return '<button type="button" class="kd-chip'+(x.r.classList.contains('open')?' on':'')+'" data-key="'+esc(x.r.dataset.key)+'" title="'+esc(x.name)+'" aria-label="'+esc(x.name)+'">'+
   '<span class="kd-cf">'+x.f+n+'</span><span class="kd-cl">'+(x.main?'<i class="g">P</i>':'')+'<i class="'+(x.run?'g':'')+'">VPN</i><i class="'+(x.tun?'g':'')+'">T</i></span></button>'}).join('')}
function chips(){if(!document.body.classList.contains('kd-vpn'))return;
 $$('#pg .kxl').forEach(function(l){var rows=$$(':scope>.kxr',l);if(!rows.length||!rows[0].dataset.acc)return;var g=rows[0].dataset.acc;
  l.classList.add('kd-rows');var rail=l.previousElementSibling;
  if(!rail||!rail.classList.contains('kd-crail')){rail=document.createElement('div');rail.className='kd-crail';l.parentNode.insertBefore(rail,l);dragRow(rail);
   rail.addEventListener('click',function(e){var b=e.target.closest('[data-key]');if(!b)return;var r=$$(':scope>.kxr',l).filter(function(x){return x.dataset.key==b.dataset.key})[0],h=r&&$('.kxr-h',r);if(h)h.click()})}
  var sig=railSig(rows);if(rail._sig!==sig){rail._sig=sig;
   rail.innerHTML=chipsHtml(rows);
   var on=$('.kd-chip.on',rail);if(on)try{on.scrollIntoView({block:'nearest',inline:'center',behavior:rail._seen?'smooth':'auto'})}catch(e){}rail._seen=1}
  // (no server is opened by itself: a server's settings open only when its chip is tapped)
  })}
window.addEventListener('hashchange',function(){AUTO={}});
// Servers page: two columns of slim cards with a pencil; a tap opens the server's settings in the side drawer
var PEN='<span class="kd-pen" aria-hidden="true"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M14 6l4 4"/></svg></span>';
function servers(){var g=$('#svp_g');if(!g||S.page!='nodes')return;g.classList.add('k310cards','kd-srv');
 $$('.kxr[data-acc] > .kxr-h',g).forEach(function(h){if(!$('.kd-pen',h))h.insertAdjacentHTML('beforeend',PEN)})}
// Anti-DPI: the methods fold to one line (name, tags, make); a tap shows what each one is for
function antidpi(){if(S.page!='antidpi')return;$$('#pg .g2>.box').forEach(function(b){if(b.classList.contains('kd-tpl'))return;b.classList.add('kd-tpl');
 b.addEventListener('click',function(e){if(e.target.closest('button'))return;b.classList.toggle('open')})})}
// Xray's own tabs: one row you swipe sideways
function xrTabsRow(){var x=$('#xr_tabs');if(x&&!x._kd){x.classList.add('kd-xtabs');dragRow(x)}}
// REALITY: test the suggested targets from the panel server and mark the ones that work
function reality(){var sel=$('#xi_dp');if(!sel||$('#kd_rt'))return;
 sel.insertAdjacentHTML('afterend','<button type="button" class="b2 sm" id="kd_rt">'+t('Test the sites')+'</button>');
 $('.inl',$('#xi_rl')).insertAdjacentHTML('afterend','<div id="kd_rtl" class="kd-rtl"></div>');
 $('#kd_rt').onclick=function(){var b=this,box=$('#kd_rtl');b.disabled=true;b.textContent=t('Testing…');box.innerHTML='';
  api('POST','/api/xray/reality/test',{targets:REALITY_TARGETS}).then(function(r){b.disabled=false;b.textContent=t('Test again');
   var res=(r.results||[]).sort(function(a,c){return (c.ok-a.ok)||((a.ms||9e9)-(c.ms||9e9))});
   box.innerHTML='<small class="muted">'+t('Tested from the panel server: TLS 1.3, a valid certificate and HTTP/2. Tap one to use it.')+'</small><div class="kd-rtg">'+res.map(function(x){var h=x.target.split(':')[0];
    return '<button type="button" class="kd-rt '+(x.ok?'ok':x.tls13?'mid':'bad')+'" data-t="'+esc(x.target)+'" title="'+esc(x.error||'')+'"><i>'+(x.ok?'✓':'✕')+'</i><span class="ltr">'+esc(h)+'</span>'+(x.ms?'<small class="ltr">'+N(x.ms)+'ms</small>':'')+(/\.ir$/.test(h)?'<em>IR</em>':'')+'</button>'}).join('')+'</div>';
   $$('.kd-rt',box).forEach(function(c){c.onclick=function(){$('#xi_de').value=c.dataset.t;$('#xi_na').value=c.dataset.t.split(':')[0];$$('.kd-rt',box).forEach(function(z){z.classList.toggle('pick',z==c)})}})}).catch(function(e){b.disabled=false;b.textContent=t('Test the sites');fail(e)})}}
// the dashboard numbers get a turning edge in their own colour
function kpiEdges(){$$('#kpis .kpi').forEach(function(k){if(!$('.kd-edge',k))k.insertAdjacentHTML('beforeend','<i class="kd-edge" aria-hidden="true"></i>')})}
// every turning edge turns in step with the others, and a redraw does not send it back to the start
var EDGE='.kd-it.on,.kd-tn.on,.kd-rail .stl a.on,.kd-chip.on,.uchip.kd-u,#st .stn button.on,.k310st,.kd-edge,.kxr[data-acc="srv"]>.kxr-h';
function phase(){var ph=-((Date.now()/1000)%3.2);$$(EDGE).forEach(function(e){if(!e._kdph){e._kdph=1;e.style.setProperty('--kdph',ph.toFixed(2)+'s')}})}
// whatever a page draws is dressed right away: number icons, tab marks, drawers, rails and chips
new MutationObserver(function(){if($('#kpis'))V.kpiIcons();if($('#sectabs'))V.markTabs();V.drawerDress();if($('#sectabs'))dressRail();if(document.body.classList.contains('kd-vpn'))chips();servers();antidpi();xrTabsRow();reality();kpiEdges();phase()}).observe(document.body,{childList:true,subtree:true});

// ---------------------------------------------------------------- users: two columns, data and expiry date
 window.uchip=function(u){var st=ustate(u),lv=liveOf(u),on=u.online_connections>0||lv.length>0,dot=st=='disabled'?'r':st=='finished'?'y':(on?'g':''),ps=[];
  lv.forEach(function(c){if(ps.indexOf(c.p)<0)ps.push(c.p)});
  var pc=usage(u),used=(+u.traffic_used_gb||0).toFixed(1),exp=st=='disabled'?t('Disabled'):!u.expires_ts?'∞':u.expires_ts<Date.now()/1000?t('Expired'):jdate(u.expires_ts);
  return '<button class="uchip kd-u st-'+st+(on?' on':'')+(S.sel[u.id]?' sel':'')+'" data-id="'+u.id+'" title="'+esc(u.username)+'">'+
   '<span class="kd-un"><span class="dot '+dot+'"></span><span class="nm">'+esc(u.username)+'</span>'+
   (ps.length?'<span class="lvs">'+liveBadges(lv)+'</span>':'')+
   '<span class="tick">'+ic('check',13)+'</span></span>'+
   '<span class="k310bar'+(pc<0?' inf':pc>=90?' hot':pc>=70?' warm':'')+'"><i style="width:'+(pc<0?100:Math.max(3,pc))+'%"></i></span>'+
   '<span class="kd-meta"><span>'+t('Data')+' <b class="ltr">'+N(used)+(pc<0?' GB / ∞':' / '+N(u.traffic_limit_gb)+' GB')+'</b></span><span>'+t('Expires')+' <b>'+exp+'</b></span></span></button>'};

look();
})();

/* 3.13 — what a delete left to do on each server, live: a small card at the bottom lists every
   server's part (stop the tunnel, remove everything, remove the VPN services) with a spinner,
   a tick when that server confirmed it, or "off" (it is done when the server comes back). */
(function(){
var fa=function(){return (document.documentElement.dir||'rtl')=='rtl'};
function L(p,e){return fa()?p:e}
var RM={},timer=0,started=0;
var WHAT={tunnel:['توقف تانل و آزاد کردن پورت‌ها','stop the tunnel, free its ports'],
 server:['پاک کردن همه‌چیز و حذف خودِ سرور','remove everything and uninstall'],
 node:['حذف سرویس‌های VPN و بستن پورت‌ها','remove the VPN services, close ports'],
 xray:['حذف Xray و بستن پورت‌هایش','remove Xray, close its ports'],
 dns:['حذف DNS کانکی و بستن پورت‌هایش','remove Kanki DNS, close its ports']};
var KIND={tunnel:['تانل','tunnel'],server:['سرور','server'],node:['سرور','server'],xray:['Xray','Xray'],dns:['DNS','DNS']};
function esc2(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function box(){var b=document.getElementById('kdrm');if(!b){b=document.createElement('div');b.id='kdrm';b.setAttribute('role','status');b.setAttribute('aria-live','polite');document.body.appendChild(b);
 b.onclick=function(e){if(e.target.closest('.kdrm-x'))close()}}return b}
function close(){var b=document.getElementById('kdrm');if(b){b.classList.remove('on');setTimeout(function(){if(!b.classList.contains('on'))b.remove()},350)}RM={};clearTimeout(timer);timer=0}
function draw(){
 var ids=Object.keys(RM);if(!ids.length)return;
 var all=true,h='';
 ids.forEach(function(id){var r=RM[id].r;if(!r){all=false;return}
  var w=KIND[r.kind]||KIND.server;
  h+='<div class="kdrm-g"><div class="kdrm-n">'+esc2(L(w[0],w[1]))+' <b>'+esc2(r.name)+'</b></div>';
  if(!r.steps.length)h+='<div class="kdrm-r done"><i></i><span>'+L('از پنل حذف شد','removed from the panel')+'</span></div>';
  r.steps.forEach(function(s){if(s.state!='done')all=false;var d=WHAT[s.what]||WHAT.server;
   var tail=s.state=='done'?L('پاک شد','removed'):s.state=='off'?L('خاموش است؛ وقتی برگردد پاک می‌شود','off — removed when it is back'):L('در حال حذف…','removing…');
   h+='<div class="kdrm-r '+s.state+'"><i></i><span><b>'+esc2(s.name)+'</b> · '+esc2(L(d[0],d[1]))+'<em>'+tail+'</em></span></div>'});
  h+='</div>'});
 var late=Date.now()-started>180000;
 var title=all?L('همه‌چیز پاک شد ✓','everything removed ✓'):late?L('بقیه در پس‌زمینه انجام می‌شود','the rest goes on in the background'):L('در حال حذف از سرورها…','removing from the servers…');
 var b=box();b.className='on'+(all?' all':'');
 b.innerHTML='<div class="kdrm-h"><span class="kdrm-sp"></span><b>'+title+'</b><button class="kdrm-x" aria-label="'+L('بستن','close')+'">✕</button></div>'+h;
 return all||late}
function poll(){timer=0;var ids=Object.keys(RM);if(!ids.length)return;
 Promise.all(ids.map(function(id){return window.api('GET','/api/removals/'+encodeURIComponent(id)).then(function(r){if(RM[id])RM[id].r=r}).catch(function(){if(RM[id]&&!RM[id].r)delete RM[id]})})).then(function(){
  var fin=draw();
  if(document.querySelector('#kdrm.all')){timer=setTimeout(close,3500);return}
  // after three minutes it stops asking; what is left is done when those servers come back
  if(!fin)timer=setTimeout(poll,2000)})}
function follow(rid){if(!rid)return;if(!Object.keys(RM).length)started=Date.now();RM[rid]={r:null};clearTimeout(timer);timer=setTimeout(poll,600)}
window.kdFollowRemoval=follow;
})();

// ==================================================================== start
applyLook();if(S.token)boot();else loginView();
