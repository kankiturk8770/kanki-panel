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
var FW_NAMES={tunnels:'Tunnels',dns:'Kanki DNS',xray:'Xray',kmix:'KANKI MIX',subsrv:'Subscription link',acme:'SSL (port 80)'};
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
function p_vpn(){$('#pg').innerHTML='<div class="ku">'+kuHead('cores',t('VPN & cores'),t('Every core your users get, each on its own card'))+'<div id="vh_s"></div><div id="vh_g">'+skel()+'</div>'+
  '<section class="card kv-svc"><div class="kc-h"><div><h3>'+t('Tools & background services')+'</h3><small class="muted">'+t('Start, stop or restart the VPN services')+'</small></div></div>'+
  '<a class="kv-tool" href="#xray/inbounds" style="--pc:'+PCOL.xray+'"><span class="cci">'+ic('security',18)+'</span><span><b>'+t('Anti-DPI inbounds')+'</b><small>'+t('REALITY, CDN and the other presets of the Xray inbound editor')+'</small></span><span class="kv-go" aria-hidden="true">'+ic('chev',16)+'</span></a>'+
  '<a class="kv-tool" href="#tunnels" style="--pc:'+PCOL.awg+'"><span class="cci">'+ic('tunnel',18)+'</span><span><b>'+t('Anti-DPI transports')+'</b><small>'+t('Tunnels between your servers that filters cannot see')+'</small></span><span class="kv-go" aria-hidden="true">'+ic('chev',16)+'</span></a>'+
  '<div id="svcs" class="svcs"><span class="muted">'+t('Loading…')+'</span></div></section></div>';
 $('#svcs').onclick=function(e){var b=e.target.closest('[data-svc]');if(b&&!b.disabled)svc(b.dataset.svc,b.dataset.act)};sysSvcLoad();
 var go=function(){Promise.all([api('GET','/api/nodes').catch(function(){return []}),api('GET','/api/overview').catch(function(){return {}}),api('GET','/api/xray').catch(function(){return null}),api('GET','/api/dns').catch(function(){return null})]).then(function(r){if(S.page!='vpn')return;S.nodes=r[0]||[];if(r[2])XR.d=r[2];if(r[3])DN.d=r[3];vhGrid(r[0]||[],r[1]||{},r[2],r[3])})};
 go();clearInterval(S.timer);S.timer=setInterval(function(){if(document.visibilityState=='visible'&&!$('#modal').classList.contains('on'))go()},refreshMs())}
// one card per core (3.34): status, servers running it and users; the whole card opens the core's own page
function vhGrid(nodes,o,xr,dn){var el=$('#vh_g');if(!el)return;var pr=o.protocols||{};
 var up=function(n){return n.id=='local'||n.online},num=function(v){return v!=null&&v!==''&&+v>0};
 // servers that run a core (the agent reports its port) and how many of them are up
 var on=function(k){var l=nodes.filter(function(n){return num((n.info||{})[k])});return [l.filter(up).length,l.length]};
 var K=[['wg','WireGuard','shield2','Standard and fast; through Iran only',on('wg_port')],['awg','AmneziaWG','security','WireGuard with hidden packets; direct or through Iran',on('awg_port')],
  ['hy2','Hysteria2','globe','QUIC, fast on weak internet',on('hy2_port')],['kmix','KANKI MIX','game','Kanki\'s own game protocol, low ping',on('kmix_port')]];
 var card=function(href,col,icon,name,sub,st,stats){return '<a class="ccard" href="'+href+'" style="--pc:'+col+'"><div class="cc1"><span class="cci">'+ic(icon,20)+'</span><span class="ccs '+st[0]+'"><i></i>'+st[1]+'</span></div>'+
  '<b class="ccn">'+name+'</b><small class="ccd">'+t(sub)+'</small><div class="ccst">'+stats.map(function(x){return '<div><small>'+x[0]+'</small><b class="ltr">'+x[1]+'</b></div>'}).join('')+'</div></a>'};
 var state=function(u,all){return all==0?['n',t('Not installed')]:u==all?['g',t('Running')]:u==0?['r',t('Down')]:['y',t('Partly down')]};
 // (3.57) three groups: the game cores, the VPN cores, the services; each card as tall as the others
 var by={};K.forEach(function(c){var u=c[4][0],all=c[4][1];by[c[0]]=card('#'+c[0],PCOL[c[0]],c[2],c[1],c[3],state(u,all),[[t('Servers'),N(u)+' / '+N(all)],[t('Users'),N(pr[c[0]]||0)]])});
 var sv='';
 if(xr){var act=xr.inbounds.filter(function(x){return x.enabled&&!x.state}).length;
  sv+=card('#xray/status',PCOL.xray,'xray','Xray','VLESS · VMess · Trojan · Shadowsocks',xr.on?(act?['g',t('Running')]:['y',t('No inbound')]):['r',t('Off')],[[t('Inbounds'),N(act)+' / '+N(xr.inbounds.length)],[t('Online now'),N((xr.online||[]).length)]])}
 if(dn){var run=dn.servers.filter(function(x){return x.status&&x.status.active}).length;
  sv+=card('#dns/overview',PCOL.dns,'dns','Kanki DNS','Private DNS for sanctioned sites',dn.on?(run?['g',t('Running')]:['y',t('No server')]):['r',t('Off')],[[t('Servers'),N(run)+' / '+N(dn.servers.length)],[t('Users'),N(dn.users||0)]])}
 var grp=function(title,keys,extra){var c=keys.map(function(k){return by[k]||''}).join('')+(extra||'');return c?'<section class="cgrp"><h3 class="cgrp-h">'+t(title)+'</h3><div class="cgrid">'+c+'</div></section>':''};
 el.innerHTML=grp('Game cores',['kmix'])+grp('VPN cores',['wg','awg','hy2'])+grp('Services',[],sv);
 var ups=nodes.filter(up).length,s=$('#vh_s');
 var ex=nodes.filter(function(n){return n.enabled!==false&&n.role!='panel'&&n.role!='iran'}),exUp=ex.filter(up).length;
 if(s)s.innerHTML=kuStats([[t('VPN exits online'),N(exUp)+' / '+N(ex.length),exUp<ex.length?'warn':'ok'],[t('Online now'),N(o.online||0),'ok'],[t('Total traffic'),'<span class="ltr">'+N(o.traffic_gb||0)+' GB</span>'],[t('Users'),N(o.users||0)]])}

// ---------------------------------------------------------------- user form: tier and one switch per core (3.64)
// The tier says what the user bought (3.70: one account, one code, three plans): only the tier's cores can be
// switched on; a core outside the tier is locked (the server refuses it too). Ticking a tier ticks its cores.
var TIER_NAMES={v2ray:'Anti-filter V2Ray',gaming:'Gaming WireGuard',vip:'VIP All-in-One'};
var TIER_CORES={v2ray:['xray','hy2'],gaming:['kmix','awg','wg','dns'],vip:['xray','hy2','kmix','awg','wg','dns']};
function tierKey(k){return k=='combo'?'vip':(TIER_CORES[k]?k:'')}
var UF_CORES=[['wg','WireGuard','shield2'],['awg','AmneziaWG','security'],['kmix','KANKI MIX','game'],['hy2','Hysteria2','globe'],['xray','Xray','xray'],['dns','Kanki DNS','dns']];
function tierOfProtos(protos){var has=function(p){return protos.indexOf(p)>=0},ps=protos.filter(Boolean);
 if(has('xray')&&ps.every(function(p){return p=='xray'||p=='hy2'}))return 'v2ray';
 if((has('wg')||has('awg'))&&ps.every(function(p){return TIER_CORES.gaming.indexOf(p)>=0}))return 'gaming';return 'vip'}
function ufServices(protos,un,tier){tier=tierKey(tier)||(protos.length?tierOfProtos(protos):'');var nodes=S.nodes||[];
 // a new user: the «New user» default tier with exactly its cores (never every core by default)
 if(!tier){tier=tierKey((S.me&&S.me.default_tier)||'vip')||'vip';protos=TIER_CORES[tier].slice()}
 var has=function(p){return protos.indexOf(p)>=0};
 var h='<label class="f" style="margin-top:12px" id="uf_tl">'+t('Subscription tier')+'</label>'+
  '<div class="seg uf-tier" id="uf_tier" role="radiogroup" aria-labelledby="uf_tl">'+['v2ray','gaming','vip'].map(function(k){
   return '<button type="button" role="radio" data-tier="'+k+'" aria-checked="'+(k==tier)+'" class="'+(k==tier?'on':'')+'"><b>'+t(TIER_NAMES[k])+'</b><small>'+t({v2ray:'Xray + Hysteria2',gaming:'KANKI MIX + AmneziaWG + WireGuard + DNS',vip:'Every core'}[k])+'</small></button>'}).join('')+'</div>'+
  '<label class="f" id="uf_cl">'+t('Cores of this user')+'</label><div class="uf-cores" role="group" aria-labelledby="uf_cl">'+UF_CORES.map(function(c){
   return '<label class="uf-core" style="--pc:'+(PCOL[c[0]]||'var(--a)')+'" data-core="'+c[0]+'"><span class="ni">'+ic(c[2],16)+'</span><span class="nm"><b>'+c[1]+'</b><small class="uf-out">'+t('Outside the tier')+'</small></span>'+
    '<span class="sw"><input type="checkbox" class="f_pr" value="'+c[0]+'" '+(has(c[0])?'checked':'')+' aria-label="'+esc(c[1])+'"><span></span></span></label>'}).join('')+'</div>'+
  (nodes.length>1?'<label class="f">'+t('Servers')+'</label><div class="ckrow">'+nodes.map(function(n){return '<label class="chk"><input type="checkbox" class="f_nd" value="'+esc(n.id)+'" '+(un.length==0||un.indexOf(n.id)>=0?'checked':'')+'>'+esc(n.name)+'</label>'}).join('')+'</div>':'');
 setTimeout(ufWire,0);return h}
function ufTier(){var b=$('#uf_tier [aria-checked=true]');return b?b.dataset.tier:'vip'}
function ufWire(){if(!$('#uf_tier'))return;
 var mark=function(){var k=ufTier();$$('.uf-core').forEach(function(c){var x=$('.f_pr',c),out=TIER_CORES[k].indexOf(c.dataset.core)<0;
  if(out)x.checked=false;x.disabled=out;c.classList.toggle('on',x.checked);c.classList.toggle('out',out)})};
 $$('#uf_tier [data-tier]').forEach(function(b){b.onclick=function(){var k=b.dataset.tier;
  $$('#uf_tier [data-tier]').forEach(function(x){var on=x==b;x.classList.toggle('on',on);x.setAttribute('aria-checked',on)});
  $$('.uf-core .f_pr').forEach(function(x){x.checked=TIER_CORES[k].indexOf(x.value)>=0});mark()}});
 $$('.uf-core .f_pr').forEach(function(x){x.addEventListener('change',mark)});mark()}

