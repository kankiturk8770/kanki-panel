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
var FW_NAMES={mtun:'microtun',tunnels:'Tunnels',dns:'Kanki DNS',xray:'Xray',emergency:'Emergency chat',kmix:'KANKI MIX',subsrv:'Subscription link',acme:'SSL (port 80)'};
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
function p_vpn(){$('#pg').innerHTML='<div class="ku">'+kuHead('cores',t('VPN & cores'),t('Every core your users get, each on its own card'))+'<div id="vh_s"></div><div class="cgrid" id="vh_g">'+t('Loading…')+'</div>'+
  '<section class="card kv-svc"><div class="kc-h"><div><h3>'+t('Services')+'</h3><small class="muted">'+t('Start, stop or restart the VPN services')+'</small></div></div><div id="svcs" class="svcs"><span class="muted">'+t('Loading…')+'</span></div></section></div>';
 $('#svcs').onclick=function(e){var b=e.target.closest('[data-svc]');if(b&&!b.disabled)svc(b.dataset.svc,b.dataset.act)};sysSvcLoad();
 var go=function(){Promise.all([api('GET','/api/nodes').catch(function(){return []}),api('GET','/api/overview').catch(function(){return {}}),api('GET','/api/xray').catch(function(){return null}),api('GET','/api/dns').catch(function(){return null}),api('GET','/api/kping').catch(function(){return null})]).then(function(r){if(S.page!='vpn')return;S.nodes=r[0]||[];if(r[2])XR.d=r[2];if(r[3])DN.d=r[3];vhGrid(r[0]||[],r[1]||{},r[2],r[3],r[4])})};
 go();clearInterval(S.timer);S.timer=setInterval(function(){if(document.visibilityState=='visible'&&!$('#modal').classList.contains('on'))go()},8000)}
// one card per core (3.34): status, servers running it and users; the whole card opens the core's own page
function vhGrid(nodes,o,xr,dn,kp){var el=$('#vh_g');if(!el)return;var pr=o.protocols||{};
 var up=function(n){return n.id=='local'||n.online},num=function(v){return v!=null&&v!==''&&+v>0};
 // servers that run a core (the agent reports its port) and how many of them are up
 var on=function(k){var l=nodes.filter(function(n){return num((n.info||{})[k])});return [l.filter(up).length,l.length]};
 var K=[['wg','WireGuard','shield2','Standard and fast; through Iran only',on('wg_port')],['awg','AmneziaWG','security','WireGuard with hidden packets; direct or through Iran',on('awg_port')],
  ['hy2','Hysteria2','globe','QUIC, fast on weak internet',on('hy2_port')],['kmix','KANKI MIX','game','Kanki\'s own game protocol, low ping',on('kmix_port')],['mtun','microtun','game','A light game VPN, small packets sent twice',on('mt_port')]];
 var card=function(href,col,icon,name,sub,st,stats){return '<a class="ccard" href="'+href+'" style="--pc:'+col+'"><div class="cc1"><span class="cci">'+ic(icon,20)+'</span><span class="ccs '+st[0]+'"><i></i>'+st[1]+'</span></div>'+
  '<b class="ccn">'+name+'</b><small class="ccd">'+t(sub)+'</small><div class="ccst">'+stats.map(function(x){return '<div><small>'+x[0]+'</small><b class="ltr">'+x[1]+'</b></div>'}).join('')+'</div></a>'};
 var state=function(u,all){return all==0?['n',t('Not installed')]:u==all?['g',t('Running')]:u==0?['r',t('Down')]:['y',t('Partly down')]};
 var hs=K.map(function(c){var u=c[4][0],all=c[4][1];return card('#'+c[0],PCOL[c[0]],c[2],c[1],c[3],state(u,all),[[t('Servers'),N(u)+' / '+N(all)],[t('Users'),N(pr[c[0]]||0)]])});
 // (3.42) KPING sits beside KANKI MIX (the two game cores), as in the core bar
 if(kp){var kr=kp.routes.filter(function(x){return x.exit_runs&&x.tunnel_up&&x.relay&&!x.relay.error}).length;
  hs.splice(4,0,card('#kping/status',PCOL.kping,'game','KPING','Hidden game core: only PUBG, only for testers',!kp.settings.on?['r',t('Off')]:!kp.routes.length?['n',t('No route')]:kr==kp.routes.length?['g',t('Running')]:kr?['y',t('Partly down')]:['y',t('Not ready')],[[t('Routes'),N(kr)+' / '+N(kp.routes.length)],[t('Testers'),N(kp.users||0)]]))}
 var h=hs.join('');
 if(xr){var act=xr.inbounds.filter(function(x){return x.enabled&&!x.state}).length;
  h+=card('#xray/status',PCOL.xray,'xray','Xray','VLESS · VMess · Trojan · Shadowsocks',xr.on?(act?['g',t('Running')]:['y',t('No inbound')]):['r',t('Off')],[[t('Inbounds'),N(act)+' / '+N(xr.inbounds.length)],[t('Online now'),N((xr.online||[]).length)]])}
 if(dn){var run=dn.servers.filter(function(x){return x.status&&x.status.active}).length;
  h+=card('#dns/overview',PCOL.dns,'dns','Kanki DNS','Private DNS for sanctioned sites',dn.on?(run?['g',t('Running')]:['y',t('No server')]):['r',t('Off')],[[t('Servers'),N(run)+' / '+N(dn.servers.length)],[t('Users'),N(dn.users||0)]])}
 h+=card('#antidpi',PCOL.awg,'security','Anti-DPI','Tunnels between your servers that filters cannot see',['n',t('Tools')],[[t('Tunnels'),t('Open')]]);
 el.innerHTML=h;
 var ups=nodes.filter(up).length,s=$('#vh_s');
 if(s)s.innerHTML=kuStats([[t('Servers online'),N(ups)+' / '+N(nodes.length),ups<nodes.length?'warn':'ok'],[t('Online now'),N(o.online||0),'ok'],[t('Total traffic'),'<span class="ltr">'+N(o.traffic_gb||0)+' GB</span>'],[t('Users'),N(o.users||0)]])}

// ---------------------------------------------------------------- user form: what the user gets, service by service
function ufServices(protos,un){var has=function(p){return protos.indexOf(p)>=0},vpnOn=has('wg')||has('awg')||has('hy2')||has('kmix')||has('mtun');
 var card=function(key,icon,title,sub,on,body,head){return '<div class="ufsvc'+(on?' on':'')+'" data-svc="'+key+'"><div class="hd"><span class="ni">'+ic(icon,18)+'</span><div class="nm"><b>'+t(title)+'</b><small>'+t(sub)+'</small></div>'+(head||'')+'</div><div class="bd3">'+body+'</div></div>'};
 var nodes=S.nodes||[];
 var h='<label class="f" style="margin-top:12px">'+t('Services of this user')+'</label><div class="chipset" id="uf_pre"><button type="button" data-pre="all">'+t('Everything')+'</button><button type="button" data-pre="vpn">'+t('Kanki VPN only')+'</button><button type="button" data-pre="xray">'+t('Xray only')+'</button><button type="button" data-pre="dns">'+t('DNS only')+'</button></div>';
 h+=card('vpn','nodes','Kanki VPN','WireGuard · AmneziaWG · Hysteria2 · KANKI MIX',vpnOn,
  '<div class="ckrow">'+[['wg','WireGuard'],['awg','AmneziaWG'],['hy2','Hysteria2'],['kmix','KANKI MIX'],['mtun','microtun']].map(function(p){return '<label class="pchk" style="--pc:'+PCOL[p[0]]+'"><input type="checkbox" class="f_pr" value="'+p[0]+'" '+(has(p[0])?'checked':'')+'><i></i>'+p[1]+'</label>'}).join('')+'</div>'+
  (nodes.length>1?'<label class="f">'+t('Servers')+'</label><div class="ckrow">'+nodes.map(function(n){return '<label class="chk"><input type="checkbox" class="f_nd" value="'+esc(n.id)+'" '+(un.length==0||un.indexOf(n.id)>=0?'checked':'')+'>'+esc(n.name)+'</label>'}).join('')+'</div>':''),
  '<label class="sw"><input type="checkbox" class="uf_all" data-for="vpn" '+(vpnOn?'checked':'')+'><span></span></label>');
 h+=card('xray','xray','Xray','Links of every Xray inbound go into the subscription',has('xray'),'<div id="uf_xr" class="muted">…</div>','<label class="sw"><input type="checkbox" class="f_pr" value="xray" '+(has('xray')?'checked':'')+'><span></span></label>');
 h+=card('dns','dns','Kanki DNS','Private DNS for sanctioned sites',has('dns'),'<div id="uf_dn" class="muted">…</div>','<label class="sw"><input type="checkbox" class="f_pr" value="dns" '+(has('dns')?'checked':'')+'><span></span></label>');
 h+=card('kping','game','KPING','Hidden game core, only in the Kanki app (testers only)',has('kping'),'<p class="muted" style="margin:0">'+t('Only PUBG goes through it. Not on the subscription page, in links or in the bot.')+'</p>','<label class="sw"><input type="checkbox" class="f_pr" value="kping" '+(has('kping')?'checked':'')+'><span></span></label>');
 setTimeout(ufWire,0);return h}
function ufWire(){if(!$('#uf_pre'))return;
 var sync=function(){$$('.ufsvc').forEach(function(c){var on=$$('.f_pr',c).some(function(x){return x.checked});c.classList.toggle('on',on);var a=$('.uf_all',c);if(a)a.checked=on})};
 $$('.uf_all').forEach(function(a){a.onchange=function(){var c=a.closest('.ufsvc');$$('.f_pr',c).forEach(function(x){x.checked=a.checked});sync()}});
 $$('.ufsvc .f_pr').forEach(function(x){x.addEventListener('change',sync)});
 $$('#uf_pre [data-pre]').forEach(function(b){b.onclick=function(){var k=b.dataset.pre;$$('.ufsvc').forEach(function(c){var on=(k=='all'&&c.dataset.svc!='kping')||c.dataset.svc==k;if(c.dataset.svc=='kping'&&k!='kping')on=$$('.f_pr',c).some(function(x){return x.checked});$$('.f_pr',c).forEach(function(x){x.checked=on})});sync()}});
 var xr=function(d){var el=$('#uf_xr');if(!el)return;if(!d){el.textContent='—';return}var l=d.inbounds.filter(function(x){return x.enabled});
  el.innerHTML=(d.on?'':'<span style="color:var(--warn)">'+t('Is off in the panel')+'</span> · ')+(l.length?l.map(function(ib){return '<span class="chipx a" style="margin:2px">'+esc(ib.remark||ib.protocol)+' · '+esc(ib.server_name||ib.server)+'</span>'}).join(''):t('No Xray inbound yet')+' · <a href="#xray/inbounds" onclick="closeModal()">'+t('Inbounds')+'</a>')};
 var dn=function(d){var el=$('#uf_dn');if(!el)return;if(!d){el.textContent='—';return}var l=d.servers.filter(function(x){return !x.hidden});
  el.innerHTML=(d.on?'':'<span style="color:var(--warn)">'+t('Is off in the panel')+'</span> · ')+(l.length?l.map(function(x){return '<span class="chipx b" style="margin:2px">'+(x.role=='relay'?'🇮🇷 ':'🌍 ')+esc(x.name||x.server)+'</span>'}).join(''):t('No DNS server yet')+' · <a href="#dns/servers" onclick="closeModal()">'+t('Add DNS server')+'</a>')};
 if(XR.d)xr(XR.d);api('GET','/api/xray').then(function(d){XR.d=d;xr(d)}).catch(function(){xr(null)});
 if(DN.d)dn(DN.d);api('GET','/api/dns').then(function(d){DN.d=d;dn(d)}).catch(function(){dn(null)})}

