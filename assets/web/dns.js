// Kanki Panel: the Kanki DNS page (v3.5). Tabs: overview, servers, services, users, settings and SSL.
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
function dnFA(){if(dnFA.done||typeof FA=='undefined')return;dnFA.done=1;Object.assign(FA,{
 "PUBG and games":"پابجی و بازی‌ها",
 "PUBG Mobile through Kanki DNS":"پابجی موبایل با DNS کانکی",
 "Pick one: it changes only the PUBG Mobile names below.":"یکی را انتخاب کن: فقط نام‌های پابجی موبایل پایین عوض می‌شوند.",
 "Direct":"مستقیم","Nothing of PUBG passes your servers. Fine where the game opens without help.":"هیچ چیز پابجی از سرورهای تو رد نمی‌شود. برای جاهایی که بازی بدون کمک باز می‌شود.",
 "Login and lobby (recommended)":"ورود و لابی (پیشنهادی)","Login, account, lobby and the UC store go through your server; the match stays direct.":"ورود، حساب، لابی و فروشگاه UC از سرور تو رد می‌شوند؛ خود مسابقه مستقیم می‌ماند.",
 "Everything":"همه","Also updates and anti-cheat. Use it when the game still stops at login or the update does not download.":"آپدیت و ضدتقلب هم. وقتی بازی هنوز روی ورود می‌ماند یا آپدیت دانلود نمی‌شود.",
 "Now":"الان","Custom":"دلخواه","Saved: the DNS servers use it within a few seconds":"ذخیره شد: سرورهای DNS تا چند ثانیه‌ی دیگر از آن استفاده می‌کنند",
 "Parts of PUBG Mobile":"بخش‌های پابجی موبایل","Every name of a ticked part and all its subdomains go through your server.":"همه‌ی نام‌های بخش تیک‌خورده و همه‌ی زیردامنه‌هایشان از سرور تو رد می‌شوند.",
 "PUBG names your users asked":"نام‌های پابجی که کاربرهایت پرسیده‌اند","From the query log: a direct name that the game needs can be added here.":"از گزارش پرس‌وجوها: اگر نامی که بازی لازم دارد مستقیم رفته، از همین‌جا اضافه‌اش کن.",
 "Add":"افزودن","No PUBG query in the log yet: open the game on a phone that uses your DNS, then press Refresh.":"هنوز پرس‌وجوی پابجی در گزارش نیست: بازی را روی گوشی‌ای که DNS تو را دارد باز کن، بعد «تازه‌سازی» را بزن.",
 "PUBG on PC (Krafton)":"پابجی کامپیوتر (Krafton)","It is in Services › Games › Other games.":"در «سرویس‌ها › بازی‌ها › بازی‌های دیگر» است."});}
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
function dnsPubgTab(d,el){dnFA();var sv=dnsPubgSvc(d),mode=dnsPubgMode(d),fa=S.lang!='en';
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
