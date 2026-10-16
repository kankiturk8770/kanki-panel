// Kanki Panel: the Kanki DNS page (v3.5). Tabs: overview, servers, services, users, settings and SSL.
var DN={d:null,tab:'overview',q:'',users:null};
var DTABS=[['overview','Overview','dash'],['servers','DNS servers','srv'],['services','Services','globe'],['users','DNS users','users'],['settings','Settings and SSL','settings']];
var UPSTREAMS=[['Cloudflare','1.1.1.1, 1.0.0.1'],['Google','8.8.8.8, 8.8.4.4'],['Quad9','9.9.9.9, 149.112.112.112'],['AdGuard (no ads)','94.140.14.14, 94.140.15.15'],['OpenDNS','208.67.222.222, 208.67.220.220']];
function p_dns(){DN.tab=S.sub||'overview';
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Kanki DNS')+'</h2><p>'+t('Private smart DNS for your subscribers: sanctioned services go through your servers, everything else goes direct')+'</p></div><div class="row" style="gap:6px"><button class="b2" onclick="dnsAdd(\'relay\')">+ '+t('Add relay')+'</button><button class="btn" onclick="dnsAdd(\'exit\')">+ '+t('Add DNS server')+'</button></div></div>'+
  '<div class="ptabs" id="dn_tabs"></div><div id="dn">'+t('Loading…')+'</div>';
 dnsLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName))&&['overview','servers','users'].indexOf(DN.tab)>=0)dnsLoad(true)},5000)}
function tab_dns(sub){DN.tab=sub||'overview';if(DN.d)dnsDraw(DN.d);else dnsLoad()}
function dnsTabs(d){var el=$('#dn_tabs');if(!el)return;var cnt={servers:d.servers.length,users:d.users};
 el.innerHTML=DTABS.map(function(x){return '<a href="#dns/'+x[0]+'" class="'+(DN.tab==x[0]?'on':'')+'">'+ic(x[2],15)+t(x[1])+(cnt[x[0]]?' <em>'+N(cnt[x[0]])+'</em>':'')+'</a>'}).join('')}
function dnsLoad(quiet){return api('GET','/api/dns').then(function(d){DN.d=d;if(S.page!='dns')return d;
  if(quiet){dnsTabs(d);if(DN.tab=='overview'&&$('#dn_kv')){$('#dn_kv').innerHTML=dnsKpis(d);$('#dn_top').innerHTML=dnsTop(d);$('#dn_topo').innerHTML=dnsTopo(d);return d}
   if(DN.tab=='servers'&&$('#dn_srv')){$('#dn_srv').innerHTML=dnsServers(d);return d}
   if(DN.tab=='users'&&$('#dn_ul')){dnsUsersLoad();return d}
   if(DN.tab=='settings'&&$('#dn_cert')){$('#dn_cert').innerHTML=dnsCertState(d);return d}return d}
  dnsDraw(d);return d}).catch(fail)}
function dnsName(id){var a=(DN.d&&DN.d.agents)||[];for(var i=0;i<a.length;i++)if(a[i].id==id)return a[i].name;return id}
function dnsDraw(d){var el=$('#dn');if(!el)return;dnsTabs(d);({overview:dnsOverview,servers:dnsServersTab,services:dnsServicesTab,users:dnsUsersTab,settings:dnsSettingsTab}[DN.tab]||dnsOverview)(d,el)}
function dnsSum(d,f){return d.servers.reduce(function(a,x){return a+(+f(x.status||{})||0)},0)}
function dnsKpis(d){var run=d.servers.filter(function(x){return x.status&&x.status.active}).length,q=dnsSum(d,function(s){return s.q&&s.q.total}),r=dnsSum(d,function(s){return s.q&&s.q.routed});
 return '<div><small>'+t('Status')+'</small><b style="color:'+(d.on?'var(--ok)':'var(--bad)')+'">'+(d.on?t('On'):t('Off'))+'</b></div><div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(d.servers.length)+'</b></div>'+
  '<div><small>'+t('Users with DNS')+'</small><b>'+N(d.users)+'</b></div><div><small>'+t('Allowed addresses')+'</small><b>'+N(dnsSum(d,function(s){return s.allowed}))+'</b></div>'+
  '<div><small>'+t('Queries')+' / '+t('routed')+'</small><b class="ltr">'+N(q)+' / '+N(r)+'</b></div>'}
function dnsWarn(d){var w=[];if(!d.on)w.push(t('DNS is off: nothing runs on the servers.')+' <a href="#dns/settings">'+t('Turn it on')+'</a>');
 if(!d.base)w.push(t('No DNS domain yet: encrypted DNS (DoT / DoH) needs one.')+' <a href="#dns/settings">'+t('Settings and SSL')+'</a>');
 else if(!(d.cert&&d.cert.present))w.push(t('No certificate yet: DoT / DoH and registering by link do not work without it.')+' <a href="#dns/settings">'+t('Settings and SSL')+'</a>');
 if(!d.servers.some(function(x){return x.role=='exit'}))w.push(t('Add an exit DNS server first'));
 return w.map(function(x){return '<div class="warnbox">'+x+'</div>'}).join('')}
function dnsOverview(d,el){
 el.innerHTML=dnsWarn(d)+'<div class="kv k5" id="dn_kv">'+dnsKpis(d)+'</div>'+
  '<div class="g2"><div class="card"><div class="nh"><h3>'+ic('tunnel',16)+' '+t('Path of the traffic')+'</h3><a class="b2" href="#dns/servers">'+t('Manage')+'</a></div><div id="dn_topo" style="margin-top:10px">'+dnsTopo(d)+'</div></div>'+
  '<div class="card"><h3>'+ic('traffic',16)+' '+t('Busiest services')+'</h3><p class="sub">'+t('Routed names asked for most since the DNS services started')+'</p><div id="dn_top">'+dnsTop(d)+'</div></div></div>'+
  '<div class="card"><h3>'+ic('globe',16)+' '+t('Check a domain')+'</h3><p class="sub">'+t('Does this site go through Kanki DNS, and which service lists it?')+'</p>'+dnsCheckBox()+'</div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0;line-height:2">'+t('1) A user\'s phone uses your DNS (Private DNS with the user\'s own address). 2) Names of sanctioned services (games, AI, developer sites …) are answered with your server\'s IP; everything else is answered normally and goes direct. 3) Your server passes those connections on without opening them. A relay inside Iran sends them to an exit abroad through a hidden Kanki tunnel.')+'</p></div>';
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
function dnsServersTab(d,el){el.innerHTML=dnsWarn(d)+'<div class="row" style="gap:8px;margin-bottom:12px"><button class="btn" onclick="dnsAdd(\'exit\')">+ '+t('Add DNS server')+' ('+t('Exit')+')</button><button class="b2" onclick="dnsAdd(\'relay\')">+ '+t('Add relay')+' ('+t('Iran')+')</button></div><div id="dn_srv">'+dnsServers(d)+'</div>'}
function dnsCertChip(d,x){var names=(d.cert_names||'').split(','),has=x.host&&names.indexOf(x.host)>=0&&d.cert&&d.cert.present;
 return d.acme_busy?'<span class="chipx y">SSL · '+t('Working…')+'</span>':has?'<span class="chipx g">SSL ✓ '+ago(d.cert_at)+'</span>':!x.host?'<span class="chipx">SSL · '+t('no name')+'</span>':d.acme_err?'<span class="chipx r" title="'+esc(d.acme_err)+'">SSL · '+t('error')+'</span>':'<span class="chipx y">SSL · '+t('waiting')+'</span>'}
function dnsCertNow(){api('POST','/api/dns/cert').then(function(){toast(t('Working… about a minute'));setTimeout(function(){dnsLoad(true)},5000)}).catch(fail)}
function dnsCertState(d){var c=d.cert||{};
 return '<div class="vrow"><span class="dot '+(c.present?'g':'r')+'"></span><div class="nm"><b>'+t('Certificate')+': '+(c.present?t('issued'):t('none yet'))+'</b><small><bdi>'+(d.cert_names?esc(d.cert_names.split(',').join('  ')):'—')+'</bdi></small></div>'+(d.cert_at?'<span class="chipx g">'+ago(d.cert_at)+'</span>':'')+(d.acme_busy?'<span class="chipx y">'+t('Working… about a minute')+'</span>':'')+'</div>'+
  (d.acme_err?'<div class="warnbox ltr">'+t('Last error')+': '+esc(d.acme_err)+'</div>':'')}
function dnsServers(d){if(!d.servers.length)return '<div class="card" style="text-align:center;padding:30px"><p class="muted">'+t('Add an exit DNS server first')+'</p><button class="btn" onclick="dnsAdd(\'exit\')">+ '+t('Add DNS server')+'</button></div>';
 return '<div class="ibl">'+d.servers.map(function(x){var st=x.status||{},on=st.active,q=st.q||{},errs=(st.errors||[]).concat(st.deploy_error?[st.deploy_error]:[]).concat(st.error?[st.error]:[]),relay=x.role=='relay';
  var hit=q.total?Math.round(100*(q.cache||0)/q.total):0;
  return '<div class="ibc"><div class="hd"><span class="pi">'+(relay?'IR':'EX')+'</span><div class="nm"><b>'+esc(x.name||x.server)+'</b><small>'+(relay?t('Relay (inside Iran)')+' → '+esc(dnsName(x.exit)):t('Exit (abroad)'))+'</small></div><span class="chipx '+(on?'g':x.status_at?'r':'y')+'">'+(x.status_at?(on?t('Running'):t('Not running')):t('Waiting for the server…'))+'</span></div>'+
   '<div class="chs"><span class="chipx a ltr">'+esc(x.host||t('no name'))+'</span><span class="chipx ltr">IP '+esc(x.answer_ip||'?')+'</span>'+(relay?'<span class="chipx b">'+esc(x.transport||'tcpmux')+' :'+(x.tunnel_port||8446)+'</span>':'')+(x.hidden?'<span class="chipx y">'+t('Hidden from subscribers')+'</span>':'')+(st.version?'<span class="chipx">v'+esc(st.version)+'</span>':'')+'</div>'+
   (x.note?'<p class="muted" style="margin:0">'+esc(x.note)+'</p>':'')+
   '<div class="kv k4" style="margin:0"><div><small>'+t('Queries')+'</small><b>'+N(q.total||0)+'</b></div><div><small>'+t('routed')+'</small><b>'+N(q.routed||0)+'</b></div><div><small>'+t('From cache')+'</small><b>'+N(hit)+'%</b></div><div><small>'+t('Allowed addresses')+'</small><b>'+N(st.allowed||0)+'</b></div></div>'+
   (q.refused?'<p class="muted" style="margin:0">'+t('Refused (not a subscriber)')+': '+N(q.refused)+' · '+t('Connections')+': '+N(st.conns||0)+'</p>':'')+
   (errs.length?'<div class="warnbox ltr" style="margin:0">'+errs.map(esc).join('<br>')+'</div>':'')+
   '<div class="row" style="gap:6px">'+dnsCertChip(d,x)+(d.provider&&d.has_token?'<button class="b2" style="margin-inline-start:auto" onclick="dnsCertNow()">'+ic('refresh',14)+' SSL</button>':'')+'</div>'+
   '<div class="g2"><button class="b2" onclick="dnsEdit(\''+x.server+'\')">'+ic('edit',15)+' '+t('Edit')+'</button><button class="b2 bd" onclick="dnsDel(\''+x.server+'\')">'+ic('trash',15)+' '+t('Remove from DNS')+'</button></div></div>'}).join('')+'</div>'}

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

// ---- settings tab
function dnsSettingsTab(d,el){
 el.innerHTML='<div class="g2"><div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
  '<div class="srow"><div class="tx"><b>'+t('DNS is on')+'</b><small>'+t('Off: DNS stops on every server and leaves the subscriptions')+'</small></div><label class="sw"><input type="checkbox" id="dn_on" '+(d.on?'checked':'')+'><span></span></label></div>'+
  '<label class="f">'+t('DNS domain')+'</label><input id="dn_base" class="ltr" placeholder="dns.example.com" value="'+esc(d.base)+'"><p class="hint">'+t('Each DNS server gets a name under it, like de.dns.example.com')+'</p>'+
  '<label class="f">'+t('Upstream resolvers')+'</label><input id="dn_up" class="ltr" value="'+esc(d.upstreams.join(', '))+'"><div class="chipset">'+UPSTREAMS.map(function(u){return '<button type="button" data-up="'+u[1]+'">'+esc(t(u[0]))+'</button>'}).join('')+'</div>'+
  '<label class="f">'+t('An allowed address stays open for (hours)')+'</label><input id="dn_h" type="number" min="1" class="ltr" value="'+d.ip_hours+'"><p class="hint">'+t('After this long without the user\'s app registering again, the address is closed')+'</p>'+
  '<div class="sbar"><button class="btn" id="dn_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><h3>'+ic('security',16)+' '+t('Certificate and records')+'</h3><div id="dn_cert">'+dnsCertState(d)+'</div>'+
  '<label class="f">'+t('Provider')+'</label><div class="ftabs" id="dn_pvt">'+[['',t('Manual (paste a certificate)')],['cloudflare','Cloudflare'],['arvan','ArvanCloud']].map(function(o){return '<button type="button" data-pv="'+o[0]+'" class="'+(d.provider==o[0]?'on':'')+'">'+o[1]+'</button>'}).join('')+'</div>'+
  '<div id="dn_auto"><p class="hint">'+t('The panel makes the A records of every server (and *.) with this API token, then gets a wildcard certificate from Let\'s Encrypt with a DNS challenge and renews it every 60 days. Works for servers inside Iran too.')+'</p><div class="g2"><div><label class="f">'+t('API token')+'</label><input id="dn_tok" type="password" class="ltr" autocomplete="off" placeholder="'+(d.has_token?t('unchanged'):'')+'"></div><div><label class="f">'+t("E-mail for Let's Encrypt (optional)")+'</label><input id="dn_em" class="ltr" value="'+esc(d.email||'')+'"></div></div>'+
   '<button class="b2" style="width:100%;margin-top:10px" id="dn_iss">'+ic('refresh',14)+' '+t('Set records and get the certificate now')+'</button></div>'+
  '<div id="dn_man"><label class="f">'+t('Certificate (PEM, full chain)')+'</label><textarea id="dn_c" rows="3" class="ltr" placeholder="-----BEGIN CERTIFICATE-----"></textarea><label class="f">'+t('Private key (PKCS#8 PEM)')+'</label><textarea id="dn_k" rows="3" class="ltr" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>'+
  '<div class="sbar"><button class="btn" id="dn_csave">'+t('Save')+'</button></div></div></div>';
 var pv=d.provider||'',pvu=function(){$('#dn_auto').style.display=pv?'':'none';$('#dn_man').style.display=pv?'none':''};
 $$('#dn_pvt [data-pv]').forEach(function(b){b.onclick=function(){pv=b.dataset.pv;$$('#dn_pvt [data-pv]').forEach(function(x){x.classList.toggle('on',x==b)});pvu()}});pvu();
 $$('[data-up]').forEach(function(b){b.onclick=function(){$('#dn_up').value=b.dataset.up}});
 $('#dn_save').onclick=function(){api('PUT','/api/dns',{on:$('#dn_on').checked,base:$('#dn_base').value,upstreams:$('#dn_up').value,ip_hours:+$('#dn_h').value||12}).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};
 $('#dn_csave').onclick=function(){var b={provider:pv,api_token:$('#dn_tok').value,email:$('#dn_em').value};if(!b.provider&&$('#dn_c').value.trim()){b.cert=$('#dn_c').value;b.key=$('#dn_k').value}
  api('PUT','/api/dns',b).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};
 $('#dn_iss').onclick=function(){var me=this;me.disabled=true;api('PUT','/api/dns',{provider:pv,api_token:$('#dn_tok').value,email:$('#dn_em').value}).then(function(){return api('POST','/api/dns/cert')}).then(function(){toast(t('Working… about a minute'));setTimeout(function(){me.disabled=false;dnsLoad(true)},5000)}).catch(function(e){me.disabled=false;fail(e)})}}

// ---- add / edit a DNS server
function dnsForm(x,role){var d=DN.d,exits=d.servers.filter(function(s){return s.role=='exit'&&s.server!=(x&&x.server)}),agents=d.agents.filter(function(a){return !d.servers.some(function(s){return s.server==a.id&&(!x||s.server!=x.server)})});
 if(role=='relay'&&!exits.length){toast(t('Add an exit DNS server first'),1);return null}
 var h='<p class="muted" style="margin:0 0 6px">'+t('Ports 53, 80, 443 and 853 must be free on this server: give DNS its own server.')+'</p>';
 if(!x)h+='<label class="f">'+t('Agent server')+'</label><select id="dx_sv"><option value="__new">'+t('New server (install command)')+'</option>'+agents.map(function(a){return '<option value="'+esc(a.id)+'">'+esc(a.name)+'</option>'}).join('')+'</select><div id="dx_nw"><label class="f">'+t('Server name')+'</label><input id="dx_nm" placeholder="'+(role=='relay'?'Iran-DNS':'DNS-DE')+'"></div>';
 h+='<label class="f">'+t('Domain of this DNS server')+'</label><input id="dx_dm" class="ltr" placeholder="'+(d.base?(role=='relay'?'ir1.':'de.')+esc(d.base):'de.dns.example.com')+'" value="'+esc(x?x.domain||'':'')+'"><p class="hint">'+t('Empty = label + DNS domain. The panel points it (and *.) at this server and gets the SSL for it by itself.')+'</p>'+
  (d.provider&&d.has_token?'':'<div class="warnbox">'+t('For SSL by itself, set the DNS provider and API token in Settings and SSL.')+' <a href="#dns/settings" onclick="closeModal()">'+t('Settings and SSL')+'</a></div>')+
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
   (nw?api('POST','/api/tunnels/servers',{name:$('#dx_nm').value||((role=='relay'?'DNS-relay-':'DNS-')+($('#dx_lb').value||''))}):Promise.resolve({id:$('#dx_sv').value})).then(function(r){
    return api('POST','/api/dns/servers',dnsBody(role,r.id)).then(function(q){toast(t(q&&q.cert?'Saved: getting SSL (about a minute)':'Saved'));if(nw){$('#dx_go').style.display='none';$('#dx_out').innerHTML=tunCmdBox(r,r);$('#tn_cp').onclick=function(){copy($('#tn_cmd').textContent)}}else closeModal();dnsLoad()})}).catch(function(e){me.disabled=false;fail(e)})}};
 if(DN.d)go();else dnsLoad().then(go)}
function dnsEdit(id){var x=DN.d.servers.filter(function(s){return s.server==id})[0];if(!x)return;var h=dnsForm(x,x.role);if(h===null)return;
 modal(mhead(t('Edit'),x.name)+h);$('#dx_lb').oninput=dnsLbHint;dnsLbHint();$('#dx_go').onclick=function(){api('POST','/api/dns/servers',dnsBody(x.role,id)).then(function(q){toast(t(q&&q.cert?'Saved: getting SSL (about a minute)':'Saved'));closeModal();dnsLoad()}).catch(fail)}}
function dnsDel(id){confirmDo(function(){api('DELETE','/api/dns/servers/'+encodeURIComponent(id)).then(function(){toast(t('Done'));dnsLoad()}).catch(fail)})}
