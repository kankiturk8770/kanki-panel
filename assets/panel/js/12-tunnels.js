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
// every Iran server has its own colour on the map (green, blue, violet, pink; a fifth starts again);
// red is kept for a tunnel that is down
var TMIR=['#3ddc97','#6fb6ff','#c084fc','#f472b6'];
function tmIran(sv){return sv.filter(function(s){return srvLoc(s)=='iran'}).sort(function(a,b){return String(a.name).localeCompare(String(b.name))})}
function tmIrCol(sv){var o={};tmIran(sv).forEach(function(s,i){o[s.id]=TMIR[i%TMIR.length]});return o}
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
function pTunnels(){KAcc.open.tn='';KAcc.draw.tn=function(){var l=$('#tn_list');if(l&&TN.d)l.innerHTML=tunList(TN.d)};
 $('#pg').innerHTML='<div class="ku">'+kuHead('tunnel',t('Tunnels'),t('Encrypted tunnels between your servers: users connect to the entry, traffic leaves from the exit'),
  '<button class="btn" onclick="tunEdit()">'+ic('plus',15)+' '+t('Tunnel')+'</button><button class="b2" onclick="tunMore()" aria-label="'+esc(t('More'))+'">⋯ '+t('More')+'</button>')+
 '<div class="card tmapc"><nav class="tmtabs" id="tn_mt" role="tablist"></nav><div id="tn_map"><span class="muted">'+t('Loading…')+'</span></div><div class="tkpi" id="tn_kpi"></div></div>'+
 '<div class="ku-tools tnf" id="tn_f"></div><div id="tn_list"></div></div>';
 tunRefresh();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible')tunRefresh(true)},3000)}
function tunRefresh(quiet){return tunLoad().then(tunDraw).catch(function(e){if(!quiet)fail(e)})}
// the map shows every Iran server, or one of them (its tunnels side by side); remembered on this browser
var TNV={v:(function(){try{return localStorage.getItem('kk_tmview')||'all'}catch(e){return 'all'}})()};
function tunView(v){TNV.v=v;try{localStorage.setItem('kk_tmview',v)}catch(e){}var m=$('#tn_map');if(m)m.dataset.sig='';if(TN.d)tunDraw(TN.d)}
function tunDraw(d){var m=$('#tn_map'),sl=$('#tn_srv');if(!m&&!sl)return;var sv=d.servers||[],tl=d.tunnels||[];
 var irs=tmIran(sv),col=tmIrCol(sv);if(TNV.v!='all'&&!col[TNV.v])TNV.v='all';
 var vt=TNV.v=='all'?tl:tl.filter(function(x){return x.entry==TNV.v||x.exit==TNV.v});
 var up=vt.filter(function(x){return x.state=='up'}).length,on=sv.filter(function(s){return s.online}).length,rx=0,tx=0;
 vt.forEach(function(x){var s=x.entry_status;if(s){rx+=s.rx_bytes||0;tx+=s.tx_bytes||0}});
 if(m){var mt=$('#tn_mt');if(mt)mt.innerHTML=irs.length?[['all',t('All')]].concat(irs.map(function(s){return [s.id,esc(s.name)]})).map(function(x){
    return '<button type="button" role="tab" aria-selected="'+(TNV.v==x[0])+'" class="'+(TNV.v==x[0]?'on':'')+'" onclick="tunView(\''+esc(x[0])+'\')">'+(col[x[0]]?'<i style="background:'+col[x[0]]+'"></i>':'')+x[1]+'</button>'}).join(''):'';
  var sig=TNV.v+JSON.stringify([sv.map(function(s){return [s.id,s.name,s.online,s.local,s.loc]}),tl.map(function(x){return [x.id,x.entry,x.exit,x.state,x.transport,Math.round(((x.entry_status||{}).rtt_ms||0)/10)]})]);
  var mh=tunMap(d,TNV.v);if(m.dataset.sig!==sig||!m.querySelector('canvas')){m.dataset.sig=sig;m.innerHTML=mh}
  $('#tn_kpi').innerHTML='<div><small>'+t('Tunnels connected')+'</small><b style="color:'+(up==vt.length&&vt.length?'var(--ok)':'inherit')+'">'+N(up)+' / '+N(vt.length)+'</b></div><div><small>'+t('Servers online')+'</small><b>'+N(on)+' / '+N(sv.length)+'</b></div><div><small>'+t('Through the tunnels')+'</small><b class="ltr">↑ '+bytes(tx)+' · ↓ '+bytes(rx)+'</b></div>';
  tunFilterBar(d);if(!accBusy('tn'))$('#tn_list').innerHTML=tunList(d)}
 if(sl){var k=$('#tn_skpi');if(k)k.innerHTML='<div><small>'+t('Servers online')+'</small><b style="color:'+(on==sv.length&&sv.length?'var(--ok)':'inherit')+'">'+N(on)+' / '+N(sv.length)+'</b></div><div><small>'+t('Tunnels connected')+'</small><b>'+N(up)+' / '+N(tl.length)+'</b></div><div><small>'+t('Through the tunnels')+'</small><b class="ltr">↑ '+bytes(tx)+' · ↓ '+bytes(rx)+'</b></div>';
  sl.innerHTML=SRV_GROUPS.map(function(g){var l=sv.filter(function(s){return srvLoc(s)==g[0]});return l.length?'<h3 style="grid-column:1/-1;margin:6px 0 0">'+t(g[1])+' <small class="muted">'+N(l.length)+'</small></h3>'+l.map(tunSrvCard).join(''):''}).join('')}}
function pServers(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Tunnel servers')+'</h2><p>'+t('Servers that only carry tunnels get a small agent: no VPN is installed on them')+'</p></div><div class="row" style="gap:6px"><button class="b2" onclick="updateAll()">⇪ '+t('Update all')+'</button><button class="btn" onclick="tunServerAdd()">+ '+t('Server')+'</button></div></div><div class="card" style="padding:10px"><div class="tkpi" id="tn_skpi" style="margin:0"></div></div><div class="ncards" id="tn_srv">'+t('Loading…')+'</div>';
 tunRefresh();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible')tunRefresh(true)},3000)}
// the rarer tools of the page
// a server's flag on this page, only when its country is known (the tunnel list has no country for most)
function tnFlag(s){return s&&s.cc?flagOf(s.cc)+' ':''}
function tunMore(){kuMenu(t('Tunnels'),'',[['? '+t('Tunnel guide'),'tunGuide()'],['⚡ '+t('Smart tunnel'),'tunSmart()'],['⛓ '+t('Multi-location tunnel'),'routeEdit()'],['⇪ '+t('Update all'),'updateAll()']])}
// the list under the map: only the tunnels of one server when one is picked ("" = all)
var TNF={f:(function(){try{return localStorage.getItem('kk_tnf')||''}catch(e){return ''}})()};
function tunFilter(v){TNF.f=v;try{localStorage.setItem('kk_tnf',v)}catch(e){}KAcc.open.tn='';if(TN.d){tunFilterBar(TN.d);$('#tn_list').innerHTML=tunList(TN.d)}}
function tunFilterBar(d){var el=$('#tn_f');if(!el)return;var tl=d.tunnels||[],sv=(d.servers||[]).filter(function(s){return tl.some(function(x){return x.entry==s.id||x.exit==s.id})});
 if(TNF.f&&!sv.some(function(s){return s.id==TNF.f}))TNF.f='';
 var b=function(id,label,n){return '<button type="button" class="'+(TNF.f==id?'on':'')+'" onclick="tunFilter(\''+esc(id)+'\')">'+label+(n!=null?'<em>'+N(n)+'</em>':'')+'</button>'};
 var cnt=function(id){return tl.filter(function(x){return x.entry==id||x.exit==id}).length};
 var ir=sv.filter(function(s){return srvLoc(s)=='iran'}),ab=sv.filter(function(s){return srvLoc(s)!='iran'});
 el.innerHTML=sv.length<2?'':'<div class="tnf-l">'+b('',t('All servers'),tl.length)+ab.concat(ir).map(function(s){return b(s.id,tnFlag(s)+esc(s.name),cnt(s.id))}).join('')+'</div>'}
function tunList(d){var tl=(d.tunnels||[]).filter(function(x){return !TNF.f||x.entry==TNF.f||x.exit==TNF.f});
 if(!(d.tunnels||[]).length)return kuGroup(t('Tunnels'),0,'','<p class="muted ku-empty">'+t('No tunnels yet')+' · <a href="javascript:tunEdit()">'+t('Make the first tunnel')+'</a></p>');
 if(!tl.length)return kuGroup(t('Tunnels'),0,'','<p class="muted ku-empty">'+t('Nothing found')+'</p>');
 var sv=d.servers||[],col=tmIrCol(sv),groups=[],by={},chains=[];
 tl.forEach(function(x){if(x.chain){if(chains.indexOf(x.chain)<0)chains.push(x.chain);return}var k=col[x.entry]?x.entry:col[x.exit]?x.exit:'';if(!by[k]){by[k]=[];groups.push(k)}by[k].push(x)});
 groups.sort(function(a,b){return (a?0:1)-(b?0:1)||String(tunSrv(a).name).localeCompare(String(tunSrv(b).name))});
 return groups.map(function(k){var l=by[k].sort(function(a,b){return String(tunSrv(a.exit).name).localeCompare(String(tunSrv(b.exit).name))||String(a.name).localeCompare(String(b.name))}),up=l.filter(function(x){return x.state=='up'}).length;
   var title=k?'<i class="tn-dot" style="background:'+col[k]+'"></i>'+esc(tunSrv(k).name):t('Other tunnels');
   return kuGroup(title,null,'<span class="ku-n">'+N(up)+' / '+N(l.length)+' '+t('connected')+'</span>','<div class="kxl">'+l.map(tunRow).join('')+'</div>')}).join('')+
  (chains.length?kuGroup(t('Multi-location tunnels'),chains.length,'',chains.map(function(c){var x=tl.filter(function(z){return z.chain==c})[0];return '<div class="tn-route">'+routeCardOf(x)+'</div>'}).join('')):'')}
// one tunnel: state, route and name on the first line; transport, ping and ports under it; a tap opens the rest
function tunRow(x){var e=tunSrv(x.entry),xs=tunSrv(x.exit),es=x.entry_status||{},aw=x.kind=='awg'?(x.awg||{}):null,st=x.state=='up'?'g':x.state=='partial'?'y':x.state=='off'?'':'r';
 var ports=[];if(x.tcp&&x.tcp.length)ports.push('TCP '+x.tcp.join(','));if(x.udp&&x.udp.length)ports.push('UDP '+x.udp.join(','));
 if(aw){if(aw.fwd_tcp&&aw.fwd_tcp.length)ports.push('TCP '+aw.fwd_tcp.join(','));if(aw.fwd_udp&&aw.fwd_udp.length)ports.push('UDP '+aw.fwd_udp.join(','))}
 var head='<span class="dot '+st+'"></span><b>'+esc(x.name||(e.name+' → '+xs.name))+'</b><span class="sp"></span>'+
  '<span class="kxr-st '+st+'">'+(x.state=='up'&&es.rtt_ms?es.rtt_ms+' ms':tunStateTxt(x.state))+'</span>'+
  '<span class="tn-l2"><span class="kxr-st">'+esc(tunShort(x))+'</span><span class="tn-path">'+esc(e.name)+' → '+tnFlag(xs)+esc(xs.name)+'</span>'+(ports.length?'<small class="ltr">'+esc(ports.join(' · '))+'</small>':'')+'</span>';
 return accRow('tn',x.id,head,function(){return tunBody(x)},x.enabled?'':'off')}
function tunBody(x){var e=tunSrv(x.entry),xs=tunSrv(x.exit),es=x.entry_status||{},xx=x.exit_status||{},err=es.error?e.name+': '+es.error:xx.error?xs.name+': '+xx.error:'',aw=x.kind=='awg'?(x.awg||{}):null,hy=x.kind=='hy2'?(x.hy2||{}):null;
 if(aw)err=err||(x.wrap_entry||{}).error||(x.wrap_exit||{}).error||'';
 var info=[[t('Transport'),esc(aw?('AWG'+(aw.wrap?' ⟶ '+tunTr(x.transport):'')):hy?'Hysteria2'+(hy.obfs_on?' + Salamander':''):tunTr(x.transport))],[t('Ping'),es.rtt_ms?'<span class="ltr">'+es.rtt_ms+' ms</span>':'—'],
  [t('Links'),'<span class="ltr">'+N(es.links||0)+' / '+N(es.want||x.conns||1)+'</span>'],[t('Traffic'),'<span class="ltr">↑'+bytes(es.tx_bytes||0)+' ↓'+bytes(es.rx_bytes||0)+'</span>'],
  [t('Mode'),x.mode=='direct'?t('direct'):t('reverse')],[t('Port'),'<span class="ltr">'+esc(String(aw?aw.port:x.port))+' · '+esc(x.dial_host||'?')+'</span>']];
 if(aw)info.push(['AWG','<span class="ltr">'+esc(aw.entry_ip+' ⇄ '+aw.exit_ip+(aw.routes&&aw.routes.length?' · → '+aw.routes.join(' '):'')+(aw.src_routes&&aw.src_routes.length?' · ⇠ '+aw.src_routes.join(' '):''))+'</span>']);
 if(hy&&hy.src_routes&&hy.src_routes.length)info.push(['⇠','<span class="ltr">'+esc(hy.src_routes.join(' '))+'</span>']);
 if(x.auto)info.push([t('Rotating'),esc(x.switch_note?x.switch_note+' · '+ago(x.switched):t('Rotating tunnel'))]);
 return '<div class="tn-info">'+info.map(function(r){return '<div><small>'+r[0]+'</small><b>'+r[1]+'</b></div>'}).join('')+'</div>'+
  (err&&x.state!='up'?'<div class="warnbox ltr" style="margin:8px 0 0">'+esc(err)+'</div>':'')+
  kuSwitch(t('Tunnel on'),x.enabled,"tunAct('"+x.id+"','"+(x.enabled?'disable':'enable')+"')")+
  '<div class="kxacts"><button class="btn sm" onclick="tunEdit(\''+x.id+'\')">'+ic('edit',13)+' '+t('Edit')+'</button><button class="b2 sm" onclick="tunAct(\''+x.id+'\',\'restart\')">'+ic('refresh',13)+' '+t('Reconnect')+'</button></div>'+
  '<div class="ku-danger"><button class="b2 sm bd" onclick="tunDel(\''+x.id+'\')">'+ic('trash',13)+' '+t('Delete')+'</button></div>'}
function tunSrvCard(s){var nt=((TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.entry==s.id||x.exit==s.id}).length,col=s.online?'var(--ok)':'var(--bad)';
 return '<div class="card" style="margin:0;border-inline-start:3px solid '+col+'"><div class="row" style="justify-content:space-between;align-items:flex-start"><div class="row"><div class="logo" style="width:34px;height:34px;font-size:14px">'+esc(s.local?'★':s.name.charAt(0).toUpperCase())+'</div><div><b>'+flagOf(s.cc)+' '+esc(s.name)+'</b><div class="muted ltr">'+esc(s.host||t('address unknown yet'))+'</div></div></div>'+
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
function tunSvcGroups(sid){var o={xray:{tcp:[],udp:[]},dns:{tcp:[],udp:[]}},add=function(g,l,v){v=parseInt(v,10);if(v>0&&v<65536&&g[l].indexOf(v)<0)g[l].push(v)},none=function(){return null};
 return Promise.all([api('GET','/api/xray').catch(none),api('GET','/api/dns').catch(none)]).then(function(r){var x=r[0],d=r[1];
  ((x&&x.on&&x.inbounds)||[]).forEach(function(ib){if(ib.enabled===false||ib.server!=sid)return;
   if(ib.network=='kcp')add(o.xray,'udp',ib.port);else{add(o.xray,'tcp',ib.port);if(ib.protocol=='shadowsocks')add(o.xray,'udp',ib.port)}});
  if(d&&d.on&&(d.servers||[]).some(function(z){return z.server==sid})){add(o.dns,'udp',53);add(o.dns,'tcp',53);add(o.dns,'tcp',853);add(o.dns,'tcp',443)}
  return o})}
function tunSvcPorts(sid){return tunSvcGroups(sid).then(function(g){return tunMerge(tunMerge({tcp:[],udp:[]},g.xray),g.dns)})}
function tunMerge(a,b){[['tcp'],['udp']].forEach(function(k){k=k[0];(b[k]||[]).forEach(function(p){if(a[k].indexOf(p)<0)a[k].push(p)})});return a}
// ---- «Which tunnel?»: which tunnel suits which protocol. UDP protocols through a UDP tunnel, Xray
// (TCP) through a TCP one: a lost packet inside a TCP tunnel holds up every packet after it. Each row
// can open the tunnel form with its best choice already picked.
var TGUIDE=[
 {p:'WireGuard · AmneziaWG',best:['awg','AmneziaWG link'],also:'Game, KCP',blocked:'FakeTCP, Dual',avoid:'TCP, WS',
  why:'A network card between the two servers: packets go through as they are, with the least overhead.'},
 {p:'microtun · KANKI MIX',best:['game','Game (FEC)'],also:'AmneziaWG link, KCP',blocked:'FakeTCP',avoid:'TCP, WSS, CDN',
  why:"For games: a lost packet is rebuilt without waiting. Costs about 37% more traffic between the servers, not the user's data."},
 {p:'Hysteria2',best:['hy2','Hysteria2 link'],also:'HQ-QUIC, KCP',blocked:'Dual',avoid:'TCP, WS',
  why:'QUIC stays QUIC end to end; HQ-QUIC hides it under a mask.'},
 {p:'Xray',best:['tcpmux','TCP Mux'],also:'WSS, H2',blocked:'CDN (when the abroad IP is blocked)',avoid:'—',
  why:'Xray is TCP: a steady TCP tunnel fits it; WSS and H2 look like an ordinary site.'},
 {p:'Kanki DNS',best:['tcpmux','TCP Mux'],also:'KCP',blocked:'—',avoid:'—',
  why:'DoT and DoH are TCP; plain DNS (53) is UDP and also passes KCP.'}];
function tunGuidePre(k){return k=='awg'||k=='hy2'?{kind:k}:{transport:k}}
function tunGuideHtml(){
 return '<p class="sub" style="margin:0 0 10px">'+t('Rule: UDP protocols through a UDP tunnel, Xray (TCP) through a TCP tunnel. A game packet inside a TCP tunnel waits for every lost packet before it, so the ping jumps.')+'</p>'+
  '<div class="tguide"><div class="tgr tgh"><b>'+t('Protocol')+'</b><b>'+t('Best tunnel')+'</b><b>'+t('Also good')+'</b><b>'+t('When UDP is blocked')+'</b><b>'+t('Better not')+'</b></div>'+
  TGUIDE.map(function(r,i){return '<div class="tgr"><b class="tgp">'+esc(r.p)+'</b>'+
   '<span class="tgb" data-l="'+esc(t('Best tunnel'))+'"><button type="button" class="b2 sm" data-tg="'+i+'">'+esc(t(r.best[1]))+' ＋</button></span>'+
   '<span data-l="'+esc(t('Also good'))+'">'+esc(t(r.also))+'</span><span data-l="'+esc(t('When UDP is blocked'))+'">'+esc(t(r.blocked))+'</span><span class="tgx" data-l="'+esc(t('Better not'))+'">'+esc(r.avoid)+'</span>'+
   '<small class="tgw">'+esc(t(r.why))+'</small></div>'}).join('')+'</div>'+
  '<p class="sub" style="margin:10px 0 0">'+t('A tunnel per kind of traffic: an AmneziaWG link for WireGuard and AmneziaWG, a Game tunnel for microtun and KANKI MIX, TCP Mux for Xray. Tap a best tunnel to open the form with it, then tap the cores whose ports it should carry.')+'</p>'+
  '<p class="sub" style="margin:6px 0 0">'+t('Networks in Iran differ: before choosing, «Smart tunnel» tests every transport between your two servers and shows the best one.')+'</p>'}
function tunGuide(){modal(mhead(t('Which tunnel for which protocol'))+tunGuideHtml(),'wide');
 $$('#mbox [data-tg]').forEach(function(b){b.onclick=function(){var r=TGUIDE[+b.dataset.tg];closeModal();tunEdit(null,tunGuidePre(r.best[0]))}})}
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
  '<div class="nh" style="margin-top:8px"><span></span><button type="button" class="b2 sm" id="tw_aw_vpn">'+ic('ports',14)+' '+t('All ports of the exit server')+'</button></div><div class="corechips" id="tw_aw_cc"></div><p class="muted" id="tw_aw_pn" style="font-size:12px;margin:2px 0 0"></p>'+
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
  '<div id="tw_pc"><div class="nh" style="margin-top:12px"><b>'+t('Ports to carry')+'</b><button class="b2 sm" id="tw_vpn">'+ic('ports',14)+' '+t('All ports of the exit server')+'</button></div>'+
  '<div class="corechips" id="tw_cc"></div>'+
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
   if(pn)pn.textContent=t('Ports of')+' '+(n?n.name:tunSrv(ex).name)+' ('+what+') '+t('were filled in')+(moved.length?' · '+t('Moved on the entry because they were taken')+': '+moved.join(', '):'');cc.paint();acc.paint()}).catch(function(e){if(manual)fail(e)})}
 // one button per core of the exit server: its ports go into (or out of) the boxes. Ports the entry
 // already uses (other tunnels, its own VPN, the tunnel port) are moved there, as above.
 var entryOwn={tcp:[],udp:[]},loadOwn=function(){var en=$('#tw_en').value;return Promise.all([tunNodeFor(en),tunSvcPorts(en)]).then(function(r){entryOwn=tunMerge(r[0]?tunNodePorts(r[0]):{tcp:[],udp:[]},r[1])}).catch(function(){})};
 var entryUse=function(){var en=$('#tw_en').value,u=tunPortUse(en,id),l=st.mode=='direct'?$('#tw_ex').value:en,pt=+$('#tw_pt').value;
  entryOwn.tcp.forEach(function(p){u.tcp[p]=1});entryOwn.udp.forEach(function(p){u.udp[p]=1});
  if(st.kind=='awg'){var ap=+(($('#tw_aw_pt')||{}).value||0);if(ap)u.udp[ap]=1}else if(l==en&&pt){if(tunBoth(st.tr)){u.udp[pt]=1;u.tcp[pt]=1}else(tunUdpTr(st.tr)?u.udp:u.tcp)[pt]=1}return u};
 var exitCores=function(){var ex=$('#tw_ex').value;if(ex==$('#tw_en').value)return Promise.resolve([]);return Promise.all([tunNodeFor(ex),tunSvcGroups(ex),loadOwn()]).then(function(r){return tunCoreGroups(r[0]&&r[0].info,r[1])})};
 var cc=coreChips({box:'#tw_cc',tcp:'#tw_tcp',udp:'#tw_udp',note:'#tw_pn',cores:exitCores,used:entryUse});
 var acc=coreChips({box:'#tw_aw_cc',tcp:'#tw_aw_ft',udp:'#tw_aw_fu',note:'#tw_aw_pn',cores:exitCores,used:entryUse});
 $('#tw_en').onchange=function(){hint();cc.load();acc.load();if(!id)fillPorts(false)};$('#tw_ex').onchange=function(){hint();cc.load();acc.load();if(!id)fillPorts(false)};
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
 // AmneziaWG: the same ports go into its forward fields (VPN, KANKI MIX, microtun, Xray, DNS of the exit); a port the
 // entry itself uses moves to the next free one there ("4101:4100")
 if($('#tw_aw_vpn'))$('#tw_aw_vpn').onclick=function(){var en=$('#tw_en').value,ex=$('#tw_ex').value,pn=$('#tw_aw_pn');if(en==ex)return;
  Promise.all([tunNodeFor(ex),tunNodeFor(en),tunSvcPorts(ex),tunSvcPorts(en)]).then(function(r){var n=r[0],m=r[1];
   var P=tunMerge(n?tunNodePorts(n):{tcp:[],udp:[]},r[2]),E=tunMerge(m?tunNodePorts(m):{tcp:[],udp:[]},r[3]);
   if(!P.tcp.length&&!P.udp.length){toast(t('No node found for this server: type the ports by hand'));return}
   var use={tcp:{},udp:{}},moved=[],apt=+(($('#tw_aw_pt')||{}).value||0);E.tcp.forEach(function(p){use.tcp[p]=1});E.udp.forEach(function(p){use.udp[p]=1});if(apt)use.udp[apt]=1;
   var mp=function(arr,u){return arr.map(function(p){var q=p;while(u[q]&&q<65535)q++;u[q]=1;if(q!=p)moved.push(q+'→'+p);return q==p?String(p):q+':'+p})};
   $('#tw_aw_ft').value=mp(P.tcp,use.tcp).join(', ');$('#tw_aw_fu').value=mp(P.udp,use.udp).join(', ');acc.paint();
   if(pn)pn.textContent=t('Ports of')+' '+(n?n.name:tunSrv(ex).name)+' '+t('were filled in')+(moved.length?' · '+t('Moved on the entry because they were taken')+': '+moved.join(', '):'')}).catch(fail)};
 $('#tw_kd').onclick=function(e){var b=e.target.closest('button');if(!b)return;st.kind=b.dataset.v;kindUi()};
 $('#tw_aw_wrap').onchange=function(){st.wrap=this.checked;kindUi()};$('#tw_aw_pt').oninput=function(){this.dataset.touched=1};
 $('#tw_hy_pt').oninput=function(){this.dataset.touched=1};var h1=$('#tw_hy_c1'),h2=$('#tw_hy_c2');if(h1)h1.onclick=function(){hy2Conf(id,'entry')};if(h2)h2.onclick=function(){hy2Conf(id,'exit')};
 var c1=$('#tw_aw_c1'),c2=$('#tw_aw_c2');if(c1)c1.onclick=function(){awgConf(id,'entry')};if(c2)c2.onclick=function(){awgConf(id,'exit')};
 $('#tw_smart').onclick=function(){if($('#tw_en').value==$('#tw_ex').value){toast(t('The entry and the exit must be different'),1);return}
  var L=function(v){return String(v||'').split(/[\s,]+/).filter(Boolean)},g=function(k){var e=$(k);return e?e.value:''};
  tunSmart({entry:$('#tw_en').value,exit:$('#tw_ex').value,prof:$('#tw_pf').value,apply:{id:id,snap:{name:$('#tw_nm').value,mode:st.mode,transport:st.tr,port:+$('#tw_pt').value||0,conns:TNP[$('#tw_pf').value]||4,tcp:L($('#tw_tcp').value),udp:L($('#tw_udp').value),dial:g('#tw_dl'),target:g('#tw_tg'),sni:g('#tw_sni'),host:g('#tw_host'),frag:!!($('#tw_frag2')&&$('#tw_frag2').checked),path:g('#tw_pa'),auto:!!($('#tw_au')&&$('#tw_au').checked),fec:st.tr=='game'?g('#tw_fec'):'',dup:st.tr=='game'&&!!($('#tw_dup')&&$('#tw_dup').checked)}}})};
 hint();kindUi();cc.load();acc.load();if(!id&&!(x.tcp||[]).length&&!(x.udp||[]).length&&st.kind!='awg')fillPorts(false);livePorts(id);
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
function hy2Conf(id,side){api('GET','/api/tunnels/'+id+'/hy2conf/'+side).then(function(r){modal(mhead(t('Config')+' · '+(side=='exit'?t('Exit'):t('Entry')))+'<p class="muted">'+'hysteria '+(side=='exit'?'server':'client')+' -c … · '+t('It holds the password: do not share it.')+' <span class="ltr">'+esc(r.file)+'</span></p><pre class="ltr" style="white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:50vh;overflow:auto">'+esc(r.conf)+'</pre><button class="btn" id="hy_cp" style="width:100%;margin-top:8px">'+t('Copy')+'</button>');$('#hy_cp').onclick=function(){copy(r.conf)}}).catch(fail)}

// ---- AmneziaWG: show the config of one side (for a server that does not run the agent)
function awgConf(id,side){api('GET','/api/tunnels/'+id+'/awgconf/'+side).then(function(r){modal(mhead(t('Config')+' · '+(side=='exit'?t('Exit'):t('Entry')))+'<p class="muted">'+t('Save it as the file below in /etc/amnezia/amneziawg/ and run awg-quick up. It holds a private key: do not share it.')+' <span class="ltr">'+esc(r.file)+'</span></p><pre class="ltr" id="aw_cf" style="white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:50vh;overflow:auto">'+esc(r.conf)+'</pre><button class="btn" id="aw_cp" style="width:100%;margin-top:8px">'+t('Copy')+'</button>');$('#aw_cp').onclick=function(){copy(r.conf)}}).catch(fail)}

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
 $('#tw_scres').innerHTML='<small class="muted" style="display:block;margin-top:6px">'+(fa?'این را روی سرور ایران (ورودی) اجرا کن: bash scan.sh   یا با رنج دیگر: bash scan.sh 185.143.233.0/24. خروجی OK-WS یعنی آن آی‌پی WebSocket تو را رد کرد؛ REACH یعنی لبهٔ CDN باز است ولی مسیر/Host درست نیست.':'Run this on the Iran (entry) server: bash scan.sh   or with another range: bash scan.sh 185.143.233.0/24. OK-WS means that IP passed your WebSocket; REACH means the CDN edge is open but the path/Host is not right.')+'</small><textarea id="tw_scta" class="ltr" rows="9" style="width:100%;font-size:12px" readonly></textarea><button type="button" class="b2 sm" id="tw_sccp">'+t('Copy')+'</button>';
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


