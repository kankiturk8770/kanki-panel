// ==================================================================== KPING
// The hidden game core (kping.rs, kpingd.rs): app (Wi-Fi + mobile data) → the relay on an Iran server → its
// own reverse Game-FEC tunnel → the exit on a server abroad (only the tunnel agent: «Add server abroad») → the
// game. Only the testers ticked here get it, only the Kanki app receives it (sealed), and the app sends only
// PUBG through it. Tabs: Status (the path of every route), Servers (routes), Tunnel, Testers, Settings.
var KP={d:null,tab:'status'};
var KPTABS=[['status','Status'],['servers','Servers'],['tunnel','Tunnel'],['users','Testers'],['settings','Settings']];
function p_kping(){var k=ctabOf(S.sub,KPTABS);if(S.sub&&k!=S.sub){location.replace('#kping/'+k);return}KP.tab=k;
 $('#pg').innerHTML='<div class="ku">'+kuHead('game','KPING',t('The hidden game core: only PUBG, only in the Kanki app, only for the testers you choose'))+
  '<nav class="ptabs ku-tabs" id="kp_tabs">'+kuTabs('kping',KPTABS,k)+'</nav><div id="kp">'+t('Loading…')+'</div></div>';
 kpLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!busyTyping())kpLoad(true)},8000)}
function tab_kping(sub){var k=ctabOf(sub,KPTABS);if(k!=sub){location.replace('#kping/'+k);return}KP.tab=k;var el=$('#kp_tabs');if(el)el.innerHTML=kuTabs('kping',KPTABS,k);if(KP.d)kpDraw(KP.d);else kpLoad()}
function kpLoad(quiet){return srvLoad(true).then(function(){return api('GET','/api/kping')}).then(function(d){KP.d=d;if(S.page!='kping')return d;
  // a quiet round only redraws what cannot be in the middle of being typed
  if(quiet&&KP.tab=='settings')return d;kpDraw(d);return d}).catch(fail)}

// ---------------------------------------------------------------- the state of one route
// [colour, words, where it stops: 'exit' | 'tunnel' | '' (ready)]
function kpState(x){if(!x.exit_online)return ['r',t('The server abroad is offline'),'exit'];
 if(!x.exit_knows)return ['y',t('Update the agent of the server abroad'),'exit'];
 if(x.exit_error)return ['r',t('Not running'),'exit'];
 if(!x.exit_runs)return ['y',t('Starting on the server abroad…'),'exit'];
 if(!x.tunnel_built)return ['y',t('The tunnel is not built yet'),'tunnel'];
 if(!x.tunnel_up)return ['y',t('The tunnel is connecting…'),'tunnel'];
 if(!x.iran_online)return ['r',t('The Iran server is offline'),'iran'];
 if(x.relay&&x.relay.error)return ['r',t('Not running'),'iran'];
 if(!x.relay)return ['y',t('Starting on the Iran server…'),'iran'];
 return ['g',t('Ready'),'']}
// the tunnel between the Iran server and the exit: its kinds, and how one route's is called
var KPKINDS=[['game','Game-FEC'],['kcp','KCP'],['quic','QUIC'],['hq','HQ'],['faketcp','Fake TCP'],['vip','VIP']];
function kpKind(r){return r.kind||'game'}
function kpKindName(r){var k=kpKind(r);if(k=='game')return 'Game-FEC '+(r.fec||'8:1');if(k=='vip')return 'VIP · '+N(r.vip_paths||2)+' '+t('UDP paths');
 var o=KPKINDS.filter(function(x){return x[0]==k})[0];return o?o[1]:k}
function kpCC(sid){var s=window.srvFind?srvFind(sid):null;return s&&s.cc}
function kpQ(x){var q=x.tunnel_q;return q&&q.n?{ping:q.ping,loss:q.loss,jit:q.jit}:null}

// the path of one route, hop by hop: each part is lit up to the first one that does not work yet
function kpPath(x){var st=kpState(x),r=x.route,q=kpQ(x),stop=st[2];
 var hop=function(cls,icon,name,sub){return '<div class="kp-hop '+cls+'"><span class="kp-hi">'+icon+'</span><b>'+name+'</b><small><bdi dir="ltr">'+sub+'</bdi></small></div>'};
 var exitOk=stop!='exit',tunOk=stop==''||stop=='iran',irOk=stop=='',rl=x.relay||{};
 var link=q&&tunOk?'<span class="ltr">'+N(q.ping)+' ms · '+N(q.loss)+'%</span>':t(tunOk?'Measuring…':(x.tunnel_built?'Connecting…':'Not built'));
 return '<div class="kp-path">'+
  hop('ok',ic('phone',18),t('Kanki app'),t('only PUBG')+(rl.online?' · '+N(rl.online)+' '+t('online'):''))+
  '<i class="kp-ln '+(irOk?'ok':'')+'"></i>'+
  hop(irOk?'ok':stop=='iran'?'bad':'',flagOf('IR'),esc(x.iran_name||'?'),esc(x.dial)+(rl.paths?' · '+N(rl.paths)+' '+t('paths'):''))+
  '<div class="kp-tun '+(tunOk?'ok':x.tunnel_built?'wait':'')+'"><small>'+esc(kpKindName(r))+'</small><b>'+link+'</b></div>'+
  hop(exitOk?'ok':'bad',flagOf(kpCC(r.exit)),esc(x.exit_name||'?'),'kping0'+(x.exit_stats&&x.exit_stats.fixed?' · '+N(x.exit_stats.fixed)+' '+t('rebuilt'):''))+
  '<i class="kp-ln '+(tunOk?'ok':'')+'"></i>'+
  hop(tunOk?'ok':'',ic('game',18),'PUBG',t('the match'))+'</div>'}

// ---------------------------------------------------------------- tabs
function kpStats(d){var ready=d.routes.filter(function(x){return kpState(x)[0]=='g'}).length,qs=d.routes.map(kpQ).filter(Boolean);
 var best=qs.length?Math.min.apply(null,qs.map(function(q){return q.ping})):null;
 return kuStats([[t('Ready routes'),N(ready)+' / '+N(d.routes.length),ready<d.routes.length?'y':(ready?'g':'')],[t('Testers'),N(d.users)],[t('Online now'),N(d.online),d.online?'g':''],
  [t('Tunnel ping'),best==null?'—':'<span class="ltr">'+N(best)+' ms</span>']])}
function kpDraw(d){var el=$('#kp');if(!el)return;var s=d.settings,tab=KP.tab;
 if(tab=='servers'){el.innerHTML=kuGroup(t('Routes'),d.routes.length,'<button class="btn sm" onclick="kpEdit()">'+ic('plus',14)+' '+t('Add route')+'</button>',kpRoutes(d))+
  kuGroup(t('Servers abroad'),d.exits.length,'<button class="b2 sm" onclick="kpAddServer()">'+ic('plus',14)+' '+t('Add server abroad')+'</button>',
   '<p class="muted ku-note">'+t('Any server with the Kanki agent can be the exit. A new one needs only the agent: no VPN is installed on it.')+'</p>'+
   d.exits.map(function(o){return kuItem({dot:o.online?'g':'r',flag:flagOf(kpCC(o.id)),name:esc(o.name||o.id),tags:kuTag(t(o.online?'Online':'Offline'),o.online?'g':'r')+(o.agent_only?kuTag(t('Agent only')):'')})}).join(''));return}
 if(tab=='tunnel'){el.innerHTML=kuGroup(t('Tunnel of each route'),d.routes.length,'','<p class="muted ku-note">'+t('Reverse (the server abroad dials Iran) and only KPING. Its kind and settings are in each route (Edit): Game-FEC 8:1 by default, or KCP, QUIC, HQ, Fake TCP, or a VIP tunnel with several UDP paths.')+'</p>'+kpTunnels(d));return}
 if(tab=='users'){el.innerHTML=kpUsers(d);return}
 if(tab=='settings'){el.innerHTML=kpSettings(d);$('#kp_save').onclick=kpSave;return}
 el.innerHTML=(s.on?'':'<div class="warnbox">'+t('KPING is off: no server runs it and no tester gets it.')+'</div>')+kpStats(d)+
  (d.routes.length?d.routes.map(function(x){return '<section class="ku-group kp-route"><div class="ku-gh"><b>'+esc(x.iran_name||'?')+' → '+esc(x.exit_name||'?')+'</b><span class="sp"></span><span class="kxr-st '+kpState(x)[0]+'">'+esc(kpState(x)[1])+'</span></div><div class="ku-gb">'+kpPath(x)+
   (x.exit_error?'<div class="warnbox ltr" style="margin:0 16px 12px">'+esc(x.exit_error)+'</div>':'')+(x.relay&&x.relay.error?'<div class="warnbox ltr" style="margin:0 16px 12px">'+esc(x.relay.error)+'</div>':'')+'</div></section>'}).join('')
   :kuGroup(t('Routes'),0,'','<p class="muted ku-empty">'+t('No route yet. A route is one Iran server and one server abroad.')+'</p><div class="ku-save"><button class="btn" onclick="location.hash=\'#kping/servers\';setTimeout(kpEdit,50)">'+ic('plus',14)+' '+t('Add route')+'</button></div>'))+
  kuGroup('KPING',null,'',kuSwitch(t('KPING is on'),s.on,"kpPut({on:this.checked})",t('Off = it stops on every server and leaves every tester\'s app')))+
  '<details class="ku-help"><summary>'+t('How it works')+'</summary><p>'+t('1. Servers: add a route (an Iran server and a server abroad). 2. Tunnel: build its tunnel with one button. 3. Testers: choose who gets it. The Kanki app of a tester then shows KPING in gaming mode; it sends only PUBG (and the DNS and Google services the game logs in with) through it. KPING is never on the subscription page, in links or in the bot.')+'</p></details>'}
function kpRoutes(d){if(!d.routes.length)return '<p class="muted ku-empty">'+t('No route yet')+'</p>';
 return d.routes.map(function(x,i){var st=kpState(x),r=x.route;
  return kuItem({dot:st[0],flag:flagOf(kpCC(r.exit)),name:esc(x.iran_name||'?')+' → '+esc(x.exit_name||'?'),
   act:'<button class="b2 sm" onclick="kpEdit('+i+')">'+ic('edit',14)+' '+t('Edit')+'</button>',menu:'kpMenu('+i+')',
   tags:kuTag(esc(st[1]),st[0]=='g'?'g':st[0]=='r'?'r':'y')+kuTag(t('Users dial')+' UDP '+N(r.port))+kuTag(t('Tunnel port')+' '+N(r.tunnel_port)),
   addr:esc(x.dial)})}).join('')}
function kpTunnels(d){if(!d.routes.length)return '<p class="muted ku-empty">'+t('Add a route first (Servers)')+'</p>';
 return d.routes.map(function(x,i){var q=kpQ(x),st=kpState(x),built=x.tunnel_built;
  var dot=!built?'':x.tunnel_up?'g':'y';
  return kuItem({dot:dot,flag:flagOf('IR'),name:esc(x.iran_name||'?')+' → '+esc(x.exit_name||'?'),
   act:'<button class="'+(built?'b2':'btn')+' sm" onclick="kpTunnel('+i+')">'+ic(built?'refresh':'tunnel',14)+' '+t(built?'Build again':'Build tunnel')+'</button>',
   tags:kuTag(esc(kpKindName(x.route)))+(built?kuTag(t(x.tunnel_up?'Connected':'Connecting…'),x.tunnel_up?'g':'y'):kuTag(t('Not built'),'y'))+
    (x.vip&&x.vip.length?x.vip.map(function(p,j){return kuTag(t('Path')+' '+N(j+1)+' '+esc(p.kind=='udp'?'UDP':p.kind=='ftcp'?'Fake TCP':p.kind)+(p.state==2?' · <span class="ltr">'+N(Math.round(p.rtt))+' ms</span>':''),p.state==2?'g':p.state==1?'y':'r')}).join(''):'')+
    (q?kuTag('<span class="ltr">'+N(q.ping)+' ms</span>')+kuTag(t('loss')+' <span class="ltr">'+N(q.loss)+'%</span>',q.loss>3?'r':q.loss>1?'y':'g')+kuTag(t('jitter')+' <span class="ltr">'+N(q.jit)+' ms</span>'):'')+
    (st[2]=='exit'?kuTag(esc(st[1]),'r'):''),
   addr:'UDP 127.0.0.1:'+N(kpInner(x.route))+' → '+esc(x.exit_name||'?')+' 127.0.0.1:'+N(d.settings.port)})+(kpKind(x.route)=='vip'?'':kpTunnel2Item(d,x,i))}).join('')}
function kpInner(r){return r.tunnel_port+(kpKind(r)=='vip'?(r.vip_hop||4):1)}
// the route's second tunnel (KPING v3): every packet goes through both, the first copy wins; the relay's probes
// say how each one is doing
function kpTq(x,n){var a=x.relay&&x.relay.tunnels;return a&&a[n]?a[n]:null}
function kpTunnel2Item(d,x,i){if(!x.tunnel_built)return '';var b2=x.tunnel2_built,r=x.route,p2=r.tunnel2_port||r.tunnel_port+2;
 var q1=kpTq(x,0),q2=kpTq(x,1);
 var qt=function(q){return q?kuTag('<span class="ltr">'+N(q.rtt)+' ms</span>',q.up?'g':'r')+kuTag(t('loss')+' <span class="ltr">'+N(q.loss)+'%</span>',q.loss>3?'r':q.loss>1?'y':'g'):''};
 return kuItem({dot:!b2?'':x.tunnel2_up?'g':'y',flag:flagOf('IR'),name:t('Second tunnel')+' · '+esc(x.iran_name||'?')+' → '+esc(x.exit_name||'?'),
  act:b2?'<button class="b2 sm" onclick="kpTunnel2('+i+')">'+ic('refresh',14)+' '+t('Build again')+'</button> <button class="b2 sm" onclick="kpTunnel2Del('+i+')">'+t('Remove')+'</button>'
   :'<button class="btn sm" onclick="kpTunnel2('+i+')">'+ic('tunnel',14)+' '+t('Add second tunnel')+'</button>',
  tags:(b2?kuTag(t(x.tunnel2_up?'Connected':'Connecting…'),x.tunnel2_up?'g':'y')+kuTag(t('Tunnel 1'))+qt(q1)+kuTag(t('Tunnel 2'))+qt(q2)
   :kuTag(t('Every packet through two tunnels: a stall on one costs nothing'))),
  addr:'UDP 127.0.0.1:'+N(p2+1)+' → '+esc(x.exit_name||'?')+' 127.0.0.1:'+N(d.settings.port)})}
function kpTunnel2(i){var x=KP.d&&KP.d.routes[i];if(!x)return;toast(t('Checking…'));
 api('POST','/api/kping/routes/'+encodeURIComponent(x.route.id)+'/tunnel2').then(function(){toast(t('Tunnel built'));kpLoad()}).catch(fail)}
function kpTunnel2Del(i){var x=KP.d&&KP.d.routes[i];if(!x||!confirm(t('Remove the second tunnel? KPING goes on through the first one.')))return;
 api('DELETE','/api/kping/routes/'+encodeURIComponent(x.route.id)+'/tunnel2').then(function(res){
  return res.tunnel2?api('DELETE','/api/tunnels/'+encodeURIComponent(res.tunnel2)).catch(function(){}):null}).then(function(){toast(t('Deleted'));kpLoad()}).catch(fail)}
function kpUsers(d){var on=d.user_list.filter(function(u){return u.has}),off=d.user_list.filter(function(u){return !u.has});
 var add='<div class="kp-add"><select id="kp_u"><option value="">'+t('Choose a user')+'</option>'+off.map(function(u){return '<option value="'+u.id+'">'+esc(u.name)+(u.active?'':' ('+t('not active')+')')+'</option>'}).join('')+'</select>'+
  '<button class="btn sm" onclick="kpUser(+$(\'#kp_u\').value,true)">'+ic('plus',14)+' '+t('Add tester')+'</button></div>';
 return kuGroup(t('Testers'),on.length,'','<p class="muted ku-note">'+t('Only these users get KPING, and only inside the Kanki app.')+'</p>'+add+
  (on.length?on.map(function(u){return kuItem({dot:u.active?'g':'',name:esc(u.name),off:!u.active,tags:u.active?'':kuTag(t('not active'),'y'),
   act:'<button class="b2 sm" onclick="kpUser('+u.id+',false)">'+t('Remove')+'</button>'})}).join(''):'<p class="muted ku-empty">'+t('No tester yet')+'</p>'))}
function kpSettings(d){var s=d.settings;
 return kuGroup(t('Settings'),null,'','<div class="ku-form">'+
  '<label class="f">'+t('Port on the servers abroad')+' · UDP</label><input id="kp_port" class="ltr" inputmode="numeric" value="'+esc(String(s.port))+'"><small class="muted">'+t('Reached only through the tunnel: it stays closed in the firewall.')+'</small>'+
  '<label class="f">'+t('Second copy to the phone on one path (ms)')+'</label><input id="kp_bd" class="ltr" inputmode="numeric" value="'+esc(String(s.dup_ms))+'"><small class="muted">'+t('With Wi-Fi and mobile data both on, each path gets one copy. 0 = no second copy.')+'</small>'+
  '<label class="f">'+t('Second copy between Iran and abroad (ms)')+'</label><input id="kp_td" class="ltr" inputmode="numeric" value="'+esc(String(s.tun_dup_ms))+'"><small class="muted">'+t('Every packet goes twice through the tunnel, this far apart, so a short outage between the servers loses nothing. 0 = once.')+'</small>'+
  '<label class="f">'+t('Parity: one repair packet per')+'</label><input id="kp_fec" class="ltr" inputmode="numeric" value="'+esc(String(s.fec))+'"><small class="muted">'+t('Packets (2-8). It rebuilds one lost packet of the group. 0 = off.')+'</small>'+
  '<label class="f">MTU</label><input id="kp_mtu" class="ltr" inputmode="numeric" value="'+esc(String(s.mtu))+'"><small class="muted">'+t('Used when automatic MTU is off. Now')+' <span class="ltr">'+N(d.mtu_now)+'</span></small></div>'+
  '<div class="ku-save"><button class="btn" id="kp_save">'+t('Save')+'</button></div>')}

// ---------------------------------------------------------------- actions
function kpPut(b){return api('PUT','/api/kping',b).then(function(){toast(t('Saved'));return kpLoad()}).catch(fail)}
function kpSave(){var v={};var n=function(id){return unN($(id).value).trim()};
 if(!/^\d+$/.test(n('#kp_port'))||+n('#kp_port')<1||+n('#kp_port')>65535)return toast(t('the port must be 1-65535'),1);
 v.port=+n('#kp_port');v.dup_ms=+n('#kp_bd')||0;v.tun_dup_ms=+n('#kp_td')||0;v.fec=+n('#kp_fec')||0;v.mtu=+n('#kp_mtu')||1332;kpPut(v)}
// a new server abroad for KPING: only the tunnel agent (no VPN), with one command
function kpAddServer(){modal(mhead(t('Add server abroad'),'KPING')+'<div id="ka_in" class="ku-form"><p class="muted" style="margin:0 0 8px">'+t('Only the Kanki agent is installed: it runs the KPING exit and its tunnel. Choose a server close to the game servers.')+'</p>'+
  '<label class="f">'+t('Name')+'</label><input id="ka_nm" placeholder="'+esc(t('like Frankfurt'))+'">'+
  '<button class="btn" style="width:100%;margin-top:12px" id="ka_go">'+t('Make the command')+'</button></div><div id="sa_out"></div>','wide');
 $('#ka_go').onclick=function(){var me=this;me.disabled=true;
  api('POST','/api/servers',{name:$('#ka_nm').value.trim(),loc:'abroad',agent_only:true}).then(function(r){$('#ka_in').classList.add('hide');
   var o=$('#sa_out');o.innerHTML='<label class="f">'+t('Run this on the new server, as root (Ubuntu / Debian)')+'</label><pre class="cmd">'+esc(r.command)+'</pre>'+
    '<button class="btn" style="width:100%" id="ka_cp">'+ic('link',16)+' '+t('Copy command')+'</button><div class="kxp-steps" id="ka_st"></div>'+
    '<p class="muted" style="margin:8px 0 0">'+t('Then add a route to it (Servers › Add route). Its ports open by themselves.')+'</p>';
   $('#ka_cp').onclick=function(){copy(r.command)};kpWait(r.id)}).catch(function(e){me.disabled=false;fail(e)})}}
function kpWait(id){var el=$('#ka_st');if(!el||!$('#modal').classList.contains('on'))return;
 api('GET','/api/kping').then(function(d){KP.d=d;var o=d.exits.filter(function(x){return x.id==id})[0],on=o&&o.online;
  el.innerHTML='<div>'+(on?'<span class="okc">'+ic('check',16)+'</span>':'<span class="spin"></span>')+'<span>'+t(on?'Server agent connected':'Waiting for the server to connect…')+'</span></div>';
  if(!on)setTimeout(function(){kpWait(id)},4000);else if(S.page=='kping')kpDraw(d)}).catch(function(){setTimeout(function(){kpWait(id)},6000)})}
function kpUser(id,on){if(!id)return toast(t('Choose a user'),1);api('POST','/api/kping/users',{id:id,on:on}).then(function(){toast(t('Saved'));kpLoad()}).catch(fail)}
// add / edit a route in a window
function kpEdit(i){var d=KP.d;if(!d)return;var x=i!=null?d.routes[i]:null,r=x?x.route:{port:24300,tunnel_port:24301};
 var opt=function(list,cur){return '<option value="">'+t('Choose')+'</option>'+list.map(function(o){return '<option value="'+esc(o.id)+'"'+(o.id==cur?' selected':'')+'>'+esc(o.name)+(o.online===false?' ('+t('offline')+')':'')+'</option>'}).join('')};
 var exits=d.exits.filter(function(o){return o.sid});
 modal(mhead(x?t('Edit route'):t('Add route'),'KPING')+'<div class="ku-form">'+
  '<label class="f">'+t('Iran server (users connect to it)')+'</label><select id="kr_ir">'+opt(d.irans,r.iran)+'</select>'+
  (d.irans.length?'':'<small class="muted">'+t('No Iran server yet: add one on Tunnel servers and set its location to Iran.')+'</small>')+
  '<label class="f">'+t('Server abroad (KPING runs on it)')+'</label><select id="kr_ex">'+opt(exits,r.exit)+'</select>'+
  '<label class="f">'+t('Address users dial')+'</label><input id="kr_ho" class="ltr" placeholder="'+esc(t('automatic: the Iran server\'s address'))+'" value="'+esc(r.host||'')+'">'+
  '<div class="kxf"><div><label class="f">'+t('Users\' port')+' · UDP</label><input id="kr_po" class="ltr" inputmode="numeric" value="'+esc(String(r.port))+'"></div>'+
  '<div><label class="f">'+t('Tunnel port')+'</label><input id="kr_tp" class="ltr" inputmode="numeric" value="'+esc(String(r.tunnel_port))+'"></div></div>'+
  kpTunForm(r)+'</div>'+
  '<div class="kxsave"><button class="b2" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn" id="kr_go">'+t('Save')+'</button></div>');
 kpTunShow();
 $('#kr_go').onclick=function(){var b={id:r.id||'',iran:$('#kr_ir').value,exit:$('#kr_ex').value,host:$('#kr_ho').value.trim(),port:+unN($('#kr_po').value)||0,tunnel_port:+unN($('#kr_tp').value)||0};
  if(!b.iran||!b.exit)return toast(t('Choose both servers'),1);
  var tb=kpTunBody();for(var k in tb)b[k]=tb[k];
  // what the tunnel is made of changed: it is built again with it
  var tunChanged=!r.id||kpKind(r)!=b.kind||(r.fec||'')!=(b.fec||'')||(b.kind=='vip'&&((r.vip_paths||2)!=b.vip_paths||(r.vip_hop||4)!=b.vip_hop||(r.vip_hop_secs||0)!=b.vip_hop_secs||!!r.vip_ftcp!=b.vip_ftcp))||r.tunnel_port!=b.tunnel_port;
  var go=$('#kr_go');go.disabled=true;
  api('POST','/api/kping/routes',b).then(function(res){closeModal();toast(t('Saved'));
   if(tunChanged&&res.route)return api('POST','/api/kping/routes/'+encodeURIComponent(res.route.id)+'/tunnel').then(function(){toast(t('Saved')+' · '+t('Tunnel built'))}).catch(fail);
  }).then(function(){return kpLoad()}).catch(function(e){go.disabled=false;fail(e)})}}
// the tunnel part of the route form: its kind, and the settings of that kind in their own colour
function kpTunForm(r){var k=kpKind(r),fec=r.fec||'8:1';
 var o=function(list,cur){return list.map(function(x){return '<option value="'+esc(x[0])+'"'+(x[0]==cur?' selected':'')+'>'+esc(x[1])+'</option>'}).join('')};
 return '<div class="kp-legs"><div class="kp-leg phone"><b>'+ic('phone',14)+' '+t('Phone → Iran server')+'</b><small>'+t('Two networks (Wi-Fi + mobile data) are the app\'s: with both on, every packet goes on each and the first that arrives wins. Nothing to set here.')+'</small></div>'+
  '<div class="kp-leg srv"><b>'+ic('tunnel',14)+' '+t('Iran server → server abroad')+'</b><small>'+t('This is the tunnel below. Several paths here (VIP, or a second tunnel) are between the two servers, not the phone\'s networks.')+'</small></div></div>'+
  '<label class="f">'+t('Tunnel between the servers')+'</label><select id="kr_kind" onchange="kpTunShow()">'+o(KPKINDS.map(function(x){return [x[0],x[0]=='game'?x[1]+' ('+t('suggested')+')':x[1]]}),k)+'</select>'+
  '<div class="kp-adv" id="kr_adv_game"><b>'+t('Advanced: Game-FEC')+'</b><label class="f">FEC</label><select id="kr_fec">'+o([['8:1','8:1 · '+t('light, suggested for KPING')],['8:3','8:3 · '+t('more repairs')],['4:2','4:2'],['off',t('No FEC')]],fec)+'</select>'+
   '<small class="muted">'+t('KPING already repairs end to end and sends a second copy into the tunnel: 8:1 is enough.')+'</small></div>'+
  '<div class="kp-adv" id="kr_adv_vip"><b>'+t('Advanced: VIP tunnel')+'</b>'+
   '<div class="kxf"><div><label class="f">'+t('UDP paths at the same time')+'</label><select id="kr_vpa">'+o([['1','1'],['2','2 · '+t('suggested')],['3','3'],['4','4']],String(r.vip_paths||2))+'</select></div>'+
   '<div><label class="f">'+t('UDP ports it holds')+'</label><input id="kr_vho" class="ltr" inputmode="numeric" value="'+esc(String(r.vip_hop||4))+'"></div></div>'+
   '<div class="kxf"><div><label class="f">'+t('A path moves to another port every (seconds)')+'</label><input id="kr_vhs" class="ltr" inputmode="numeric" value="'+esc(String(r.vip_hop_secs||0))+'"><small class="muted">'+t('0 = never')+'</small></div>'+
   '<div><label class="f">'+t('Fake TCP path too')+'</label><div id="kr_vft">'+kuSwitch(t('For networks that throttle UDP'),!!r.vip_ftcp,'')+'</div></div></div>'+
   '<small class="muted">'+t('The game goes on the two best paths at once with repairs; when one of them stalls the other carries it without a jump. Paths only help when they are cut apart: on one shared line between the servers a VIP tunnel is about as good as Game-FEC. With two paths or more KPING\'s own second copy into the tunnel is off (VIP sends each packet on two paths); with one path it stays on. The agents need version 3.44 or newer.')+'</small></div>'+
  '<div class="kp-adv" id="kr_adv_other"><small class="muted">'+t('KCP, QUIC and HQ resend lost packets and wait for them; Fake TCP looks like a TCP session for networks that throttle UDP. For a game, Game-FEC or VIP is better.')+'</small></div>'}
function kpTunShow(){var k=($('#kr_kind')||{}).value||'game';
 ['game','vip','other'].forEach(function(x){var el=$('#kr_adv_'+x);if(el)el.style.display=(x==k||(x=='other'&&k!='game'&&k!='vip'))?'':'none'})}
function kpTunBody(){var k=$('#kr_kind').value,b={kind:k};
 if(k=='game')b.fec=$('#kr_fec').value;
 if(k=='vip'){b.vip_paths=+$('#kr_vpa').value||2;b.vip_hop=Math.min(16,Math.max(1,+unN($('#kr_vho').value)||4));b.vip_hop_secs=+unN($('#kr_vhs').value)||0;
  var ft=$('#kr_vft input');b.vip_ftcp=!!(ft&&ft.checked)}
 return b}
function kpTunnel(i){var x=KP.d&&KP.d.routes[i];if(!x)return;toast(t('Checking…'));
 api('POST','/api/kping/routes/'+encodeURIComponent(x.route.id)+'/tunnel').then(function(){toast(t('Tunnel built'));kpLoad()}).catch(fail)}
function kpMenu(i){var x=KP.d.routes[i];
 kuMenu(x.iran_name+' → '+x.exit_name,x.dial,[[t('Edit'),'kpEdit('+i+')'],[t(x.tunnel_built?'Build tunnel again':'Build tunnel'),'kpTunnel('+i+')'],[t('Delete route and its tunnel'),'kpDel('+i+')','danger']])}
function kpDel(i){var x=KP.d.routes[i];if(!confirm(t('Delete this route and its tunnel? Its testers lose it at once.')))return;
 // the panel removes the route's tunnels itself
 api('DELETE','/api/kping/routes/'+encodeURIComponent(x.route.id)).then(function(res){if(res&&res.removal&&window.kdFollowRemoval)kdFollowRemoval(res.removal);toast(t('Deleted'));kpLoad()}).catch(fail)}
