// ==================================================================== KPING
// The game core (kping.rs, kpingd.rs). Since 3.58 a core like KANKI MIX and microtun: every VPN server where it is
// on runs the relay on a public UDP port and the exit behind it (`kping0`, NAT out). The app dials the server
// straight, or its Iran address when the server's tunnel carries the KPING port (the second config, like every
// core). Only the users ticked here get it, only the Kanki app receives it (sealed). Tabs: Status, Servers, Users,
// Settings. (Until 3.57 KPING had routes of its own on the Tunnels page; they are gone.)
var KP={d:null,tab:'status',at:0};
var KPTABS=[['status','Status'],['servers','Servers'],['users','Users'],['settings','Settings']];
function p_kping(){if(S.sub=='tunnel'){location.replace('#kping/servers');return}var k=ctabOf(S.sub,KPTABS);if(S.sub&&k!=S.sub){location.replace('#kping/'+k);return}KP.tab=k;
 $('#pg').innerHTML='<div class="ku">'+kuHead('game','KPING',t('The game core on your servers, like every core, only in the Kanki app.'))+
  '<nav class="ptabs ku-tabs" id="kp_tabs">'+kuTabs('kping',KPTABS,k)+'</nav><div id="kp">'+t('Loading…')+'</div></div>';
 kpLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!busyTyping())kpLoad(true)},8000)}
function tab_kping(sub){if(sub=='tunnel'){location.replace('#kping/servers');return}var k=ctabOf(sub,KPTABS);if(k!=sub){location.replace('#kping/'+k);return}KP.tab=k;var el=$('#kp_tabs');if(el)el.innerHTML=kuTabs('kping',KPTABS,k);if(KP.d)kpDraw(KP.d);else kpLoad()}
function kpLoad(quiet){return srvLoad(true).then(function(){return api('GET','/api/kping')}).then(function(d){KP.d=d;KP.at=Date.now();
  if(S.page!='kping')return d;
  // a quiet round only redraws what cannot be in the middle of being typed
  if(quiet&&KP.tab=='settings')return d;kpDraw(d);return d}).catch(function(e){if(!quiet)fail(e)})}

// ---------------------------------------------------------------- one server
// [colour, words]
function kpState(x){if(!x.on)return ['',t('Off')];
 if(!x.online)return ['r',t('Offline')];
 if(!x.knows)return ['y',t('Update this server')];
 if(x.relay_error||x.exit_error)return ['r',t('Not running')];
 if(!x.runs)return ['y',t('Starting…')];
 return ['g',t('Running')]}
function kpCC(nid){var s=window.srvFind?srvFind(nid):null;return s&&s.cc}
function kpItem(x,i){var st=kpState(x);
 return kuItem({dot:st[0],flag:flagOf(kpCC(x.id)),name:esc(x.name||x.id),off:!x.on,
  tags:kuTag(st[1],st[0])+(x.online_users?kuTag(N(x.online_users)+' '+t('online'),'g'):'')+(x.tunnel?kuTag(t('Tunnel')):''),
  addr:esc(x.direct)+(x.tunnel?' · '+esc(x.tunnel):''),
  act:'<span class="sw" title="'+esc(t('KPING on this server'))+'"><input type="checkbox" aria-label="'+esc(t('KPING on this server'))+'"'+(x.on?' checked':'')+' onchange="kpNode('+i+',{on:this.checked})"><span></span></span>',
  menu:'kpMenu('+i+')',
  extra:x.relay_error||x.exit_error?'<p class="muted ku-note">'+esc(x.relay_error||x.exit_error)+'</p>':''})}
function kpMenu(i){var x=KP.d&&KP.d.servers[i];if(!x)return;kuMenu(esc(x.name||x.id),'KPING',[[t('Port'),'kpPort('+i+')']])}
function kpStats(d){var on=d.servers.filter(function(x){return x.on}),run=on.filter(function(x){return kpState(x)[0]=='g'});
 return kuStats([[t('Running'),N(run.length)+' / '+N(on.length),run.length<on.length?'y':(run.length?'g':'')],[t('Users'),N(d.users)],[t('Online now'),N(d.online),d.online?'g':''],[t('Servers'),N(d.servers.length)]])}
function kpDraw(d){var el=$('#kp');if(!el)return;var s=d.settings,tab=KP.tab;
 if(tab=='users'){el.innerHTML=kpUsers(d);return}
 if(tab=='settings'){el.innerHTML=kpSettings(d);$('#kp_save').onclick=kpSave;return}
 if(tab=='servers'){el.innerHTML=kuGroup(t('Servers'),d.servers.length,'','<p class="muted ku-note">'+t('Each server runs KPING like its other cores. Its second config (through Iran) comes from the server\'s tunnel, like every core: the tunnel must carry the KPING port.')+'</p>'+
  (d.servers.map(kpItem).join('')||'<p class="muted ku-empty">'+t('No server yet')+'</p>'));return}
 el.innerHTML=(s.on?'':'<div class="warnbox">'+t('KPING is off: no server runs it and no user gets it.')+'</div>')+kpStats(d)+
  kuGroup('KPING',null,'',kuSwitch(t('KPING is on'),s.on,"kpPut({on:this.checked})",t('Off = it stops on every server and leaves every user\'s app')))+
  '<details class="ku-help"><summary>'+t('How it works')+'</summary><p>'+t('KPING runs on each server where it is on (Servers), like every core. Users: choose who gets it. The Kanki app of those users shows KPING in gaming mode, straight to each server and through Iran when the server\'s tunnel carries the KPING port. KPING is never on the subscription page, in links or in the bot.')+'</p></details>'}
function kpUsers(d){var on=d.user_list.filter(function(u){return u.has}),off=d.user_list.filter(function(u){return !u.has});
 var add='<div class="kp-add"><select id="kp_u"><option value="">'+t('Choose a user')+'</option>'+off.map(function(u){return '<option value="'+u.id+'">'+esc(u.name)+(u.active?'':' ('+t('not active')+')')+'</option>'}).join('')+'</select>'+
  '<button class="btn sm" onclick="kpUser(+$(\'#kp_u\').value,true)">'+ic('plus',14)+' '+t('Add user')+'</button></div>';
 return kuGroup(t('Users'),on.length,'','<p class="muted ku-note">'+t('Only these users get KPING, and only inside the Kanki app.')+'</p>'+add+
  (on.length?on.map(function(u){return kuItem({dot:u.active?'g':'',name:esc(u.name),off:!u.active,tags:u.active?'':kuTag(t('not active'),'y'),
   act:'<button class="b2 sm" onclick="kpUser('+u.id+',false)">'+t('Remove')+'</button>'})}).join(''):'<p class="muted ku-empty">'+t('No user yet')+'</p>'))}
function kpSettings(d){var s=d.settings;
 return kuGroup(t('Settings'),null,'','<div class="ku-form">'+
  '<label class="f">'+t('Port on the servers')+' · UDP</label><input id="kp_pub" class="ltr" inputmode="numeric" value="'+esc(String(s.public))+'"><small class="muted">'+t('The port the app dials on each server (a server may have its own, Servers › Port). It is opened in the firewall.')+'</small>'+
  '<label class="f">'+t('Second copy to the phone on one path (ms)')+'</label><input id="kp_bd" class="ltr" inputmode="numeric" value="'+esc(String(s.dup_ms))+'"><small class="muted">'+t('With Wi-Fi and mobile data both on, each path gets one copy. 0 = no second copy.')+'</small>'+
  '<label class="f">'+t('Parity: one repair packet per')+'</label><input id="kp_fec" class="ltr" inputmode="numeric" value="'+esc(String(s.fec))+'"><small class="muted">'+t('Packets (2-8). It rebuilds one lost packet of the group. 0 = off.')+'</small>'+
  '<label class="f">MTU</label><input id="kp_mtu" class="ltr" inputmode="numeric" value="'+esc(String(s.mtu))+'"><small class="muted">'+t('Used when automatic MTU is off. Now')+' <span class="ltr">'+N(d.mtu_now)+'</span></small></div>'+
  '<div class="ku-save"><button class="btn" id="kp_save">'+t('Save')+'</button></div>')}

// ---------------------------------------------------------------- actions
function kpPut(b){return api('PUT','/api/kping',b).then(function(){toast(t('Saved'));return kpLoad()}).catch(fail)}
function kpSave(){var v={};var n=function(id){return unN($(id).value).trim()};
 if(!/^\d+$/.test(n('#kp_pub'))||+n('#kp_pub')<1||+n('#kp_pub')>65535)return toast(t('the port must be 1-65535'),1);
 v.public=+n('#kp_pub');v.dup_ms=+n('#kp_bd')||0;v.fec=+n('#kp_fec')||0;v.mtu=+n('#kp_mtu')||1332;kpPut(v)}
function kpNode(i,b){var x=KP.d&&KP.d.servers[i];if(!x)return;api('POST','/api/kping/servers/'+encodeURIComponent(x.id),b).then(function(){toast(t('Saved'));kpLoad()}).catch(fail)}
function kpPort(i){var x=KP.d&&KP.d.servers[i];if(!x)return;
 modal(mhead(t('Port'),esc(x.name||x.id))+'<div class="ku-form"><label class="f">UDP</label><input id="kp_np" class="ltr" inputmode="numeric" value="'+esc(String(x.port))+'"></div><div class="ku-save"><button class="btn" id="kp_npg">'+t('Save')+'</button></div>');
 $('#kp_npg').onclick=function(){var p=+unN($('#kp_np').value).trim();if(!(p>=1&&p<=65535))return toast(t('the port must be 1-65535'),1);closeModal();kpNode(i,{port:p})}}
function kpUser(id,on){if(!id)return toast(t('Choose a user'),1);api('POST','/api/kping/users',{id:id,on:on}).then(function(){toast(t('Saved'));kpLoad()}).catch(fail)}
