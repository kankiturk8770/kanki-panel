// ==================================================================== microtun
// the microtun page: the light game VPN, ticked per user like KANKI MIX. It runs on every VPN server
// on a port of its own. Same tabs as every core.
var KC={d:{},tab:{},meta:{
 mtun:{name:'microtun',net:'UDP',desc:'A light game VPN: 28 bytes per packet (WireGuard 32), keys renewed every 2 minutes, small packets sent twice so one lost packet does not lag. Nothing on the wire looks like a protocol.'}}};
// the API of a protocol page
function kcApi(p){return '/api/mt'}

function kcPage(p){var m=KC.meta[p];KAcc.open['kc_'+p]='';KAcc.open['tn_'+p]='';var k=corePage(p,'kc','game',esc(m.name),t(m.desc));if(!k)return;KC.tab[p]=k;
 kcLoad(p);clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!busyTyping())kcLoad(p,true)},8000)}
function p_mtun(){kcPage('mtun')}
function tab_mtun(sub){var k=ctabOf(sub);if(k!=sub){location.replace('#mtun/'+k);return}KC.tab.mtun=k;coreTabsMark('mtun','kc',k);if(KC.d.mtun)kcDraw(KC.d.mtun);else kcLoad('mtun')}
function kcLoad(p,quiet){return srvLoad(true).then(function(){return api('GET',kcApi(p))}).then(function(d){KC.d[p]=noRelays(d);if(S.page!=p)return d;var tab=KC.tab[p];
  if(quiet){if(tab=='status'&&$('#kc_st')){$('#kc_st').innerHTML=kcStats(d);return d}
   if(tab=='servers'&&$('#kc_srv')){if(!accBusy('kc_'+p))$('#kc_srv').innerHTML=kcServers(d);return d}
   if(tab=='tunnel'&&$('#kc_tun')){if(!accBusy('tn_'+p))$('#kc_tun').innerHTML=kcTunRows(d);return d}
   return d}
  kcDraw(d);return d}).catch(fail)}
function kcStats(d){var run=d.servers.filter(function(x){return x.port}).length,on=d.servers.filter(function(x){return x.on}).length;
 return kuStats([[t('Running servers'),N(run)+' / '+N(on),run<on?'y':''],[t('Users with it'),N(d.users)+' / '+N(d.users_total)],[t('Online now'),N(d.online),d.online?'g':''],[t('Total traffic'),'<span class="ltr">'+N(d.traffic_gb)+' GB</span>']])}
function kcState(x){if(!x.on)return ['','Off on this server'];if(x.port)return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
// servers tab: one row per server; a tap shows microtun on that server (its port, address, switch)
function kcServers(d){if(!d.servers.length)return '<p class="muted ku-empty">'+t('No VPN server yet')+'</p>';var p=d.proto,net=KC.meta[p].net;
 return d.servers.map(function(x){var st=kcState(x),s=window.srvByNode?srvByNode(x.id):null;
  var head='<span class="dot '+(st[0]||'')+'"></span>'+flagOf(s&&s.cc)+'<b>'+esc(x.name)+'</b>'+(x.main?'<span class="kxc-tag main">'+t('Main server')+'</span>':'')+'<span class="sp"></span>'+
   '<span class="kxr-st '+(st[0]||'')+'">'+t(st[1])+'</span>'+(x.v6?'<span class="kxr-st">IPv6</span>':'')+'<small class="ltr">'+net+' '+N(x.port||x.want_port)+'</small>';
  return accRow('kc_'+p,x.id,head,function(){return kcBody(d,x)})}).join('')}
function kcBody(d,x){var p=d.proto,id=esc(x.id),o=(d.settings.nodes||{})[x.id]||{};
 return '<div class="kxr-line"><span><b>'+t(kcState(x)[1])+'</b></span><span>·</span><span>'+N(x.users)+' '+t('users')+'</span><span>·</span><span class="ltr">'+esc(x.host||'?')+':'+esc(String(x.port||x.want_port))+'</span></div>'+
  kuSwitch(esc(KC.meta[p].name)+' '+t('on this server'),x.on,"kcNodeOn('"+p+"','"+id+"',this.checked)")+
  '<div class="kxf"><div><label class="f">'+t('Port of this server')+'</label><input class="ltr" id="kc_np1" inputmode="numeric" placeholder="'+esc(t('default'))+' '+N(d.settings.port)+'" value="'+esc(o.port||'')+'"></div>'+
  '<div><label class="f">'+t('Address the app dials')+'</label><input class="ltr" id="kc_ho1" placeholder="'+esc(t('automatic'))+'" value="'+esc(o.host||'')+'"></div></div>'+
  (x.on&&x.online&&!x.reports&&d.settings.on?'<div class="warnbox" style="margin:8px 0 0">'+t('Update the agent of this server to run it')+'</div>':'')+
  (x.on&&x.error?'<div class="warnbox ltr" style="margin:8px 0 0">'+esc(x.error)+'</div>':'')+
  '<div class="kxsave"><button class="b2 sm" onclick="accClose(\'kc_'+p+'\')">'+t('Cancel')+'</button><button class="btn sm" onclick="kcSaveOne(\''+p+'\',\''+id+'\')">'+t('Save')+'</button></div>'+
  '<div class="kxacts"><button class="b2 sm" onclick="nAct(\''+id+'\',\'repair\')">↻ '+t('Restart VPN services')+'</button></div>'}
function kcSaveOne(p,id){var m=kcNodes(p),o=m[id]||{},v=unN($('#kc_np1').value).trim();if(v&&(!/^\d+$/.test(v)||+v<1||+v>65535))return toast(t('the port must be 1-65535'),1);
 o.port=v?+v:0;o.host=$('#kc_ho1').value.trim();m[id]=o;KAcc.open['kc_'+p]='';kcPut(p,{nodes:m})}
// tunnel tab: the second config of microtun on each server
function kcTunRows(d){var list=d.servers.map(function(x){return window.srvByNode?srvByNode(x.id):null}).filter(function(s){return s&&s.key});return coreTunRows(d.proto,'tn_'+d.proto,list)}
function kcDraw(d){var el=$('#kc');if(!el)return;var s=d.settings,p=d.proto,m=KC.meta[p],tab=KC.tab[p]||'status';
 if(tab=='servers'){el.innerHTML=kuGroup(t('Servers'),d.servers.length,'','<div id="kc_srv">'+kcServers(d)+'</div>');return}
 if(tab=='tunnel'){el.innerHTML=kuGroup(t('Second config through the tunnel'),d.servers.length,'','<p class="muted ku-note">'+t('Only for this core. Empty = the tunnel domain of the server (Servers page).')+'</p><div id="kc_tun">'+kcTunRows(d)+'</div>');
  KAcc.draw['tn_'+p]=function(){var c=$('#kc_tun');if(c&&KC.d[p])c.innerHTML=kcTunRows(KC.d[p])};return}
 if(tab=='settings'){el.innerHTML=kuGroup(t('Settings'),null,'','<div class="ku-form">'+
   '<label class="f">'+t('Default port')+' · '+m.net+'</label><input id="kc_port" class="ltr" inputmode="numeric" value="'+esc(String(s.port))+'"><small class="muted">'+t('Every server uses it unless it has its own port below.')+'</small>'+
   (p=='mtun'?'<label class="f">'+t('Send small packets twice: up to (bytes)')+'</label><input id="kc_bm" class="ltr" inputmode="numeric" value="'+esc(String(s.burst_max))+'"><small class="muted">'+t('0 = off. Game packets are 50-300 bytes; downloads are sent once.')+'</small>'+
    '<label class="f">'+t('Delay of the second copy (ms)')+'</label><input id="kc_bd" class="ltr" inputmode="numeric" value="'+esc(String(s.burst_delay_ms))+'">'+
    '<label class="f">MTU</label><input id="kc_mtu" class="ltr" inputmode="numeric" value="'+esc(String(s.mtu))+'">':'')+'</div>'+
   '<div class="ku-save"><button class="btn" id="kc_save">'+t('Save')+'</button></div>')+
  (p=='mtun'?kuGroup(t('Test link'),null,'','<div class="ku-form"><p class="muted" style="margin:0 0 8px">'+t('A user\'s mtun:// link per server, for the Linux client:')+'</p><code class="ltr" style="display:block;margin-bottom:8px">sudo microtun client -url \'LINK\'</code>'+
   '<select id="mt_u" onchange="mtLinks()"><option value="">'+t('Choose a user')+'</option>'+(d.user_list||[]).map(function(u){return '<option value="'+u.id+'">'+esc(u.name)+(u.has?'':' ('+t('not ticked')+')')+'</option>'}).join('')+'</select><div id="mt_l" style="margin-top:8px"></div></div>'):'');
  $('#kc_save').onclick=function(){kcSave(p)};return}
 el.innerHTML=(s.on?'':'<div class="warnbox">'+esc(m.name)+' '+t('is off: it runs on no server and is in no subscription.')+'</div>')+'<div id="kc_st">'+kcStats(d)+'</div>'+
  kuGroup(esc(m.name),null,'',kuSwitch(esc(m.name)+' '+t('is on'),s.on,"kcPut('"+p+"',{on:this.checked})")+
   kuLine(t('Every user'),'<button class="b2 sm" onclick="kcAll(\''+p+'\',false)">'+t('Disable for all users')+'</button><button class="b2 sm" onclick="kcAll(\''+p+'\',true)">'+t('Enable for all users')+'</button>'))+
  '<details class="ku-help"><summary>'+t('How it works')+'</summary><p>'+t('Tick it for a user (user form, or Enable for all users). Every server runs it by itself within a minute; the Kanki app gets the link from the subscription. Each user has their own key: a new link is a new key, an expired or disabled user is cut off at once. Open the port at the data center\'s firewall too.')+'</p></details>'}
function kcNodes(p){var d=KC.d[p],m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});return m}
function kcPut(p,b){return api('PUT',kcApi(p),b).then(function(){toast(t('Saved'));return kcLoad(p)}).catch(fail)}
function kcNodeOn(p,id,on){var m=kcNodes(p),o=m[id]||{};o.off=!on;m[id]=o;kcPut(p,{nodes:m})}
function kcSave(p){var v=unN($('#kc_port').value).trim();if(!/^\d+$/.test(v)||+v<1||+v>65535)return toast(t('the port must be 1-65535'),1);
 var b={port:+v};
 if($('#kc_bm'))b.burst_max=+unN($('#kc_bm').value)||0;if($('#kc_bd'))b.burst_delay_ms=+unN($('#kc_bd').value)||0;if($('#kc_mtu'))b.mtu=+unN($('#kc_mtu').value)||1420;kcPut(p,b)}
function mtLinks(){var id=$('#mt_u').value,el=$('#mt_l');if(!id){el.innerHTML='';return}
 api('GET','/api/mt/links/'+id).then(function(r){el.innerHTML=r.links.length?r.links.map(function(l){return '<label class="f">'+esc(l.server)+(l.tunnel?' · '+t('through the tunnel'):'')+'</label><textarea class="ltr" readonly rows="3" style="width:100%" onclick="this.select()">'+esc(l.url)+'</textarea>'}).join(''):'<div class="warnbox">'+t(r.why)+'</div>'}).catch(fail)}
function kcAll(p,on){var n=KC.meta[p].name;if(!confirm(on?n+' '+t('for every user?'):n+': '+t('Remove from every user?')))return;
 api('POST',kcApi(p)+'/users',{on:on}).then(function(r){toast(t('Saved')+' · '+N(r.changed)+' '+t('users changed'));kcLoad(p)}).catch(fail)}

