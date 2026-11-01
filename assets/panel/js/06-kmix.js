// ==================================================================== KANKI MIX
// the KANKI MIX page: our own UDP protocol on every VPN server, next to WireGuard, AmneziaWG and
// Hysteria2: game UDP on a raw datagram path (sent twice in gaming mode), TCP on KCP + FEC.
// The agent writes the built-in server to each server by itself; every user has their own key.
var KM={d:null,tab:'status'};
// the tabs every core has (CLAUDE.md, design rules); a core with more adds its own
var CTABS=[['status','Status'],['servers','Servers'],['tunnel','Tunnel'],['settings','Settings']];
function ctabOf(sub,tabs){return (tabs||CTABS).some(function(x){return x[0]==sub})?sub:'status'}
// a core page: the head, its tabs and the body (#<id>); old addresses (#kmix) open the status tab
function corePage(page,id,icon,title,desc){var k=ctabOf(S.sub);if(S.sub&&k!=S.sub){location.replace('#'+page+'/'+k);return ''}
 $('#pg').innerHTML='<div class="ku">'+kuHead(icon,title,desc)+'<nav class="ptabs ku-tabs" id="'+id+'_tabs">'+kuTabs(page,CTABS,k)+'</nav><div id="'+id+'">'+t('Loading…')+'</div></div>';return k}
function coreTabsMark(page,id,k){var el=$('#'+id+'_tabs');if(el)el.innerHTML=kuTabs(page,CTABS,k)}
// an Iran server whose VPN part serves nobody (a relay): not a server of any core
function srvRelay(s){return !!(s&&s.node&&!s.node.enabled&&(s.loc=='iran'||String(s.cc||'').toUpperCase()=='IR'))}
function noRelays(d){if(d&&d.servers&&window.srvByNode)d.servers=d.servers.filter(function(x){return !srvRelay(srvByNode(x.id))});return d}
function busyTyping(){return document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)}

function p_kmix(){KAcc.open.km='';KAcc.open.kmt='';var k=corePage('kmix','km','game','KANKI MIX',t('Our own protocol on every VPN server: game packets go straight (no queue, sent twice in gaming mode), websites over KCP + FEC.'));if(!k)return;KM.tab=k;
 kmLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!busyTyping())kmLoad(true)},8000)}
function tab_kmix(sub){var k=ctabOf(sub);if(k!=sub){location.replace('#kmix/'+k);return}KM.tab=k;coreTabsMark('kmix','km',k);if(KM.d)kmDraw(KM.d);else kmLoad()}
function kmLoad(quiet){return srvLoad(true).then(function(){return api('GET','/api/kmix')}).then(function(d){KM.d=noRelays(d);if(S.page!='kmix')return d;
  if(quiet){if(KM.tab=='status'&&$('#km_st')){$('#km_st').innerHTML=kmStats(d);return d}
   if(KM.tab=='servers'&&$('#km_srv')){if(!accBusy('km'))$('#km_srv').innerHTML=kmServers(d);return d}
   if(KM.tab=='tunnel'&&$('#km_tun')){if(!accBusy('kmt'))$('#km_tun').innerHTML=kmTunRows(d);return d}
   return d}
  kmDraw(d);return d}).catch(fail)}
function kmRun(x){return x.active===true}
function kmStats(d){var run=d.servers.filter(kmRun).length,on=d.servers.filter(function(x){return x.on}).length;
 return kuStats([[t('Running servers'),N(run)+' / '+N(on),run<on?'y':''],[t('Users with KANKI MIX'),N(d.users)+' / '+N(d.users_total)],[t('Online now'),N(d.online),d.online?'g':''],[t('Total traffic'),'<span class="ltr">'+N(d.traffic_gb)+' GB</span>']])}
function kmState(x){if(!x.on)return ['','Off on this server'];if(kmRun(x))return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
function kmDraw(d){var el=$('#km');if(!el)return;var s=d.settings;
 if(KM.tab=='servers'){el.innerHTML=kuGroup(t('Servers'),d.servers.length,'','<div id="km_srv">'+kmServers(d)+'</div>');return}
 if(KM.tab=='tunnel'){el.innerHTML=kuGroup(t('Second config through the tunnel'),d.servers.length,'','<p class="muted ku-note">'+t('Direct: the app connects straight to the foreign server, lowest ping. Tunnel: the app connects to the Iran server; the tunnel to this server must forward this UDP port.')+'</p><div id="km_tun">'+kmTunRows(d)+'</div>');return}
 if(KM.tab=='settings'){var par=[[0,'none'],[2,'light'],[3,'normal'],[5,'strong'],[8,'very strong']];
  el.innerHTML=kuGroup(t('Settings'),null,'','<div class="ku-form">'+
   '<label class="f">'+t('Default UDP port')+'</label><input id="km_port" class="ltr" inputmode="numeric" value="'+esc(String(s.port))+'"><small class="muted">'+t('Every server uses it unless it has its own port below.')+'</small>'+
   '<label class="f">'+t('FEC for websites (TCP)')+'</label><select id="km_par">'+par.map(function(p){return '<option value="'+p[0]+'"'+(s.parity==p[0]?' selected':'')+'>'+t(p[1])+' · 10+'+p[0]+'</option>'}).join('')+
    (par.some(function(p){return p[0]==s.parity})?'':'<option value="'+s.parity+'" selected>10+'+s.parity+'</option>')+'</select><small class="muted">'+t('Extra bytes that rebuild lost packets without asking again. Games do not use it (they have gaming mode).')+'</small>'+
   '<label class="f">'+t('Extra ports (port range)')+'</label><input id="km_hop" class="ltr" placeholder="4001-4010" value="'+esc(s.hop||'')+'"><small class="muted">'+t('Like 4001-4010. They all lead to the main port; the app picks one at random on every connect, so blocking one port is not enough. Empty = off.')+'</small></div>'+
   kuSwitch(t('Gaming mode on in the app by default'),s.gaming,'',t('Each game packet is sent twice: at 20% loss 92% arrive instead of 64%. Users can switch it off in the app.')).replace('<input type="checkbox"','<input type="checkbox" id="km_gm"')+
   '<div class="ku-save"><button class="btn" id="km_save">'+t('Save')+'</button></div>');
  $('#km_save').onclick=kmSave;return}
 el.innerHTML=(s.on?'':'<div class="warnbox">'+t('KANKI MIX is off: it runs on no server and is in no subscription.')+'</div>')+'<div id="km_st">'+kmStats(d)+'</div>'+
  kuGroup('KANKI MIX',null,'',kuSwitch(t('KANKI MIX on'),s.on,'kmPut({on:this.checked})')+
   kuLine(t('Every user'),'<button class="b2 sm" onclick="kmAll(false)">'+t('Disable for all users')+'</button><button class="b2 sm" onclick="kmAll(true)">'+t('Enable for all users')+'</button>'))+
  '<details class="ku-help"><summary>'+t('How it works')+'</summary><p>'+t('1) Keep it on and pick the port (4000 is fine). 2) Tick KANKI MIX for users (or Enable for all users). 3) Every server installs it by itself within a minute; the Kanki app gets the kanki:// link from the subscription, users see no IP or key.')+'</p>'+
   '<p>'+t('Each user has their own key (made from the subscription code): resetting the link gives a new key, disabling or expiring cuts the user off at once. Traffic and devices count like the other protocols.')+'</p></details>'}
function kmNodeOn(id,on){var m=kmNodes(),o=m[id]||{};o.off=!on;m[id]=o;kmPut({nodes:m})}
function kmNodes(){var d=KM.d,m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});return m}
function kmPut(b,done){return api('PUT','/api/kmix',b).then(function(r){toast(t('Saved'));if(done)done(r);return kmLoad()}).catch(fail)}
function kmSave(){var p=unN($('#km_port').value).trim();if(!/^\d+$/.test(p)||+p<1||+p>65535)return toast(t('the port must be 1-65535'),1);
 kmPut({port:+p,parity:+$('#km_par').value,gaming:$('#km_gm').checked,hop:unN($('#km_hop').value).trim()})}
function kmSetNodePort(id,port,done){var go=function(d){var m={};Object.keys(d.settings.nodes||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});var o=m[id]||{};o.port=+port||0;m[id]=o;kmPut({nodes:m},done)};
 if(!/^\d+$/.test(String(port))||+port<1||+port>65535)return toast(t('the port must be 1-65535'),1);
 api('GET','/api/kmix').then(function(d){KM.d=d;go(d)}).catch(fail)}
function kmAll(on){if(!confirm(t(on?'KANKI MIX for every user?':'Remove KANKI MIX from every user?')))return;
 api('POST','/api/kmix/users',{on:on}).then(function(r){toast(t('Saved')+' · '+N(r.changed)+' '+t('users changed'));kmLoad()}).catch(fail)}

