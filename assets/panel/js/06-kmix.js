// ==================================================================== KANKI MIX
// the KANKI MIX page: our own UDP protocol on every VPN server, next to WireGuard, AmneziaWG and
// Hysteria2: game UDP on a raw datagram path (sent twice in gaming mode), TCP on KCP + FEC.
// The agent writes the built-in server to each server by itself; every user has their own key.
var KM={d:null,tab:'status'};
// the tabs every core has (CLAUDE.md, design rules); a core with more adds its own
var CTABS=[['status','Status'],['servers','Servers'],['tunnel','Tunnel'],['settings','Settings']];
function ctabOf(sub,tabs){return (tabs||CTABS).some(function(x){return x[0]==sub})?sub:'status'}
// a core page: the head, its tabs and the body (#<id>); old addresses (#kmix) open the status tab
function corePage(page,id,icon,title,desc,tabs){tabs=tabs||CTABS;var k=ctabOf(S.sub,tabs);if(S.sub&&k!=S.sub){location.replace('#'+page+'/'+k);return ''}
 $('#pg').innerHTML='<div class="ku">'+kuHead(icon,title,desc)+'<nav class="ptabs ku-tabs" id="'+id+'_tabs">'+kuTabs(page,tabs,k)+'</nav><div id="'+id+'">'+t('Loading…')+'</div></div>';return k}
function coreTabsMark(page,id,k,tabs){var el=$('#'+id+'_tabs');if(el)el.innerHTML=kuTabs(page,tabs||CTABS,k)}
// an Iran server whose VPN part serves nobody (a relay): not a server of any core
function srvRelay(s){return !!(s&&s.node&&!s.node.enabled&&(s.loc=='iran'||String(s.cc||'').toUpperCase()=='IR'))}
function noRelays(d){if(d&&d.servers&&window.srvByNode)d.servers=d.servers.filter(function(x){return !srvRelay(srvByNode(x.id))});return d}
function busyTyping(){return document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)}

// KANKI MIX has one tab of its own: the game recorder
var KMTABS=CTABS.concat([['record','Game recorder']]);
function p_kmix(){KAcc.open.km='';KAcc.open.kmt='';var k=corePage('kmix','km','game','KANKI MIX',t('Our own protocol on every VPN server: game packets go straight (no queue, sent twice in gaming mode), websites over KCP + FEC.'),KMTABS);if(!k)return;KM.tab=k;
 kmLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!busyTyping())kmLoad(true)},8000)}
function tab_kmix(sub){var k=ctabOf(sub,KMTABS);if(k!=sub){location.replace('#kmix/'+k);return}KM.tab=k;coreTabsMark('kmix','km',k,KMTABS);if(KM.d)kmDraw(KM.d);else kmLoad()}
function kmLoad(quiet){return srvLoad(true).then(function(){return api('GET','/api/kmix')}).then(function(d){KM.d=noRelays(d);if(S.page!='kmix')return d;
  if(quiet){if(KM.tab=='status'&&$('#km_st')){$('#km_st').innerHTML=kmStats(d);return d}
   if(KM.tab=='servers'&&$('#km_srv')){if(!accBusy('km'))$('#km_srv').innerHTML=kmServers(d);return d}
   if(KM.tab=='tunnel'&&$('#km_tun')){if(!accBusy('kmt'))$('#km_tun').innerHTML=kmTunRows(d);return d}
   if(KM.tab=='record'&&KR.d&&KR.d.servers.some(function(x){return x.report&&x.report.recording}))krLoad(true);
   return d}
  kmDraw(d);return d}).catch(fail)}
function kmRun(x){return x.active===true}
function kmStats(d){var run=d.servers.filter(kmRun).length,on=d.servers.filter(function(x){return x.on}).length;
 return kuStats([[t('Running servers'),N(run)+' / '+N(on),run<on?'y':''],[t('Users with KANKI MIX'),N(d.users)+' / '+N(d.users_total)],[t('Online now'),N(d.online),d.online?'g':''],[t('Total traffic'),'<span class="ltr">'+N(d.traffic_gb)+' GB</span>']])}
function kmState(x){if(!x.on)return ['','Off on this server'];if(kmRun(x))return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
function kmDraw(d){var el=$('#km');if(!el)return;var s=d.settings;
 if(KM.tab=='record'){krDraw();return}
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


// ---------------------------------------------------------------- the game recorder (3.46)
// Each server's KANKI MIX records one user for a few minutes, where the traffic is open: every game (UDP)
// packet with its size and time, the TCP connections (downloads) and the DNS names. The report labels each
// flow (match, game service, download …), splits the time into lobby / match start / match, and shows what
// the VIP tunnel makes of it. The whole recording downloads as JSON for a closer look.
var KR={d:null,sel:'',user:'',secs:1800};
var KRL={match:'Match',game_udp:'Game service (UDP)',dns:'DNS',quic:'QUIC (web)',ntp:'Clock',download:'Download',web:'Lobby / web',lobby:'Lobby',start:'Match start'};
function krLoad(quiet){return api('POST','/api/kmix/record',{action:'get'}).then(function(d){KR.d=d;if(S.page=='kmix'&&KM.tab=='record')krDraw(quiet);return d}).catch(function(e){if(!quiet)fail(e)})}
function krRecording(d){return (d.servers||[]).some(function(x){return x.report&&x.report.recording})}
// the server whose report is shown: the one picked, else the one that saw the most packets
function krPick(d){var s=(d.servers||[]).filter(function(x){return x.report});if(!s.length)return null;
 var cur=s.filter(function(x){return x.id==KR.sel})[0];if(cur)return cur;
 return s.slice().sort(function(a,b){return b.report.events-a.report.events})[0]}
function krTime(s){s=Math.max(0,Math.round(+s||0));var m=Math.floor(s/60),x=s%60;return N(m+':'+(x<10?'0':'')+x)}
function krDraw(quiet){var el=$('#km');if(!el)return;var d=KR.d;if(!d){el.innerHTML=t('Loading…');krLoad();return}
 var rec=krRecording(d),any=(d.servers||[]).some(function(x){return x.report});
 if(!quiet||!$('#kr_form')){
  var users=(d.users||[]).slice().sort(),secs=[[300,'5'],[600,'10'],[1200,'20'],[1800,'30'],[2700,'45'],[3600,'60']];
  if(!KR.user&&users.length)KR.user=users[0];
  el.innerHTML=kuGroup(t('Game recorder'),null,'','<p class="muted ku-note">'+t('Records one user on every KANKI MIX server: each game packet (size, time, direction), the downloads and the DNS names. Start it, play one full match on that account, then look here. Packet contents are not kept.')+'</p>'+
   '<div class="ku-form" id="kr_form"><label class="f">'+t('User')+'</label>'+(users.length?'<select id="kr_user">'+users.map(function(u){return '<option value="'+esc(u)+'"'+(u==KR.user?' selected':'')+'>'+esc(u)+'</option>'}).join('')+'</select>':'<p class="muted">'+t('No user has KANKI MIX')+'</p>')+
   '<label class="f">'+t('How long')+'</label><select id="kr_secs">'+secs.map(function(x){return '<option value="'+x[0]+'"'+(x[0]==KR.secs?' selected':'')+'>'+N(x[1])+' '+t('minutes')+'</option>'}).join('')+'</select></div>'+
   '<div class="ku-save" id="kr_btns"></div>')+'<div id="kr_rep"></div>';
  var u=$('#kr_user');if(u)u.onchange=function(){KR.user=this.value};$('#kr_secs').onchange=function(){KR.secs=+this.value}}
 $('#kr_btns').innerHTML=(any&&!rec?'<button class="b2" onclick="krDo(\'clear\')">'+t('Clear')+'</button>':'')+
  (rec?'<button class="btn" onclick="krDo(\'stop\')">'+t('Stop recording')+'</button>':'<button class="btn"'+((d.users||[]).length?'':' disabled')+' onclick="krStart()">'+t('Start recording')+'</button>');
 $('#kr_rep').innerHTML=krReport(d)}
function krStart(){if(krPick(KR.d)&&!confirm(t('The last recording is replaced. Start?')))return;
 api('POST','/api/kmix/record',{action:'start',user:KR.user,secs:KR.secs}).then(function(r){var ok=(r.servers||[]).filter(function(x){return !x.error}).length;
  toast(ok?t('Recording on')+' '+N(ok)+' '+t('servers'):t('No server could record'),!ok);KR.sel='';krLoad()}).catch(fail)}
function krDo(a){if(a=='clear'&&!confirm(t('Delete the recording?')))return;api('POST','/api/kmix/record',{action:a}).then(function(){toast(t('Done'));krLoad()}).catch(fail)}
function krRaw(id,user){api('POST','/api/kmix/record',{action:'raw',node:id}).then(function(r){if(!r||r.error)return toast(t((r&&r.error)||'Failed'),1);
 dl({blob:new Blob([JSON.stringify(r)],{type:'application/json'}),name:'kanki-game-record-'+user+'-'+new Date().toISOString().slice(0,16).replace(/[:T]/g,'-')+'.json'})}).catch(fail)}
function krErr(e){return t(e=='old'?'Update this server to use the recorder':e)}
function krReport(d){var errs=(d.servers||[]).filter(function(x){return x.error}),cur=krPick(d),h='';
 if(errs.length)h+='<div class="warnbox">'+errs.map(function(x){return esc(x.name)+': '+esc(krErr(x.error))}).join('<br>')+'</div>';
 if(!cur)return h+'<p class="muted ku-empty">'+t('No recording yet')+'</p>';
 var r=cur.report,col={},tl=r.timeline||[];(r.columns||[]).forEach(function(c,i){col[c]=i});
 var withRep=(d.servers||[]).filter(function(x){return x.report});
 if(withRep.length>1)h+='<div class="ku-form"><label class="f">'+t('Server')+'</label><select onchange="KR.sel=this.value;krDraw(true)">'+withRep.map(function(x){return '<option value="'+esc(x.id)+'"'+(x.id==cur.id?' selected':'')+'>'+esc(x.name)+' · '+N(x.report.events)+' '+t('packets')+'</option>'}).join('')+'</select></div>';
 var match=r.flows.filter(function(f){return f.label=='match'}),m0=match[0],sum=function(a,k){return a.reduce(function(x,f){return x+(+k(f)||0)},0)};
 var up=sum(match,function(f){return f.up.pkts}),down=sum(match,function(f){return f.down.pkts}),span=sum(match,function(f){return f.last-f.first}),
  lost=sum(match,function(f){return f.up_lost}),big=Math.max.apply(null,[0].concat(match.map(function(f){return Math.max(f.up.max_size,f.down.max_size)})));
 h+='<div class="kr-st"><span>'+(r.recording?'<span class="dot g"></span> '+t('Recording')+' · ':t('Recorded')+' · ')+'<b><bdi>'+esc(r.user)+'</bdi></b> · <span class="ltr">'+krTime(r.elapsed)+' / '+krTime(r.secs)+'</span> · <bdi>'+esc(cur.name)+'</bdi>'+
  ' · <span class="muted"><bdi>'+N(r.events)+'</bdi> '+t('packets')+(r.full?' · '+t('full'):'')+'</span></span>'+(r.events?'<button class="b2 sm" onclick="krRaw(\''+esc(cur.id)+'\',\''+jsa(r.user)+'\')">'+t('Download everything (JSON)')+'</button>':'')+'</div>';
 h+=kuStats([[t('Match time'),match.length?krTime(span):'—'],[t('Game packets a second'),match.length&&span>0?'<span class="ltr">↑'+N(Math.round(up/span))+' ↓'+N(Math.round(down/span))+'</span>':'—'],
  [t('Biggest game packet'),big?'<span class="ltr">'+N(big)+' B</span>':'—'],[t('Lost on the way here'),up?'<span class="ltr">'+N((lost/(up+lost)*100).toFixed(1))+'%</span>':'—',lost/(up+lost||1)>0.01?'y':'']]);
 // the phases and the chart
 var n=Math.max(1,tl.length),ph=(r.phases||[]).map(function(p){return '<span class="p-'+p.label+'" style="width:'+((p.to-p.from+1)/n*100).toFixed(2)+'%" title="'+esc(t(KRL[p.label]||p.label))+' '+krTime(p.from)+'–'+krTime(p.to+1)+'"></span>'}).join('');
 var g=function(c){return tl.map(function(x){return x[col[c]]||0})},tcp=tl.map(function(x){return (x[col.tcp_down_bytes]||0)/1024});
 h+=kuGroup(t('Timeline'),null,'','<div class="kr-ph">'+ph+'</div><div class="klegend kr-lg">'+['lobby','start','match','download'].map(function(k){return '<span class="p-'+k+'"><i></i>'+t(KRL[k]||k)+'</span>'}).join('')+'</div>'+
  '<p class="muted kr-cap">'+t('Game packets a second')+'</p><div class="klegend"><span class="a"><i></i>'+t('Up (phone → server)')+'</span><span class="b"><i></i>'+t('Down (game → phone)')+'</span></div><div class="ch kr-ch">'+areaChart([{v:g('game_up'),c:'a'},{v:g('game_down'),c:'b'}],{h:120,cap:Math.max(2,tl.length)})+'</div>'+
  '<p class="muted kr-cap">'+t('TCP downloads (KB a second)')+'</p><div class="ch kr-ch">'+areaChart([{v:tcp,c:'b'}],{h:80,cap:Math.max(2,tl.length)})+'</div>'+
  '<div class="kr-tm ltr"><span>0:00</span><span>'+krTime(tl.length)+'</span></div>');
 // what the VIP tunnel makes of it
 var v=r.vip||{},pc=function(x){return N(((+x||0)*100).toFixed(1))+'%'};
 // what the VIP tunnel makes of it (3.46.1: every UDP packet is realtime; copies and repairs per flow up to
 // 96 KB at once and 256 KB a second)
 var mf=match[0];
 h+=kuGroup(t('What the VIP tunnel sees'),null,'',kuLine(t('Biggest burst of game packets in 50 ms (the VIP tunnel copies and repairs up to 96 KB at once)'),'<b class="ltr">'+N(mf?Math.max(mf.down.burst50_bytes,mf.up.burst50_bytes):0)+' B</b>')+
  kuLine(t('Game packets a second at most (all of them go first, with copies and repairs)'),'<b class="ltr">↑'+N(mf?mf.up.max_pps:0)+' ↓'+N(mf?mf.down.max_pps:0)+'</b>'));
 // flows
 var hs=['≤64','≤128','≤256','≤512','≤800','≤1100','>1100'],hist=function(a){return a.map(function(x,i){return x?hs[i]+':'+N(x):''}).filter(Boolean).join(' ')};
 h+=kuGroup(t('UDP flows (game)'),r.flows.length,'',r.flows.length?r.flows.slice(0,40).map(function(f){var lb=f.label;
  return kuItem({dot:lb=='match'?'g':lb=='game_udp'?'y':'',name:esc(f.domain||f.target||'?'),
   tags:kuTag(t(KRL[lb]||lb),lb=='match'?'g':'')+kuTag('↑ '+N(f.up.pkts)+' · '+N(Math.round(f.up.avg_pps))+'/s')+kuTag('↓ '+N(f.down.pkts)+' · '+N(Math.round(f.down.avg_pps))+'/s')+
    kuTag(t('biggest')+' '+N(Math.max(f.up.max_size,f.down.max_size))+' B')+(f.down.burst20>3?kuTag(t('burst')+' '+N(f.down.burst20)+' / 20ms','y'):'')+
    (f.up_loss>0.01?kuTag(t('lost up')+' '+N((f.up_loss*100).toFixed(1))+'%','y'):'')+(f.dup?kuTag(t('sent twice')):''),
   addr:esc(f.target)+' · '+krTime(f.first)+'–'+krTime(f.last)+'<br>↑ '+hist(f.up.hist)+'<br>↓ '+hist(f.down.hist)})}).join(''):'<p class="muted ku-empty">'+t('None')+'</p>');
 h+=kuGroup(t('TCP connections'),(r.streams||[]).length,'',(r.streams||[]).length?r.streams.slice(0,40).map(function(s){
  return kuItem({dot:s.label=='download'?'g':'',name:esc(s.domain||s.host),tags:kuTag(t(KRL[s.label]||s.label),s.label=='download'?'a':'')+kuTag('↓ '+N(bytes(s.down)))+kuTag('↑ '+N(bytes(s.up)))+kuTag(t('peak')+' '+N(bytes(s.peak_bps))+'/s'),
   addr:esc(s.host)+':'+N(s.port)+' · '+krTime(s.open)+'–'+(s.close<0?'…':krTime(s.close))})}).join(''):'<p class="muted ku-empty">'+t('None')+'</p>');
 if((r.queries||[]).length)h+='<details class="ku-help"><summary>'+t('DNS names')+' ('+N(r.queries.length)+')</summary><p class="ltr">'+r.queries.slice(0,300).map(function(q){return krTime(q.t/1000)+' '+esc(q.name)}).join('<br>')+'</p></details>';
 return h}
