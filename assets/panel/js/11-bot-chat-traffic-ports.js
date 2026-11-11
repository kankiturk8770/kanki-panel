// ==================================================================== dashboard, users, bot, chat, traffic, ports, tunnels

// ---- built-in logo: a K made of one stem and two links that end in nodes
function kLogo(){return '<svg class="klogo" viewBox="0 0 64 64" aria-hidden="true"><rect x="2.5" y="2.5" width="59" height="59" rx="17" fill="url(#gLbg)" stroke="url(#gGold)" stroke-width="2.2"/>'+
 '<path d="M23 17v30M42 17.5L25.5 32.5 42.5 47" fill="none" stroke="url(#gGold)" stroke-width="6.5" stroke-linecap="round" stroke-linejoin="round"/>'+
 '<circle cx="43" cy="16.5" r="4.4" style="fill:var(--al)"/><circle cx="43.5" cy="47.5" r="4.4" style="fill:var(--al)"/></svg>'}

// ---- dashboard: nodes say connected / disconnected
function nState(n){if(n.id=='local')return{c:'g',l:'Connected'};if(!n.online)return{c:'r',l:'Disconnected'};if(n.maint)return{c:'y',l:'Under maintenance'};if(n.drain)return{c:'y',l:'Draining'};return{c:'g',l:'Connected'}}
function drawNodesCard(list){var el=$('#nc');if(!el)return;
 var up=list.filter(function(n){return n.id=='local'||n.online}).length,all=up==list.length;
 el.innerHTML='<div class="nh"><div><h3>'+t('Nodes')+'</h3><small class="'+(all?'okt':'bad2')+'">'+(all?'✓ '+t('All servers connected'):N(list.length-up)+' '+t('server(s) disconnected'))+' · '+N(up)+' / '+N(list.length)+'</small></div>'+
  '<div class="row" style="gap:6px;flex-wrap:nowrap"><button class="b2" data-nd="all">'+t('Manage')+'</button></div></div>'+
  '<div class="nds">'+list.map(function(n){var s=nState(n),loc=n.id=='local',sy=loc?null:n.sync_state=='synced'?['g','Synced']:n.sync_state=='mismatch'?['y','Config mismatch']:n.sync_state=='pin mismatch'?['r','Certificate changed']:null;
   var hh=nHealthOf(n),stt=(n.info||{}).stats;if(s.c=='g'&&hh.c!='g')s={c:hh.c,l:hh.l};
   return '<button class="nd" data-nd="all"><span class="dot '+s.c+'"></span><span class="nn"><b>'+esc(n.name)+'</b><small class="ltr">'+esc(loc?'local':String(n.address||'').replace(/^https?:\/\//,''))+'</small></span>'+
    '<span class="nb"><span class="badge '+s.c+' cn">'+(s.c=='g'?ic('check',12)+' ':'')+t(s.l)+'</span>'+(loc?'<span class="badge">'+t('Main server')+'</span>':'')+(sy?'<span class="badge '+sy[0]+'">'+t(sy[1])+'</span>':'')+'</span>'+
    '<span class="nxw"><span class="nx"><small>'+t('Users')+'</small> <b>'+N(n.users)+'</b></span><span class="nx"><small>'+t('Last contact')+'</small> <b>'+(loc?t('this server'):ago(n.last_sync))+'</b></span>'+(stt?'<span class="nx"><small>CPU</small> <b>'+N(Math.round(+stt.cpu||0))+'%</b></span><span class="nx"><small>RAM</small> <b>'+N(Math.round(pc(stt.mem_used,stt.mem_total)))+'%</b></span>':'')+'</span></button>'}).join('')+'</div>'+
  (list.length<2?'<p class="muted" style="margin:10px 0 0">'+t('No extra nodes yet. Add one with a single command.')+'</p>':'');
 el.onclick=function(e){var b=e.target.closest('[data-nd]');if(!b)return;goNodes(b.dataset.nd=='add')}}

// ---- dashboard: live log with All / Errors / Debug
var LG={src:localStorage.getItem('kk_lsrc')||'all',lv:'all',paused:false,lines:[],err:''};
var LSRC=[['all','All services'],['panel','Kanki Panel'],['wireguard','WireGuard'],['amneziawg','AmneziaWG'],['hysteria2','Hysteria2'],['kankimix','KANKI MIX'],['web','Web (Caddy)']];
function lgLevel(x){var m=x.m||'';
 if(x.p<=3||/\b(error|err|fatal|panic|fail(ed|ure)?|critical|denied|refused)\b|"level":"(error|fatal)"/i.test(m))return 'e';
 if(x.p>=7||/\b(debug|dbg|trace)\b|"level":"debug"/i.test(m))return 'd';return 'i'}
function logCard(){return '<div class="card" id="lgc"><div class="nh"><div><h3>'+ic('term',16)+' '+t('Live log')+'</h3><small class="muted">'+t('Panel and VPN services on this server')+'</small></div>'+
 '<div class="row" style="gap:6px;flex-wrap:nowrap"><select id="lg_src" style="width:auto;padding:6px 9px;font-size:12px">'+LSRC.map(function(s){return '<option value="'+s[0]+'"'+(s[0]==LG.src?' selected':'')+'>'+t(s[1])+'</option>'}).join('')+'</select>'+
 '<button class="ib" id="lg_pause" title="'+t(LG.paused?'Resume':'Pause')+'">'+ic(LG.paused?'play':'pause',15)+'</button><button class="ib" id="lg_copy" title="'+t('Copy')+'">'+ic('copy',15)+'</button><button class="ib" id="lg_rf" title="'+t('Refresh')+'">'+ic('refresh',15)+'</button></div></div>'+
 '<div class="lgt" id="lg_tabs"></div><div class="lgb" id="lg_box"><span class="muted">'+t('Loading…')+'</span></div></div>'}
function logWire(){if(!$('#lgc'))return;
 $('#lg_src').onchange=function(){LG.src=this.value;localStorage.setItem('kk_lsrc',LG.src);logLoad()};
 $('#lg_pause').onclick=function(){LG.paused=!LG.paused;this.innerHTML=ic(LG.paused?'play':'pause',15);this.title=t(LG.paused?'Resume':'Pause')};
 $('#lg_rf').onclick=logLoad;
 $('#lg_copy').onclick=function(){copy(logRows().map(function(x){return logTime(x.ts)+' '+x.u+' '+x.m}).join('\n'))};
 $('#lg_tabs').onclick=function(e){var b=e.target.closest('[data-lv]');if(!b)return;LG.lv=b.dataset.lv;logDraw()};
 logLoad();clearInterval(S.timer3);S.timer3=setInterval(function(){if(S.page=='dash'&&!LG.paused&&document.visibilityState=='visible')logLoad()},5000)}
function logLoad(){return api('GET','/api/logs?src='+encodeURIComponent(LG.src)+'&n=300').then(function(r){LG.lines=r.lines||[];LG.err='';logDraw()}).catch(function(e){LG.err=e.message||'error';logDraw()})}
function logRows(){return LG.lines.filter(function(x){return LG.lv=='all'||lgLevel(x)==LG.lv})}
function logTime(ts){var d=new Date(ts*1000);return p2(d.getHours())+':'+p2(d.getMinutes())+':'+p2(d.getSeconds())}
function logDraw(){var tb=$('#lg_tabs'),bx=$('#lg_box');if(!tb||!bx)return;
 var c={all:LG.lines.length,e:0,d:0};LG.lines.forEach(function(x){var l=lgLevel(x);if(l!='i')c[l]++});
 tb.innerHTML=[['all','All'],['e','Errors'],['d','Debug']].map(function(x){return '<button data-lv="'+x[0]+'" class="lv-'+x[0]+(LG.lv==x[0]?' on':'')+'">'+t(x[1])+' <b>'+N(c[x[0]])+'</b></button>'}).join('');
 if(LG.err){bx.innerHTML='<span class="bad2">'+t('Logs are not available')+' ('+esc(LG.err)+')</span>';return}
 var rows=logRows(),stick=bx.scrollHeight-bx.scrollTop-bx.clientHeight<40;
 bx.innerHTML=rows.length?rows.map(function(x){return '<div class="lr '+lgLevel(x)+'"><span class="lt">'+logTime(x.ts)+'</span><span class="lu">'+esc(String(x.u||'').replace(/\.service$/,''))+'</span><span class="lm">'+esc(x.m)+'</span></div>'}).join(''):
  '<span class="muted">'+t(LG.lv=='e'?'No errors':LG.lv=='d'?'No debug lines':'No log lines yet')+'</span>';
 if(stick)bx.scrollTop=bx.scrollHeight}

function editUser(id,tab){var u=findU(id);if(!u)return;var p=usage(u),st=ustate(u),
  tg=(u.protocols||'').split(',').filter(function(x){return x}).map(function(x){return '<span class="ptag" style="--pc:'+(PCOL[x]||'#999')+'">'+esc(pname(x))+'</span>'}).join(''),
  cls=st=='active'?'g':st=='finished'?'y':'r',lbl=t(st=='active'?'Active':st=='finished'?(u.status=='Limited'?'Limited':'Expired'):'Disabled'),cur='';
 modal('<div class="us-h"><span class="dot '+((u.online_connections>0||liveOf(u).length)?'g':'')+'"></span><b class="ltr nm">'+esc(u.username)+'</b><span class="u-st '+cls+'" id="e_badge">'+lbl+'</span><span class="sp"></span>'+
  '<label class="sw"><input type="checkbox" id="e_sw" '+(u.enabled?'checked':'')+' aria-label="'+t('Enable')+'"><span></span></label><button class="ib" onclick="closeModal()" aria-label="close">✕</button></div>'+
  '<div class="us-tags">'+(tg||'<span class="ptag none">—</span>')+'</div>'+
  (liveOf(u).length?'<div class="lvlist"><small class="muted" style="width:100%">'+t('Connected now')+'</small>'+liveOf(u).map(function(c){return '<span style="--pc:'+(PCOL[c.p]||'#888')+'"><b>'+esc(pname(c.p))+'</b>'+esc(c.s)+'</span>'}).join('')+'</div>':'<div class="lvlist"><small class="muted">'+t('Not connected right now')+'</small></div>')+
  '<div class="us-st"><div><small>'+t('Used')+'</small><b class="ltr">'+exactB(u.used_bytes)+' / '+(u.traffic_limit_gb>0?N(gbtxt(u.traffic_limit_gb)):'∞')+'</b><div class="trk"><div class="fil '+(p>85?'hot':'')+'" style="width:'+(p<0?100:Math.max(2,p))+'%"></div></div></div>'+
  '<div><small>'+t('Expiry')+'</small><b>'+jdate(u.expires_ts)+'</b><small>'+leftTxt(u.expires_ts)+'</small></div>'+
  '<div><small>'+t('Connections')+'</small><b class="ltr">'+N(u.online_connections)+' / '+(u.max_connections?N(u.max_connections):'∞')+'</b><small>'+(u.last_seen_ts?ago(u.last_seen_ts)+'<br><span class="ltr">'+jdate(u.last_seen_ts,true)+'</span>':t('never'))+'</small></div></div>'+
  // (3.40) what is only in the details: note, Telegram ID and the devices that opened the link
  (function(){var dv=u.devices||[],rows=[];
   if(u.notes)rows.push('<div><small>'+t('Note')+'</small><span>'+esc(u.notes)+'</span></div>');
   if(u.tg_id)rows.push('<div><small>'+t('Telegram ID')+'</small><span class="ltr">'+esc(String(u.tg_id))+'</span></div>');
   if(dv.length)rows.push('<div class="wide"><small>'+t('Devices')+' ('+N(dv.length)+')</small>'+dv.map(function(x){return '<span class="us-dev">'+esc(x.app||x.kind||'—')+(x.kanki?' · Kanki':'')+'<small class="ltr">'+esc(x.ip||'')+(x.last?' · '+ago(x.last):'')+'</small></span>'}).join('')+'</div>');
   return rows.length?'<div class="us-info">'+rows.join('')+'</div>':''})()+
  '<div class="qb5 us-q" id="us_q"><button data-t="edit">'+ic('edit',18)+'<span>'+t('Edit')+'</span></button><button data-t="link">'+ic('link',18)+'<span>'+t('Link')+'</span></button><button data-t="qr">'+ic('qr',18)+'<span>QR</span></button>'+
  '<button data-t="reset">'+ic('reset',18)+'<span>'+t('Reset')+'</span></button><button data-t="del" class="x">'+ic('trash',18)+'<span>'+t('Delete')+'</span></button></div>'+
  '<div id="us_p"></div>','usheet');
 function show(k){var el=$('#us_p');cur=k;$$('#us_q [data-t]').forEach(function(b){b.classList.toggle('on',b.dataset.t==k)});
  if(!k){el.innerHTML='';return}
  if(k=='edit'){el.innerHTML=ufForm(u)+'<button class="btn" style="width:100%;margin-top:10px" id="f_save">'+t('Save changes')+'</button><button class="lnk" id="s_rg">'+ic('refresh',14)+' '+t('New link (the old one stops working)')+'</button>';wireForm(u);
   $('#f_save').onclick=function(){var b=formBody();if(!b)return;var nm=$('#f_name').value.trim();if(nm&&nm!=u.username){if(!nameOk(nm))return toast(t(NAME_ERR),1);b.username=nm}var me=this;me.disabled=true;
    api('PUT','/api/users/'+u.id,b).then(function(){toast(t('Saved'));closeModal();loadUsers()}).catch(function(e){me.disabled=false;fail(e)})};
   $('#s_rg').onclick=function(){confirmDo(function(){api('POST','/api/users/'+u.id+'/regen').then(function(){toast(t('Done'));return loadUsers()}).then(function(){editUser(id,'link')}).catch(fail)})};return}
  if(k=='link'){el.innerHTML='<small class="muted">'+t('Subscription link')+' · '+t('Created')+' '+(u.created_at?jdate(Date.parse(u.created_at)/1000):'—')+'</small><div class="lk">'+esc(u.link)+'</div>'+
    '<div class="g2" style="gap:8px"><button class="btn" id="s_cp">'+ic('copy',16)+' '+t('Copy link')+'</button><a class="b2" style="text-decoration:none;text-align:center" target="_blank" rel="noopener" href="'+esc(u.link)+'">'+ic('ext',16)+' '+t('Open page')+'</a></div>'+
    '<div class="us-cfg"><small class="muted">'+t('Configs')+'</small><div id="sx"></div></div>'+
    '<div class="us-cfg"><small class="muted">'+t('AmneziaVPN backup: every WireGuard and AmneziaWG server in one file (Restore from backup)')+'</small>'+
    '<div class="row" style="gap:8px;flex-wrap:wrap;margin-top:6px">'+[['i','iPhone'],['a','Android'],['w','Windows']].map(function(x){return '<button class="b2 sm" data-amz="'+x[0]+'">'+ic('dl',15)+' '+x[1]+'</button>'}).join('')+'</div></div>';
   $('#s_cp').onclick=function(){copy(u.link)};sheetCfg(u.id);
   $$('[data-amz]',el).forEach(function(b){b.onclick=function(){var me=this;me.disabled=true;
    api('GET','/api/users/'+u.id+'/amnezia/'+me.dataset.amz,undefined,{blob:1}).then(function(r){dl(r);me.disabled=false}).catch(function(e){me.disabled=false;fail(e)})}});return}
  if(k=='qr')qrInto(el,u.link)}
 $('#us_q').onclick=function(e){var b=e.target.closest('[data-t]');if(!b)return;var k=b.dataset.t;
  if(k=='reset')return resetU(u.id);if(k=='del')return delU(u.id);show(cur==k?'':k)};
 $('#e_sw').onchange=function(){var cb=this;cb.disabled=true;api('POST','/api/users/'+u.id+'/toggle').then(function(r){cb.disabled=false;u.enabled=r.enabled;u.status=r.status;var s2=ustate(u),b=$('#e_badge');
   if(b){b.className='u-st '+(s2=='active'?'g':s2=='finished'?'y':'r');b.textContent=t(s2=='active'?'Active':s2=='finished'?(u.status=='Limited'?'Limited':'Expired'):'Disabled')}toast(t('Done'));loadUsers()}).catch(function(e){cb.checked=!cb.checked;cb.disabled=false;fail(e)})};
 if(tab)show(tab)}

// ---- Telegram sales bot page
// ---- the Kanki app's install files: uploaded here, sent by the bot and offered on the subscription page
function botApk(){var el=$('#bt_apk');if(!el)return;
 api('GET','/api/apps').then(function(r){var f=r.files||[];
  var mb=function(n){return (n/1e6).toFixed(1)+' MB'};
  var row=function(x,i){return '<div class="box" style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">'+
    '<span class="bav" style="width:40px;height:40px;font-weight:900">K</span>'+
    '<div style="flex:1;min-width:180px"><b>'+esc(x.title)+(i==0&&f.length>1?' <span class="badge g">'+t('Recommended')+'</span>':'')+'</b>'+
     '<div class="ltr" style="font-size:12px;margin-top:2px">'+esc(x.name)+' · '+mb(x.size)+'</div>'+
     '<small class="muted">'+esc(x.hint)+' · '+ago(x.at)+(x.bot?'':' · <span style="color:var(--bad)">'+t('Too big for the bot (over 50 MB): only on the subscription page')+'</span>')+'</small></div>'+
    '<button class="b2" data-apv="'+esc(x.abi)+'" data-v="'+esc(x.version||'')+'">'+ic('edit',15)+' '+t('Version')+'</button>'+
    '<button class="b2 bd" data-apd="'+esc(x.abi)+'">'+ic('trash',15)+'</button></div>'};
  el.innerHTML='<div class="card"><h3>'+ic('dl',16)+' '+t('App files')+'</h3>'+
   '<p class="sub">'+t('Upload the Kanki app (.apk) here, one file per phone type. The bot sends the file itself (📱 Download app) and the subscription page shows a download button for each. A new file of the same type replaces the old one.')+'</p>'+
   ((S.bot||{}).username?'<div class="box"><b>'+t('Link for your channel')+'</b><small class="muted" style="display:block;margin:4px 0 6px">'+t('Put it on a “Download the app” button: the bot opens straight on the download menu.')+'</small>'+
    '<div class="row" style="gap:8px"><input readonly class="ltr" style="flex:1" id="ap_dl" value="https://t.me/'+esc(S.bot.username)+'?start=app"><button class="b2" id="ap_cp">'+ic('copy',15)+'</button></div></div>':'')+
   (f.length?f.map(row).join(''):'<p class="muted">'+t('No file yet: the bot and the subscription page show the app download link of Sales settings.')+'</p>')+
   '<div class="box"><b>'+ic('plus',15)+' '+t('Upload files')+'</b>'+
    '<input type="file" id="ap_f" accept=".apk,application/vnd.android.package-archive" multiple style="margin:8px 0;width:100%">'+
    '<div class="g2f"><div><label class="f">'+t('Phone type')+'</label><select id="ap_abi"><option value="">'+t('From the file name (arm64 / armeabi-v7a …)')+'</option>'+
     '<option value="arm64-v8a">arm64-v8a · '+t('new phones (64-bit)')+'</option><option value="armeabi-v7a">armeabi-v7a · '+t('older phones (32-bit)')+'</option><option value="universal">universal · '+t('every phone')+'</option></select></div>'+
     '<div><label class="f">'+t('Version')+'</label><input id="ap_v" class="ltr" placeholder="'+t('from the file name, e.g. 1.15.1')+'"></div></div>'+
    '<div id="ap_prog" class="muted" style="margin-top:6px"></div>'+
    '<button class="btn" id="ap_go" style="width:100%;margin-top:8px">'+ic('dl',15)+' '+t('Upload')+'</button></div></div>';
  $('#ap_go').onclick=function(){var files=[].slice.call($('#ap_f').files||[]);if(!files.length)return toast(t('Choose the .apk file(s) first'),1);
   var me=this;me.disabled=true;var i=0;
   var next=function(){if(i>=files.length){me.disabled=false;toast(t('Done'));return botApk()}
    var file=files[i++],q='?name='+encodeURIComponent(file.name)+'&abi='+encodeURIComponent($('#ap_abi').value)+'&version='+encodeURIComponent($('#ap_v').value);
    var x=new XMLHttpRequest();x.open('POST','/api/apps'+q);if(S.token)x.setRequestHeader('Authorization','Bearer '+S.token);
    x.setRequestHeader('Content-Type','application/octet-stream');
    x.upload.onprogress=function(e){if(e.lengthComputable)$('#ap_prog').textContent=file.name+' · '+Math.round(100*e.loaded/e.total)+'%'};
    x.onload=function(){var j={};try{j=JSON.parse(x.responseText||'{}')}catch(e){}
     if(x.status>=300){me.disabled=false;$('#ap_prog').textContent='';return toast(file.name+': '+t(j.error||('HTTP '+x.status)),1)}
     $('#ap_prog').textContent='✓ '+file.name;next()};
    x.onerror=function(){me.disabled=false;toast(t('Upload failed'),1)};x.send(file)};
   next()};
  var cp=$('#ap_cp');if(cp)cp.onclick=function(){var i=$('#ap_dl');i.select();try{navigator.clipboard.writeText(i.value)}catch(e){document.execCommand('copy')}toast(t('Copied'))};
  $$('[data-apd]').forEach(function(b){b.onclick=function(){confirmDo(function(){api('DELETE','/api/apps/'+b.dataset.apd).then(function(){toast(t('Done'));botApk()}).catch(fail)})}});
  $$('[data-apv]').forEach(function(b){b.onclick=function(){var v=prompt(t('Version'),b.dataset.v);if(v===null)return;
   api('PUT','/api/apps/'+b.dataset.apv,{version:v}).then(function(){toast(t('Saved'));botApk()}).catch(fail)}});
 }).catch(fail)}
function pBot(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Telegram sales bot')+'</h2><p>'+t('Create and manage the sales bot')+'</p></div><div id="bt_top"></div></div><div id="bt">'+t('Loading…')+'</div>';botLoad()}
function botLoad(){return Promise.all([api('GET','/api/bot'),api('GET','/api/settings'),api('GET','/api/plans').catch(function(){return []})]).then(function(r){S.bot=r[0];S.bset=r[1];S.plans=r[2]||[];botDraw()}).catch(fail)}
// the bot's customer buttons whose colour can be set (bot.rs STYLE_KEYS)
function bsChk(k,label){return '<label class="chk"><input type="checkbox" data-bs="'+k+'" '+((S.bset||{})[k]=='1'?'checked':'')+'>'+t(label)+'</label>'}
function bsIn(k,label,ph,typ,ltr){return '<div><label class="f">'+t(label)+'</label><input data-bs="'+k+'"'+(typ?' type="'+typ+'"':'')+(ltr?' class="ltr"':'')+' value="'+esc((S.bset||{})[k]||'')+'" placeholder="'+esc(ph||'')+'"></div>'}
function botDraw(){var b=S.bot||{},el=$('#bt');if(!el)return;var has=!!b.token_set;
 $('#bt_top').innerHTML=has?'':'<button class="btn" id="bt_new">+ '+t('Create bot')+'</button>';
 var st=b.paused?['y','Paused']:b.online?['g','Online']:['r','Offline'];
 var head=has?'<div class="card bcard"><div class="bh"><span class="bav">'+ic('bot',24)+'</span><div class="bn2"><b>'+esc(b.name||t('Sales bot'))+'</b>'+(b.username?'<a class="ltr" target="_blank" rel="noopener" href="https://t.me/'+encodeURIComponent(b.username)+'">@'+esc(b.username)+'</a>':'')+'</div>'+
   '<span class="badge '+st[0]+'"><span class="dot '+st[0]+'"></span> '+t(st[1])+'</span></div>'+
   (!b.paused&&!b.online&&b.error?'<div class="warnbox ltr" style="margin:10px 0">'+esc(b.error)+'</div>':'')+(b.conflict?'<div class="warnbox">'+t('Another program uses this bot token (an old panel still running?). Stop it, or make a new token in @BotFather.')+'</div>':'')+
   '<p class="muted" style="margin:10px 0">'+t('Plans, prices and payments can also be managed inside the bot (Admin panel button).')+'</p><div class="bmeta"><span>'+t('Bot admins')+': <b class="ltr">'+esc(b.admins||'—')+'</b></span><span>'+t('Token')+': <b class="ltr">'+esc(b.token_masked||'')+'</b></span></div>'+
   '<div class="g4b"><button class="b2" id="bt_test">'+ic('send',15)+' '+t('Test connection')+'</button><button class="b2" id="bt_pause">'+ic(b.paused?'play':'pause',15)+' '+t(b.paused?'Resume':'Pause')+'</button><button class="b2" id="bt_edit">'+ic('edit',15)+' '+t('Edit')+'</button><button class="b2 bd" id="bt_del">'+ic('trash',15)+' '+t('Delete bot')+'</button></div></div>'
  :'<div class="card bempty"><span class="bav big">'+ic('bot',30)+'</span><h3>'+t('No sales bot yet')+'</h3><ol class="steps"><li>'+t('In Telegram open @BotFather, send /newbot and copy the token it gives.')+'</li><li>'+t('Get your numeric Telegram ID from @userinfobot.')+'</li><li>'+t('Press Create bot and paste both.')+'</li></ol><button class="btn" id="bt_new2">+ '+t('Create bot')+'</button></div>';
 S.btab=S.btab||'sales';
 var tabs=[['sales','Sales settings'],['plans','Plans'],['apk','App files'],['disc','Discount codes'],['chan','Smart channel'],['appmsg','App message']];
 el.innerHTML=head+'<div class="seg btabs" id="bt_tabs">'+tabs.map(function(x){return '<button data-bt="'+x[0]+'" class="'+(S.btab==x[0]?'on':'')+'">'+t(x[1])+'</button>'}).join('')+'</div>'+
  '<div data-btp="sales"><div class="card"><h3>'+ic('settings',16)+' '+t('Sales settings')+'</h3><p class="sub">'+t('How the bot sells: trials, payments, referrals and messages.')+'</p>'+
   '<div class="chips">'+bsChk('sales_on','Sales enabled')+bsChk('warn_on','Warn buyers before expiry / end of data')+'</div>'+
   '<div class="g2f">'+bsIn('support','Support ID','@support',0,1)+bsIn('app_link','App download link','https://…',0,1)+bsIn('channel','Required channel (empty = none)','@channel',0,1)+bsIn('win_link','Windows app download link','https://…',0,1)+'</div>'+
   '<label class="f">'+t('Welcome message')+'</label><textarea data-bs="welcome" rows="3">'+esc((S.bset||{}).welcome||'')+'</textarea>'+
   '<div class="box"><b>'+ic('gift',15)+' '+t('Free trial')+'</b><div class="chips">'+bsChk('trial_on','Give a free trial')+'</div><div class="g2f">'+bsIn('trial_gb','Trial volume (GB)','1','number')+bsIn('trial_days','Trial days','1','number')+'</div></div>'+
   '<div class="box"><b>'+ic('users',15)+' '+t('Referral reward')+'</b><div class="g2f">'+bsIn('ref_gb','Reward volume (GB)','5','number')+bsIn('ref_days','Reward days','3','number')+'</div></div>'+
   '<div class="box"><b>'+ic('card',15)+' '+t('Card to card')+'</b><div class="chips">'+bsChk('card_on','Accept card to card')+'</div><div class="g2f">'+bsIn('card_number','Card number','6037 ....',0,1)+bsIn('card_holder','Card holder name','')+'</div></div>'+
   '<div class="box"><b>💎 '+t('Crypto payment (TON / USDT)')+'</b><div class="chips">'+bsChk('wallet_on','Accept crypto to my wallet')+'</div>'+
    '<div class="g2f">'+bsIn('ton_address','TON wallet address (Tonkeeper…)','UQ…',0,1)+bsIn('usdt_address','USDT address (TRC20)','T…',0,1)+'</div>'+
    '<div class="g2f">'+bsIn('usd_rate','Toman per dollar (for plans without a dollar price)','100000','number')+'<div></div></div>'+
    '<p class="hint">'+t('The buyer sees the amount in dollars and in TON (at today\'s price), your addresses to copy and a Tonkeeper button, then sends the receipt or TXID for you to approve. Plans without a dollar price get it from the toman price at this rate; with no rate and no dollar price, crypto is not offered for that plan.')+'</p>'+
    '<label class="f">'+t('Extra text for the buyer (optional)')+'</label><textarea data-bs="wallet_text" rows="2">'+esc((S.bset||{}).wallet_text||'')+'</textarea>'+
    '<p class="r" id="bs_wwarn" style="display:none;font-size:12px;margin:6px 0 0">'+t('An address is written but «Accept crypto to my wallet» is off: buyers will not see it.')+'</p></div>'+
   '<div class="box"><b>💎 '+t('TON and Telegram Stars (automatic)')+'</b><div class="chips">'+bsChk('ton_on','TON, checked on the chain')+bsChk('stars_on','Telegram Stars')+'</div>'+
    '<div class="g2f">'+bsIn('star_usd','Dollars per Star (Telegram pays 0.013)','0.013',0,1)+bsIn('toncenter_key','toncenter API key (optional)','',0,1)+'</div>'+
    '<p class="hint">'+t('Priced from the toman price at today\'s rate (the dollar from Iranian exchanges, TON from world markets, read every 5 minutes). TON goes to the TON address above with a comment of its own; the bot reads the public wallet history and delivers when the payment is there, with no key of the wallet. Stars are delivered only when Telegram reports them paid.')+'</p></div>'+
   '<details class="box"><summary><b>'+ic('globe',15)+' '+t('Online payments')+'</b></summary>'+
    '<div class="chips">'+bsChk('np_on','NOWPayments (crypto)')+'</div><div class="g2f">'+bsIn('np_key','NOWPayments API key','',0,1)+bsIn('np_coins','Coins','usdttrc20,trx,ton',0,1)+'</div>'+
    '<div class="chips">'+bsChk('zp_on','ZarinPal')+'</div><div class="g2f">'+bsIn('zp_merchant','ZarinPal merchant ID','',0,1)+bsIn('zp_callback','ZarinPal callback URL','https://…',0,1)+'</div>'+
    '</details>'+
   '<div class="box"><b>🧮 '+t('Custom purchase (mini app)')+'</b><div class="chips">'+bsChk('cp_on','Buyers can choose their own volume, days and users')+bsChk('mini_menu','The chat menu button opens the mini app')+'</div>'+
    '<div class="g2f">'+bsIn('cp_min_gb','Smallest volume (GB)','10','number')+bsIn('cp_max_gb','Largest volume (GB)','200','number')+bsIn('cp_days','Durations (days)','30,60,90',0,1)+bsIn('cp_users','Most users','3','number')+'</div>'+
    '<p class="hint">'+t('The price comes from the price rules of the Smart plan builder (Plans tab): the same size costs the same as a listed plan.')+'</p></div>'+
   '<p class="hint">'+t('Button texts, premium emoji and colours are set in Telegram: the bot › Admin panel › Buttons and texts › Manage buttons.')+'</p>'+
   '<button class="btn" style="width:100%;margin-top:10px" id="bs_save">'+t('Save sales settings')+'</button></div>'+
   '<div class="card" id="bt_watch"></div></div>'+
  '<div data-btp="plans">'+botSmart()+botPlans()+'</div><div data-btp="apk"><div id="bt_apk"></div></div><div data-btp="disc"><div id="bt_disc"></div></div><div data-btp="chan"><div id="bt_chan"></div></div><div data-btp="appmsg"><div id="bt_am"></div></div>';
 var showTab=function(k){S.btab=k;$$('#bt_tabs [data-bt]').forEach(function(b){b.classList.toggle('on',b.dataset.bt==k)});$$('[data-btp]').forEach(function(d){d.style.display=d.dataset.btp==k?'':'none'});
  if(k=='disc')botDisc();if(k=='chan')botChan();if(k=='appmsg')botAppMsg();if(k=='apk')botApk()};
 $('#bt_tabs').onclick=function(e){var b=e.target.closest('[data-bt]');if(b)showTab(b.dataset.bt)};showTab(S.btab);smartWire();botWatch();
 // crypto: typing an address switches «accept crypto» on; a written address with the switch off is warned about
 (function(){var on=$('[data-bs="wallet_on"]'),ww=$('#bs_wwarn');if(!on)return;var has=function(){return ['ton_address','usdt_address'].some(function(k){var x=$('[data-bs="'+k+'"]');return x&&x.value.trim()})};
  var chk=function(){if(ww)ww.style.display=has()&&!on.checked?'':'none'};
  ['ton_address','usdt_address'].forEach(function(k){var x=$('[data-bs="'+k+'"]');if(x)x.addEventListener('input',function(){if(this.value.trim())on.checked=true;chk()})});on.addEventListener('change',chk);chk()})();
 var w=function(id,fn){var x=$(id);if(x)x.onclick=fn};
 w('#bt_new',function(){botModal(false)});w('#bt_new2',function(){botModal(false)});w('#bt_edit',function(){botModal(true)});
 w('#bt_test',function(){toast(t('Checking…'));api('POST','/api/bot/test').then(function(r){toast(r.ok?'✓ @'+(r.username||''):(r.error||t('Failed')),!r.ok)}).catch(fail)});
 w('#bt_pause',function(){api('POST','/api/bot/pause').then(function(){toast(t('Done'));botLoad()}).catch(fail)});
 w('#bt_del',function(){confirmDo(function(){api('DELETE','/api/bot').then(waitRestart).catch(fail)})});
 w('#bs_save',function(){var body={};$$('[data-bs]').forEach(function(x){body[x.dataset.bs]=x.type=='checkbox'?(x.checked?'1':'0'):x.value});
  api('PUT','/api/settings',body).then(function(){toast(t('Saved'));botLoad()}).catch(fail)});
 w('#pl_add',function(){var n=$('#pl_n').value.trim();if(!n)return toast(t('Plan name'),1);
  api('POST','/api/plans',{name:n,days:+$('#pl_d').value||30,gb:+$('#pl_g').value||0,toman:+$('#pl_t').value||0,usd:+$('#pl_u').value||0,conns:+$('#pl_c').value||1,category:($('#pl_cat').value||'').trim()}).then(function(){toast(t('Saved'));botLoad()}).catch(fail)});
 var pl=$('#pl_list');if(pl)pl.onchange=function(e){var se=e.target.closest('[data-pst]');if(se)api('PUT','/api/plans/'+se.dataset.pst,{style:se.value}).then(function(){toast(t('Saved'))}).catch(fail)};
 var pl=$('#pl_list');if(pl)pl.onclick=function(e){var sv=e.target.closest('[data-psvc]');if(sv){api('PUT','/api/plans/'+sv.dataset.psvc,{service:sv.dataset.s}).then(botLoad).catch(fail);return}var a=e.target.closest('[data-pact]');if(a){api('PUT','/api/plans/'+a.dataset.pact,{active:a.dataset.a=='1'}).then(botLoad).catch(fail);return}var pu=e.target.closest('[data-pusd]');if(pu){var x1=(S.plans||[]).filter(function(z){return z.id==pu.dataset.pusd})[0]||{},v1=prompt(t('Dollar price (crypto)')+' · 0 = '+t('from the toman price at the dollar rate'),x1.usd||0);if(v1!==null)api('PUT','/api/plans/'+pu.dataset.pusd,{usd:+unN(v1)||0}).then(botLoad).catch(fail);return}var m=e.target.closest('[data-pcat]');if(m){var x0=(S.plans||[]).filter(function(z){return z.id==m.dataset.pcat})[0]||{},v=prompt(t('Category name'),x0.category||'');if(v!==null)api('PUT','/api/plans/'+m.dataset.pcat,{category:v.trim()}).then(botLoad).catch(fail);return}
 var rn=e.target.closest('[data-crn]');if(rn){var v2=prompt(t('Category name'),rn.dataset.crn);if(v2!==null)api('PUT','/api/plans/category',{from:rn.dataset.crn,to:v2.trim()}).then(botLoad).catch(fail);return}
 var b=e.target.closest('[data-pdel]');if(b)confirmDo(function(){api('DELETE','/api/plans/'+b.dataset.pdel).then(function(){toast(t('Done'));botLoad()}).catch(fail)})}}
// the daily report (kanki-watch on the panel server): its API token is pasted here and the panel writes it for the script
function botWatch(){var el=$('#bt_watch');if(!el)return;
 api('GET','/api/bot/watch').then(function(d){if(!$('#bt_watch'))return;
  var st=!d.installed?['y','The report script is not on this server']:!d.token_set?['y','No token yet']:d.problem?['r',d.problem]:['g','The token works'];
  el.innerHTML='<h3>📋 '+t('Daily report')+'</h3><p class="sub">'+t('Every 30 minutes the panel server checks the tunnels and servers and tells you on Telegram; every morning it sends a report. It needs an API token with the «Servers and tunnels» right.')+'</p>'+
   '<p><span class="badge '+st[0]+'"><span class="dot '+st[0]+'"></span> '+esc(t(st[1]))+'</span>'+(d.token_masked?' <b class="ltr">'+esc(d.token_masked)+'</b>':'')+'</p>'+
   (d.last?'<label class="f">'+t('Last check')+'</label><div class="warnbox ltr" style="margin:4px 0 10px;white-space:pre-wrap;word-break:break-all">'+esc(d.last)+'</div>':'')+
   '<ol class="steps"><li>'+t('System › Security › API tokens: make a token named kanki-watch with only «Servers and tunnels».')+'</li><li>'+t('Paste it here and press Save. Do not delete that token later.')+'</li></ol>'+
   '<label class="f">'+t('API token for the report')+'</label><input id="bw_tok" class="ltr" autocomplete="off" placeholder="'+esc(t('Paste the token'))+'">'+
   '<div class="g2f" style="margin-top:10px"><button class="btn" id="bw_save">'+t('Save')+'</button><button class="b2" id="bw_send"'+(d.installed?'':' disabled')+'>'+ic('send',15)+' '+t('Send the report now')+'</button></div>';
  $('#bw_save').onclick=function(){var v=$('#bw_tok').value.trim();if(!v)return toast(t('Paste the token'),1);var me=this;me.disabled=true;
   api('PUT','/api/bot/watch',{token:v}).then(function(){toast(t('Saved'));botWatch()}).catch(function(e){me.disabled=false;fail(e)})};
  $('#bw_send').onclick=function(){var me=this;me.disabled=true;toast(t('Checking…'));
   api('POST','/api/bot/watch/send').then(function(){toast(t('The report was sent to Telegram'));botWatch()}).catch(function(e){me.disabled=false;fail(e)})};
 }).catch(function(e){el.innerHTML='';fail(e)})}
function plCats(p){var o=[];(p||[]).forEach(function(x){if(x.category&&o.indexOf(x.category)<0)o.push(x.category)});return o.sort()}
// the colour of a plan's button in the bot ('' = by users: one blue, two or more green)
var PSTY=[['','Auto (by users)'],['success','🟢 Green'],['primary','🔵 Blue'],['danger','🔴 Red'],['none','⚪ Plain']];
function plStyle(x){return '<select class="pst" data-pst="'+x.id+'" aria-label="'+esc(t('Button colour in the bot'))+'" title="'+esc(t('Button colour in the bot'))+'">'+PSTY.map(function(o){return '<option value="'+o[0]+'"'+((x.style||'')==o[0]?' selected':'')+'>'+t(o[1])+'</option>'}).join('')+'</select>'}
function plRow(x){return '<div class="li"><span><b>'+esc(x.name)+'</b><small>'+N(x.days)+' '+t('days')+' · '+(x.gb>0?N(x.gb)+' GB':'∞')+' · '+N(x.conns)+' '+t('connections')+(x.countries>0?' · '+N(x.countries)+' '+t('countries'):'')+(x.active?'':' · '+t('Hidden'))+'</small></span>'+
  '<span class="row" style="gap:8px;flex-wrap:wrap;justify-content:flex-end"><span class="pprice"><b>'+N(Number(x.toman||0).toLocaleString('en-US'))+' '+t('Toman')+'</b>'+(x.usd?'<small class="ltr">$'+x.usd+'</small>':'')+'</span>'+plStyle(x)+'<button class="ib" data-psvc="'+x.id+'" data-s="'+(x.service=='v2ray'?'vip':'v2ray')+'" title="'+t(x.service=='v2ray'?'V2Ray service: only the subscription link (tap for VIP)':'VIP service: every protocol and the Kanki app (tap for V2Ray)')+'">'+(x.service=='v2ray'?'🌐':'🚀')+'</button><button class="ib" data-pusd="'+x.id+'" title="'+t('Dollar price (crypto)')+'">$</button><button class="ib" data-pcat="'+x.id+'" title="'+t('Move to category')+'">📂</button><button class="ib'+(x.active?' on':'')+'" data-pact="'+x.id+'" data-a="'+(x.active?0:1)+'" title="'+t(x.active?'Shown in the bot':'Hidden')+'">'+(x.active?'👁':'—')+'</button><button class="ib" data-pdel="'+x.id+'" aria-label="'+t('Delete')+'">'+ic('trash',14)+'</button></span></div>'}
function plGroups(p){if(!p.length)return '<span class="muted">'+t('No plans yet')+'</span>';var g={},ord=[];p.forEach(function(x){var k=x.category||'';if(!g[k]){g[k]=[];ord.push(k)}g[k].push(x)});
 if(ord.length==1&&ord[0]==='')return '<div class="list">'+p.map(plRow).join('')+'</div>';
 ord.sort(function(a,b){return a===''?1:b===''?-1:a.localeCompare(b)});
 return ord.map(function(k){return '<div class="pcat"><div class="pch"><b>📂 '+esc(k||t('Other'))+'</b><small class="muted">'+N(g[k].length)+'</small>'+(k?'<button class="ib" data-crn="'+esc(k)+'" title="'+t('Rename category')+'">'+ic('edit',14)+'</button>':'')+'</div><div class="list">'+g[k].map(plRow).join('')+'</div></div>'}).join('')}
function botPlans(){var p=S.plans||[];return '<div class="card"><h3>'+ic('traffic',16)+' '+t('Plans')+'</h3><p class="sub">'+t('What buyers can choose in the bot')+'</p>'+
 '<div id="pl_list">'+plGroups(p)+'</div>'+
 '<label class="f">'+t('Category')+'</label><input id="pl_cat" list="pl_cats" placeholder="'+t('Category name')+'"><datalist id="pl_cats">'+plCats(p).map(function(c){return '<option value="'+esc(c)+'">'}).join('')+'</datalist><div style="height:6px"></div>'+
 '<div class="g3p"><input id="pl_n" placeholder="'+t('Plan name')+'"><input id="pl_d" type="number" min="1" placeholder="'+t('Days')+'"><input id="pl_g" type="number" min="0" placeholder="GB (0 = ∞)"><input id="pl_t" type="number" min="0" placeholder="'+t('Price (Toman)')+'"><input id="pl_u" type="number" min="0" step="0.1" placeholder="'+t('Price (USD)')+'"><input id="pl_c" type="number" min="1" placeholder="'+t('Connections')+'"></div>'+
 '<button class="btn" style="width:100%;margin-top:8px" id="pl_add">+ '+t('Add plan')+'</button></div>'}

// ---- smart plan builder: price per GB + per extra country + per extra connection (+ monthly base)
function smartRules(){var d={gb:3000,base:20000,country:15000,conn:20000,round:5000,vols:'10,20,30,50,100',days:'30',conns:'1,2',countries:'0',bulk:10};try{var r=JSON.parse((S.bset||{}).price_rules||'{}');for(var k in r)d[k]=r[k]}catch(e){}return d}
function smartPrice(r,gb,days,conns,cn){var m=Math.max(1,days/30),p=(+r.base||0)*m+gb*(+r.gb||0)+Math.max(0,conns-1)*(+r.conn||0)*m+Math.max(0,cn-1)*(+r.country||0)*m;
 if(gb>=50&&+r.bulk>0)p=p*(1-Math.min(40,+r.bulk*(gb>=100?2:1))/100);var rd=+r.round||1000;return Math.max(rd,Math.round(p/rd)*rd)}
function smartList(r){var L=function(x){return String(x).split(/[,،\s]+/).map(Number).filter(function(n){return n>=0&&!isNaN(n)})},out=[];
 L(r.days).forEach(function(d){if(!d)return;L(r.countries).forEach(function(cn){L(r.conns).forEach(function(c){if(!c)return;L(r.vols).forEach(function(g){
  var nm=(g>0?g+' گیگ':'نامحدود')+' · '+(d%30?d+' روزه':(d/30==1?'یک ماهه':(d/30)+' ماهه'))+(c>1?' · '+c+' کاربره':'')+(cn>0?' · '+cn+' کشور':'');
  out.push({category:String(r.category||'').trim(),name:nm,gb:g,days:d,conns:c,countries:cn,toman:smartPrice(r,g,d,c,cn||1)})})})})});return out.slice(0,60)}
function botSmart(){var r=smartRules(),f=function(k,l,typ){return '<div><label class="f">'+t(l)+'</label><input data-sr="'+k+'"'+(typ?' type="number" min="0"':' class="ltr"')+' value="'+esc(r[k])+'"></div>'};
 return '<div class="card"><h3>✨ '+t('Smart plan builder')+'</h3><p class="sub">'+t('Set the price rules once; every plan gets a fair price automatically.')+'</p>'+
  '<div class="g3f">'+f('gb','Price per GB (Toman)',1)+f('base','Base price per month',1)+f('country','Each extra country / month',1)+f('conn','Each extra connection / month',1)+f('round','Round to',1)+f('bulk','Big plan discount %',1)+'</div>'+
  '<div class="g3f">'+f('vols','Volumes (GB, 0 = unlimited)')+f('days','Durations (days)')+f('conns','Connections')+f('countries','Countries (0 = all)')+'<div><label class="f">'+t('Category')+'</label><input data-sr="category" value="'+esc(r.category||'')+'" placeholder="'+t('Category name')+'"></div></div>'+
  '<div id="sp_prev" class="sprev"></div><div class="row" style="gap:8px;margin-top:8px"><button class="btn" id="sp_add" style="flex:1">'+t('Add these plans')+'</button><button class="b2 bd" id="sp_rep">'+t('Replace all plans')+'</button></div></div>'}
function smartRead(){var r={};$$('[data-sr]').forEach(function(x){r[x.dataset.sr]=x.type=='number'?(+x.value||0):x.value});return r}
function smartWire(){var pv=function(){var el=$('#sp_prev');if(!el)return;var l=smartList(smartRead());
  el.innerHTML=l.length?'<small class="muted">'+N(l.length)+' '+t('plans')+'</small>'+l.map(function(x){return '<div class="spi"><span>'+esc(x.name)+'</span><b>'+N(x.toman.toLocaleString('en-US'))+'</b></div>'}).join(''):'<span class="muted">—</span>'};
 $$('[data-sr]').forEach(function(x){x.oninput=pv});pv();
 var send=function(rep){var r=smartRead(),l=smartList(r);if(!l.length)return;var go=function(){api('POST','/api/plans/bulk',{plans:l,replace:rep,rules:r}).then(function(x){toast(t('Saved')+' · '+N(x.added));botLoad()}).catch(fail)};rep?confirmDo(go):go()};
 var a=$('#sp_add'),b=$('#sp_rep');if(a)a.onclick=function(){send(false)};if(b)b.onclick=function(){send(true)}}


// ---- Emergency chat: a small chat server on a server inside Iran, for when the international internet is cut
function pEmergency(){$('#pg').innerHTML='<div class="ph"><div><h2>'+ic('sos',22)+' '+t('Emergency chat')+'</h2><p>'+t('Talk to your customers and send them configs when the international internet is cut')+'</p></div></div><div id="em">'+t('Loading…')+'</div>';emLoad()}
function emLoad(){Promise.all([api('GET','/api/emergency'),api('GET','/api/tunnels')]).then(function(r){var e=r[0],sv=(r[1].servers||[]),el=$('#em');if(!el)return;
 var srvOpt=srvOptGroups(sv,function(x){return '<option value="'+esc(x.id)+'"'+(x.id==e.server?' selected':'')+'>'+esc(x.name+(x.local?' ('+t('panel')+')':''))+(x.online?'':' · '+t('Disconnected'))+'</option>'});
 var cur=sv.filter(function(x){return x.id==e.server})[0],old=cur&&!cur.local&&cur.version&&verLt(cur.version,'3.3.0');
 var st=e.status||null,stHtml=!e.on?'<span class="badge">'+t('Off')+'</span>':!st?'<span class="badge r">'+t('Waiting for the server…')+'</span>':st.active?'<span class="badge g"><span class="dot g"></span> '+t('Running')+'</span>':'<span class="badge r">'+t('Not running')+'</span>';
 el.innerHTML='<div class="card"><h3>'+t('How it works')+'</h3><ol class="sub" style="margin:6px 0;padding-inline-start:18px;line-height:2">'+
   '<li>'+t('Choose a server inside Iran (one of your tunnel servers) and a domain that points to it (ArvanCloud CDN or plain DNS).')+'</li>'+
   '<li>'+t('The panel installs the emergency chat on that server by itself and keeps the list of your customers there while the internet works.')+'</li>'+
   '<li>'+t('When the internet is cut, customers tap the emergency button in the Kanki app and write to you; you answer and send configs from the address below, from inside Iran.')+'</li>'+
   '<li>'+t('Your messages are signed: the app only trusts messages that really come from you, even over plain HTTP.')+'</li></ol></div>'+
  '<div class="card"><div class="row" style="justify-content:space-between"><h3 style="margin:0">'+t('Status')+'</h3>'+stHtml+'</div>'+
   (e.on&&e.url?'<p style="margin:10px 0 4px">'+t('Admin chat address (open it from inside Iran)')+':</p><p class="ltr"><a href="'+esc(e.url)+'/admin" target="_blank" rel="noopener">'+esc(e.url)+'/admin</a></p>':'')+
   (st&&st.active?'<p>'+t('Unread messages')+': <b>'+N(st.unread||0)+'</b></p>':'')+
   (st&&st.error?'<div class="warnbox ltr">'+esc(st.error)+'</div>':'')+
   (old?'<div class="warnbox">'+t('The agent of this server is old: press “Update all” in Tunnel servers first.')+'</div>':'')+
   (e.on&&e.ssl=='http'?'<div class="warnbox">'+t('Without a certificate (HTTP) the chat works, but messages and your password are not encrypted on the way. Get an SSL certificate before the internet is cut and paste it below. Your configs stay safe: they are signed.')+'</div>':'')+
   '<p class="hint">'+t('Customers known to the chat')+': '+N(e.customers||0)+(e.key?' · '+t('Signing key')+' …<span class="ltr">'+esc(e.key)+'</span>':'')+'</p></div>'+
  '<div class="card"><h3>'+t('Settings')+'</h3>'+
   '<label class="chk"><input type="checkbox" id="em_on" '+(e.on?'checked':'')+'><span><b>'+t('Emergency chat is on')+'</b></span></label>'+
   '<label class="f">'+t('Server inside Iran')+'</label><select id="em_sv">'+srvOpt+'</select>'+
   '<div class="g2"><div><label class="f">'+t('Domain')+'</label><input id="em_d" class="ltr" placeholder="chat.kanki.pro" value="'+esc(e.domain||'')+'"></div>'+
   '<div><label class="f">'+t('Port')+'</label><input id="em_p" type="number" class="ltr" list="em_pl" value="'+(e.port||8080)+'">'+
    '<datalist id="em_pl">'+[8080,8880,2052,2082,2086,2095,2053,2083,2087,2096,8443,80,443].map(function(p){return '<option value="'+p+'">'}).join('')+'</datalist></div></div>'+
   '<small class="muted">'+t('With ArvanCloud CDN use a port it forwards (80, 8080, 443, 2053, 8443 …). Open the port on the server.')+' '+
    t('HTTP (CDN SSL or no SSL): 8080, 8880, 2052, 2082, 2086, 2095 · HTTPS (own SSL): 2053, 2083, 2087, 2096, 8443. Keep 80 and 443 free when Kanki DNS runs on this server.')+'</small>'+
   '<label class="f">'+t('Admin password of the chat')+'</label><input id="em_pw" type="password" autocomplete="new-password" placeholder="'+(e.has_password?t('unchanged'):t('at least 10 characters'))+'">'+
   '<label class="f">SSL</label><select id="em_ssl">'+[['auto','Automatic SSL (Let’s Encrypt, recommended)'],['cdn','SSL from the CDN (ArvanCloud)'],['manual','My own certificate'],['http','No SSL (HTTP)']].map(function(o){return '<option value="'+o[0]+'"'+(e.ssl==o[0]?' selected':'')+'>'+t(o[1])+'</option>'}).join('')+'</select>'+
   '<small class="muted" id="em_sslh"></small>'+
   '<div id="em_pem" style="display:none"><label class="f">'+t('Certificate (PEM, full chain)')+'</label><textarea id="em_c" rows="4" class="ltr" placeholder="-----BEGIN CERTIFICATE-----"></textarea>'+
    '<label class="f">'+t('Private key (PKCS#8 PEM)')+'</label><textarea id="em_k" rows="4" class="ltr" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>'+
   '<button class="btn" style="width:100%;margin-top:12px" id="em_go">'+t('Save')+'</button>'+
   '<button class="b2 bd" style="width:100%;margin-top:8px" id="em_rk">'+t('New signing key')+'</button>'+
   '<p class="hint">'+t('A new signing key is only needed if the server was compromised. Apps learn the new key when they refresh their subscription, so do it while the internet still works.')+'</p></div>';
 $('#em_go').onclick=function(){var me=this,b={on:$('#em_on').checked,server:$('#em_sv').value,domain:$('#em_d').value,port:+$('#em_p').value||0,password:$('#em_pw').value,cert:$('#em_c').value,key:$('#em_k').value,ssl:$('#em_ssl').value};
  me.disabled=true;api('PUT','/api/emergency',b).then(function(){toast(t('Saved: the server sets it up in a few seconds'));emLoad()}).catch(function(x){me.disabled=false;fail(x)})};
 var sslH={auto:'The server gets and renews a free certificate by itself. Do it before the internet is cut. Port 80 of the server must be free and the domain must point to it (ArvanCloud: DNS or CDN both work).',cdn:'ArvanCloud shows HTTPS to the users with its own certificate and talks to the server on the port above with HTTP. In ArvanCloud set the origin port to this port.',manual:'Paste a certificate you already have.',http:'Works, but messages and your password travel unencrypted. Configs stay safe: they are signed.'};
 var sslUi=function(){var v=$('#em_ssl').value;$('#em_pem').style.display=v=='manual'?'':'none';$('#em_sslh').textContent=t(sslH[v]||'')};$('#em_ssl').onchange=sslUi;sslUi();
 $('#em_rk').onclick=function(){confirmDo(function(){api('POST','/api/emergency/rekey').then(function(){toast(t('Done'));emLoad()}).catch(fail)})};
 clearTimeout(S.emT);S.emT=setTimeout(function(){if($('#em')&&!$('#modal').classList.contains('on')&&document.activeElement.tagName!='INPUT'&&document.activeElement.tagName!='TEXTAREA')emLoad()},8000)
}).catch(fail)}
function verLt(a,b){var p=function(v){return String(v).replace(/^v/,'').split('.').map(function(x){return +x||0})},x=p(a),y=p(b);for(var i=0;i<3;i++){if((x[i]||0)!=(y[i]||0))return (x[i]||0)<(y[i]||0)}return false}

// ---- message shown by the robot inside the Kanki app (read from the subscription page, so no extra address is needed)
var AM_DUR=[[30,'30 min'],[60,'1 hour'],[180,'3 hours'],[360,'6 hours'],[720,'12 hours'],[1440,'1 day'],[4320,'3 days'],[10080,'7 days'],[0,'Until I remove it']];
function amLeft(until,now){if(!until)return t('Until I remove it');var s=Math.max(0,until-now),h=Math.floor(s/3600),m=Math.ceil(s%3600/60);
 return (h?N(h)+' '+t('hours')+' ':'')+N(m)+' '+t('min')+' '+t('left')}
function botAppMsg(){var el=$('#bt_am');if(!el)return;S.amDur=S.amDur==null?60:S.amDur;
 api('GET','/api/app-msg').then(function(m){
  var cur=m.active?'<div class="amcur on"><div class="row" style="justify-content:space-between;gap:8px"><span class="badge g"><span class="dot g"></span> '+t('Showing in the app')+'</span><small class="muted">'+amLeft(m.until,m.now)+'</small></div>'+
    '<p style="margin:8px 0">'+esc(m.text)+'</p><small class="muted">'+t('For')+': '+(m.users?'<span class="ltr">'+esc(m.users)+'</span>':t('All users'))+'</small>'+
    '<button class="b2 bd" style="width:100%;margin-top:8px" id="am_del">'+ic('trash',15)+' '+t('Remove now')+'</button></div>'
   :'<div class="amcur"><span class="muted">'+t('No message is showing in the app right now.')+'</span></div>';
  el.innerHTML='<div class="card"><h3>'+ic('bot',16)+' '+t('App message')+'</h3><p class="sub">'+t('Write a message; the robot on the first screen of the Kanki app shows it to users, and it disappears by itself when the time is over.')+'</p>'+cur+
   '<label class="f">'+t('Message')+'</label><textarea id="am_t" rows="3" maxlength="500" placeholder="'+t('e.g. The Germany server is under maintenance for one hour.')+'"></textarea><small class="muted" id="am_c"></small>'+
   '<label class="f">'+t('Show for')+'</label><div class="amdur" id="am_d">'+AM_DUR.map(function(x){return '<button data-m="'+x[0]+'" class="'+(S.amDur==x[0]?'on':'')+'">'+t(x[1])+'</button>'}).join('')+'</div>'+
   '<label class="f">'+t('Only for these users (empty = everyone)')+'</label><input id="am_u" class="ltr" placeholder="user1, user2">'+
   '<button class="btn" style="width:100%;margin-top:10px" id="am_go">'+ic('send',15)+' '+t(m.active?'Replace the message':'Send to the app')+'</button>'+
   '<p class="hint" style="margin-top:8px">'+t('The app picks the message up when it is opened, then every 30 seconds while connected (every 5 minutes when not). A user who closes the message will not see it again; a new message is shown again.')+'</p></div>';
  var ta=$('#am_t'),cnt=function(){$('#am_c').textContent=N(ta.value.length)+' / '+N(500)};ta.oninput=cnt;cnt();
  $('#am_d').onclick=function(e){var b=e.target.closest('[data-m]');if(!b)return;S.amDur=+b.dataset.m;$$('#am_d [data-m]').forEach(function(x){x.classList.toggle('on',x==b)})};
  $('#am_go').onclick=function(){var tx=ta.value.trim();if(!tx)return toast(t('Write the message first'),1);
   api('PUT','/api/app-msg',{text:tx,minutes:S.amDur,users:$('#am_u').value}).then(function(){toast(t('Sent'));botAppMsg()}).catch(fail)};
  var d=$('#am_del');if(d)d.onclick=function(){confirmDo(function(){api('DELETE','/api/app-msg').then(function(){toast(t('Done'));botAppMsg()}).catch(fail)})}
 }).catch(fail)}

// ---- discount codes
function botDisc(){var el=$('#bt_disc');if(!el)return;api('GET','/api/discounts').then(function(l){
 el.innerHTML='<div class="card"><h3>🎟 '+t('Discount codes')+'</h3><p class="sub">'+t('Buyers type the code in the bot. Used-up and expired codes are removed by themselves.')+'</p><div class="list">'+
  (l.length?l.map(function(d){return '<div class="li"><span><b class="ltr">'+esc(d.code)+'</b><small>'+N(d.percent)+'% · '+N(d.uses)+' '+t('uses left')+(d.expires?' · '+t('until')+' '+fmtDate(d.expires,1):'')+'</small></span><span class="row" style="gap:6px;flex-wrap:nowrap"><button class="ib" data-dcp="'+esc(d.code)+'">'+ic('link',14)+'</button><button class="ib" data-ddel="'+esc(d.code)+'">'+ic('trash',14)+'</button></span></div>'}).join(''):'<span class="muted">'+t('No codes yet')+'</span>')+'</div>'+
  '<div class="g4f" style="margin-top:10px"><input id="dc_c" class="ltr" placeholder="'+t('Code')+' (NOWRUZ)"><input id="dc_p" type="number" min="1" max="90" placeholder="%"><input id="dc_u" type="number" min="1" placeholder="'+t('Uses')+'"><input id="dc_h" type="number" min="0" placeholder="'+t('Hours (0 = no end)')+'"></div>'+
  '<button class="btn" style="width:100%;margin-top:8px" id="dc_add">+ '+t('Add code')+'</button></div>';
 $('#dc_add').onclick=function(){var c=$('#dc_c').value.trim();if(!c)return toast(t('Code'),1);api('POST','/api/discounts',{code:c,percent:+$('#dc_p').value||10,uses:+$('#dc_u').value||100,hours:+$('#dc_h').value||0}).then(function(){toast(t('Saved'));botDisc()}).catch(fail)};
 el.querySelector('.list').onclick=function(e){var d=e.target.closest('[data-ddel]'),c=e.target.closest('[data-dcp]');if(c)copy(c.dataset.dcp);if(d)confirmDo(function(){api('DELETE','/api/discounts/'+encodeURIComponent(d.dataset.ddel)).then(botDisc).catch(fail)})}}).catch(fail)}

// ---- smart channel
function botChan(){var el=$('#bt_chan');if(!el)return;api('GET','/api/channel').then(function(c){var ks=(c.kinds||'').split(',');
 el.innerHTML='<div class="card"><div class="nh"><div><h3>📢 '+t('Smart channel')+'</h3><p class="sub">'+t('The bot writes and publishes posts in your channel by itself: prices, offers, tips, guides, trials and occasion greetings. Make the bot an admin of the channel.')+'</p></div>'+
  '<label class="sw"><input type="checkbox" id="ch_on" '+(c.on?'checked':'')+'><span></span></label></div>'+
  '<div class="g2f"><div><label class="f">'+t('Channel')+'</label><input id="ch_id" class="ltr" value="'+esc(c.id)+'" placeholder="@mychannel"></div><div><label class="f">'+t('Post every (hours)')+'</label><input id="ch_h" type="number" min="1" max="72" value="'+(+c.hours||8)+'"></div>'+
  '<div><label class="f">'+t('Signature (empty = bot link)')+'</label><input id="ch_sg" value="'+esc(c.sign)+'" placeholder="@'+esc(c.bot||'bot')+'"></div><div><label class="f">'+t('Discount code prefix')+'</label><input id="ch_cd" class="ltr" value="'+esc(c.code)+'" placeholder="KANKI"></div></div>'+
  '<label class="f">'+t('Post types')+'</label><div class="chips">'+(c.all_kinds||[]).map(function(k){return '<label class="chk"><input type="checkbox" class="ch_k" value="'+k.id+'" '+(ks.indexOf(k.id)>=0?'checked':'')+'>'+t(k.name)+'</label>'}).join('')+'</div>'+
  '<div class="chips">'+'<label class="chk"><input type="checkbox" id="ch_ao" '+(c.auto_offer?'checked':'')+'>'+t('Automatic discount on occasions (Nowruz, Yalda…)')+'</label></div>'+
  '<p class="muted" style="font-size:12px">'+t('No posts between 1 and 8 in the morning.')+' · '+t('Posts sent')+': '+N(c.count)+(c.last?' · '+t('Last')+': '+ago(c.last):'')+(c.occasion?' · 🎉 '+esc(c.occasion):'')+(String(c.status||'').indexOf('error')==0?'<br><span class="r">'+esc(c.status)+'</span>':'')+'</p>'+
  '<button class="btn" style="width:100%" id="ch_save">'+t('Save')+'</button></div>'+aiCard(c)+
  '<div class="card"><div class="nh"><h3>👁 '+t('Post preview')+'</h3><select id="ch_kind" style="width:auto"><option value="auto">'+t('Smart choice')+'</option>'+(c.all_kinds||[]).map(function(k){return '<option value="'+k.id+'">'+t(k.name)+'</option>'}).join('')+'</select></div>'+
  '<div class="chpv" id="ch_pv"><span class="muted">…</span></div><div class="row" style="gap:8px;margin-top:8px"><button class="b2" id="ch_new" style="flex:1">🔄 '+t('Another one')+'</button><button class="btn" id="ch_pub" style="flex:1">📤 '+t('Publish now')+'</button></div></div>'+
  '<div class="card"><h3>🔥 '+t('Discount campaign')+'</h3><p class="sub">'+t('Makes a new code that ends by itself and announces it in the channel.')+'</p><div class="g3f"><div><label class="f">%</label><input id="cc_p" type="number" min="1" max="90" value="20"></div><div><label class="f">'+t('Hours')+'</label><input id="cc_h" type="number" min="1" value="48"></div><div><label class="f">'+t('Uses')+'</label><input id="cc_u" type="number" min="1" value="200"></div></div>'+
  '<button class="btn" style="width:100%;margin-top:8px" id="cc_go">🔥 '+t('Start the campaign')+'</button></div>';
 var draft={};var pv=function(){api('POST','/api/channel/preview',{kind:$('#ch_kind').value}).then(function(r){draft=r;$('#ch_pv').innerHTML=r.text.replace(/\n/g,'<br>')}).catch(fail)};pv();
 $('#ch_kind').onchange=pv;$('#ch_new').onclick=pv;
 $('#ch_pub').onclick=function(){var me=this;me.disabled=true;api('POST','/api/channel/post',{text:draft.text,kind:draft.kind}).then(function(){me.disabled=false;toast(t('Published'));botChan()}).catch(function(e){me.disabled=false;fail(e)})};
 $('#ch_save').onclick=function(){api('PUT','/api/channel',{on:$('#ch_on').checked,id:$('#ch_id').value,hours:+unN($('#ch_h').value)||8,sign:$('#ch_sg').value,code:$('#ch_cd').value,auto_offer:$('#ch_ao').checked,
  kinds:$$('.ch_k').filter(function(x){return x.checked}).map(function(x){return x.value}).join(',')}).then(function(){toast(t('Saved'));botChan()}).catch(fail)};
 $('#ch_on').onchange=function(){api('PUT','/api/channel',{on:this.checked}).then(function(){toast(t('Saved'))}).catch(fail)};
 $('#cc_go').onclick=function(){var me=this;me.disabled=true;api('POST','/api/channel/campaign',{percent:+$('#cc_p').value||20,hours:+$('#cc_h').value||48,uses:+$('#cc_u').value||200}).then(function(r){me.disabled=false;
  toast(r.posted?t('Published')+' · '+r.code:r.code+' · '+(r.error||''),!r.posted);botChan()}).catch(function(e){me.disabled=false;fail(e)})};
 aiWire()}).catch(fail)}
// the smart channel's AI writer
function aiCard(c){var st=String(c.ai_status||''),ok=st.indexOf('ok:')==0;
 return '<div class="card" id="v37ai"><div class="nh"><div><h3>🤖 '+t('AI writer')+'</h3><p class="sub">'+t('Posts are written by the AI from your real plans, prices and codes, in the tone you describe. When it does not answer (it is tried again, and another model is tried), the built-in writer posts instead.')+'</p></div>'+
  '<label class="sw"><input type="checkbox" id="ai_on" '+(c.ai_on?'checked':'')+'><span></span></label></div>'+
  '<div class="g2f"><div><label class="f">'+t('API key')+(c.ai_has_key?' · <span class="okt">'+t('saved')+' <span class="ltr">'+esc(c.ai_key_hint||'')+'</span></span>':'')+'</label><input id="ai_key" class="ltr aikey" type="text" name="kk-grok-api" autocomplete="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore placeholder="'+esc(c.ai_has_key?t('Paste a new key to replace it'):'AQ.… / gsk_… / xai-…')+'"></div>'+
  '<div><label class="f">'+t('Model')+'</label><input id="ai_model" class="ltr" value="'+esc(c.ai_model||'')+'" placeholder="'+esc(c.ai_provider_used=='gemini'?'gemini-flash-latest':c.ai_provider_used=='xai'?'grok-4':'openai/gpt-oss-120b')+'"></div></div>'+
  '<label class="f">'+t('AI service')+'</label><select id="ai_pv">'+[['','Automatic (from the key)'],['gemini','Gemini (Google AI Studio, key AQ.… / AIza…)'],['groq','Groq (groq.com, key gsk_…)'],['xai','Grok (x.ai, key xai-…)']].map(function(o){return '<option value="'+o[0]+'"'+((c.ai_provider||'')==o[0]?' selected':'')+'>'+t(o[1])+'</option>'}).join('')+'</select>'+
  '<small class="muted">'+t('Now')+': <b class="ltr">'+esc(c.ai_provider_used=='xai'?'Grok · api.x.ai/v1':c.ai_provider_used=='gemini'?'Gemini · generativelanguage.googleapis.com':'Groq · api.groq.com/openai/v1')+'</b> · '+t('Empty model = the best one of that service; a refused model is replaced by another one of your account.')+'</small>'+
  '<label class="f">'+t('About us and how to write')+'</label><textarea id="ai_brief" rows="4" placeholder="'+esc(t('Who you are, what to stress, the tone, words to avoid…'))+'">'+esc(c.ai_brief||'')+'</textarea>'+
  '<label class="f">'+t('Posting times (Iran time)')+'</label><div class="inl"><input id="ch_times" class="ltr" value="'+esc(c.times||'')+'" placeholder="10:00, 16:00, 21:30"><button type="button" class="b2" id="ai_3x" style="flex:none">'+t('Use 3 times a day')+'</button></div><small class="muted">'+t('Empty = every N hours as above. Three times a day: 10:00, 16:00, 21:30')+'</small>'+
  (st?'<p class="'+(ok?'okt':'r')+'" style="font-size:12px;margin:8px 0 0">'+t('Last answer')+': <span class="ltr">'+esc(ok?st.slice(3):st)+'</span></p>':'')+
  '<div class="g3" style="margin-top:12px"><button class="btn" id="ai_save">'+t('Save')+'</button><button class="b2" id="ai_test">⚡ '+t('Test the key')+'</button>'+(c.ai_has_key?'<button class="b2 bd" id="ai_rm">'+t('Remove the key')+'</button>':'<span></span>')+'</div>'+
  '<div id="ai_out" class="chpv" style="display:none;margin-top:10px"></div></div>'}
function aiWire(){var g=function(id){return $('#'+id)};
 g('ai_3x').onclick=function(){g('ch_times').value='10:00, 16:00, 21:30'};
 var keyOk=function(){var k=g('ai_key').value.trim();if(k&&!/^(gsk_|xai-|AQ\.|AIza)/.test(k)&&!confirm(t('A Gemini key starts with AQ. or AIza (aistudio.google.com/apikey), a Groq key with gsk_, a Grok key with xai-. Save this one anyway?')))return false;return true};
 g('ai_save').onclick=function(){if(!keyOk())return;var b=this;b.disabled=true;api('PUT','/api/channel',{ai_on:g('ai_on').checked,ai_key:g('ai_key').value.trim(),ai_provider:g('ai_pv').value,ai_model:g('ai_model').value.trim(),ai_brief:g('ai_brief').value,times:g('ch_times').value.trim()})
  .then(function(){toast(t('Saved'));botChan()}).catch(function(e){b.disabled=false;fail(e)})};
 g('ai_test').onclick=function(){if(!keyOk())return;var b=this,o=g('ai_out');b.disabled=true;o.style.display='';o.innerHTML='<span class="muted">…</span>';
  var save=api('PUT','/api/channel',{ai_key:g('ai_key').value.trim(),ai_provider:g('ai_pv').value,ai_model:g('ai_model').value.trim()});
  save.then(function(){return api('POST','/api/channel/ai-test')}).then(function(r){o.innerHTML='<b class="okt">✓ '+t('The AI works')+' · <span class="ltr">'+esc(r.model)+'</span></b><br><br>'+String(r.text||'').replace(/\n/g,'<br>');b.disabled=false})
   .catch(function(e){o.innerHTML='<span class="r">'+esc(e.message||'')+'</span>';b.disabled=false})};
 var rm=g('ai_rm');if(rm)rm.onclick=function(){if(!confirm(t('Remove the key')+'?'))return;api('PUT','/api/channel',{ai_key:'-',ai_on:false}).then(function(){toast(t('Done'));botChan()}).catch(fail)}}
function botModal(edit){var b=S.bot||{};modal(mhead(t(edit?'Edit bot':'Create bot'))+
 '<label class="f">'+t('Bot token (from @BotFather)')+'</label><input id="bm_t" class="ltr" autocomplete="off" placeholder="'+(edit?t('Empty = keep the current token'):'123456789:AA…')+'">'+
 '<label class="f">'+t('Admin numeric ID(s), comma separated')+'</label><input id="bm_a" class="ltr" value="'+esc(b.admins||'')+'" placeholder="123456789">'+
 '<p class="muted">'+t('The panel restarts for a few seconds after saving.')+'</p><button class="btn" style="width:100%" id="bm_go">'+t('Save')+'</button>');
 $('#bm_go').onclick=function(){var tok=$('#bm_t').value.trim(),ad=$('#bm_a').value.trim();if(!edit&&!tok)return toast(t('Token is required'),1);var me=this,body={admins:ad};if(tok)body.token=tok;me.disabled=true;
  api('PUT','/api/bot',body).then(function(){closeModal();waitRestart()}).catch(function(e){me.disabled=false;fail(e)})}}
function waitRestart(){toast(t('Panel is restarting…'));var n=0;setTimeout(function(){var iv=setInterval(function(){n++;api('GET','/api/me').then(function(){clearInterval(iv);toast(t('Done'));if(S.page=='bot')botLoad()}).catch(function(){if(n>24){clearInterval(iv);location.reload()}})},2500)},3000)}

// ---- traffic & stats page
var TR={h:{rx:[],tx:[]},last:null,max:40,q:'',all:false};
function pTraffic(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Traffic & stats')+'</h2><p>'+t('Users usage and live network traffic')+'</p></div><button class="ib" id="tr_rf" title="'+t('Refresh')+'">'+ic('refresh',17)+'</button></div><div id="tr">'+t('Loading…')+'</div>';
 TR={h:{rx:[],tx:[]},last:null,max:40,q:'',all:false};if(DB.h&&DB.h.rx&&DB.h.rx.length>1){TR.h.rx=DB.h.rx.slice(-TR.max);TR.h.tx=(DB.h.tx||[]).slice(-TR.max)}$('#tr_rf').onclick=trLoad;trLoad();trTick();setTimeout(trTick,900);
 clearInterval(S.timer3);S.timer3=setInterval(function(){if(S.page=='traffic'&&document.visibilityState=='visible')trTick()},2000)}
function trLoad(){Promise.all([api('GET','/api/users'),api('GET','/api/nodes').catch(function(){return S.nodes||[]})]).then(function(r){S.users=r[0];S.nodes=r[1];trDraw()}).catch(fail)}
function trTick(){api('GET','/api/live').then(function(l){var p=TR.last;TR.last=l;if(!p)return;var sec=Math.max(.5,(l.ts-p.ts)/1000),v={rx:Math.max(0,(l.net_rx-p.net_rx)/sec),tx:Math.max(0,(l.net_tx-p.net_tx)/sec)};
  ['rx','tx'].forEach(function(k){TR.h[k].push(v[k]);if(TR.h[k].length>TR.max)TR.h[k].shift()});
  var a=$('#tr_rx'),b=$('#tr_tx'),c=$('#tr_ch');if(a)a.textContent=N(rate(v.rx));if(b)b.textContent=N(rate(v.tx));if(c)c.innerHTML=areaChart([{v:TR.h.rx,c:'a'},{v:TR.h.tx,c:'b'}],{h:132,cap:TR.max})}).catch(function(){})}
function trDraw(){var el=$('#tr');if(!el)return;var us=S.users||[],tot=0,lim=0,lu=0,pc={};
 us.forEach(function(u){var used=+u.traffic_used_gb||0;tot+=used;if(u.traffic_limit_gb>0){lim+=+u.traffic_limit_gb;lu+=Math.min(used,+u.traffic_limit_gb)}(u.protocols||'').split(',').forEach(function(p){pc[p]=(pc[p]||0)+1})});
 var pl=lim>0?Math.round(lu/lim*1000)/10:0,bar=function(lbl,v,col){var w=us.length?Math.round(v/us.length*100):0;return '<div class="brow">'+lbl+'<span class="trk"><span class="fil" style="width:'+w+'%'+(col?';background:'+col:'')+'"></span></span><b>'+N(v)+'</b></div>'};
 el.innerHTML='<div class="tr3"><div class="card tk"><small>'+t('Total recorded usage')+'</small><b class="ltr">'+N(gbtxt(tot))+'</b><span class="muted">'+N(us.length)+' '+t('users')+'</span></div>'+
  '<div class="card tk"><small>'+t('Quota of limited users')+'</small><b class="ltr">'+N(gbtxt(lim))+'</b><span class="muted">'+N(pl)+'% '+t('of it used')+'</span><span class="trk"><span class="fil" style="width:'+Math.min(100,pl)+'%"></span></span></div>'+
  '<div class="card tk"><small>'+t('Live speed')+' · '+t('this server')+'</small><div class="trs"><span>↓ <b id="tr_rx" class="ltr">—</b></span><span>↑ <b id="tr_tx" class="ltr">—</b></span></div></div></div>'+
  '<div class="card"><h3>'+t('Live network traffic')+'</h3><small class="muted">'+t('Download and upload, every 2 seconds')+'</small><div class="ch tall" id="tr_ch"></div></div>'+
  '<div class="g2 trg"><div class="card" style="margin:0"><h3>'+t('By protocol')+'</h3>'+PROTOS.map(function(p){return bar('<span class="ptag" style="--pc:'+PCOL[p[0]]+'">'+p[1]+'</span>',pc[p[0]]||0,PCOL[p[0]])}).join('')+'</div>'+
  '<div class="card" style="margin:0"><h3>'+t('By node')+'</h3>'+((S.nodes||[]).map(function(n){return bar('<span class="nmn">'+esc(n.name)+'</span>',n.users||0)}).join('')||'<span class="muted">—</span>')+'</div></div>'+
  '<div class="card" style="margin-top:12px"><div class="nh"><div><h3>'+t('Users usage')+'</h3><small class="muted">'+t('Used volume, limit and percent')+'</small></div><input id="tr_q" type="search" autocomplete="off" placeholder="'+t('Search')+'" style="max-width:190px"></div><div id="tr_ul" class="trul"></div></div>';
 $('#tr_q').value=TR.q;$('#tr_q').oninput=function(){TR.q=this.value.toLowerCase();trUsers()};trUsers();if(TR.h.rx.length>1)$('#tr_ch').innerHTML=areaChart([{v:TR.h.rx,c:'a'},{v:TR.h.tx,c:'b'}],{h:132,cap:TR.max})}
function trUsers(){var el=$('#tr_ul');if(!el)return;var l=(S.users||[]).filter(function(u){return !TR.q||u.username.toLowerCase().indexOf(TR.q)>=0}).sort(function(a,b){return b.traffic_used_gb-a.traffic_used_gb}),max=TR.all?l.length:30;
 el.innerHTML=l.slice(0,max).map(function(u){var p=usage(u),st=ustate(u);return '<button class="urow" data-u="'+u.id+'"><span class="dot '+(st=='disabled'?'r':st=='finished'?'y':(u.online_connections>0||liveOf(u).length)?'g':'')+'"></span><b class="ltr nm">'+esc(u.username)+'</b>'+
  '<span class="uu ltr">'+N(gbtxt(u.traffic_used_gb))+' / '+(u.traffic_limit_gb>0?N(gbtxt(u.traffic_limit_gb)):'∞')+'</span><span class="ub"><span class="trk"><span class="fil '+(p>85?'hot':'')+'" style="width:'+(p<0?0:Math.max(1,p))+'%"></span></span></span><span class="up ltr">'+(p<0?'∞':N(p)+'%')+'</span></button>'}).join('')+
  (l.length>max?'<button class="b2" style="width:100%;margin-top:8px" id="tr_more">'+t('Show all')+' ('+N(l.length)+')</button>':'')+(l.length?'':'<span class="muted">'+t('No match')+'</span>');
 el.onclick=function(e){var b=e.target.closest('[data-u]');if(b){editUser(+b.dataset.u);return}if(e.target.closest('#tr_more')){TR.all=true;trUsers()}}}

// ---- port management page
var PSEL='local';
function pPorts(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Port management')+'</h2><p>'+t('Ports used on the main server and on every node')+'</p></div><button class="ib" id="pt_rf" title="'+t('Refresh')+'">'+ic('refresh',17)+'</button></div><div id="pt">'+t('Loading…')+'</div>';
 $('#pt_rf').onclick=ptLoad;ptLoad()}
function ptLoad(){Promise.all([api('GET','/api/nodes'),api('GET','/api/settings').catch(function(){return {}}),api('GET','/api/system').catch(function(){return null})]).then(function(r){S.nodes=r[0];S.pset=r[1]||{};S.psys=r[2];ptDraw()}).catch(fail)}
function svcOf(list,k){for(var i=0;i<(list||[]).length;i++)if(list[i].key==k)return list[i];return null}
function ptRows(n){var loc=n.id=='local',inf=n.info||{},sv=loc&&S.psys?S.psys.services:(inf.services||[]),rows=[],ps=S.pset||{};
 var add=function(k,name,proto,port,svk){if(!port)return;var s=svcOf(sv,svk);rows.push({k:k,name:name,proto:proto,port:String(port),st:s?(s.active?'run':'stop'):'none'})};
 add('wg','WireGuard','UDP',inf.wg_port,'wireguard');add('awg','AmneziaWG','UDP',inf.awg_port,'amneziawg');add('hy2','Hysteria2','UDP',inf.hy2_port,'hysteria2');add('kmix','KANKI MIX','UDP',inf.kmix_port,'kankimix');
 if(loc){add('web',t('Panel (HTTPS)'),'TCP',ps.https_port||'443','web');add('panel',t('Panel (internal)'),'TCP',ps.web_port,'panel')}
 else{var m=String(n.address||'').match(/:(\d+)(\/|$)/);add('api',t('Node API (HTTPS)'),'TCP',m?m[1]:'443','web')}
 return rows}
function fwCmd(rows){var p=rows.filter(function(r){return r.k!='panel'}).map(function(r){return 'ufw allow '+r.port+'/'+r.proto.toLowerCase()}).filter(function(x,i,a){return a.indexOf(x)==i});return p.length?p.join(' && '):'—'}
function ptDraw(){var el=$('#pt');if(!el)return;var ns=S.nodes||[];if(!ns.some(function(n){return n.id==PSEL}))PSEL=(ns[0]||{}).id||'local';
 var n=ns.filter(function(x){return x.id==PSEL})[0]||{id:'local',info:{}},rows=ptRows(n),loc=n.id=='local',ps=S.pset||{},host=loc?(ps.endpoint||ps.domain||''):(n.effective_endpoint||''),cnt={};
 rows.forEach(function(r){cnt[r.proto+r.port]=(cnt[r.proto+r.port]||0)+1});
 el.innerHTML='<div class="psel">'+ns.map(function(x){var on=x.id=='local'||x.online;return '<button class="'+(x.id==PSEL?'on':'')+'" data-ps="'+esc(x.id)+'"><span class="dot '+(on?'g':'r')+'"></span>'+esc(x.name)+(x.id=='local'?' <small>'+t('Main')+'</small>':'')+'</button>'}).join('')+'</div>'+
  '<div class="pgrid">'+(rows.length?rows.map(function(r){var bad=cnt[r.proto+r.port]>1,sl=r.st=='run'?['g','Running']:r.st=='stop'?['r','Stopped']:['','Unknown'];
   return '<div class="card pcard'+(bad?' pbad':'')+'"><div class="ph2"><b>'+esc(r.name)+'</b><span class="pp '+r.proto.toLowerCase()+'">'+r.proto+'</span><span class="sp"></span><span class="badge '+sl[0]+'">'+t(sl[1])+'</span></div>'+
    '<button class="pnum ltr" data-cp="'+esc(r.port)+'" title="'+t('Copy')+'">'+esc(r.port)+'</button>'+
    '<small class="muted ltr pub">'+(r.k=='panel'?t('local only (127.0.0.1)'):esc((host||'?')+':'+r.port))+'</small>'+
    (bad?'<div class="warnbox">'+t('Port conflict: another service on this server uses the same port')+'</div>':'')+'</div>'}).join(''):'<p class="muted">'+t('No port information yet. Press Check now.')+'</p>')+'</div>'+
  '<div class="row" style="gap:8px;margin:2px 0 12px"><button class="b2" id="pt_chk">'+ic('check',15)+' '+t('Check now')+'</button>'+(!loc&&n.last_sync?'<small class="muted">'+t('Last contact')+': '+ago(n.last_sync)+'</small>':'')+'</div>'+
  '<div class="card"><h3>'+t('Firewall')+'</h3><p class="sub">'+t('If a port is closed, run this on that server as root:')+'</p><pre class="cmd ltr">'+esc(fwCmd(rows))+'</pre><button class="b2" id="pt_fwc">'+ic('copy',15)+' '+t('Copy command')+'</button></div>'+
  '<div class="card"><h3>'+t('All servers')+'</h3><div class="ptab"><table><thead><tr><th>'+t('Server')+'</th><th>WireGuard</th><th>AmneziaWG</th><th>Hysteria2</th><th>KANKI MIX</th><th>'+t('Panel / API')+'</th></tr></thead><tbody>'+
   ns.map(function(x){var rr=ptRows(x),g=function(k){var r=rr.filter(function(y){return y.k==k})[0];return r?'<span class="ltr">'+esc(r.port)+'</span> <span class="dot '+(r.st=='run'?'g':r.st=='stop'?'r':'')+'"></span>':'<span class="muted">—</span>'};
    return '<tr><td><b>'+esc(x.name)+'</b></td><td>'+g('wg')+'</td><td>'+g('awg')+'</td><td>'+g('hy2')+'</td><td>'+g('kmix')+'</td><td>'+(x.id=='local'?g('web'):g('api'))+'</td></tr>'}).join('')+'</tbody></table></div></div>';
 el.onclick=function(e){var b=e.target.closest('[data-ps]');if(b){PSEL=b.dataset.ps;ptDraw();return}var c=e.target.closest('[data-cp]');if(c){copy(c.dataset.cp);return}
  if(e.target.closest('#pt_fwc'))copy(fwCmd(rows));if(e.target.closest('#pt_chk'))ptCheck(n)}}
function ptCheck(n){toast(t('Checking…'));if(n.id=='local'){api('GET','/api/system').then(function(s){S.psys=s;ptDraw();toast(t('Done'))}).catch(fail);return}
 api('POST','/api/nodes/'+encodeURIComponent(n.id)+'/health').then(function(r){if(r.services){n.info=n.info||{};n.info.services=r.services}toast(r.ok?t('Done'):t('Offline'),!r.ok);ptDraw()}).catch(fail)}

