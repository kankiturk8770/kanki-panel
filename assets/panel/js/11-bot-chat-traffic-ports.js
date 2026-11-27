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
function logCard(){return '<section class="card klog" id="lgc"><div class="kc-h"><div><h3>'+t('Live log')+'</h3><small class="muted">'+t('Panel and VPN services on this server')+'</small></div>'+
 '<div class="klog-tools"><label class="klog-q"><span class="vh">'+t('Search')+'</span><input id="lg_q" type="search" placeholder="'+esc(t('Search'))+'" value="'+esc(LG.q||'')+'"></label>'+
 '<label><span class="vh">'+t('Server')+'</span><select id="lg_srv"><option value="">'+t('Panel server')+'</option></select></label>'+
 '<label><span class="vh">'+t('Source')+'</span><select id="lg_src">'+LSRC.map(function(s){return '<option value="'+s[0]+'"'+(s[0]==LG.src?' selected':'')+'>'+t(s[1])+'</option>'}).join('')+'</select></label>'+
 '<button type="button" class="kib" id="lg_pause" aria-pressed="'+LG.paused+'" aria-label="'+esc(t(LG.paused?'Resume':'Pause'))+'" title="'+esc(t(LG.paused?'Resume':'Pause'))+'">'+ic(LG.paused?'play':'pause',16)+'</button>'+
 '<button type="button" class="kib" id="lg_copy" aria-label="'+esc(t('Copy'))+'" title="'+esc(t('Copy'))+'">'+ic('copy',16)+'</button>'+
 '<button type="button" class="kib" id="lg_rf" aria-label="'+esc(t('Refresh'))+'" title="'+esc(t('Refresh'))+'">'+ic('refresh',16)+'</button></div></div>'+
 '<div class="lgt" id="lg_tabs" role="group" aria-label="'+esc(t('Level'))+'"></div><div class="klog-wrap"><div class="lgb" id="lg_box" role="log" aria-live="off" tabindex="0"><span class="muted">'+t('Loading…')+'</span></div>'+
 '<button type="button" class="b2 sm klog-latest" id="lg_latest" hidden>'+t('Return to latest')+' ↓</button></div></section>'}
function logWire(){if(!$('#lgc'))return;
 $('#lg_src').onchange=function(){LG.src=this.value;localStorage.setItem('kk_lsrc',LG.src);logLoad()};
 // another server: the warnings and errors its agent sends once a minute
 LG.srv=LG.srv||'';api('GET','/api/servers').then(function(r){var sel=$('#lg_srv');if(!sel)return;
  (r||[]).filter(function(x){return !x.local}).forEach(function(x){var o=document.createElement('option');o.value=x.key;o.textContent=x.name;if(x.key==LG.srv)o.selected=true;sel.appendChild(o)})}).catch(function(){});
 $('#lg_srv').onchange=function(){LG.srv=this.value;$('#lg_src').disabled=!!LG.srv;logLoad()};
 $('#lg_pause').onclick=function(){LG.paused=!LG.paused;var l=t(LG.paused?'Resume':'Pause');this.innerHTML=ic(LG.paused?'play':'pause',16);this.title=l;this.setAttribute('aria-label',l);this.setAttribute('aria-pressed',LG.paused)};
 $('#lg_rf').onclick=logLoad;
 $('#lg_copy').onclick=function(){copy(logRows().map(function(x){return logTime(x.ts)+' '+x.u+' '+x.m}).join('\n'))};
 $('#lg_q').oninput=function(){LG.q=this.value;logDraw()};
 $('#lg_tabs').onclick=function(e){var b=e.target.closest('[data-lv]');if(!b)return;LG.lv=b.dataset.lv;logDraw()};
 var bx=$('#lg_box');bx.onscroll=function(){LG.away=bx.scrollHeight-bx.scrollTop-bx.clientHeight>40;$('#lg_latest').hidden=!LG.away};
 $('#lg_latest').onclick=function(){LG.away=false;bx.scrollTop=bx.scrollHeight;this.hidden=true};
 LG.away=false;logLoad();clearInterval(S.timer3);S.timer3=setInterval(function(){if($('#lgc')&&!LG.paused&&document.visibilityState=='visible')logLoad()},5000)}
function logLoad(){return api('GET','/api/logs?src='+encodeURIComponent(LG.src)+'&n=300'+(LG.srv?'&server='+encodeURIComponent(LG.srv):'')).then(function(r){LG.lines=r.lines||[];LG.err='';logDraw()}).catch(function(e){LG.err=e.message||'error';logDraw()})}
function logRows(){var q=String(LG.q||'').trim().toLowerCase();return LG.lines.filter(function(x){return (LG.lv=='all'||lgLevel(x)==LG.lv)&&(!q||(String(x.m)+' '+String(x.u)).toLowerCase().indexOf(q)>=0)})}
function logTime(ts){var d=new Date(ts*1000);return p2(d.getHours())+':'+p2(d.getMinutes())+':'+p2(d.getSeconds())}
function logDraw(){var tb=$('#lg_tabs'),bx=$('#lg_box');if(!tb||!bx)return;
 var c={all:LG.lines.length,e:0,d:0};LG.lines.forEach(function(x){var l=lgLevel(x);if(l!='i')c[l]++});
 tb.innerHTML=[['all','All'],['e','Errors'],['d','Debug']].map(function(x){return '<button type="button" data-lv="'+x[0]+'" aria-pressed="'+(LG.lv==x[0])+'" class="lv-'+x[0]+(LG.lv==x[0]?' on':'')+'">'+t(x[1])+' <b>'+N(c[x[0]])+'</b></button>'}).join('');
 if(LG.err){bx.innerHTML='<span class="bad2">'+t('Logs are not available')+' ('+esc(LG.err)+')</span>';return}
 var rows=logRows(),top=bx.scrollTop;
 bx.innerHTML=rows.length?rows.map(function(x){var l=lgLevel(x);return '<div class="lr '+l+'"><time class="lt">'+logTime(x.ts)+'</time><span class="lv" aria-label="'+esc(t(l=='e'?'Error':l=='d'?'Debug':'Info'))+'">'+(l=='e'?'ERR':l=='d'?'DBG':'INF')+'</span><span class="lu">'+esc(String(x.u||'').replace(/\.service$/,''))+'</span><span class="lm">'+esc(x.m)+'</span></div>'}).join(''):
  '<span class="muted">'+t(LG.lv=='e'?'No errors':LG.lv=='d'?'No debug lines':'No log lines yet')+'</span>';
 // follow the newest line, unless you have scrolled back to read
 if(LG.away)bx.scrollTop=top;else bx.scrollTop=bx.scrollHeight}

function editUser(id,tab){var u=findU(id);if(!u)return;if(tab=='edit')return userEditModal(id);var p=usage(u),st=ustate(u),
  tg=(u.protocols||'').split(',').filter(function(x){return x}).map(function(x){return '<span class="ptag" style="--pc:'+(PCOL[x]||'#999')+'">'+esc(pname(x))+'</span>'}).join(''),
  cls=st=='active'?'g':st=='finished'?'y':'r',lbl=t(st=='active'?'Active':st=='finished'?(u.status=='Limited'?'Limited':'Expired'):'Disabled'),cur='';
 modal('<div class="us-h"><span class="dot '+((u.online_connections>0||liveOf(u).length)?'g':'')+'"></span><b class="ltr nm">'+esc(u.username)+'</b><span class="u-st '+cls+'" id="e_badge">'+lbl+'</span><span class="sp"></span>'+
  '<label class="sw"><input type="checkbox" id="e_sw" '+(u.enabled?'checked':'')+' aria-label="'+t('Enable')+'"><span></span></label><button class="ib" onclick="closeModal()" aria-label="close">✕</button></div>'+
  '<div class="us-tags">'+(tg||'<span class="ptag none">—</span>')+'</div>'+
  (liveOf(u).length?'<div class="lvlist"><small class="muted" style="width:100%">'+t('Connected now')+'</small>'+liveOf(u).map(function(c){return '<span style="--pc:'+(PCOL[c.p]||'#888')+'"><b>'+esc(pname(c.p))+'</b>'+(c.cc?flagOf(c.cc)+' ':'')+esc(c.s)+(c.t?' · '+flagOf('IR')+' '+t('through Iran'):'')+'</span>'}).join('')+'</div>':'<div class="lvlist"><small class="muted">'+t('Not connected right now')+'</small></div>')+
  '<div class="us-st"><div><small>'+t('Used')+'</small><b class="ltr">'+exactB(u.used_bytes)+' / '+(u.traffic_limit_gb>0?N(gbtxt(u.traffic_limit_gb)):'∞')+'</b><div class="trk"><div class="fil '+(p>85?'hot':'')+'" style="width:'+(p<0?100:Math.max(2,p))+'%"></div></div></div>'+
  '<div><small>'+t('Expiry')+'</small><b>'+jdate(u.expires_ts)+'</b><small>'+leftTxt(u.expires_ts)+'</small></div>'+
  '<div><small>'+t('Connections')+'</small><b class="ltr">'+N(u.online_connections)+' / '+(u.max_connections?N(u.max_connections):'∞')+'</b><small>'+(u.last_seen_ts?ago(u.last_seen_ts)+'<br><span class="ltr">'+jdate(u.last_seen_ts,true)+'</span>':t('never'))+'</small></div></div>'+
  // (3.52) data moved after the account ran out, and where: a server or protocol that does not take an
  // ended account off shows here
  (function(){var al=u.after_limit||{},src=al.src||{},k=Object.keys(src);if(!k.length)return '';
   return '<div class="warnbox u-mt2"><b>'+t('Data used after the account ended')+'</b><br>'+k.map(function(x){return '<span class="ltr">'+esc(x)+'</span>: <b class="ltr">'+exactB(src[x])+'</b>'}).join('<br>')+'</div>'})()+
  // (3.40) what is only in the details: note, Telegram ID and the devices that opened the link
  (function(){var dv=u.devices||[],rows=[];
   if(u.notes)rows.push('<div><small>'+t('Note')+'</small><span>'+esc(u.notes)+'</span></div>');
   if(u.tg_id)rows.push('<div><small>'+t('Telegram ID')+'</small><span class="ltr">'+esc(String(u.tg_id))+'</span></div>');
   if(dv.length)rows.push('<div class="wide"><small>'+t('Devices')+' ('+N(dv.length)+')</small>'+dv.map(function(x){return '<span class="us-dev">'+esc(x.app||x.kind||'—')+(x.kanki?' · Kanki':'')+'<small class="ltr">'+esc(x.ip||'')+(x.last?' · '+ago(x.last):'')+'</small></span>'}).join('')+'</div>');
   return rows.length?'<div class="us-info">'+rows.join('')+'</div>':''})()+
  // (3.71) a v2ray or gaming account becomes VIP in place: same account, code, volume and end date
  (tierKey(u.tier)&&tierKey(u.tier)!='vip'?'<div class="us-upg"><span><b>'+esc(t(TIER_NAMES[tierKey(u.tier)]))+'</b><small>'+t('Same account, code, volume and end date; the other cores are added.')+'</small></span><button type="button" class="btn sm" id="us_upg">⬆️ '+t('Upgrade to VIP')+'</button></div>':'')+
  '<div class="qb5 us-q" id="us_q"><button data-t="edit">'+ic('edit',18)+'<span>'+t('Edit')+'</span></button><button data-t="link">'+ic('link',18)+'<span>'+t('Link')+'</span></button><button data-t="qr">'+ic('qr',18)+'<span>QR</span></button>'+
  '<button data-t="reset">'+ic('reset',18)+'<span>'+t('Reset')+'</span></button><button data-t="del" class="x">'+ic('trash',18)+'<span>'+t('Delete')+'</span></button></div>'+
  '<div id="us_p"></div>','usheet');
 function show(k){var el=$('#us_p');cur=k;$$('#us_q [data-t]').forEach(function(b){b.classList.toggle('on',b.dataset.t==k)});
  if(!k){el.innerHTML='';return}
  if(k=='edit'){userEditModal(u.id);return}
  if(k=='link'){el.innerHTML='<small class="muted">'+t('Subscription link')+' · '+t('Created')+' '+(u.created_at?jdate(Date.parse(u.created_at)/1000):'—')+'</small><div class="lk">'+esc(u.link)+'</div>'+
    '<div class="g2" style="gap:8px"><button class="btn" id="s_cp">'+ic('copy',16)+' '+t('Copy link')+'</button><a class="b2" style="text-decoration:none;text-align:center" target="_blank" rel="noopener" href="'+esc(u.link)+'">'+ic('ext',16)+' '+t('Open page')+'</a></div>'+
    '<div class="us-cfg"><small class="muted">'+t('Configs')+'</small><div id="sx"></div></div>'+
    '<div class="us-cfg"><small class="muted">'+t('AmneziaVPN backup: every WireGuard and AmneziaWG server in one file (Restore from backup)')+'</small>'+
    '<div class="row" style="gap:8px;flex-wrap:wrap;margin-top:6px">'+[['i','iPhone'],['a','Android'],['w','Windows']].map(function(x){return '<button class="b2 sm" data-amz="'+x[0]+'">'+ic('dl',15)+' '+x[1]+'</button>'}).join('')+'</div></div>';
   $('#s_cp').onclick=function(){copy(u.link)};sheetCfg(u.id);
   $$('[data-amz]',el).forEach(function(b){b.onclick=function(){var me=this;me.disabled=true;
    api('GET','/api/users/'+u.id+'/amnezia/'+me.dataset.amz,undefined,{blob:1}).then(function(r){dl(r);me.disabled=false}).catch(function(e){me.disabled=false;fail(e)})}});return}
  if(k=='qr')qrInto(el,u.link)}
 var ug=$('#us_upg');if(ug)ug.onclick=function(){confirmDo(function(){ug.disabled=true;api('POST','/api/users/'+u.id+'/upgrade',{tier:'vip'}).then(function(){toast(t('Done'));closeModal();loadUsers()}).catch(function(e){ug.disabled=false;fail(e)})})};
 $('#us_q').onclick=function(e){var b=e.target.closest('[data-t]');if(!b)return;var k=b.dataset.t;
  if(k=='reset')return resetU(u.id);if(k=='del')return delU(u.id);show(cur==k?'':k)};
 $('#e_sw').onchange=function(){var cb=this;cb.disabled=true;api('POST','/api/users/'+u.id+'/toggle').then(function(r){cb.disabled=false;u.enabled=r.enabled;u.status=r.status;var s2=ustate(u),b=$('#e_badge');
   if(b){b.className='u-st '+(s2=='active'?'g':s2=='finished'?'y':'r');b.textContent=t(s2=='active'?'Active':s2=='finished'?(u.status=='Limited'?'Limited':'Expired'):'Disabled')}toast(t('Done'));loadUsers()}).catch(function(e){cb.checked=!cb.checked;cb.disabled=false;fail(e)})};
 if(tab)show(tab)}

// (3.64) the edit form of one user: a window of its own in the middle of the screen, never a form further down
function userEditModal(id){var u=findU(id);if(!u)return;
 modal(mhead(t('Edit user'),u.username)+ufForm(u)+'<button class="btn" style="width:100%;margin-top:12px" id="f_save">'+t('Save changes')+'</button>'+
  '<button class="lnk" id="s_rg">'+ic('refresh',14)+' '+t('New link (the old one stops working)')+'</button>','wide uedit');wireForm(u);
 $('#f_save').onclick=function(){var b=formBody();if(!b)return;var nm=$('#f_name').value.trim();if(nm&&nm!=u.username){if(!nameOk(nm))return toast(t(NAME_ERR),1);b.username=nm}var me=this;me.disabled=true;
  api('PUT','/api/users/'+u.id,b).then(function(){toast(t('Saved'));closeModal();loadUsers()}).catch(function(e){me.disabled=false;fail(e)})};
 $('#s_rg').onclick=function(){confirmDo(function(){api('POST','/api/users/'+u.id+'/regen').then(function(){toast(t('Done'));return loadUsers()}).then(function(){editUser(id,'link')}).catch(fail)})};
 var f=$('#f_name');if(f)try{f.focus({preventScroll:true})}catch(e){}}

// ---- Telegram sales bot page
function pBot(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Telegram sales bot')+'</h2><p>'+t('Create and manage the sales bot')+'</p></div><div id="bt_top"></div></div><div id="bt">'+skel()+'</div>';botLoad()}
function botLoad(){return Promise.all([api('GET','/api/bot'),api('GET','/api/overview').catch(function(){return {}})]).then(function(r){S.bot=r[0];S.bov=r[1]||{};botDraw()}).catch(fail)}
function botDraw(){var b=S.bot||{},el=$('#bt');if(!el)return;var has=!!b.token_set;
 $('#bt_top').innerHTML='';
 // (3.40.1) the shop at a glance: sales, money in, active users, orders still open
 var o=S.bov||{},bst=kuStats([[t('Total sales'),N(o.sales||0)],[t('Revenue'),money(o.revenue)],[t('Active users'),N(o.active||0),'ok'],[t('Pending orders'),N(o.pending_orders||0),(o.pending_orders?'warn':'')]]);
 var st=b.paused?['y','Paused']:b.online?['g','Online']:['r','Offline'];
 var head=has?'<div class="card bcard"><div class="bh"><span class="bav">'+ic('bot',24)+'</span><div class="bn2"><b>'+esc(b.name||t('Sales bot'))+'</b>'+(b.username?'<a class="ltr" target="_blank" rel="noopener" href="https://t.me/'+encodeURIComponent(b.username)+'">@'+esc(b.username)+'</a>':'')+'</div>'+
   '<span class="badge '+st[0]+'"><span class="dot '+st[0]+'"></span> '+t(st[1])+'</span></div>'+
   (!b.paused&&!b.online&&b.error?'<div class="warnbox ltr" style="margin:10px 0">'+esc(b.error)+'</div>':'')+(b.conflict?'<div class="warnbox">'+t('Another program uses this bot token (an old panel still running?). Stop it, or make a new token in @BotFather.')+'</div>':'')+
   '<p class="muted" style="margin:10px 0">'+t('Plans, prices and payments can also be managed inside the bot (Admin panel button).')+'</p><div class="bmeta"><span>'+t('Bot admins')+': <b class="ltr">'+esc(b.admins||'—')+'</b></span><span>'+t('Token')+': <b class="ltr">'+esc(b.token_masked||'')+'</b></span></div>'+
   '<div class="g4b"><button class="b2" id="bt_test">'+ic('send',15)+' '+t('Test connection')+'</button><button class="b2" id="bt_pause">'+ic(b.paused?'play':'pause',15)+' '+t(b.paused?'Resume':'Pause')+'</button><button class="b2" id="bt_edit">'+ic('edit',15)+' '+t('Edit')+'</button><button class="b2 bd" id="bt_del">'+ic('trash',15)+' '+t('Delete bot')+'</button></div></div>'
  :'<div class="card bempty"><span class="bav big">'+ic('bot',30)+'</span><h3>'+t('No sales bot yet')+'</h3><ol class="steps"><li>'+t('In Telegram open @BotFather, send /newbot and copy the token it gives.')+'</li><li>'+t('Get your numeric Telegram ID from @userinfobot.')+'</li><li>'+t('Press Create bot and paste both.')+'</li></ol><button class="btn" id="bt_new2">+ '+t('Create bot')+'</button></div>';
 // (3.48) the web panel keeps only the bot itself (token, admins) and the report bot: sales, payments, plans, discount
 // codes, the channel, the app message and the app files are set in the bot's own admin mini app
 el.innerHTML=(has?bst:'')+head+(has?'<div class="card bmove"><h3>⚙️ '+t('Bot management is in the bot now')+'</h3><p class="sub">'+t('Sales, payments, plans, discount codes, invites, the free trial, the smart channel, the app message and the app files are set inside Telegram: open the bot › Admin panel › «Bot management». The panel keeps only the bot\'s token.')+'</p>'+(b.username?'<a class="btn" target="_blank" rel="noopener" href="https://t.me/'+encodeURIComponent(b.username)+'">'+ic('send',15)+' '+t('Open the bot')+'</a>':'')+'</div>':'')+botMon();
 var w=function(id,fn){var x=$(id);if(x)x.onclick=fn};
 w('#bt_new',function(){botModal(false)});w('#bt_new2',function(){botModal(false)});w('#bt_edit',function(){botModal(true)});
 w('#bt_test',function(){toast(t('Checking…'));api('POST','/api/bot/test').then(function(r){toast(r.ok?'✓ @'+(r.username||''):(r.error||t('Failed')),!r.ok)}).catch(fail)});
 w('#bt_pause',function(){api('POST','/api/bot/pause').then(function(){toast(t('Done'));botLoad()}).catch(fail)});
 w('#bt_del',function(){confirmDo(function(){api('DELETE','/api/bot').then(waitRestart).catch(fail)})});}
// ---- Logs: the last warnings and errors of Kanki's services on every server (3.65: a page of its own)
function pLogs(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Logs')+'</h2></div></div><div id="lgv">'+logCard()+'</div>';logWire()}
function verLt(a,b){var p=function(v){return String(v).replace(/^v/,'').split('.').map(function(x){return +x||0})},x=p(a),y=p(b);for(var i=0;i<3;i++){if((x[i]||0)!=(y[i]||0))return (x[i]||0)<(y[i]||0)}return false}

function botModal(edit){var b=S.bot||{};modal(mhead(t(edit?'Edit bot':'Create bot'))+
 '<label class="f">'+t('Bot token (from @BotFather)')+'</label><input id="bm_t" class="ltr" autocomplete="off" placeholder="'+(edit?t('Empty = keep the current token'):'123456789:AA…')+'">'+
 '<label class="f">'+t('Admin numeric ID(s), comma separated')+'</label><input id="bm_a" class="ltr" value="'+esc(b.admins||'')+'" placeholder="123456789">'+
 '<p class="muted">'+t('The panel restarts for a few seconds after saving.')+'</p><button class="btn" style="width:100%" id="bm_go">'+t('Save')+'</button>');
 $('#bm_go').onclick=function(){var tok=$('#bm_t').value.trim(),ad=$('#bm_a').value.trim();if(!edit&&!tok)return toast(t('Token is required'),1);var me=this,body={admins:ad};if(tok)body.token=tok;me.disabled=true;
  api('PUT','/api/bot',body).then(function(){closeModal();waitRestart()}).catch(function(e){me.disabled=false;fail(e)})}}
// (3.47) the report bot: a second bot with its own token, only for the panel's owners (servers, tunnels, paths, backups)
function botMon(){var b=S.bot||{},st=b.mon_set?(b.mon_online?['g','Online']:['r','Offline']):['y','Not set'];
 return '<div class="card"><h3>🛰 '+t('Report bot')+'</h3><p class="sub">'+t('Alerts about servers, tunnels and paths, and the daily backup, go to a second bot, so the sales bot stays only for customers. Without it they go to the sales bot admins.')+'</p>'+
  '<p><span class="badge '+st[0]+'"><span class="dot '+st[0]+'"></span> '+t(st[1])+'</span>'+(b.mon_username?' <a class="ltr" target="_blank" rel="noopener" href="https://t.me/'+encodeURIComponent(b.mon_username)+'">@'+esc(b.mon_username)+'</a>':'')+'</p>'+
  (b.mon_set&&!b.mon_online&&b.mon_error?'<div class="warnbox ltr" style="margin:10px 0">'+esc(b.mon_error)+'</div>':'')+
  (b.mon_set?'<div class="bmeta"><span>'+t('Report admins')+': <b class="ltr">'+esc(b.mon_admins||b.admins||'—')+'</b></span><span>'+t('Token')+': <b class="ltr">'+esc(b.mon_masked||'')+'</b></span></div>':'<ol class="steps"><li>'+t('In @BotFather make a second bot (/newbot) and copy its token.')+'</li><li>'+t('Paste it here; open the new bot and press Start.')+'</li></ol>')+
  '<div class="g2f" style="margin-top:10px"><button class="btn" onclick="botMonModal()">'+ic('edit',15)+' '+t(b.mon_set?'Edit':'Set the report bot')+'</button>'+(b.mon_set?'<button class="b2 bd" onclick="botMonOff()">'+ic('trash',15)+' '+t('Turn off')+'</button>':'<div></div>')+'</div></div>'}
function botMonModal(){var b=S.bot||{};modal(mhead(t('Report bot'))+
 '<label class="f">'+t('Bot token (from @BotFather)')+'</label><input id="mm_t" class="ltr" autocomplete="off" placeholder="'+(b.mon_set?t('Empty = keep the current token'):'123456789:AA…')+'">'+
 '<label class="f">'+t('Who gets the reports (numeric IDs, comma separated; empty = the sales bot admins)')+'</label><input id="mm_a" class="ltr" value="'+esc(b.mon_admins||'')+'" placeholder="123456789">'+
 '<p class="muted">'+t('The panel restarts for a few seconds after saving.')+'</p><button class="btn" style="width:100%" id="mm_go">'+t('Save')+'</button>');
 $('#mm_go').onclick=function(){var tok=$('#mm_t').value.trim();if(!b.mon_set&&!tok)return toast(t('Token is required'),1);var me=this,body={mon_admins:$('#mm_a').value.trim()};if(tok)body.mon_token=tok;me.disabled=true;
  api('PUT','/api/bot',body).then(function(){closeModal();waitRestart()}).catch(function(e){me.disabled=false;fail(e)})}}
function botMonOff(){confirmDo(function(){api('PUT','/api/bot',{mon_clear:true}).then(waitRestart).catch(fail)})}
function waitRestart(){toast(t('Panel is restarting…'));var n=0;setTimeout(function(){var iv=setInterval(function(){n++;api('GET','/api/me').then(function(){clearInterval(iv);toast(t('Done'));if(S.page=='bot')botLoad()}).catch(function(){if(n>24){clearInterval(iv);location.reload()}})},2500)},3000)}

// ---- traffic & stats page
var TR={h:{rx:[],tx:[]},last:null,max:40,q:'',all:false};
function pTraffic(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Traffic & stats')+'</h2><p>'+t('Users usage and live network traffic')+'</p></div><div class="row"><button type="button" class="kib" id="tr_rf" title="'+t('Refresh')+'" aria-label="'+t('Refresh')+'">'+ic('refresh',17)+'</button></div></div><div id="tr"><div class="kskel"></div><div class="kskel"></div></div>';
 TR={h:{rx:[],tx:[]},last:null,max:40,q:'',all:false};if(DB.h&&DB.h.rx&&DB.h.rx.length>1){TR.h.rx=DB.h.rx.slice(-TR.max);TR.h.tx=(DB.h.tx||[]).slice(-TR.max)}$('#tr_rf').onclick=trLoad;trLoad();trTick();setTimeout(trTick,900);
 var n=0;clearInterval(S.timer3);S.timer3=setInterval(function(){if(S.page=='traffic'&&document.visibilityState=='visible'){trTick();if(++n%15==0)trSrvLoad()}},2000)}
function trLoad(){Promise.all([api('GET','/api/users'),api('GET','/api/nodes').catch(function(){return S.nodes||[]}),api('GET','/api/servers/traffic').catch(function(){return null})]).then(function(r){S.users=r[0];S.nodes=r[1];TR.srv=r[2];trDraw()}).catch(fail)}
// (3.45) what every server's network card moved: VPN users, tunnels in and out, everything. A user behind a
// tunnel crosses two servers, so their bytes are on both rows (both datacenters count them).
function trSrvLoad(){api('GET','/api/servers/traffic').then(function(d){TR.srv=d;trSrv()}).catch(function(){})}
function trPair(v){v=v||[0,0];return '<b class="ltr">'+N(bytes(v[0]+v[1]))+'</b><small class="muted ltr"><span>↓ '+N(bytes(v[0]))+'</span> <span>↑ '+N(bytes(v[1]))+'</span></small>'}
function trSrv(){var el=$('#tr_srv');if(!el)return;var d=TR.srv;
 if(!d){el.innerHTML='<p class="muted ku-empty">'+t('Could not load the traffic of the servers')+'</p>';return}
 var l=(d.servers||[]).slice().sort(function(a,b){return (b.none?-1:(b.d30||[0,0])[0]+(b.d30||[0,0])[1])-(a.none?-1:(a.d30||[0,0])[0]+(a.d30||[0,0])[1])}),sum={today:[0,0],d7:[0,0],d30:[0,0],total:[0,0]};
 if(!l.length){el.innerHTML='<p class="muted ku-empty">'+t('No server yet')+'</p>';return}
 l.forEach(function(r){if(r.none)return;['today','d7','d30','total'].forEach(function(k){sum[k][0]+=(r[k]||[0,0])[0];sum[k][1]+=(r[k]||[0,0])[1]})});
 var th='<thead><tr><th>'+t('Server')+'</th><th>'+t('Today')+'</th><th class="d7">'+t('Last 7 days')+'</th><th>'+t('Last 30 days')+'</th><th>'+t('Since counting began')+'</th><th>'+t('Now')+'</th></tr></thead>';
 var tr=function(r){var nm='<td class="nm"><span class="dot '+(r.online?'g':'r')+'"></span>'+flagOf(r.cc)+'<b>'+esc(r.name)+'</b>'+(r.none?'':'<small class="muted"><span class="ltr">'+esc(r.nic||'')+'</span> <span>'+t('since')+' '+jdate(r.since)+'</span></small><button type="button" class="b2 sm" data-sd="'+esc(r.key)+'">'+ic('traffic',14)+' '+t('Days')+'</button>')+'</td>';
  if(r.none)return '<tr>'+nm+'<td colspan="5" data-l="'+esc(t('Traffic'))+'"><span class="muted">'+t('Update this server to see its traffic')+'</span></td></tr>';
  var lv=r.live||[0,0];
  return '<tr>'+nm+'<td data-l="'+esc(t('Today'))+'">'+trPair(r.today)+'</td><td class="d7" data-l="'+esc(t('Last 7 days'))+'">'+trPair(r.d7)+'</td><td data-l="'+esc(t('Last 30 days'))+'">'+trPair(r.d30)+'</td>'+
   '<td data-l="'+esc(t('Since counting began'))+'">'+trPair(r.total)+'</td><td data-l="'+esc(t('Now'))+'"><b class="ltr">↓ '+N(rate(lv[0]))+'</b><small class="muted ltr"><span>↑ '+N(rate(lv[1]))+'</span></small></td></tr>'};
 el.innerHTML='<div class="ku-tt-wrap"><table class="ku-tt ktr-st">'+th+'<tbody>'+l.map(tr).join('')+
  '<tr class="sum"><td class="nm"><b>'+t('All servers')+'</b></td><td data-l="'+esc(t('Today'))+'">'+trPair(sum.today)+'</td><td class="d7" data-l="'+esc(t('Last 7 days'))+'">'+trPair(sum.d7)+'</td><td data-l="'+esc(t('Last 30 days'))+'">'+trPair(sum.d30)+'</td><td data-l="'+esc(t('Since counting began'))+'">'+trPair(sum.total)+'</td><td></td></tr>'+
  '</tbody></table></div><p class="muted ktr-note">'+t('Measured on each server\'s network card: users, tunnels and everything else. Traffic through a tunnel crosses two servers, so it is on both rows. Days are Tehran days.')+'</p>';
 el.onclick=function(e){var b=e.target.closest('[data-sd]');if(b)trDays(b.dataset.sd)}}
function trDays(key){var r=((TR.srv||{}).servers||[]).filter(function(x){return x.key==key})[0];if(!r||r.none)return;
 var d0=Math.floor((r.since+12600)/86400),ds=(r.days||[]).filter(function(x){return x[0]>=d0}).reverse(),mx=1;ds.forEach(function(x){mx=Math.max(mx,x[1]+x[2])});
 modal(mhead(t('Traffic by day'),r.name)+'<div class="ktr-days">'+ds.map(function(x){var w=Math.round((x[1]+x[2])/mx*100);
  return '<div class="kbr"><span class="kbr-l ltr">'+jdate(x[0]*86400-12600+43200)+'</span><span class="trk"><span class="fil" style="width:'+(x[1]+x[2]>0?Math.max(1,w):0)+'%"></span></span><b class="kbr-v ltr" title="↓ '+N(bytes(x[1]))+' · ↑ '+N(bytes(x[2]))+'">'+N(bytes(x[1]+x[2]))+'</b></div>'}).join('')+'</div>'+
  '<p class="muted">↓ '+t('Received')+' · ↑ '+t('Sent')+' — '+t('since')+' '+jdate(r.since,1)+'</p>')}
function trTick(){api('GET','/api/live').then(function(l){var p=TR.last;TR.last=l;if(!p)return;var sec=Math.max(.5,(l.ts-p.ts)/1000),v={rx:Math.max(0,(l.net_rx-p.net_rx)/sec),tx:Math.max(0,(l.net_tx-p.net_tx)/sec)};
  ['rx','tx'].forEach(function(k){TR.h[k].push(v[k]);if(TR.h[k].length>TR.max)TR.h[k].shift()});
  var a=$('#tr_rx'),b=$('#tr_tx'),c=$('#tr_ch');if(a)a.textContent=N(rate(v.rx));if(b)b.textContent=N(rate(v.tx));if(c)c.innerHTML=areaChart([{v:TR.h.rx,c:'a'},{v:TR.h.tx,c:'b'}],{h:160,cap:TR.max})}).catch(function(){})}
// (3.41) the totals, the live chart with its legend, who uses what (protocol and server), then every user
function trDraw(){var el=$('#tr');if(!el)return;var us=S.users||[],tot=0,lim=0,lu=0,pc={};
 us.forEach(function(u){var used=+u.traffic_used_gb||0;tot+=used;if(u.traffic_limit_gb>0){lim+=+u.traffic_limit_gb;lu+=Math.min(used,+u.traffic_limit_gb)}(u.protocols||'').split(',').forEach(function(p){pc[p]=(pc[p]||0)+1})});
 var pl=lim>0?Math.round(lu/lim*1000)/10:0,
  bar=function(lbl,v,col){var w=us.length?Math.max(0,Math.min(100,Math.round(v/us.length*100))):0;return '<div class="kbr"><span class="kbr-l">'+lbl+'</span><span class="trk"><span class="fil" style="width:'+w+'%'+(col?';background:'+col:'')+'"></span></span><b class="kbr-v">'+N(v)+'</b></div>'};
 el.innerHTML=kuStats([[t('Total recorded usage'),'<span class="ltr">'+N(gbtxt(tot))+'</span>'],[t('Quota of limited users')+' · '+N(pl)+'% '+t('of it used'),'<span class="ltr">'+N(gbtxt(lim))+'</span>'],
   ['↓ '+t('Download')+' · '+t('this server'),'<span class="ltr" id="tr_rx">—</span>'],['↑ '+t('Upload')+' · '+t('this server'),'<span class="ltr" id="tr_tx">—</span>']])+
  '<section class="card"><div class="kc-h"><div><h3>'+t('Live network traffic')+'</h3><small class="muted">'+t('Download and upload, every 2 seconds')+'</small></div>'+
   '<div class="klegend"><span class="a"><i></i>'+t('Download')+'</span><span class="b"><i></i>'+t('Upload')+'</span></div></div><div class="ch ktr-ch" id="tr_ch"></div></section>'+
  '<section class="card ktr-s"><div class="kc-h"><div><h3>'+t('Traffic of each server')+'</h3><small class="muted">'+t('Received and sent by the server itself, tunnels included')+'</small></div></div><div id="tr_srv"></div></section>'+
  '<div class="kgrid"><section class="card c6"><div class="kc-h"><div><h3>'+t('By protocol')+'</h3><small class="muted">'+t('Users')+'</small></div></div>'+PROTOS.map(function(p){return bar('<span class="ptag" style="--pc:'+PCOL[p[0]]+'">'+p[1]+'</span>',pc[p[0]]||0,PCOL[p[0]])}).join('')+'</section>'+
  '<section class="card c6"><div class="kc-h"><div><h3>'+t('By node')+'</h3><small class="muted">'+t('Users')+'</small></div></div>'+((S.nodes||[]).map(function(n){return bar('<span class="nmn">'+esc(n.name)+'</span>',n.users||0)}).join('')||'<span class="muted">—</span>')+'</section></div>'+
  '<section class="card ktr-u"><div class="kc-h"><div><h3>'+t('Users usage')+'</h3><small class="muted">'+t('Used volume, limit and percent')+'</small></div><label class="ktr-q"><span class="vh">'+t('Search')+'</span><input id="tr_q" type="search" autocomplete="off" placeholder="'+t('Search')+'"></label></div><div id="tr_ul" class="trul"></div></section>';
 $('#tr_q').value=TR.q;$('#tr_q').oninput=function(){TR.q=this.value.toLowerCase();trUsers()};trUsers();trSrv();if(TR.h.rx.length>1)$('#tr_ch').innerHTML=areaChart([{v:TR.h.rx,c:'a'},{v:TR.h.tx,c:'b'}],{h:160,cap:TR.max})}
function trUsers(){var el=$('#tr_ul');if(!el)return;var l=(S.users||[]).filter(function(u){return !TR.q||u.username.toLowerCase().indexOf(TR.q)>=0}).sort(function(a,b){return b.traffic_used_gb-a.traffic_used_gb}),max=TR.all?l.length:30;
 el.innerHTML=l.slice(0,max).map(function(u){var p=usage(u),st=ustate(u);return '<button class="urow" data-u="'+u.id+'"><span class="dot '+(st=='disabled'?'r':st=='finished'?'y':(u.online_connections>0||liveOf(u).length)?'g':'')+'"></span><b class="ltr nm">'+esc(u.username)+'</b>'+
  '<span class="uu ltr">'+N(gbtxt(u.traffic_used_gb))+' / '+(u.traffic_limit_gb>0?N(gbtxt(u.traffic_limit_gb)):'∞')+'</span><span class="ub"><span class="trk"><span class="fil '+(p>85?'hot':'')+'" style="width:'+(p<0?0:Math.max(1,p))+'%"></span></span></span><span class="up ltr">'+(p<0?'∞':N(p)+'%')+'</span></button>'}).join('')+
  (l.length>max?'<button class="b2" style="width:100%;margin-top:8px" id="tr_more">'+t('Show all')+' ('+N(l.length)+')</button>':'')+(l.length?'':'<span class="muted">'+t('No match')+'</span>');
 el.onclick=function(e){var b=e.target.closest('[data-u]');if(b){editUser(+b.dataset.u);return}if(e.target.closest('#tr_more')){TR.all=true;trUsers()}}}

// ---- port management page
var PSEL='local';
function pPorts(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Port management')+'</h2><p>'+t('Ports used on the main server and on every node')+'</p></div><div class="row"><button type="button" class="kib" id="pt_rf" title="'+t('Refresh')+'" aria-label="'+t('Refresh')+'">'+ic('refresh',17)+'</button></div></div><div id="pt"><div class="kskel"></div><div class="kskel"></div></div>';
 $('#pt_rf').onclick=ptLoad;ptLoad()}
// (3.71) every server: the panel, the servers abroad and the Iran servers (also those without a VPN part, from what
// their agent says is listening), under the one name they have everywhere
function ptLoad(){Promise.all([api('GET','/api/nodes'),api('GET','/api/settings').catch(function(){return {}}),api('GET','/api/system').catch(function(){return null}),api('GET','/api/servers').catch(function(){return null})]).then(function(r){S.nodes=r[0];S.pset=r[1]||{};S.psys=r[2];S.psrv=r[3];ptDraw()}).catch(fail)}
function ptList(){var sv=(S.psrv&&S.psrv.servers)||[];
 if(!sv.length)return (S.nodes||[]).map(function(n){return {id:n.id,name:n.name,online:n.id=='local'||n.online,node:n,loc:''}});
 return sv.map(function(x){var nd=x.node||null;if(x.local&&!nd)nd={id:'local',info:{},name:x.name};if(nd)nd=Object.assign({},nd,{name:x.name});
  return {id:x.key,name:x.name,online:!!(x.local||(x.agent&&x.agent.online)||(nd&&nd.online)),node:nd,loc:x.loc||'',listen:x.agent&&x.agent.listen}})}
function ptRowsOf(e){if(e.node)return ptRows(e.node);
 return (e.listen||[]).map(function(l){return {k:'l'+l.port+l.proto,name:l.unit?String(l.unit).replace(/\.service$/,''):(l.prog||'?'),proto:l.proto,port:String(l.port),st:'run'}})}
function svcOf(list,k){for(var i=0;i<(list||[]).length;i++)if(list[i].key==k)return list[i];return null}
function ptRows(n){var loc=n.id=='local',inf=n.info||{},sv=loc&&S.psys?S.psys.services:(inf.services||[]),rows=[],ps=S.pset||{};
 var add=function(k,name,proto,port,svk){if(!port)return;var s=svcOf(sv,svk);rows.push({k:k,name:name,proto:proto,port:String(port),st:s?(s.active?'run':'stop'):'none'})};
 add('wg','WireGuard','UDP',inf.wg_port,'wireguard');add('awg','AmneziaWG','UDP',inf.awg_port,'amneziawg');add('hy2','Hysteria2','UDP',inf.hy2_port,'hysteria2');add('kmix','KANKI MIX','UDP',inf.kmix_port,'kankimix');
 if(loc){add('web',t('Panel (HTTPS)'),'TCP',ps.https_port||'443','web');add('panel',t('Panel (internal)'),'TCP',ps.web_port,'panel')}
 else{var m=String(n.address||'').match(/:(\d+)(\/|$)/);add('api',t('Node API (HTTPS)'),'TCP',m?m[1]:'443','web')}
 return rows}
function fwCmd(rows){var p=rows.filter(function(r){return r.k!='panel'}).map(function(r){return 'ufw allow '+r.port+'/'+r.proto.toLowerCase()}).filter(function(x,i,a){return a.indexOf(x)==i});return p.length?p.join(' && '):'—'}
// (3.41) the numbers first (TCP, UDP, running, clashes), then one table of the chosen server's ports
// (a card per port on a phone), the firewall command, and every server side by side
function ptDraw(){var el=$('#pt');if(!el)return;var ns=ptList();if(!ns.some(function(n){return n.id==PSEL}))PSEL=(ns[0]||{}).id||'local';
 var e=ns.filter(function(x){return x.id==PSEL})[0]||{id:'local',name:'',node:{id:'local',info:{}}},n=e.node||{id:e.id,name:e.name,info:{}},rows=ptRowsOf(e),loc=n.id=='local',ps=S.pset||{},host=loc?(ps.endpoint||ps.domain||''):(n.effective_endpoint||((e.node||{}).address||'').replace(/^https?:\/\//,'').replace(/[:\/].*$/,'')),cnt={};
 rows.forEach(function(r){cnt[r.proto+r.port]=(cnt[r.proto+r.port]||0)+1});
 var nT=rows.filter(function(r){return r.proto=='TCP'}).length,nU=rows.length-nT,nR=rows.filter(function(r){return r.st=='run'}).length,nC=rows.filter(function(r){return cnt[r.proto+r.port]>1}).length;
 el.innerHTML=kuStats([['TCP',N(nT)],['UDP',N(nU)],[t('Running'),N(nR)+' / '+N(rows.length),nR<rows.length?'y':'g'],[t('Conflicts'),N(nC),nC?'r':'']])+
  '<div class="psel kreg" role="group" aria-label="'+esc(t('Server'))+'">'+ns.map(function(x){return '<button type="button" class="'+(x.id==PSEL?'on':'')+'" aria-pressed="'+(x.id==PSEL)+'" data-ps="'+esc(x.id)+'"><span class="dot '+(x.online?'g':'r')+'"></span>'+esc(x.name)+(x.id=='local'?' <small>'+t('Main')+'</small>':x.loc=='iran'?' <small>'+t('Iran')+'</small>':'')+'</button>'}).join('')+'</div>'+
  '<section class="card"><div class="kc-h"><div><h3>'+esc(e.name||n.name||'')+'</h3>'+(!loc&&n.last_sync?'<small class="muted">'+t('Last contact')+': '+ago(n.last_sync)+'</small>':'')+'</div><button type="button" class="b2 sm" id="pt_chk">'+ic('check',15)+' '+t('Check now')+'</button></div>'+
  (rows.length?'<div class="ktbl-w"><table class="ktbl"><thead><tr><th>'+t('Service')+'</th><th>'+t('Protocol')+'</th><th>'+t('Port')+'</th><th>'+t('Address')+'</th><th>'+t('Status')+'</th></tr></thead><tbody>'+
   rows.map(function(r){var bad=cnt[r.proto+r.port]>1,sl=r.st=='run'?['g','Running']:r.st=='stop'?['r','Stopped']:['n','Unknown'],adr=r.k=='panel'?t('local only (127.0.0.1)'):(host||'?')+':'+r.port;
    return '<tr'+(bad?' class="bad"':'')+'><td class="ktbl-h"><b>'+esc(r.name)+'</b>'+(bad?'<small class="bad2">'+t('Port conflict: another service on this server uses the same port')+'</small>':'')+'</td>'+
     '<td data-l="'+esc(t('Protocol'))+'"><span class="pp '+r.proto.toLowerCase()+'">'+r.proto+'</span></td>'+
     '<td data-l="'+esc(t('Port'))+'"><button type="button" class="kcopy" data-cp="'+esc(r.port)+'" title="'+esc(t('Copy'))+'" aria-label="'+esc(t('Copy')+' '+r.port)+'"><b class="ltr">'+esc(r.port)+'</b>'+ic('copy',14)+'</button></td>'+
     '<td data-l="'+esc(t('Address'))+'"><span class="ltr kclip" title="'+esc(adr)+'">'+esc(adr)+'</span></td>'+
     '<td data-l="'+esc(t('Status'))+'"><span class="kpill '+sl[0]+'"><i class="dot '+sl[0]+'"></i><span>'+t(sl[1])+'</span></span></td></tr>'}).join('')+'</tbody></table></div>':
   '<p class="muted">'+t('No port information yet. Press Check now.')+'</p>')+'</section>'+
  '<section class="card"><div class="kc-h"><div><h3>'+t('Firewall')+'</h3><small class="muted">'+t('If a port is closed, run this on that server as root:')+'</small></div><button type="button" class="b2 sm" id="pt_fwc">'+ic('copy',15)+' '+t('Copy command')+'</button></div><pre class="cmd ltr">'+esc(fwCmd(rows))+'</pre></section>'+
  '<section class="card"><div class="kc-h"><h3>'+t('All servers')+'</h3></div><div class="ktbl-w"><table class="ktbl"><thead><tr><th>'+t('Server')+'</th><th>WireGuard</th><th>AmneziaWG</th><th>Hysteria2</th><th>KANKI MIX</th><th>'+t('Panel / API')+'</th></tr></thead><tbody>'+
   ns.map(function(x){var rr=ptRowsOf(x),g=function(k,l){var r=rr.filter(function(y){return y.k==k})[0];return '<td data-l="'+esc(l)+'">'+(r?'<span class="kpp"><i class="dot '+(r.st=='run'?'g':r.st=='stop'?'r':'n')+'"></i><b class="ltr">'+esc(r.port)+'</b></span>':'<span class="muted">—</span>')+'</td>'};
    return '<tr><td class="ktbl-h"><b>'+esc(x.name)+'</b>'+(x.node?'':'<small class="muted">'+N(rr.length)+' '+t('ports listening')+'</small>')+'</td>'+g('wg','WireGuard')+g('awg','AmneziaWG')+g('hy2','Hysteria2')+g('kmix','KANKI MIX')+(x.id=='local'?g('web',t('Panel / API')):g('api',t('Panel / API')))+'</tr>'}).join('')+'</tbody></table></div></section>';
 var e2=e;el.onclick=function(e){var b=e.target.closest('[data-ps]');if(b){PSEL=b.dataset.ps;ptDraw();return}var c=e.target.closest('[data-cp]');if(c){copy(c.dataset.cp);c.classList.add('done');setTimeout(function(){c.classList.remove('done')},1200);return}
  if(e.target.closest('#pt_fwc'))copy(fwCmd(rows));if(e.target.closest('#pt_chk')){if(e2.node)ptCheck(n);else ptLoad()}}}
function ptCheck(n){toast(t('Checking…'));if(n.id=='local'){api('GET','/api/system').then(function(s){S.psys=s;ptDraw();toast(t('Done'))}).catch(fail);return}
 api('POST','/api/nodes/'+encodeURIComponent(n.id)+'/health').then(function(r){if(r.services){n.info=n.info||{};n.info.services=r.services}toast(r.ok?t('Done'):t('Offline'),!r.ok);ptDraw()}).catch(fail)}

