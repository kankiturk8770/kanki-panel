// Kanki Panel 3.7: the new shell. Loaded after every other script, it changes the menu, the look and a
// few pages without touching how they work:
//  - a short, flat menu of sections; a section with several pages shows them as tabs at the top
//    (VPN services: overview, KANKI MIX, Xray, Kanki DNS, Anti-DPI · Tunnels: tunnels, servers, ports ·
//    Sales: bot, emergency chat · System: settings, backup, security)
//  - the glass look (cards, buttons, menu, tabs) in dark and light
//  - Servers: a grid of every server and the services it runs, with country flags
//  - Tunnel servers: Iran and abroad apart, with flags
//  - Smart channel: the Grok AI writer and the posting times
(function(){
'use strict';
var V37FA={
 "VPN services":"سرویس‌های VPN","Tunnels":"تانل‌ها","Sales & support":"فروش و پشتیبانی","System":"سیستم","Overview":"نمای کلی",
 "Kanki DNS":"DNS کانکی","Anti-DPI":"ضد DPI","Tunnel servers":"سرورهای تانل","Ports":"پورت‌ها","Sales bot":"ربات فروش","Emergency chat":"چت اضطراری",
 "Settings":"تنظیمات","Backup":"بکاپ","Security":"امنیت","Servers":"سرورها","Every server and what runs on it":"همه‌ی سرورها و سرویس‌هایی که رویشان است",
 "Server":"سرور","Tunnels count":"تانل","Repair":"تعمیر","Health":"سلامت","on":"روشن","off":"خاموش","not installed":"نصب نیست","inbounds":"اینباند",
 "exit":"خروجی","relay":"رله","Iran servers":"سرورهای ایران","Abroad servers":"سرورهای خارج","Press a service to open its settings":"روی هر سرویس بزن تا تنظیمات و تعمیرش باز شود",
 "AI writer (Grok)":"نویسنده‌ی هوش مصنوعی (Groq / Grok)","AI service":"سرویس هوش مصنوعی","Automatic (from the key)":"خودکار (از روی کلید)","Groq (groq.com, key gsk_…)":"Groq (groq.com، کلید gsk_…)","Grok (x.ai, key xai-…)":"Grok (x.ai، کلید xai-…)","Now":"الان","Empty model = the best one of that service; a refused model is replaced by another one of your account.":"مدل خالی = بهترین مدل همان سرویس؛ اگر مدلی قبول نشود، مدل دیگری از حساب خودت امتحان می‌شود.",
 "Posts are written by Grok from your real plans, prices and codes, in the tone you describe. When Grok does not answer (it is tried again, and another model is tried), the built-in writer posts instead.":"پست‌ها را هوش مصنوعی (Groq یا Grok) از روی پلن‌ها، قیمت‌ها و کدهای واقعی‌ات با لحنی که می‌نویسی می‌نویسد. اگر جواب ندهد (چند بار دوباره امتحان می‌شود و مدل دیگری هم امتحان می‌شود)، نویسنده‌ی داخلی پست را می‌گذارد.",
 "API key":"کلید API","saved":"ذخیره شده","Paste a new key to replace it":"برای عوض کردن، کلید جدید را بچسبان","Model":"مدل",
 "About us and how to write":"درباره‌ی ما و لحن نوشتن","Who you are, what to stress, the tone, words to avoid…":"چه کسی هستید، روی چه چیزی تأکید شود، لحن، کلماتی که نباید بیاید…",
 "Posting times (Iran time)":"ساعت‌های انتشار (به وقت ایران)","Empty = every N hours as above. Three times a day: 10:00, 16:00, 21:30":"خالی = هر چند ساعت یک‌بار (بالا). سه بار در روز: ۱۰:۰۰، ۱۶:۰۰، ۲۱:۳۰",
 "Test the key":"تست کلید","Remove the key":"حذف کلید","Grok works":"هوش مصنوعی کار می‌کند","Last answer":"آخرین جواب","Use 3 times a day":"سه بار در روز",
 "Written by Grok":"نوشته‌ی Grok","Written by the built-in writer":"نوشته‌ی نویسنده‌ی داخلی",
 "Fast, for games and calls":"سریع، برای بازی و تماس","Steady, works almost everywhere":"پایدار، تقریباً همه‌جا","For strong filtering":"برای فیلترینگ شدید",
 "Over UDP (fast, games)":"روی UDP (سریع، بازی)","Over TCP (steady)":"روی TCP (پایدار)","Advanced (hardest to block)":"پیشرفته (سخت‌ترین برای بستن)"
};
function fa(){if(typeof FA!='undefined')Object.assign(FA,V37FA)}
fa();

// ---------------------------------------------------------------- sections and menu
// [section key, label, icon, [[page, sub page, tab label], ...]]
var SECS=[
 ['dash','Dashboard','dash',[['dash','','Dashboard']]],
 ['users','Users','users',[['users','','Users']]],
 ['nodes','Servers','nodes',[['nodes','','Servers']]],
 ['vpnsec','VPN services','shield2',[['vpn','','Overview'],['kmix','','KANKI MIX'],['xray','','Xray'],['dns','','Kanki DNS'],['antidpi','','Anti-DPI']]],
 ['netsec','Tunnels','tunnel',[['tunnels','','Tunnels'],['servers','','Tunnel servers'],['ports','','Ports']]],
 ['salesec','Sales & support','bot',[['bot','','Sales bot'],['emergency','','Emergency chat']]],
 ['traffic','Traffic & stats','traffic',[['traffic','','Traffic & stats']]],
 ['syssec','System','settings',[['settings','','Settings'],['backup','','Backup'],['security','','Security']]]];
function secOf(p){for(var i=0;i<SECS.length;i++)if(SECS[i][3].some(function(x){return x[0]==p}))return SECS[i];return SECS[0]}
window.V37={secOf:secOf,SECS:SECS};

// the old menu groups become plain links to the first page of each section
window.NAV=SECS.map(function(s){return {p:s[3][0][0],sec:s[0]}});
window.grpOf=function(p){var s=secOf(p);return s[3].length>1?s[1]:''};
window.navSide=function(){return SECS.map(function(s){var first=s[3][0];
 return '<a href="#'+first[0]+'" data-p="'+first[0]+'" data-sec="'+s[0]+'"><span class="ni">'+ic(s[2],18)+'</span>'+t(s[1])+(s[3].length>1?'<em class="nsc">'+N(s[3].length)+'</em>':'')+'</a>'}).join('')};
window.navBar=function(){return '<div class="mbar" id="mbar">'+SECS.map(function(s){var first=s[3][0];
 return '<a href="#'+first[0]+'" data-p="'+first[0]+'" data-sec="'+s[0]+'">'+ic(s[2],17)+'<span>'+t(s[1])+'</span></a>'}).join('')+'</div><div class="msheet" id="msheet"></div>'};
window.navMark=function(p,sub){var sk=secOf(p)[0];
 $$('#side a[data-sec]').forEach(function(a){a.classList.toggle('on',a.dataset.sec==sk)});
 $$('#mbar a[data-sec]').forEach(function(a){a.classList.toggle('on',a.dataset.sec==sk)});
 var cur=$('#mbar .on'),bar=$('#mbar');if(cur&&bar&&bar.scrollWidth>bar.clientWidth)try{cur.scrollIntoView({block:'nearest',inline:'center'})}catch(e){}
 drawSecTabs(p)};
window.navSheet=function(){};

// the tabs of the section, always the first thing of the page
function secTabsHtml(p){var s=secOf(p);if(s[3].length<2)return '';
 return '<div class="sectabs" id="sectabs"><div class="sth2"><span class="sti">'+ic(s[2],18)+'</span><b>'+t(s[1])+'</b></div><div class="stl">'+
  s[3].map(function(x){return '<a href="#'+x[0]+(x[1]?'/'+x[1]:'')+'" class="'+(x[0]==p?'on':'')+'">'+t(x[2])+'</a>'}).join('')+'</div></div>'}
function drawSecTabs(p){var pg=$('#pg');if(!pg)return;var old=$('#sectabs'),h=secTabsHtml(p);
 if(!h){if(old)old.remove();return}
 if(old&&old.parentNode==pg&&pg.firstChild==old&&old.dataset.p==p)return;
 if(old)old.remove();var d=document.createElement('div');d.innerHTML=h;var el=d.firstChild;el.dataset.p=p;pg.insertBefore(el,pg.firstChild)}
// a page that redraws itself (innerHTML) loses the tabs: put them back
var mo=null;
function watchPg(){var pg=$('#pg');if(!pg||pg._v37)return;pg._v37=1;if(mo)mo.disconnect();
 mo=new MutationObserver(function(){if(S&&S.page&&secOf(S.page)[3].length>1&&(!$('#sectabs')||pg.firstChild!=$('#sectabs')))drawSecTabs(S.page)});
 mo.observe(pg,{childList:true})}
var _shell=window.shell;
window.shell=function(){_shell.apply(this,arguments);document.body.classList.add('v37');watchPg()};
var _route=window.route;
window.route=function(){_route.apply(this,arguments);watchPg();drawSecTabs(S.page);fa()};

// ---------------------------------------------------------------- flags
function flag(cc){cc=String(cc||'').toUpperCase();if(!/^[A-Z]{2}$/.test(cc))return '<span class="flg nf" title="?">🌐</span>';
 return '<span class="flg" title="'+cc+'">'+String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65,0x1F1E6+cc.charCodeAt(1)-65)+'</span>'}
window.flagOf=flag;

// tunnel servers: the flag of each one (Iran and abroad are already apart)
if(window.tunSrvCard){var _tsc=window.tunSrvCard;window.tunSrvCard=function(s){var h=_tsc(s);return h.replace('<div><b>','<div><b>'+flag(s.cc)+' ')}}

// ---------------------------------------------------------------- Servers: the grid of every server
function svcCell(on,label,sub,act,cls){return '<button type="button" class="svc '+(cls||(on?'ok':'no'))+'" '+(act?'onclick="'+act+'"':'disabled')+'><b>'+label+'</b><small>'+sub+'</small></button>'}
function nodeGrid(){var el=$('#v37grid');if(!el)return;var ns=S.nodes||[],xr=(window.XR&&XR.d)||null,dn=(window.DN&&DN.d)||null,tn=(window.TN&&TN.d)||null;
 var rows=[];
 ns.forEach(function(n){var i=n.info||{},sv={};(i.services||[]).forEach(function(s){sv[s.key]=s});
  var st=function(key,port){var s=sv[key];if(!port&&!s)return null;return {on:!!(s?s.active:port),port:port}};
  rows.push({id:n.id,name:n.name,cc:n.cc,kind:'node',online:n.id=='local'||n.online,
   wg:st('wireguard',i.wg_port),awg:st('amneziawg',i.awg_port),hy2:st('hysteria2',i.hy2_port),kmix:i.kmix_port?{on:i.kmix_active!==false,port:i.kmix_port}:null})});
 // agent servers (Iran / abroad) that run Xray, Kanki DNS or tunnels
 var tsv=(tn&&tn.servers)||[];
 tsv.forEach(function(s){var r=rows.filter(function(x){return x.id==s.id})[0];if(!r){r={id:s.id,name:s.name,cc:s.cc,kind:'agent',online:s.online,loc:s.loc};rows.push(r)}else{r.cc=r.cc||s.cc;r.loc=s.loc}
  r.tun=((tn&&tn.tunnels)||[]).filter(function(x){return x.entry==s.id||x.exit==s.id}).length});
 if(xr)(xr.servers||[]).forEach(function(x){var r=rows.filter(function(y){return y.id==x.server})[0];if(!r)return;var ib=(xr.inbounds||[]).filter(function(i){return i.server==x.server});r.xray={n:ib.length,on:!!(x.status&&x.status.active)}});
 if(dn)(dn.servers||[]).forEach(function(x){var r=rows.filter(function(y){return y.id==x.server})[0];if(!r)return;r.dns={role:x.role,on:!!(x.status&&x.status.active)}});
 var vpnRow=function(r,k,label){var v=r[k];var act=r.kind=='node'?(k=='kmix'?"location.hash='#kmix'":"v37NodeMenu('"+esc(r.id)+"')"):'';
  return v?svcCell(v.on,label,v.port?'UDP '+N(v.port):t(v.on?'on':'off'),act,v.on?'ok':'bad'):svcCell(false,label,r.kind=='node'?t('not installed'):'—','', 'no')};
 var head='<div class="sgh"><span>'+t('Server')+'</span><span>WireGuard</span><span>AmneziaWG</span><span>Hysteria2</span><span>KANKI MIX</span><span>Xray</span><span>DNS</span><span>'+t('Tunnels')+'</span></div>';
 var body=rows.map(function(r){
  return '<div class="sgr"><div class="sgn"><span class="dot '+(r.online?'g':'r')+'"></span>'+flag(r.cc)+'<b>'+esc(r.name)+'</b><small>'+(r.id=='local'?t('Main'):r.kind=='node'?'VPN':(r.loc=='iran'?'IR':'')) +'</small></div>'+
   vpnRow(r,'wg','WireGuard')+vpnRow(r,'awg','AmneziaWG')+vpnRow(r,'hy2','Hysteria2')+vpnRow(r,'kmix','KANKI MIX')+
   (r.xray?svcCell(r.xray.on,'Xray',N(r.xray.n)+' '+t('inbounds'),"location.hash='#xray'",r.xray.on?'ok':'bad'):svcCell(false,'Xray','—','','no'))+
   (r.dns?svcCell(r.dns.on,'DNS',t(r.dns.role=='relay'?'relay':'exit'),"location.hash='#dns/servers'",r.dns.on?'ok':'bad'):svcCell(false,'DNS','—','','no'))+
   (r.tun!=null?svcCell(r.tun>0,t('Tunnels'),N(r.tun),"location.hash='#tunnels'",r.tun>0?'ok':'no'):svcCell(false,t('Tunnels'),'—','','no'))+'</div>'}).join('');
 el.innerHTML='<div class="nh"><div><h3>'+ic('nodes',16)+' '+t('Every server and what runs on it')+'</h3><p class="sub" style="margin:0">'+t('Press a service to open its settings')+'</p></div></div><div class="sgw"><div class="sgrid">'+head+body+'</div></div>'}
// the actions of one VPN server, from the grid
window.v37NodeMenu=function(id){var n=(S.nodes||[]).filter(function(x){return x.id==id})[0];if(!n)return;var i=n.info||{},e=esc(id);
 modal(mhead(n.name,flag(n.cc))+
  '<div class="list">'+[['WireGuard',i.wg_port],['AmneziaWG',i.awg_port],['Hysteria2',i.hy2_port],['KANKI MIX',i.kmix_port]].map(function(x){return '<div class="li"><span>'+x[0]+'</span><span class="ltr">'+(x[1]?'UDP '+esc(String(x[1])):'—')+'</span></div>'}).join('')+'</div>'+
  '<div class="g2" style="margin-top:12px"><button class="btn" onclick="closeModal();nAct(\''+e+'\',\'repair\')">↻ '+t('Repair')+'</button><button class="b2" onclick="closeModal();nHealth(\''+e+'\')">♡ '+t('Health')+'</button>'+
  '<button class="b2" onclick="closeModal();nAct(\''+e+'\',\'sync\')">⇄ '+t('Sync')+'</button>'+(window.nodePorts?'<button class="b2" onclick="closeModal();nodePorts(\''+e+'\')">'+ic('ports',15)+' '+t('Ports')+'</button>':'<a class="b2" href="#ports" onclick="closeModal()">'+ic('ports',15)+' '+t('Ports')+'</a>')+'</div>')};
if(window.pNodes){var _pn=window.pNodes;window.pNodes=function(){_pn.apply(this,arguments);var ph=$('#pg .ph');if(ph&&!$('#v37grid')){var c=document.createElement('div');c.className='card v37grid';c.id='v37grid';c.innerHTML=t('Loading…');ph.parentNode.insertBefore(c,ph.nextSibling)}}}
if(window.loadNodes){var _ln=window.loadNodes;window.loadNodes=function(){_ln.apply(this,arguments);
 api('GET','/api/tunnels').then(function(d){if(window.TN)TN.d=d;else window.TN={d:d};nodeGrid()}).catch(function(){nodeGrid()});setTimeout(nodeGrid,900)}}
if(window.drawNodes){var _dn=window.drawNodes;window.drawNodes=function(){_dn.apply(this,arguments);
 // a flag in front of each server's name
 var cards=$$('#nl .nodec');(S.nodes||[]).forEach(function(n,i){var b=cards[i]&&cards[i].querySelector('.nnm b');if(b&&!b.querySelector('.flg'))b.insertAdjacentHTML('afterbegin',flag(n.cc)+' ')});nodeGrid()}}

// ---------------------------------------------------------------- tunnel form: live port check
// what the servers themselves say is listening, shown while the ports are typed
var PC={};
function portsOf(sid){var c=PC[sid];if(c&&Date.now()-c.at<8000)return Promise.resolve(c.v);
 return api('GET','/api/tunnels/servers/'+encodeURIComponent(sid)+'/ports').then(function(v){PC[sid]={at:Date.now(),v:v};return v}).catch(function(){return {known:false,used:[]}})}
function nums(v){var o=[];String(v||'').split(/[\s,]+/).forEach(function(x){var a=x.split(':')[0];var r=a.split('-');if(r.length==2){for(var i=+r[0];i<=+r[1]&&i-+r[0]<2000;i++)o.push(i)}else if(+a>0)o.push(+a)});return o}
function liveCheck(id){var en=$('#tw_en'),ex=$('#tw_ex');if(!en||!ex)return;var box=$('#v37pc');if(!box){box=document.createElement('div');box.id='v37pc';var ph=$('#tw_ph');if(!ph)return;ph.parentNode.insertBefore(box,ph.nextSibling)}
 var mode=($('#tw_md button.on')||{dataset:{v:'reverse'}}).dataset.v,trb=$('#tw_tr button.on'),tr=trb?trb.dataset.v:'tcpmux',listener=mode=='direct'?ex.value:en.value;
 var udp=['quic','kcp','hq','game'].indexOf(tr)>=0,both=tr=='dual',port=+(($('#tw_pt')||{}).value||0);
 var old=id?((TN.d&&TN.d.tunnels)||[]).filter(function(x){return x.id==id})[0]:null;
 var mine=function(sid,p,u){if(!old||!old.enabled)return false;var ol=old.mode=='direct'?old.exit:old.entry;var ou=['quic','kcp','hq','game','dual'].indexOf(old.transport)>=0,ot=['quic','kcp','hq','game'].indexOf(old.transport)<0;
  return (sid==ol&&p==old.port&&(u?ou:ot))||(sid==old.entry&&nums((u?old.udp:old.tcp)||[]).indexOf(p)>=0)};
 var need=[];if(port){if(!udp||both)need.push([listener,port,false]);if(udp||both)need.push([listener,port,true])}
 nums(($('#tw_tcp')||{}).value).forEach(function(p){need.push([en.value,p,false])});nums(($('#tw_udp')||{}).value).forEach(function(p){need.push([en.value,p,true])});
 var sids=need.map(function(x){return x[0]}).filter(function(v,i,a){return v&&a.indexOf(v)==i});
 Promise.all(sids.map(function(sid){return portsOf(sid).then(function(v){return [sid,v]})})).then(function(rs){var msg=[],unknown=[];
  rs.forEach(function(r){var sid=r[0],v=r[1];if(!v.known){unknown.push(sid);return}
   need.filter(function(n){return n[0]==sid}).forEach(function(n){var hit=(v.used||[]).filter(function(u){return u.port==n[1]&&(u.proto=='udp')==n[2]})[0];
    if(hit&&!(hit.kanki&&mine(sid,n[1],n[2])))msg.push((n[2]?'UDP ':'TCP ')+n[1]+' · '+(tunSrv(sid).name||sid)+': '+t('taken by')+' '+hit.by)})});
  box.className=msg.length?'warnbox':'';box.innerHTML=msg.length?'<b>⚠ '+t('These ports are already taken on the server')+'</b><br>'+msg.map(esc).join('<br>'):(unknown.length?'<small class="muted">'+t('The server has not said which ports are free yet (update it to 3.7)')+'</small>':(need.length?'<small class="okt">✓ '+t('The ports are free on the servers')+'</small>':''))})}
if(window.tunEdit){var _te=window.tunEdit;window.tunEdit=function(id,pre){var r=_te.apply(this,arguments);
 setTimeout(function(){if(!$('#tw_pt'))return;var tm;var go=function(){clearTimeout(tm);tm=setTimeout(function(){liveCheck(id)},350)};
  ['#tw_pt','#tw_tcp','#tw_udp'].forEach(function(s){var e=$(s);if(e)e.addEventListener('input',go)});['#tw_en','#tw_ex'].forEach(function(s){var e=$(s);if(e)e.addEventListener('change',go)});
  ['#tw_tr','#tw_md'].forEach(function(s){var e=$(s);if(e)e.addEventListener('click',go)});setTimeout(go,600)},300);return r}}
Object.assign(V37FA,{"A Groq key starts with gsk_ (console.groq.com/keys), a Grok key with xai- (console.x.ai). Save this one anyway?":"کلید Groq با gsk_ شروع می‌شود (console.groq.com/keys) و کلید Grok با xai- (console.x.ai). همین را ذخیره کنم؟","taken by":"گرفته شده توسط","These ports are already taken on the server":"این پورت‌ها روی سرور گرفته شده‌اند","The server has not said which ports are free yet (update it to 3.7)":"سرور هنوز نگفته کدام پورت‌ها آزادند (آن را به ۳.۷ آپدیت کن)","The ports are free on the servers":"پورت‌ها روی سرورها آزادند"});fa();

// ---------------------------------------------------------------- smart channel: the Grok writer
function aiCard(c){var st=String(c.ai_status||''),ok=st.indexOf('ok:')==0;
 return '<div class="card" id="v37ai"><div class="nh"><div><h3>🤖 '+t('AI writer (Grok)')+'</h3><p class="sub">'+t('Posts are written by Grok from your real plans, prices and codes, in the tone you describe. When Grok does not answer (it is tried again, and another model is tried), the built-in writer posts instead.')+'</p></div>'+
  '<label class="sw"><input type="checkbox" id="ai_on" '+(c.ai_on?'checked':'')+'><span></span></label></div>'+
  '<div class="g2f"><div><label class="f">'+t('API key')+(c.ai_has_key?' · <span class="okt">'+t('saved')+' <span class="ltr">'+esc(c.ai_key_hint||'')+'</span></span>':'')+'</label><input id="ai_key" class="ltr aikey" type="text" name="kk-grok-api" autocomplete="off" autocapitalize="off" spellcheck="false" data-lpignore="true" data-1p-ignore placeholder="'+esc(c.ai_has_key?t('Paste a new key to replace it'):'gsk_… / xai-…')+'"></div>'+
  '<div><label class="f">'+t('Model')+'</label><input id="ai_model" class="ltr" value="'+esc(c.ai_model||'')+'" placeholder="openai/gpt-oss-120b"></div></div>'+
  '<label class="f">'+t('AI service')+'</label><select id="ai_pv">'+[['','Automatic (from the key)'],['groq','Groq (groq.com, key gsk_…)'],['xai','Grok (x.ai, key xai-…)']].map(function(o){return '<option value="'+o[0]+'"'+((c.ai_provider||'')==o[0]?' selected':'')+'>'+t(o[1])+'</option>'}).join('')+'</select>'+
  '<small class="muted">'+t('Now')+': <b class="ltr">'+esc(c.ai_provider_used=='xai'?'Grok · api.x.ai/v1':'Groq · api.groq.com/openai/v1')+'</b> · '+t('Empty model = the best one of that service; a refused model is replaced by another one of your account.')+'</small>'+
  '<label class="f">'+t('About us and how to write')+'</label><textarea id="ai_brief" rows="4" placeholder="'+esc(t('Who you are, what to stress, the tone, words to avoid…'))+'">'+esc(c.ai_brief||'')+'</textarea>'+
  '<label class="f">'+t('Posting times (Iran time)')+'</label><div class="inl"><input id="ch_times" class="ltr" value="'+esc(c.times||'')+'" placeholder="10:00, 16:00, 21:30"><button type="button" class="b2" id="ai_3x" style="flex:none">'+t('Use 3 times a day')+'</button></div><small class="muted">'+t('Empty = every N hours as above. Three times a day: 10:00, 16:00, 21:30')+'</small>'+
  (st?'<p class="'+(ok?'okt':'r')+'" style="font-size:12px;margin:8px 0 0">'+t('Last answer')+': <span class="ltr">'+esc(ok?st.slice(3):st)+'</span></p>':'')+
  '<div class="g3" style="margin-top:12px"><button class="btn" id="ai_save">'+t('Save')+'</button><button class="b2" id="ai_test">⚡ '+t('Test the key')+'</button>'+(c.ai_has_key?'<button class="b2 bd" id="ai_rm">'+t('Remove the key')+'</button>':'<span></span>')+'</div>'+
  '<div id="ai_out" class="chpv" style="display:none;margin-top:10px"></div></div>'}
function aiWire(){var g=function(id){return $('#'+id)};
 g('ai_3x').onclick=function(){g('ch_times').value='10:00, 16:00, 21:30'};
 var keyOk=function(){var k=g('ai_key').value.trim();if(k&&!/^(gsk_|xai-)/.test(k)&&!confirm(t('A Groq key starts with gsk_ (console.groq.com/keys), a Grok key with xai- (console.x.ai). Save this one anyway?')))return false;return true};
 g('ai_save').onclick=function(){if(!keyOk())return;var b=this;b.disabled=true;api('PUT','/api/channel',{ai_on:g('ai_on').checked,ai_key:g('ai_key').value.trim(),ai_provider:g('ai_pv').value,ai_model:g('ai_model').value.trim(),ai_brief:g('ai_brief').value,times:g('ch_times').value.trim()})
  .then(function(){toast(t('Saved'));botChan()}).catch(function(e){b.disabled=false;fail(e)})};
 g('ai_test').onclick=function(){if(!keyOk())return;var b=this,o=g('ai_out');b.disabled=true;o.style.display='';o.innerHTML='<span class="muted">…</span>';
  var save=api('PUT','/api/channel',{ai_key:g('ai_key').value.trim(),ai_provider:g('ai_pv').value,ai_model:g('ai_model').value.trim()});
  save.then(function(){return api('POST','/api/channel/ai-test')}).then(function(r){o.innerHTML='<b class="okt">✓ '+t('Grok works')+' · <span class="ltr">'+esc(r.model)+'</span></b><br><br>'+String(r.text||'').replace(/\n/g,'<br>');b.disabled=false})
   .catch(function(e){o.innerHTML='<span class="r">'+esc(e.message||'')+'</span>';b.disabled=false})};
 var rm=g('ai_rm');if(rm)rm.onclick=function(){if(!confirm(t('Remove the key')+'?'))return;api('PUT','/api/channel',{ai_key:'-',ai_on:false}).then(function(){toast(t('Done'));botChan()}).catch(fail)}}
if(window.botChan){var _bc=window.botChan;window.botChan=function(){_bc.apply(this,arguments);var tries=0;
 var wait=setInterval(function(){tries++;var el=$('#bt_chan');if(!el||tries>40){clearInterval(wait);return}
  if($('#ch_save')&&!$('#v37ai')){clearInterval(wait);api('GET','/api/channel').then(function(c){if($('#v37ai'))return;var first=el.querySelector('.card');var d=document.createElement('div');d.innerHTML=aiCard(c);
   if(first&&first.nextSibling)el.insertBefore(d.firstChild,first.nextSibling);else el.appendChild(d.firstChild);aiWire()}).catch(function(){})}},150)}}

// ---------------------------------------------------------------- Backup: move the whole panel to a new server
Object.assign(V37FA,{"Move the panel to a new server":"انتقال کامل پنل به سرور جدید",
 "Everything moves: users, servers, tunnels, DNS, Xray, bot and plans, the panel settings, the keys of this server's WireGuard / AmneziaWG / Hysteria2 (users' configs keep working), the certificate and the app files.":"همه‌چیز منتقل می‌شود: کاربرها، سرورها، تانل‌ها، DNS، Xray، ربات و پلن‌ها، تنظیمات پنل، کلیدهای WireGuard / AmneziaWG / Hysteria2 همین سرور (کانفیگ کاربرها کار می‌کند)، گواهی و فایل‌های اپ.",
 "Point the panel's domain to the new server's IP":"دامنه‌ی پنل را روی آی‌پی سرور جدید بگذار","In your DNS (Cloudflare / ArvanCloud): the A record of":"در DNS دامنه (کلادفلر / ابرآروان): رکورد A دامنه‌ی",
 "= the IP of the new server, without CDN (DNS only). The old panel keeps working by its IP until the move is done.":"= آی‌پی سرور جدید، بدون CDN (فقط DNS). پنل قدیمی تا پایان انتقال با آی‌پی خودش کار می‌کند.",
 "Make the move command":"ساخت دستور انتقال","Run this on the new server (Ubuntu / Debian, as root)":"این را روی سرور جدید اجرا کن (اوبونتو / دبیان، با root)",
 "It downloads everything straight from this server, puts it back with the same keys and starts the panel there. Then this panel stops by itself.":"همه‌چیز را مستقیم از همین سرور می‌گیرد، با همان کلیدها برمی‌گرداند و پنل را آن‌جا روشن می‌کند. بعد این پنل خودش خاموش می‌شود.",
 "This server's IP (empty = found by itself)":"آی‌پی همین سرور (خالی = خودکار)","Valid for 3 hours, one time. It holds the key of the backup: do not share it.":"۳ ساعت و یک‌بار اعتبار دارد. کلید بکاپ داخلش است: به کسی نده.",
 "Waiting for the new server…":"منتظر سرور جدید…","The new server downloaded the backup":"سرور جدید بکاپ را گرفت","Moved: the panel runs on the new server. This one is stopping.":"انتقال تمام شد: پنل روی سرور جدید اجرا می‌شود و این یکی خاموش می‌شود.",
 "Cancel the command":"لغو دستور","Copy the command":"کپی دستور","The backup above is complete too: it can also be restored by hand on a new server (Restore with «Also restore server keys»).":"بکاپ بالا هم کامل است: می‌شود آن را دستی هم روی سرور جدید برگرداند (بازگردانی با تیک «کلیدها و تنظیمات سرور»)."});fa();
function moveCard(){return '<div class="card" id="v37move"><h3>🚚 '+t('Move the panel to a new server')+'</h3><p class="sub">'+t("Everything moves: users, servers, tunnels, DNS, Xray, bot and plans, the panel settings, the keys of this server's WireGuard / AmneziaWG / Hysteria2 (users' configs keep working), the certificate and the app files.")+'</p><div id="mv_in">'+t('Loading…')+'</div></div>'}
function moveDraw(m){var el=$('#mv_in');if(!el)return;
 var steps='<ol class="steps" style="margin:6px 0 10px;line-height:2"><li><b>'+t("Point the panel's domain to the new server's IP")+'</b><br><small class="muted">'+t('In your DNS (Cloudflare / ArvanCloud): the A record of')+' <span class="ltr">'+esc(m.domain||'')+'</span> '+t('= the IP of the new server, without CDN (DNS only). The old panel keeps working by its IP until the move is done.')+'</small></li>'+
  '<li><b>'+t('Run this on the new server (Ubuntu / Debian, as root)')+'</b><br><small class="muted">'+t('It downloads everything straight from this server, puts it back with the same keys and starts the panel there. Then this panel stops by itself.')+'</small></li></ol>';
 if(m.done>0){el.innerHTML='<div class="okbox" style="padding:10px;border-radius:12px;border:1px solid var(--ok)">✓ '+t('Moved: the panel runs on the new server. This one is stopping.')+'</div>';return}
 if(!m.active){el.innerHTML=steps+'<label class="f">'+t("This server's IP (empty = found by itself)")+'</label><div class="inl"><input id="mv_ip" class="ltr" value="'+esc(m.ip||'')+'" placeholder="1.2.3.4"><button class="btn" id="mv_go" style="flex:none">'+t('Make the move command')+'</button></div>'+
   '<p class="hint">'+t('The backup above is complete too: it can also be restored by hand on a new server (Restore with «Also restore server keys»).')+'</p>';
  $('#mv_go').onclick=function(){var b=this;b.disabled=true;api('POST','/api/migrate/start',{ip:$('#mv_ip').value.trim()}).then(moveLoad).catch(function(e){b.disabled=false;fail(e)})};return}
 el.innerHTML=steps+'<pre class="ltr" id="mv_cmd" style="white-space:pre-wrap;word-break:break-all;font-size:11.5px;padding:10px;border-radius:12px;background:var(--in);border:1px solid var(--gb2);margin:0">'+esc(m.command)+'</pre>'+
  '<p class="hint">'+t('Valid for 3 hours, one time. It holds the key of the backup: do not share it.')+'</p>'+
  '<p style="margin:6px 0">'+(m.fetched>0?'<span class="okt">✓ '+t('The new server downloaded the backup')+(m.new_ip?' (<span class="ltr">'+esc(m.new_ip)+'</span>)':'')+'</span>':'<span class="muted">⏳ '+t('Waiting for the new server…')+'</span>')+'</p>'+
  '<div class="g2"><button class="btn" id="mv_cp">'+t('Copy the command')+'</button><button class="b2 bd" id="mv_x">'+t('Cancel the command')+'</button></div>';
 $('#mv_cp').onclick=function(){copy(m.command)};$('#mv_x').onclick=function(){api('DELETE','/api/migrate').then(moveLoad).catch(fail)}}
function moveLoad(){return api('GET','/api/migrate').then(moveDraw).catch(function(e){var el=$('#mv_in');if(el)el.textContent=e.message||''})}
if(window.pBackup){var _pb=window.pBackup;window.pBackup=function(){_pb.apply(this,arguments);var g=$('#pg .g2');if(g&&!$('#v37move')){var d=document.createElement('div');d.innerHTML=moveCard();g.parentNode.insertBefore(d.firstChild,g.nextSibling)}
 moveLoad();clearInterval(S.timer4);S.timer4=setInterval(function(){if(S.page=='backup'&&$('#v37move')&&!$('#modal').classList.contains('on'))moveLoad()},5000)}}

// ---------------------------------------------------------------- the look
var css=`
body.v37{--g1:rgba(255,255,255,.055);--g2:rgba(255,255,255,.018);--gb:rgba(255,255,255,.085);--gb2:rgba(255,255,255,.14);--gl:inset 0 1px 0 rgba(255,255,255,.07);--blur:saturate(150%) blur(18px)}
body.v37.light{--g1:rgba(255,255,255,.82);--g2:rgba(255,255,255,.55);--gb:rgba(120,90,30,.14);--gb2:rgba(120,90,30,.24);--gl:inset 0 1px 0 rgba(255,255,255,.9)}
body.v37:before{background:radial-gradient(1100px 620px at 105% -10%,color-mix(in srgb,var(--a) 16%,transparent),transparent 65%),radial-gradient(900px 600px at -10% 110%,color-mix(in srgb,var(--info) 9%,transparent),transparent 65%),radial-gradient(700px 500px at 50% 120%,color-mix(in srgb,var(--a) 7%,transparent),transparent 70%)!important}
/* glass surfaces */
body.v37 .card,body.v37 .kv>div,body.v37 .ibc,body.v37 .secc{background:linear-gradient(160deg,var(--g1),var(--g2)),color-mix(in srgb,var(--c2) 70%,transparent)!important;border:1px solid var(--gb)!important;box-shadow:var(--gl),0 18px 44px -26px rgba(0,0,0,.8)!important;border-radius:20px}
body.v37.light .card,body.v37.light .kv>div,body.v37.light .ibc,body.v37.light .secc{box-shadow:var(--gl),0 14px 34px -22px rgba(90,60,10,.35)!important}
body.v37 header.top{background:color-mix(in srgb,var(--bg1) 62%,transparent)!important;backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border-bottom:1px solid var(--gb)!important}
body.v37 nav.side{background:linear-gradient(180deg,color-mix(in srgb,var(--c1) 82%,transparent),color-mix(in srgb,var(--c2) 88%,transparent))!important;backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border-inline-end:1px solid var(--gb)!important}
body.v37 .mbox{background:linear-gradient(160deg,var(--g1),var(--g2)),color-mix(in srgb,var(--c2) 92%,transparent)!important;backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--gb2)!important;border-radius:22px!important}
/* buttons: gold glass and frosted glass */
body.v37 .btn{position:relative;overflow:hidden;border-radius:14px!important;background:linear-gradient(135deg,var(--al) 0%,var(--a) 42%,var(--ad) 100%)!important;color:#1a1206!important;border:1px solid color-mix(in srgb,var(--al) 60%,transparent)!important;
 box-shadow:inset 0 1px 0 rgba(255,255,255,.6),inset 0 -2px 6px rgba(120,80,10,.35),0 10px 24px -10px color-mix(in srgb,var(--a) 85%,transparent)!important;transition:transform .12s,box-shadow .2s,filter .2s}
body.v37 .btn:before{content:"";position:absolute;inset:0 0 50% 0;background:linear-gradient(180deg,rgba(255,255,255,.45),rgba(255,255,255,0));pointer-events:none;border-radius:inherit}
body.v37 .btn:after{content:"";position:absolute;top:-50%;bottom:-50%;width:40%;left:-60%;background:linear-gradient(100deg,transparent,rgba(255,255,255,.55),transparent);transform:skewX(-20deg);transition:left .6s;pointer-events:none}
body.v37 .btn:hover:not(:disabled):after{left:130%}
body.v37 .btn:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.05)}
body.v37 .btn:active:not(:disabled){transform:translateY(0) scale(.98)}
body.v37 .b2,body.v37 .ib,body.v37 .sb{background:linear-gradient(180deg,rgba(255,255,255,.10),rgba(255,255,255,.025))!important;border:1px solid var(--gb2)!important;border-radius:13px!important;
 box-shadow:inset 0 1px 0 rgba(255,255,255,.12),0 6px 16px -10px rgba(0,0,0,.7)!important;backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);transition:transform .12s,border-color .15s,background .15s}
body.v37.light .b2,body.v37.light .ib,body.v37.light .sb{background:linear-gradient(180deg,rgba(255,255,255,.95),rgba(255,255,255,.6))!important;box-shadow:inset 0 1px 0 #fff,0 4px 12px -8px rgba(90,60,10,.4)!important}
body.v37 .b2:hover:not(:disabled),body.v37 .ib:hover{border-color:color-mix(in srgb,var(--a) 65%,transparent)!important;transform:translateY(-1px)}
body.v37 .b2.bd{color:var(--bad)}body.v37 .b2.bd:hover{border-color:color-mix(in srgb,var(--bad) 60%,transparent)!important;background:color-mix(in srgb,var(--bad) 10%,transparent)!important}
body.v37 input,body.v37 select,body.v37 textarea{background:color-mix(in srgb,var(--bg1) 45%,transparent)!important;border:1px solid var(--gb2)!important;border-radius:13px!important}
body.v37.light input,body.v37.light select,body.v37.light textarea{background:rgba(255,255,255,.75)!important}
/* menu */
body.v37 nav.side a{border-radius:13px}
body.v37 nav.side a .nsc{margin-inline-start:auto;font-style:normal;font-size:10.5px;font-weight:800;padding:1px 7px;border-radius:9px;background:var(--in);color:var(--s)}
body.v37 nav.side a.on .nsc{background:color-mix(in srgb,var(--a) 22%,transparent);color:var(--t)}
body.v37 .snav{display:flex;flex-direction:column;gap:3px}
/* section tabs */
.sectabs{position:sticky;top:64px;z-index:5;display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 16px;padding:8px 10px;border-radius:18px;border:1px solid var(--gb2);
 background:linear-gradient(160deg,var(--g1),var(--g2)),color-mix(in srgb,var(--bg1) 70%,transparent);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);box-shadow:var(--gl),0 14px 30px -20px rgba(0,0,0,.8)}
.sectabs .sth2{display:flex;align-items:center;gap:8px;padding-inline:4px}
.sectabs .sth2 b{font-size:14px}
.sectabs .sti{width:30px;height:30px;border-radius:10px;display:grid;place-items:center;color:#1a1206;background:linear-gradient(145deg,var(--al),var(--a),var(--ad))}
.sectabs .stl{display:flex;gap:4px;overflow-x:auto;scrollbar-width:none;flex:1;padding:3px;border-radius:14px;background:color-mix(in srgb,var(--bg1) 40%,transparent);border:1px solid var(--gb)}
.sectabs .stl a{flex:none;padding:8px 15px;border-radius:11px;color:var(--s);font-weight:800;font-size:13px;text-decoration:none;white-space:nowrap;transition:background .15s,color .15s}
.sectabs .stl a:hover{color:var(--t);background:var(--in)}
.sectabs .stl a.on{color:#1a1206;background:linear-gradient(135deg,var(--al),var(--a) 50%,var(--ad));box-shadow:inset 0 1px 0 rgba(255,255,255,.55),0 6px 16px -8px color-mix(in srgb,var(--a) 80%,transparent)}
@media(max-width:1099px){.sectabs{top:110px}}
@media(max-width:620px){.sectabs .sth2{display:none}.sectabs{padding:6px}}
body.v37 .ptabs a.on,body.v37 .seg button.on,body.v37 .segl button.on{background:linear-gradient(135deg,var(--al),var(--a) 50%,var(--ad))!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.55)}
/* flags */
.flg{font-size:1.05em;line-height:1;display:inline-block;vertical-align:-1px;font-family:"Apple Color Emoji","Segoe UI Emoji","Noto Color Emoji",sans-serif}.flg.nf{opacity:.55}
/* servers grid */
.v37grid .sgw{overflow-x:auto;margin-top:12px}
.sgrid{display:grid;grid-template-columns:minmax(170px,1.4fr) repeat(7,minmax(92px,1fr));gap:6px;min-width:860px}
.sgh,.sgr{display:contents}
.sgh span{font-size:11px;font-weight:800;color:var(--s);padding:2px 6px;text-align:center}
.sgh span:first-child{text-align:start}
.sgn{display:flex;align-items:center;gap:7px;padding:8px 10px;border-radius:13px;background:var(--in);border:1px solid var(--gb);min-width:0}
.sgn b{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.sgn small{color:var(--s);font-size:10.5px;margin-inline-start:auto}
.svc{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:1px;padding:7px 4px;border-radius:13px;border:1px solid var(--gb);background:var(--in);color:var(--t);font:inherit;cursor:pointer;transition:transform .12s,border-color .15s}
.svc b{font-size:11.5px}.svc small{font-size:10.5px;color:var(--s)}
.svc.ok{border-color:color-mix(in srgb,var(--ok) 45%,transparent);background:color-mix(in srgb,var(--ok) 9%,transparent)}
.svc.bad{border-color:color-mix(in srgb,var(--bad) 50%,transparent);background:color-mix(in srgb,var(--bad) 9%,transparent)}
.svc.no{opacity:.45;cursor:default}
.svc:not(:disabled):hover{transform:translateY(-1px);border-color:var(--a)}
/* tunnel transports in three columns */
.trcols{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.trcol{border:1px solid var(--gb);border-radius:16px;padding:8px;background:var(--in)}
.trcol .trgl{margin:2px 4px 8px!important}
.trcol .tropt{display:flex!important;flex-direction:column;gap:6px}
.trc0 .trgl{color:var(--info)!important}.trc1 .trgl{color:var(--ok)!important}.trc2 .trgl{color:var(--a)!important}
@media(max-width:820px){.trcols{grid-template-columns:1fr}}
/* KANKI MIX second config */
.km2 .chk span small{display:block;margin-top:2px}
.aikey{-webkit-text-security:disc}.aikey:focus{-webkit-text-security:none}
.km2{display:flex;gap:8px;align-items:center;justify-content:space-between;flex-wrap:wrap;width:100%;margin-top:6px;padding:8px 10px;border-radius:12px;border:1px dashed var(--gb2)}
`;
var st=document.createElement('style');st.id='v37css';st.textContent=css;document.head.appendChild(st);

// the panel may already have drawn itself before this script ran
if(window.S&&S.me&&$('#app header.top')){shell();route()}
})();
