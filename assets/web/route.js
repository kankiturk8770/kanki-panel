// Kanki Panel 3.9.3: multi-location tunnels. A route is several servers in a row (Iran → Turkey →
// Germany): users connect to the first one, the traffic goes through each next one and leaves from the
// last. Every hop is a tunnel of its own with its own transport (KCP from Iran to Turkey, TCP Mux from
// Turkey to Germany…), made, tested, changed and deleted together. The ports carried are the same on
// every hop, so the configs of the last server work through the first one.
// Also: "Ports of the exit server" now fills in the KANKI MIX port too.
(function(){
'use strict';
if(typeof FA!='undefined')Object.assign(FA,{
 "Multi-location tunnel":"تانل چندمرحله‌ای","Multi-location":"چندمرحله‌ای",
 "Users connect to the first server; the traffic goes through each next server and leaves from the last. Every hop is a tunnel of its own with its own transport.":"کاربر به سرور اول وصل می‌شود؛ ترافیک از سرورهای بعدی رد می‌شود و از آخری بیرون می‌رود. هر مرحله یک تانل جدا با روش انتقال خودش است.",
 "Route name":"اسم مسیر","Stop":"ایستگاه","Users connect here":"کاربرها به این وصل می‌شوند","Traffic leaves here":"ترافیک از اینجا بیرون می‌رود","Passes through":"از این رد می‌شود",
 "Add a stop":"افزودن ایستگاه","Remove this stop":"حذف این ایستگاه","Hop":"مرحله","Link port":"پورت تانل","Test":"تست","Test every hop":"تست همه‌ی مرحله‌ها",
 "Testing…":"در حال تست…","Best":"بهترین","No transport passed on this hop":"هیچ روشی روی این مرحله رد نشد","Waiting":"در صف",
 "Ports to carry":"پورت‌هایی که از مسیر رد می‌شوند","Ports of":"پورت‌های","The same ports on every hop: users reach them on the first server and land on the same ports of the last one.":"روی همه‌ی مرحله‌ها همین پورت‌ها: کاربر به این پورت‌ها روی سرور اول وصل می‌شود و به همان پورت‌ها روی سرور آخر می‌رسد.",
 "Users of the last server connect through the first one":"کاربرهای سرور آخر از راه سرور اول وصل شوند",
 "WireGuard, AmneziaWG and Hysteria2 configs of the last server get the address of the first server; KANKI MIX gets its second config through the route by itself.":"کانفیگ‌های WireGuard، AmneziaWG و Hysteria2 سرور آخر آدرس سرور اول را می‌گیرند؛ کانفیگ دوم KANKI MIX خودش از همین مسیر ساخته می‌شود.",
 "Make the route":"ساخت مسیر","Save the route":"ذخیره‌ی مسیر","Pick at least three servers: the first, one in the middle and the last":"حداقل سه سرور انتخاب کن: اولی، یکی وسط و آخری",
 "A server cannot come twice on the route":"یک سرور نمی‌تواند دو بار در مسیر باشد","Pick every server":"همه‌ی سرورها را انتخاب کن","Add at least one port to carry":"حداقل یک پورت برای عبور اضافه کن",
 "The route is made: it connects in a few seconds":"مسیر ساخته شد: تا چند ثانیه‌ی دیگر وصل می‌شود","Route saved":"مسیر ذخیره شد",
 "Delete the whole route? Every hop stops and its ports are closed.":"کل مسیر حذف شود؟ همه‌ی مرحله‌ها خاموش می‌شوند و پورت‌هایشان بسته می‌شود.",
 "Total ping":"پینگ کل","Hops":"مرحله‌ها","Edit hop":"ویرایش مرحله","Reconnect all":"اتصال دوباره‌ی همه","Pause":"توقف","Resume":"ادامه",
 "Could not make hop":"مرحله ساخته نشد","the hops made so far were taken back":"مرحله‌هایی که ساخته شده بودند برداشته شدند",
 "Another test is running; it starts when that one ends":"یک تست دیگر در جریان است؛ بعد از تمام شدن آن شروع می‌شود",
 "Direction":"جهت","reverse":"معکوس","direct":"مستقیم","Profile":"پروفایل"
});

(function(){var st=document.createElement('style');st.textContent=
 '.rt-path{display:flex;flex-direction:column;gap:0;margin:10px 0 4px}'+
 '.rt-stop{display:flex;align-items:center;gap:8px;border:1px solid var(--ln);border-radius:14px;padding:7px 9px;background:var(--c1)}'+
 '.rt-stop>i{flex:none;width:24px;height:24px;border-radius:50%;display:inline-flex;align-items:center;justify-content:center;font-style:normal;font-weight:800;font-size:12px;background:color-mix(in srgb,var(--a) 18%,transparent);color:var(--a)}'+
 '.rt-stop select{flex:1;min-width:0;height:34px;padding:0 8px;font-size:13px}.rt-stop small{color:var(--s);font-size:11px;white-space:nowrap}'+
 '.rt-stop .ib{width:30px;height:30px}'+
 '.rt-hop{position:relative;margin:0 22px;padding:8px 0 8px 14px;border-inline-start:2px dashed color-mix(in srgb,var(--a) 45%,var(--ln))}'+
 '[dir=rtl] .rt-hop{padding:8px 14px 8px 0}'+
 '.rt-hop .rt-hg{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr) 84px minmax(0,1fr) auto;gap:6px;align-items:end}'+
 '.rt-hop label{font-size:11px;color:var(--s);display:block;margin:0 0 2px}.rt-hop select,.rt-hop input{height:32px;padding:0 8px;font-size:12px;width:100%}'+
 '.rt-hop .b2{height:32px;padding:0 10px;font-size:12px;white-space:nowrap}'+
 '.rt-res{font-size:11px;color:var(--s);margin-top:4px;min-height:14px}.rt-res b{color:var(--ok)}.rt-res .r{color:var(--bad)}'+
 '.rt-add{border:1px dashed var(--ln);background:transparent;color:var(--s);border-radius:12px;padding:6px;font:inherit;font-size:12px;cursor:pointer;margin:8px 0 0;width:100%}'+
 '.rt-add:hover{border-color:var(--a);color:var(--a)}'+
 '.rtc .rt-line{display:flex;align-items:center;flex-wrap:wrap;gap:4px;margin:8px 0 2px}'+
 '.rtc .rt-n{display:inline-flex;align-items:center;gap:5px;border:1px solid var(--ln);border-radius:999px;padding:3px 10px;font-weight:700;font-size:13px}'+
 '.rtc .rt-l{display:inline-flex;flex-direction:column;align-items:center;min-width:86px;font-size:10px;color:var(--s);line-height:1.3}'+
 '.rtc .rt-l i{display:block;width:100%;height:3px;border-radius:3px;background:var(--c);position:relative;overflow:hidden;margin:2px 0}'+
 '.rtc .rt-l i:after{content:"";position:absolute;inset:0;width:30%;background:linear-gradient(90deg,transparent,#fff8,transparent);animation:rtflow 1.6s linear infinite}'+
 '[dir=rtl] .rtc .rt-l i:after{animation-name:rtflowr}'+
 '@keyframes rtflow{from{transform:translateX(-100%)}to{transform:translateX(340%)}}@keyframes rtflowr{from{transform:translateX(100%)}to{transform:translateX(-340%)}}'+
 '.rtc .rt-badge{font-size:11px;border:1px solid color-mix(in srgb,var(--a) 55%,transparent);color:var(--a);border-radius:8px;padding:1px 7px;margin-inline-start:6px}'+
 '.rtc .rt-hops{display:flex;flex-direction:column;gap:4px;margin-top:8px}.rtc .rt-h{display:flex;align-items:center;gap:8px;font-size:12px;border:1px solid var(--ln);border-radius:10px;padding:5px 8px}'+
 '.rtc .rt-h b{min-width:0;flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.rtc .rt-h .ib{width:28px;height:28px}'+
 '@media(max-width:620px){.rt-hop .rt-hg{grid-template-columns:1fr 1fr}.rt-hop{margin:0 10px}}';
 document.head.appendChild(st)})();

// ---------------------------------------------------------------- ports of a server, KANKI MIX too
window.tunNodePorts=function(n){var i=(n&&n.info)||{},tcp=[],udp=[],add=function(l,v){v=parseInt(v,10);if(v>0&&v<65536&&l.indexOf(v)<0)l.push(v)};
 [i.wg_port,i.awg_port,i.hy2_port,i.kmix_port,(i.kc_ports||{}).game].forEach(function(v){add(udp,v)});return {tcp:tcp,udp:udp}};

// ---------------------------------------------------------------- data
function tl(){return (window.TN&&TN.d&&TN.d.tunnels)||[]}
function hopsOf(chain){return tl().filter(function(x){return x.chain==chain}).sort(function(a,b){return (a.hop||0)-(b.hop||0)})}
function sname(id){return (window.tunSrv?tunSrv(id):{name:id}).name}
function uid(){var s='abcdefghijkmnpqrstuvwxyz23456789',r='';for(var i=0;i<8;i++)r+=s.charAt(Math.floor(Math.random()*s.length));return r}
var TRS=[['Over UDP (fast, games)',['game','kcp','quic','hq']],['Over TCP (steady)',['tcpmux','wss','ws','tcp']],['Advanced (hardest to block)',['dual','h2','faketcp']]];
function trOpts(sel){return TRS.map(function(g){return '<optgroup label="'+esc(t(g[0]))+'">'+g[1].map(function(k){return '<option value="'+k+'"'+(k==sel?' selected':'')+'>'+esc(tunTr(k))+'</option>'}).join('')+'</optgroup>'}).join('')+
 (TRS.some(function(g){return g[1].indexOf(sel)>=0})||!sel?'':'<option value="'+esc(sel)+'" selected>'+esc(tunTr(sel))+'</option>')}

// ---------------------------------------------------------------- the list: the hops of a route are one card
var _card=window.tunCard;
window.tunCard=function(x){if(!x.chain)return _card(x);var hs=hopsOf(x.chain);if(hs.length&&hs[0].id!=x.id)return '';return routeCard(hs)};
function routeCard(hs){var first=hs[0],name=first.chain_name||first.name,states=hs.map(function(x){return x.state}),
 all=states.every(function(s){return s=='up'}),any=states.some(function(s){return s=='up'}),st=all?'up':!hs.some(function(x){return x.enabled})?'off':any?'partial':'down',col=tunCol(st),
 ping=hs.reduce(function(a,x){var r=(x.entry_status||{}).rtt_ms;return a==null||!r?null:a+r},0),ch=esc(first.chain);
 var line='<span class="rt-n">'+fl(first.entry)+esc(sname(first.entry))+'</span>';
 hs.forEach(function(x){var r=(x.entry_status||{}).rtt_ms;line+='<span class="rt-l" style="--c:'+tunCol(x.state)+'"><span>'+esc(tunTr(x.transport))+'</span><i></i><span class="ltr">'+(r?N(r)+' ms':tunStateTxt(x.state))+'</span></span><span class="rt-n">'+fl(x.exit)+esc(sname(x.exit))+'</span>'});
 var ports=[];if(first.tcp&&first.tcp.length)ports.push('TCP '+first.tcp.join(', '));if(first.udp&&first.udp.length)ports.push('UDP '+first.udp.join(', '));
 var err=hs.map(function(x){var e=(x.entry_status||{}).error||(x.exit_status||{}).error;return e&&x.state!='up'?sname(x.entry)+' → '+sname(x.exit)+': '+e:''}).filter(Boolean);
 return '<div class="card tcard rtc" style="border-inline-start:3px solid '+col+'"><div class="row" style="justify-content:space-between;align-items:flex-start;gap:8px">'+
  '<div style="min-width:0"><b>'+esc(name)+'</b><span class="rt-badge">⛓ '+t('Multi-location')+' · '+N(hs.length)+' '+t('Hops')+'</span><div class="rt-line">'+line+'</div></div>'+
  '<div class="row" style="gap:8px;flex-wrap:nowrap"><span class="tst" style="color:'+col+';border-color:'+col+'"><i style="background:'+col+'"></i>'+tunStateTxt(st)+'</span></div></div>'+
  '<div class="tgrid"><div><small>'+t('Total ping')+'</small><b class="ltr">'+(ping?N(ping)+' ms':'—')+'</b></div><div><small>'+t('Hops')+'</small><b>'+N(hs.filter(function(x){return x.state=='up'}).length)+' / '+N(hs.length)+'</b></div>'+
  '<div><small>'+t('Traffic')+'</small><b class="ltr">↑'+bytes((first.entry_status||{}).tx_bytes||0)+' ↓'+bytes((first.entry_status||{}).rx_bytes||0)+'</b></div></div>'+
  '<p class="muted ltr tmeta">'+esc(ports.join(' · '))+'</p>'+
  '<div class="rt-hops">'+hs.map(function(x){return '<div class="rt-h"><span class="dot" style="background:'+tunCol(x.state)+'"></span><b>'+esc(sname(x.entry))+' → '+esc(sname(x.exit))+'</b><small class="muted ltr">'+esc(tunTr(x.transport))+' · '+t('port')+' '+N(x.port)+'</small>'+
   '<button class="ib" title="'+esc(t('Edit hop'))+'" onclick="tunEdit(\''+esc(x.id)+'\')">'+ic('edit',14)+'</button></div>'}).join('')+'</div>'+
  (err.length?'<div class="warnbox ltr" style="margin:6px 0 0">'+err.map(esc).join('<br>')+'</div>':'')+
  '<div class="g4" style="margin-top:10px;display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:6px">'+
  '<button class="b2" onclick="routeEdit(\''+ch+'\')">'+ic('edit',15)+' '+t('Edit')+'</button>'+
  '<button class="b2" onclick="routeAct(\''+ch+'\',\'restart\')">'+ic('refresh',15)+' '+t('Reconnect all')+'</button>'+
  '<button class="b2" onclick="routeAct(\''+ch+'\',\''+(hs.some(function(x){return x.enabled})?'disable':'enable')+'\')">'+t(hs.some(function(x){return x.enabled})?'Pause':'Resume')+'</button>'+
  '<button class="b2 bd" onclick="routeDel(\''+ch+'\')">'+ic('trash',15)+' '+t('Delete')+'</button></div></div>'}
function fl(sid){var s=window.tunSrv?tunSrv(sid):null;return s&&s.cc&&window.flagOf?flagOf(s.cc):''}
window.routeAct=function(ch,a){var hs=hopsOf(ch);Promise.all(hs.map(function(x){return api('POST','/api/tunnels/'+x.id+'/'+a)})).then(function(){toast(a=='restart'?t('The tunnel reconnects in a few seconds'):t('Done'));tunRefresh()}).catch(fail)};
window.routeDel=function(ch){if(!confirm(t('Delete the whole route? Every hop stops and its ports are closed.')))return;var hs=hopsOf(ch);
 Promise.all(hs.map(function(x){return api('DELETE','/api/tunnels/'+x.id)})).then(function(){toast(t('Done'));tunRefresh()}).catch(fail)};

// a button next to "+ Tunnel"
var _pt=window.pTunnels;
window.pTunnels=function(){_pt.apply(this,arguments);var r=$('#pg .ph .row');if(r&&!$('#rt_new')){var b=document.createElement('button');b.className='b2';b.id='rt_new';b.innerHTML='⛓ '+t('Multi-location tunnel');b.onclick=function(){routeEdit()};r.insertBefore(b,r.lastElementChild)}};

// ---------------------------------------------------------------- make / edit a route
var R=null;
window.routeEdit=function(ch){var go=function(){Promise.all([api('GET','/api/servers').catch(function(){return null}),api('GET','/api/xray').catch(function(){return null})]).then(function(r){routeOpen(ch,r[0],r[1])})};
 if(!window.TN||!TN.d)return tunLoad().then(go);go()};
function routeOpen(ch,srvs,xr){var sv=TN.d.servers||[],remote=sv.filter(function(s){return !s.local}),hs=ch?hopsOf(ch):[];
 R={chain:ch||'',srvs:srvs,xr:xr,hops:[],stops:[],name:'',use:!ch};
 if(hs.length){R.name=hs[0].chain_name||hs[0].name;R.stops=[hs[0].entry].concat(hs.map(function(x){return x.exit}));
  R.hops=hs.map(function(x){return {id:x.id,transport:x.transport,mode:x.mode||'reverse',port:x.port,prof:x.conns==8?'speed':x.conns==2?'gaming':'balanced',fec:x.fec,dup:x.dup}});
  R.tcp=(hs[0].tcp||[]).join(', ');R.udp=(hs[0].udp||[]).join(', ')}
 else{var ir=sv.filter(function(s){return srvLocOf(s)=='iran'}),ab=sv.filter(function(s){return srvLocOf(s)!='iran'});
  // first an Iran server, then an abroad one to pass through, the last abroad one as the exit
  ab=ab.filter(function(s){return !s.local});
  R.stops=[(ir[0]||remote[0]||{}).id||'',ab.length>1?ab[0].id:'',(ab[ab.length-1]||{}).id||'local'];
  R.hops=[{},{}];R.tcp='';R.udp=''}
 R.hops.forEach(function(h){h.transport=h.transport||'kcp';h.mode=h.mode||'reverse';h.prof=h.prof||'balanced'});
 modal(mhead('⛓ '+t('Multi-location tunnel'))+'<p class="sub" style="margin:0 0 8px">'+t('Users connect to the first server; the traffic goes through each next server and leaves from the last. Every hop is a tunnel of its own with its own transport.')+'</p>'+
  '<label class="f">'+t('Route name')+'</label><input id="rt_nm" value="'+esc(R.name)+'" placeholder="Iran → Turkey → Germany" maxlength="40">'+
  '<div class="rt-path" id="rt_path"></div><button type="button" class="rt-add" id="rt_add">+ '+t('Add a stop')+'</button>'+
  '<div class="nh" style="margin-top:14px"><b>'+t('Ports to carry')+'</b><button class="b2 sm" id="rt_vpn">'+ic('ports',14)+' <span id="rt_vpnl"></span></button></div>'+
  '<small class="muted" style="display:block;margin-bottom:6px">'+t('The same ports on every hop: users reach them on the first server and land on the same ports of the last one.')+'</small>'+
  '<div class="g2"><div><label class="f">TCP</label><input id="rt_tcp" class="ltr" value="'+esc(R.tcp)+'" placeholder="443, 2053"></div><div><label class="f">UDP</label><input id="rt_udp" class="ltr" value="'+esc(R.udp)+'" placeholder="51820, 51821, 8443, 4000"></div></div>'+
  '<label class="chk" style="margin-top:10px"><input type="checkbox" id="rt_use"'+(R.use?' checked':'')+'><span><b>'+t('Users of the last server connect through the first one')+'</b><small>'+t('WireGuard, AmneziaWG and Hysteria2 configs of the last server get the address of the first server; KANKI MIX gets its second config through the route by itself.')+'</small></span></label>'+
  '<div class="g2" style="margin-top:14px"><button class="b2" id="rt_test">⚡ '+t('Test every hop')+'</button><button class="btn" id="rt_go">'+t(ch?'Save the route':'Make the route')+'</button></div>','wide');
 drawPath();
 $('#rt_add').onclick=function(){readForm();R.stops.splice(R.stops.length-1,0,'');R.hops.push({transport:'tcpmux',mode:'reverse',prof:'balanced'});drawPath()};
 $('#rt_vpn').onclick=function(){fillPorts(true)};
 $('#rt_test').onclick=function(){readForm();testAll()};
 $('#rt_go').onclick=function(){save(this)};
 if(!ch)fillPorts(false)}
function srvLocOf(s){return window.srvLoc?srvLoc(s):(s.loc||'')}
function srvOpts(sel){var sv=TN.d.servers||[];return '<option value="">—</option>'+srvOptGroups(sv,function(s){return '<option value="'+esc(s.id)+'"'+(s.id==sel?' selected':'')+'>'+esc(s.name+(s.local?' ('+t('panel')+')':''))+'</option>'})}
function drawPath(){var el=$('#rt_path');if(!el)return;var n=R.stops.length,h='';
 R.stops.forEach(function(sid,i){
  h+='<div class="rt-stop"><i>'+N(i+1)+'</i><select class="rt-s" data-i="'+i+'">'+srvOpts(sid)+'</select><small>'+t(i==0?'Users connect here':i==n-1?'Traffic leaves here':'Passes through')+'</small>'+
   (i>0&&i<n-1?'<button type="button" class="ib bd" title="'+esc(t('Remove this stop'))+'" data-rm="'+i+'">✕</button>':'')+'</div>';
  if(i<n-1){var hp=R.hops[i]||{};
   h+='<div class="rt-hop" data-h="'+i+'"><div class="rt-hg">'+
    '<div><label>'+t('Transport')+'</label><select class="rt-tr" data-h="'+i+'">'+trOpts(hp.transport)+'</select></div>'+
    '<div><label>'+t('Direction')+'</label><select class="rt-md" data-h="'+i+'"><option value="reverse"'+(hp.mode!='direct'?' selected':'')+'>'+t('reverse')+'</option><option value="direct"'+(hp.mode=='direct'?' selected':'')+'>'+t('direct')+'</option></select></div>'+
    '<div><label>'+t('Link port')+'</label><input class="rt-pt ltr" data-h="'+i+'" inputmode="numeric" value="'+esc(hp.port?String(hp.port):'')+'"></div>'+
    '<div><label>'+t('Profile')+'</label><select class="rt-pf" data-h="'+i+'"><option value="balanced"'+(hp.prof=='balanced'?' selected':'')+'>'+t('Balanced')+'</option><option value="speed"'+(hp.prof=='speed'?' selected':'')+'>'+t('Most speed')+'</option><option value="gaming"'+(hp.prof=='gaming'?' selected':'')+'>'+t('Gaming (low ping)')+'</option></select></div>'+
    '<div><button type="button" class="b2" data-t="'+i+'">⚡ '+t('Test')+'</button></div></div><div class="rt-res" id="rt_res'+i+'">'+(hp.res||'')+'</div></div>'}});
 el.innerHTML=h;
 $$('#rt_path [data-rm]').forEach(function(b){b.onclick=function(){readForm();var i=+b.dataset.rm;R.stops.splice(i,1);R.hops.splice(i,1);drawPath()}});
 $$('#rt_path [data-t]').forEach(function(b){b.onclick=function(){readForm();testHop(+b.dataset.t)}});
 $$('#rt_path .rt-s').forEach(function(s){s.onchange=function(){readForm();autoPorts();if(+s.dataset.i==R.stops.length-1)fillPorts(false);drawPath()}});
 $$('#rt_path .rt-tr,#rt_path .rt-md').forEach(function(s){s.onchange=function(){var i=+s.dataset.h;readForm();R.hops[i].auto=true;R.hops[i].port=0;autoPorts();drawPath()}});
 $$('#rt_path .rt-pt').forEach(function(s){s.oninput=function(){R.hops[+s.dataset.h].typed=1}});
 autoPorts(true);
 var last=R.stops[n-1],l=$('#rt_vpnl');if(l)l.textContent=t('Ports of')+' '+(last?sname(last):'—')}
function readForm(){$$('#rt_path .rt-s').forEach(function(s){R.stops[+s.dataset.i]=s.value});
 $$('#rt_path .rt-tr').forEach(function(s){R.hops[+s.dataset.h].transport=s.value});
 $$('#rt_path .rt-md').forEach(function(s){R.hops[+s.dataset.h].mode=s.value});
 $$('#rt_path .rt-pf').forEach(function(s){R.hops[+s.dataset.h].prof=s.value});
 $$('#rt_path .rt-pt').forEach(function(s){var v=+unN(s.value)||0;R.hops[+s.dataset.h].port=v});
 if($('#rt_nm'))R.name=$('#rt_nm').value;if($('#rt_tcp'))R.tcp=$('#rt_tcp').value;if($('#rt_udp'))R.udp=$('#rt_udp').value}
// a free link port for each hop on the server that listens (two hops of this route never share one)
function autoPorts(paint){var taken={};
 R.hops.forEach(function(h,i){var en=R.stops[i],ex=R.stops[i+1];if(!en||!ex)return;var l=h.mode=='direct'?ex:en,udp=tunUdpTr(h.transport),both=tunBoth(h.transport),k=l+'|'+(both?'b':udp?'u':'t');
  taken[k]=taken[k]||{};
  if(h.port&&(h.typed||h.id)&&!h.auto){taken[k][h.port]=1;return}
  var p=tunFreePort(l,h.id||null,udp,both);while(taken[k][p]&&p<3500)p++;taken[k][p]=1;h.port=p;h.auto=false});
 if(paint)$$('#rt_path .rt-pt').forEach(function(s){var h=R.hops[+s.dataset.h];if(h&&h.port&&!s.value)s.value=h.port})}
// the ports of the last server: its VPN ports (UDP), its Xray inbounds and its Kanki DNS (tunSvcPorts)
function fillPorts(manual){readForm();var last=R.stops[R.stops.length-1];if(!last)return;
 var s=((R.srvs&&R.srvs.servers)||[]).filter(function(x){return (x.agent&&x.agent.id==last)||(last=='local'&&x.local)})[0],n=s&&s.node,i=(n&&n.info)||{},udp=[],tcp=[];
 var add=function(l,v){v=parseInt(v,10);if(v>0&&v<65536&&l.indexOf(v)<0)l.push(v)};
 [i.wg_port,i.awg_port,i.hy2_port,i.kmix_port].forEach(function(v){add(udp,v)});
 (window.tunSvcPorts?tunSvcPorts(last):Promise.resolve({tcp:[],udp:[]})).then(function(o){
  o.tcp.forEach(function(v){add(tcp,v)});o.udp.forEach(function(v){add(udp,v)});
  if(!udp.length&&!tcp.length){if(manual)toast(t('No node found for this server: type the ports by hand'),1);return}
  if(!manual&&(R.tcp||R.udp))return;
  $('#rt_tcp').value=tcp.join(', ');$('#rt_udp').value=udp.join(', ');readForm()})}

// ---------------------------------------------------------------- smart test, hop by hop
function probeWait(){return new Promise(function(res){var iv=setInterval(function(){api('GET','/api/tunnels/probe').then(function(r){var j=r.job;if(!j||j.finished){clearInterval(iv);res(j)}else{var p=Math.min(99,Math.round(j.elapsed*100/60));R.onp&&R.onp(p)}}).catch(function(){})},2000)})}
function bestOf(j,prof){var L=(j&&j.results)||[],ok=L.filter(function(r){return !r.baseline&&r.done&&!r.failed&&r.down_mbps>0});
 ok.sort(function(a,b){return ((b.scores||{})[prof]||0)-((a.scores||{})[prof]||0)||(b.down_mbps||0)-(a.down_mbps||0)});
 var b=ok[0];if(!b)return null;return {transport:b.transport,mode:b.mode,score:(b.scores||{})[prof]||0,ping:b.ping_ms}}
function testHop(i){var en=R.stops[i],ex=R.stops[i+1],res=function(h){var el=$('#rt_res'+i);if(el)el.innerHTML=h;R.hops[i].res=h};
 if(!en||!ex||en==ex){toast(t('Pick every server'),1);return Promise.resolve(null)}
 res('<span class="spin"></span> '+t('Testing…'));R.onp=function(p){res('<span class="spin"></span> '+t('Testing…')+' '+N(p)+'%')};
 return api('GET','/api/tunnels/probe').then(function(r){if(r.job&&!r.job.finished){res(t('Another test is running; it starts when that one ends'));return probeWait()}}).then(function(){
  return api('POST','/api/tunnels/probe',{entry:en,exit:ex,port:3990,transports:TS_TR.map(function(x){return x[0]}),baseline:true})}).then(function(){return probeWait()}).then(function(j){
  var b=bestOf(j,R.hops[i].prof||'balanced');
  if(!b){res('<span class="r">'+t('No transport passed on this hop')+'</span>');return null}
  R.hops[i].transport=b.transport;R.hops[i].mode=b.mode;R.hops[i].auto=true;R.hops[i].port=0;
  var h='🏆 '+t('Best')+': <b>'+esc(tunTr(b.transport))+'</b> · '+t(b.mode=='direct'?'direct':'reverse')+' · '+N(b.score)+'/100'+(b.ping!=null?' · <span class="ltr">'+N(b.ping)+' ms</span>':'');
  R.hops[i].res=h;readFormSafe();autoPorts();drawPath();return b}).catch(function(e){res('<span class="r">'+esc(e.message||String(e))+'</span>');return null})}
function readFormSafe(){var keep=R.hops.map(function(h){return {transport:h.transport,mode:h.mode,auto:h.auto,port:h.port,res:h.res}});readForm();keep.forEach(function(k,i){if(k.auto){R.hops[i].transport=k.transport;R.hops[i].mode=k.mode;R.hops[i].port=k.port}R.hops[i].res=k.res})}
function testAll(){var i=0,next=function(){if(!$('#rt_path')||i>=R.hops.length)return;var k=i++;testHop(k).then(next)};next()}

// ---------------------------------------------------------------- save: one tunnel per hop
function save(btn){readForm();var st=R.stops,n=st.length;
 if(n<3)return toast(t('Pick at least three servers: the first, one in the middle and the last'),1);
 if(st.some(function(x){return !x}))return toast(t('Pick every server'),1);
 if(st.some(function(x,i){return st.indexOf(x)!=i}))return toast(t('A server cannot come twice on the route'),1);
 if(!R.tcp.trim()&&!R.udp.trim())return toast(t('Add at least one port to carry'),1);
 autoPorts();
 var ch=R.chain||uid(),name=R.name.trim()||st.map(sname).join(' → '),old=R.chain?hopsOf(R.chain):[],made=[];
 btn.disabled=true;
 var body=function(i){var h=R.hops[i],b={name:name+' · '+N(i+1)+'/'+N(n-1),entry:st[i],exit:st[i+1],mode:h.mode,transport:h.transport,port:h.port,conns:TNP[h.prof]||4,
   tcp:R.tcp,udp:R.udp,chain:ch,hop:i,chain_name:name,kind:'',auto:false};
  if(h.transport=='game'){b.fec=h.fec||'8:3';b.dup=!!h.dup}
  if(old[i])b.id=old[i].id;return b};
 var step=function(i){if(i>=n-1)return Promise.resolve();return api('POST','/api/tunnels',body(i)).then(function(r){if(!old[i])made.push(r.id);return step(i+1)},function(e){
   var m=t('Could not make hop')+' '+N(i+1)+' ('+sname(st[i])+' → '+sname(st[i+1])+'): '+(e.message||e);throw new Error(m)})};
 step(0).then(function(){
  // hops of the old route past the new end go away
  return Promise.all(old.slice(n-1).map(function(x){return api('DELETE','/api/tunnels/'+x.id)}))}).then(function(){
  if(!$('#rt_use').checked)return;
  var last=st[n-1],first=st[0],s=((R.srvs&&R.srvs.servers)||[]).filter(function(x){return (x.agent&&x.agent.id==last)||(last=='local'&&x.local)})[0],f=tunSrv(first);
  if(!s||!s.node||!(f.addr||f.host))return;
  return api('PUT','/api/nodes/'+encodeURIComponent(s.node.id),{endpoint_mode:'custom',endpoint:f.addr||f.host})}).then(function(){
  closeModal();toast(t(R.chain?'Route saved':'The route is made: it connects in a few seconds'));tunRefresh();if(window.srvLoad)srvLoad(true)}).catch(function(e){
  btn.disabled=false;
  if(made.length)Promise.all(made.map(function(id){return api('DELETE','/api/tunnels/'+id)})).then(function(){tunRefresh()});
  toast((e.message||String(e))+(made.length?' · '+t('the hops made so far were taken back'):''),1)})}
})();
