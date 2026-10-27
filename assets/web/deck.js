// Kanki Panel 3.11: the look of the new design. Loaded last (after kanki-hub.js); it changes how the
// panel looks and moves, never what a button does:
//  - the side menu: groups that open and close smoothly (items slide in one after another), the open
//    section lit gold with a turning gold edge; a button folds it to icons only
//  - "Side menu / Top menu": the whole menu can sit in one row across the top, dragged or scrolled sideways
//  - Cores (VPN services): the tabs are a rail of cards (drag it, tap one); under a core its servers are
//    country chips, and the picked one opens its settings right below them
//  - users in two columns of slim cards: the whole name, data used and the expiry date
//  - every page comes in with its cards rising one after another
(function(){
'use strict';
var V=window.V37;if(!V)return;
if(typeof FA!='undefined')Object.assign(FA,{"Cores":"هسته‌ها","Inbounds":"دروازه‌ها","Inbound":"دروازه","+ Inbound":"+ دروازه",
 "Working inbounds":"دروازه‌های فعال","inbounds":"دروازه","No inbound yet.":"هنوز دروازه‌ای نیست.","No inbound on this server yet":"هنوز دروازه‌ای روی این سرور نیست","Make the first one":"اولی را بساز",
 "Side menu":"منوی کنار","Top menu":"منوی بالا","Fold the menu":"جمع کردن منو","Expires":"انقضا","Data":"حجم","Expired":"منقضی",
 "All cores at a glance":"همه‌ی هسته‌ها در یک نگاه","Games · low ping":"گیم · پینگ پایین","Plain and fast":"ساده و سریع","Obfuscated WireGuard":"WireGuard مبهم",
 "QUIC · lossy internet":"QUIC · اینترنت پرافت","Blocked sites only":"فقط سایت‌های تحریم‌شده"});
ICO.cores='<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>';
var CHEV='<svg class="kd-chev" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>';
function store(k,v){try{if(v===undefined)return localStorage.getItem(k);localStorage.setItem(k,v)}catch(e){}return null}
// the services section is called Cores
V.SECS.forEach(function(s){if(s[0]=='vpnsec'){s[1]='Cores';s[2]='cores'}});

// ---------------------------------------------------------------- side menu: groups that open and close
var GOPEN={};try{GOPEN=JSON.parse(store('kk_navg')||'{}')||{}}catch(e){}
function groups(){var gs=[];V.SECS.forEach(function(s){var g=gs[gs.length-1];if(!g||g.l!=s[4])gs.push(g={l:s[4],s:[]});g.s.push(s)});return gs}
function href(f){return '#'+f[0]+(f[1]?'/'+f[1]:'')}
window.navSide=function(){var cur=V.secOf(S.page)[0];
 return groups().map(function(g){var open=GOPEN[g.l]!==false||g.s.some(function(x){return x[0]==cur});
  return '<div class="kd-g'+(open?' open':'')+'" data-g="'+esc(g.l)+'"><button type="button" class="kd-gh" aria-expanded="'+open+'"><span>'+t(g.l)+'</span>'+CHEV+'</button>'+
   '<div class="kd-gb"><div class="kd-gbi">'+g.s.map(function(s,i){var f=s[3][0];
    return '<a href="'+href(f)+'" data-p="'+f[0]+'" data-sec="'+s[0]+'" class="kd-it d'+Math.min(5,i+1)+'" title="'+esc(t(s[1]))+'"><span class="ni">'+ic(s[2],18)+'</span><span class="kd-l">'+t(s[1])+'</span></a>'}).join('')+
   '</div></div></div>'}).join('')};
document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('.kd-gh');if(!b)return;
 var g=b.parentNode,o=!g.classList.contains('open');g.classList.toggle('open',o);b.setAttribute('aria-expanded',o);GOPEN[g.dataset.g]=o;store('kk_navg',JSON.stringify(GOPEN))});

// ---------------------------------------------------------------- the menu across the top
function topNav(){return '<nav class="kd-top" id="kdtop" aria-label="'+esc(t('Top menu'))+'">'+groups().map(function(g){
  return '<span class="kd-sep">'+t(g.l)+'</span>'+g.s.map(function(s){var f=s[3][0];return '<a href="'+href(f)+'" data-sec="'+s[0]+'" class="kd-tn"><span class="ni">'+ic(s[2],17)+'</span>'+t(s[1])+'</a>'}).join('')}).join('')+'</nav>'}
// drag a row sideways with the mouse (fingers scroll it by themselves); a drag is not a click
function dragRow(el){if(!el||el._kd)return;el._kd=1;var d=null,moved=false;
 el.addEventListener('pointerdown',function(e){if(e.pointerType!='mouse')return;d={x:e.clientX,l:el.scrollLeft};moved=false});
 el.addEventListener('pointermove',function(e){if(!d)return;var dx=e.clientX-d.x;if(Math.abs(dx)>5)moved=true;if(moved){el.scrollLeft=d.l-dx;el.classList.add('kd-drag')}});
 var up=function(){d=null;setTimeout(function(){el.classList.remove('kd-drag')},0)};el.addEventListener('pointerup',up);el.addEventListener('pointerleave',up);
 el.addEventListener('click',function(e){if(moved){e.preventDefault();e.stopPropagation();moved=false}},true)}
function look(){document.body.classList.add('kd');document.body.classList.toggle('kd-mini',store('kk_mini')=='1');document.body.classList.toggle('kd-topm',store('kk_menu')=='top');
 $$('.kd-lay button').forEach(function(b){b.classList.toggle('on',(b.dataset.m=='top')==(store('kk_menu')=='top'))})}
window.kdMenu=function(m){store('kk_menu',m);look();markAll()};
window.kdMini=function(){store('kk_mini',store('kk_mini')=='1'?'0':'1');look()};
var _sh=window.shell;
window.shell=function(){_sh.apply(this,arguments);
 var br=$('#side .sbrand');if(br&&!$('.kd-fold',br))br.insertAdjacentHTML('beforeend','<button type="button" class="kd-fold" onclick="kdMini()" aria-label="'+esc(t('Fold the menu'))+'" title="'+esc(t('Fold the menu'))+'">'+CHEV+'</button>');
 var ta=$('header.top .tb-act');if(ta&&!$('.kd-lay',ta))ta.insertAdjacentHTML('afterbegin','<div class="kd-lay" role="group" aria-label="'+esc(t('Top menu'))+'"><button type="button" data-m="side" onclick="kdMenu(\'side\')">'+t('Side menu')+'</button><button type="button" data-m="top" onclick="kdMenu(\'top\')">'+t('Top menu')+'</button></div>');
 var hd=$('header.top');if(hd&&!$('#kdtop'))hd.insertAdjacentHTML('afterend',topNav());dragRow($('#kdtop'));look()};
function markAll(){var sk=V.secOf(S.page)[0];
 $$('#kdtop a[data-sec]').forEach(function(a){a.classList.toggle('on',a.dataset.sec==sk)});
 var on=$('#kdtop a.on');if(on&&document.body.classList.contains('kd-topm'))try{on.scrollIntoView({block:'nearest',inline:'center'})}catch(e){}
 var a=$('#side a.on'),g=a&&a.closest('.kd-g');if(g&&!g.classList.contains('open')){g.classList.add('open');var b=$('.kd-gh',g);if(b)b.setAttribute('aria-expanded','true')}}
var _nm=window.navMark;window.navMark=function(){_nm.apply(this,arguments);markAll()};

// ---------------------------------------------------------------- every page comes in card by card
var _rt=window.route;
window.route=function(){var r=_rt.apply(this,arguments),pg=$('#pg');if(pg){pg.classList.remove('kd-enter');void pg.offsetWidth;pg.classList.add('kd-enter');clearTimeout(pg._kd);pg._kd=setTimeout(function(){pg.classList.remove('kd-enter')},1400)}
 document.body.classList.toggle('kd-vpn',V.secOf(S.page)[0]=='vpnsec');return r};

// ---------------------------------------------------------------- Cores: a rail of cards
var CORE={vpn:['dash','All cores at a glance','#F5C451'],kmix:['game','Games · low ping','#ff8a2a'],xray:['xray','VLESS · VMess · Trojan','#6fb6ff'],wg:['shield2','Plain and fast','#3ddc97'],
 awg:['shield2','Obfuscated WireGuard','#a78bfa'],hy2:['shield2','QUIC · lossy internet','#f472b6'],antidpi:['security','REALITY · CDN','#2fd6d6'],dns:['dns','Blocked sites only','#F5C451']};
function dressRail(){var st=$('#sectabs');if(!st||V.secOf(S.page)[0]!='vpnsec')return;
 if(!st.classList.contains('kd-rail')){st.classList.add('kd-rail');
  $$('.stl a',st).forEach(function(a){var p=(a.getAttribute('href')||'').slice(1).split('/')[0],m=CORE[p]||['cores','',''],name=a.textContent;
   a.style.setProperty('--cc',m[2]||'#F5C451');a.innerHTML='<span class="kd-ci">'+ic(m[0],20)+'</span><b>'+esc(name)+'</b><small>'+esc(t(m[1]))+'</small>'});
  dragRow($('.stl',st))}
 var on=$('.stl a.on',st);if(on&&on!==st._on){st._on=on;try{on.scrollIntoView({block:'nearest',inline:'center',behavior:st._seen?'smooth':'auto'})}catch(e){}st._seen=1}}
// under a core: its servers are country chips; the first one opens by itself so its settings show
var AUTO={};
function chips(){if(!document.body.classList.contains('kd-vpn'))return;
 ['km','xr','pv_wg','pv_awg','pv_hy2'].forEach(function(g){var rows=$$('.kxr[data-acc="'+g+'"]');if(!rows.length||AUTO[g+S.page])return;AUTO[g+S.page]=1;
  if(!rows.some(function(r){return r.classList.contains('open')})){var h=$('.kxr-h',rows[0]);if(h)h.click()}})}
window.addEventListener('hashchange',function(){AUTO={}});
new MutationObserver(function(){if($('#sectabs'))dressRail();if(document.body.classList.contains('kd-vpn'))chips()}).observe(document.body,{childList:true,subtree:true});

// ---------------------------------------------------------------- users: two columns, data and expiry date
if(window.uchip){
 window.uchip=function(u){var st=ustate(u),lv=liveOf(u),on=u.online_connections>0||lv.length>0,dot=st=='disabled'?'r':st=='finished'?'y':(on?'g':''),ps=[];
  lv.forEach(function(c){if(ps.indexOf(c.p)<0)ps.push(c.p)});
  var pc=usage(u),used=(+u.traffic_used_gb||0).toFixed(1),exp=st=='disabled'?t('Disabled'):!u.expires_ts?'∞':u.expires_ts<Date.now()/1000?t('Expired'):jdate(u.expires_ts);
  return '<button class="uchip kd-u st-'+st+(on?' on':'')+(S.sel[u.id]?' sel':'')+'" data-id="'+u.id+'" title="'+esc(u.username)+'">'+
   '<span class="kd-un"><span class="dot '+dot+'"></span><span class="nm">'+esc(u.username)+'</span>'+
   (ps.length?'<span class="lvs">'+ps.slice(0,3).map(function(p){return '<i style="--pc:'+(PCOL[p]||'#888')+'">'+liveShort(p)+'</i>'}).join('')+'</span>':'')+
   '<span class="tick">'+ic('check',13)+'</span></span>'+
   '<span class="k310bar'+(pc<0?' inf':pc>=90?' hot':pc>=70?' warm':'')+'"><i style="width:'+(pc<0?100:Math.max(3,pc))+'%"></i></span>'+
   '<span class="kd-meta"><span>'+t('Data')+' <b class="ltr">'+N(used)+(pc<0?' GB / ∞':' / '+N(u.traffic_limit_gb)+' GB')+'</b></span><span>'+t('Expires')+' <b>'+exp+'</b></span></span></button>'};
}

var css=`
/* ---- the moving gold edge (needs @property; without it the edge stays still) ---- */
@property --kda{syntax:"<angle>";initial-value:0deg;inherits:false}
@keyframes kdang{to{--kda:360deg}}
body.kd .kd-it.on::after,body.kd .kd-tn.on::after,body.kd .kd-rail .stl a.on::after,body.kd.kd-vpn .kxl>.kxr.open>.kxr-h::after,body.kd .uchip.kd-u:hover::after,body.kd #st .stn button.on::after,body.kd .k310st::after{
 content:"";position:absolute;inset:0;border-radius:inherit;padding:1.5px;pointer-events:none;z-index:2;
 background:conic-gradient(from var(--kda),transparent 0 55%,var(--cc,var(--a)) 70%,#fff 74%,var(--cc,var(--a)) 78%,transparent 92%);
 -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0);animation:kdang 3.2s linear infinite}
body.kd .k310st{position:relative}body.kd .k310st::after{opacity:.55;animation-duration:6s}
/* ---- side menu ---- */
body.kd nav.side .snav{display:flex;flex-direction:column;gap:2px}
.kd-g{display:flex;flex-direction:column}
.kd-gh{display:flex;align-items:center;gap:8px;width:100%;border:0;background:none;padding:12px 10px 6px;color:var(--s);font:inherit;font-size:11.5px;font-weight:800;letter-spacing:.3px;cursor:pointer;text-align:start;border-radius:10px}
.kd-gh:hover{color:var(--t)}
.kd-chev{margin-inline-start:auto;transition:transform .4s cubic-bezier(.2,.8,.2,1)}
.kd-g.open>.kd-gh .kd-chev{transform:rotate(-90deg)}
html[dir=ltr] .kd-chev{transform:scaleX(-1)}html[dir=ltr] .kd-g.open>.kd-gh .kd-chev{transform:scaleX(-1) rotate(-90deg)}
.kd-gb{display:grid;grid-template-rows:0fr;transition:grid-template-rows .45s cubic-bezier(.2,.8,.2,1)}
.kd-g.open>.kd-gb{grid-template-rows:1fr}
.kd-gbi{overflow:hidden;display:flex;flex-direction:column;gap:3px;min-height:0}
body.kd nav.side a.kd-it{position:relative;display:flex;align-items:center;gap:12px;padding:6px 8px!important;margin:0!important;border-radius:14px!important;font-weight:700;opacity:0;transform:translateX(calc(14px * var(--kdd,1)));
 transition:opacity .35s,transform .45s cubic-bezier(.2,.8,.2,1),background .2s,color .2s}
html[dir=ltr] body.kd nav.side a.kd-it{--kdd:-1}
.kd-g.open a.kd-it{opacity:1!important;transform:none!important}
.kd-g.open a.kd-it.d2{transition-delay:.05s,.05s,0s,0s}.kd-g.open a.kd-it.d3{transition-delay:.1s,.1s,0s,0s}.kd-g.open a.kd-it.d4{transition-delay:.15s,.15s,0s,0s}.kd-g.open a.kd-it.d5{transition-delay:.2s,.2s,0s,0s}
body.kd nav.side a.kd-it .ni{width:38px;height:38px;flex:none;border-radius:12px;display:grid;place-items:center;background:var(--in);border:1px solid var(--gb,var(--ln));color:var(--a);transition:all .3s}
body.kd nav.side a.kd-it:hover{background:color-mix(in srgb,var(--a) 7%,transparent)!important;color:var(--t)}
body.kd nav.side a.kd-it.on{background:linear-gradient(90deg,color-mix(in srgb,var(--a) 3%,transparent),color-mix(in srgb,var(--a) 15%,transparent))!important;color:var(--t)!important;box-shadow:none!important}
html[dir=ltr] body.kd nav.side a.kd-it.on{background:linear-gradient(270deg,color-mix(in srgb,var(--a) 3%,transparent),color-mix(in srgb,var(--a) 15%,transparent))!important}
body.kd nav.side a.kd-it.on .ni{background:radial-gradient(circle at 30% 25%,#fff3c4,var(--a) 50%,var(--ad));color:#160f00;border-color:transparent;box-shadow:0 0 22px -4px color-mix(in srgb,var(--a) 85%,transparent)}
body.kd nav.side a.kd-it.on::before{content:"";position:absolute;inset-inline-start:-12px;top:9px;bottom:9px;width:4px;border-radius:4px;background:var(--a);box-shadow:0 0 14px var(--a);animation:kdbar .45s cubic-bezier(.2,.8,.2,1)}
@keyframes kdbar{from{transform:scaleY(0)}to{transform:scaleY(1)}}
.kd-fold{margin-inline-start:auto;width:32px;height:32px;flex:none;border-radius:10px;border:1px solid var(--gb2,var(--ln));background:var(--in);color:var(--t);display:grid;place-items:center;cursor:pointer;transition:transform .45s cubic-bezier(.2,.8,.2,1)}
html[dir=ltr] .kd-fold svg{transform:scaleX(-1)}
@media(min-width:900px){
 body.kd nav.side{transition:width .45s cubic-bezier(.2,.8,.2,1)}
 body.kd header.top,body.kd main{transition:margin .45s cubic-bezier(.2,.8,.2,1)}
 body.kd.kd-mini{--sbw:88px}
 body.kd.kd-mini .kd-fold{transform:rotate(180deg)}
 body.kd.kd-mini nav.side .sbrand>div:not(:first-child),body.kd.kd-mini .kd-gh span,body.kd.kd-mini .kd-gh .kd-chev,body.kd.kd-mini a.kd-it .kd-l,body.kd.kd-mini nav.side .sfoot small,body.kd.kd-mini nav.side .sfoot b,body.kd.kd-mini nav.side .lo2{opacity:0;width:0;overflow:hidden;white-space:nowrap}
 body.kd.kd-mini .kd-gh{justify-content:center;padding:8px 0 2px;min-height:10px}body.kd.kd-mini .kd-gh::before{content:"";width:18px;height:2px;border-radius:2px;background:var(--gb2,var(--ln))}
 body.kd.kd-mini nav.side .sbrand{flex-direction:column;gap:8px}body.kd.kd-mini .kd-fold{margin:0}
 body.kd.kd-mini .kd-g>.kd-gb{grid-template-rows:1fr}body.kd.kd-mini a.kd-it{opacity:1!important;transform:none!important;justify-content:center}
 /* the menu across the top */
 body.kd.kd-topm{--sbw:0px}
 body.kd.kd-topm nav.side{display:none}
}
.kd-top{display:none}
body.kd.kd-topm .kd-top{display:flex;position:sticky;top:59px;z-index:6;gap:8px;align-items:center;overflow-x:auto;scrollbar-width:none;padding:8px 18px 10px;cursor:grab;
 background:color-mix(in srgb,var(--bg1) 86%,transparent);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border-bottom:1px solid var(--gb,var(--ln));
 -webkit-mask-image:linear-gradient(90deg,transparent,#000 24px,#000 calc(100% - 24px),transparent);mask-image:linear-gradient(90deg,transparent,#000 24px,#000 calc(100% - 24px),transparent)}
.kd-top::-webkit-scrollbar{display:none}
.kd-top.kd-drag,.kd-rail .stl.kd-drag{cursor:grabbing;scroll-snap-type:none!important}
.kd-sep{flex:none;font-size:11px;font-weight:800;color:var(--s);padding:0 8px 0 4px}
.kd-tn{position:relative;flex:none;display:flex;align-items:center;gap:9px;padding:5px 14px 5px 6px;border-radius:15px;border:1px solid var(--gb2,var(--ln));background:var(--c1);color:var(--t);text-decoration:none;font-weight:800;font-size:13px;min-height:46px;transition:all .3s cubic-bezier(.2,.8,.2,1)}
html[dir=rtl] .kd-tn{padding:5px 6px 5px 14px}
.kd-tn .ni{width:34px;height:34px;border-radius:11px;display:grid;place-items:center;background:var(--in);color:var(--a)}
.kd-tn:hover{border-color:color-mix(in srgb,var(--a) 45%,transparent)}
.kd-tn.on{background:linear-gradient(180deg,color-mix(in srgb,var(--a) 16%,transparent),color-mix(in srgb,var(--a) 4%,transparent));transform:translateY(-2px)}
.kd-tn.on .ni{background:radial-gradient(circle at 30% 25%,#fff3c4,var(--a) 50%,var(--ad));color:#160f00;box-shadow:0 0 20px -4px var(--a)}
body.kd.kd-topm .sectabs{top:124px}
.kd-lay{display:inline-flex;border:1px solid var(--gb2,var(--ln));border-radius:12px;padding:3px;background:var(--in)}
.kd-lay button{border:0;background:none;border-radius:9px;padding:5px 10px;font:inherit;font-size:11.5px;font-weight:800;color:var(--s);cursor:pointer}
.kd-lay button.on{background:var(--a);color:#160f00}
@media(max-width:899px){.kd-lay{display:none}body.kd.kd-topm .kd-top{display:none}}
/* ---- pages come in card by card ---- */
@keyframes kdrise{from{opacity:0;transform:translateY(20px) scale(.985)}to{opacity:1;transform:none}}
#pg.kd-enter>*:not(#sectabs),#pg.kd-enter .k310c,#pg.kd-enter .kpi{animation:kdrise .65s cubic-bezier(.2,.8,.2,1) both}
#pg.kd-enter>*:nth-child(2){animation-delay:.05s}#pg.kd-enter>*:nth-child(3){animation-delay:.1s}#pg.kd-enter>*:nth-child(4){animation-delay:.15s}#pg.kd-enter>*:nth-child(5){animation-delay:.2s}#pg.kd-enter>*:nth-child(n+6){animation-delay:.25s}
#pg.kd-enter .kpi:nth-child(2){animation-delay:.08s}#pg.kd-enter .kpi:nth-child(3){animation-delay:.12s}#pg.kd-enter .kpi:nth-child(4){animation-delay:.16s}#pg.kd-enter .kpi:nth-child(5){animation-delay:.2s}#pg.kd-enter .kpi:nth-child(6){animation-delay:.24s}
#pg.kd-enter .k310c:nth-child(2){animation-delay:.18s}#pg.kd-enter .k310c:nth-child(3){animation-delay:.26s}#pg.kd-enter .k310c:nth-child(4){animation-delay:.32s}#pg.kd-enter .k310c:nth-child(n+5){animation-delay:.38s}
/* ---- phones: the More sheet slides up, its tiles follow ---- */
@keyframes kdup{from{transform:translateY(100%)}to{transform:none}}
body.kd .msheet.k38sheet.on{animation:kdup .42s cubic-bezier(.2,.8,.2,1)}
body.kd .msheet.k38sheet.on .k38tile{animation:kdrise .5s cubic-bezier(.2,.8,.2,1) both}
body.kd .msheet.k38sheet.on .k38tiles:nth-of-type(2) .k38tile{animation-delay:.05s}body.kd .msheet.k38sheet.on .k38tiles:nth-of-type(3) .k38tile{animation-delay:.1s}body.kd .msheet.k38sheet.on .k38tiles:nth-of-type(n+4) .k38tile{animation-delay:.15s}
/* ---- Cores: the rail of cards ---- */
body.kd .sectabs.kd-rail{position:relative;top:auto;display:block;padding:0;border:0;background:none;backdrop-filter:none;-webkit-backdrop-filter:none;box-shadow:none;margin-bottom:10px}
body.kd .sectabs.kd-rail .sth2{display:none}
body.kd .sectabs.kd-rail .stl{display:flex;gap:12px;overflow-x:auto;scroll-snap-type:x mandatory;padding:12px 6px 18px;border:0;background:none;border-radius:0;cursor:grab;
 -webkit-mask-image:linear-gradient(90deg,transparent,#000 32px,#000 calc(100% - 32px),transparent);mask-image:linear-gradient(90deg,transparent,#000 32px,#000 calc(100% - 32px),transparent)}
body.kd .sectabs.kd-rail .stl a{position:relative;flex:0 0 156px;scroll-snap-align:center;display:flex;flex-direction:column;align-items:flex-start;gap:5px;padding:12px!important;border-radius:18px!important;
 border:1px solid var(--gb2,var(--ln));background:linear-gradient(180deg,color-mix(in srgb,var(--t) 4%,var(--c1)),var(--c2))!important;color:var(--t)!important;white-space:normal;
 transition:transform .45s cubic-bezier(.2,.8,.2,1),box-shadow .45s,border-color .3s!important}
body.kd .sectabs.kd-rail .stl a:hover{border-color:color-mix(in srgb,var(--cc) 45%,transparent)}
body.kd .sectabs.kd-rail .stl a b{font-size:14px;font-weight:900}
body.kd .sectabs.kd-rail .stl a small{font-size:11px;font-weight:600;color:var(--s);line-height:1.4}
.kd-ci{width:36px;height:36px;border-radius:12px;display:grid;place-items:center;background:color-mix(in srgb,var(--cc) 16%,transparent);color:var(--cc);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--cc) 35%,transparent);transition:all .35s}
body.kd .sectabs.kd-rail .stl a.on{transform:translateY(-5px) scale(1.03);border-color:transparent;box-shadow:0 20px 44px -22px var(--cc)}
body.kd .sectabs.kd-rail .stl a.on .kd-ci{background:var(--cc);color:#0b0b0a;box-shadow:0 0 24px -2px var(--cc)}
/* ---- Cores: servers as country chips, the picked one opens below them ---- */
body.kd.kd-vpn .kxl{display:flex!important;flex-direction:row!important;flex-wrap:wrap!important;align-items:center;gap:10px!important}
body.kd.kd-vpn .kxl>.kxr{display:contents}
body.kd.kd-vpn .kxl>.kxr>.kxr-h{position:relative;width:max-content!important;max-width:100%;flex:0 0 auto!important;min-height:48px!important;padding:8px 14px!important;border-radius:16px!important;border:1px solid var(--gb2,var(--ln))!important;background:var(--c1)!important;gap:8px!important;flex-wrap:nowrap!important;transform:none!important;transition:all .3s cubic-bezier(.2,.8,.2,1)}
body.kd.kd-vpn .kxl>.kxr>.kxr-h .kxr-arr,body.kd.kd-vpn .kxl>.kxr>.kxr-h .sp,body.kd.kd-vpn .kxl>.kxr>.kxr-h small{display:none!important}
body.kd.kd-vpn .kxl>.kxr>.kxr-h:hover{border-color:color-mix(in srgb,var(--a) 45%,transparent)!important}
body.kd.kd-vpn .kxl>.kxr.open>.kxr-h{background:linear-gradient(180deg,#FFE9A6,var(--a) 55%,var(--ad))!important;color:#160f00!important;border-color:transparent!important;box-shadow:0 12px 30px -12px color-mix(in srgb,var(--a) 90%,transparent);--cc:#fff}
body.kd.kd-vpn .kxl>.kxr.open>.kxr-h *{color:#160f00!important}
body.kd.kd-vpn .kxl>.kxr.open>.kxr-h .kxr-st{background:rgba(0,0,0,.14)!important;border-color:transparent!important}
body.kd.kd-vpn .kxl>.kxr>.kxr-b{order:99;flex:1 0 100%;width:100%;position:static!important;height:auto;max-height:none!important;inset:auto!important;box-shadow:none!important;border:1px solid var(--gb,var(--ln))!important;border-radius:18px!important;
 background:linear-gradient(180deg,color-mix(in srgb,var(--t) 3%,var(--c1)),var(--c2))!important;padding:6px 16px 14px!important;animation:kdrise .5s cubic-bezier(.2,.8,.2,1)!important}
body.kd.kd-vpn .k310dh{display:none!important}
body.kd.kd-vpn #k310scrim{display:none!important}
/* ---- users: two columns of slim cards ---- */
body.kd .uchips{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:10px!important}
body.kd .uchip.kd-u{position:relative;display:flex;flex-direction:column;align-items:stretch;gap:7px;padding:10px 12px!important;border-radius:15px;text-align:start;transition:transform .3s,border-color .3s}
body.kd .uchip.kd-u:hover{transform:translateY(-2px)}
body.kd .uchip.kd-u.on{border-color:color-mix(in srgb,var(--ok) 35%,transparent)}
.kd-un{display:flex;align-items:center;gap:8px;min-width:0}
body.kd .uchip.kd-u .nm{flex:1;min-width:0;white-space:normal!important;overflow:visible!important;text-overflow:clip!important;overflow-wrap:anywhere;font-weight:800;font-size:13.5px;line-height:1.35}
.kd-meta{display:flex;justify-content:space-between;gap:4px 10px;flex-wrap:wrap;font-size:11.5px;font-weight:600;color:var(--s)}
.kd-meta b{color:var(--t);font-weight:800}
.uchip.st-finished .kd-meta span:last-child b,.uchip.st-disabled .kd-meta span:last-child b{color:var(--bad)}
.k310bar.hot~.kd-meta span:first-child b{color:var(--bad)}.k310bar.warm~.kd-meta span:first-child b{color:var(--warn)}
@media(prefers-reduced-motion:reduce){#pg.kd-enter *,body.kd .msheet.k38sheet.on,body.kd .msheet.k38sheet.on .k38tile{animation:none!important}
 body.kd nav.side a.kd-it,.kd-gb,.kd-chev{transition:none!important}body.kd .kd-it.on::after,body.kd .kd-tn.on::after,body.kd .kd-rail .stl a.on::after,body.kd.kd-vpn .kxl>.kxr.open>.kxr-h::after,body.kd .k310st::after{animation:none}}
`;
var st=document.createElement('style');st.id='kdcss';st.textContent=css;document.head.appendChild(st);
look();
})();
