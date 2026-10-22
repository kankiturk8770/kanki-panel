// Kanki Panel 3.8: the AMOLED look. Loaded after kanki-v37.js, it changes how the panel looks and how
// the menu is grouped, never how a page works:
//  - pure black (night) and pure white (day), gold or purple, picked from four dots in the top bar
//  - 3D glass buttons with a soft moving shine
//  - the menu in groups of things that belong together (customers, servers and network, services,
//    reports, system); Servers and Tunnel servers are tabs of one section
//  - phones: a tab bar at the bottom (home, users, servers, services, more) and a sheet with the rest
//  - the dashboard gets a row of quick actions
(function(){
'use strict';
var V=window.V37;if(!V)return;
var FA38={"Home":"خانه","Customers":"مشتری‌ها","Servers & network":"سرورها و شبکه","Services":"سرویس‌ها","Reports":"گزارش","More":"بیشتر",
 "Abroad":"خارج","Iran":"ایران","All":"همه","VPN server":"سرور VPN","DNS exit":"خروجی DNS","DNS relay":"واسط DNS","No service on this server yet":"هنوز سرویسی روی این سرور نیست",
 "No server here":"سروری در این دسته نیست","Quick actions":"کارهای سریع","New user":"کاربر جدید","Add server":"افزودن سرور","Sales bot":"ربات فروش","Backup":"بکاپ",
 "Gold · night":"طلایی · شب","Gold · day":"طلایی · روز","Purple · night":"بنفش · شب","Purple · day":"بنفش · روز","Panel color":"رنگ پنل"};
function fa(){if(typeof FA!='undefined')Object.assign(FA,FA38)}
fa();

// ---------------------------------------------------------------- menu: groups of what belongs together
// [section key, label, icon, [[page, sub page, tab label], ...], group]
var SECS=[
 ['dash','Dashboard','dash',[['dash','','Dashboard']],'Home'],
 ['users','Users','users',[['users','','Users']],'Customers'],
 ['bot','Sales bot','bot',[['bot','','Sales bot']],'Customers'],
 ['emergency','Emergency chat','sos',[['emergency','','Emergency chat']],'Customers'],
 ['nodes','Servers','nodes',[['nodes','','Servers'],['servers','','Tunnel servers']],'Servers & network'],
 ['netsec','Tunnels','tunnel',[['tunnels','','Tunnels']],'Servers & network'],
 ['ports','Ports','ports',[['ports','','Ports']],'Servers & network'],
 ['vpnsec','VPN services','shield2',[['vpn','','Overview'],['kmix','','KANKI MIX'],['xray','','Xray'],['antidpi','','Anti-DPI']],'Services'],
 ['dnssec','Kanki DNS','dns',[['dns','','Kanki DNS']],'Services'],
 ['traffic','Traffic & stats','traffic',[['traffic','','Traffic & stats']],'Reports'],
 ['syssec','System','settings',[['settings','','Settings'],['security','','Security'],['backup','','Backup']],'System']];
V.SECS.length=0;SECS.forEach(function(s){V.SECS.push(s)});
window.NAV=SECS.map(function(s){return {p:s[3][0][0],sec:s[0]}});
function secBy(k){for(var i=0;i<SECS.length;i++)if(SECS[i][0]==k)return SECS[i];return SECS[0]}
window.grpOf=function(p){return V.secOf(p)[4]||''};
ICO.more38='<circle cx="5" cy="12" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="19" cy="12" r="1.7"/>';

window.navSide=function(){var g='',h='';
 SECS.forEach(function(s){if(s[4]!=g){g=s[4];h+='<div class="ngt">'+t(g)+'</div>'}var f=s[3][0];
  h+='<a href="#'+f[0]+'" data-p="'+f[0]+'" data-sec="'+s[0]+'"><span class="ni">'+ic(s[2],18)+'</span>'+t(s[1])+'</a>'});return h};

// phones: four tabs and "more"
var BAR=[['dash','Home'],['users','Users'],['nodes','Servers'],['vpnsec','Services']];
window.navBar=function(){
 return '<div class="mbar k38bar" id="mbar">'+BAR.map(function(b){var s=secBy(b[0]),f=s[3][0];
  return '<a href="#'+f[0]+'" data-p="'+f[0]+'" data-sec="'+s[0]+'">'+ic(s[2],21)+'<span>'+t(b[1])+'</span></a>'}).join('')+
  '<button type="button" id="mmore" onclick="k38More()">'+ic('more38',21)+'<span>'+t('More')+'</span></button></div>'+
  '<div class="k38scrim" id="k38scrim" onclick="k38More(0)"></div><div class="msheet k38sheet" id="msheet"></div>'};
function sheetHtml(){var g='',h='<i class="k38grab"></i>',open=false;
 SECS.forEach(function(s){if(s[4]!=g){if(open)h+='</div>';g=s[4];h+='<div class="k38g">'+t(g)+'</div><div class="k38tiles">';open=true}var f=s[3][0];
  h+='<a class="k38tile'+(V.secOf(S.page)[0]==s[0]?' on':'')+'" href="#'+f[0]+'">'+ic(s[2],22)+'<span>'+t(s[1])+'</span></a>'});
 return h+(open?'</div>':'')}
window.k38More=function(on){var sh=$('#msheet'),sc=$('#k38scrim');if(!sh)return;if(on===undefined)on=!sh.classList.contains('on');
 if(on)sh.innerHTML=sheetHtml();sh.classList.toggle('on',!!on);if(sc)sc.classList.toggle('on',!!on)};
window.navSheet=function(){};
var _nm=window.navMark;
window.navMark=function(p){_nm.apply(this,arguments);var sk=V.secOf(p)[0],mb=$('#mmore');
 if(mb)mb.classList.toggle('on',!BAR.some(function(b){return b[0]==sk}));k38More(0)};

// ---------------------------------------------------------------- the four looks
var LOOKS=[['gold','dark','Gold · night','#000','#f5c518'],['gold','light','Gold · day','#fff','#f2b705'],['violet','dark','Purple · night','#000','#9d63ff'],['violet','light','Purple · day','#fff','#8b4dff']];
function looksHtml(){return LOOKS.map(function(l,i){var on=(S.color||'gold')==l[0]&&(S.theme||'dark')==l[1];
 return '<button type="button" data-lk="'+i+'" class="'+(on?'on':'')+'" title="'+t(l[2])+'" aria-label="'+t(l[2])+'"><i style="background:linear-gradient(135deg,'+l[3]+' 50%,'+l[4]+' 50%)"></i></button>'}).join('')}
function drawLooks(){$$('.k38looks').forEach(function(b){b.innerHTML=looksHtml()})}
document.addEventListener('click',function(e){var b=e.target.closest&&e.target.closest('[data-lk]');if(!b)return;var l=LOOKS[+b.dataset.lk];
 S.color=l[0];S.theme=l[1];try{localStorage.setItem('kk_color',S.color);localStorage.setItem('kk_theme',S.theme)}catch(x){}applyLook()});
var _al=window.applyLook;
window.applyLook=function(){_al.apply(this,arguments);document.body.classList.add('k38');if($('#side'))document.body.classList.add('v37');drawLooks()};
var _sh=window.shell;
window.shell=function(){_sh.apply(this,arguments);document.body.classList.add('k38');
 var thm=$('#thm');if(thm&&!$('.tb-act .k38looks')){var d=document.createElement('div');d.className='k38looks';d.setAttribute('role','group');d.setAttribute('aria-label',t('Panel color'));thm.parentNode.insertBefore(d,thm)}
 drawLooks()};

// ---------------------------------------------------------------- dashboard: quick actions
if(window.pDash){var _pd=window.pDash;window.pDash=function(){_pd.apply(this,arguments);var ph=$('#pg .ph');if(!ph||$('#k38qa'))return;
 var d=document.createElement('div');d.className='k38qa';d.id='k38qa';
 d.innerHTML='<b>'+t('Quick actions')+'</b><div class="k38qb"><button class="btn" onclick="newUser()">'+ic('plus',16)+' '+t('New user')+'</button>'+
  '<button class="b2" onclick="(window.nodeAddTyped||nodeAdd)()">'+ic('nodes',16)+' '+t('Add server')+'</button>'+
  '<a class="b2" href="#bot">'+ic('bot',16)+' '+t('Sales bot')+'</a><a class="b2" href="#backup">'+ic('backup',16)+' '+t('Backup')+'</a></div>';
 ph.parentNode.insertBefore(d,ph.nextSibling)}}

// ---------------------------------------------------------------- the look
var css=`
html:has(body.k38){background:#000}html:has(body.k38.light){background:#fff}
body.k38{--bg1:#000;--bg2:#000;--c1:#0b0b0b;--c2:#090909;--in:rgba(255,255,255,.045);--ln:rgba(255,255,255,.09);--ln2:rgba(255,255,255,.07);--t:#f5f5f2;--s:#a3a39b;
 --g1:rgba(255,255,255,.035);--g2:rgba(255,255,255,.012);--gb:rgba(255,255,255,.085);--gb2:rgba(255,255,255,.15);--gl:inset 0 1px 0 rgba(255,255,255,.06);--on:#140f00;background:#000!important}
body.k38.light{--bg1:#fff;--bg2:#fff;--c1:#fff;--c2:#f7f7f5;--in:rgba(10,10,10,.035);--ln:rgba(10,10,10,.1);--ln2:rgba(10,10,10,.07);--t:#0a0a0a;--s:#5c5c56;
 --g1:#fff;--g2:#fbfbfa;--gb:rgba(10,10,10,.09);--gb2:rgba(10,10,10,.16);--gl:inset 0 1px 0 #fff;background:#fff!important}
body.k38:not([class*="c-"]){--a:#f5c518;--al:#ffe066;--ad:#d19a00}
body.k38.light:not([class*="c-"]){--a:#f2b705;--al:#ffd84d;--ad:#8f6800}
body.k38.c-violet{--a:#9d63ff;--al:#c7a3ff;--ad:#7236f0;--on:#fff}
body.k38.light.c-violet{--a:#8b4dff;--al:#b48bff;--ad:#5b21d6}
body.k38:before{background:radial-gradient(900px 420px at 100% -8%,color-mix(in srgb,var(--a) 7%,transparent),transparent 70%)!important}
body.k38:after{display:none!important}
/* surfaces: flat AMOLED cards with a thin edge */
body.k38 .card,body.k38 .kv>div,body.k38 .ibc,body.k38 .secc{background:var(--c1)!important;border:1px solid var(--gb)!important;box-shadow:var(--gl)!important;border-radius:18px}
body.k38.light .card,body.k38.light .kv>div,body.k38.light .ibc,body.k38.light .secc{box-shadow:0 1px 2px rgba(0,0,0,.04),0 10px 26px -18px rgba(0,0,0,.18)!important}
body.k38 nav.side{background:var(--c1)!important;border-inline-end:1px solid var(--gb)!important}
body.k38 header.top{background:color-mix(in srgb,var(--bg1) 80%,transparent)!important}
body.k38 .mbox{background:var(--c1)!important}
/* 3D glass buttons */
body.k38 .btn{color:var(--on)!important;border:1px solid var(--ad)!important;background:linear-gradient(180deg,var(--al) 0%,var(--a) 48%,var(--ad) 100%)!important;
 box-shadow:inset 0 1px 0 rgba(255,255,255,.6),inset 0 -3px 0 rgba(0,0,0,.16),0 8px 22px -8px color-mix(in srgb,var(--a) 70%,transparent),0 2px 0 var(--ad)!important}
body.k38 .btn:before{inset:1px 1px 50% 1px;border-radius:13px 13px 40% 40%/13px 13px 10px 10px;background:linear-gradient(180deg,rgba(255,255,255,.5),rgba(255,255,255,.04))}
body.k38 .btn:after{left:auto;right:-60%;transition:none;animation:k38sheen 4.2s ease-in-out infinite}
body.k38 .btn:hover:not(:disabled):after{left:auto}
body.k38 .btn:active:not(:disabled){transform:translateY(2px);box-shadow:inset 0 1px 0 rgba(255,255,255,.4),inset 0 -1px 0 rgba(0,0,0,.2),0 3px 10px -4px color-mix(in srgb,var(--a) 60%,transparent)!important}
@keyframes k38sheen{0%,62%{right:-60%}100%{right:130%}}
body.k38 .b2,body.k38 .ib,body.k38 .sb{position:relative;overflow:hidden;background:linear-gradient(180deg,rgba(255,255,255,.12),rgba(255,255,255,.03) 55%)!important;
 box-shadow:inset 0 1px 0 rgba(255,255,255,.16),inset 0 -2px 0 rgba(0,0,0,.5),0 6px 16px -10px rgba(0,0,0,.8)!important}
body.k38.light .b2,body.k38.light .ib,body.k38.light .sb{background:linear-gradient(180deg,#fff,#f3f3f1)!important;box-shadow:inset 0 1px 0 #fff,inset 0 -2px 0 rgba(0,0,0,.06),0 4px 12px -8px rgba(0,0,0,.25)!important}
body.k38 .b2:active:not(:disabled),body.k38 .ib:active{transform:translateY(1px)}
body.k38 .sectabs .sti,body.k38 .sectabs .stl a.on,body.k38 .ptabs a.on,body.k38 .seg button.on,body.k38 .segl button.on{color:var(--on)!important}
body.k38 .sectabs{background:color-mix(in srgb,var(--bg1) 82%,transparent)}
body.k38 input:focus,body.k38 select:focus,body.k38 textarea:focus{border-color:var(--a)!important;box-shadow:0 0 0 3px color-mix(in srgb,var(--a) 18%,transparent)!important}
@media(prefers-reduced-motion:reduce){body.k38 .btn:after{animation:none;display:none}}
/* menu groups */
body.k38 nav.side .ngt{font-size:11px;font-weight:800;color:var(--s);padding:12px 12px 4px;letter-spacing:.2px}
body.k38 nav.side .ngt:first-child{padding-top:2px}
body.k38 nav.side a.on{background:linear-gradient(180deg,color-mix(in srgb,var(--a) 16%,transparent),color-mix(in srgb,var(--a) 4%,transparent))!important;box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--a) 22%,transparent)}
/* the four looks in the top bar */
.k38looks{display:flex;gap:3px;padding:3px;border-radius:13px;background:var(--in);border:1px solid var(--gb)}
.k38looks button{width:28px;height:28px;border-radius:9px;border:0;background:transparent;display:grid;place-items:center;cursor:pointer;padding:0}
.k38looks button.on{background:var(--c1);box-shadow:0 0 0 1px var(--gb2),0 2px 6px rgba(0,0,0,.25)}
.k38looks i{width:15px;height:15px;border-radius:50%;box-shadow:inset 0 0 0 1px rgba(128,128,128,.45)}
body.k38 #thm{display:none}
/* dashboard quick actions */
.k38qa{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin:0 0 16px;padding:12px 14px;border-radius:18px;border:1px solid var(--gb);background:var(--c1)}
.k38qa>b{font-size:13.5px}.k38qb{display:flex;gap:8px;flex-wrap:wrap;flex:1;justify-content:flex-end}
.k38qb .btn,.k38qb .b2{display:inline-flex;align-items:center;gap:6px;text-decoration:none;color:var(--t)}
/* servers: one card per server */
.sgf{display:flex;gap:6px;flex-wrap:wrap;margin-top:12px}
.sgf button{display:inline-flex;align-items:center;gap:6px;height:34px;padding:0 14px;border-radius:11px;border:1px solid var(--gb);background:var(--in);color:var(--t);font:inherit;font-weight:700;font-size:12.5px;cursor:pointer}
.sgf button b{font-size:11px;color:var(--s)}
.sgf button.on{color:var(--on);border-color:var(--ad);background:linear-gradient(180deg,var(--al),var(--a));box-shadow:inset 0 1px 0 rgba(255,255,255,.5),0 4px 12px -6px color-mix(in srgb,var(--a) 70%,transparent)}
.sgf button.on b{color:var(--on);opacity:.7}
.sgcards{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));align-items:start;gap:12px;margin-top:12px}
.sgc{display:flex;flex-direction:column;gap:10px;padding:12px;border-radius:16px;border:1px solid var(--gb);background:var(--in);min-width:0}
.sgc .sgn{background:transparent;border:0;padding:0}
.sgr2{display:flex;gap:5px;flex-wrap:wrap}
.sgr2 span{font-size:11px;font-weight:700;padding:2px 8px;border-radius:7px;background:var(--c1);border:1px solid var(--gb);color:var(--s)}
.sgcells{display:grid;grid-template-columns:repeat(auto-fill,minmax(96px,1fr));gap:6px}
/* phones: bottom tab bar and a sheet with the rest */
@media(max-width:1099px){
 body.k38 .mbar.k38bar{position:fixed;top:auto;bottom:0;left:0;right:0;z-index:40;overflow:visible;gap:2px;padding:6px max(10px,env(safe-area-inset-right,0px)) calc(6px + env(safe-area-inset-bottom,0px)) max(10px,env(safe-area-inset-left,0px));
  background:color-mix(in srgb,var(--c1) 90%,transparent);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-top:1px solid var(--gb);border-bottom:0}
 body.k38 .mbar.k38bar a,body.k38 .mbar.k38bar button{flex:1;flex-direction:column;gap:2px;justify-content:center;padding:6px 0;border:0;background:transparent;color:var(--s);font-size:10.5px;border-radius:12px}
 body.k38 .mbar.k38bar svg{color:inherit}
 body.k38 .mbar.k38bar .on{color:var(--a);background:transparent}
 body.k38.light .mbar.k38bar .on{color:var(--ad)}
 body.k38 .mbar.k38bar .on svg{color:inherit;filter:drop-shadow(0 2px 6px color-mix(in srgb,var(--a) 60%,transparent))}
 body.k38 main{padding-bottom:calc(90px + env(safe-area-inset-bottom,0px))!important}
 body.k38 .sectabs{top:64px}
 .k38scrim.on{display:block;position:fixed;inset:0;z-index:44;background:rgba(0,0,0,.5)}
 body.k38 .msheet.k38sheet{top:auto;bottom:0;left:0;right:0;inset-inline:0;z-index:45;max-height:80vh;border:1px solid var(--gb2);border-bottom:0;border-radius:22px 22px 0 0;background:var(--c1);
  padding:12px max(16px,env(safe-area-inset-right,0px)) calc(18px + env(safe-area-inset-bottom,0px)) max(16px,env(safe-area-inset-left,0px))}
}
@media(max-width:560px){body.k38 .sectabs{top:56px}}
.k38scrim{display:none}
.k38grab{display:block;width:44px;height:5px;border-radius:5px;background:var(--gb2);margin:0 auto 10px}
.k38g{font-size:11px;font-weight:800;color:var(--s);margin:10px 2px 6px}
.k38tiles{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}
.k38tile{display:flex;flex-direction:column;align-items:center;gap:6px;padding:12px 6px;border-radius:14px;background:var(--in);border:1px solid var(--gb);color:var(--t);text-decoration:none;font-size:11.5px;font-weight:700;text-align:center}
.k38tile svg{color:var(--a)}body.k38.light .k38tile svg{color:var(--ad)}
.k38tile.on{border-color:var(--a);box-shadow:inset 0 0 0 1px var(--a)}
@media(max-width:620px){body.k38 header.top .segl{display:none}.k38looks button{width:24px;height:24px}.k38looks i{width:13px;height:13px}.k38qb{justify-content:flex-start}}
`;
var st=document.createElement('style');st.id='k38css';st.textContent=css;document.head.appendChild(st);
})();
