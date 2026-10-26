// Kanki Panel 3.10: the polished look. Loaded last (after kanki-look.js), it changes how the panel looks,
// never how a page works:
//  - a new sign-in screen: glow behind a glass card, the panel name and a short line under the logo
//  - dashboard numbers: a colored edge and an icon per number, bigger digits
//  - every user tile shows how much data is used (a bar) and the days left, not only the name
//  - softer cards with a light top edge, a lift on hover, a clear focus ring for the keyboard
//  - no motion for those who ask their system for less motion
(function(){
'use strict';
if(typeof FA!='undefined')Object.assign(FA,{"VPN management panel":"پنل مدیریت VPN","Sign in to continue":"برای ادامه وارد شو",
 "Light / dark":"روشن / تیره","Language":"زبان","left":"مانده","Unlimited data":"حجم نامحدود","Disabled":"غیرفعال"});

Object.assign(ICO,{
 k310sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4"/>',
 k310online:'<path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 15.8a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.2"/>',
 k310ok:'<circle cx="12" cy="12" r="8.5"/><path d="M8.5 12.3l2.4 2.4 4.6-4.9"/>',
 k310warn:'<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5.2l3 1.8"/>',
 k310off:'<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
 k310traffic:'<path d="M7 4v14M3.5 14.5L7 18l3.5-3.5"/><path d="M17 20V6M13.5 9.5L17 6l3.5 3.5"/>'});

// ---------------------------------------------------------------- sign-in screen
var _lv=window.loginView;
window.loginView=function(){_lv.apply(this,arguments);
 var l=$('.login');if(!l)return;l.classList.add('k310login');
 var c=l.querySelector('.card'),h=c&&c.querySelector('h3');
 if(h){h.removeAttribute('style');h.insertAdjacentHTML('afterend','<p class="k310sub">'+t('Sign in to continue')+'</p>')}
 var lt=$('#lt');if(lt){lt.innerHTML=ic(document.body.classList.contains('light')?'moon':'k310sun',17);lt.title=t('Light / dark');lt.setAttribute('aria-label',t('Light / dark'));
  var o=lt.onclick;lt.onclick=function(){o.apply(this,arguments);lt.innerHTML=ic(document.body.classList.contains('light')?'moon':'k310sun',17)}}
 var ll=$('#ll');if(ll){ll.title=t('Language');ll.setAttribute('aria-label',t('Language'))}
 l.insertAdjacentHTML('afterbegin','<i class="k310orb a"></i><i class="k310orb b"></i>');
 var lg=l.querySelector('.logo');if(lg)lg.insertAdjacentHTML('afterend','<div class="k310brand">'+t('VPN management panel')+'</div>')};

// ---------------------------------------------------------------- user tiles: data used and days left
function daysLeft(u){var d=Math.ceil((u.expires_ts-Date.now()/1000)/86400);return d<=0?t('Expired'):N(d)+' '+t('days left')}
window.uchip=function(u){var st=ustate(u),lv=liveOf(u),on=u.online_connections>0||lv.length>0,dot=st=='disabled'?'r':st=='finished'?'y':(on?'g':''),ps=[];
 lv.forEach(function(c){if(ps.indexOf(c.p)<0)ps.push(c.p)});
 var tip=u.username+(lv.length?'\n'+lv.map(function(c){return pname(c.p)+' · '+c.s}).join('\n'):''),pc=usage(u),
  bar=pc<0?'<span class="k310bar inf"><i></i></span>':'<span class="k310bar'+(pc>=90?' hot':pc>=70?' warm':'')+'"><i style="width:'+Math.max(3,pc)+'%"></i></span>',
  data=pc<0?N((+u.traffic_used_gb||0).toFixed(1))+' GB · '+t('Unlimited data'):N((+u.traffic_used_gb||0).toFixed(1))+' / '+N(u.traffic_limit_gb)+' GB',
  days=st=='disabled'?t('Disabled'):u.expires_ts?daysLeft(u):'∞';
 return '<button class="uchip k310u st-'+st+(on?' on':'')+(S.sel[u.id]?' sel':'')+'" data-id="'+u.id+'" title="'+esc(tip)+'">'+
  '<span class="k310top"><span class="dot '+dot+'"></span><span class="nm">'+esc(u.username)+'</span>'+
  (ps.length?'<span class="lvs">'+ps.slice(0,3).map(function(p){return '<i style="--pc:'+(PCOL[p]||'#888')+'">'+liveShort(p)+'</i>'}).join('')+'</span>':'')+
  '<span class="tick">'+ic('check',13)+'</span></span>'+bar+
  '<span class="k310meta"><span class="ltr">'+data+'</span><span>'+days+'</span></span></button>'};

// ---------------------------------------------------------------- dashboard numbers: an icon per number
var KICO={all:'users',online:'k310online',active:'k310ok',finished:'k310warn',disabled:'k310off'};
function kpiIcons(){$$('#kpis .kpi').forEach(function(k){if(k.querySelector('.k310ki'))return;
 k.insertAdjacentHTML('afterbegin','<span class="k310ki">'+ic(KICO[k.dataset.go]||'k310traffic',18)+'</span>')})}
new MutationObserver(function(){if($('#kpis'))kpiIcons()}).observe(document.body,{childList:true,subtree:true});

var css=`
/* sign-in */
.k310login{position:relative;max-width:400px;margin:0 auto;min-height:100vh;min-height:100dvh;display:flex;flex-direction:column;justify-content:center;padding:32px 16px}
.k310login .logo{position:relative;z-index:1;width:72px;height:72px;margin:0 auto 10px;border-radius:22px;box-shadow:0 18px 50px -12px color-mix(in srgb,var(--a) 65%,transparent)}
.k310brand{position:relative;z-index:1;text-align:center;font-size:12.5px;font-weight:700;color:var(--s);margin-bottom:18px;letter-spacing:.2px}
.k310login .card{position:relative;z-index:1;padding:26px 24px 20px;border-radius:24px;border:1px solid var(--gb2,var(--ln));
 background:linear-gradient(180deg,color-mix(in srgb,var(--c1) 82%,transparent),color-mix(in srgb,var(--c2) 92%,transparent))!important;
 backdrop-filter:blur(20px) saturate(140%);-webkit-backdrop-filter:blur(20px) saturate(140%);
 box-shadow:inset 0 1px 0 rgba(255,255,255,.08),0 30px 80px -30px rgba(0,0,0,.9),0 0 0 1px color-mix(in srgb,var(--a) 10%,transparent)!important}
body.light .k310login .card{box-shadow:inset 0 1px 0 #fff,0 30px 70px -34px rgba(60,40,0,.35)!important}
.k310login .card h3{justify-content:center;font-size:20px;margin:0}
.k310sub{text-align:center;margin:6px 0 10px;font-size:12.5px;color:var(--s)}
.k310login input{height:46px;font-size:14px}
.k310login .btn{height:48px;font-size:15px;font-weight:800;margin-top:20px!important;border-radius:14px}
.k310login .ib{width:40px;height:40px;display:inline-grid;place-items:center}
.k310orb{position:fixed;z-index:0;pointer-events:none;border-radius:50%;filter:blur(70px);opacity:.55}
.k310orb.a{width:420px;height:420px;top:-120px;inset-inline-end:-80px;background:radial-gradient(circle,color-mix(in srgb,var(--a) 55%,transparent),transparent 65%)}
.k310orb.b{width:360px;height:360px;bottom:-140px;inset-inline-start:-100px;background:radial-gradient(circle,color-mix(in srgb,var(--ad) 45%,transparent),transparent 65%);opacity:.4}
body.light .k310orb{opacity:.35}

/* cards: a light top edge and a soft depth */
body.k38 .card{border-radius:20px;background:linear-gradient(180deg,color-mix(in srgb,var(--t) 3.5%,var(--c1)),var(--c2))!important;
 box-shadow:inset 0 1px 0 color-mix(in srgb,var(--t) 7%,transparent),0 20px 44px -30px rgba(0,0,0,.9)!important}
body.k38.light .card{box-shadow:inset 0 1px 0 #fff,0 16px 36px -28px rgba(0,0,0,.28)!important}

/* dashboard numbers */
body.k38 .kpis{gap:12px;grid-template-columns:repeat(2,minmax(0,1fr))}
@media(min-width:600px){body.k38 .kpis{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(min-width:1280px){body.k38 .kpis{grid-template-columns:repeat(6,minmax(0,1fr))}}
body.k38 .kpi{position:relative;overflow:hidden;display:grid;grid-template-columns:auto 1fr;grid-template-rows:auto auto;column-gap:12px;row-gap:2px;align-items:center;
 text-align:start;padding:16px 16px 15px;border-radius:18px;cursor:pointer;--kc:var(--a);
 transition:transform .18s ease,border-color .18s,box-shadow .18s}
body.k38 .kpi.g{--kc:var(--ok)}body.k38 .kpi.y{--kc:var(--warn)}body.k38 .kpi.r{--kc:var(--bad)}
body.k38 .kpi:before{content:"";position:absolute;inset:0 0 auto;height:2px;background:linear-gradient(90deg,transparent,var(--kc),transparent);opacity:.8}
body.k38 .kpi:after{content:"";position:absolute;width:140px;height:140px;top:-70px;inset-inline-start:-40px;border-radius:50%;pointer-events:none;
 background:radial-gradient(circle,color-mix(in srgb,var(--kc) 22%,transparent),transparent 70%)}
body.k38 .kpi .k310ki{grid-row:1/3;width:40px;height:40px;border-radius:13px;display:grid;place-items:center;color:var(--kc);
 background:color-mix(in srgb,var(--kc) 13%,transparent);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--kc) 26%,transparent)}
body.k38 .kpi small{grid-column:2;font-size:12px;font-weight:700;color:var(--s);margin:0;white-space:normal;overflow:visible;line-height:1.5}
body.k38 .kpi b{grid-column:2;white-space:nowrap;font-size:clamp(18px,1.7vw,24px);font-weight:900;line-height:1.15;color:var(--kc);font-variant-numeric:tabular-nums;text-align:start}
body.k38 .kpi:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--kc) 45%,transparent)!important;box-shadow:0 16px 34px -20px color-mix(in srgb,var(--kc) 55%,transparent)!important}

/* user tiles */
body.k38 .uchips{grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:10px}
body.k38 .uchip.k310u{flex-direction:column;align-items:stretch;gap:9px;padding:13px 14px 12px;border-radius:16px;transition:transform .18s ease,border-color .18s,box-shadow .18s}
body.k38 .uchip.k310u:hover{transform:translateY(-2px)}
body.k38 .uchip.k310u.on{border-color:color-mix(in srgb,var(--ok) 35%,transparent)}
.k310top{display:flex;align-items:center;gap:8px;min-width:0}
.k310top .nm{font-weight:800;font-size:13.5px}
.k310bar{display:block;height:6px;border-radius:6px;background:color-mix(in srgb,var(--t) 8%,transparent);overflow:hidden}
.k310bar i{display:block;height:100%;border-radius:inherit;background:linear-gradient(to left,var(--a),var(--ad))}
html[dir=ltr] .k310bar i{background:linear-gradient(to right,var(--a),var(--ad))}
.k310bar.inf i{width:100%;opacity:.28;background:repeating-linear-gradient(135deg,var(--a) 0 6px,transparent 6px 12px)}
.k310bar.warm i{background:var(--warn)}.k310bar.hot i{background:var(--bad)}
.k310meta{display:flex;justify-content:space-between;gap:8px;font-size:11.5px;font-weight:600;color:var(--s);white-space:nowrap}
.k310meta span{overflow:hidden;text-overflow:ellipsis}
.uchip.st-finished .k310meta span:last-child{color:var(--warn)}
body.light .uchip.st-finished .k310meta span:last-child{color:#a35f00}
@media(max-width:430px){body.k38 .uchips{grid-template-columns:1fr 1fr}.k310meta{flex-direction:column;gap:2px}}

/* keyboard focus, everywhere */
body.k38 :is(button,a,.kpi,.uchip,select,input,textarea):focus-visible{outline:2px solid var(--a);outline-offset:2px}

@media(prefers-reduced-motion:reduce){body.k38 .kpi,body.k38 .uchip.k310u{transition:none}body.k38 .kpi:hover,body.k38 .uchip.k310u:hover{transform:none}}
`;
var st=document.createElement('style');st.id='k310css';st.textContent=css;document.head.appendChild(st);
// the sign-in screen may already be drawn before this file ran
if($('.login')&&!$('.k310login'))loginView(!($('#otpw')||{classList:{contains:function(){return true}}}).classList.contains('hide'));
})();
