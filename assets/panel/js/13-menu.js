// ==================================================================== menu and sections
// the shell: a short menu of sections; a section with several pages shows them as tabs at the top.
// Also here: country flags, the AI writer of the smart channel, moving the panel to a new server.
(function(){
'use strict';

// ---------------------------------------------------------------- sections and menu
// [section key, label, icon, [[page, sub page, tab label], ...], menu group]
var SECS=[
 ['dash','Dashboard','dash',[['dash','','Dashboard']],'Home'],
 ['users','Users','users',[['users','','Users']],'Customers'],
 ['bot','Sales bot','bot',[['bot','','Sales bot']],'Customers'],
 ['emergency','Emergency chat','sos',[['emergency','','Emergency chat']],'Customers'],
 ['nodes','Servers','nodes',[['nodes','','Servers']],'Servers & network'],
 ['netsec','Tunnels','tunnel',[['tunnels','','Tunnels']],'Servers & network'],
 ['ports','Ports','ports',[['ports','','Ports']],'Servers & network'],
 ['vpnsec','Cores','cores',[['vpn','','Overview'],['kmix','','KANKI MIX'],['mtun','','microtun'],['kping','','KPING'],['xray','status','Xray'],['wg','','WireGuard'],['awg','','AmneziaWG'],['hy2','','Hysteria2'],['antidpi','','Anti-DPI']],'Services'],
 ['dnssec','Kanki DNS','dns',[['dns','','Kanki DNS']],'Services'],
 ['traffic','Traffic & stats','traffic',[['traffic','','Traffic & stats']],'Reports'],
 ['syssec','System','settings',[['settings','','Settings'],['security','','Security'],['backup','','Backup']],'System']];
function secOf(p){for(var i=0;i<SECS.length;i++)if(SECS[i][3].some(function(x){return x[0]==p}))return SECS[i];return SECS[0]}
window.V37={secOf:secOf,SECS:SECS,watchPg:watchPg,drawSecTabs:drawSecTabs};


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

// ---------------------------------------------------------------- flags
function flag(cc){cc=String(cc||'').toUpperCase();if(!/^[A-Z]{2}$/.test(cc))return '<span class="flg nf" title="?">🌐</span>';
 return '<span class="flg" title="'+cc+'">'+String.fromCodePoint(0x1F1E6+cc.charCodeAt(0)-65,0x1F1E6+cc.charCodeAt(1)-65)+'</span>'}
window.flagOf=flag;


// ---------------------------------------------------------------- the look

})();

// ==================================================================== phone bar, night/day
// the look: night (pure black) and day (pure white) from one button in the top bar, the menu in
// groups, and on phones a bar of every section at the bottom.
(function(){
'use strict';
var V=V37;

// ---------------------------------------------------------------- menu: groups of what belongs together
// [section key, label, icon, [[page, sub page, tab label], ...], group]
function secBy(k){for(var i=0;i<V.SECS.length;i++)if(V.SECS[i][0]==k)return V.SECS[i];return V.SECS[0]}
window.grpOf=function(p){return V.secOf(p)[4]||''};


// phones: every section in the bottom bar, swiped sideways, in this order from the right
var BAR=[['dash','Home'],['users','Users'],['nodes','Servers'],['netsec','Tunnels'],['vpnsec','VPN services'],['dnssec','Kanki DNS'],['bot','Sales bot'],['emergency','Emergency chat'],['ports','Ports'],['traffic','Traffic & stats'],['syssec','System']];
window.navBar=function(){
 return '<div class="mbar k38bar k39bar" id="mbar">'+BAR.map(function(b){var s=secBy(b[0]),f=s[3][0];
  return '<a href="#'+f[0]+'" data-p="'+f[0]+'" data-sec="'+s[0]+'">'+ic(s[2],21)+'<span>'+t(b[1])+'</span></a>'}).join('')+'</div>'+
  '<div class="k38scrim" id="k38scrim" onclick="k38More(0)"></div><div class="msheet k38sheet" id="msheet"></div>'};


// ---------------------------------------------------------------- night / day in the top bar
// The top bar has only one button: night or day. The panel's colors are chosen in Settings ›
// Look, not in the bar.
function drawLooks(){var b=$('#thm');if(!b)return;var night=(S.theme||'dark')!='light';
 b.innerHTML=ic(night?'sun38':'moon',17)+'<span>'+t(night?'Day':'Night')+'</span>';b.title=t(night?'Day':'Night');b.setAttribute('aria-label',b.title);b.classList.add('k38dn')}
V.drawLooks=drawLooks;


// ---------------------------------------------------------------- the look
})();

