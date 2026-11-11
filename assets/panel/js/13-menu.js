// ==================================================================== menu and sections
// the shell: a short menu of sections; a section with several pages shows them as tabs at the top.
// Also here: country flags, the AI writer of the smart channel, moving the panel to a new server.
(function(){
'use strict';

// ---------------------------------------------------------------- sections and menu
// [section key, label, icon, [[page, sub page, tab label], ...], menu group]
// (3.41) the menu in six groups: what you look at, who uses it, how they connect, the machines,
// selling, and running the panel. The cores are one section: its tabs are the core bar (the eight
// cores side by side, DNS and KPING among them); the VPN overview opens it.
var SECS=[
 ['dash','Dashboard','dash',[['dash','','Dashboard']],'Overview'],
 ['users','Users','users',[['users','','Users']],'Users'],
 ['vpnsec','VPN & cores','cores',[['vpn','','Overview'],['wg','','WireGuard'],['awg','','AmneziaWG'],['hy2','','Hysteria2'],['kmix','','KANKI MIX'],['mtun','','microtun'],['xray','status','Xray'],['dns','','DNS'],['kping','','KPING']],'Connectivity'],
 ['netsec','Tunnels','tunnel',[['tunnels','','Tunnels']],'Connectivity'],
 ['ports','Ports','ports',[['ports','','Ports']],'Connectivity'],
 ['traffic','Traffic & stats','traffic',[['traffic','','Traffic & stats']],'Connectivity'],
 ['nodes','Servers','nodes',[['nodes','','Servers']],'Infrastructure'],
 ['bot','Sales bot','bot',[['bot','','Sales bot']],'Sales'],
 ['antidpi','Anti-DPI','security',[['antidpi','','Anti-DPI']],'Operations & System'],
 ['emergency','Emergency chat','sos',[['emergency','','Emergency chat']],'Operations & System'],
 ['backup','Backup','backup',[['backup','','Backup']],'Operations & System'],
 ['security','Security','shield2',[['security','','Security']],'Operations & System'],
 ['settings','Settings','settings',[['settings','','Settings']],'Operations & System']];
// the eight cores, the same weight each (the core bar)
var CORES=SECS[2][3].slice(1).map(function(x){return x[0]});
function secOf(p){for(var i=0;i<SECS.length;i++)if(SECS[i][3].some(function(x){return x[0]==p}))return SECS[i];return SECS[0]}
window.V37={secOf:secOf,SECS:SECS,CORES:CORES,watchPg:watchPg,drawSecTabs:drawSecTabs};

// ---------------------------------------------------------------- the core bar
// One row: «Overview» on its own, then the eight cores in one rail that scrolls inside itself
// (never the page) with a fade at the edge that has more; the open core is scrolled into sight.
function secTabsHtml(p){var s=secOf(p);if(s[3].length<2)return '';
 var ov=s[3][0],cur=function(x){return x[0]==p};
 return '<div class="kcb" id="sectabs" data-p="'+p+'"><a href="#'+ov[0]+'" class="kcb-ov'+(cur(ov)?' on':'')+'"'+(cur(ov)?' aria-current="page"':'')+'>'+ic(s[2],16)+'<span>'+t(ov[2])+'</span></a>'+
  '<div class="kcb-wrap"><div class="kcb-rail" role="tablist" aria-label="'+esc(t('Cores'))+'">'+
  s[3].slice(1).map(function(x){var on=cur(x);return '<a role="tab" href="#'+x[0]+(x[1]?'/'+x[1]:'')+'" data-core="'+x[0]+'" class="kcb-t'+(on?' on':'')+'" aria-selected="'+on+'" tabindex="'+(on||(p==ov[0]&&x[0]==CORES[0])?0:-1)+'"'+(on?' aria-current="page"':'')+'>'+
   '<i class="tdot" aria-hidden="true"></i><span>'+t(x[2])+'</span><em class="kcb-st"></em></a>'}).join('')+'</div></div></div>'}
function railEdges(r){var w=r.parentNode,max=r.scrollWidth-r.clientWidth,x=Math.abs(r.scrollLeft);
 w.classList.toggle('more-s',x>2);w.classList.toggle('more-e',x<max-2)}
function railShow(r){var a=r.querySelector('.on');if(!a)return;var rr=r.getBoundingClientRect(),ar=a.getBoundingClientRect();
 if(ar.left<rr.left+8||ar.right>rr.right-8)r.scrollLeft+=(ar.left+ar.width/2)-(rr.left+rr.width/2)}
function wireRail(el){var r=el.querySelector('.kcb-rail');if(!r)return;
 r.addEventListener('scroll',function(){railEdges(r)},{passive:true});
 r.addEventListener('keydown',function(e){var k=e.key,ts=$$('.kcb-t',r),i=ts.indexOf(document.activeElement);if(i<0)return;
  var rtl=document.documentElement.dir=='rtl',n=k=='ArrowRight'?(rtl?-1:1):k=='ArrowLeft'?(rtl?1:-1):0,j=k=='Home'?0:k=='End'?ts.length-1:n?Math.max(0,Math.min(ts.length-1,i+n)):-1;
  if(j<0)return;e.preventDefault();ts.forEach(function(x){x.tabIndex=-1});ts[j].tabIndex=0;ts[j].focus();
  try{ts[j].scrollIntoView({block:'nearest',inline:'nearest'})}catch(_){}});
 window.addEventListener('resize',function(){if(r.isConnected)railEdges(r)});
 requestAnimationFrame(function(){railShow(r);railEdges(r)})}
function drawSecTabs(p){var pg=$('#pg');if(!pg)return;var old=$('#sectabs'),h=secTabsHtml(p);
 if(!h){if(old)old.remove();return}
 if(old&&old.parentNode==pg&&pg.firstChild==old&&old.dataset.p==p)return;
 if(old)old.remove();var d=document.createElement('div');d.innerHTML=h;var el=d.firstChild;pg.insertBefore(el,pg.firstChild);
 wireRail(el);coreDots(el)}
// a live dot on each core: green running everywhere, yellow partly, red down, grey not set up
var CD={at:0,v:null},WORD={g:'Running',y:'Partly down',r:'Down',n:'Not set up'};
function coreDots(el){var draw=function(v){$$('.kcb-t',el).forEach(function(a){var st=v[a.dataset.core]||'n',i=a.querySelector('.tdot'),w=a.querySelector('.kcb-st');
  i.className='tdot '+st;w.textContent=t(WORD[st]);a.title=t(WORD[st])})};
 if(CD.v&&Date.now()-CD.at<20000)return draw(CD.v);
 Promise.all([api('GET','/api/nodes').catch(function(){return []}),api('GET','/api/xray').catch(function(){return null}),api('GET','/api/kping').catch(function(){return null}),api('GET','/api/dns').catch(function(){return null})]).then(function(r){
  var nodes=r[0]||[],up=function(n){return n.id=='local'||n.online},num=function(x){return x!=null&&x!==''&&+x>0};
  var st=function(k){var l=nodes.filter(function(n){return num((n.info||{})[k])}),u=l.filter(up).length;return !l.length?'n':u==l.length?'g':u?'y':'r'};
  var v={wg:st('wg_port'),awg:st('awg_port'),hy2:st('hy2_port'),kmix:st('kmix_port'),mtun:st('mt_port')};
  var xr=r[1];if(xr)v.xray=!xr.on?'r':xr.inbounds.some(function(x){return x.enabled&&!x.state})?'g':'y';
  var kp=r[2];if(kp&&kp.settings)v.kping=!kp.settings.on?'r':!kp.routes.length?'n':kp.routes.every(function(x){return x.exit_runs&&x.tunnel_up})?'g':'y';
  var dn=r[3];if(dn){var sv=dn.servers||[],run=sv.filter(function(x){return x.status&&x.status.active}).length;v.dns=!dn.on?'r':!sv.length?'n':run==sv.length?'g':run?'y':'r'}
  CD={at:Date.now(),v:v};if(el.isConnected)draw(v)})}
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


// phones: the five places used most in the bottom bar, everything else behind «More» (a sheet of every section)
var BAR=[['dash','Home'],['users','Users'],['nodes','Servers'],['netsec','Tunnels'],['vpnsec','Cores']];
window.navBar=function(){
 return '<nav class="kmb" id="mbar" aria-label="'+esc(t('Main menu'))+'">'+BAR.map(function(b){var s=secBy(b[0]),f=s[3][0];
  return '<a href="#'+f[0]+'" data-p="'+f[0]+'" data-sec="'+s[0]+'">'+ic(s[2],20)+'<span>'+t(b[1])+'</span></a>'}).join('')+
  '<button type="button" id="mbmore" aria-haspopup="dialog" aria-expanded="false" aria-controls="msheet" onclick="k38More()">'+ic('more38',20)+'<span>'+t('More')+'</span></button></nav>'+
  '<div class="ksh-scrim" id="k38scrim" onclick="k38More(0)"></div><div class="ksh" id="msheet" role="dialog" aria-modal="true" aria-label="'+esc(t('All sections'))+'" tabindex="-1"></div>'};


// ---------------------------------------------------------------- night / day in the top bar
// The top bar has only one button: night or day. The panel's colors are chosen in Settings ›
// Look, not in the bar.
function drawLooks(){var b=$('#thm');if(!b)return;var night=(S.theme||'dark')!='light';
 b.innerHTML=ic(night?'sun38':'moon',18);b.title=t(night?'Day':'Night');b.setAttribute('aria-label',b.title)}
V.drawLooks=drawLooks;


// ---------------------------------------------------------------- the look
})();

