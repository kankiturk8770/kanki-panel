// Kanki Panel 3.10: where things live. Loaded last (after kanki-skin.js), it changes how pages are
// grouped and laid out, never what a button does:
//  - the menu: KANKI MIX and Xray are their own sections next to VPN services and Kanki DNS
//  - Xray in two parts: "Servers & network" (servers, routing, settings) and "Inbounds" (inbounds,
//    online clients)
//  - KANKI MIX and Xray servers are cards; a tap opens that server's settings in a side drawer
//  - the dashboard: a status line on top, then numbers, live traffic beside server health, servers
//    beside tunnels, services beside connections; the activity log last
//  - the tunnel map: Iran entries in one column, exits abroad in the next, each tunnel on its own
//    curve that never shares a line with another, its short protocol name and live ping in the middle
(function(){
'use strict';
var V=window.V37;if(!V)return;
if(window.KM_ICO&&!ICO.game)ICO.game=KM_ICO;
if(typeof FA!='undefined')Object.assign(FA,{"Servers & network":"سرورها و شبکه","Inbounds":"اینباندها","Online clients":"کلاینت‌های آنلاین",
 "Routing and outbounds":"روتینگ و خروجی‌ها","Overview":"نمای کلی","Settings":"تنظیمات","Xray servers":"سرورهای Xray",
 "Servers online":"سرورهای آنلاین","Tunnels up":"تانل‌های وصل","Services":"سرویس‌ها","Users online":"کاربران آنلاین","all running":"همه روشن",
 "stopped":"متوقف","Server resources":"منابع سرور","Iran · entry":"ایران · ورودی","Abroad · exit":"خارج · خروجی","Next hop":"مرحله‌ی بعد",
 "down":"قطع","Close":"بستن","New user":"کاربر جدید","Add server":"افزودن سرور","no tunnels":"بدون تانل"});

// ---------------------------------------------------------------- the menu
// [section key, label, icon, [[page, sub page, tab label], ...], group]
var SECS=[
 ['dash','Dashboard','dash',[['dash','','Dashboard']],'Home'],
 ['users','Users','users',[['users','','Users']],'Customers'],
 ['bot','Sales bot','bot',[['bot','','Sales bot']],'Customers'],
 ['emergency','Emergency chat','sos',[['emergency','','Emergency chat']],'Customers'],
 ['nodes','Servers','nodes',[['nodes','','Servers']],'Servers & network'],
 ['netsec','Tunnels','tunnel',[['tunnels','','Tunnels']],'Servers & network'],
 ['ports','Ports','ports',[['ports','','Ports']],'Servers & network'],
 ['vpnsec','VPN services','shield2',[['vpn','','Overview'],['wg','','WireGuard'],['awg','','AmneziaWG'],['hy2','','Hysteria2'],['antidpi','','Anti-DPI']],'Services'],
 ['kmsec','KANKI MIX','game',[['kmix','','KANKI MIX']],'Services'],
 ['xrsec','Xray','xray',[['xray','overview','Servers & network'],['xray','inbounds','Inbounds']],'Services'],
 ['dnssec','Kanki DNS','dns',[['dns','','Kanki DNS']],'Services'],
 ['traffic','Traffic & stats','traffic',[['traffic','','Traffic & stats']],'Reports'],
 ['syssec','System','settings',[['settings','','Settings'],['security','','Security'],['backup','','Backup']],'System']];
// the sections other layers already know keep their objects (some code holds on to them)
var old={};V.SECS.forEach(function(s){old[s[0]]=s});
V.SECS.length=0;SECS.forEach(function(s){var o=old[s[0]];if(o){o.length=0;s.forEach(function(x){o.push(x)});V.SECS.push(o)}else V.SECS.push(s)});
window.NAV=V.SECS.map(function(s){return {p:s[3][0][0],sec:s[0]}});
function secBy(k){for(var i=0;i<V.SECS.length;i++)if(V.SECS[i][0]==k)return V.SECS[i];return V.SECS[0]}
function href(f){return '#'+f[0]+(f[1]?'/'+f[1]:'')}
window.navSide=function(){var g='',h='';
 V.SECS.forEach(function(s){if(s[4]!=g){g=s[4];h+='<div class="ngt">'+t(g)+'</div>'}var f=s[3][0];
  h+='<a href="'+href(f)+'" data-p="'+f[0]+'" data-sec="'+s[0]+'"><span class="ni">'+ic(s[2],18)+'</span>'+t(s[1])+'</a>'});return h};
function sheetHtml(){var g='',h='<i class="k38grab"></i>',open=false,cur=V.secOf(S.page)[0];
 V.SECS.forEach(function(s){if(s[4]!=g){if(open)h+='</div>';g=s[4];h+='<div class="k38g">'+t(g)+'</div><div class="k38tiles">';open=true}
  h+='<a class="k38tile'+(cur==s[0]?' on':'')+'" href="'+href(s[3][0])+'">'+ic(s[2],22)+'<span>'+t(s[1])+'</span></a>'});
 return h+(open?'</div>':'')}
window.k38More=function(on){var sh=$('#msheet'),sc=$('#k38scrim');if(!sh)return;if(on===undefined)on=!sh.classList.contains('on');
 if(on)sh.innerHTML=sheetHtml();sh.classList.toggle('on',!!on);if(sc)sc.classList.toggle('on',!!on)};
// a section whose tabs are sub pages of one page (Xray): mark the tab of the sub page, not all of them
function markTabs(){var el=$('#sectabs');if(!el)return;var as=$$('.stl a',el),h=location.hash||'',hit=as.filter(function(a){return a.getAttribute('href')==h});
 if(!hit.length){var p='#'+S.page;hit=as.filter(function(a){return a.getAttribute('href').split('/')[0]==p}).slice(0,1)}
 as.forEach(function(a){a.classList.toggle('on',hit.indexOf(a)>=0)})}
var _nm=window.navMark;
window.navMark=function(){_nm.apply(this,arguments);markTabs()};
new MutationObserver(function(){if($('#sectabs'))markTabs()}).observe(document.body,{childList:true,subtree:true});
// the Xray menu item opens its first part
var _route=window.route;
window.route=function(){if((location.hash||'')=='#xray'){location.replace('#xray/overview');return}return _route.apply(this,arguments)};

// ---------------------------------------------------------------- Xray in two parts
var XPART={net:[['overview','Xray servers','srv'],['routing','Routing and outbounds','tunnel'],['settings','Settings','settings']],
 ib:[['inbounds','Inbounds','xray'],['clients','Online clients','users']]};
function xPart(tab){return XPART.ib.some(function(x){return x[0]==tab})?'ib':'net'}
if(window.xrTabs){
 window.xrTabs=function(d){var el=$('#xr_tabs');if(!el)return;var cnt={inbounds:d.inbounds.length,clients:(d.online||[]).length,routing:(d.rule_list||[]).length+(d.outs||[]).length,overview:d.servers.length};
  el.innerHTML=XPART[xPart(XR.tab)].map(function(x){return '<a href="#xray/'+x[0]+'" class="'+(XR.tab==x[0]?'on':'')+'">'+ic(x[2],15)+t(x[1])+(cnt[x[0]]?' <em>'+N(cnt[x[0]])+'</em>':'')+'</a>'}).join('');
  var pg=$('#pg');if(pg)pg.dataset.xpart=xPart(XR.tab)};
 // part one shows the servers across the page; the inbounds have their own part
 var _xo=window.xrOverview;
 if(_xo)window.xrOverview=function(d,el){_xo.apply(this,arguments);var s=$('#xr_srv',el),c=s&&s.closest('.card'),g=c&&c.parentNode;
  if(g&&g.classList.contains('g2')){$$(':scope>.card',g).forEach(function(x){if(x!=c)x.remove()});g.classList.add('k310one')}};
}

// ---------------------------------------------------------------- server cards with a side drawer
// KANKI MIX (km) and Xray (xr) rows become cards; the open one shows its settings in a drawer
var DRW={km:'#km_srv',xr:'#xr_srv'};
function drawerDress(){Object.keys(DRW).forEach(function(g){var box=$(DRW[g]);if(box)box.classList.add('k310cards')});
 var open=$('.k310cards .kxr.open'),sc=$('#k310scrim');
 if(!open){if(sc)sc.classList.remove('on');document.body.classList.remove('k310drw');return}
 if(!sc){sc=document.createElement('div');sc.id='k310scrim';sc.className='k310scrim';document.body.appendChild(sc)}
 var g=open.dataset.acc;sc.onclick=function(){accClose(g)};sc.classList.add('on');document.body.classList.add('k310drw');
 var b=$('.kxr-b',open);if(b&&!$('.k310dh',b)){var h=$('.kxr-h',open),nm=h&&$('b',h);
  b.insertAdjacentHTML('afterbegin','<div class="k310dh"><b>'+(nm?esc(nm.textContent):'')+'</b><button type="button" class="ib" aria-label="'+esc(t('Close'))+'" onclick="accClose(\''+g+'\')">✕</button></div>')}}
new MutationObserver(function(){if($('.k310cards')||$(DRW.km)||$(DRW.xr)||$('#k310scrim.on'))drawerDress()}).observe(document.body,{childList:true,subtree:true});
window.addEventListener('hashchange',function(){var sc=$('#k310scrim');if(sc)sc.classList.remove('on');document.body.classList.remove('k310drw')});

// ---------------------------------------------------------------- dashboard
function chip(c,label,val){return '<span class="k310st '+c+'"><i></i>'+t(label)+'<b class="ltr">'+val+'</b></span>'}
function strip(){var el=$('#k310strip');if(!el)return;var h='';
 var ns=S.nodes||[];if(ns.length){var on=ns.filter(function(n){return n.online}).length;h+=chip(on==ns.length?'g':on?'y':'r','Servers online',N(on)+' / '+N(ns.length))}
 var tl=(window.TN&&TN.d&&TN.d.tunnels)||[];if(tl.length){var up=tl.filter(function(x){return x.state=='up'}).length;h+=chip(up==tl.length?'g':up?'y':'r','Tunnels up',N(up)+' / '+N(tl.length))}
 var sv=((DB.sys||{}).services||[]);if(sv.length){var bad=sv.filter(function(x){return !x.active}).length;h+=chip(bad?'y':'g','Services',bad?N(bad)+' '+t('stopped'):t('all running'))}
 if(DB.ov)h+=chip(DB.ov.online?'g':'','Users online',N(DB.ov.online));
 el.innerHTML=h||'<span class="muted">…</span>'}
var _dk=window.drawKpis;if(_dk)window.drawKpis=function(){_dk.apply(this,arguments);strip()};
var _pd=window.pDash;
window.pDash=function(){_pd.apply(this,arguments);var pg=$('#pg'),ph=$('#pg .ph');if(!pg||!ph||$('#k310dash'))return;
 // the two actions that matter go up next to the live switch; the quick-actions bar goes
 var qa=$('#k38qa'),row=$('.row',ph);
 if(qa){if(row)row.insertAdjacentHTML('afterbegin','<button class="btn sm" onclick="newUser()">'+ic('plus',15)+' '+t('New user')+'</button><button class="b2 sm" onclick="(window.nodeAddTyped||nodeAdd)()">'+ic('nodes',15)+' '+t('Add server')+'</button>');qa.remove()}
 var st=document.createElement('div');st.className='k310strip';st.id='k310strip';ph.parentNode.insertBefore(st,ph.nextSibling);
 var k=$('#kpis'),gg=$('#pg .gg'),nc=$('#nc'),net=$('#ch_net'),con=$('#ch_con'),sv=$('#svcs'),td=$('#tdc'),lg=$('#lgc');
 var card=function(x){return x&&x.closest('.card')};net=card(net);con=card(con);sv=card(sv);
 var d=document.createElement('div');d.className='k310dash';d.id='k310dash';
 var cell=function(cls,els){var c=document.createElement('div');c.className='k310c '+cls;els.forEach(function(e){if(e)c.appendChild(e)});d.appendChild(c)};
 if(k)k.parentNode.insertBefore(d,k.nextSibling);
 var res=document.createElement('div');res.className='card k310res';res.innerHTML='<h3>'+ic('cpu',16)+' '+t('Server resources')+'</h3>';if(gg)res.appendChild(gg);
 cell('w8',[net]);cell('w4',[res]);cell('w6',[nc]);cell('w6',[td]);cell('w6',[sv]);cell('w6',[con]);
 if(lg)pg.appendChild(lg);
 strip();clearInterval(S.timer4);S.timer4=setInterval(function(){if(S.page!='dash'){clearInterval(S.timer4);return}strip()},3000)};

// ---------------------------------------------------------------- tunnel map (SVG)
var TMH={hot:'',t0:Date.now()};
function tmName(s){return s?s.name:'?'}
function tmClip(s,n){s=String(s||'');return s.length>n?s.slice(0,n-1)+'…':s}
function tmPing(x){return ((x.entry_status||{}).rtt_ms)||0}
window.tunMap=function(d,small){var sv=d.servers||[],tl=(d.tunnels||[]).filter(function(x){return x.entry&&x.exit&&x.entry!=x.exit});
 if(!tl.length&&sv.length<2)return '<div class="tempty">'+ic('tunnel',34)+'<b>'+t('No tunnels yet')+'</b><span class="muted">'+t('Add your entry server (for example in Iran), then make a tunnel to the panel server or another server.')+'</span></div>';
 var byId={};sv.forEach(function(s){byId[s.id]=s});
 tl=tl.filter(function(x){return byId[x.entry]&&byId[x.exit]});
 // columns: Iran entries, then exits abroad, then the servers a second hop goes on to
 var lay={};sv.forEach(function(s){lay[s.id]=srvLoc(s)=='iran'?0:1});
 for(var it=0;it<3;it++)tl.forEach(function(x){if(lay[x.entry]>=1&&lay[x.exit]>=1&&lay[x.exit]<=lay[x.entry]&&!tl.some(function(z){return z.exit==x.exit&&lay[z.entry]==0}))lay[x.exit]=Math.min(2,lay[x.entry]+1)});
 var cols=[[],[],[]];sv.forEach(function(s){cols[lay[s.id]].push(s)});if(!cols[2].length)cols.pop();
 // order every column by where its tunnels go (fewer crossings), a few rounds both ways
 var pos={};var setPos=function(){cols.forEach(function(c){c.forEach(function(s,i){pos[s.id]=c.length>1?i/(c.length-1):.5})})};setPos();
 var bary=function(s){var nb=[];tl.forEach(function(x){if(x.entry==s.id)nb.push(pos[x.exit]);if(x.exit==s.id)nb.push(pos[x.entry])});return nb.length?nb.reduce(function(a,b){return a+b},0)/nb.length:pos[s.id]};
 for(it=0;it<6;it++){cols.forEach(function(c){c.sort(function(a,b){return bary(a)-bary(b)||(a.local?-1:0)})});setPos()}
 // then swap neighbours while that removes crossings (exact count; a panel has a few dozen tunnels at most)
 var cross=function(){var n=0;for(var i=0;i<tl.length;i++)for(var j=i+1;j<tl.length;j++){var x=tl[i],y=tl[j];
   if(x.entry==y.entry||x.exit==y.exit||x.entry==y.exit||x.exit==y.entry)continue;
   if((pos[x.entry]-pos[y.entry])*(pos[x.exit]-pos[y.exit])<0&&lay[x.entry]==lay[y.entry]&&lay[x.exit]==lay[y.exit])n++}return n};
 var best=cross(),more=best>0;for(it=0;it<20&&more;it++){more=false;
  cols.forEach(function(c){for(var i=0;i+1<c.length;i++){var s0=c[i];c[i]=c[i+1];c[i+1]=s0;setPos();var n=cross();if(n<best){best=n;more=true}else{c[i+1]=c[i];c[i]=s0;setPos()}}})}
 var vert=window.innerWidth<640,rtl=document.documentElement.dir=='rtl',nc=cols.length,maxN=Math.max.apply(null,cols.map(function(c){return c.length}).concat([1]));
 var W=vert?380:(small?640:880),nw=vert?Math.min(118,(W-10)/maxN-10):(small?132:156),nh=vert?44:50,gap=12;
 var portsOf=function(id){return tl.filter(function(x){return x.entry==id||x.exit==id}).length};
 var rowH=vert?0:Math.max(nh+34,Math.max.apply(null,sv.map(function(s){return portsOf(s.id)}).concat([1]))*gap+26);
 var H=vert?Math.max(420,nc*190):Math.max(small?240:300,maxN*rowH+48),P={};
 cols.forEach(function(c,ci){var n=c.length;c.forEach(function(s,i){
  if(vert){var step=W/n;P[s.id]={x:step*(i+.5),y:46+ci*((H-92)/Math.max(1,nc-1)),c:ci}}
  else{var step=(H-40)/n,cx=nw/2+8+ci*((W-nw-16)/Math.max(1,nc-1));if(rtl)cx=W-cx;P[s.id]={x:cx,y:32+step*(i+.5),c:ci}}})});
 // every tunnel gets its own point on each server it touches, sorted by where the other end is
 var dirX=rtl?-1:1,ends={};
 sv.forEach(function(s){var p=P[s.id];[['out','entry','exit'],['in','exit','entry']].forEach(function(k){
  var es=tl.filter(function(x){return x[k[1]]==s.id}).sort(function(a,b){var A=P[a[k[2]]],B=P[b[k[2]]];return vert?A.x-B.x:A.y-B.y});
  es.forEach(function(x,j){var off=(j-(es.length-1)/2)*gap,fwd=P[x[k[2]]].c>=p.c;
   var pt=vert?{x:p.x+off,y:p.y+(fwd?nh/2:-nh/2)}:{x:p.x+(fwd?nw/2:-nw/2)*dirX,y:p.y+off};(ends[x.id]=ends[x.id]||{})[k[0]]=pt})})});
 var paths=[],boxes=[],out='';
 tl.forEach(function(x,i){var a=ends[x.id].out,b=ends[x.id].in,d;if(!a||!b)return;
  if(vert){var dy=(b.y-a.y)*.5;d='M'+a.x+' '+a.y+' C'+a.x+' '+(a.y+dy)+' '+b.x+' '+(b.y-dy)+' '+b.x+' '+b.y}
  else{var same=P[x.entry].c==P[x.exit].c,dx=same?70*dirX:(b.x-a.x)*.5;d='M'+a.x+' '+a.y+' C'+(a.x+dx)+' '+a.y+' '+(b.x-(same?-dx:dx))+' '+b.y+' '+b.x+' '+b.y}
  paths.push({x:x,d:d,a:a,b:b})});
 var col=function(x){return x.enabled===false?'#8a8f98':tunCol(x.state)};
 var now=(Date.now()-TMH.t0)/1000;
 out+='<g class="tme">'+paths.map(function(p){var x=p.x,c=col(x),up=x.state=='up'||x.state=='partial',dur=(1.1+Math.min(3,tmPing(x)/120)).toFixed(2);
  return '<g class="tml'+(up?'':' dn')+(TMH.hot==x.id?' hot':'')+'" data-t="'+esc(x.id)+'" tabindex="0" role="img" aria-label="'+esc(tmName(byId[x.entry])+' → '+tmName(byId[x.exit])+' · '+tunShort(x)+(up&&tmPing(x)?' · '+tmPing(x)+' ms':''))+'">'+
   '<path d="'+p.d+'" class="h" stroke="'+c+'"/><path d="'+p.d+'" class="b" stroke="'+c+'"/>'+
   (up?'<path d="'+p.d+'" class="f" stroke="'+c+'" style="animation-duration:'+dur+'s;animation-delay:-'+(now%dur).toFixed(2)+'s"/>':'')+
   '<path d="'+p.d+'" class="hit"/><circle cx="'+p.a.x+'" cy="'+p.a.y+'" r="3.4" fill="'+c+'" class="pt"/><circle cx="'+p.b.x+'" cy="'+p.b.y+'" r="3.4" fill="'+c+'" class="pt"/></g>'}).join('')+'</g>';
 // labels in the middle of each curve, moved along it only when another label is already there
 var bez=function(p,u){var m=p.d.match(/-?[\d.]+/g).map(Number),v=1-u;return {x:v*v*v*m[0]+3*v*v*u*m[2]+3*v*u*u*m[4]+u*u*u*m[6],y:v*v*v*m[1]+3*v*v*u*m[3]+3*v*u*u*m[5]+u*u*u*m[7]}};
 out+='<g class="tmb">'+paths.map(function(p){var x=p.x,c=col(x),up=x.state=='up'||x.state=='partial',pg=tmPing(x),
  lab=tunShort(x),ms=up?(pg?N(pg)+'ms':'…'):t('down'),w=Math.round((lab.length+String(ms).length)*6.4+26),h=21,spot=null;
  [.5,.4,.6,.32,.68,.25,.75].some(function(u){var q=bez(p,u),r={x:q.x-w/2,y:q.y-h/2,w:w,h:h};
   if(!boxes.some(function(o){return r.x<o.x+o.w+4&&o.x<r.x+r.w+4&&r.y<o.y+o.h+3&&o.y<r.y+r.h+3})){spot=r;return true}});
  if(!spot){var q=bez(p,.5);spot={x:q.x-w/2,y:q.y-h/2,w:w,h:h}}boxes.push(spot);
  return '<g class="tbg'+(TMH.hot==x.id?' hot':'')+'" data-t="'+esc(x.id)+'"><rect x="'+spot.x.toFixed(1)+'" y="'+spot.y.toFixed(1)+'" width="'+w+'" height="'+h+'" rx="10.5" stroke="'+c+'"/>'+
   '<text x="'+(spot.x+10).toFixed(1)+'" y="'+(spot.y+14.5).toFixed(1)+'" class="p" direction="ltr">'+esc(lab)+'</text>'+
   '<text x="'+(spot.x+w-10).toFixed(1)+'" y="'+(spot.y+14.5).toFixed(1)+'" class="m" text-anchor="end" fill="'+c+'" direction="ltr">'+esc(ms)+'</text></g>'}).join('')+'</g>';
 // servers
 out+='<g class="tmn">'+sv.map(function(s){var p=P[s.id],on=s.online,c=on?'var(--ok)':'var(--bad)',ir=srvLoc(s)=='iran',nt=portsOf(s.id),mx=vert?Math.max(6,Math.floor(nw/8)):(small?15:18);
  return '<g class="tmnd'+(ir?' ir':'')+(on?'':' off')+(nt?'':' lone')+'"><rect x="'+(p.x-nw/2).toFixed(1)+'" y="'+(p.y-nh/2).toFixed(1)+'" width="'+nw.toFixed(1)+'" height="'+nh+'" rx="13"/>'+
   '<circle cx="'+(p.x+(nw/2-12)*(rtl?1:-1)).toFixed(1)+'" cy="'+(p.y-nh/2+12)+'" r="4" fill="'+c+'"/>'+
   '<text x="'+p.x.toFixed(1)+'" y="'+(p.y-1)+'" text-anchor="middle" class="n">'+esc(tmClip(s.name,mx))+'</text>'+
   '<text x="'+p.x.toFixed(1)+'" y="'+(p.y+15)+'" text-anchor="middle" class="s">'+(s.local?'★ ':'')+(nt?N(nt)+' '+t('Tunnels'):t('no tunnels'))+'</text></g>'}).join('')+'</g>';
 var heads='';
 if(!vert){var hl=[t('Iran · entry'),t('Abroad · exit'),t('Next hop')];cols.forEach(function(c,ci){var x=nw/2+8+ci*((W-nw-16)/Math.max(1,nc-1));if(rtl)x=W-x;heads+='<text x="'+x.toFixed(1)+'" y="14" text-anchor="middle" class="ch">'+hl[ci]+'</text>'})}
 return '<div class="k310tm'+(small?' sm':'')+'"><svg viewBox="0 0 '+W+' '+H+'" role="group" aria-label="'+esc(t('Tunnels'))+'">'+heads+out+'</svg></div>'};
// hover / focus / tap: one tunnel lit, the others dimmed
function tmHot(id){TMH.hot=id||'';$$('.k310tm svg').forEach(function(s){s.classList.toggle('dim',!!id);$$('[data-t]',s).forEach(function(g){g.classList.toggle('hot',g.dataset.t==id)})})}
document.addEventListener('mouseover',function(e){var g=e.target.closest&&e.target.closest('.k310tm [data-t]');if(g)tmHot(g.dataset.t);else if(TMH.hot&&e.target.closest&&e.target.closest('.k310tm'))tmHot('')});
document.addEventListener('mouseout',function(e){if(e.target.closest&&e.target.closest('.k310tm')&&!(e.relatedTarget&&e.relatedTarget.closest&&e.relatedTarget.closest('.k310tm')))tmHot('')});
document.addEventListener('focusin',function(e){var g=e.target.closest&&e.target.closest('.k310tm [data-t]');if(g)tmHot(g.dataset.t)});
document.addEventListener('focusout',function(e){if(e.target.closest&&e.target.closest('.k310tm'))tmHot('')});

var css=`
/* Xray part one: servers across the page */
.g2.k310one{grid-template-columns:1fr!important}

/* server cards with a side drawer (KANKI MIX, Xray) */
.k310cards .kxl{display:grid;grid-template-columns:repeat(auto-fill,minmax(min(100%,250px),1fr));gap:10px}
.k310cards .kxr{border-radius:16px;border:1px solid var(--gb,var(--ln));background:linear-gradient(180deg,color-mix(in srgb,var(--t) 3%,var(--c1)),var(--c2));transition:border-color .18s,transform .18s,box-shadow .18s;margin:0!important}
.k310cards .kxr:hover{transform:translateY(-2px);border-color:color-mix(in srgb,var(--a) 40%,transparent)}
/* the open card must not move: a transform would trap the fixed drawer inside the card */
.k310cards .kxr.open,.k310cards .kxr.open:hover{transform:none!important}
.k310cards .kxr.open{border-color:var(--a);box-shadow:0 0 0 1px var(--a),0 12px 30px -16px color-mix(in srgb,var(--a) 60%,transparent)}
.k310cards .kxr-h{flex-wrap:wrap;row-gap:8px;padding:14px!important;min-height:86px;align-content:center}
.k310cards .kxr-h .sp{flex-basis:100%;height:0}
.k310cards .kxr-h b{font-size:14px}
.k310cards .kxr-arr{order:9;margin-inline-start:auto;transform:none!important;opacity:.6}
html[dir=rtl] .k310cards .kxr-arr svg{transform:scaleX(-1)}
.k310cards .kxr.open>.kxr-b{position:fixed;z-index:60;top:0;bottom:0;inset-inline-end:0;width:min(460px,100vw);height:auto!important;overflow:auto;overscroll-behavior:contain;
 background:var(--c1);border-inline-start:1px solid var(--gb2,var(--ln));box-shadow:-40px 0 80px -30px rgba(0,0,0,.85);
 padding:0 18px calc(24px + env(safe-area-inset-bottom,0px));animation:k310in .22s cubic-bezier(.2,.8,.2,1)}
body.light .k310cards .kxr.open>.kxr-b{box-shadow:-30px 0 70px -30px rgba(0,0,0,.3)}
.k310cards .kxr.open>.kxr-b.shut{animation:k310out .18s ease-in forwards}
@keyframes k310in{from{transform:translateX(var(--k310dx,100%))}to{transform:none}}
@keyframes k310out{to{transform:translateX(var(--k310dx,100%))}}
html[dir=rtl] .k310cards{--k310dx:-100%}
.k310dh{position:sticky;top:0;z-index:2;display:flex;align-items:center;gap:10px;margin:0 -18px 12px;padding:calc(14px + env(safe-area-inset-top,0px)) 18px 12px;background:color-mix(in srgb,var(--c1) 92%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border-bottom:1px solid var(--gb,var(--ln))}
.k310dh b{flex:1;font-size:16px;font-weight:900}
.k310scrim{display:none;position:fixed;inset:0;z-index:59;background:rgba(0,0,0,.55);backdrop-filter:blur(2px)}
.k310scrim.on{display:block}
@media(max-width:700px){.k310cards .kxr.open>.kxr-b{top:auto;width:100vw;max-height:86vh;border-radius:22px 22px 0 0;border:1px solid var(--gb2,var(--ln));border-bottom:0;--k310dx:0;animation-name:k310up}
 .k310dh{padding-top:14px}}
@keyframes k310up{from{transform:translateY(100%)}to{transform:none}}

/* dashboard */
.k310strip{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 14px}
.k310st{display:inline-flex;align-items:center;gap:8px;height:38px;padding:0 14px;border-radius:12px;border:1px solid var(--gb,var(--ln));background:var(--c1);font-size:12.5px;font-weight:700;color:var(--s)}
.k310st b{color:var(--t);font-weight:900}
.k310st i{width:8px;height:8px;border-radius:50%;background:var(--s)}
.k310st.g i{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 22%,transparent)}
.k310st.y i{background:var(--warn);box-shadow:0 0 0 3px color-mix(in srgb,var(--warn) 22%,transparent)}
.k310st.r i{background:var(--bad);box-shadow:0 0 0 3px color-mix(in srgb,var(--bad) 22%,transparent)}
.k310st.y{border-color:color-mix(in srgb,var(--warn) 35%,transparent)}.k310st.r{border-color:color-mix(in srgb,var(--bad) 35%,transparent)}
.k310dash{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:12px;margin:12px 0}
.k310c{min-width:0;display:grid}.k310c>.card{margin:0!important;min-width:0}
.k310c.w8{grid-column:span 8}.k310c.w4{grid-column:span 4}.k310c.w6{grid-column:span 6}
.k310res{display:grid;gap:10px;align-content:start}
.k310res .gg{display:grid!important;grid-template-columns:1fr 1fr!important;gap:8px!important;margin:0!important}
.k310res .gc{padding:10px!important;border-radius:14px!important}
.k310res .gc .ch,.k310res .gc [id^=ch_]{display:none}
@media(max-width:1100px){.k310c.w8,.k310c.w4,.k310c.w6{grid-column:span 12}}
#pg .ph .row .btn.sm,#pg .ph .row .b2.sm{display:inline-flex;align-items:center;gap:6px}
@media(max-width:620px){#pg .ph .row:has(#d_live){flex-wrap:wrap!important}}

/* tunnel map */
.k310tm{width:100%;overflow:hidden;border-radius:16px;background:radial-gradient(120% 90% at 50% 0%,color-mix(in srgb,var(--a) 7%,transparent),transparent 60%),var(--in);border:1px solid var(--gb,var(--ln));padding:8px}
.k310tm svg{display:block;width:100%;height:auto;font-family:Vazirmatn,sans-serif}
.k310tm .ch{fill:var(--s);font-size:11px;font-weight:800;letter-spacing:.3px}
.k310tm .tml path{fill:none;stroke-linecap:round}
.k310tm .tml .h{stroke-width:10;opacity:.09}
.k310tm .tml .b{stroke-width:2.2;opacity:.55}
.k310tm .tml .f{stroke-width:2.6;stroke-dasharray:3 15;animation:k310flow linear infinite}
.k310tm .tml.dn .b{stroke-dasharray:6 6;opacity:.8}
.k310tm .tml .hit{stroke:transparent;stroke-width:16;cursor:pointer}
.k310tm .tml .pt{stroke:var(--c1);stroke-width:1.5}
@keyframes k310flow{to{stroke-dashoffset:-36}}
.k310tm .tbg rect{fill:var(--c1);stroke-width:1.2}
.k310tm .tbg text{font-size:10.5px;font-weight:800;font-family:ui-monospace,Menlo,Consolas,monospace}
.k310tm .tbg .p{fill:var(--t)}
.k310tm .tmnd rect{fill:var(--c2);stroke:var(--gb2,var(--ln));stroke-width:1.2}
.k310tm .tmnd.ir rect{stroke:color-mix(in srgb,var(--a) 50%,transparent)}
.k310tm .tmnd.off rect{stroke:color-mix(in srgb,var(--bad) 55%,transparent);stroke-dasharray:4 4}
.k310tm .tmnd.lone{opacity:.6}
.k310tm .tmnd .n{fill:var(--t);font-size:13px;font-weight:800}
.k310tm .tmnd .s{fill:var(--s);font-size:10.5px;font-weight:600}
.k310tm.sm .tmnd .n{font-size:12px}
.k310tm .tml,.k310tm .tbg{transition:opacity .18s}
.k310tm svg.dim .tml:not(.hot),.k310tm svg.dim .tbg:not(.hot){opacity:.15}
.k310tm .tml.hot .b{opacity:1;stroke-width:3}
.k310tm .tml:focus{outline:none}.k310tm .tml:focus-visible .b{stroke-width:3.4;opacity:1}
@media(prefers-reduced-motion:reduce){.k310tm .tml .f{animation:none;stroke-dasharray:none;opacity:.85}.k310cards .kxr.open>.kxr-b{animation:none}.k310cards .kxr{transition:none}}

/* settings: the section list stays in view, the save bar sticks to the bottom of the section */
@media(min-width:900px){#st .stn{position:sticky;top:84px;align-self:start}}
#st .sts .sbar{position:sticky;bottom:12px;z-index:3;border-radius:14px;padding:10px 12px;margin-top:14px;background:color-mix(in srgb,var(--c1) 88%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid var(--gb,var(--ln))}
#st .sts .sbar:has(button[data-save]:not(:disabled)){border-color:color-mix(in srgb,var(--a) 55%,transparent);box-shadow:0 10px 30px -16px color-mix(in srgb,var(--a) 70%,transparent)}
#st .stn button.dirty em{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--a);margin-inline-start:auto}
#st .sts .srow{padding:12px 0;border-bottom:1px solid var(--gb,var(--ln))}
`;
var st=document.createElement('style');st.id='k310hub';st.textContent=css;document.head.appendChild(st);
})();
