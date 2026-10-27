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
 ['vpnsec','VPN services','shield2',[['vpn','','Overview'],['kmix','','KANKI MIX'],['xray','overview','Xray'],['wg','','WireGuard'],['awg','','AmneziaWG'],['hy2','','Hysteria2'],['antidpi','','Anti-DPI'],['dns','','Kanki DNS']],'Services'],
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

// ---------------------------------------------------------------- Xray: servers first, inbounds their own tab
// the servers tab shows the servers across the page; the inbounds are on the next tab
if(window.XTABS){XTABS.length=0;[['overview','Servers','srv'],['inbounds','Inbounds','xray'],['clients','Online clients','users'],['routing','Routing and outbounds','tunnel'],['settings','Settings','settings']].forEach(function(x){XTABS.push(x)})}
var _xo=window.xrOverview;
if(_xo)window.xrOverview=function(d,el){_xo.apply(this,arguments);var s=$('#xr_srv',el),c=s&&s.closest('.card'),g=c&&c.parentNode;
 if(g&&g.classList.contains('g2')){$$(':scope>.card',g).forEach(function(x){if(x!=c)x.remove()});g.classList.add('k310one')}};

// ---------------------------------------------------------------- one word for a server
// a server is added once, in Servers; nodes and tunnel servers are the same servers
var WFA=[[/سرورهای تانل/g,'سرورها'],[/سرور تانل/g,'سرور'],[/Nodeها/g,'سرورها'],[/نودهای/g,'سرورهای'],[/نودها/g,'سرورها'],[/نودی/g,'سروری'],[/نود/g,'سرور']],
 WEN=[[/\bTunnel servers\b/g,'Servers'],[/\btunnel servers\b/g,'servers'],[/\bTunnel server\b/g,'Server'],[/\btunnel server\b/g,'server'],[/\bNodes\b/g,'Servers'],[/\bnodes\b/g,'servers'],[/\bNode\b/g,'Server'],[/\bnode\b/g,'server']];
if(typeof FA!='undefined')Object.assign(FA,{"Both a node and a tunnel server (updated once, through the node)":"سرور (یک‌بار آپدیت می‌شود)",
 "Also use this node as a tunnel server":"تانل هم روی این سرور ساخته شود","Tunnel servers (updating by themselves)":"سرورها (خودشان آپدیت می‌شوند)"});
var _t=window.t;
window.t=function(k){var s=_t.apply(this,arguments);if(typeof s!='string')return s;(S.lang=='fa'?WFA:WEN).forEach(function(r){s=s.replace(r[0],r[1])});return s};

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
 h=h||'<span class="muted">…</span>';if(el._h!==h){el._h=h;el.innerHTML=h}}  // unchanged: leave it, so its turning edges keep turning
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

// ---------------------------------------------------------------- tunnel map
// The old neon map (glowing fibres, packets that turn into the tunnel colour at the lock, cyan packets
// coming back, servers with a turning ring and a little satellite), laid out so nothing overlaps:
// Iran entries in one column, exits abroad in the next (a third for second hops; rows on phones),
// the columns ordered to cut crossings, every tunnel leaving and reaching its server at its own point,
// and its label (short name · ping) in the middle of its own line, never over a server or another label.
function tmLayout(d,small){var sv=d.servers||[],byId={};sv.forEach(function(s){byId[s.id]=s});
 var tl=(d.tunnels||[]).filter(function(x){return x.entry!=x.exit&&byId[x.entry]&&byId[x.exit]});
 var lay={};sv.forEach(function(s){lay[s.id]=srvLoc(s)=='iran'?0:1});
 for(var it=0;it<3;it++)tl.forEach(function(x){if(lay[x.entry]>=1&&lay[x.exit]>=1&&lay[x.exit]<=lay[x.entry]&&!tl.some(function(z){return z.exit==x.exit&&lay[z.entry]==0}))lay[x.exit]=Math.min(2,lay[x.entry]+1)});
 var cols=[[],[],[]];sv.forEach(function(s){cols[lay[s.id]].push(s)});while(cols.length>1&&!cols[cols.length-1].length)cols.pop();if(!cols[0].length&&cols.length>1)cols.shift();
 var pos={},setPos=function(){cols.forEach(function(c){c.forEach(function(s,i){pos[s.id]=c.length>1?i/(c.length-1):.5})})};setPos();
 var bary=function(s){var nb=[];tl.forEach(function(x){if(x.entry==s.id)nb.push(pos[x.exit]);if(x.exit==s.id)nb.push(pos[x.entry])});return nb.length?nb.reduce(function(a,b){return a+b},0)/nb.length:pos[s.id]};
 for(it=0;it<6;it++){cols.forEach(function(c){c.sort(function(a,b){return bary(a)-bary(b)})});setPos()}
 var cross=function(){var n=0;for(var i=0;i<tl.length;i++)for(var j=i+1;j<tl.length;j++){var x=tl[i],y=tl[j];
   if(x.entry==y.entry||x.exit==y.exit||x.entry==y.exit||x.exit==y.entry)continue;
   if(lay[x.entry]==lay[y.entry]&&lay[x.exit]==lay[y.exit]&&(pos[x.entry]-pos[y.entry])*(pos[x.exit]-pos[y.exit])<0)n++}return n};
 var best=cross(),more=best>0;for(it=0;it<20&&more;it++){more=false;
  cols.forEach(function(c){for(var i=0;i+1<c.length;i++){var s0=c[i];c[i]=c[i+1];c[i+1]=s0;setPos();var n=cross();if(n<best){best=n;more=true}else{c[i+1]=c[i];c[i]=s0;setPos()}}})}
 var vert=window.innerWidth<640,rtl=document.documentElement.dir=='rtl',nc=cols.length,maxN=Math.max.apply(null,cols.map(function(c){return c.length}).concat([1]));
 var W,H,P={},R=26,mg=78;
 if(vert){W=420;H=Math.max(560,nc*300);cols.forEach(function(c,ci){c.forEach(function(s,i){P[s.id]={x:W/c.length*(i+.5),y:mg+ci*((H-2*mg)/Math.max(1,nc-1)),c:ci}})})}
 else{W=small?680:820;var step=Math.max(118,Math.max.apply(null,sv.map(function(s){return tl.filter(function(x){return x.entry==s.id||x.exit==s.id}).length*14+40}).concat([0])));
  H=Math.max(small?330:380,maxN*step+70);
  cols.forEach(function(c,ci){var x=mg+ci*((W-2*mg)/Math.max(1,nc-1));if(rtl)x=W-x;c.forEach(function(s,i){P[s.id]={x:x,y:40+(H-70)/c.length*(i+.5),c:ci}})})}
 // a trunk from each entry: a short stem, one line across, then a straight branch down (or across) to every
 // server it reaches. Branches into one server sit side by side; entries of one column get their own trunk
 // level, so trunks never lie on each other
 var E={},lvl={},arr={},has={};tl.forEach(function(x){has[x.entry]=1;(arr[x.exit]=arr[x.exit]||[]).push(x)});
 cols.forEach(function(c){var k=0;c.forEach(function(s){if(has[s.id])lvl[s.id]=k++})});
 Object.keys(arr).forEach(function(id){arr[id].sort(function(a,b){return vert?P[a.entry].x-P[b.entry].x:P[a.entry].y-P[b.entry].y})});
 tl.forEach(function(x){var a=P[x.entry],b=P[x.exit],l=arr[x.exit],j=l.indexOf(x),off=(j-(l.length-1)/2)*10,stem=R+20+(lvl[x.entry]||0)*14,r2=Math.sqrt(Math.max(0,R*R-off*off)),pts;
  if(vert){var d=b.y>=a.y?1:-1,ty=a.y+d*stem;pts=[{x:a.x,y:a.y+d*R},{x:a.x,y:ty},{x:b.x+off,y:ty},{x:b.x+off,y:b.y-d*r2}]}
  else{var d2=b.x>=a.x?1:-1,tx=a.x+d2*stem;pts=[{x:a.x+d2*R,y:a.y},{x:tx,y:a.y},{x:tx,y:b.y+off},{x:b.x-d2*r2,y:b.y+off}]}
  E[x.id]={pts:pts}});
 // labels (short name, ping under it) on each branch, moved along it until they cover no server, name or
 // other label: neighbouring branches end up with their labels at different heights
 var boxes=[],L={};
 sv.forEach(function(s){var p=P[s.id];boxes.push({x:p.x-44,y:p.y-44,w:88,h:110})});
 tl.forEach(function(x){var pts=E[x.id].pts,p0=pts[pts.length-2],p1=pts[pts.length-1],rt=(x.entry_status||{}).rtt_ms||0,
  w=Math.max(tunShort(x).length,(rt+'ms').length)*6.8+18,h=32,spot=null;
  var at=function(f){return {x:p0.x+(p1.x-p0.x)*f,y:p0.y+(p1.y-p0.y)*f}};
  [.5,.3,.7,.18,.82,.4,.6,.1,.9].some(function(f){var q=at(f),r={x:q.x-w/2,y:q.y-h/2,w:w,h:h};
   if(!boxes.some(function(o){return r.x<o.x+o.w+3&&o.x<r.x+r.w+3&&r.y<o.y+o.h+3&&o.y<r.y+r.h+3})){spot=q;boxes.push(r);return true}});
  L[x.id]=spot||at(.5);if(!spot)boxes.push({x:L[x.id].x-w/2,y:L[x.id].y-h/2,w:w,h:h})});
 return {W:W,H:H,small:!!small,pos:P,sv:sv,tl:tl,hub:'',cx:W/2,cy:H/2,R:0,n:sv.length,cols:true,E:E,L:L,mx:vert?Math.max(7,Math.floor(W/Math.max(1,maxN)/8)):16}}
window.tunMap=function(d,small){var sv=d.servers||[],tl=d.tunnels||[];
 if(!tl.length&&sv.length<2)return '<div class="tempty">'+ic('tunnel',34)+'<b>'+t('No tunnels yet')+'</b><span class="muted">'+t('Add your entry server (for example in Iran), then make a tunnel to the panel server or another server.')+'</span></div>';
 var key=small?'s':'m',st=TM.reg[key]||(TM.reg[key]={rate:{},last:{}}),now=Date.now();
 tl.forEach(function(x){var es=x.entry_status||{},by=(es.rx_bytes||0)+(es.tx_bytes||0),l=st.last[x.id];
  if(l&&now-l.t>500){var r=(by-l.b)/((now-l.t)/1000);if(r>=0)st.rate[x.id]=r}if(!l||now-l.t>500)st.last[x.id]={b:by,t:now}});
 st.m=tmLayout(d,small);tmStart();
 return '<canvas class="tmapcv" data-tm="'+key+'" style="aspect-ratio:'+st.m.W+'/'+st.m.H+'" role="img" aria-label="'+esc(t('Tunnels'))+'"></canvas>'};
// the drawing is the old one; only where things sit comes from tmLayout
window.tmDraw=function(cv,T){var st=TM.reg[cv.dataset.tm];if(!st||!st.m)return;var m=st.m,w=cv.clientWidth;if(!w)return;
 var dpr=Math.min(2,window.devicePixelRatio||1),pw=Math.round(w*dpr),ph=Math.round(w*m.H/m.W*dpr);if(cv.width!=pw||cv.height!=ph){cv.width=pw;cv.height=ph}
 var c=cv.getContext('2d'),k=pw/m.W,th=(T%1<.02||!st.th)?(st.th=tmTheme()):st.th,W=m.W,H=m.H,TAU=Math.PI*2;
 c.setTransform(k,0,0,k,0,0);c.clearRect(0,0,W,H);
 // ---- background: soft side glows, dot grid, drifting dust
 var bg=c.createRadialGradient(m.cx,m.cy,10,m.cx,m.cy,Math.max(W,H)*.6);bg.addColorStop(0,tmA(th.a,th.light?.13:.11));bg.addColorStop(.55,tmA(th.a,th.light?.04:.03));bg.addColorStop(1,'rgba(61,220,151,'+(th.light?.07:.05)+')');
 c.fillStyle=bg;tmRound(c,0,0,W,H,16);c.fill();
 c.fillStyle=tmA(th.a,th.light?.18:.13);for(var gx=11;gx<W;gx+=22)for(var gy=11;gy<H;gy+=22){c.beginPath();c.arc(gx,gy,.9,0,TAU);c.fill()}
 for(var q=0;q<22;q++){var sx=(q*97.3+T*(6+q%5*3))%W,sy=(q*53.7+Math.sin(T*.4+q)*14+H)%H,sa=.25+.25*Math.sin(T*1.3+q*2.1);c.fillStyle=tmA(th.al,(sa*(th.light?.5:.7)).toFixed(3));c.beginPath();c.arc(sx,sy,q%4?0.9:1.5,0,TAU);c.fill()}
 // the orbit the servers sit on (slowly turning) and a faint inner shell
 if(m.n&&!m.cols){c.strokeStyle=tmA(th.a,.28);c.lineWidth=1.2;c.setLineDash([4,7]);c.lineDashOffset=-T*6;c.beginPath();c.arc(m.cx,m.cy,m.R,0,TAU);c.stroke();
  c.strokeStyle=tmA(th.a,.12);c.setLineDash([2,9]);c.lineDashOffset=T*4;c.beginPath();c.arc(m.cx,m.cy,m.R*.55,0,TAU);c.stroke();c.setLineDash([])}
 // ---- tunnels (their labels are drawn after all of them, on top)
 var labs=[];
 m.tl.forEach(function(x,i){var G=m.E[x.id];if(!G)return;var pts=G.pts,A=pts[0],B=pts[pts.length-1],col=tmRgb(tunCol(x.state)),es=x.entry_status||{},k=0,same=[x];
  var segs=[],tot=0;for(var q=0;q+1<pts.length;q++){var sl=Math.hypot(pts[q+1].x-pts[q].x,pts[q+1].y-pts[q].y);segs.push(sl);tot+=sl}
  var bz=function(u){var d=Math.max(0,Math.min(1,u))*tot;for(var q=0;q<segs.length;q++){if(d<=segs[q]||q==segs.length-1){var f=segs[q]?Math.min(1,d/segs[q]):0;return {x:pts[q].x+(pts[q+1].x-pts[q].x)*f,y:pts[q].y+(pts[q+1].y-pts[q].y)*f}}d-=segs[q]}return B};
  var path=function(){c.beginPath();c.moveTo(A.x,A.y);for(var q=1;q+1<pts.length;q++)c.arcTo(pts[q].x,pts[q].y,pts[q+1].x,pts[q+1].y,10);c.lineTo(B.x,B.y)};
  var ls=tot?(tot-segs[segs.length-1])/tot:0,lt=ls+(1-ls)*.22,up=x.state=='up',part=x.state=='partial',down=!up&&!part,flick=part?(.65+.35*Math.sin(T*7+i)):1;
  c.lineCap='round';
  // fibre: wide halo, body, bright core
  path();c.strokeStyle=tmA(col,(.07*flick).toFixed(3));c.lineWidth=18;c.stroke();
  path();c.strokeStyle=tmA(col,(.16*flick).toFixed(3));c.lineWidth=8;c.stroke();
  if(down){path();c.setLineDash([5,8]);c.lineDashOffset=0;c.strokeStyle=tmA(col,.75);c.lineWidth=2;c.stroke();c.setLineDash([]);
   var mp=bz(lt),fl=.45+.55*Math.abs(Math.sin(T*5+i));c.strokeStyle=tmA(col,fl.toFixed(3));c.lineWidth=2.4;
   c.beginPath();c.moveTo(mp.x-6,mp.y-6);c.lineTo(mp.x+6,mp.y+6);c.moveTo(mp.x+6,mp.y-6);c.lineTo(mp.x-6,mp.y+6);c.stroke();
   for(var z=0;z<5;z++){var ang=z*1.26+T*3,rr=7+((T*18+z*5)%12);c.fillStyle=tmA(col,((1-(rr-7)/12)*.8).toFixed(3));c.beginPath();c.arc(mp.x+Math.cos(ang)*rr,mp.y+Math.sin(ang)*rr,1.3,0,TAU);c.fill()}}
  else{path();var gr=c.createLinearGradient(A.x,A.y,B.x,B.y);gr.addColorStop(0,tmA(th.al,.85));gr.addColorStop(.5,tmA(col,.9));gr.addColorStop(1,tmA(col,.9));c.strokeStyle=gr;c.lineWidth=2.6;c.stroke();
   path();c.setLineDash([2,16]);c.lineDashOffset=-T*46;c.strokeStyle='rgba(255,255,255,'+(.55*flick).toFixed(3)+')';c.lineWidth=1.4;c.stroke();c.setLineDash([])}
  // packets: forward (plain -> encrypted at the lock) and return
  var rtt=es.rtt_ms||0,dur=up?Math.max(1.5,Math.min(4.6,1.5+rtt/110)):5.4,rate=st.rate[x.id]||0,n=up?Math.max(3,Math.min(9,Math.round(3+Math.log(1+rate/2048)/Math.log(10)*1.6))):part?2:0,lockHot=0;
  for(var j=0;j<n;j++){var u=((T/dur)+j/n+i*.13)%1;lockHot=Math.max(lockHot,1-Math.min(1,Math.abs(u-lt)*12));
   for(var tr=7;tr>=0;tr--){var uu=u-tr*.011;if(uu<0)continue;var p=bz(uu),enc=Math.max(0,Math.min(1,(uu-lt+.03)/.06)),pc=tmMix(th.al,col,enc),ra=(tr?2.9*(1-tr*.1):3.6),al=(tr?(1-tr/8)*.55:1)*flick;
    if(!tr){c.fillStyle=tmA(pc,.28*flick);c.beginPath();c.arc(p.x,p.y,8,0,TAU);c.fill()}
    c.fillStyle=tr?tmA(pc,al.toFixed(3)):'rgba(255,255,255,'+al.toFixed(3)+')';c.beginPath();c.arc(p.x,p.y,ra,0,TAU);c.fill()}}
  var nb=up?Math.max(1,Math.floor(n/2)):0;
  for(j=0;j<nb;j++){u=1-(((T/(dur*1.3))+j/nb+.31+i*.07)%1);for(tr=4;tr>=0;tr--){uu=u+tr*.012;if(uu>1)continue;p=bz(uu);c.fillStyle='rgba(111,231,255,'+(tr?(.45*(1-tr/5)).toFixed(3):'.95')+')';c.beginPath();c.arc(p.x,p.y,tr?1.8:2.2,0,TAU);c.fill()}}
  // arrival ripples at the exit, launch ring at the entry
  if(up||part){var ph=((T/dur)*Math.max(1,n))%1;c.strokeStyle=tmA(col,((1-ph)*.55*flick).toFixed(3));c.lineWidth=1.6;c.beginPath();c.arc(m.pos[x.exit].x,m.pos[x.exit].y,25+ph*22,0,TAU);c.stroke();
   var ph2=((T/dur)*Math.max(1,n)+.5)%1;c.strokeStyle=tmA(th.al,((1-ph2)*.35*flick).toFixed(3));c.beginPath();c.arc(m.pos[x.entry].x,m.pos[x.entry].y,25+ph2*12,0,TAU);c.stroke()}
  // the lock in the middle (encryption), lights up when a packet passes
  var L0=bz(lt);if(!down){var hr=10+lockHot*2.5;c.save();c.translate(L0.x,L0.y);
   if(lockHot>0){c.fillStyle=tmA(col,(.3*lockHot).toFixed(3));c.beginPath();c.arc(0,0,hr+9,0,TAU);c.fill()}
   c.beginPath();for(var hx=0;hx<6;hx++){var aa=Math.PI/6+hx*Math.PI/3;c[hx?'lineTo':'moveTo'](Math.cos(aa)*hr,Math.sin(aa)*hr)}c.closePath();c.fillStyle=th.disc;c.fill();c.strokeStyle=tmA(col,(.6+.4*lockHot).toFixed(3));c.lineWidth=1.6;c.stroke();
   c.strokeStyle=tmA(tmMix(col,[255,255,255],lockHot*.6),.95);c.lineWidth=1.4;c.beginPath();c.arc(0,-1.5,2.6,Math.PI,0);c.stroke();c.fillStyle=c.strokeStyle;c.fillRect(-3.6,-1.2,7.2,5.2);c.restore()}
  // label: transport · ping
  // label: short name • ping in the middle of the line; tunnels between the same two servers share one
  // stacked label (drawn once, by the first of them) so their texts never cover each other
  if(m.L[x.id]){var bp=m.L[x.id];
   labs.push(function(){var zr=es.rtt_ms||0,zc=tmRgb(tunCol(x.state)),l1=tunShort(x),l2=x.state=='down'||x.state=='off'?t('down'):zr?zr+'ms':'…';
    c.direction='ltr';c.textAlign='center';c.font='800 10.5px Vazirmatn,sans-serif';var lw=Math.max(c.measureText(l1).width,c.measureText(l2).width)+16,lh=31;
    c.fillStyle=th.disc;tmRound(c,bp.x-lw/2,bp.y-lh/2,lw,lh,9);c.fill();c.strokeStyle=tmA(zc,.7);c.lineWidth=1;c.stroke();
    c.fillStyle=th.t;c.fillText(l1,bp.x,bp.y-2);c.font='700 10px Vazirmatn,sans-serif';c.fillStyle=tmA(zc,1);c.fillText(l2,bp.x,bp.y+11)})}});
 labs.forEach(function(f){f()});
 // ---- servers
 m.sv.forEach(function(s,i){var P=m.pos[s.id];if(!P)return;var col=tmRgb(s.online?'#3ddc97':'#ff6b6b'),br=.5+.5*Math.sin(T*2.1+i),Z=s.id==m.hub?1.25:1;c.save();c.translate(P.x,P.y);c.scale(Z,Z);c.translate(-P.x,-P.y);
  if(s.online){var hg=c.createRadialGradient(P.x,P.y,10,P.x,P.y,46);hg.addColorStop(0,tmA(col,(.16+.08*br).toFixed(3)));hg.addColorStop(1,tmA(col,0));c.fillStyle=hg;c.beginPath();c.arc(P.x,P.y,46,0,TAU);c.fill();
   c.setLineDash([3,9]);c.lineDashOffset=-T*9;c.strokeStyle=tmA(col,.5);c.lineWidth=1.4;c.beginPath();c.arc(P.x,P.y,33,0,TAU);c.stroke();c.setLineDash([]);
   c.save();c.translate(P.x,P.y);c.rotate(-.35);c.strokeStyle=tmA(th.a,.35);c.lineWidth=1;c.beginPath();c.ellipse(0,0,39,13,0,0,TAU);c.stroke();
   var sa=T*1.15+i;c.fillStyle=tmA(th.al,.95);c.beginPath();c.arc(Math.cos(sa)*39,Math.sin(sa)*13,2.2,0,TAU);c.fill();c.restore()}
  else{var fo=.4+.4*Math.abs(Math.sin(T*3+i));c.strokeStyle=tmA(col,fo.toFixed(3));c.lineWidth=1.4;c.setLineDash([2,5]);c.beginPath();c.arc(P.x,P.y,31,0,TAU);c.stroke();c.setLineDash([])}
  c.save();c.shadowColor=tmA(col,.7);c.shadowBlur=12;c.fillStyle=th.disc;c.beginPath();c.arc(P.x,P.y,24,0,TAU);c.fill();c.restore();
  c.strokeStyle=tmA(col,.95);c.lineWidth=2;c.beginPath();c.arc(P.x,P.y,24,0,TAU);c.stroke();
  var cg=c.createRadialGradient(P.x-5,P.y-6,2,P.x,P.y,18);cg.addColorStop(0,'#fff7d6');cg.addColorStop(.45,tmA(th.al,1));cg.addColorStop(1,tmA(th.ad,1));c.fillStyle=s.online?cg:'rgba(140,140,150,.55)';c.beginPath();c.arc(P.x,P.y,17,0,TAU);c.fill();
  c.fillStyle='#2a1d06';c.font='900 14px Vazirmatn,sans-serif';c.textAlign='center';c.fillText((s.local?'★':s.name.charAt(0)).toUpperCase(),P.x,P.y+5);
  c.fillStyle=tmA(col,1);c.strokeStyle=th.disc;c.lineWidth=2;c.beginPath();c.arc(P.x+18,P.y-18,5,0,TAU);c.fill();c.stroke();c.restore();
  var mx=m.mx||(m.n>9?10:14),nm=s.name.length>mx?s.name.slice(0,mx-1)+'…':s.name;c.font='700 12.5px Vazirmatn,sans-serif';var nw=c.measureText(nm).width+12,ny=s.id!=m.hub&&P.y<m.cy-20?P.y-24*Z-14:P.y+24*Z+19; // the name on the outer side, away from the lines
  c.fillStyle=tmA(tmRgb(th.disc),.72);tmRound(c,P.x-nw/2,ny-13,nw,18,9);c.fill();c.fillStyle=th.t;c.textAlign='center';c.direction=/[\u0600-\u06FF]/.test(nm)?'rtl':'ltr';c.fillText(nm,P.x,ny)})};

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

@media(prefers-reduced-motion:reduce){.k310cards .kxr.open>.kxr-b{animation:none}.k310cards .kxr{transition:none}}

/* settings: the section list stays in view, the save bar sticks to the bottom of the section */
@media(min-width:900px){#st .stn{position:sticky;top:84px;align-self:start}}
#st .sts .sbar{position:sticky;bottom:12px;z-index:3;border-radius:14px;padding:10px 12px;margin-top:14px;background:color-mix(in srgb,var(--c1) 88%,transparent);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid var(--gb,var(--ln))}
#st .sts .sbar:has(button[data-save]:not(:disabled)){border-color:color-mix(in srgb,var(--a) 55%,transparent);box-shadow:0 10px 30px -16px color-mix(in srgb,var(--a) 70%,transparent)}
#st .stn button.dirty em{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--a);margin-inline-start:auto}
#st .sts .srow{padding:12px 0;border-bottom:1px solid var(--gb,var(--ln))}
`;
var st=document.createElement('style');st.id='k310hub';st.textContent=css;document.head.appendChild(st);
})();
