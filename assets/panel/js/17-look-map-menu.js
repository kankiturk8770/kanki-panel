// ==================================================================== colors and cards
// cards and colors: the sign-in screen, an icon per dashboard number, data used and days left on
// every user tile, a clear focus ring, and no motion for those who ask their system for less.
(function(){
'use strict';


// ---------------------------------------------------------------- dashboard numbers: an icon per number
var KICO={all:'users',online:'k310online',active:'k310ok',finished:'k310warn',disabled:'k310off'};
function kpiIcons(){$$('#kpis .kpi').forEach(function(k){if(k.querySelector('.k310ki'))return;
 k.insertAdjacentHTML('afterbegin','<span class="k310ki">'+ic(KICO[k.dataset.go]||'k310traffic',18)+'</span>')})}
V37.kpiIcons=kpiIcons;

// the sign-in screen may already be drawn before this file ran
if($('.login')&&!$('.k310login'))loginView(!($('#otpw')||{classList:{contains:function(){return true}}}).classList.contains('hide'));
})();

// ==================================================================== tunnel map, drawers
// where things live: KANKI MIX and Xray servers as cards with a side drawer; the dashboard (a status
// line, the numbers, then live traffic beside server resources, servers beside tunnels, services beside
// connections, the log last); the tunnel map (Iran entries in one column, exits in the next, each
// tunnel on its own curve with its protocol and live ping).
(function(){
'use strict';
var V=V37;

// ---------------------------------------------------------------- the menu
// [section key, label, icon, [[page, sub page, tab label], ...], group]
function secBy(k){for(var i=0;i<V.SECS.length;i++)if(V.SECS[i][0]==k)return V.SECS[i];return V.SECS[0]}
function href(f){return '#'+f[0]+(f[1]?'/'+f[1]:'')}
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
V.markTabs=markTabs;




// ---------------------------------------------------------------- dashboard
function chip(c,label,val){return '<span class="k310st '+c+'"><i></i>'+t(label)+'<b class="ltr">'+val+'</b></span>'}
// the dashboard: a status line, the numbers, then live traffic beside server resources, servers beside tunnels,
// services beside connections, the activity log last
window.pDash=function(){dbReset();
$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Dashboard')+'</h2><p class="ltr" id="d_sub" style="text-align:start">…</p></div>'+
 '<div class="row" style="gap:6px;flex-wrap:nowrap"><button class="btn sm" onclick="newUser()">'+ic('plus',15)+' '+t('New user')+'</button><span class="live" id="d_live"><i></i><span id="d_lt">'+t('Live')+'</span></span>'+
 '<select id="d_iv" style="width:auto;padding:6px 9px;font-size:12px">'+[1,2,5,10].map(function(n){return '<option value="'+n+'"'+(n==DB.iv?' selected':'')+'>'+N(n)+' '+t('seconds')+'</option>'}).join('')+'</select>'+
 '<button class="ib" id="d_pause" title="'+t('Pause')+'">❚❚</button></div></div>'+
 '<div class="k310strip" id="k310strip"></div><div class="kpis" id="kpis"></div>'+
 '<div class="k310dash" id="k310dash">'+
  '<div class="k310c w8">'+'<div class="card" style="margin-bottom:12px"><div class="nh"><div><h3>'+t('Network speed')+'</h3><small class="muted ltr" id="n_if"></small></div>'+
  '<div class="nbig"><div class="dn"><small>↓ '+t('Download')+'</small><b id="n_rx" class="ltr">—</b></div><div class="upl"><small>↑ '+t('Upload')+'</small><b id="n_tx" class="ltr">—</b></div></div></div>'+
  '<div class="ch tall" id="ch_net"></div>'+
  '<div class="nf ltr"><span>'+t('Peak')+' ↓ <b id="n_prx">—</b></span><span>'+t('Peak')+' ↑ <b id="n_ptx">—</b></span><span>'+t('Total since boot')+' ↓ <b id="n_trx">—</b></span><span>↑ <b id="n_ttx">—</b></span></div></div>'+'</div>'+
  '<div class="k310c w4"><div class="card k310res"><h3>'+ic('cpu',16)+' '+t('Server resources')+'</h3>'+'<div class="gg">'+gcard('cpu','CPU',ic('cpu',16))+gcard('ram','RAM',ic('ram',16))+gcard('disk','Storage',ic('disk',16))+gcard('swap','Swap',ic('swap',16))+'</div>'+'</div></div>'+
  '<div class="k310c w12">'+'<div class="card" id="nc" style="margin-bottom:12px"></div>'+'</div>'+
  '<div class="k310c w6">'+'<div class="card"><h3>'+t('Services')+'</h3><p class="sub">'+t('Start, stop or restart the VPN services')+'</p><div id="svcs" class="svcs"><span class="muted">'+t('Loading…')+'</span></div></div>'+'</div>'+
  '<div class="k310c w6">'+'<div class="card" style="margin-bottom:12px"><div class="nh"><div><h3>'+t('TCP / UDP connections')+'</h3><small class="muted" id="c_sub"></small></div>'+
  '<div class="nbig"><div class="dn"><small>TCP</small><b id="c_tcp" class="ltr">—</b></div><div class="upl"><small>UDP</small><b id="c_udp" class="ltr">—</b></div></div></div>'+
  '<div class="ch tall" id="ch_con"></div></div>'+'</div>'+
 '</div>'+logCard();
 $('#d_iv').onchange=function(){DB.iv=+this.value;localStorage.setItem('kk_div',DB.iv);dashTimers()};
 $('#d_pause').onclick=function(){DB.paused=!DB.paused;if(!DB.paused)DB.last=null;this.textContent=DB.paused?'▶':'❚❚';this.title=DB.paused?t('Resume'):t('Pause');dashLive(DB.paused?'off':'')};
 $('#svcs').onclick=function(e){var b=e.target.closest('[data-svc]');if(b&&!b.disabled)svc(b.dataset.svc,b.dataset.act)};logWire();
 $('#kpis').onclick=function(e){var b=e.target.closest('[data-go]');if(b)goUsers(b.dataset.go)};
 dashTick();dashSys();dashTimers();
 strip();clearInterval(S.timer4);S.timer4=setInterval(function(){if(S.page!='dash'){clearInterval(S.timer4);return}strip()},3000)};
window.drawKpis=function(o){var el=$('#kpis');if(el&&o){
 var it=[['a','Total users',o.users,'all'],['g','Online',o.online,'online'],['g','Active',o.active,'active'],['y','Expired / out of data',o.expired,'finished'],['r','Disabled',o.disabled,'disabled'],['a','Total traffic',N(o.traffic_gb)+' GB','']];
 el.innerHTML=it.map(function(x){return '<button class="kpi '+x[0]+'" '+(x[3]?'data-go="'+x[3]+'"':'')+'><small>'+t(x[1])+'</small><b class="ltr">'+(typeof x[2]=='number'?N(x[2]):x[2])+'</b></button>'}).join('')}
 strip()};
function strip(){var el=$('#k310strip');if(!el)return;var h='';
 var ns=S.nodes||[];if(ns.length){var on=ns.filter(function(n){return n.online}).length;h+=chip(on==ns.length?'g':on?'y':'r','Servers online',N(on)+' / '+N(ns.length))}
 var tl=(TN.d&&TN.d.tunnels)||[];if(tl.length){var up=tl.filter(function(x){return x.state=='up'}).length;h+=chip(up==tl.length?'g':up?'y':'r','Tunnels up',N(up)+' / '+N(tl.length))}
 var sv=((DB.sys||{}).services||[]);if(sv.length){var bad=sv.filter(function(x){return !x.active}).length;h+=chip(bad?'y':'g','Services',bad?N(bad)+' '+t('stopped'):t('all running'))}
 if(DB.ov)h+=chip(DB.ov.online?'g':'','Users online',N(DB.ov.online));
 h=h||'<span class="muted">…</span>';if(el._h!==h){el._h=h;el.innerHTML=h}}  // unchanged: leave it, so its turning edges keep turning

// ---------------------------------------------------------------- tunnel map
// The neon map (glowing fibres, packets that turn into the tunnel colour at the lock, cyan packets
// coming back, servers with a turning ring and a little satellite), laid out so nothing overlaps:
// Iran entries in one column, exits abroad in the next (a third for second hops; rows on phones),
// the columns ordered to cut crossings, every tunnel leaving and reaching its server at its own point,
// and its label (short name · ping) in the middle of its own line, never over a server or another label.
// on the map: the tunnel's shortest name (HQ-QUIC → HQ-Q, Game-FEC → GFEC …)
var TMS={'HQ-QUIC':'HQ-Q','Game-FEC':'GFEC','TCP-Mux':'TMUX','FakeTCP':'FTCP','QUIC':'Q'};
function tmShort(x){var n=tunShort(x);return TMS[n]||n.replace('AWG+','A+')}
// on the map: a server's short name, its country's short code (Germany GR, England UK …) and its number,
// numbered when two share a code (GR1, GR2); a name with no known country gives its first two letters
var TMC=[[/german|آلمان|^de$/i,'GR'],[/england|brit|^uk$|united king|انگلیس|بریتانیا|^gb$/i,'UK'],[/nether|holland|هلند|^nl$/i,'NL'],[/swed|سوئد|^se$/i,'SE'],
 [/turk|ترکیه|^tr$/i,'TR'],[/iran|tehran|tabriz|mashhad|shiraz|isfahan|ایران|تهران|تبریز|مشهد|شیراز|اصفهان|^ir$/i,'IR'],[/finl|فنلاند|^fi$/i,'FI'],[/fran|فرانسه|^fr$/i,'FR'],
 [/usa|america|united states|آمریکا|^us$/i,'US'],[/canad|کانادا|^ca$/i,'CA'],[/poland|لهستان|^pl$/i,'PL'],[/russia|روسیه|^ru$/i,'RU'],[/emirat|dubai|uae|امارات|دبی|^ae$/i,'AE'],
 [/armen|ارمنستان|^am$/i,'AM'],[/austria|اتریش|^at$/i,'AT'],[/switz|سوئیس|^ch$/i,'CH'],[/ital|ایتالیا|^it$/i,'IT'],[/spain|اسپانیا|^es$/i,'ES'],[/japan|ژاپن|^jp$/i,'JP'],[/singap|سنگاپور|^sg$/i,'SG']];
function tmCode(s){var nm=String(s.name||'');for(var i=0;i<TMC.length;i++)if(TMC[i][0].test(nm)||TMC[i][0].test(String(s.cc||'')))return TMC[i][1];
 var w=nm.match(/[A-Za-z]+/);return (w?w[0].slice(0,2):(s.cc||nm.slice(0,2))).toUpperCase()}
function tmAbbr(sv){var out={},by={};
 sv.forEach(function(s){var code=tmCode(s),num=(String(s.name||'').match(/\d+/)||[''])[0];(by[code]=by[code]||[]).push({s:s,num:num})});
 Object.keys(by).forEach(function(c){var l=by[c],own=l.every(function(y){return y.num})&&new Set(l.map(function(y){return y.num})).size==l.length;
  l.forEach(function(x,i){out[x.s.id]=c+(l.length>1?(own?x.num:String(i+1)):x.num)})});
 return out}
function tmLayout(d){var sv=d.servers||[],byId={};sv.forEach(function(s){byId[s.id]=s});
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
 // always across: Iran on the left, the servers abroad on the right (phones too, a little narrower)
 var phone=window.innerWidth<640,nc=cols.length,maxN=Math.max.apply(null,cols.map(function(c){return c.length}).concat([1]));
 var W,H,P={},R=26,mg=78;
 {W=phone?Math.max(460,250*(nc-1)+140):820;if(phone)mg=62;var step=Math.max(118,Math.max.apply(null,sv.map(function(s){return tl.filter(function(x){return x.exit==s.id}).length*36+50}).concat([0])));
  H=Math.max(380,maxN*step+70);
  cols.forEach(function(c,ci){var x=mg+ci*((W-2*mg)/Math.max(1,nc-1));c.forEach(function(s,i){P[s.id]={x:x,y:40+(H-70)/c.length*(i+.5),c:ci}})})}
 // a trunk from each entry: a short stem, one line across, then a straight branch down (or across) to every
 // server it reaches. Branches into one server sit side by side; entries of one column get their own trunk
 // level, so trunks never lie on each other
 var E={},lvl={},arr={},has={};tl.forEach(function(x){has[x.entry]=1;(arr[x.exit]=arr[x.exit]||[]).push(x)});
 cols.forEach(function(c){var k=0;c.forEach(function(s){if(has[s.id])lvl[s.id]=k++})});
 Object.keys(arr).forEach(function(id){arr[id].sort(function(a,b){return P[a.entry].y-P[b.entry].y})});
 // lines into one server run 36 apart (room for a label each) and bend into the server's circle at its edge
 tl.forEach(function(x){var a=P[x.entry],b=P[x.exit],l=arr[x.exit],j=l.indexOf(x),off=l.length>1?(j-(l.length-1)/2)*36:0,offc=Math.max(-(R-5),Math.min(R-5,off)),stem=R+20+(lvl[x.entry]||0)*14,r2=Math.sqrt(Math.max(0,R*R-offc*offc)),pts;
  var d2=b.x>=a.x?1:-1,tx=a.x+d2*stem;pts=[{x:a.x+d2*R,y:a.y},{x:tx,y:a.y},{x:tx,y:b.y+off},{x:b.x-d2*(R+16),y:b.y+off},{x:b.x-d2*r2,y:b.y+offc}];
  E[x.id]={pts:pts}});
 // labels (short name, ping under it) on each branch, moved along it until they cover no server, name or
 // other label: neighbouring branches end up with their labels at different heights
 var boxes=[],L={};
 sv.forEach(function(s){var p=P[s.id];boxes.push({x:p.x-44,y:p.y-44,w:88,h:110})});
 tl.forEach(function(x){var pts=E[x.id].pts,p0=pts[pts.length-3],p1=pts[pts.length-2],rt=(x.entry_status||{}).rtt_ms||0,
  w=Math.max((x._lab||tmShort(x)).length,(rt+'ms').length)*6.8+18,h=32,spot=null;
  var at=function(f){return {x:p0.x+(p1.x-p0.x)*f,y:p0.y+(p1.y-p0.y)*f}};
  [.5,.3,.7,.18,.82,.4,.6,.1,.9].some(function(f){var q=at(f),r={x:q.x-w/2,y:q.y-h/2,w:w,h:h};
   if(!boxes.some(function(o){return r.x<o.x+o.w+3&&o.x<r.x+r.w+3&&r.y<o.y+o.h+3&&o.y<r.y+r.h+3})){spot=q;boxes.push(r);return true}});
  L[x.id]=spot||at(.5);if(!spot)boxes.push({x:L[x.id].x-w/2,y:L[x.id].y-h/2,w:w,h:h})});
 return {ab:tmAbbr(sv),W:W,H:H,pos:P,sv:sv,tl:tl,hub:'',cx:W/2,cy:H/2,R:0,n:sv.length,cols:true,E:E,L:L,mx:16}}
// what one view shows: 'all', or the id of one Iran server
function tmView(d,view){var sv=d.servers||[],tl=d.tunnels||[],col=tmIrCol(sv),ir=function(id){return col[id]};
 if(view&&view!='all'&&col[view]){var mine=tl.filter(function(x){return x.entry==view||x.exit==view}),ids={};ids[view]=1;
  mine.forEach(function(x){ids[x.entry]=1;ids[x.exit]=1});
  return {servers:sv.filter(function(s){return ids[s.id]}).map(function(s){return s.id==view?Object.assign({},s,{_col:col[view]}):s}),
   tunnels:mine.map(function(x){return Object.assign({},x,{_col:col[view]})})}}
 // all: the tunnels between the same two servers are one line, labelled with how many there are
 var by={},order=[];tl.forEach(function(x){var k=x.entry+'>'+x.exit;if(!by[k]){by[k]=[];order.push(k)}by[k].push(x)});
 var lines=order.map(function(k){var l=by[k],x=l[0],up=l.filter(function(z){return z.state=='up'}).length,rt=l.map(function(z){return (z.entry_status||{}).rtt_ms||0}).filter(Boolean);
  if(l.length==1)return Object.assign({},x,{_col:ir(x.entry)||ir(x.exit)});
  return {id:'g:'+k,entry:x.entry,exit:x.exit,kind:x.kind,transport:x.transport,state:up==l.length?'up':up?'partial':l.some(function(z){return z.state=='off'})&&!up?'off':'down',
   entry_status:{rtt_ms:rt.length?Math.min.apply(null,rt):0,rx_bytes:l.reduce(function(a,z){return a+((z.entry_status||{}).rx_bytes||0)},0),tx_bytes:l.reduce(function(a,z){return a+((z.entry_status||{}).tx_bytes||0)},0)},
   _col:ir(x.entry)||ir(x.exit),_lab:N(l.length)+' '+t('tunnels')}});
 var used={};lines.forEach(function(x){used[x.entry]=1;used[x.exit]=1});
 return {servers:sv.filter(function(s){return used[s.id]}).map(function(s){return col[s.id]?Object.assign({},s,{_col:col[s.id]}):s}),tunnels:lines}}
window.tunMap=function(d,view){var v=tmView(d,view),sv=v.servers,tl=v.tunnels;
 if(!tl.length)return '<div class="tempty">'+ic('tunnel',34)+'<b>'+t('No tunnels yet')+'</b><span class="muted">'+t('Add your entry server (for example in Iran), then make a tunnel to the panel server or another server.')+'</span></div>';
 var st=TM.reg.m||(TM.reg.m={rate:{},last:{}}),now=Date.now();
 tl.forEach(function(x){var es=x.entry_status||{},by=(es.rx_bytes||0)+(es.tx_bytes||0),l=st.last[x.id];
  if(l&&now-l.t>500){var r=(by-l.b)/((now-l.t)/1000);if(r>=0)st.rate[x.id]=r}if(!l||now-l.t>500)st.last[x.id]={b:by,t:now}});
 st.m=tmLayout(v);tmStart();
 return '<canvas class="tmapcv" data-tm="m" style="aspect-ratio:'+st.m.W+'/'+st.m.H+'" role="img" aria-label="'+esc(t('Tunnels'))+'"></canvas>'};
// the drawing; where things sit comes from tmLayout
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
 m.tl.forEach(function(x,i){var G=m.E[x.id];if(!G)return;var pts=G.pts,A=pts[0],B=pts[pts.length-1],col=tmRgb(x._col||tunCol(x.state)),es=x.entry_status||{},k=0,same=[x];
  var segs=[],tot=0;for(var q=0;q+1<pts.length;q++){var sl=Math.hypot(pts[q+1].x-pts[q].x,pts[q+1].y-pts[q].y);segs.push(sl);tot+=sl}
  var bz=function(u){var d=Math.max(0,Math.min(1,u))*tot;for(var q=0;q<segs.length;q++){if(d<=segs[q]||q==segs.length-1){var f=segs[q]?Math.min(1,d/segs[q]):0;return {x:pts[q].x+(pts[q+1].x-pts[q].x)*f,y:pts[q].y+(pts[q+1].y-pts[q].y)*f}}d-=segs[q]}return B};
  var path=function(){c.beginPath();c.moveTo(A.x,A.y);for(var q=1;q+1<pts.length;q++)c.arcTo(pts[q].x,pts[q].y,pts[q+1].x,pts[q+1].y,10);c.lineTo(B.x,B.y)};
  var tail=segs[segs.length-1]+(segs.length>3?segs[segs.length-2]:0),ls=tot?(tot-tail)/tot:0,lt=ls+(1-ls)*.22,up=x.state=='up',part=x.state=='partial',down=!up&&!part,flick=part?(.65+.35*Math.sin(T*7+i)):1;
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
   labs.push(function(){var zr=es.rtt_ms||0,zc=tmRgb(x._col||tunCol(x.state)),l1=x._lab||tmShort(x),l2=x.state=='down'||x.state=='off'?t('down'):zr?zr+'ms':'…';
    c.direction='ltr';c.textAlign='center';c.font='800 10.5px Vazirmatn,sans-serif';var lw=Math.max(c.measureText(l1).width,c.measureText(l2).width)+16,lh=31;
    c.fillStyle=th.disc;tmRound(c,bp.x-lw/2,bp.y-lh/2,lw,lh,9);c.fill();c.strokeStyle=tmA(zc,.7);c.lineWidth=1;c.stroke();
    c.fillStyle=th.t;c.fillText(l1,bp.x,bp.y-2);c.font='700 10px Vazirmatn,sans-serif';c.fillStyle=tmA(zc,1);c.fillText(l2,bp.x,bp.y+11)})}});
 labs.forEach(function(f){f()});
 // ---- servers
 m.sv.forEach(function(s,i){var P=m.pos[s.id];if(!P)return;var col=tmRgb(s._col?(s.online?s._col:'#8a8f98'):s.online?'#3ddc97':'#ff6b6b'),br=.5+.5*Math.sin(T*2.1+i),Z=s.id==m.hub?1.25:1;c.save();c.translate(P.x,P.y);c.scale(Z,Z);c.translate(-P.x,-P.y);
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
  var mx=m.mx||(m.n>9?10:14),nm0=(m.ab&&m.ab[s.id])||s.name,nm=nm0.length>mx?nm0.slice(0,mx-1)+'…':nm0;c.font='700 12.5px Vazirmatn,sans-serif';var nw=c.measureText(nm).width+12,ny=s.id!=m.hub&&P.y<m.cy-20?P.y-24*Z-14:P.y+24*Z+19; // the name on the outer side, away from the lines
  c.fillStyle=tmA(tmRgb(th.disc),.72);tmRound(c,P.x-nw/2,ny-13,nw,18,9);c.fill();c.fillStyle=th.t;c.textAlign='center';c.direction=/[\u0600-\u06FF]/.test(nm)?'rtl':'ltr';c.fillText(nm,P.x,ny)})};

})();

// ==================================================================== the look: menu, rails, cards
// the menu and motion: side menu groups that open and close (or the whole menu in one row across the
// top), the Cores rail of cards with a server's settings right below its chip, users in two columns
// of slim cards, and pages that come in card by card.
(function(){
'use strict';
var V=V37;
var CHEV='<svg class="kd-chev" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg>';
function store(k,v){try{if(v===undefined)return localStorage.getItem(k);localStorage.setItem(k,v)}catch(e){}return null}

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
window.shell=function(){var me=S.me||{},nm=me.panel_name||'Kanki Panel',L=nm.charAt(0);
 $('#app').innerHTML='<header class="top"><div class="'+logoCls()+'" id="mlogo">'+logoInner(L)+'</div>'+
 '<div class="tb-title"><small><span>'+esc(nm)+'</span><span>›</span><span id="tbsec"></span></small><b id="tbt"></b></div><div class="sp"></div>'+
 '<div class="tb-act"><div class="kd-lay" role="group" aria-label="'+esc(t('Top menu'))+'"><button type="button" data-m="side" onclick="kdMenu(\'side\')">'+t('Side menu')+'</button><button type="button" data-m="top" onclick="kdMenu(\'top\')">'+t('Top menu')+'</button></div><div class="segl"><button data-l="fa" class="'+(S.lang=='fa'?'on':'')+'">FA</button><button data-l="en" class="'+(S.lang=='en'?'on':'')+'">EN</button></div>'+
 '<button class="ib" id="thm" title="'+t('Theme')+'" aria-label="theme">'+ic('moon',17)+'</button>'+
 '<button class="ib" id="upd" title="'+t('Update')+'"><span class="dot" id="updot"></span><span class="uv ltr">v'+esc(me.version||'')+'</span></button>'+
 '<div class="uchip2" title="'+esc(me.user||'')+'"><i>'+esc((me.user||'A').charAt(0).toUpperCase())+'</i><span>'+esc(me.user||'')+'</span></div>'+
 '<button class="ib" id="lo" title="'+t('Logout')+'" aria-label="logout">'+ic('logout',17)+'</button></div></header>'+topNav()+
 '<nav class="side" id="side"><div class="sbrand"><div class="'+logoCls()+'">'+logoInner(L)+'</div><div style="min-width:0"><b>'+esc(nm)+'</b><small>'+t('VPN management')+'</small></div>'+
  '<button type="button" class="kd-fold" onclick="kdMini()" aria-label="'+esc(t('Fold the menu'))+'" title="'+esc(t('Fold the menu'))+'">'+CHEV+'</button></div>'+
 '<div class="snav">'+navSide()+'</div>'+
 '<div class="sfoot"><button class="sver" id="upd2"><span class="dot" id="updot2"></span><span><b class="ltr">v'+esc(me.version||'')+'</b><small id="updt">'+t('Check for update')+'</small></span></button>'+
 '<a href="#" id="lo2" class="lo2"><span class="ni">'+ic('logout',18)+'</span>'+t('Logout')+'</a></div></nav><div class="shade" id="shade"></div>'+navBar()+'<main id="pg"></main>';
 $('#shade').onclick=function(){$('#side').classList.remove('on');$('#shade').classList.remove('on')};
 $('#msheet').onclick=function(e){if(e.target.closest('a'))navMark(S.page,S.sub)};
 var mb=$('#mbar');if(mb){mb.addEventListener('touchstart',function(){mb._touch=1},{passive:true});
  mb.addEventListener('touchend',function(){setTimeout(function(){mb._touch=0},400)},{passive:true})}
 if(!window._navDoc){window._navDoc=1;document.addEventListener('click',function(e){var sh=$('#msheet');if(sh&&sh.classList.contains('on')&&!e.target.closest('#msheet,#mbar'))navMark(S.page,S.sub)})}
 $$('[data-l]').forEach(function(b){b.onclick=function(){S.lang=b.dataset.l;localStorage.setItem('kk_lang',S.lang);applyLook();shell();route()}});
 $('#thm').onclick=function(){S.theme=S.theme=='light'?'dark':'light';localStorage.setItem('kk_theme',S.theme);applyLook()};
 $('#lo').onclick=function(){logout()};$('#lo2').onclick=function(e){e.preventDefault();logout()};
 $('#upd').onclick=updateModal;$('#upd2').onclick=function(){$('#shade').click();location.hash='#settings';S.stsec='upd';if(S.page=='settings')route()};
 // page headers get the page icon, whenever a page draws (or redraws) its header
 new MutationObserver(decoratePh).observe($('#pg'),{childList:true,subtree:true});
 api('GET','/api/update/check').then(function(r){var c='dot '+(r.available?'y':(r.error?'':'g'));
  ['#updot','#updot2'].forEach(function(x){var d=$(x);if(d)d.className=c});
  var u=$('#updt');if(u)u.textContent=r.available?t('A new version is available.'):(r.error?t('Update source not set'):t('You are on the latest version.'))}).catch(function(){});
 document.body.classList.add('v37','k38');V.watchPg();V.drawLooks();dragRow($('#kdtop'));look()};
function markAll(){var sk=V.secOf(S.page)[0];
 $$('#kdtop a[data-sec]').forEach(function(a){a.classList.toggle('on',a.dataset.sec==sk)});
 var on=$('#kdtop a.on');if(on&&document.body.classList.contains('kd-topm'))try{on.scrollIntoView({block:'nearest',inline:'center'})}catch(e){}
 var a=$('#side a.on'),g=a&&a.closest('.kd-g');if(g&&!g.classList.contains('open')){g.classList.add('open');var b=$('.kd-gh',g);if(b)b.setAttribute('aria-expanded','true')}}
// the open section lit in every menu, its tabs on top of the page
window.navMark=function(p){var sk=V.secOf(p)[0];
 $$('#side a[data-sec],#mbar a[data-sec]').forEach(function(a){a.classList.toggle('on',a.dataset.sec==sk)});
 V.drawSecTabs(p);k38More(0);
 // the open section stays in sight in the scrolling bar
 // only when it is out of sight and the bar is not being swiped, and never the page itself
 var bar=$('#mbar'),a=bar&&bar.querySelector('a[data-sec="'+sk+'"]');
 if(a&&!bar._touch&&bar.clientWidth){var br=bar.getBoundingClientRect(),r=a.getBoundingClientRect();
  if(r.left<br.left||r.right>br.right)bar.scrollBy({left:(r.left+r.width/2)-(br.left+br.width/2),behavior:'smooth'})}
 V.markTabs();markAll()};

// ---------------------------------------------------------------- pages
window.route=function(){var hs=location.hash||'';
 // old addresses
 if(hs=='#xray'){location.replace('#xray/status');return}
 if(hs.slice(1).split('/')[0]=='servers'){location.replace('#nodes');return}
 Object.keys(KAcc.open).forEach(function(k){KAcc.open[k]=''});
 var h=(hs||'#dash').slice(1).split('/'),p=h[0];S.sub=h[1]||'';if(!PAGES.some(function(x){return x[0]==p})){p='dash';S.sub=''}S.page=p;
 var tb=$('#tbt');if(tb){tb.textContent=t(pgOf(p)[1]);$('#tbsec').textContent=t(grpOf(p))}
 navMark(p,S.sub);clearPageTimers();window.scrollTo(0,0);
 (({dash:pDash,users:pUsers,nodes:pNodes,servers:pServers,tunnels:pTunnels,traffic:pTraffic,ports:pPorts,bot:pBot,emergency:pEmergency,backup:pBackup,security:pSecurity,settings:pSettings})[p]||window['p_'+p])();
 V.watchPg();V.drawSecTabs(S.page);
 // every page comes in card by card
 var pg=$('#pg');if(pg){pg.classList.remove('kd-enter');void pg.offsetWidth;pg.classList.add('kd-enter');clearTimeout(pg._kd);pg._kd=setTimeout(function(){pg.classList.remove('kd-enter')},1400)}
};

// Anti-DPI: the methods fold to one line (name, tags, make); a tap shows what each one is for
function antidpi(){if(S.page!='antidpi')return;$$('#pg .g2>.box').forEach(function(b){if(b.classList.contains('kd-tpl'))return;b.classList.add('kd-tpl');
 b.addEventListener('click',function(e){if(e.target.closest('button'))return;b.classList.toggle('open')})})}
// REALITY: test the suggested targets from the panel server and mark the ones that work
function reality(){var sel=$('#xi_dp');if(!sel||$('#kd_rt'))return;
 sel.insertAdjacentHTML('afterend','<button type="button" class="b2 sm" id="kd_rt">'+t('Test the sites')+'</button>');
 $('.inl',$('#xi_rl')).insertAdjacentHTML('afterend','<div id="kd_rtl" class="kd-rtl"></div>');
 $('#kd_rt').onclick=function(){var b=this,box=$('#kd_rtl');b.disabled=true;b.textContent=t('Testing…');box.innerHTML='';
  api('POST','/api/xray/reality/test',{targets:REALITY_TARGETS}).then(function(r){b.disabled=false;b.textContent=t('Test again');
   var res=(r.results||[]).sort(function(a,c){return (c.ok-a.ok)||((a.ms||9e9)-(c.ms||9e9))});
   box.innerHTML='<small class="muted">'+t('Tested from the panel server: TLS 1.3, a valid certificate and HTTP/2. Tap one to use it.')+'</small><div class="kd-rtg">'+res.map(function(x){var h=x.target.split(':')[0];
    return '<button type="button" class="kd-rt '+(x.ok?'ok':x.tls13?'mid':'bad')+'" data-t="'+esc(x.target)+'" title="'+esc(x.error||'')+'"><i>'+(x.ok?'✓':'✕')+'</i><span class="ltr">'+esc(h)+'</span>'+(x.ms?'<small class="ltr">'+N(x.ms)+'ms</small>':'')+(/\.ir$/.test(h)?'<em>IR</em>':'')+'</button>'}).join('')+'</div>';
   $$('.kd-rt',box).forEach(function(c){c.onclick=function(){$('#xi_de').value=c.dataset.t;$('#xi_na').value=c.dataset.t.split(':')[0];$$('.kd-rt',box).forEach(function(z){z.classList.toggle('pick',z==c)})}})}).catch(function(e){b.disabled=false;b.textContent=t('Test the sites');fail(e)})}}
// the dashboard numbers get a turning edge in their own colour
function kpiEdges(){$$('#kpis .kpi').forEach(function(k){if(!$('.kd-edge',k))k.insertAdjacentHTML('beforeend','<i class="kd-edge" aria-hidden="true"></i>')})}
// every turning edge turns in step with the others, and a redraw does not send it back to the start
var EDGE='.kd-it.on,.kd-tn.on,.uchip.kd-u,#st .stn button.on,.k310st,.kd-edge,.kxr[data-acc="srv"]>.kxr-h';
function phase(){var ph=-((Date.now()/1000)%3.2);$$(EDGE).forEach(function(e){if(!e._kdph){e._kdph=1;e.style.setProperty('--kdph',ph.toFixed(2)+'s')}})}
// whatever a page draws is dressed right away: number icons, tab marks, drawers, rails and chips
new MutationObserver(function(){if($('#kpis'))V.kpiIcons();if($('#sectabs'))V.markTabs();antidpi();reality();kpiEdges();phase()}).observe(document.body,{childList:true,subtree:true});

// ---------------------------------------------------------------- users: two columns, data and expiry date
 window.uchip=function(u){var st=ustate(u),lv=liveOf(u),on=u.online_connections>0||lv.length>0,dot=st=='disabled'?'r':st=='finished'?'y':(on?'g':''),ps=[];
  lv.forEach(function(c){if(ps.indexOf(c.p)<0)ps.push(c.p)});
  var pc=usage(u),used=(+u.traffic_used_gb||0).toFixed(1),exp=st=='disabled'?t('Disabled'):!u.expires_ts?'∞':u.expires_ts<Date.now()/1000?t('Expired'):jdate(u.expires_ts);
  return '<button class="uchip kd-u st-'+st+(on?' on':'')+(S.sel[u.id]?' sel':'')+'" data-id="'+u.id+'" title="'+esc(u.username)+'">'+
   '<span class="kd-un"><span class="dot '+dot+'"></span><span class="nm">'+esc(u.username)+'</span>'+
   (ps.length?'<span class="lvs">'+liveBadges(lv)+'</span>':'')+
   '<span class="tick">'+ic('check',13)+'</span></span>'+
   '<span class="k310bar'+(pc<0?' inf':pc>=90?' hot':pc>=70?' warm':'')+'"><i style="width:'+(pc<0?100:Math.max(3,pc))+'%"></i></span>'+
   '<span class="kd-meta"><span>'+t('Data')+' <b class="ltr" title="'+esc(exactB(u.used_bytes))+'">'+exactB(u.used_bytes,false)+(pc<0?' / ∞':' / '+N(u.traffic_limit_gb)+' GB')+'</b></span><span>'+t('Expires')+' <b>'+exp+'</b></span></span></button>'};

look();
})();

/* 3.13 — what a delete left to do on each server, live: a small card at the bottom lists every
   server's part (stop the tunnel, remove everything, remove the VPN services) with a spinner,
   a tick when that server confirmed it, or "off" (it is done when the server comes back). */
(function(){
var fa=function(){return (document.documentElement.dir||'rtl')=='rtl'};
function L(p,e){return fa()?p:e}
var RM={},timer=0,started=0;
var WHAT={tunnel:['توقف تانل و آزاد کردن پورت‌ها','stop the tunnel, free its ports'],
 server:['پاک کردن همه‌چیز و حذف خودِ سرور','remove everything and uninstall'],
 node:['حذف سرویس‌های VPN و بستن پورت‌ها','remove the VPN services, close ports'],
 xray:['حذف Xray و بستن پورت‌هایش','remove Xray, close its ports'],
 dns:['حذف DNS کانکی و بستن پورت‌هایش','remove Kanki DNS, close its ports']};
var KIND={tunnel:['تانل','tunnel'],server:['سرور','server'],node:['سرور','server'],xray:['Xray','Xray'],dns:['DNS','DNS']};
function esc2(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function box(){var b=document.getElementById('kdrm');if(!b){b=document.createElement('div');b.id='kdrm';b.setAttribute('role','status');b.setAttribute('aria-live','polite');document.body.appendChild(b);
 b.onclick=function(e){if(e.target.closest('.kdrm-x'))close()}}return b}
function close(){var b=document.getElementById('kdrm');if(b){b.classList.remove('on');setTimeout(function(){if(!b.classList.contains('on'))b.remove()},350)}RM={};clearTimeout(timer);timer=0}
function draw(){
 var ids=Object.keys(RM);if(!ids.length)return;
 var all=true,h='';
 ids.forEach(function(id){var r=RM[id].r;if(!r){all=false;return}
  var w=KIND[r.kind]||KIND.server;
  h+='<div class="kdrm-g"><div class="kdrm-n">'+esc2(L(w[0],w[1]))+' <b>'+esc2(r.name)+'</b></div>';
  if(!r.steps.length)h+='<div class="kdrm-r done"><i></i><span>'+L('از پنل حذف شد','removed from the panel')+'</span></div>';
  r.steps.forEach(function(s){if(s.state!='done')all=false;var d=WHAT[s.what]||WHAT.server;
   var tail=s.state=='done'?L('پاک شد','removed'):s.state=='off'?L('خاموش است؛ وقتی برگردد پاک می‌شود','off — removed when it is back'):L('در حال حذف…','removing…');
   h+='<div class="kdrm-r '+s.state+'"><i></i><span><b>'+esc2(s.name)+'</b> · '+esc2(L(d[0],d[1]))+'<em>'+tail+'</em></span></div>'});
  h+='</div>'});
 var late=Date.now()-started>180000;
 var title=all?L('همه‌چیز پاک شد ✓','everything removed ✓'):late?L('بقیه در پس‌زمینه انجام می‌شود','the rest goes on in the background'):L('در حال حذف از سرورها…','removing from the servers…');
 var b=box();b.className='on'+(all?' all':'');
 b.innerHTML='<div class="kdrm-h"><span class="kdrm-sp"></span><b>'+title+'</b><button class="kdrm-x" aria-label="'+L('بستن','close')+'">✕</button></div>'+h;
 return all||late}
function poll(){timer=0;var ids=Object.keys(RM);if(!ids.length)return;
 Promise.all(ids.map(function(id){return window.api('GET','/api/removals/'+encodeURIComponent(id)).then(function(r){if(RM[id])RM[id].r=r}).catch(function(){if(RM[id]&&!RM[id].r)delete RM[id]})})).then(function(){
  var fin=draw();
  if(document.querySelector('#kdrm.all')){timer=setTimeout(close,3500);return}
  // after three minutes it stops asking; what is left is done when those servers come back
  if(!fin)timer=setTimeout(poll,2000)})}
function follow(rid){if(!rid)return;if(!Object.keys(RM).length)started=Date.now();RM[rid]={r:null};clearTimeout(timer);timer=setTimeout(poll,600)}
window.kdFollowRemoval=follow;
})();

