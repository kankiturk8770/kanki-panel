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
function sheetHtml(){var g='',h='<div class="ksh-h"><i class="ksh-grab" aria-hidden="true"></i><b>'+t('All sections')+'</b><button type="button" class="kib" onclick="k38More(0)" aria-label="'+esc(t('Close'))+'">✕</button></div>',open=false,cur=V.secOf(S.page)[0];
 V.SECS.forEach(function(s){if(s[4]!=g){if(open)h+='</div>';g=s[4];h+='<div class="ksh-g">'+t(g)+'</div><div class="ksh-tiles">';open=true}
  h+='<a class="ksh-t'+(cur==s[0]?' on':'')+'" href="'+href(s[3][0])+'"'+(cur==s[0]?' aria-current="page"':'')+'>'+ic(s[2],20)+'<span>'+t(s[1])+'</span></a>'});
 return h+(open?'</div>':'')}
window.k38More=function(on){var sh=$('#msheet'),sc=$('#k38scrim'),mb=$('#mbmore');if(!sh)return;var was=sh.classList.contains('on');if(on===undefined)on=!was;
 if(on&&!was)sh.innerHTML=sheetHtml();sh.classList.toggle('on',!!on);if(sc)sc.classList.toggle('on',!!on);if(mb)mb.setAttribute('aria-expanded',!!on);
 document.body.classList.toggle('ksh-open',!!on);
 if(on&&!was)setTimeout(function(){sh.focus()},30);else if(!on&&was&&mb&&sh.contains(document.activeElement))mb.focus()};
// the sheet keeps the keyboard inside it, and Esc closes it (and the account menu)
document.addEventListener('keydown',function(e){var sh=$('#msheet');
 if(e.key=='Escape'){if(sh&&sh.classList.contains('on'))k38More(0);if(window.kAcct)kAcct(0);return}
 if(e.key=='Tab'&&sh&&sh.classList.contains('on')){var f=$$('a,button',sh);if(!f.length)return;var a=f[0],z=f[f.length-1];
  if(e.shiftKey&&(document.activeElement==a||document.activeElement==sh)){e.preventDefault();z.focus()}else if(!e.shiftKey&&document.activeElement==z){e.preventDefault();a.focus()}}});
// a section whose tabs are sub pages of one page (Xray): mark the tab of the sub page, not all of them
function markTabs(){var el=$('#sectabs');if(!el)return;var as=$$('a.kcb-t,a.kcb-ov',el),h=location.hash||'',hit=as.filter(function(a){return a.getAttribute('href')==h});
 if(!hit.length){var p='#'+S.page;hit=as.filter(function(a){return a.getAttribute('href').split('/')[0]==p}).slice(0,1)}
 as.forEach(function(a){var on=hit.indexOf(a)>=0;a.classList.toggle('on',on);if(a.classList.contains('kcb-t'))a.setAttribute('aria-selected',on);if(on)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current')})}
V.markTabs=markTabs;




// ---------------------------------------------------------------- dashboard
// (3.41) look, then decide: the server and its health at the top, six numbers, live traffic beside the
// server's resources, then only what needs you (servers, tunnels and services in trouble, the latest
// errors) and a summary of the connections. Starting and stopping services lives in VPN & cores, the
// full log in the emergency page's Logs tab, every server in Servers.
window.pDash=function(){dbReset();
 var iv=[1,2,5,10].map(function(n){return '<option value="'+n+'"'+(n==DB.iv?' selected':'')+'>'+N(n)+' '+t('seconds')+'</option>'}).join('');
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Dashboard')+'</h2><p class="ltr kd2-sub" id="d_sub">…</p></div>'+
  '<div class="row kd2-acts"><span class="kpill" id="d_health"><i class="dot"></i><span>…</span></span>'+
  '<span class="live" id="d_live"><i></i><span id="d_lt">'+t('Live')+'</span></span>'+
  '<label class="kd2-iv"><span class="vh">'+t('Refresh every')+'</span><select id="d_iv">'+iv+'</select></label>'+
  '<button type="button" class="kib" id="d_pause" aria-label="'+esc(t('Pause'))+'" title="'+esc(t('Pause'))+'">'+ic('pause',16)+'</button>'+
  '<button type="button" class="btn" onclick="newUser()">'+ic('plus',16)+'<span>'+t('New user')+'</span></button></div></div>'+
 '<section class="kd2-kpis" id="kpis" aria-label="'+esc(t('Users'))+'">'+kpiSkel()+'</section>'+
 '<div class="kgrid">'+
  '<section class="card kd2-net c8"><div class="kc-h"><div><h3>'+t('Network speed')+'</h3><small class="muted ltr" id="n_if">&nbsp;</small></div>'+
   '<div class="kd2-big"><div class="dn"><small>↓ '+t('Download')+'</small><b id="n_rx" class="ltr">—</b></div><div class="upl"><small>↑ '+t('Upload')+'</small><b id="n_tx" class="ltr">—</b></div></div></div>'+
   '<div class="ch kd2-ch" id="ch_net"></div>'+
   '<dl class="kd2-foot ltr"><div><dt>'+t('Peak')+' ↓</dt><dd id="n_prx">—</dd></div><div><dt>'+t('Peak')+' ↑</dt><dd id="n_ptx">—</dd></div><div><dt>'+t('Total since boot')+' ↓</dt><dd id="n_trx">—</dd></div><div><dt>'+t('Total since boot')+' ↑</dt><dd id="n_ttx">—</dd></div></dl></section>'+
  '<section class="card kd2-res c4"><div class="kc-h"><h3>'+t('Server resources')+'</h3></div><div class="kd2-gg">'+gcard('cpu','CPU',ic('cpu',14))+gcard('ram','RAM',ic('ram',14))+gcard('disk','Storage',ic('disk',14))+gcard('swap','Swap',ic('swap',14))+'</div></section>'+
  '<section class="card kd2-att c8"><div class="kc-h"><div><h3>'+t('Needs attention')+'</h3><small class="muted" id="att_sub">&nbsp;</small></div><div class="kd2-chips" id="k310strip"></div></div><div id="att" class="kd2-attl"><div class="kskel"></div><div class="kskel"></div></div></section>'+
  '<section class="card kd2-con c4"><div class="kc-h"><div><h3>'+t('TCP / UDP connections')+'</h3><small class="muted" id="c_sub">&nbsp;</small></div><a class="b2 sm" href="#ports">'+t('Ports')+'</a></div>'+
   '<div class="kd2-big"><div class="dn"><small>TCP</small><b id="c_tcp" class="ltr">—</b></div><div class="upl"><small>UDP</small><b id="c_udp" class="ltr">—</b></div></div><div class="ch kd2-chs" id="ch_con"></div></section>'+
 '</div>';
 $('#d_iv').onchange=function(){DB.iv=+this.value;localStorage.setItem('kk_div',DB.iv);dashTimers()};
 $('#d_pause').onclick=function(){DB.paused=!DB.paused;if(!DB.paused)DB.last=null;var l=t(DB.paused?'Resume':'Pause');this.innerHTML=ic(DB.paused?'play':'pause',16);this.title=l;this.setAttribute('aria-label',l);this.setAttribute('aria-pressed',DB.paused);dashLive(DB.paused?'off':'')};
 $('#kpis').onclick=function(e){var b=e.target.closest('[data-go]');if(b)goUsers(b.dataset.go)};
 dashTick();dashSys();dashTimers();dashErrs();
 strip();clearInterval(S.timer4);S.timer4=setInterval(function(){if(S.page!='dash'){clearInterval(S.timer4);return}strip()},3000)};
var KPIS=[['a','Total users','users','all'],['g','Online','k310online','online'],['g','Active','k310ok','active'],['y','Expired / out of data','k310warn','finished'],['r','Disabled','k310off','disabled'],['a','Total traffic','k310traffic','']];
function kpiOne(x,v,u){return '<button type="button" class="kstat tone-'+x[0]+'"'+(x[3]?' data-go="'+x[3]+'"':' disabled')+'><span class="kstat-l">'+t(x[1])+'</span><span class="kstat-v"><b class="ltr">'+v+'</b>'+(u?'<em>'+u+'</em>':'')+'</span><span class="kstat-i" aria-hidden="true">'+ic(x[2],18)+'</span></button>'}
function kpiSkel(){return KPIS.map(function(x){return kpiOne(x,'—','')}).join('')}
window.drawKpis=function(o){var el=$('#kpis');if(el&&o){var v=[o.users,o.online,o.active,o.expired,o.disabled];
 el.innerHTML=KPIS.map(function(x,i){return i<5?kpiOne(x,N(v[i]||0),''):kpiOne(x,N(o.traffic_gb||0),'GB')}).join('')}
 strip()};
function chip(c,label,val,href){return '<a class="kpill '+c+'" href="'+href+'"><i class="dot '+c+'"></i><span>'+t(label)+'</span><b class="ltr">'+val+'</b></a>'}
function strip(){var el=$('#k310strip');if(!el)return;var h='';
 var ns=S.nodes||[];if(ns.length){var on=ns.filter(function(n){return n.online||n.id=='local'}).length;h+=chip(on==ns.length?'g':on?'y':'r','Servers online',N(on)+' / '+N(ns.length),'#nodes')}
 var tl=(TN.d&&TN.d.tunnels)||[];if(tl.length){var up=tl.filter(function(x){return x.state=='up'}).length;h+=chip(up==tl.length?'g':up?'y':'r','Tunnels up',N(up)+' / '+N(tl.length),'#tunnels')}
 var sv=((DB.sys||{}).services||[]);if(sv.length){var bad=sv.filter(function(x){return !x.active}).length;h+=chip(bad?'y':'g','Services',bad?N(bad)+' '+t('stopped'):t('all running'),'#vpn')}
 if(el._h!==h){el._h=h;el.innerHTML=h}
 attention()}
// what needs you now: each problem once, with where to fix it; the last errors of the log under them
function attention(){var el=$('#att');if(!el)return;var it=[];
 (S.nodes||[]).forEach(function(n){var h=nHealthOf(n),loc=n.id=='local';
  if(!loc&&!n.online)it.push(['r','nodes',esc(n.name),t('Disconnected')+' · '+t('Last contact')+' '+ago(n.last_sync),'#nodes']);
  else if(h.c!='g')it.push([h.c,'nodes',esc(n.name),esc(t(h.l))+((h.r&&h.r.length)?' · '+esc(t(h.r.slice().sort(function(a,b){return b[0]-a[0]})[0][1])):''),'#nodes'])});
 ((TN.d&&TN.d.tunnels)||[]).forEach(function(x){if(x.enabled!==false&&x.state&&x.state!='up'&&x.state!='off')it.push([x.state=='partial'?'y':'r','tunnel',esc(x.name||x.id),t('Tunnel')+' · '+t(x.state=='partial'?'Partly down':'Down'),'#tunnels'])});
 (((DB.sys||{}).services)||[]).forEach(function(x){if(!x.active)it.push(['y','cores',esc(SVN[x.key]||x.key),t('Stopped'),'#vpn'])});
 var er=(DB.errs||[]).slice(-3).reverse(),h='';
 h+=it.length?'<ul class="kd2-list">'+it.slice(0,8).map(function(x){return '<li><a href="'+x[4]+'"><i class="dot '+x[0]+'"></i><span class="ki">'+ic(x[1],16)+'</span><b>'+x[2]+'</b><small>'+x[3]+'</small></a></li>'}).join('')+'</ul>'+
   (it.length>8?'<p class="muted">+'+N(it.length-8)+'</p>':''):
  '<div class="kd2-ok"><span>'+ic('check',18)+'</span><div><b>'+t('Everything is working')+'</b><small>'+t('No server, tunnel or service needs you right now.')+'</small></div></div>';
 h+='<div class="kd2-ev"><div class="kd2-evh"><b>'+t('Latest errors')+'</b><a href="#emergency/logs">'+t('All logs')+'</a></div>'+
  (DB.errs==null?'<div class="kskel"></div>':er.length?er.map(function(x){return '<div class="kd2-evr"><time class="ltr">'+logTime(x.ts)+'</time><span class="ltr">'+esc(String(x.u||'').replace(/\.service$/,''))+'</span><code class="ltr">'+esc(x.m)+'</code></div>'}).join(''):'<p class="muted">'+t('No errors')+'</p>')+'</div>';
 var sub=$('#att_sub');if(sub)sub.textContent=it.length?N(it.length)+' '+t('item(s)'):t('All clear');
 var hp=$('#d_health');if(hp){var c=it.some(function(x){return x[0]=='r'})?'r':it.length?'y':'g';hp.className='kpill '+c;hp.innerHTML='<i class="dot '+c+'"></i><span>'+(c=='g'?t('Healthy'):N(it.length)+' '+t('issue(s)'))+'</span>'}
 if(el._h!==h){el._h=h;el.innerHTML=h}}
function dashErrs(){api('GET','/api/logs?src=all&n=200').then(function(r){DB.errs=(r.lines||[]).filter(function(x){return lgLevel(x)=='e'});attention()}).catch(function(){DB.errs=[];attention()})}

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

// ---------------------------------------------------------------- the shell (3.41)
// One sidebar (or, if chosen, one menu across the top: never both), a 64px header in three parts
// (where you are · what needs you · language, day/night, account) and the page. The panel's name
// sits in the sidebar on a desktop and in the header on a phone; the version, the update and the
// logout live in the account menu only.
function groups(){var gs=[];V.SECS.forEach(function(s){var g=gs[gs.length-1];if(!g||g.l!=s[4])gs.push(g={l:s[4],s:[]});g.s.push(s)});return gs}
function href(f){return '#'+f[0]+(f[1]?'/'+f[1]:'')}
window.navSide=function(){
 return groups().map(function(g){
  return '<div class="ksn-g"><div class="ksn-gl">'+t(g.l)+'</div>'+g.s.map(function(s){var f=s[3][0];
   return '<a href="'+href(f)+'" data-p="'+f[0]+'" data-sec="'+s[0]+'" class="ksn-it" title="'+esc(t(s[1]))+'"><span class="ksn-ic">'+ic(s[2],18)+'</span><span class="ksn-l">'+t(s[1])+'</span></a>'}).join('')+'</div>'}).join('')};
function topNav(){return '<nav class="kst" id="kdtop" aria-label="'+esc(t('Top menu'))+'">'+groups().map(function(g){
  return '<span class="kst-g">'+t(g.l)+'</span>'+g.s.map(function(s){var f=s[3][0];return '<a href="'+href(f)+'" data-sec="'+s[0]+'" class="kst-it">'+ic(s[2],16)+'<span>'+t(s[1])+'</span></a>'}).join('')}).join('')+'</nav>'}
// drag a row sideways with the mouse (fingers scroll it by themselves); a drag is not a click
function dragRow(el){if(!el||el._kd)return;el._kd=1;var d=null,moved=false;
 el.addEventListener('pointerdown',function(e){if(e.pointerType!='mouse')return;d={x:e.clientX,l:el.scrollLeft};moved=false});
 el.addEventListener('pointermove',function(e){if(!d)return;var dx=e.clientX-d.x;if(Math.abs(dx)>5)moved=true;if(moved)el.scrollLeft=d.l-dx});
 var up=function(){d=null};el.addEventListener('pointerup',up);el.addEventListener('pointerleave',up);
 el.addEventListener('click',function(e){if(moved){e.preventDefault();e.stopPropagation();moved=false}},true)}
function look(){var top=store('kk_menu')=='top',mini=store('kk_mini')=='1';
 document.body.classList.toggle('ks-topm',top);document.body.classList.toggle('ks-mini',mini&&!top);
 $$('#kmenu [data-m]').forEach(function(b){b.setAttribute('aria-checked',(b.dataset.m=='top')==top)});
 var f=$('#kfold');if(f){f.setAttribute('aria-pressed',mini);f.title=t(mini?'Open the menu':'Fold the menu');f.setAttribute('aria-label',f.title)}}
window.kdMenu=function(m){store('kk_menu',m);look();markAll();if(window.kAcct)kAcct(0)};
window.kdMini=function(){store('kk_mini',store('kk_mini')=='1'?'0':'1');look()};
// the account menu: who is signed in, the version and its update, where the menu sits, logout
window.kAcct=function(on){var m=$('#kmenu'),b=$('#kacct');if(!m||!b)return;if(on===undefined)on=m.hidden;m.hidden=!on;b.setAttribute('aria-expanded',!!on);
 if(on){var f=m.querySelector('button');if(f)f.focus()}};
document.addEventListener('click',function(e){var m=$('#kmenu');if(m&&!m.hidden&&!e.target.closest('#kmenu,#kacct'))kAcct(0)});
function acctMenu(me){return '<div class="kam" id="kmenu" role="menu" hidden>'+
 '<div class="kam-who"><i>'+esc((me.user||'A').charAt(0).toUpperCase())+'</i><div><b class="ltr">'+esc(me.user||'')+'</b><small>'+t('Administrator')+'</small></div></div>'+
 '<button type="button" role="menuitem" class="kam-it" id="upd2"><span class="dot" id="updot2"></span><span><b class="ltr">v'+esc(me.version||'')+'</b><small id="updt">'+t('Check for update')+'</small></span></button>'+
 '<div class="kam-sep kam-lang" role="none"><span>'+t('Language')+'</span><div class="segl" role="group"><button type="button" data-l="fa" class="'+(S.lang=='fa'?'on':'')+'">FA</button><button type="button" data-l="en" class="'+(S.lang=='en'?'on':'')+'">EN</button></div></div>'+
 '<div class="kam-sep kam-lay" role="group" aria-label="'+esc(t('Menu position'))+'"><span>'+t('Menu position')+'</span><div class="segl"><button type="button" role="menuitemradio" data-m="side" onclick="kdMenu(\'side\')">'+t('Side menu')+'</button><button type="button" role="menuitemradio" data-m="top" onclick="kdMenu(\'top\')">'+t('Top menu')+'</button></div></div>'+
 '<button type="button" role="menuitem" class="kam-it kam-out" id="lo">'+ic('logout',17)+'<span>'+t('Logout')+'</span></button></div>'}
window.shell=function(){var me=S.me||{},nm=me.panel_name||'Kanki Panel',L=nm.charAt(0);
 $('#app').innerHTML='<a class="kskip" href="#pg">'+t('Skip to content')+'</a>'+
 '<aside class="kss" id="side" aria-label="'+esc(t('Main menu'))+'"><div class="kss-brand"><div class="'+logoCls()+'">'+logoInner(L)+'</div><div class="kss-bt"><b>'+esc(nm)+'</b><small>'+t('VPN management')+'</small></div></div>'+
  '<nav class="kss-nav">'+navSide()+'</nav>'+
  '<button type="button" class="kss-fold" id="kfold" onclick="kdMini()">'+ic('chev',16)+'<span>'+t('Fold the menu')+'</span></button></aside>'+
 '<header class="ksh-top top" id="khead"><div class="ksh-brand"><div class="'+logoCls()+'" id="mlogo">'+logoInner(L)+'</div><b>'+esc(nm)+'</b></div>'+
  '<nav class="ksh-id" aria-label="'+esc(t('You are here'))+'"><ol><li id="tbsec"></li><li id="tbt" aria-current="page"></li></ol></nav>'+
  '<div class="ksh-glob" id="kglob"><button type="button" class="kupd" id="upd" hidden><span class="dot y"></span><span>'+t('Update available')+'</span></button></div>'+
  '<div class="ksh-ctl"><div class="segl ksh-lang" role="group" aria-label="'+esc(t('Language'))+'"><button type="button" data-l="fa" class="'+(S.lang=='fa'?'on':'')+'">FA</button><button type="button" data-l="en" class="'+(S.lang=='en'?'on':'')+'">EN</button></div>'+
  '<button type="button" class="kib" id="thm" aria-label="theme">'+ic('moon',18)+'</button>'+
  '<div class="kacc"><button type="button" class="kacct" id="kacct" aria-haspopup="menu" aria-expanded="false" aria-controls="kmenu" onclick="kAcct()"><i>'+esc((me.user||'A').charAt(0).toUpperCase())+'</i><span class="ltr">'+esc(me.user||'')+'</span><span class="dot" id="updot"></span></button>'+acctMenu(me)+'</div></div></header>'+
 topNav()+navBar()+'<main id="pg" tabindex="-1"></main>';
 $('#msheet').onclick=function(e){if(e.target.closest('a'))k38More(0)};
 $$('[data-l]').forEach(function(b){b.onclick=function(){S.lang=b.dataset.l;localStorage.setItem('kk_lang',S.lang);applyLook();shell();route()}});
 $('#thm').onclick=function(){S.theme=S.theme=='light'?'dark':'light';localStorage.setItem('kk_theme',S.theme);applyLook()};
 $('#lo').onclick=function(){logout()};
 $('#upd').onclick=updateModal;$('#upd2').onclick=function(){kAcct(0);updateModal()};
 // page headers get the page icon, whenever a page draws (or redraws) its header
 new MutationObserver(decoratePh).observe($('#pg'),{childList:true,subtree:true});
 api('GET','/api/update/check').then(function(r){var c='dot '+(r.available?'y':(r.error?'':'g'));
  ['#updot2'].forEach(function(x){var d=$(x);if(d)d.className=c});var d1=$('#updot');if(d1)d1.className=r.available?'dot y':'dot hide';
  var ub=$('#upd');if(ub)ub.hidden=!r.available;
  var u=$('#updt');if(u)u.textContent=r.available?t('A new version is available.'):(r.error?t('Update source not set'):t('You are on the latest version.'))}).catch(function(){});
 document.body.classList.add('v37','k38','kd');V.watchPg();V.drawLooks();dragRow($('#kdtop'));look()};
function markAll(){var sk=V.secOf(S.page)[0];
 $$('#kdtop a[data-sec]').forEach(function(a){var on=a.dataset.sec==sk;a.classList.toggle('on',on);if(on)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current')});
 var on=$('#kdtop a.on');if(on&&document.body.classList.contains('ks-topm')){var r=$('#kdtop'),rr=r.getBoundingClientRect(),ar=on.getBoundingClientRect();if(ar.left<rr.left||ar.right>rr.right)r.scrollLeft+=(ar.left+ar.width/2)-(rr.left+rr.width/2)}}
// the open section lit in every menu, the core bar on top of a core's page
window.navMark=function(p){var sk=V.secOf(p)[0];
 $$('#side a[data-sec],#mbar a[data-sec]').forEach(function(a){var on=a.dataset.sec==sk;a.classList.toggle('on',on);if(on)a.setAttribute('aria-current','page');else a.removeAttribute('aria-current')});
 // a section that is not in the bottom bar is open: «More» is lit
 var mm=$('#mbmore');if(mm)mm.classList.toggle('on',!$('#mbar a.on'));
 V.drawSecTabs(p);k38More(0);V.markTabs();markAll()};

// ---------------------------------------------------------------- pages
window.route=function(){var hs=location.hash||'';
 // old addresses: one name and one place for each thing
 if(hs=='#xray'){location.replace('#xray/status');return}
 if(hs.slice(1).split('/')[0]=='servers'){location.replace('#nodes');return}
 Object.keys(KAcc.open).forEach(function(k){KAcc.open[k]=''});
 var h=(hs||'#dash').slice(1).split('/'),p=h[0];S.sub=h[1]||'';if(!PAGES.some(function(x){return x[0]==p})){p='dash';S.sub=''}S.page=p;
 var sec=V.secOf(p),tb=$('#tbt');if(tb){var lbl=(sec[3].filter(function(x){return x[0]==p})[0]||[])[2]||pgOf(p)[1];
  $('#tbsec').textContent=t(sec[4]);tb.textContent=sec[3].length>1?t(sec[1])+' › '+t(lbl):t(sec[1]);
  document.title=t(sec[3].length>1?lbl:sec[1])+' · '+((S.me&&S.me.panel_name)||'Kanki Panel')}
 navMark(p,S.sub);clearPageTimers();window.scrollTo(0,0);
 (({dash:pDash,users:pUsers,nodes:pNodes,tunnels:pTunnels,traffic:pTraffic,ports:pPorts,bot:pBot,emergency:pEmergency,backup:pBackup,security:pSecurity,settings:pSettings})[p]||window['p_'+p])();
 V.watchPg();V.drawSecTabs(S.page);
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
// whatever a page draws is dressed right away: number icons, tab marks, drawers, rails and chips
new MutationObserver(function(){if($('#kpis'))V.kpiIcons();if($('#sectabs'))V.markTabs();antidpi();reality()}).observe(document.body,{childList:true,subtree:true});

// ---------------------------------------------------------------- users: two columns, data and expiry date
 // (3.40) a clean card: name and status, the data bar, data · days left · connections now / allowed,
 // and three quick buttons (copy link, QR, details); the protocols are in the details sheet
 window.uchip=function(u){var st=ustate(u),lv=liveOf(u),conn=Math.max(+u.online_connections||0,lv.length?1:0),on=conn>0,
   dot=st=='disabled'?'r':st=='finished'?'y':(on?'g':''),pc=usage(u),now=Date.now()/1000,
   left=st=='disabled'?'':!u.expires_ts?'∞':u.expires_ts<now?t('Expired'):N(Math.ceil((u.expires_ts-now)/86400))+' '+t('days'),
   badge=st=='active'?['g',t('Active')]:st=='finished'?['y',t(u.status=='Limited'?'Limited':'Expired')]:['r',t('Disabled')];
  return '<div class="uchip uc st-'+st+(on?' on':'')+(S.sel[u.id]?' sel':'')+'" role="button" tabindex="0" data-id="'+u.id+'" aria-label="'+esc(u.username)+'">'+
   '<span class="uc-h"><span class="dot '+dot+'"></span><span class="nm">'+esc(u.username)+'</span><span class="u-st '+badge[0]+'">'+badge[1]+'</span><span class="tick">'+ic('check',13)+'</span></span>'+
   '<span class="k310bar'+(pc<0?' inf':pc>=90?' hot':pc>=70?' warm':'')+'"><i style="width:'+(pc<0?100:Math.max(3,pc))+'%"></i></span>'+
   '<span class="uc-m"><b class="ltr" title="'+esc(exactB(u.used_bytes))+'">'+exactB(u.used_bytes,false)+(pc<0?' / ∞':' / '+N(u.traffic_limit_gb)+' GB')+'</b>'+
    (left?'<span>'+left+'</span>':'')+'<span class="uc-c" title="'+esc(t('Connections'))+'">'+ic('users',13)+'<b class="ltr">'+N(conn)+' / '+(u.max_connections?N(u.max_connections):'∞')+'</b></span></span>'+
   '<span class="uc-a"><button type="button" class="b2 sm" data-q="link" title="'+esc(t('Copy link'))+'" aria-label="'+esc(t('Copy link'))+'">'+ic('link',15)+'</button>'+
    '<button type="button" class="b2 sm" data-q="qr" title="QR" aria-label="QR">'+ic('qr',15)+'</button>'+
    '<button type="button" class="b2 sm" data-q="det">'+t('Details')+'</button></span></div>'};

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

