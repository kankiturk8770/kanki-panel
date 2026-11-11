// ---------------------------------------------------------------- dashboard (live)
var DB={h:{},last:null,iv:+localStorage.getItem('kk_div')||2,paused:false,cpu:0,max:60,peak:{rx:0,tx:0},sys:null,ov:null};
var SVN={wireguard:'WireGuard',amneziawg:'AmneziaWG',hysteria2:'Hysteria2',kankimix:'KANKI MIX',web:'Web (Caddy)',panel:'Kanki Panel',node:'Node agent'};
function dbReset(){DB.h={cpu:[],ram:[],swap:[],disk:[],rx:[],tx:[],tcp:[],udp:[]};DB.last=null;DB.cpu=0;DB.peak={rx:0,tx:0};DB.sys=null;DB.paused=false;DB.dp=null}
function pushH(k,v){var a=DB.h[k];a.push(v);if(a.length>DB.max)a.shift()}
function pc(u,tt){return tt>0?Math.max(0,Math.min(100,100*u/tt)):0}
function rate(b){b=+b||0;var u=['B/s','KB/s','MB/s','GB/s'],i=0;while(b>=1024&&i<3){b/=1024;i++}return (i==0||b>=100?Math.round(b):b.toFixed(b>=10?1:2))+' '+u[i]}
function upt(s){s=Math.floor(+s||0);var d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);return (d?N(d)+' '+t('days')+' ':'')+N(p2(h))+':'+N(p2(m))}
function gcard(id,title,icon){return '<div class="gc" id="gc_'+id+'"><div class="gh"><span>'+icon+'</span><b>'+t(title)+'</b></div><div class="gb">'+
 '<svg class="ring" viewBox="0 0 80 80" aria-hidden="true"><circle class="rb" cx="40" cy="40" r="34"/><circle class="rf" id="rf_'+id+'" cx="40" cy="40" r="34" transform="rotate(-90 40 40)" stroke-dasharray="0 213.6"/><text class="rt" id="rt_'+id+'" x="40" y="46" text-anchor="middle">—</text></svg>'+
 '<div class="gi"><b id="gv_'+id+'">—</b><small id="gs_'+id+'"></small></div></div><div class="ch" id="ch_'+id+'"></div></div>'}
function setRing(id,p,val,sub){var f=$('#rf_'+id);if(!f)return;f.setAttribute('stroke-dasharray',(p*2.136).toFixed(1)+' 213.6');
 $('#gc_'+id).className='gc'+(p>=90?' hot':p>=70?' warm':'');$('#rt_'+id).textContent=N(Math.round(p))+'%';
 $('#gv_'+id).innerHTML=/^[\d۰-۹]/.test(val)?'<bdi class="ltr">'+esc(val)+'</bdi>':esc(val);$('#gs_'+id).textContent=sub||''}
function dashTimers(){clearInterval(S.timer);clearInterval(S.timer2);S.timer=setInterval(dashTick,DB.iv*1000);S.timer2=setInterval(dashSys,10000)}
function dashLive(state){var l=$('#d_live');if(!l)return;l.className='live'+(state?' '+state:'');$('#d_lt').textContent=state=='bad'?t('Reconnecting…'):state=='off'?t('Paused'):t('Live')}
function goUsers(f){S.filter=f;S.q='';S.pg=1;S.pf='all';location.hash='#users'}
function dashTick(){if(S.page!='dash'||DB.paused||document.visibilityState!='visible')return;
 api('GET','/api/live').then(function(l){if(S.page!='dash')return;var p=DB.last,cpu=DB.cpu,rxs=0,txs=0;
  if(p&&l.cpu_total>p.cpu_total){var dT=l.cpu_total-p.cpu_total,dI=l.cpu_idle-p.cpu_idle;cpu=Math.max(0,Math.min(100,100*(1-dI/dT)))}
  else if(!p)cpu=Math.min(100,100*((l.load&&l.load[0])||0)/(l.cores||1));
  if(p&&l.ts>p.ts){var sec=(l.ts-p.ts)/1000;rxs=Math.max(0,(l.net_rx-p.net_rx)/sec);txs=Math.max(0,(l.net_tx-p.net_tx)/sec)}
  DB.last=l;DB.cpu=cpu;
  pushH('cpu',cpu);pushH('ram',pc(l.mem_used,l.mem_total));pushH('swap',pc(l.swap_used,l.swap_total));
  if(p){pushH('rx',rxs);pushH('tx',txs);if(rxs>DB.peak.rx)DB.peak.rx=rxs;if(txs>DB.peak.tx)DB.peak.tx=txs}
  pushH('tcp',l.tcp_est);pushH('udp',l.udp);if(DB.dp!=null)pushH('disk',DB.dp);
  dashLive('');dashDraw(rxs,txs)}).catch(function(){dashLive('bad')})}
function dashDraw(rxs,txs){var l=DB.last;if(!l||!$('#d_sub'))return;
 $('#d_sub').textContent=(l.host||'server')+' · '+(l.kernel||'')+' · '+t('Uptime')+' '+upt(l.uptime);
 var cpu=DB.cpu,rp=pc(l.mem_used,l.mem_total),sp=pc(l.swap_used,l.swap_total);
 setRing('cpu',cpu,N((l.load||[0])[0]),t('Load')+' · '+N(l.cores)+' '+t('Cores'));
 setRing('ram',rp,N(bytes(l.mem_used))+' / '+N(bytes(l.mem_total)),'');
 setRing('swap',sp,l.swap_total>0?N(bytes(l.swap_used))+' / '+N(bytes(l.swap_total)):t('No swap'),'');
 $('#ch_cpu').innerHTML=areaChart([{v:DB.h.cpu,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#ch_ram').innerHTML=areaChart([{v:DB.h.ram,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#ch_swap').innerHTML=areaChart([{v:DB.h.swap,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#ch_disk').innerHTML=areaChart([{v:DB.h.disk,c:'a'}],{h:54,max:100,cap:DB.max});
 $('#n_if').textContent=l.iface||'';$('#n_rx').textContent=N(rate(rxs));$('#n_tx').textContent=N(rate(txs));
 $('#n_prx').textContent=N(rate(DB.peak.rx));$('#n_ptx').textContent=N(rate(DB.peak.tx));$('#n_trx').textContent=N(bytes(l.net_rx));$('#n_ttx').textContent=N(bytes(l.net_tx));
 $('#ch_net').innerHTML=areaChart([{v:DB.h.rx,c:'a'},{v:DB.h.tx,c:'b'}],{h:132,cap:DB.max});
 $('#c_tcp').textContent=N(l.tcp_est);$('#c_udp').textContent=N(l.udp);$('#c_sub').textContent=t('TCP listening')+': '+N(l.tcp_listen);
 $('#ch_con').innerHTML=areaChart([{v:DB.h.tcp,c:'a'},{v:DB.h.udp,c:'b'}],{h:132,cap:DB.max})}
function dashSys(){if(S.page!='dash'||document.visibilityState!='visible')return;
 Promise.all([api('GET','/api/system'),api('GET','/api/overview'),api('GET','/api/nodes').catch(function(){return null})]).then(function(r){if(S.page!='dash')return;DB.sys=r[0];DB.ov=r[1];if(r[2]){S.nodes=r[2];drawNodesCard(r[2])}
  var s=r[0],dp=pc(s.disk_used,s.disk_total);DB.dp=dp;if(!DB.h.disk.length)for(var i=0;i<DB.max;i++)DB.h.disk.push(dp);
  setRing('disk',dp,N(bytes(s.disk_used))+' / '+N(bytes(s.disk_total)),'');$('#ch_disk').innerHTML=areaChart([{v:DB.h.disk,c:'a'}],{h:54,max:100,cap:DB.max});
  drawKpis(r[1]);drawSvcs(s.services||[])}).catch(function(){})}

function goNodes(add){S.openAdd=!!add;if(location.hash=='#nodes')route();else location.hash='#nodes'}

function drawSvcs(list){var el=$('#svcs');if(!el)return;list=(list||[]);
 if(!list.length){el.innerHTML='<span class="muted">—</span>';return}
 el.innerHTML=list.map(function(x){var fixed=['web','panel','node'].indexOf(x.key)>=0,k=esc(x.key);
  return '<div class="svc"><div class="sn"><span class="dot '+(x.active?'g':'r')+'"></span><div><b>'+esc(SVN[x.key]||x.key)+'</b><small class="ltr">'+esc(x.unit)+'</small></div></div>'+
  '<span class="badge '+(x.active?'g':'r')+'">'+(x.active?t('Running'):t('Stopped'))+'</span>'+
  '<div class="sbtn"><button class="sb on" data-svc="'+k+'" data-act="start" '+(x.active||fixed?'disabled':'')+'>▶ '+t('Start')+'</button>'+
  '<button class="sb off" data-svc="'+k+'" data-act="stop" '+(!x.active||fixed?'disabled':'')+' title="'+(fixed?t('Only restart is allowed for this service'):'')+'">■ '+t('Stop')+'</button>'+
  '<button class="sb" data-svc="'+k+'" data-act="restart">↻ '+t('Restart')+'</button></div></div>'}).join('')}
function svc(k,a){var go=function(){toast(t('Checking…'));api('POST','/api/services/'+encodeURIComponent(k)+'/'+a).then(function(r){toast(r.ok===false?t('Failed'):t('Done'),r.ok===false);setTimeout(dashSys,1500)}).catch(fail)};
 if(a=='start')go();else confirmDo(go)}

// ---------------------------------------------------------------- users
var PCOL={wg:'#1fa36b',awg:'#7c5cf0',hy2:'#d1497a',kmix:'#ff7a1a',mtun:'#3fb6c9',kping:'#8bc34a',xray:'#e0a020',dns:'#2a9df4'};
var SORTS={new:function(a,b){return b.id-a.id},old:function(a,b){return a.id-b.id},name:function(a,b){return a.username.toLowerCase()<b.username.toLowerCase()?-1:1},
 usage:function(a,b){return usageVal(b)-usageVal(a)},expiry:function(a,b){return expVal(a)-expVal(b)},seen:function(a,b){return (b.last_seen_ts||0)-(a.last_seen_ts||0)}};
function usageVal(u){return u.traffic_limit_gb>0?u.traffic_used_gb/u.traffic_limit_gb:-1}
function expVal(u){return u.expires_ts>0?u.expires_ts:9e15}
function hasP(u,p){return (','+u.protocols+',').indexOf(','+p+',')>=0}
function ustate(u){if(!u.enabled)return 'disabled';if(u.status!='Active')return 'finished';return 'active'}
function usage(u){var lim=u.traffic_limit_gb;return lim>0?Math.min(100,Math.round(100*u.traffic_used_gb/lim)):-1}
function findU(id){for(var i=0;i<S.users.length;i++)if(S.users[i].id==id)return S.users[i]}
function pUsers(){var pg=$('#pg');
 S.size=+localStorage.getItem('kk_size2')||48;S.sort=localStorage.getItem('kk_sort')||'new';S.pf=S.pf||'all';S.filter=S.filter||'all';S.q=S.q||'';S.pg=1;S.sel={};S.selMode=false;
 var fo=[['all','All'],['online','Online'],['active','Active'],['finished','Expired'],['disabled','Disabled'],['offline','Offline']],
  so=[['new','Newest'],['old','Oldest'],['name','Name'],['usage','Most used'],['expiry','Nearest expiry'],['seen','Last seen']],
  po=[['all','All protocols']].concat(PROTOS);
 var opt=function(a,cur,tr){return a.map(function(x){return '<option value="'+x[0]+'"'+(x[0]==cur?' selected':'')+'>'+(tr===false?esc(x[1]):t(x[1]))+'</option>'}).join('')};
 pg.innerHTML='<div class="ph"><div><h2>'+t('Users')+'</h2><p id="ucount"></p></div><div class="row" style="gap:6px;flex-wrap:nowrap"><button class="ib" id="selm" title="'+t('Select')+'" aria-label="'+t('Select')+'">'+ic('sel',18)+'</button><button class="ib" id="rf" title="'+t('Refresh')+'">'+ic('refresh',17)+'</button><button class="btn" onclick="newUser()">+ '+t('New user')+'</button></div></div>'+
  // (3.40) one toolbar instead of the rows of counters: search, status, sort and protocol
 '<div class="ubar"><div class="srch"><input id="q" type="search" autocomplete="off" placeholder="'+t('Search by name or note…')+'" value="'+esc(S.q)+'"><button id="qx" class="'+(S.q?'':'hide')+'" aria-label="clear">✕</button></div>'+
  '<div class="ufilt" id="ust" role="tablist" aria-label="'+t('Status')+'"></div>'+
  '<div class="usel"><select id="srt" aria-label="'+t('Sort')+'">'+opt(so,S.sort)+'</select><select id="pf" aria-label="'+t('Protocol')+'">'+opt(po,S.pf,false).replace('>All protocols<','>'+t('All protocols')+'<')+'</select></div></div>'+
 '<div class="selbar hide" id="selbar"><label><span class="ck"><input type="checkbox" id="sall"><i></i></span><span>'+t('Select all')+' (<span id="sallc">0</span>)</span></label></div>'+
 '<div class="uchips" id="ul"><div class="empty2">'+t('Loading…')+'</div></div><div class="pager2" id="pager"></div>'+
 '<div class="bulk hide" id="bulk"><span class="cnt" id="bcnt"></span><button class="b2" data-b="enable">'+t('Enable')+'</button><button class="b2" data-b="disable">'+t('Disable')+'</button><button class="b2" data-b="reset">'+t('Reset traffic')+'</button><button class="b2" data-b="extend">'+t('Extend')+'</button><button class="b2 bd" data-b="delete">'+t('Delete')+'</button><button class="ib" data-b="clear" title="'+t('Clear selection')+'">✕</button></div>';
 $('#q').oninput=function(){S.q=this.value;$('#qx').classList.toggle('hide',!this.value);S.pg=1;pruneSel();drawUsers()};
 $('#qx').onclick=function(){$('#q').value='';S.q='';this.classList.add('hide');S.pg=1;pruneSel();drawUsers()};
 
 $('#pf').onchange=function(){S.pf=this.value;S.pg=1;pruneSel();drawUsers()};
 $('#srt').onchange=function(){S.sort=this.value;localStorage.setItem('kk_sort',S.sort);S.pg=1;drawUsers()};
 $('#rf').onclick=function(){loadUsers()};
 $('#selm').onclick=function(){S.selMode=!S.selMode;if(!S.selMode)S.sel={};this.classList.toggle('on',S.selMode);drawUsers()};
 $('#sall').onchange=function(){var all=this.checked;filtered().forEach(function(u){if(all)S.sel[u.id]=1;else delete S.sel[u.id]});drawUsers()};
 $('#ust').onclick=function(e){var b=e.target.closest('[data-f]');if(!b)return;S.filter=b.dataset.f;S.pg=1;pruneSel();drawUsers();drawStats()};
 $('#ul').onkeydown=function(e){if((e.key=='Enter'||e.key==' ')&&e.target.classList&&e.target.classList.contains('uchip')){e.preventDefault();e.target.click()}};
 $('#ul').onclick=function(e){var q=e.target.closest('[data-q]'),b=e.target.closest('[data-id]');
  if(q&&b&&!S.selMode){var u=findU(+b.dataset.id);if(!u)return;if(q.dataset.q=='link')copy(u.link);else editUser(u.id,q.dataset.q=='qr'?'qr':'');return}
  if(b){var id=+b.dataset.id;
   if(S.selMode){if(S.sel[id])delete S.sel[id];else S.sel[id]=1;b.classList.toggle('sel',!!S.sel[id]);drawSelBar(filtered());drawBulk()}else editUser(id);return}
  if(e.target.closest('[data-a=new]'))newUser()};
 $('#pager').onclick=function(e){var b=e.target.closest('[data-pg]');if(b&&!b.disabled){S.pg=+b.dataset.pg;drawUsers();window.scrollTo(0,0)}};
 $('#pager').onchange=function(e){if(e.target.id=='psz'){S.size=+e.target.value;localStorage.setItem('kk_size2',S.size);S.pg=1;drawUsers()}};
 $('#bulk').onclick=function(e){var b=e.target.closest('[data-b]');if(b)bulkDo(b.dataset.b)};
 loadUsers();api('GET','/api/nodes').then(function(n){S.nodes=n}).catch(function(){});autoRefresh(loadUsers)}
function loadUsers(){return Promise.all([api('GET','/api/users'),api('GET','/api/overview')]).then(function(r){S.users=r[0];S.ov=r[1];
 var live={};S.users.forEach(function(u){live[u.id]=1});Object.keys(S.sel).forEach(function(k){if(!live[k])delete S.sel[k]});drawStats();drawUsers()}).catch(fail)}
function drawStats(){var o=S.ov;if(!o||!$('#ust'))return;
 var c=[['',o.users,'All','all'],['g',o.online,'Online','online'],['g',o.active,'Active','active'],['y',o.expired,'Expired','finished'],['r',o.disabled,'Disabled','disabled']];
 $('#ust').innerHTML=c.map(function(x){return '<button type="button" role="tab" aria-selected="'+(S.filter==x[3])+'" class="uf'+(S.filter==x[3]?' act':'')+'" data-f="'+x[3]+'">'+(x[0]?'<span class="dot '+x[0]+'"></span>':'')+'<span>'+t(x[2])+'</span><b>'+N(x[1]||0)+'</b></button>'}).join('');
 drawLive()}
// connected right now, by protocol: a count per protocol, a tap filters the list to it
function liveOf(u){return u.live||[]}
function drawLive(){var el=$('#ulv');if(!el)return;var cnt={},any=0;
 S.users.forEach(function(u){var seen={};liveOf(u).forEach(function(c){if(!seen[c.p]){seen[c.p]=1;cnt[c.p]=(cnt[c.p]||0)+1}});if(liveOf(u).length)any++});
 if(!any){el.innerHTML='<span class="muted" style="font-size:12px">'+t('Nobody is connected right now')+'</span>';if(S.lv){S.lv='';drawUsers()}return}
 el.innerHTML='<span class="muted" style="font-size:12px;font-weight:700">'+t('Connected now')+':</span>'+
  '<button class="sc'+(S.lv?'':' act')+'" data-lv=""><span class="dot g"></span>'+t('All')+' <b>'+N(any)+'</b></button>'+
  PROTOS.filter(function(p){return cnt[p[0]]}).map(function(p){return '<button class="sc'+(S.lv==p[0]?' act':'')+'" data-lv="'+p[0]+'" style="--pc:'+(PCOL[p[0]]||'#999')+'"><i></i><bdi dir="ltr">'+p[1]+'</bdi> <b>'+N(cnt[p[0]])+'</b></button>'}).join('');
 el.onclick=function(e){var b=e.target.closest('[data-lv]');if(!b)return;S.lv=b.dataset.lv;S.pg=1;drawLive();drawUsers()}}
function liveShort(p){return {wg:'WG',awg:'AWG',hy2:'HY2',kmix:'MIX',mtun:'MT',kping:'KP',xray:'XR',dns:'DNS'}[p]||p.toUpperCase()}
// what a user is connected with: one badge per protocol, the flag of the server's exit country and a small
// Iran flag when that config goes through an Iran tunnel
function liveBadges(lv){var by={},order=[];lv.forEach(function(c){if(!by[c.p]){by[c.p]=[];order.push(c.p)}by[c.p].push(c)});
 return order.slice(0,3).map(function(p){var fl='',seen={};by[p].forEach(function(c){var k=(c.cc||'')+(c.t?'+':'');if(seen[k])return;seen[k]=1;
   if(c.cc)fl+='<span class="lvf">'+flagOf(c.cc)+'</span>';if(c.t)fl+='<span class="lvf lvir">'+flagOf('IR')+'</span>'});
  return '<i dir="ltr" style="--pc:'+(PCOL[p]||'#888')+'">'+liveShort(p)+(fl?' '+fl:'')+'</i>'}).join('')}
function filtered(){var q=S.q.trim().toLowerCase(),f=S.filter;
 var out=S.users.filter(function(u){
  if(q&&(u.username+' '+u.notes+' '+(u.tg_id||'')).toLowerCase().indexOf(q)<0)return false;
  if(S.pf&&S.pf!='all'&&!hasP(u,S.pf))return false;
  if(S.lv&&!liveOf(u).some(function(c){return c.p==S.lv}))return false;
  if(f=='online')return u.online_connections>0||liveOf(u).length>0;if(f=='offline')return !(u.online_connections>0||liveOf(u).length>0);if(f!='all')return ustate(u)==f;return true});
 out.sort(SORTS[S.sort]||SORTS.new);return out}
function pruneSel(){var ok={};filtered().forEach(function(u){ok[u.id]=1});Object.keys(S.sel).forEach(function(k){if(!ok[k])delete S.sel[k]})}
function drawUsers(){var el=$('#ul');if(!el)return;var list=filtered(),pages=Math.max(1,Math.ceil(list.length/S.size));if(S.pg>pages)S.pg=pages;if(S.pg<1)S.pg=1;
 var part=list.slice((S.pg-1)*S.size,S.pg*S.size);
 el.className='uchips'+(S.selMode?' selmode':'');
 el.innerHTML=part.length?part.map(uchip).join(''):'<div class="empty2">'+(S.users.length?t('No match'):t('No users yet')+'<br><button class="btn" data-a="new">+ '+t('Create the first user')+'</button>')+'</div>';
 drawPager(pages);drawSelBar(list);drawBulk();
 $('#ucount').textContent=N(S.users.length)+' '+t('users total')+(list.length!=S.users.length?' · '+N(list.length)+' '+t('match'):'')}
function drawSelBar(list){var c=$('#sall');if(!c)return;var n=0;list.forEach(function(u){if(S.sel[u.id])n++});
 $('#selbar').classList.toggle('hide',!S.selMode);
 c.checked=list.length>0&&n==list.length;c.indeterminate=n>0&&n<list.length;$('#sallc').textContent=N(list.length)}
function drawBulk(){var b=$('#bulk');if(!b)return;var n=Object.keys(S.sel).length;b.classList.toggle('hide',!n);$('#bcnt').textContent=N(n)+' '+t('selected')}
function drawPager(pages){var el=$('#pager');if(!el)return;var h='',i,nums=[];
 if(pages>1){for(i=1;i<=pages;i++){if(i==1||i==pages||Math.abs(i-S.pg)<=1)nums.push(i);else if(nums[nums.length-1]!=='…')nums.push('…')}
  h+='<button class="b2" data-pg="'+(S.pg-1)+'" '+(S.pg<=1?'disabled':'')+'>'+t('Prev')+'</button>';
  nums.forEach(function(n){h+=n==='…'?'<span class="dots">…</span>':'<button class="b2'+(n==S.pg?' on':'')+'" data-pg="'+n+'">'+N(n)+'</button>'});
  h+='<button class="b2" data-pg="'+(S.pg+1)+'" '+(S.pg>=pages?'disabled':'')+'>'+t('Next')+'</button>'}
 h+='<select id="psz" aria-label="'+t('per page')+'">'+[24,48,96,200].map(function(n){return '<option value="'+n+'"'+(n==S.size?' selected':'')+'>'+N(n)+' '+t('per page')+'</option>'}).join('')+'</select>';
 el.innerHTML=h}
// ---- single-user actions
function resetU(id){confirmDo(function(){api('POST','/api/users/'+id+'/reset').then(function(){toast(t('Done'));loadUsers()}).catch(fail)})}
function delU(id){confirmDo(function(){api('DELETE','/api/users/'+id).then(function(){closeModal();toast(t('Done'));loadUsers()}).catch(fail)})}

// ---- bulk actions
function bulkDo(a){var ids=Object.keys(S.sel).map(Number);if(a=='clear'){S.sel={};drawUsers();return}if(!ids.length)return;if(a=='extend')return bulkExtend(ids);
 var run=function(){api('POST','/api/bulk/users',{ids:ids,action:a}).then(function(){S.sel={};toast(t('Done'));loadUsers()}).catch(fail)};
 if(a=='delete'){if(confirm(t('Delete selected users?')+' ('+N(ids.length)+')'))run()}else if(a=='reset')confirmDo(run);else run()}
function bulkExtend(ids){modal(mhead(t('Extend'),N(ids.length)+' '+t('selected'))+'<div class="g2f"><div><label class="f">'+t('Days to add')+'</label><input type="number" id="x_d" min="0" value="30"></div><div><label class="f">'+t('GB to add')+'</label><input type="number" id="x_g" min="0" step="0.5" value="0"></div></div>'+
 '<button class="btn" style="width:100%;margin-top:12px" id="x_go">'+t('Apply')+'</button>');
 $('#x_go').onclick=function(){var d=+$('#x_d').value||0,g=+$('#x_g').value||0;if(d<=0&&g<=0)return toast(t('Enter days or GB'),1);
  api('POST','/api/bulk/users',{ids:ids,action:'extend',days:d,gb:g}).then(function(){closeModal();S.sel={};toast(t('Done'));loadUsers()}).catch(fail)}}

// ---- QR / configs
function qrInto(el,text){el.innerHTML='<div class="qr" style="margin:8px 0"></div>';api('GET','/api/qr?text='+encodeURIComponent(text),undefined,{blob:1}).then(function(r){var i=new Image();i.alt='QR';i.src=URL.createObjectURL(r.blob);el.querySelector('.qr').appendChild(i)}).catch(fail)}
function sheetCfg(id){var u=findU(id);if(!u)return;var un=u.nodes.split(',').filter(Boolean),pr=u.protocols.split(','),map={wg:'wireguard',awg:'amneziawg',hy2:'hysteria2',kmix:'kankimix'},rows='';
 S.nodes.forEach(function(n){if(un.length&&un.indexOf(n.id)<0)return;if(!un.length&&!n.accept_all)return;var inf=n.info||{},b='';
  pr.forEach(function(p){if(!map[p])return;var base='/api/config/'+u.id+'/'+map[p]+'?sub='+encodeURIComponent(u.code)+'&node='+encodeURIComponent(n.id);
   var cb=function(nm,tg){return '<a class="cfgb" style="--pc:'+PCOL[p]+'"'+(tg?' target="_blank"':'')+' href="'+base+'">'+ic('dl',14)+nm+'</a>'};
   if(p=='wg'&&inf.wg_pub)b+=cb('WireGuard');if(p=='awg'&&inf.awg_pub)b+=cb('AmneziaWG');
   if(p=='hy2'&&inf.hy2_port)b+=cb('Hysteria2',1);if(p=='kmix'&&inf.kmix_port)b+=cb('KANKI MIX',1)});
  if(b)rows+='<div class="li" style="flex-wrap:wrap"><b>'+esc(n.name)+'</b><span class="row">'+b+'</span></div>'});
 $('#sx').innerHTML='<div class="list" style="margin:8px 0">'+(rows||'<p class="muted">'+t('No configs: user has no nodes or protocols')+'</p>')+'</div>'}

// ---- form (create + edit): Jalali expiry, quick add days / GB
function dateVal(ts){return ts?jdate(ts):''}
function timeVal(ts){if(!ts)return '23:59';var d=new Date(ts*1000);return p2(d.getHours())+':'+p2(d.getMinutes())}
function readExp(){var s=unN(($('#f_date').value||'').trim());if(!s)return 0;var m=s.match(/^(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})$/);if(!m)return NaN;
 var y=+m[1],mo=+m[2],d=+m[3];if(mo<1||mo>12||d<1||d>31)return NaN;var g=y<1700?j2g(y,mo,d):[y,mo,d],tm=($('#f_time').value||'23:59').split(':'),
  ts=Math.floor(new Date(g[0],g[1]-1,g[2],+tm[0]||0,+tm[1]||0,0).getTime()/1000);return isNaN(ts)?NaN:ts}
function setExp(ts){$('#f_date').value=dateVal(ts);$('#f_time').value=timeVal(ts);prevExp()}
function prevExp(){var el=$('#f_prev');if(!el)return;var ts=readExp();
 if(isNaN(ts)){el.innerHTML='<span class="bad2">'+t('Invalid date')+'</span>';return}
 if(!ts){el.textContent='∞ '+t('Unlimited');return}
 var d=new Date(ts*1000);el.innerHTML=leftTxt(ts)+' · <span class="ltr muted">'+d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate())+' '+p2(d.getHours())+':'+p2(d.getMinutes())+'</span>'}
function qDays(n){var cur=readExp(),now=Math.floor(Date.now()/1000);if(isNaN(cur)||!cur||cur<now)cur=now;setExp(cur+n*86400)}
function qGB(n,u){var cur=+$('#f_gb').value||0,used=u?u.traffic_used_gb:0,base=cur>0?(used>=cur?used:cur):0;$('#f_gb').value=Math.round((base+n)*100)/100}
// user / config names: English letters and digits, 3-12, starting with a letter (WireGuard apps refuse other names)
var NAME_ERR='name: English letters and digits only, 3-12 characters, starting with a letter (like mahtab87)';
function nameOk(v){return /^[A-Za-z][A-Za-z0-9]{2,11}$/.test(v)}
function ufForm(u){var protos=u?u.protocols.split(','):((S.me&&S.me.default_protocols)||'wg,awg,hy2').split(','),un=u?u.nodes.split(',').filter(Boolean):[],
  me0=S.me||{},dd=Math.max(1,+me0.def_days||30),exp=u?u.expires_ts:Math.floor(Date.now()/1000)+dd*86400,h='<div class="g2f">';
 h+='<div class="full"><label class="f">'+t('Username')+'</label><input id="f_name" class="ltr" autocomplete="off" value="'+esc(u?u.username:'')+'" placeholder="'+(u?'':t('Optional, created if empty'))+'" maxlength="12"><small class="muted">'+t('English letters and digits, 3-12, starting with a letter (like mahtab87). No spaces, emoji or symbols.')+'</small></div>';
 h+='<div class="full"><label class="f">'+t('Expiry date')+' <small>('+t(S.lang=='fa'?'Date (Jalali)':'Date')+')</small></label><div class="jd"><input id="f_date" class="ltr" inputmode="numeric" autocomplete="off" placeholder="'+N(S.lang=='fa'?'1405/01/01':'2026-01-31')+'" value="'+esc(dateVal(exp))+'"><input id="f_time" type="time" value="'+timeVal(exp)+'"><button type="button" class="ib" id="f_inf" title="'+t('Unlimited')+'">∞</button></div><div class="muted" id="f_prev" style="margin-top:5px"></div>'+
  '<div class="qchips" id="qd"><span class="muted">'+t('Quick add days')+'</span>'+[7,30,60,90,180,365].map(function(n){return '<button type="button" data-qd="'+n+'">+'+N(n)+'</button>'}).join('')+'</div></div>';
 h+='<div><label class="f">'+t('Total volume (0 = unlimited)')+'</label><div class="row" style="flex-wrap:nowrap"><input type="number" min="0" step="0.5" id="f_gb" value="'+(u?u.traffic_limit_gb:(me0.def_gb!=null&&me0.def_gb!==''?+me0.def_gb:30))+'"><button type="button" class="ib" id="f_gbinf" title="'+t('Unlimited')+'">∞</button></div></div>';
 h+='<div><label class="f">'+t('Connections')+'</label><input type="number" min="0" id="f_conn" value="'+(u?u.max_connections:Math.max(1,+me0.def_conns||1))+'"></div>';
 h+='<div class="full"><div class="qchips" id="qg" style="margin-top:0"><span class="muted">'+t('Quick add volume')+'</span>'+[5,10,20,50,100].map(function(n){return '<button type="button" data-qg="'+n+'">+'+N(n)+' GB</button>'}).join('')+'</div></div>';
 if(!u)h+='<div><label class="f">'+t('Count')+'</label><input type="number" min="1" max="200" id="f_count" value="1"></div><div></div>';
 h+='</div>'+ufServices(protos,un);
 return h+'<input id="f_note" placeholder="'+t('Note')+'" value="'+esc(u?u.notes:'')+'" style="margin-top:8px">'}
function wireForm(u){$('#f_date').oninput=prevExp;$('#f_time').oninput=prevExp;
 $('#f_inf').onclick=function(){$('#f_date').value='';prevExp()};$('#f_gbinf').onclick=function(){$('#f_gb').value=0};
 $('#qd').onclick=function(e){var b=e.target.closest('[data-qd]');if(b)qDays(+b.dataset.qd)};
 $('#qg').onclick=function(e){var b=e.target.closest('[data-qg]');if(b)qGB(+b.dataset.qg,u)};prevExp()}
function formBody(){var ts=readExp();if(isNaN(ts)){toast(t('Invalid date'),1);return null}
 var pr=$$('.f_pr').filter(function(x){return x.checked}).map(function(x){return x.value}),nd=$$('.f_nd'),ns=nd.filter(function(x){return x.checked}).map(function(x){return x.value});if(ns.length==nd.length)ns=[];
 return {expires_ts:ts,traffic_limit_gb:+$('#f_gb').value||0,max_connections:+$('#f_conn').value||0,protocols:pr,nodes:ns,notes:$('#f_note').value}}
function newUser(){modal(mhead(t('New user'))+ufForm(null)+'<button class="btn" style="width:100%;margin-top:12px" id="f_save">'+t('Create')+'</button>','wide');wireForm(null);
 $('#f_save').onclick=function(){var b=formBody();if(!b)return;b.username=$('#f_name').value.trim();if(b.username&&!nameOk(b.username))return toast(t(NAME_ERR),1);b.count=+$('#f_count').value||1;var me=this;me.disabled=true;
  api('POST','/api/users',b).then(function(r){toast(t('Saved'));return loadUsers().then(function(){var u=r&&r.length==1&&findU(r[0].id);if(u)editUser(u.id,'link');else closeModal()})}).catch(function(e){me.disabled=false;fail(e)})}}

// ---------------------------------------------------------------- nodes
// ---- node health: judged from the last sync and the CPU / RAM / disk the node reports
// the version the panel really runs (an older saved one of its own server made every up-to-date agent look old)
function panelVer(){if(S.me&&S.me.version)return S.me.version;var l=(S.nodes||[]).filter(function(x){return x.id=='local'})[0];return l&&l.info&&l.info.version||''}

function nHealthOf(n){var loc=n.id=='local',i=n.info||{},st=i.stats,r=[],lv=0,bump=function(l,m){r.push([l,m]);if(l>lv)lv=l};
 if(!loc&&n.sync_state=='pin mismatch')return{lv:2,c:'r',l:'Problem',r:[[2,'The node\'s certificate changed (reinstalled?): run its join command again, or remove and add the node']]};
 if(!loc&&!n.online)return{lv:2,c:'r',l:'Problem',r:[[2,'Not reachable: check the server, its agent and the firewall']]};
 if(!loc&&n.last_sync&&Date.now()/1000-n.last_sync>180)bump(1,'No contact for more than 3 minutes');
 if(n.sync_state=='mismatch')bump(1,'Some users are not on this server yet (config mismatch): press Sync');
 (i.services||[]).forEach(function(s){if(!s.active)bump(2,t('Service stopped')+': '+s.key+' ('+s.state+')')});
 if(st){var cpu=+st.cpu||0,mem=pc(st.mem_used,st.mem_total),dk=pc(st.disk_used,st.disk_total),sw=pc(st.swap_used,st.swap_total);
  if(cpu>=90)bump(2,t('CPU is full')+' ('+N(Math.round(cpu))+'%)');else if(cpu>=70)bump(1,t('CPU is busy')+' ('+N(Math.round(cpu))+'%)');
  if(mem>=92)bump(2,t('RAM is almost full')+' ('+N(Math.round(mem))+'%)');else if(mem>=80)bump(1,t('RAM is getting full')+' ('+N(Math.round(mem))+'%)');
  if(dk>=95)bump(2,t('Disk is almost full')+' ('+N(Math.round(dk))+'%)');else if(dk>=85)bump(1,t('Disk is getting full')+' ('+N(Math.round(dk))+'%)');
  if(st.swap_total>0&&sw>=50)bump(1,t('Using a lot of swap: the server needs more RAM')+' ('+N(Math.round(sw))+'%)');
 }else if(!loc)bump(0,'Press Update agent to see CPU, RAM and disk of this node');
 var pv=panelVer();if(!loc&&pv&&i.version&&verLt(i.version,pv))bump(1,t('Agent is on an older version')+' (v'+i.version+'): '+t('press Update agent'));
 if(n.maint)bump(1,'Under maintenance: new users are not sent here');
 return lv==2?{lv:2,c:'r',l:'Problem',r:r}:lv==1?{lv:1,c:'y',l:'Under pressure',r:r}:{lv:0,c:'g',l:'Healthy',r:r}}
function nMeter(lbl,p,txt){var c=p>=90?'var(--bad)':p>=70?'var(--warn)':'var(--ok)';
 return '<div class="nm"><div class="nmh"><small>'+t(lbl)+'</small><b class="ltr">'+txt+'</b></div><i><s style="width:'+Math.round(p)+'%;background:'+c+'"></s></i></div>'}
S.nopen=S.nopen||{};
function findN(id){for(var i=0;i<S.nodes.length;i++)if(S.nodes[i].id==id)return S.nodes[i]}
function nAct(id,a){toast(t('Checking…'));api('POST','/api/nodes/'+encodeURIComponent(id)+'/'+a).then(function(r){toast(r.ok===false?(r.result&&r.result.error||'failed'):t('Done'),r.ok===false);loadNodes()}).catch(fail)}
function nHealth(id){toast(t('Checking…'));api('POST','/api/nodes/'+encodeURIComponent(id)+'/health').then(function(r){var n=findN(id);
 modal(mhead(t('Health'),n?n.name:'')+'<p>'+(r.ok?'<span class="badge g">OK</span>':'<span class="badge r">'+t('Offline')+'</span>')+' <span class="ltr">'+r.ms+' ms</span> '+(r.version?'· v'+esc(r.version):'')+(r.load?' · load '+esc(r.load):'')+'</p>'+
 '<div class="list">'+((r.services||[]).map(function(s){return '<div class="li"><span>'+esc(s.key)+' <small class="ltr">'+esc(s.unit)+'</small></span><span class="badge '+(s.active?'g':'r')+'">'+esc(s.state)+'</span></div>'}).join(''))+'</div>')}).catch(fail)}
function nAssign(id,add){var n=findN(id);if(!confirm(t(add?'Add this node to ALL users?':'Remove this node from ALL users?')+(n?' ('+n.name+')':'')))return;
 toast(t('Checking…'));api('POST','/api/nodes/'+encodeURIComponent(id)+'/'+(add?'assign-all':'unassign-all')).then(function(){toast(t('Done'));loadNodes()}).catch(fail)}
function updateAll(){if(!confirm(t('Update every node, every tunnel server and the panel itself to the latest version?')))return;toast(t('Updating…'));
 api('POST','/api/update-all').then(function(r){var h='';
  h+='<p><b>'+t('Panel')+':</b> '+esc(String(r.panel))+(r.latest?' · '+esc(r.latest):'')+'</p>';
  if((r.nodes||[]).length)h+='<label class="f">'+t('Nodes')+'</label><div class="list">'+r.nodes.map(function(z){return '<div class="li"><span><b>'+esc(z.name)+'</b>'+(z.ok?'':'<small>'+esc(z.error||t('no answer: update it once with the kanki command'))+'</small>')+'</span><span>'+(z.ok?'✅':'❌')+'</span></div>'}).join('')+'</div>';
  if((r.agents||[]).length)h+='<label class="f">'+t('Tunnel servers (updating by themselves)')+'</label><p class="muted">'+esc(r.agents.join(', '))+'</p>';
  if((r.also_nodes||[]).length)h+='<label class="f">'+t('Both a node and a tunnel server (updated once, through the node)')+'</label><p class="muted">'+esc(r.also_nodes.join(', '))+'</p>';
  if((r.manual||[]).length)h+='<div class="warnbox">'+t('These agents are too old to update remotely. Run the command kanki on them and choose 3 (Update) once:')+' <b>'+esc(r.manual.join(', '))+'</b></div>';
  if(!(r.nodes||[]).length&&!(r.agents||[]).length&&!(r.manual||[]).length&&String(r.panel)=='current')h+='<p>'+t('Everything is already up to date')+'</p>';
  modal(mhead(t('Update all'),'')+h);setTimeout(function(){if(S.page=='nodes')loadNodes()},8000)}).catch(fail)}

// ---------------------------------------------------------------- backup
function pBackup(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Backup')+'</h2><p>'+t('Full backup of users, credentials, certificates, VPN settings, nodes and panel state')+'</p></div></div>'+
 '<div class="g2"><div class="card" style="margin:0"><h3>'+t('Backup file')+'</h3><p class="sub">'+t('Encrypted archive. File name includes date and time.')+'</p><div class="row" style="flex-wrap:nowrap"><input id="bk_p" type="password" placeholder="'+t('Empty = panel backup passphrase')+'"><button class="btn" id="bk_go" style="flex:none">'+t('Download backup')+'</button></div></div>'+
 '<div class="card" style="margin:0"><h3>'+t('Restore')+'</h3><p class="sub">'+t('Pick a backup file; if encrypted, enter its passphrase.')+'</p><div class="row" style="flex-wrap:nowrap"><label class="b2" style="white-space:nowrap;flex:none">'+t('Choose file')+'<input type="file" id="rs_f" class="hide"></label><input id="rs_p" type="password" placeholder="'+t('Empty = panel backup passphrase')+'"></div><small class="muted" id="rs_n">'+t('No file chosen')+'</small>'+
 '<label class="chk" style="margin-top:8px"><input type="checkbox" id="rs_full">'+t('Also restore server keys & configs (same/new server migration)')+'</label><div style="text-align:center;margin-top:8px"><button class="btn" id="rs_go">'+t('Restore backup')+'</button></div></div></div>'+moveCard()+
 '<div class="card" style="margin-top:12px"><div class="row" style="justify-content:space-between"><div><h3>🌙 '+t('Nightly backup to the bot')+'</h3><p class="sub">'+t('Every night the database is cleaned and an encrypted backup is sent to Telegram')+'</p></div><label class="ku-sw ku-sw-in"><span class="ku-swt"><b>'+t('On')+'</b></span><span class="sw"><input type="checkbox" id="tg_on"><span></span></span></label></div>'+
 '<div class="g2"><div><label class="f">'+t('When')+'</label><div class="row" style="flex-wrap:nowrap;gap:6px"><select id="tg_m" style="width:auto"><option value="nightly">'+t('Every night at')+'</option><option value="hours">'+t('Every … hours')+'</option></select><input id="tg_at" class="ltr" style="max-width:90px" placeholder="03:00"><input id="tg_h" type="number" min="1" style="max-width:90px"></div><small class="muted">'+t('Iran time')+'</small></div>'+
 '<div><label class="f">'+t('Chat ID')+'</label><input id="tg_chat" class="ltr" placeholder="'+t('Auto after /start (or first bot admin)')+'"></div></div>'+
 '<div class="bkpass"><div><small class="muted">'+t('Panel backup passphrase (needed to restore)')+'</small><b class="ltr" id="tg_pw">••••••••</b></div><div class="row" style="gap:6px;flex-wrap:nowrap"><button class="ib" id="tg_eye" title="'+t('Show')+'">👁</button><button class="ib" id="tg_cp">'+ic('link',14)+'</button><button class="b2" id="tg_pch">'+t('Change')+'</button></div></div>'+
 '<details class="box" style="margin-top:8px"><summary><b>'+t('Separate backup bot (optional)')+'</b></summary><label class="f">'+t('Bot token')+'</label><input id="tg_tok" class="ltr" placeholder="123456789:AA…"><small class="muted" id="tg_tn"></small></details>'+
 '<div class="g2" style="margin-top:10px"><button class="b2" id="tg_test">✈ '+t('Test connection')+'</button><button class="b2" id="tg_send">⇪ '+t('Send backup now')+'</button></div><button class="btn" style="width:100%;margin-top:8px" id="tg_save">'+t('Save settings')+'</button><div class="li" style="margin-top:10px" id="tg_st"></div></div>'+
 '<div class="card"><div class="row" style="justify-content:space-between"><div><h3>🧹 '+t('Clean database')+'</h3><p class="sub">'+t('Removes old logs, expired sessions and abandoned unpaid orders, then compacts the file. Users and plans are not touched.')+'</p></div><button class="b2" id="db_cl">'+t('Clean now')+'</button></div><small class="muted" id="db_inf"></small></div>';
 $('#bk_go').onclick=function(){var p=$('#bk_p').value,me=this;me.disabled=true;api('POST','/api/backup',{passphrase:p},{blob:1}).then(function(r){dl(r);me.disabled=false}).catch(function(e){me.disabled=false;fail(e)})};
 $('#rs_f').onchange=function(){$('#rs_n').textContent=this.files[0]?this.files[0].name:t('No file chosen')};
 $('#rs_go').onclick=function(){var f=$('#rs_f').files[0];if(!f)return toast(t('No file chosen'),1);confirmDo(function(){
  api('POST','/api/restore',f,{headers:{'X-Passphrase':$('#rs_p').value,'X-Full':$('#rs_full').checked?'1':'0','Content-Type':'application/octet-stream'}}).then(function(){toast(t('Restore done, panel is restarting…'));setTimeout(function(){location.reload()},4000)}).catch(fail)})};
 var tg={},showPw=false,kb=function(n){return n>1048576?N((n/1048576).toFixed(1))+' MB':N(Math.round(n/1024))+' KB'};
 function tgDraw(){if(!$('#tg_on'))return;$('#tg_on').checked=!!tg.on;$('#tg_chat').value=tg.chat||'';$('#tg_h').value=tg.hours||24;$('#tg_at').value=tg.at||'03:00';$('#tg_m').value=tg.mode||'nightly';
  var hrs=tg.mode=='hours';$('#tg_at').style.display=hrs?'none':'';$('#tg_h').style.display=hrs?'':'none';
  $('#tg_pw').textContent=showPw?(tg.pass||''):'••••••••••';
  $('#tg_tn').textContent=tg.token_set?'✓':(tg.uses_bot_token?t('Empty = use the sales bot token'):'');
  $('#tg_st').innerHTML='<span><span class="dot '+(tg.status=='ok'?'g':tg.status?'r':'')+'"></span> '+(tg.on?t('On'):t('Off'))+'</span><small class="ltr">'+(tg.last?t('Last')+': '+fmtDate(tg.last,1)+' · '+esc(tg.status):'')+'</small>';
  $('#db_inf').textContent=t('Database size')+': '+kb(tg.db_size||0)+(tg.cleaned?' · '+t('Last cleaned')+': '+ago(tg.cleaned):'')}
 function tgLoad(){api('GET','/api/tgbackup').then(function(r){tg=r;tgDraw()}).catch(fail)}
 function tgBody(){return{token:$('#tg_tok').value,chat:$('#tg_chat').value,hours:+$('#tg_h').value||24,at:$('#tg_at').value||'03:00',mode:$('#tg_m').value,on:$('#tg_on').checked}}
 $('#tg_m').onchange=function(){tg.mode=this.value;tgDraw()};
 $('#tg_on').onchange=function(){api('PUT','/api/tgbackup',tgBody()).then(function(){toast(t('Saved'));tgLoad()}).catch(fail)};
 $('#tg_eye').onclick=function(){showPw=!showPw;tgDraw()};$('#tg_cp').onclick=function(){copy(tg.pass||'')};
 $('#tg_pch').onclick=function(){var p=prompt(t('New backup passphrase (min 6). Old backups still need the old one.'));if(!p)return;api('PUT','/api/tgbackup',{pass:p}).then(function(){toast(t('Saved'));tgLoad()}).catch(fail)};
 $('#tg_save').onclick=function(){api('PUT','/api/tgbackup',tgBody()).then(function(){toast(t('Saved'));tgLoad()}).catch(fail)};
 $('#tg_test').onclick=function(){api('PUT','/api/tgbackup',tgBody()).then(function(){return api('POST','/api/tgbackup/test')}).then(function(r){toast(r.ok?'✓ @'+r.bot+' → '+r.chat:'failed',!r.ok);tgLoad()}).catch(fail)};
 $('#tg_send').onclick=function(){toast(t('Checking…'));api('POST','/api/tgbackup/send').then(function(){toast(t('Done'));tgLoad()}).catch(function(e){fail(e);tgLoad()})};
 $('#db_cl').onclick=function(){var me=this;me.disabled=true;api('POST','/api/db/clean').then(function(r){me.disabled=false;var x=r.result||{};toast(t('Done')+' · '+kb(x.before||0)+' → '+kb(x.after||0));tgLoad()}).catch(function(e){me.disabled=false;fail(e)})};
 tgLoad();restoreBox();
 moveLoad();clearInterval(S.timer4);S.timer4=setInterval(function(){if(S.page=='backup'&&$('#v37move')&&!$('#modal').classList.contains('on'))moveLoad()},5000)}
// move the whole panel to a new server
function moveCard(){return '<div class="card" id="v37move"><h3>🚚 '+t('Move the panel to a new server')+'</h3><p class="sub">'+t("Everything moves: users, servers, tunnels, DNS, Xray, bot and plans, the panel settings, the keys of this server's WireGuard / AmneziaWG / Hysteria2 (users' configs keep working), the certificate and the app files.")+'</p><div id="mv_in">'+t('Loading…')+'</div></div>'}
function moveDraw(m){var el=$('#mv_in');if(!el)return;
 var steps='<ol class="steps" style="margin:6px 0 10px;line-height:2"><li><b>'+t("Point the panel's domain to the new server's IP")+'</b><br><small class="muted">'+t('In your DNS (Cloudflare / ArvanCloud): the A record of')+' <span class="ltr">'+esc(m.domain||'')+'</span> '+t('= the IP of the new server, without CDN (DNS only). The old panel keeps working by its IP until the move is done.')+'</small></li>'+
  '<li><b>'+t('Run this on the new server (Ubuntu / Debian, as root)')+'</b><br><small class="muted">'+t('It downloads everything straight from this server, puts it back with the same keys and starts the panel there. Then this panel stops by itself.')+'</small></li></ol>';
 if(m.done>0){el.innerHTML='<div class="okbox" style="padding:10px;border-radius:12px;border:1px solid var(--ok)">✓ '+t('Moved: the panel runs on the new server. This one is stopping.')+'</div>';return}
 if(!m.active){el.innerHTML=steps+'<label class="f">'+t("This server's IP (empty = found by itself)")+'</label><div class="inl"><input id="mv_ip" class="ltr" value="'+esc(m.ip||'')+'" placeholder="1.2.3.4"><button class="btn" id="mv_go" style="flex:none">'+t('Make the move command')+'</button></div>'+
   '<p class="hint">'+t('The backup above is complete too: it can also be restored by hand on a new server (Restore with «Also restore server keys»).')+'</p>';
  $('#mv_go').onclick=function(){var b=this;b.disabled=true;api('POST','/api/migrate/start',{ip:$('#mv_ip').value.trim()}).then(moveLoad).catch(function(e){b.disabled=false;fail(e)})};return}
 el.innerHTML=steps+'<pre class="ltr" id="mv_cmd" style="white-space:pre-wrap;word-break:break-all;font-size:12px;padding:10px;border-radius:12px;background:var(--in);border:1px solid var(--gb2);margin:0">'+esc(m.command)+'</pre>'+
  '<p class="hint">'+t('Valid for 3 hours, one time. It holds the key of the backup: do not share it.')+'</p>'+
  '<p style="margin:6px 0">'+(m.fetched>0?'<span class="okt">✓ '+t('The new server downloaded the backup')+(m.new_ip?' (<span class="ltr">'+esc(m.new_ip)+'</span>)':'')+'</span>':'<span class="muted">⏳ '+t('Waiting for the new server…')+'</span>')+'</p>'+
  '<div class="g2"><button class="btn" id="mv_cp">'+t('Copy the command')+'</button><button class="b2 bd" id="mv_x">'+t('Cancel the command')+'</button></div>';
 $('#mv_cp').onclick=function(){copy(m.command)};$('#mv_x').onclick=function(){api('DELETE','/api/migrate').then(moveLoad).catch(fail)}}
function moveLoad(){return api('GET','/api/migrate').then(moveDraw).catch(function(e){var el=$('#mv_in');if(el)el.textContent=e.message||''})}
// after a restore: which servers are back
function restoreBox(){var pg=$('#pg');if(!pg||S.page!='backup'||$('#svp_rs'))return;
 api('GET','/api/restore/check').then(function(r){if((!r.restored_at||Date.now()/1000-r.restored_at>3*86400)&&!r.bot_conflict||$('#svp_rs')||S.page!='backup')return;
  var sv=r.servers||[],bad=sv.filter(function(x){return (x.agent===false)||(x.vpn===false&&x.vpn_on)});
  var c=document.createElement('div');c.className='card';c.id='svp_rs';
  c.innerHTML='<h3>'+t('After restore')+'</h3><p class="sub">'+t('Restored')+' '+ago(r.restored_at)+(r.moved_from?' · '+t('from')+' <span class="ltr">'+esc(r.moved_from)+'</span>':'')+'</p>'+
   (r.bot_conflict?'<div class="warnbox">'+t('The panel on the old server still runs the same Telegram bot: both answer customers and both post to the channel. Stop it there: systemctl disable --now kanki-panel')+'</div>':'')+
   (bad.length?'<div class="list">'+sv.map(function(x){var ok=x.agent!==false&&!(x.vpn===false&&x.vpn_on);return '<div class="li"><span>'+esc(x.name)+'</span><span>'+(ok?'✅':'⏳ '+t('Not connected yet'))+'</span></div>'}).join('')+'</div>':'<p>✅ '+t('Every server is connected')+'</p>');
  var ph=$('#pg .ph');if(ph)ph.parentNode.insertBefore(c,ph.nextSibling)}).catch(function(){})}

// ---------------------------------------------------------------- security
function pSecurity(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Security')+'</h2><p>'+t('Login, 2FA, sessions and IP access')+'</p></div></div><div id="sec">'+t('Loading…')+'</div>';loadSec()}
// what to fix first, in colour: 2FA off (red), the old full-access API key (yellow), no IP allow list (grey)
function secStatus(s){var r=[[s.totp_on?'g':'r',t('Two-step login (2FA)'),s.totp_on?t('On'):t('Off: turn it on below, the panel is open on the internet')],
  [s.legacy_key?'y':'g',t('Old API key'),s.legacy_key?t('Still there, with full access: delete it below if nothing uses it'):t('None')],
  [s.ip_allow?'g':'',t('Login only from your IPs'),s.ip_allow?t('On'):t('Off (optional)')],
  [s.https_only?'g':'y',t('HTTPS only'),s.https_only?t('On: the panel listens only behind HTTPS'):t('The panel also listens without HTTPS (PANEL_BIND)')],
  ['g',t('Login and subscription rate limit'),t('On')]];
 var bad=r.filter(function(x){return x[0]=='r'}).length,warn=r.filter(function(x){return x[0]=='y'}).length;
 return kuGroup(t('Security status'),null,'<span class="ku-tag '+(bad?'r':warn?'y':'g')+'">'+(bad?t('Needs attention'):warn?t('Almost'):t('Good'))+'</span>',
  r.map(function(x){return kuItem({dot:x[0],name:x[1],tags:'<span class="ku-tag '+x[0]+'">'+x[2]+'</span>'})}).join(''))}
function loadSec(){api('GET','/api/security').then(function(s){S.sec=s;var el=$('#sec');if(!el)return;
 var open=!s.ip_allow&&!s.ip_deny,lg=(s.logins||[]).slice(0,8);
 el.innerHTML=secStatus(s)+'<div class="g4"><div class="stat"><div><small>'+t('Current account')+'</small><b style="font-size:15px">'+esc(s.admin_user)+'</b></div><i>◈</i></div><div class="stat"><div><small>2FA</small><b style="font-size:15px">'+(s.totp_on?'ON':'OFF')+'</b></div><i>◎</i></div><div class="stat"><div><small>'+t('Active sessions')+'</small><b style="font-size:15px">'+N(s.sessions.length)+'</b></div><i>⌁</i></div><div class="stat"><div><small>'+t('Network policy')+'</small><b style="font-size:15px">'+(open?t('Open'):t('Restricted'))+'</b></div><i>⬡</i></div></div>'+
 '<div class="g2" style="margin-top:12px"><div class="card" style="margin:0"><h3>'+t('Change login')+'</h3><label class="f">'+t('Current password')+'</label><input type="password" id="cp_cur"><label class="f">'+t('New username (optional)')+'</label><input id="cp_u" class="ltr" placeholder="'+esc(s.admin_user)+'"><label class="f">'+t('New password (min 8)')+'</label><input type="password" id="cp_p"><button class="btn" style="margin-top:10px;width:100%" onclick="chPass()">'+t('Save')+'</button></div>'+
 '<div class="card" style="margin:0"><div class="row" style="justify-content:space-between"><h3>'+t('Two-step login')+'</h3><span class="badge '+(s.totp_on?'g':'')+'">'+(s.totp_on?'ON':'OFF')+'</span></div><p class="sub">'+t('TOTP with apps like Google Authenticator / 2FAS')+'</p>'+
 '<div class="row"><button class="b2" onclick="totpSetup()" '+(s.totp_on?'disabled':'')+'>'+t('Enable 2FA')+'</button><button class="b2 bd" onclick="totpOff()" '+(s.totp_on?'':'disabled')+'>'+t('Disable 2FA')+'</button></div>'+
 '<label class="chk" style="margin-top:10px"><input type="checkbox" id="ip_f" '+(s.force_2fa?'checked':'')+'>'+t('Enforce 2FA for admin')+'</label>'+
 '<label class="f">'+t('Session lifetime (hours)')+'</label><input type="number" id="ip_h" min="1" value="'+esc(s.session_hours)+'"></div></div>'+
 '<div class="card" style="margin-top:12px"><div class="row" style="justify-content:space-between"><div><h3>'+t('Active sessions')+'</h3><p class="sub">'+t('Devices and IPs logged in to the panel')+'</p></div><button class="b2 bd" onclick="revokeOthers()">'+t('Log out others')+'</button></div><div class="list">'+
 s.sessions.map(function(x){var cur=x.id==s.current_session;return '<div class="li"><span><b class="ltr">'+esc(x.ip)+'</b> '+(cur?'<span class="badge g">'+t('current')+'</span>':'')+'<small class="ltr">'+esc(x.ua.slice(0,60))+' · '+ago(x.last_seen)+'</small></span>'+(cur?'':'<button class="b2 bd" onclick="sessDel(\''+x.id+'\')">✕</button>')+'</div>'}).join('')+'</div></div>'+
 // API tokens: a key for a script or a helper with only some rights (shown once when made)
 '<div class="card" style="margin-top:12px"><div class="row" style="justify-content:space-between"><div><h3>'+t('API tokens')+'</h3><p class="sub">'+t('A key with only some rights, for a script or for someone helping you. Delete it when the work is done.')+'</p></div><button class="b2" onclick="tokNew()">＋ '+t('Create API token')+'</button></div><div class="list">'+
 ((s.tokens||[]).map(function(k){return '<div class="li"><span><b>'+esc(k.name)+'</b> <span class="ltr muted">'+esc(k.prefix)+'…</span><small class="ltr">'+esc(k.scopes)+' · '+(k.last_used?ago(k.last_used):t('never used'))+'</small></span><button class="b2 bd" onclick="tokDel('+(+k.id)+')">✕</button></div>'}).join('')||'<span class="muted">—</span>')+'</div></div>'+
 '<details class="card secx"'+(open?'':' open')+'><summary><b>'+t('IP restriction')+'</b> <small class="muted">'+t('Your IP')+': <span class="ltr">'+esc(s.my_ip)+'</span></small></summary><p class="sub" style="margin-top:8px">'+t('Allow/Deny for the admin panel, one IP or CIDR per line')+'</p>'+
 '<div class="g2"><div><label class="f">Allow</label><textarea id="ip_a" class="ltr" rows="3" placeholder="'+t('IP / CIDR allowed, one per line')+'">'+esc(s.ip_allow)+'</textarea></div><div><label class="f">Deny</label><textarea id="ip_d" class="ltr" rows="3" placeholder="'+t('IP / CIDR blocked, one per line')+'">'+esc(s.ip_deny)+'</textarea></div></div></details>'+
 '<div style="text-align:center;margin:4px 0 12px"><button class="btn" onclick="savePolicy()">'+t('Save security policy')+'</button></div>'+
 '<div class="card"><h3>'+t('Login history')+'</h3><p class="sub">'+t('Last logins to the panel')+'</p><div class="list">'+(lg.map(function(l){return '<div class="li"><span><b>'+esc(l.username||'—')+'</b><small class="ltr">'+esc(l.ip)+' · '+fmtDate(l.ts,1)+'</small></span><span class="badge '+(l.ok?'g':'r')+'">'+(l.ok?'OK':'FAIL')+'</span></div>'}).join('')||'<span class="muted">—</span>')+'</div></div>'}).catch(fail)}
function totpSetup(){api('POST','/api/security/2fa/setup').then(function(r){modal(mhead(t('Enable 2FA'))+'<p class="muted">'+t('Scan with your authenticator app, then enter the 6-digit code')+'</p><div class="qr">'+r.qr+'</div><pre>'+esc(r.secret)+'</pre><input id="tf_c" inputmode="numeric" maxlength="6" class="ltr" placeholder="123456"><button class="btn" style="width:100%;margin-top:10px" id="tf_go">'+t('Confirm')+'</button>');
 $('#tf_go').onclick=function(){api('POST','/api/security/2fa/enable',{code:$('#tf_c').value}).then(function(){closeModal();toast(t('Done'));loadSec()}).catch(fail)}}).catch(fail)}
function totpOff(){var c=prompt(t('2FA code'));if(!c)return;api('POST','/api/security/2fa/disable',{code:c}).then(function(){toast(t('Done'));loadSec()}).catch(fail)}
function revokeOthers(){confirmDo(function(){api('POST','/api/security/revoke-others').then(loadSec).catch(fail)})}
// rights a token can have (the panel's scopes); «nodes» is servers and tunnels
var TOKSC=[['nodes','Servers and tunnels'],['users:read','Read users'],['users:write','Users (read and change)'],['settings','Settings'],['backup','Backup'],['admin','Everything (like the admin)']];
function tokNew(){modal(mhead(t('Create API token'))+'<label class="f">'+t('Name')+'</label><input id="tk_n" maxlength="40" placeholder="tunnels">'+
  '<label class="f">'+t('Rights')+'</label>'+TOKSC.map(function(x){return '<label class="chk"><input type="checkbox" class="tk_s" value="'+x[0]+'"'+(x[0]=='nodes'?' checked':'')+'><span><b>'+t(x[1])+'</b> <small class="ltr muted">'+x[0]+'</small></span></label>'}).join('')+
  '<button class="btn" style="width:100%;margin-top:12px" id="tk_go">'+t('Create API token')+'</button>');
 $('#tk_go').onclick=function(){var sc=$$('.tk_s').filter(function(c){return c.checked}).map(function(c){return c.value});
  api('POST','/api/security/tokens',{name:$('#tk_n').value.trim()||'token',scopes:sc}).then(function(r){
   modal(mhead(t('API token'))+'<p class="sub">'+t('Copy it now: it is shown only this once.')+'</p><textarea class="ltr" readonly rows="2" style="width:100%" onclick="this.select()">'+esc(r.token)+'</textarea>'+
    '<button class="btn" style="width:100%;margin-top:10px" id="tk_cp">'+t('Copy')+'</button>');
   $('#tk_cp').onclick=function(){try{navigator.clipboard.writeText(r.token);toast(t('Copied'))}catch(e){}};loadSec()}).catch(fail)}}
function tokDel(id){confirmDo(function(){api('DELETE','/api/security/tokens/'+id).then(loadSec).catch(fail)})}
function sessDel(id){api('DELETE','/api/security/sessions/'+id).then(loadSec).catch(fail)}
function chPass(){api('POST','/api/security/password',{current:$('#cp_cur').value,username:$('#cp_u').value,password:$('#cp_p').value}).then(function(){toast(t('Saved'));loadSec()}).catch(fail)}
function savePolicy(){api('POST','/api/security/policy',{ip_allow:$('#ip_a').value,ip_deny:$('#ip_d').value,session_hours:+$('#ip_h').value||24,force_2fa:$('#ip_f').checked}).then(function(){toast(t('Saved'));loadSec()}).catch(fail)}

// ---------------------------------------------------------------- settings
function setLogo(data){return api('PUT','/api/settings',{logo:data}).then(function(){S.me.logo=data;try{localStorage.setItem('kk_logo',data)}catch(e){}toast(t('Saved'));shell();route()})}
function wireLogo(){var f=$('#lg_file');if(!f)return;
 f.onchange=function(){var file=f.files&&f.files[0];if(!file)return;var rd=new FileReader();
  rd.onload=function(){var im=new Image();im.onload=function(){var best='',sz=[256,192,128],iw=im.width||256,ih=im.height||256;
    for(var i=0;i<sz.length&&!best;i++){var cv=document.createElement('canvas');cv.width=cv.height=sz[i];var cx=cv.getContext('2d'),r=Math.min(sz[i]/iw,sz[i]/ih),w=iw*r,h=ih*r;
     cx.drawImage(im,(sz[i]-w)/2,(sz[i]-h)/2,w,h);var d=cv.toDataURL('image/png');if(d.length<150000)best=d}
    if(!best)return toast(t('Image is too complex, use a simpler logo'),1);setLogo(best).catch(fail)};
   im.onerror=function(){toast(t('Cannot read this image'),1)};im.src=rd.result};
  rd.readAsDataURL(file)};
 var rm=$('#lg_rm');if(rm)rm.onclick=function(){confirmDo(function(){setLogo('').catch(fail)})}}
// ---------------------------------------------------------------- settings: sections, each saved on its own
var STSEC=[
 ['look','Appearance','brush','Name, logo, language and theme of the panel',['panel_name','lang','theme','color','refresh']],
 ['net','Addresses','globe','Panel address, the public VPN address and subscription links',['endpoint','sub_base']],
 ['vpn','VPN & protocols','shield2','DNS, MTU and protocol behaviour on every server',['dns','mtu','mtu_auto','mtu_budget','awg_compat','conn_limit_on']],
 ['newu','New users','users','Ready values for the “New user” form',['default_protocols','def_gb','def_days','def_conns']],
 ['ntf','Notifications','bell','Telegram messages for you and for your buyers',['tg_alerts','warn_on','backup_on']],
 ['srv','Servers','nodes','What happens to a server that stays offline',['autodel_on','autodel_hours','autodel_iran']],
 ['upd','Update & version','refresh','Version, update source and installing updates',['update_repo']],
 ['io','Export & import','box','Move all settings to another panel or keep a copy',[]]];
var ST_SKIP=['web_bind','web_port','domain','https_port','repo_env'];
function stSw(k,title,desc){return '<div class="srow"><div class="tx"><b>'+t(title)+'</b><small>'+t(desc)+'</small></div><label class="sw"><input type="checkbox" data-k="'+k+'"><span></span></label></div>'}
function stIn(k,label,ph,hint,cls,type){return '<div class="'+(cls||'')+'"><label class="f">'+t(label)+'</label><input data-k="'+k+'"'+(type?' type="'+type+'" min="0"':'')+' class="'+(type?'':'ltr')+'" placeholder="'+esc(ph||'')+'">'+(hint?'<div class="hint">'+t(hint)+'</div>':'')+'</div>'}
function stPick(k,items,cls){return '<input type="hidden" data-k="'+k+'"><div class="'+cls+'" data-pick="'+k+'">'+items.join('')+'</div>'}
function stBody(id,s){var addr='https://'+(s.domain||'')+(s.https_port&&s.https_port!='443'?':'+s.https_port:'')+'/admin';
 switch(id){
  case 'srv':return stSw('autodel_on','Remove a server that stays offline','The server leaves the panel completely (its tunnels, settings and ports too). A Telegram message comes at half the time, and a backup is made just before.')+
   stIn('autodel_hours','After how many hours','24','',' ','number')+
   stSw('autodel_iran','Iran servers too','Off by default: when Iran\'s internet is cut, its servers can be away for days, and removing them takes every tunnel with them.')+
   '<p class="muted" style="font-size:12px">'+t('Only when other servers are online: if every server is away at once, it is the panel\'s own network and nothing is removed. The panel server is never removed.')+'</p>';
 case 'look':return '<div class="sgrid">'+stIn('panel_name','Panel name','Kanki Panel','Shown in the menu, the browser tab and the login page.')+
  '<div><label class="f">'+t('Auto refresh')+'</label><select data-k="refresh">'+[5,10,30,60].map(function(n){return '<option value="'+n+'">'+N(n)+' '+t('seconds')+'</option>'}).join('')+'</select><div class="hint">'+t('How often lists and the dashboard refresh themselves.')+'</div></div>'+
  '<div class="full"><label class="f">'+t('Logo')+'</label><div class="row" style="gap:10px"><div class="'+logoCls()+'" id="lg_prev" style="width:52px;height:52px;border-radius:15px">'+logoInner(((S.me&&S.me.panel_name)||'K').charAt(0))+'</div>'+
  '<label class="b2" for="lg_file" style="cursor:pointer;display:inline-flex;align-items:center;gap:6px">'+ic('image',16)+' '+t('Choose image')+'</label><input type="file" id="lg_file" accept="image/*" class="hide">'+
  '<button class="b2 bd'+(curLogo()?'':' hide')+'" id="lg_rm">'+t('Remove')+'</button></div><div class="hint">'+t('Saved at once. Shown in the header, the menu, the login page and the subscription page.')+'</div></div>'+
  '<div class="full"><label class="f">'+t('Language')+'</label>'+stPick('lang',['<button type="button" data-v="fa">فارسی<small class="muted" style="display:block;font-weight:500">راست به چپ</small></button>','<button type="button" data-v="en">English<small class="muted" style="display:block;font-weight:500">Left to right</small></button>'],'thc')+'</div>'+
  '<div class="full"><label class="f">'+t('Theme')+'</label>'+stPick('theme',['<button type="button" data-v="dark"><i style="background:linear-gradient(135deg,#1c160d,#070604)"></i>'+t('Dark')+'</button>','<button type="button" data-v="light"><i style="background:linear-gradient(135deg,#fffaf0,#e6dcc6)"></i>'+t('Soft light')+'</button>'],'thc')+'</div>'+
  '<input type="hidden" data-k="color" value="gold"></div>';
 case 'net':return '<div class="sgrid"><div class="full"><label class="f">'+t('Panel address')+'</label><div class="cpy"><input class="ltr" readonly value="'+esc(addr)+'"><button class="b2" type="button" onclick="copy(\''+esc(addr)+'\')">'+ic('copy',15)+'</button></div></div>'+
  stIn('endpoint','Public VPN host or IP',s.domain||'vpn.example.com','Written inside every user config. Empty = the panel domain.','full')+
  stIn('sub_base','Subscription base URL','https://sub.example.com','Base of the subscription links (for example a CDN domain). Empty = the panel address.','full')+
  '<div class="full box"><b>'+t('Separate subscription domain')+'</b><div class="hint">'+t('A domain that points to this server. The panel gets its SSL by itself and serves only the subscription pages on it, so the panel address stays hidden.')+'</div><div class="cpy"><input class="ltr" id="sd_in" placeholder="sub.example.ir" value="'+esc(s.sub_domain||'')+'"><button class="btn" type="button" id="sd_go">'+t('Set up SSL and use it')+'</button>'+(s.sub_domain?'<button class="b2 bd" type="button" id="sd_rm">'+t('Remove')+'</button>':'')+'</div><div class="hint" id="sd_msg">'+(s.sub_domain?'✓ https://'+esc(s.sub_domain)+'/sub/…':'')+'</div></div>'+
  '<div class="full box" id="si_box"><b>'+t('Serve the subscription from an Iran server')+'</b><div class="hint">'+t('For ISPs that block the panel domain: a tunnel server inside Iran serves the subscription pages with its own SSL and carries them to the panel through a hidden tunnel. Subscription links use it once it works.')+'</div><div id="si_in">'+t('Loading…')+'</div></div>'+
  '<div class="full">'+'<div class="srow"><div class="tx"><b>'+t('Use this address on every node too')+'</b><small>'+t('Nodes that have their own address switch back to this one when you save.')+'</small></div><label class="sw"><input type="checkbox" id="st_all"><span></span></label></div></div>'+
  '<div class="full box"><b>'+t('Web panel')+'</b><div class="g2"><div><label class="f">'+t('Web bind')+'</label><input class="ltr" readonly value="'+esc(s.web_bind)+'"></div><div><label class="f">'+t('Web port')+'</label><input class="ltr" readonly value="'+esc(s.web_port)+'"></div></div><div class="hint">'+t('Bind and port are where the panel itself listens; changing them needs a panel restart. File:')+' <span class="ltr">/etc/kanki/kanki.env</span></div></div></div>';
 case 'vpn':return '<div class="sgrid"><div><label class="f">DNS</label><input data-k="dns" class="ltr" placeholder="1.1.1.1, 8.8.8.8"><div class="chipset" data-fill="dns">'+
  [['Cloudflare','1.1.1.1, 1.0.0.1'],['Google','8.8.8.8, 8.8.4.4'],['Quad9','9.9.9.9, 149.112.112.112'],['AdGuard','94.140.14.14, 94.140.15.15']].map(function(d){return '<button type="button" data-v="'+d[1]+'">'+d[0]+'</button>'}).join('')+'</div><div class="hint">'+t('DNS servers given to every user config, comma separated.')+'</div></div>'+
  '<div><label class="f">MTU</label><input data-k="mtu" class="ltr" inputmode="numeric" placeholder="1380"><div class="chipset" data-fill="mtu">'+['1280','1380','1420'].map(function(m){return '<button type="button" data-v="'+m+'">'+m+'</button>'}).join('')+'</div><div class="hint">'+t('Lower it (1280) if some sites do not open on mobile data.')+'</div></div>'+
  '<div class="full" style="margin-top:6px">'+stSw('mtu_auto','Automatic MTU','Each config gets the largest MTU whose whole packet stays under the limit below, counting the core and the tunnels on its way. Off = the MTU above for every config.')+'</div>'+
  '<div><label class="f">'+t('Largest packet on mobile data')+'</label><input data-k="mtu_budget" class="ltr" inputmode="numeric" placeholder="1380"><div class="chipset" data-fill="mtu_budget">'+['1340','1380','1420'].map(function(m){return '<button type="button" data-v="'+m+'">'+m+'</button>'}).join('')+'</div><div class="hint">'+t('Bytes of the whole packet (IPv4 + UDP + core). Iran mobile networks pass about 1420-1440; 1380 leaves a safe margin.')+'</div></div>'+
  '<div class="full box"><b>'+t('MTU of every config')+'</b><div class="hint">'+t('Worked out again with every subscription refresh and server sync, so a tunnel that changes type changes the MTU by itself.')+'</div><div id="mtu_rep">'+t('Loading…')+'</div></div>'+
  '<div class="full" style="margin-top:6px">'+stSw('awg_compat','AmneziaWG compatibility mode','Only Jc/Jmin/Jmax/S1/S2/H1-H4, for old AmneziaWG apps.')+stSw('conn_limit_on','Enforce connection limit (Hysteria2)','A user cannot connect from more devices than his limit.')+'</div></div>';
 case 'newu':return '<label class="f" style="margin-top:0">'+t('Default protocols for new users')+'</label><input type="hidden" data-k="default_protocols"><div class="pgs" data-multi="default_protocols">'+
  PROTOS.map(function(x){return '<label style="--pc:'+((PCOL[x[0]]))+'"><input type="checkbox" value="'+x[0]+'" class="hide"><i></i>'+x[1]+'</label>'}).join('')+'</div><div class="hint">'+t('Also used by the sales bot when it makes an account.')+'</div>'+
  '<div class="g3" style="margin-top:6px">'+stIn('def_gb','Volume (GB)','30','0 = unlimited','', 'number')+stIn('def_days','Days','30','','', 'number')+stIn('def_conns','Connections','1','','', 'number')+'</div>';
 case 'ntf':return stSw('tg_alerts','Server alerts','Telegram message to the bot admins when a node, tunnel server or tunnel goes offline, and when it is back.')+
  stSw('warn_on','Warn buyers','The buyer gets a message before his time or data runs out.')+stSw('backup_on','Daily backup to bot admins','An encrypted full backup is sent to the bot admins once a day.')+
  '<div class="hint" style="margin-top:8px">'+t('These messages are sent by the sales bot; set it up first in')+' <a href="#bot">'+t('Sales bot')+'</a>.</div>';
 case 'upd':return '<div class="vcard"><div><small>'+t('Current version')+'</small><b>v'+esc(S.me.version)+'</b></div><div><small>'+t('Latest version')+'</small><b id="st_lv">…</b></div></div><div class="vmsg" id="st_um">'+t('Checking…')+'</div>'+autoUpdBox()+
  '<div class="row" style="margin-top:10px"><button class="b2" type="button" id="st_chk">'+ic('refresh',15)+' '+t('Check for update')+'</button><button class="btn hide" type="button" id="st_go">'+t('Install update')+'</button></div>'+
  '<div class="sgrid" style="margin-top:8px">'+stIn('update_repo','Update source (GitHub repo)','owner/kanki-panel','Releases of this repository are used for updates, for “Update all” and for new tunnel servers.','full')+'</div>'+
  (s.repo_env?'<div class="warnbox">'+t('KANKI_REPO in /etc/kanki/kanki.env is set; it wins over this field.')+'</div>':'')+
  '<div class="hint">'+t('Nodes and tunnel servers are updated together with')+' <a href="#nodes">'+t('Nodes')+' › '+t('Update all')+'</a>.</div>';
 case 'io':return '<div class="ioc"><div><b>'+ic('dl',18)+' '+t('Export')+'</b><p>'+t('A JSON file with every panel and sales setting. It holds payment keys too, keep it private. Users are not in it; use Backup for that.')+'</p><button class="btn" type="button" id="st_exp">'+t('Download settings')+'</button></div>'+
  '<div><b>'+ic('refresh',18)+' '+t('Import')+'</b><p>'+t('Pick a settings file exported from a Kanki panel. Only known settings are taken; users, nodes and keys are not touched.')+'</p><label class="b2" for="st_imf" style="cursor:pointer;display:inline-flex;gap:6px;align-items:center">'+ic('dl',15)+' '+t('Choose file')+'</label><input type="file" id="st_imf" accept=".json,application/json" class="hide"></div></div>';
 }return ''}
function pSettings(){var cur=S.stsec||'look';
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Settings')+'</h2><p>'+t('Everything about how the panel looks and works, in one place')+'</p></div></div><div id="st">'+t('Loading…')+'</div>';
 api('GET','/api/settings').then(function(s){if(!$('#st'))return;S.st=s;if(!STSEC.some(function(x){return x[0]==cur}))cur='look';
  $('#st').innerHTML='<div class="stw"><div class="stn" role="tablist">'+STSEC.map(function(x){return '<button type="button" data-sec="'+x[0]+'" class="'+(x[0]==cur?'on':'')+'"><span class="si">'+ic(x[2],17)+'</span>'+t(x[1])+'<em></em></button>'}).join('')+'</div><div>'+
  STSEC.map(function(x){return '<section class="sts card'+(x[0]==cur?' on':'')+'" data-sec="'+x[0]+'"><div class="sth"><span class="phi">'+ic(x[2],20)+'</span><div><b>'+t(x[1])+'</b><small>'+t(x[3])+'</small></div></div>'+stBody(x[0],s)+
   (x[4].length?'<div class="sbar"><span class="muted" data-msg></span><button class="b2" type="button" data-undo disabled>'+t('Undo')+'</button><button class="btn" type="button" data-save disabled>'+t('Save')+'</button></div>':'')+'</section>'}).join('')+'</div></div>';
  stFill(s);stWire();wireLogo();stUpdate(false);stIran();stMtu()}).catch(fail)}
function stVal(el){return el.type=='checkbox'?(el.checked?'1':'0'):el.value}
function stFill(s){$$('#st [data-k]').forEach(function(el){var k=el.dataset.k,v=s[k]==null?'':String(s[k]);
  if(k=='refresh'&&!v)v='10';if(k=='lang'&&!v)v='fa';if(k=='theme'&&!v)v='dark';if(k=='color'&&!v)v='gold';
  if(k=='conn_limit_on'||k=='tg_alerts'||k=='mtu_auto')v=v=='0'?'0':'1';
  if(el.type=='checkbox')el.checked=v=='1';else el.value=v;el._orig=stVal(el)});
 stSync($('#st'))}
// pickers and protocol chips follow their hidden input
function stSync(root){$$('[data-pick]',root).forEach(function(g){var h=$('#st [data-k="'+g.dataset.pick+'"]');$$('button',g).forEach(function(b){b.classList.toggle('on',b.dataset.v==h.value)})});
 $$('[data-multi]',root).forEach(function(g){var h=$('#st [data-k="'+g.dataset.multi+'"]'),on=h.value.split(',');$$('input',g).forEach(function(c){c.checked=on.indexOf(c.value)>=0})})}
function stDirty(sec){var any=false;$$('[data-k]',sec).forEach(function(el){if(stVal(el)!==el._orig)any=true});
 $$('[data-save],[data-undo]',sec).forEach(function(b){b.disabled=!any});var m=$('[data-msg]',sec);if(m)m.textContent=any?t('Unsaved changes'):'';
 var nb=$('.stn button[data-sec="'+sec.dataset.sec+'"]');if(nb)nb.classList.toggle('dirty',any)}
function stWire(){
 $$('.stn button').forEach(function(b){b.onclick=function(){S.stsec=b.dataset.sec;$$('.stn button').forEach(function(x){x.classList.toggle('on',x==b)});$$('.sts').forEach(function(x){x.classList.toggle('on',x.dataset.sec==b.dataset.sec)});if(b.dataset.sec=='upd')stUpdate(false)}});
 $$('.sts').forEach(function(sec){sec.addEventListener('input',function(){stDirty(sec)});sec.addEventListener('change',function(){stDirty(sec)})});
 $$('#st [data-pick] button').forEach(function(b){b.onclick=function(){var g=b.parentNode,h=$('#st [data-k="'+g.dataset.pick+'"]');h.value=b.dataset.v;$$('button',g).forEach(function(x){x.classList.toggle('on',x==b)});stDirty(g.closest('.sts'))}});
 $$('#st [data-multi] input').forEach(function(c){c.onchange=function(){var g=c.closest('[data-multi]'),h=$('#st [data-k="'+g.dataset.multi+'"]');h.value=$$('input',g).filter(function(x){return x.checked}).map(function(x){return x.value}).join(',');stDirty(g.closest('.sts'))}});
 $$('#st [data-fill] button').forEach(function(b){b.onclick=function(){var g=b.parentNode,i=$('#st [data-k="'+g.dataset.fill+'"]');i.value=b.dataset.v;stDirty(g.closest('.sts'))}});
 $$('.sts [data-undo]').forEach(function(b){b.onclick=function(){var sec=b.closest('.sts');
  $$('[data-k]',sec).forEach(function(el){if(el.type=='checkbox')el.checked=el._orig=='1';else el.value=el._orig});stSync(sec);stDirty(sec)}});
 $$('.sts [data-save]').forEach(function(b){b.onclick=function(){stSave(b.closest('.sts'),b)}});
 var ck=$('#st_chk');if(ck)ck.onclick=function(){stUpdate(true)};
 var go=$('#st_go');if(go)go.onclick=function(){go.disabled=true;api('POST','/api/update/apply').then(function(r){toast('v'+r.version+' ✓');setTimeout(function(){location.reload()},5000)}).catch(function(e){go.disabled=false;fail(e)})};
 var ex=$('#st_exp');if(ex)ex.onclick=stExport;
 var sg=$('#sd_go');if(sg)sg.onclick=function(){stSub($('#sd_in').value.trim())};var sr=$('#sd_rm');if(sr)sr.onclick=function(){confirmDo(function(){stSub('')})};
 var im=$('#st_imf');if(im)im.onchange=function(){stImport(im)}}
function stSave(sec,btn){var id=sec.dataset.sec,body={};$$('[data-k]',sec).forEach(function(el){body[el.dataset.k]=stVal(el)});
 if(id=='newu'&&!body.default_protocols)return toast(t('Choose at least one protocol'),1);
 if(id=='upd'&&body.update_repo&&!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(body.update_repo))return toast(t('Write it as owner/repo'),1);
 if(id=='vpn'&&body.mtu&&!(+body.mtu>=1200&&+body.mtu<=1500))return toast(t('MTU must be between 1200 and 1500'),1);
 if(id=='vpn'&&body.mtu_budget&&!(+body.mtu_budget>=1300&&+body.mtu_budget<=1500))return toast(t('The largest packet must be between 1300 and 1500'),1);
 var all=id=='net'&&$('#st_all')&&$('#st_all').checked;btn.disabled=true;
 api('PUT','/api/settings',body).then(function(){return all?api('POST','/api/settings/apply-endpoint'):null}).then(function(){
  Object.assign(S.st,body);$$('[data-k]',sec).forEach(function(el){el._orig=stVal(el)});stDirty(sec);toast(t('Saved'));
  if(id=='newu'&&S.me){S.me.default_protocols=body.default_protocols;S.me.def_gb=body.def_gb;S.me.def_days=body.def_days;S.me.def_conns=body.def_conns}
  if(id=='look'){S.lang=body.lang;S.theme=body.theme;S.color=body.color;localStorage.setItem('kk_lang',S.lang);localStorage.setItem('kk_theme',S.theme);localStorage.setItem('kk_color',S.color);S.stsec='look';boot()}
  if(id=='upd')stUpdate(true);if(id=='vpn')stMtu()}).catch(function(e){btn.disabled=false;fail(e)})}
// automatic MTU: what every config gets (mtu.rs)
var MTU_CORE={wg:'WireGuard',awg:'AmneziaWG',mtun:'microtun'};
function stMtu(){var box=$('#mtu_rep');if(!box)return;api('GET','/api/mtu').then(function(r){if(!$('#mtu_rep'))return;
 var rows=(r.rows||[]).map(function(x){var path=x.via=='tunnel'?(x.hops||[]).map(function(h){return h.transport||'?'}).join(' → '):'';
  var fec=(x.hops||[]).filter(function(h){return h.fec}).map(function(h){return kuTag('FEC '+h.fec+' (+'+N(h.fec_pct)+'%)')}).join('');
  return kuItem({dot:x.fits?'g':'r',name:esc(x.node)+' · '+MTU_CORE[x.core],act:'<b class="ltr">'+N(r.auto?x.mtu:(x.core=='mtun'?r.manual_mtun:r.manual))+'</b>',
   tags:kuTag(x.via=='tunnel'?t('Through Iran tunnel'):t('Direct'),x.via=='tunnel'?'b':'')+(path?kuTag(esc(path)):'')+fec+(x.fits?'':kuTag(t('Tunnel too small'),'r')),
   addr:N(x.mtu)+' + '+N(x.overhead)+' = '+N(x.wire)+' / '+N(x.cap)})});
 var xr=(r.xray_kcp||[]).map(function(x){return kuItem({dot:x.fits?'g':'y',name:'Xray mKCP · '+esc(x.id),act:'<b class="ltr">'+N(x.mtu)+'</b>',tags:x.fits?'':kuTag(t('Bigger than the limit'),'y'),addr:N(x.wire)+' / '+N(r.budget)})});
 box.innerHTML=(r.auto?'':'<div class="warnbox">'+t('Automatic MTU is off: every config gets the MTU set above.')+'</div>')+
  (rows.length||xr.length?rows.concat(xr).join(''):'<p class="muted">'+t('No server runs WireGuard, AmneziaWG or microtun yet.')+'</p>')+
  '<div class="hint">'+t('Hysteria2 sizes its own packets (QUIC, never fragmented); KANKI MIX packet size is set in the app.')+'</div>'}).catch(function(){var b=$('#mtu_rep');if(b)b.textContent=t('Could not load')})}
// subscription served from a tunnel server inside Iran
function stIran(){var box=$('#si_in');if(!box)return;api('GET','/api/sub-iran').then(function(r){if(!$('#si_in'))return;
 var st=r.status||{},msg='';
 // an expired (or soon ending) certificate counts as an SSL problem: the apps cannot read the subscription
 var cdays=st.cert_end?Math.floor((st.cert_end*1000-Date.now())/864e5):null,cbad=cdays!==null&&cdays<7;
 if(cbad&&!st.error)st.error=(cdays<0?t('The SSL certificate has expired: the apps cannot read the subscription from this link.'):t('The SSL certificate ends in {n} days and was not renewed yet.').replace('{n}',cdays))+(st.renew_error?' '+st.renew_error:'');
 if(r.server){if(r.ready&&st.active!==false&&!cbad)msg='✓ '+esc(r.link)+'/sub/…'+(cdays!==null?' · '+t('SSL ends in {n} days').replace('{n}',cdays):'');else if(st.error)msg='<span style="color:var(--bad,#e5484d)">'+esc(st.error)+'</span>';else msg=t('Waiting for the server: getting SSL and starting the listener…');
  if(r.tunnel=='down'){msg+='<br>'+t('Tunnel to the panel')+': '+t('down');var td=r.tunnel_detail||{},ir=td.iran||{},pn=td.panel||{},why=[],er=function(x){return x?' <span class="ltr" style="word-break:break-all">('+esc(x)+')</span>':''};
   if(td.iran_seen==null||td.iran_seen>180)why.push(t('The Iran server\'s tunnel agent is not talking to the panel (offline, or the Iran server cannot reach the panel).'));
   else if(!ir.runs)why.push(t('The Iran server does not run this tunnel yet: update the tunnel agent of that server.'));
   else if(!ir.listening)why.push(t('The Iran server does not listen on port {p}: another program holds it.').replace('{p}',td.port)+er(ir.error));
   if(why.length==0&&pn.runs&&!pn.links)why.push(t('The panel cannot reach {a}: open port {p}/TCP in the firewall of the Iran data center for connections from abroad.').replace('{a}','<span class="ltr">'+esc(td.dial||'')+'</span>').replace('{p}',td.port)+er(pn.error));
   if(why.length==0&&ir.error)why.push(esc(ir.error));
   if(why.length)msg+='<br>'+t('Why')+': '+why.join('<br>')}}
 box.innerHTML='<div class="g3"><div><label class="f">'+t('Tunnel server')+'</label><select id="si_srv"><option value="">—</option>'+(r.agents||[]).filter(function(a){return a.loc=='iran'||a.id==r.server}).map(function(a){return '<option value="'+esc(a.id)+'"'+(a.id==r.server?' selected':'')+'>'+esc(a.name)+(a.ip?' ('+esc(a.ip)+')':'')+'</option>'}).join('')+'</select></div>'+
  '<div><label class="f">'+t('Domain')+'</label><input class="ltr" id="si_dom" placeholder="sub.example.com" value="'+esc(r.domain||'')+'"></div>'+
  '<div><label class="f">'+t('Port')+'</label><input class="ltr" id="si_port" inputmode="numeric" value="'+esc(String(r.port||2053))+'"></div></div>'+
  '<div class="hint" id="si_ip"></div><div class="row" style="margin-top:8px"><button class="btn" type="button" id="si_go">'+t('Save')+'</button>'+(r.server&&st.error?'<button class="b2" type="button" id="si_re">↻ '+t('Try SSL again')+'</button>':'')+(r.server?'<button class="b2 bd" type="button" id="si_rm">'+t('Remove')+'</button>':'')+'</div><div class="hint">'+msg+'</div>'+
  (r.server&&st.error?'<details class="secc" style="margin-top:8px" open><summary>'+t('Why SSL is not taken')+'</summary><div class="bd2"><ul style="margin:0;padding-inline-start:18px;line-height:2">'+
   ['The domain\'s A record must point to this Iran server\'s IP (not to a CDN while the certificate is taken: in ArvanCloud / Cloudflare set it to DNS only).',
    'Let\'s Encrypt checks from outside Iran: port 80/TCP of the server must be open from abroad. Open it in the data center\'s firewall panel too; when international traffic is cut, SSL cannot be taken until it is back.',
    'Port 80 busy: the error names the program. A Kanki tunnel that forwards port 80 holds it: take 80 out of that tunnel. Caddy / nginx are set aside by themselves for a few seconds.',
    'After a failure the server waits (10 minutes, then longer) before it tries again; after fixing the cause press «Try SSL again».'].map(function(x){return '<li>'+esc(t(x))+'</li>'}).join('')+'</ul></div></details>':'');
 var ipHint=function(){var a=(r.agents||[]).filter(function(x){return x.id==$('#si_srv').value})[0];$('#si_ip').textContent=a?t('The domain\'s A record must point to this server\'s IP')+(a.ip?': '+a.ip:''):((r.agents||[]).some(function(x){return x.loc=='iran'})?'':t('Add a tunnel server inside Iran first (Servers), or set its location to Inside Iran.'))};
 ipHint();$('#si_srv').onchange=ipHint;
 $('#si_go').onclick=function(){var b=this;b.disabled=true;api('PUT','/api/sub-iran',{server:$('#si_srv').value,domain:$('#si_dom').value.trim(),port:+$('#si_port').value||2053}).then(function(){toast(t('Saved'));stIran()}).catch(function(e){b.disabled=false;fail(e)})};
 var rm=$('#si_rm');if(rm)rm.onclick=function(){confirmDo(function(){api('PUT','/api/sub-iran',{server:'',domain:''}).then(function(){toast(t('Done'));stIran()}).catch(fail)})};
 var re=$('#si_re');if(re)re.onclick=function(){re.disabled=true;api('POST','/api/tunnels/servers/'+encodeURIComponent(r.server)+'/ssl-retry').then(function(){toast(t('Sent: the server tries SSL again within a minute'));setTimeout(stIran,8000)}).catch(function(e){re.disabled=false;fail(e)})}}).catch(function(e){box.textContent=e.message||''})}
function stSub(d){var g=$('#sd_go'),m=$('#sd_msg');g.disabled=true;m.textContent=d?t('Getting the SSL certificate… this can take up to one minute'):'…';
 api('POST','/api/sub-domain',{domain:d}).then(function(r){S.st.sub_domain=r.domain||'';toast(t('Done'));pSettings()}).catch(function(e){g.disabled=false;m.textContent=e.message||'';fail(e)})}
function stUpdate(force){autoUpdWire();var m=$('#st_um');if(!m||(!force&&m._done))return;m._done=1;m.className='vmsg';m.textContent=t('Checking…');
 api('GET','/api/update/check').then(function(r){$('#st_lv').textContent=r.latest?'v'+r.latest:'—';
  m.className='vmsg '+(r.error?'er':(r.available?'up':'ok'));m.textContent=r.error?t(r.error):(r.available?t('A new version is available.'):t('You are on the latest version.'));
  $('#st_go').classList.toggle('hide',!r.available)}).catch(function(e){m.className='vmsg er';m.textContent=t(e.message||'')})}
function stExport(){api('GET','/api/settings').then(function(s){var o={};Object.keys(s).forEach(function(k){if(ST_SKIP.indexOf(k)<0)o[k]=s[k]});
 var d=new Date(),name='kanki-settings-'+d.getFullYear()+p2(d.getMonth()+1)+p2(d.getDate())+'.json';
 dl({blob:new Blob([JSON.stringify({kanki_settings:1,version:S.me.version,settings:o},null,2)],{type:'application/json'}),name:name});toast(t('Done'))}).catch(fail)}
function stImport(inp){var f=inp.files&&inp.files[0];if(!f)return;var rd=new FileReader();
 rd.onload=function(){var j;try{j=JSON.parse(rd.result)}catch(e){inp.value='';return toast(t('This is not a settings file'),1)}
  var o=j&&j.settings&&typeof j.settings=='object'?j.settings:null;if(!o){inp.value='';return toast(t('This is not a settings file'),1)}
  ST_SKIP.forEach(function(k){delete o[k]});var n=Object.keys(o).length;
  if(!confirm(t('Replace the current settings with the file?')+' ('+N(n)+')')){inp.value='';return}
  api('PUT','/api/settings',o).then(function(){toast(t('Saved'));S.stsec='io';boot()}).catch(fail)};
 rd.readAsText(f)}

// ---------------------------------------------------------------- update
// automatic update every night at 03:30 Tehran time (the same as “Update all”)
function autoUpdBox(){return '<label class="chk" style="margin:10px 0"><input type="checkbox" id="au_on"><span><b>🌙 '+t('Automatic update')+'</b><small id="au_txt" style="display:block;margin-top:2px">'+t('Every night at 03:30 Tehran time, if GitHub has a new version: the panel, the nodes, the tunnel servers and the emergency chat are updated by themselves.')+'</small></span></label>'}
function auTxt(r){var el=$('#au_txt');if(!el||!r)return;var f=function(ts,o){return new Date(ts*1000).toLocaleString(S.lang=='fa'?'fa-IR':'en-GB',Object.assign({timeZone:'Asia/Tehran',hour:'2-digit',minute:'2-digit'},o))};
 var x=t('Every night at 03:30 Tehran time, if GitHub has a new version: the panel, the nodes, the tunnel servers and the emergency chat are updated by themselves.');
 if(r.on)x+=' · '+t('Next run')+': '+f(r.next,{weekday:'short'});
 if(r.last&&r.last.ts)x+=' · '+t('Last run')+': '+f(r.last.ts,{month:'short',day:'numeric'})+' — '+r.last.msg;el.textContent=x}
function autoUpdWire(){var c=$('#au_on');if(!c||c._w)return;c._w=1;
 api('GET','/api/auto-update').then(function(r){c.checked=r.on;auTxt(r)}).catch(function(){c.closest('label').style.display='none'});
 c.onchange=function(){var on=c.checked;api('PUT','/api/auto-update',{on:on}).then(function(){toast(on?t('Automatic update is on'):t('Automatic update is off'));return api('GET','/api/auto-update').then(auTxt)}).catch(function(e){c.checked=!on;fail(e)})}}
function updateModal(){modal(mhead(t('Update')+' '+((S.me&&S.me.panel_name)||''))+'<div class="g2"><div class="pc" style="flex-direction:column"><small class="muted">'+t('Current version')+'</small><b class="ltr" id="u_c">v'+esc(S.me.version)+'</b></div><div class="pc" style="flex-direction:column"><small class="muted">'+t('Latest version')+'</small><b class="ltr" id="u_l">…</b></div></div><p id="u_m" class="muted"></p>'+autoUpdBox()+
 '<div class="row" style="justify-content:center"><button class="btn" id="u_chk">'+t('Check for update')+'</button><button class="btn hide" id="u_go">'+t('Install update')+'</button></div><p class="muted">'+t('Updates come from the GitHub releases of your repo.')+'</p>');
 function chk(){$('#u_m').textContent=t('Checking…');api('GET','/api/update/check').then(function(r){$('#u_l').textContent=r.latest?'v'+r.latest:'—';$('#u_m').textContent=r.error?r.error:(r.available?t('A new version is available.'):t('You are on the latest version.'));$('#u_go').classList.toggle('hide',!r.available)}).catch(fail)}
 autoUpdWire();$('#u_chk').onclick=chk;$('#u_go').onclick=function(){this.disabled=true;api('POST','/api/update/apply').then(function(r){toast('v'+r.version+' ✓');setTimeout(function(){location.reload()},5000)}).catch(fail)};chk()}

