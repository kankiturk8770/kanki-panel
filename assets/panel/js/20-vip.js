// ==================================================================== VIP tunnel
// One tunnel over several paths at once (vip/*.rs): UDP on ports that change, UDP inside fake TCP, and a web
// link (HTTP/2, WebSocket, a CDN). Game packets take the two best paths and are rebuilt on the spot; downloads
// take the best one. Its own page, its own settings: nothing here touches the other tunnels.
var VP={d:null};
function p_vip(){
 $('#pg').innerHTML='<div class="ku">'+kuHead('vip',t('VIP tunnel'),t('One tunnel over several paths at once: when one is cut or throttled, the others carry on without a break'),
  '<button class="btn" onclick="vpEdit()">'+ic('plus',15)+' '+t('VIP tunnel')+'</button>')+'<div id="vp">'+t('Loading…')+'</div></div>';
 vpLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible')vpLoad(true)},3000)}
function vpLoad(quiet){return api('GET','/api/vip').then(function(d){VP.d=d;if(S.page=='vip')vpDraw(d);return d}).catch(function(e){if(!quiet)fail(e)})}
function vpSrv(id){return ((VP.d&&VP.d.servers)||[]).filter(function(s){return s.id==id})[0]||{id:id,name:id}}
function vpCC(id){var s=window.srvFind?srvFind(id):null;return s&&s.cc}
var VPKIND={udp:'UDP',ftcp:'Fake TCP',stream:'Web'};
// [colour, words]
function vpState(x){var e=x.entry,o=x.exit,t0=x.t;
 if(!t0.enabled)return ['',t('Off')];
 var se=vpSrv(t0.entry),sx=vpSrv(t0.exit);
 if(!se.online||!sx.online)return ['r',t('A server is offline')];
 if(!se.knows||!sx.knows)return ['y',t('Update the agent of both servers')];
 if(!e||!o)return ['y',t('Starting…')];
 if(x.up)return ['g',t('Connected')];
 return ['y',t('Connecting…')]}
function vpPathsOf(x){var e=x.entry,o=x.exit,a=(e&&e.paths)||[],b=(o&&o.paths)||[],n=Math.max(a.length,b.length),out=[];
 for(var i=0;i<n;i++){var p=a[i]||{},q=b[i]||{};
  // each side measures what it sends: the worse of the two is what the path is
  var up=(p.state==2)&&(q.state==2),some=(p.state>0)||(q.state>0);
  // the game's packets to the players leave from the exit: its choice is the one shown
  out.push({id:i,kind:p.kind||q.kind,up:up,some:some,rank:o?(q.rank||0):(p.rank||0),
   rtt:Math.max(p.rtt_ms||0,q.rtt_ms||0),jit:Math.max(p.jit_ms||0,q.jit_ms||0),loss:Math.max(p.loss||0,q.loss||0),port:p.port||q.port,err:p.error||q.error||''})}
 return out}
function vpLane(p,cnt){var name=(VPKIND[p.kind]||p.kind)+(p.kind=='udp'&&cnt>1?' '+N(p.id+1):''),cls=p.up?'ok':p.some?'wait':'';
 var tag=p.rank==1?'<em class="vp-g">'+t('game')+'</em>':p.rank==2?'<em class="vp-c">'+t('copy')+'</em>':'';
 return '<div class="vp-lane '+cls+'"><span class="vp-k">'+esc(name)+tag+'</span>'+
  '<span class="vp-m ltr">'+(p.up?N(p.rtt)+' ms · '+N(p.loss)+'%':(p.err?'':'—'))+'</span>'+
  (p.port?'<small>'+t('port')+' '+N(p.port)+'</small>':'')+(p.err&&!p.up?'<small class="vp-err">'+esc(t(p.err))+'</small>':'')+'</div>'}
function vpLink(x){var t0=x.t,se=vpSrv(t0.entry),sx=vpSrv(t0.exit),ps=vpPathsOf(x),udpN=ps.filter(function(p){return p.kind=='udp'}).length;
 var end=function(s,role,on){return '<div class="vp-end '+(on?'ok':'')+'">'+flagOf(vpCC(s.id))+'<b>'+esc(s.name||s.id)+'</b><small>'+role+'</small></div>'};
 return '<div class="vp-link">'+end(se,t('entry · users connect here'),se.online)+
  '<div class="vp-lanes">'+(ps.length?ps.map(function(p){return vpLane(p,udpN)}).join(''):'<div class="vp-lane"><span class="muted">'+t('Waiting for the servers…')+'</span></div>')+'</div>'+
  end(sx,t('exit · traffic leaves here'),sx.online)+'</div>'}
function vpTags(x){var e=x.entry||{},o=x.exit||{},q=e.quality,tg=[];
 var mode={gaming:t('Gaming'),balanced:t('Balanced'),speed:t('Most speed')}[x.t.mode]||x.t.mode;
 tg.push(kuTag(mode,'a'));
 if(q&&q.n)tg.push(kuTag(t('game ping')+' <span class="ltr">'+N(q.ping)+' ms</span>',q.ping<120?'g':'y'),kuTag(t('jitter')+' <span class="ltr">'+N(q.jit)+' ms</span>'),kuTag(t('loss after repair')+' <span class="ltr">'+N(q.loss)+'%</span>',q.loss>1?'r':q.loss>0.2?'y':'g'));
 var fixed=(e.rt_fixed||0)+(o.rt_fixed||0)+(e.bulk_fixed||0)+(o.bulk_fixed||0);
 if(fixed)tg.push(kuTag(t('rebuilt')+' '+N(fixed)));
 if(e.pq||o.pq)tg.push(kuTag(t('Post-quantum keys'),'g'));
 if(e.guard_bps||o.guard_bps)tg.push(kuTag(t('Game priority is holding downloads'),'y'));
 if(e.streams||o.streams)tg.push(kuTag(N(e.streams||o.streams)+' '+t('TCP connections')));
 return tg.join('')}
function vpStats(d){var ts=d.tunnels,up=ts.filter(function(x){return x.up}).length,qs=ts.map(function(x){return x.entry&&x.entry.quality}).filter(function(q){return q&&q.n});
 var lanes=0,lanesUp=0;ts.forEach(function(x){vpPathsOf(x).forEach(function(p){lanes++;if(p.up)lanesUp++})});
 var best=qs.length?Math.min.apply(null,qs.map(function(q){return q.ping})):null;
 return kuStats([[t('Connected'),N(up)+' / '+N(ts.length),up<ts.length?'y':(up?'g':'')],[t('Paths up'),N(lanesUp)+' / '+N(lanes),lanesUp<lanes?'y':(lanes?'g':'')],
  [t('Game ping'),best==null?'—':'<span class="ltr">'+N(best)+' ms</span>'],[t('Post-quantum'),'ML-KEM-768']])}
function vpDraw(d){var el=$('#vp');if(!el)return;
 if(!d.tunnels.length){el.innerHTML=kuGroup(t('VIP tunnels'),0,'','<p class="muted ku-empty">'+t('No VIP tunnel yet. It joins one Iran server to one server abroad, like a normal tunnel, but over several paths at once.')+'</p><div class="ku-save"><button class="btn" onclick="vpEdit()">'+ic('plus',14)+' '+t('VIP tunnel')+'</button></div>')+vpHelp();return}
 el.innerHTML=vpStats(d)+d.tunnels.map(function(x,i){var st=vpState(x),err=[(x.entry||{}).error,(x.exit||{}).error].filter(Boolean);
  return '<section class="ku-group vp-card'+(x.t.enabled?'':' off')+'"><div class="ku-gh"><span class="dot '+st[0]+'"></span><b>'+esc(x.t.name)+'</b><span class="sp"></span><span class="kxr-st '+st[0]+'">'+esc(st[1])+'</span>'+
   '<button class="b2 sm" onclick="vpEdit('+i+')">'+ic('edit',14)+' '+t('Edit')+'</button><button type="button" class="ib ku-more" aria-label="'+esc(t('More'))+'" onclick="vpMenu('+i+')">⋯</button></div>'+
   '<div class="ku-gb">'+vpLink(x)+'<div class="ku-i2 vp-tags">'+vpTags(x)+'</div>'+
   err.map(function(e){return '<div class="warnbox vp-warn">'+esc(t(e))+'</div>'}).join('')+'</div></section>'}).join('')+vpHelp()}
function vpHelp(){return '<details class="ku-help"><summary>'+t('How it works')+'</summary><p>'+
 t('Paths: several ways between the two servers at the same time. UDP is the fastest; it moves to another port and another source port every few seconds, so no UDP flow lives long enough to be throttled. Fake TCP carries the same packets as a TCP session, for networks that cut UDP. The web path is a normal HTTPS or CDN connection, for networks where only the web passes.')+'</p><p>'+
 t('Game packets (small UDP) leave at once on the two best paths; the first copy wins, and a lost one is rebuilt from the repairs that follow it, never waited for. Downloads and every TCP connection take the best path; TCP travels as QUIC streams inside the tunnel, so a lost packet of one download never holds up another connection, and a short outage does not cut it.')+'</p><p>'+
 t('Every path is measured all the time (ping, jitter, loss) and ranked by ping + 3×jitter + 20×loss%. Keys: X25519 and ML-KEM-768 (post-quantum) with the tunnel secret, made new every few minutes; every packet is sealed and its header hidden, so nothing on the wire repeats.')+'</p></details>'}

// ---------------------------------------------------------------- the form
function vpEdit(i){var d=VP.d;if(!d)return;var x=i!=null?d.tunnels[i]:null,v=x?x.t:{mode:'gaming',dialer:'exit',stealth:1,pq:true,port:24400,hop:8,hop_secs:30,udp_paths:2,ftcp_port:0,s_kind:'h2',s_port:24443,burst:4,tcp:[],udp:[],enabled:true};
 var sv=d.servers,iran=sv.filter(function(s){return s.loc=='iran'}),abroad=sv.filter(function(s){return s.loc!='iran'});
 var opt=function(list,cur){return '<option value="">'+t('Choose')+'</option>'+list.map(function(o){return '<option value="'+esc(o.id)+'"'+(o.id==cur?' selected':'')+'>'+esc(o.name||o.id)+(o.online?'':' ('+t('offline')+')')+(o.knows?'':' · '+t('update the agent'))+'</option>'}).join('')};
 var seg=function(id,items,cur){return '<div class="seg vp-seg" id="'+id+'">'+items.map(function(o){return '<button type="button" data-v="'+o[0]+'" class="'+(String(cur)==String(o[0])?'on':'')+'"><b>'+o[1]+'</b>'+(o[2]?'<small>'+o[2]+'</small>':'')+'</button>'}).join('')+'</div>'};
 var num=function(id,label,val,ph){return '<div><label class="f">'+label+'</label><input id="'+id+'" class="ltr" inputmode="numeric" value="'+esc(val==null||val===0&&ph?'':String(val))+'"'+(ph?' placeholder="'+esc(ph)+'"':'')+'></div>'};
 var txt=function(id,label,val,ph,wide){return '<div'+(wide?' class="wide"':'')+'><label class="f">'+label+'</label><input id="'+id+'" class="ltr" value="'+esc(val||'')+'"'+(ph?' placeholder="'+esc(ph)+'"':'')+'></div>'};
 var sw=function(id,label,on,sub){return '<label class="ku-sw"><span class="ku-swt"><b>'+label+'</b>'+(sub?'<small>'+sub+'</small>':'')+'</span><span class="sw"><input type="checkbox" id="'+id+'" '+(on?'checked':'')+'><span></span></span></label>'};
 var h=function(n,title){return '<h4 class="vp-h"><i>'+N(n)+'</i>'+title+'</h4>'};
 modal(mhead(x?t('Edit VIP tunnel'):t('New VIP tunnel'),x?v.name:t('its own settings: the other tunnels stay as they are'))+'<div class="ku-form vp-form">'+
  h(1,t('The two servers'))+'<div class="kxf">'+
   '<div><label class="f">'+t('Entry: the Iran server users connect to')+'</label><select id="vf_en">'+opt(iran.length?iran:sv,v.entry)+'</select></div>'+
   '<div><label class="f">'+t('Exit: the server abroad traffic leaves from')+'</label><select id="vf_ex">'+opt(abroad.length?abroad:sv,v.exit)+'</select></div>'+
   txt('vf_nm',t('Name'),v.name,t('automatic'),true)+'</div>'+
   '<label class="f">'+t('Who connects')+'</label>'+seg('vf_dl',[['exit',t('The server abroad dials Iran'),t('recommended: works when Iran cannot reach abroad')],['entry',t('Iran dials the server abroad'),'']],v.dialer||'exit')+
  h(2,t('Mode'))+seg('vf_md',[['gaming',t('Gaming'),t('game packets on the two best paths, repairs every 2 packets')],['balanced',t('Balanced'),t('a second path only when the first one shakes')],['speed',t('Most speed'),t('one path, light repairs, nothing held back')]],v.mode||'gaming')+
  h(3,t('Paths'))+
   sw('vf_udp',t('UDP (fastest)'),(v.port||0)>0,t('ports that change every few seconds'))+
   '<div class="kxf vp-sub" id="vf_udpb">'+num('vf_po',t('First UDP port'),v.port||24400)+num('vf_hp',t('How many ports'),v.hop||8)+
    num('vf_hs',t('Change port every (seconds, 0 = never)'),v.hop_secs==null?30:v.hop_secs)+num('vf_up',t('UDP paths at the same time (1-4)'),v.udp_paths||2)+'</div>'+
   sw('vf_ft',t('Fake TCP'),(v.ftcp_port||0)>0,t('the same packets inside a TCP session, for networks that cut UDP'))+
   '<div class="kxf vp-sub" id="vf_ftb">'+num('vf_fp',t('TCP port'),v.ftcp_port||24420)+'</div>'+
   '<label class="f">'+t('Web path')+'</label><select id="vf_sk">'+[['',t('None')],['h2','HTTP/2 + TLS'],['wss','WebSocket + TLS'],['ws','WebSocket'],['tcp','TCP'],['cdn',t('Through a CDN')]].map(function(o){return '<option value="'+o[0]+'"'+((v.s_kind||'')==o[0]?' selected':'')+'>'+o[1]+'</option>'}).join('')+'</select>'+
   '<div class="kxf vp-sub" id="vf_skb">'+num('vf_sp',t('TCP port'),v.s_port||24443)+txt('vf_sn','SNI',v.s_sni,t('optional'))+
    txt('vf_sh',t('Domain on the CDN (Host)'),v.s_host,'cdn.example.com')+txt('vf_sa',t('CDN edge addresses'),v.s_dial,'104.16.1.1, 104.17.2.2')+txt('vf_pt',t('Path'),v.s_path,'/')+
    '<div class="wide">'+sw('vf_fr',t('Split the TLS hello'),!!v.s_frag,t('for filters that read the SNI'))+'</div></div>'+
  h(4,t('Ports to forward'))+'<div class="kxf">'+
   txt('vf_tcp',t('TCP ports'),(v.tcp||[]).join(', '),'443, 8443:443')+txt('vf_udpp',t('UDP ports'),(v.udp||[]).join(', '),'51820, 4500')+
   txt('vf_tg',t('Target on the exit'),v.target,'127.0.0.1',true)+'</div>'+
   '<small class="muted">'+t('"8443:443" = port 8443 on the Iran server leads to port 443 on the exit. Games and WireGuard: UDP ports; Xray and websites: TCP ports.')+'</small>'+
  h(5,t('Security and hiding'))+
   sw('vf_pq',t('Post-quantum keys (ML-KEM-768)'),v.pq!==false,t('next to X25519: a recording of today cannot be opened by a quantum computer later'))+
   '<label class="f">'+t('Hiding the packet sizes')+'</label>'+seg('vf_st',[[0,t('None'),t('fastest')],[1,t('A little'),t('small packets padded')],[2,t('More'),t('every size changes')]],v.stealth==null?1:v.stealth)+
  '<details class="vp-adv"><summary>'+t('Advanced')+'</summary><div class="kxf">'+
   num('vf_rk',t('New keys every (minutes)'),v.rekey_secs?Math.round(v.rekey_secs/60):'','10')+num('vf_mt',t('Largest UDP packet'),v.mtu||'','1420')+
   num('vf_rm',t('UDP packets up to this size are game packets'),v.rt_max||'','512')+
   '<div><label class="f">'+t('Download repair lanes')+'</label><select id="vf_bu">'+[1,2,4,8].map(function(n){return '<option value="'+n+'"'+((v.burst||4)==n?' selected':'')+'>'+N(n)+'</option>'}).join('')+'</select></div>'+
   txt('vf_da',t('Address the dialer uses'),v.dial,t('automatic: the server\'s own'),true)+'</div></details></div>'+
  '<div class="kxsave"><button class="b2" onclick="closeModal()">'+t('Cancel')+'</button><button class="btn" id="vf_go">'+t('Save')+'</button></div>','wide');
 $$('.vp-seg').forEach(function(g){$$('button',g).forEach(function(b){b.onclick=function(){$$('button',g).forEach(function(z){z.classList.remove('on')});b.classList.add('on')}})});
 var shows=function(){$('#vf_udpb').classList.toggle('hide',!$('#vf_udp').checked);$('#vf_ftb').classList.toggle('hide',!$('#vf_ft').checked);
  var k=$('#vf_sk').value;$('#vf_skb').classList.toggle('hide',!k);['vf_sh','vf_sa'].forEach(function(id){$('#'+id).parentNode.classList.toggle('hide',k!='cdn')});
  ['vf_sn'].forEach(function(id){$('#'+id).parentNode.classList.toggle('hide',!(k=='h2'||k=='wss'||k=='cdn'))});
  $('#vf_pt').parentNode.classList.toggle('hide',!(k=='ws'||k=='wss'||k=='cdn'));$('#vf_fr').closest('.wide').classList.toggle('hide',!(k=='wss'||k=='cdn'))};
 ['vf_udp','vf_ft','vf_sk'].forEach(function(id){$('#'+id).onchange=shows});shows();
 $('#vf_go').onclick=function(){var n=function(id){var s=unN($('#'+id).value).trim();return s===''?0:+s};var on=function(id){return $('#'+id).checked};
  var segv=function(id){var b=$('#'+id+' button.on');return b?b.dataset.v:''};
  var list=function(id){return unN($('#'+id).value).split(/[\s,]+/).filter(Boolean)};
  var b={id:v.id||'',name:$('#vf_nm').value.trim(),entry:$('#vf_en').value,exit:$('#vf_ex').value,dialer:segv('vf_dl'),mode:segv('vf_md'),
   port:on('vf_udp')?n('vf_po'):0,hop:n('vf_hp')||1,hop_secs:n('vf_hs'),udp_paths:n('vf_up')||1,ftcp_port:on('vf_ft')?n('vf_fp'):0,
   s_kind:$('#vf_sk').value,s_port:n('vf_sp'),s_sni:$('#vf_sn').value.trim(),s_host:$('#vf_sh').value.trim(),s_dial:$('#vf_sa').value.trim(),s_path:$('#vf_pt').value.trim(),s_frag:on('vf_fr'),
   tcp:list('vf_tcp'),udp:list('vf_udpp'),target:$('#vf_tg').value.trim(),pq:on('vf_pq'),stealth:+segv('vf_st')||0,
   rekey_secs:n('vf_rk')*60,mtu:n('vf_mt'),rt_max:n('vf_rm'),burst:+$('#vf_bu').value,dial:$('#vf_da').value.trim()};
  if(!b.entry||!b.exit)return toast(t('Choose both servers'),1);
  if(!b.port&&!b.ftcp_port&&!b.s_kind)return toast(t('Turn on at least one path'),1);
  if(!b.tcp.length&&!b.udp.length)return toast(t('Forward at least one port'),1);
  var go=this;go.disabled=true;
  api('POST','/api/vip',b).then(function(){closeModal();toast(t('Saved')+' · '+t('both servers take it within a few seconds'));vpLoad()}).catch(function(e){go.disabled=false;fail(e)})}}
function vpMenu(i){var x=VP.d.tunnels[i],id=encodeURIComponent(x.t.id);
 kuMenu(x.t.name,'',[[t('Edit'),'vpEdit('+i+')'],[t(x.t.enabled?'Turn off':'Turn on'),"vpAct('"+id+"','"+(x.t.enabled?'off':'on')+"')"],
  [t('New secret'),"vpAct('"+id+"','secret',1)"],[t('Delete VIP tunnel'),"vpDel('"+id+"')",'danger']])}
function vpAct(id,a,ask){if(ask&&!confirm(t('Make a new secret? The tunnel stops for a few seconds while both servers take it.')))return;
 api('POST','/api/vip/'+id+'/'+a).then(function(){toast(t('Saved'));vpLoad()}).catch(fail)}
function vpDel(id){if(!confirm(t('Delete this VIP tunnel? Its ports stop on both servers at once.')))return;
 api('DELETE','/api/vip/'+id).then(function(){toast(t('Deleted'));vpLoad()}).catch(fail)}
