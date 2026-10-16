// Kanki Panel: the Xray page (v3.5). Tabs: overview, inbounds, online clients, routing, settings.
// Every user with Xray ticked is a client of every inbound (or of the inbounds that list them).
var XR={d:null,q:'',srv:'',tab:'overview'};
var XTABS=[['overview','Overview','dash'],['inbounds','Inbounds','xray'],['clients','Online clients','users'],['routing','Routing and outbounds','tunnel'],['settings','Settings','settings']];
var REALITY_TARGETS=['www.microsoft.com:443','www.apple.com:443','dl.google.com:443','www.speedtest.net:443','www.cloudflare.com:443','www.yahoo.com:443','www.amazon.com:443','addons.mozilla.org:443','www.samsung.com:443','www.nvidia.com:443'];
function p_xray(){XR.tab=S.sub||'overview';
 $('#pg').innerHTML='<div class="ph"><div><h2>Xray</h2><p>'+t('Xray inbounds for your users: every user with Xray ticked is a client of every inbound')+'</p></div><div class="row" style="gap:6px"><button class="b2" onclick="xrAddNode()">'+ic('plus',15)+' '+t('Add server')+'</button><button class="btn" onclick="xrInbound()">+ '+t('Inbound')+'</button></div></div>'+
  '<div class="ptabs" id="xr_tabs"></div><div id="xr">'+t('Loading…')+'</div>';
 xrLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName))&&(XR.tab=='overview'||XR.tab=='inbounds'||XR.tab=='clients'))xrLoad(true)},5000)}
function tab_xray(sub){XR.tab=sub||'overview';if(XR.d)xrDraw(XR.d);else xrLoad()}
function xrTabs(d){var el=$('#xr_tabs');if(!el)return;var cnt={inbounds:d.inbounds.length,clients:(d.online||[]).length,routing:(d.rule_list||[]).length+(d.outs||[]).length};
 el.innerHTML=XTABS.map(function(x){return '<a href="#xray/'+x[0]+'" class="'+(XR.tab==x[0]?'on':'')+'">'+ic(x[2],15)+t(x[1])+(cnt[x[0]]?' <em>'+N(cnt[x[0]])+'</em>':'')+'</a>'}).join('')}
function xrLoad(quiet){return api('GET','/api/xray').then(function(d){XR.d=d;if(S.page!='xray')return d;if(quiet){xrTabs(d);
   if(XR.tab=='overview'&&$('#xr_srv')){$('#xr_srv').innerHTML=xrServers(d);$('#xr_kv').innerHTML=xrKpis(d);return d}
   if(XR.tab=='inbounds'&&$('#xr_ib')){$('#xr_ib').innerHTML=xrInbounds(d);return d}
   if(XR.tab=='clients'&&$('#xr_on')){$('#xr_on').innerHTML=xrOnline(d);return d}
   return d}
  xrDraw(d);return d}).catch(fail)}
function xrName(id){var a=(XR.d&&XR.d.agents)||[];for(var i=0;i<a.length;i++)if(a[i].id==id)return a[i].name;return id}
function xrDraw(d){var el=$('#xr');if(!el)return;xrTabs(d);
 ({overview:xrOverview,inbounds:xrIbTab,clients:xrClientsTab,routing:xrRouting,settings:xrSettings}[XR.tab]||xrOverview)(d,el)}
function xrTot(d){return d.inbounds.reduce(function(a,b){return a+(+b.traffic||0)},0)}
function xrKpis(d){var act=d.inbounds.filter(function(x){return x.enabled&&!x.state}).length;
 return '<div><small>'+t('Status')+'</small><b style="color:'+(d.on?'var(--ok)':'var(--bad)')+'">'+(d.on?t('On'):t('Off'))+'</b></div><div><small>'+t('Users with Xray')+'</small><b>'+N(d.users)+'</b></div>'+
  '<div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N((d.online||[]).length)+'</b></div><div><small>'+t('Working inbounds')+'</small><b>'+N(act)+' / '+N(d.inbounds.length)+'</b></div>'+
  '<div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(bytes(xrTot(d)))+'</b></div>'}
function xrOverview(d,el){
 el.innerHTML=(d.on?'':'<div class="warnbox">'+t('Xray is off: nothing runs on the servers and no links go to the users.')+' <a href="#xray/settings">'+t('Turn it on')+'</a></div>')+
  '<div class="kv k5" id="xr_kv">'+xrKpis(d)+'</div>'+
  '<div class="g2"><div class="card"><div class="nh"><h3>'+ic('srv',16)+' '+t('Xray servers')+'</h3><button class="b2" onclick="xrAddNode()">'+ic('plus',14)+' '+t('Add server')+'</button></div><div id="xr_srv" style="margin-top:10px">'+xrServers(d)+'</div></div>'+
  '<div class="card"><div class="nh"><h3>'+ic('xray',16)+' '+t('Inbounds')+'</h3><a class="b2" href="#xray/inbounds">'+t('Manage')+'</a></div><div style="margin-top:6px">'+(d.inbounds.length?d.inbounds.map(function(ib){return xrMiniRow(ib)}).join(''):'<p class="muted">'+t('No inbound yet.')+' <a href="#" onclick="xrInbound();return false">'+t('Make the first one')+'</a></p>')+'</div></div></div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0">'+t('1) Add a server (the panel server or any tunnel server). 2) Make inbounds on it. 3) Tick Xray for a user: the links of every inbound go into the user\'s subscription, and the traffic counts toward the user\'s volume.')+'</p></div>'}
function xrProtoShort(p){return {vless:'VL',vmess:'VM',trojan:'TR',shadowsocks:'SS'}[p]||p}
function xrMiniRow(ib){var st=xrState(ib);return '<div class="vrow"><span class="dot '+st[0]+'"></span><div class="nm"><b>'+esc(ib.remark||ib.protocol)+'</b><small class="ltr">'+esc(ib.protocol.toUpperCase())+' · '+esc(ib.network)+(ib.security!='none'?' · '+esc(ib.security.toUpperCase()):'')+' · :'+ib.port+'</small></div><span class="chipx '+st[0]+'">'+t(st[1])+'</span><b class="ltr" style="font-size:12px">'+N(bytes(ib.traffic))+'</b></div>'}
function xrState(ib){if(!ib.enabled)return ['r','Off'];if(ib.state=='depleted')return ['y','Traffic used up'];if(ib.state=='expired')return ['y','Expired'];if(ib.state=='nocert')return [ib.cert_err?'r':'y',ib.cert_err?'Certificate error':'Waiting for the certificate'];var s=(XR.d&&XR.d.servers||[]).filter(function(x){return x.server==ib.server})[0];
 if(s&&s.status&&s.status.active)return ['g','Running'];return ['y','Waiting for the server…']}
function xrServers(d){if(!d.servers.length)return '<p class="muted">'+t('Add an Xray server first')+'</p>';
 return d.servers.map(function(x){var st=x.status||{},on=st.active,errs=[st.deploy_error,st.error].filter(Boolean),n=d.inbounds.filter(function(i){return i.server==x.server}).length;
  return '<div class="vrow" style="flex-wrap:wrap;align-items:flex-start"><span class="dot '+(on?'g':'r')+'" style="margin-top:6px"></span><div class="nm"><b>'+esc(x.name||x.server)+(x.server=='local'?' <span class="rotb">'+t('Panel server')+'</span>':'')+'</b><small class="ltr">'+esc(x.effective||'?')+(st.core?' · Xray '+esc(st.core):'')+' · '+N(n)+' '+t('inbounds')+'</small></div>'+
   '<span class="chipx '+(on?'g':'r')+'">'+(x.status_at?(on?t('Running'):t('Not running')):t('Waiting for the server…'))+'</span>'+xrCertChip(x)+
   '<div class="row" style="gap:4px;width:100%;justify-content:flex-end">'+'<button class="ib" title="'+t('Edit')+'" onclick="xrSrvEdit(\''+x.server+'\')">'+ic('edit',15)+'</button><button class="ib" title="'+t('Config')+'" onclick="xrPreview(\''+x.server+'\')">{ }</button><button class="ib bd" title="'+t('Delete')+'" onclick="xrSrvDel(\''+x.server+'\')">'+ic('trash',15)+'</button></div>'+
   (errs.length?'<div class="warnbox ltr" style="margin:6px 0 0;width:100%">'+errs.map(esc).join('<br>')+'</div>':'')+
   (xrCertErr(x)?'<div class="warnbox ltr" style="margin:6px 0 0;width:100%">'+esc(xrCertErr(x))+'</div>':'')+'</div>'}).join('')}

// ---- inbounds tab
function xrIbTab(d,el){
 el.innerHTML='<div class="row" style="gap:8px;margin-bottom:12px;flex-wrap:nowrap"><input id="xr_q" placeholder="'+t('Search')+'…" value="'+esc(XR.q)+'" style="flex:1;min-width:0">'+
  '<select id="xr_sf" style="width:auto"><option value="">'+t('All servers')+'</option>'+d.servers.map(function(x){return '<option value="'+esc(x.server)+'"'+(XR.srv==x.server?' selected':'')+'>'+esc(x.name||x.server)+'</option>'}).join('')+'</select>'+
  '<button class="btn" onclick="xrInbound()" style="white-space:nowrap">+ '+t('Inbound')+'</button></div><div id="xr_ib">'+xrInbounds(d)+'</div>';
 $('#xr_q').oninput=function(){XR.q=this.value;$('#xr_ib').innerHTML=xrInbounds(XR.d)};$('#xr_sf').onchange=function(){XR.srv=this.value;$('#xr_ib').innerHTML=xrInbounds(XR.d)}}
function xrInbounds(d){var q=(XR.q||'').toLowerCase(),list=d.inbounds.filter(function(ib){return (!XR.srv||ib.server==XR.srv)&&(!q||[ib.remark,ib.protocol,ib.network,ib.security,String(ib.port),ib.server_name].join(' ').toLowerCase().indexOf(q)>=0)});
 if(!d.inbounds.length)return '<div class="card" style="text-align:center;padding:30px"><p class="muted">'+t('No inbound yet.')+'</p><button class="btn" onclick="xrInbound()">+ '+t('Inbound')+'</button></div>';
 if(!list.length)return '<p class="muted">'+t('Nothing found')+'</p>';
 return '<div class="ibl">'+list.map(function(ib){var st=xrState(ib),lim=+ib.total_gb||0,used=+ib.traffic||0,p=lim>0?Math.min(100,100*used/(lim*1073741824)):0,id=esc(ib.id);
  return '<div class="ibc'+(ib.enabled?'':' off')+'"><div class="hd"><span class="pi">'+xrProtoShort(ib.protocol)+'</span><div class="nm"><b>'+esc(ib.remark||ib.protocol)+'</b><small class="ltr">'+esc(ib.server_name||ib.server)+' · '+esc(ib.listen||'0.0.0.0')+':'+ib.port+'</small></div>'+sw('',ib.enabled,"xrToggle('"+id+"')")+'</div>'+
   '<div class="chs"><span class="chipx a">'+esc(ib.protocol.toUpperCase())+'</span><span class="chipx b">'+esc(ib.network.toUpperCase())+'</span>'+(ib.security!='none'?'<span class="chipx g">'+esc(ib.security.toUpperCase())+'</span>':'')+(ib.flow?'<span class="chipx">Vision</span>':'')+(ib.link_tls||ib.link_host?'<span class="chipx">CDN</span>':'')+((ib.fallbacks||[]).length?'<span class="chipx">'+t('Fallbacks')+'</span>':'')+((ib.only||[]).length?'<span class="chipx y">'+N(ib.only.length)+' '+t('users only')+'</span>':'')+'<span class="chipx '+st[0]+'">'+t(st[1])+'</span></div>'+
   '<div><div class="use"><span>'+t('Traffic')+': <b class="ltr">'+N(bytes(used))+'</b>'+(lim>0?' / <b class="ltr">'+N(lim)+' GB</b>':'')+'</span><span>'+t('Clients')+': <b>'+N(ib.clients)+'</b></span></div>'+(lim>0?'<div class="trk"><div class="fil'+(p>=90?' hot':'')+'" style="width:'+p.toFixed(1)+'%"></div></div>':'')+
   (ib.expire?'<div class="use" style="margin-top:4px"><span>'+t('Expires')+': '+xrDate(ib.expire)+'</span></div>':'')+'</div>'+
   '<div class="acts2"><button onclick="xrInbound(\''+id+'\')">'+ic('edit',15)+'<span>'+t('Edit')+'</span></button><button onclick="xrClients(\''+id+'\')">'+ic('users',15)+'<span>'+t('Links')+'</span></button>'+
   '<button onclick="xrClone(\''+id+'\')">'+ic('copy',15)+'<span>'+t('Copy')+'</span></button><button onclick="xrReset(\''+id+'\')">'+ic('reset',15)+'<span>'+t('Reset')+'</span></button>'+
   '<button onclick="xrIbJson(\''+id+'\')"><b style="font-size:12px">{ }</b><span>JSON</span></button><button class="x" onclick="xrIbDel(\''+id+'\')">'+ic('trash',15)+'<span>'+t('Delete')+'</span></button></div></div>'}).join('')+'</div>'}
function xrDate(ts){var d=new Date(ts*1000),left=Math.ceil((ts*1000-Date.now())/86400000);return '<span class="ltr">'+N(d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate()))+'</span> ('+(left>0?N(left)+' '+t('days'):t('Expired'))+')'}

// ---- online clients tab
function xrClientsTab(d,el){el.innerHTML='<div class="card"><div class="nh"><div><h3>'+t('Online clients')+'</h3><p class="sub" style="margin:0">'+t('Users whose Xray traffic moved in the last few seconds')+'</p></div><a class="b2" href="#users">'+t('All users')+'</a></div><div id="xr_on" style="margin-top:8px">'+xrOnline(d)+'</div></div>'}
function xrOnline(d){var on=d.online||[];if(!on.length)return '<p class="muted">'+t('Nobody is online right now')+'</p>';
 return '<div class="mtiles">'+on.map(function(u){return '<div class="vrow" style="margin:0"><span class="dot g"></span><div class="nm"><b><bdi>'+esc(u.name)+'</bdi></b><small>'+esc(u.server)+'</small></div></div>'}).join('')+'</div>'}

// ---- routing tab
function xrOutTags(d){return ['direct','block'].concat((d.outs||[]).map(function(o){return o.tag}))}
function xrRouting(d,el){XR.rules=JSON.parse(JSON.stringify(d.rule_list||[]));XR.outs=JSON.parse(JSON.stringify(d.outs||[]));
 var pre=function(id,on,title,sub){return '<div class="srow"><div class="tx"><b>'+t(title)+'</b><small>'+t(sub)+'</small></div><label class="sw"><input type="checkbox" id="'+id+'" '+(on?'checked':'')+'><span></span></label></div>'};
 el.innerHTML='<div class="card"><h3>'+ic('security',16)+' '+t('Ready-made rules')+'</h3>'+
  pre('xs_bp',d.block_private,'Block private addresses','Users cannot reach the server\'s own network (10.x, 192.168.x …)')+
  pre('xs_bt',d.block_bt,'Block BitTorrent','Torrent traffic gets abuse reports to your servers')+
  pre('xs_ba',d.block_ads,'Block ads','Ad and tracker domains (geosite:category-ads-all)')+
  pre('xs_bi',d.block_ir,'Block Iranian sites','.ir domains and Iranian addresses do not go through the server: they should be opened directly')+'</div>'+
  '<div class="card"><div class="nh"><div><h3>'+ic('tunnel',16)+' '+t('Outbounds')+'</h3><p class="sub" style="margin:0">'+t('Where traffic leaves the server: directly, or on to another server (chain)')+'</p></div><button class="b2" onclick="xrOutEdit(-1)">'+ic('plus',14)+' '+t('Add outbound')+'</button></div><div id="xr_outs" style="margin-top:10px"></div>'+
  '<label class="f">'+t('Default outbound (what no rule catches)')+'</label><select id="xs_def"></select></div>'+
  '<div class="card"><div class="nh"><div><h3>'+ic('ports',16)+' '+t('Routing rules')+'</h3><p class="sub" style="margin:0">'+t('Checked from top to bottom; the first rule that matches decides')+'</p></div><button class="b2" onclick="xrRuleEdit(-1)">'+ic('plus',14)+' '+t('Add rule')+'</button></div><div id="xr_rules" style="margin-top:10px"></div>'+
  '<label class="f">'+t('Domain strategy')+'</label><select id="xs_ds">'+[['AsIs','AsIs — '+t('by name (fastest)')],['IPIfNonMatch','IPIfNonMatch — '+t('resolve when no name rule matched')],['IPOnDemand','IPOnDemand — '+t('always resolve for IP rules')]].map(function(o){return '<option value="'+o[0]+'"'+((d.domain_strategy||'AsIs')==o[0]?' selected':'')+'>'+o[1]+'</option>'}).join('')+'</select></div>'+
  '<details class="secc"><summary>'+ic('term',16)+' '+t('Advanced: raw JSON')+'<span class="chev">'+ic('chev',14)+'</span></summary><div class="bd2"><label class="f">'+t('Advanced: extra routing rules (JSON array)')+'</label><textarea id="xs_r" rows="4" class="ltr" placeholder="[]">'+esc(d.rules)+'</textarea><label class="f">'+t('Advanced: extra outbounds (JSON array, the first one becomes the default)')+'</label><textarea id="xs_o" rows="4" class="ltr" placeholder="[]">'+esc(d.outbounds)+'</textarea></div></details>'+
  '<div class="sbar"><span class="muted">'+t('Changes reach the servers within a few seconds of saving')+'</span><button class="btn" id="xs_rgo">'+t('Save routing')+'</button></div>';
 xrRoutingDraw();
 $('#xs_rgo').onclick=function(){var me=this;me.disabled=true;
  api('PUT','/api/xray',{block_private:$('#xs_bp').checked,block_bt:$('#xs_bt').checked,block_ads:$('#xs_ba').checked,block_ir:$('#xs_bi').checked,outs:XR.outs.map(function(o){var c=Object.assign({},o);delete c.error;return c}),rule_list:XR.rules,default_out:$('#xs_def').value,domain_strategy:$('#xs_ds').value,rules:$('#xs_r').value,outbounds:$('#xs_o').value})
   .then(function(){toast(t('Saved'));XR.d=null;return xrLoad()}).catch(fail).then(function(){me.disabled=false})}}
function xrOutDesc(o){if(o.kind=='socks'||o.kind=='http')return o.kind.toUpperCase()+' '+o.address+':'+o.port;if(o.kind=='link')return (o.link||'').split('://')[0].toUpperCase()+' · '+((o.link||'').split('@')[1]||'').split('?')[0].split('#')[0];if(o.kind=='json')return 'JSON';if(o.kind=='blackhole')return t('Block');return t('Direct')}
function xrRoutingDraw(){var d=XR.d,def=$('#xs_def');
 $('#xr_outs').innerHTML='<div class="rl"><span class="dot g"></span><div class="nm"><b class="ltr" style="text-align:start">direct</b><small>'+t('Straight to the internet from this server')+'</small></div><span class="chipx">'+t('built in')+'</span></div>'+
  '<div class="rl"><span class="dot r"></span><div class="nm"><b class="ltr" style="text-align:start">block</b><small>'+t('Dropped')+'</small></div><span class="chipx">'+t('built in')+'</span></div>'+
  XR.outs.map(function(o,i){return '<div class="rl"><span class="dot '+(o.error?'r':'g')+'"></span><div class="nm"><b><bdi>'+esc(o.tag)+'</bdi></b><small><bdi>'+esc(xrOutDesc(o))+'</bdi></small>'+(o.error?'<small style="color:var(--bad)">'+esc(o.error)+'</small>':'')+'</div>'+
   '<button class="ib" onclick="xrOutEdit('+i+')">'+ic('edit',15)+'</button><button class="ib bd" onclick="xrOutDel('+i+')">'+ic('trash',15)+'</button></div>'}).join('');
 var tags=['direct','block'].concat(XR.outs.map(function(o){return o.tag})),cur=def.value||d.default_out||'';
 def.innerHTML='<option value="">direct</option>'+tags.filter(function(x){return x!='direct'}).map(function(x){return '<option'+(cur==x?' selected':'')+'>'+esc(x)+'</option>'}).join('');
 $('#xr_rules').innerHTML=XR.rules.length?XR.rules.map(function(r,i){var m=[];if(r.domain)m.push(r.domain.split(/[\n,]/).filter(Boolean).slice(0,3).join(', '));if(r.ip)m.push(r.ip.split(/[\n,]/).filter(Boolean).slice(0,3).join(', '));if(r.port)m.push(t('port')+' '+r.port);if(r.network)m.push(r.network);if(r.protocol)m.push(r.protocol);
   if((r.inbound||[]).length)m.push(N(r.inbound.length)+' '+t('inbounds'));if((r.users||[]).length)m.push(N(r.users.length)+' '+t('users'));
   return '<div class="rl"'+(r.off?' style="opacity:.55"':'')+'><span class="muted" style="font-weight:800">'+N(i+1)+'</span><div class="nm"><b>'+esc(r.name||t('Rule')+' '+N(i+1))+'</b><small><bdi>'+esc(m.join(' · ')||'—')+'</bdi></small></div><span class="arrow ltr">→ '+esc(r.outbound||'direct')+'</span>'+
    '<label class="sw"><input type="checkbox" '+(r.off?'':'checked')+' onchange="XR.rules['+i+'].off=!this.checked;xrRoutingDraw()"><span></span></label>'+
    '<button class="ib" '+(i==0?'disabled':'')+' onclick="xrRuleMove('+i+',-1)">↑</button><button class="ib" onclick="xrRuleEdit('+i+')">'+ic('edit',15)+'</button><button class="ib bd" onclick="XR.rules.splice('+i+',1);xrRoutingDraw()">'+ic('trash',15)+'</button></div>'}).join(''):'<p class="muted">'+t('No rules yet: everything goes to the default outbound.')+'</p>'}
function xrRuleMove(i,dir){var j=i+dir;if(j<0||j>=XR.rules.length)return;var x=XR.rules[i];XR.rules[i]=XR.rules[j];XR.rules[j]=x;xrRoutingDraw()}
function xrOutDel(i){var tag=XR.outs[i].tag;if(XR.rules.some(function(r){return r.outbound==tag}))return toast(t('A rule still sends traffic to this outbound'),1);XR.outs.splice(i,1);xrRoutingDraw()}
function xrOutEdit(i){var o=i>=0?Object.assign({},XR.outs[i]):{tag:'',kind:'link',address:'',port:0,user:'',pass:'',link:'',json:''};
 var kinds=[['link',t('Another server (from its link)')],['socks','SOCKS5'],['http','HTTP proxy'],['freedom',t('Direct (freedom)')],['blackhole',t('Block (blackhole)')],['json','JSON']];
 modal(mhead(t(i>=0?'Edit outbound':'Add outbound'))+
  '<div class="g2"><div><label class="f">'+t('Tag (name)')+'</label><input id="xo_tag" class="ltr" placeholder="germany" value="'+esc(o.tag)+'"></div><div><label class="f">'+t('Type')+'</label><select id="xo_k">'+kinds.map(function(k){return '<option value="'+k[0]+'"'+(o.kind==k[0]?' selected':'')+'>'+k[1]+'</option>'}).join('')+'</select></div></div>'+
  '<div id="xo_link"><label class="f">'+t('Link of the other server (vless, vmess, trojan or ss)')+'</label><textarea id="xo_l" rows="3" class="ltr" placeholder="vless://…">'+esc(o.link)+'</textarea><p class="hint">'+t('Typical use: this server is in Iran and the link is of a server abroad, so users connect inside Iran and leave from abroad.')+'</p></div>'+
  '<div id="xo_px" class="g2"><div><label class="f">'+t('Address')+'</label><input id="xo_a" class="ltr" value="'+esc(o.address)+'"></div><div><label class="f">'+t('Port')+'</label><input id="xo_p" type="number" class="ltr" value="'+(o.port||'')+'"></div><div><label class="f">'+t('Username (optional)')+'</label><input id="xo_u" class="ltr" value="'+esc(o.user)+'"></div><div><label class="f">'+t('Password')+'</label><input id="xo_pw" class="ltr" value="'+esc(o.pass)+'"></div></div>'+
  '<div id="xo_js"><label class="f">'+t('The whole outbound (JSON object)')+'</label><textarea id="xo_j" rows="6" class="ltr" placeholder=\'{"protocol":"freedom"}\'>'+esc(o.json)+'</textarea></div>'+
  '<div class="row" style="margin-top:12px;gap:8px"><button class="b2" id="xo_t" style="flex:1">'+t('Check')+'</button><button class="btn" id="xo_go" style="flex:2">'+t('OK')+'</button></div><pre id="xo_out" class="hide" style="max-height:220px;overflow:auto;margin-top:10px"></pre>');
 var ui=function(){var k=$('#xo_k').value;$('#xo_link').style.display=k=='link'?'':'none';$('#xo_px').style.display=k=='socks'||k=='http'?'':'none';$('#xo_js').style.display=k=='json'?'':'none'};$('#xo_k').onchange=ui;ui();
 var read=function(){return {tag:$('#xo_tag').value.trim(),kind:$('#xo_k').value,address:$('#xo_a').value.trim(),port:+$('#xo_p').value||0,user:$('#xo_u').value,pass:$('#xo_pw').value,link:$('#xo_l').value.trim(),json:$('#xo_j').value}};
 $('#xo_t').onclick=function(){var b=read();if(!b.tag)b.tag='test';api('POST','/api/xray/outs/check',b).then(function(v){var p=$('#xo_out');p.classList.remove('hide');p.textContent=JSON.stringify(v,null,2)}).catch(fail)};
 $('#xo_go').onclick=function(){var b=read();if(!/^[A-Za-z0-9_-]+$/.test(b.tag))return toast(t('an outbound tag is English letters, digits, - and _'),1);
  if(['direct','block','api'].indexOf(b.tag)>=0||XR.outs.some(function(x,j){return j!=i&&x.tag==b.tag}))return toast(t('This tag is already used'),1);
  api('POST','/api/xray/outs/check',b).then(function(){var old=i>=0?XR.outs[i].tag:'';if(i>=0)XR.outs[i]=b;else XR.outs.push(b);
   if(old&&old!=b.tag)XR.rules.forEach(function(r){if(r.outbound==old)r.outbound=b.tag});closeModal();xrRoutingDraw();toast(t('Press Save routing to apply'))}).catch(fail)}}
var RULE_PRESETS={domain:['geosite:openai','geosite:google','geosite:youtube','geosite:netflix','geosite:spotify','geosite:telegram','geosite:category-ir','geosite:category-ads-all','domain:ir','regexp:\\.ir$'],ip:['geoip:ir','geoip:private','geoip:us','geoip:de','geoip:cn']};
function xrRuleEdit(i){var d=XR.d,r=i>=0?Object.assign({},XR.rules[i]):{name:'',domain:'',ip:'',port:'',network:'',protocol:'',inbound:[],users:[],outbound:'direct'};
 var chips=function(k){return '<div class="chipset">'+RULE_PRESETS[k].map(function(x){return '<button type="button" data-add="'+k+'" data-v="'+esc(x)+'">+ '+esc(x)+'</button>'}).join('')+'</div>'};
 var tags=['direct','block'].concat(XR.outs.map(function(o){return o.tag}));
 modal(mhead(t(i>=0?'Edit rule':'Add rule'))+'<label class="f">'+t('Name')+'</label><input id="xu_n" value="'+esc(r.name)+'" placeholder="'+t('like: AI sites through Germany')+'">'+
  '<label class="f">'+t('Domains (one per line)')+'</label><textarea id="xu_d" rows="3" class="ltr" placeholder="geosite:openai&#10;domain:example.com">'+esc(r.domain)+'</textarea>'+chips('domain')+
  '<label class="f">'+t('IP addresses and ranges (one per line)')+'</label><textarea id="xu_i" rows="2" class="ltr" placeholder="geoip:ir&#10;1.2.3.0/24">'+esc(r.ip)+'</textarea>'+chips('ip')+
  '<div class="g2"><div><label class="f">'+t('Ports')+'</label><input id="xu_p" class="ltr" placeholder="443, 1000-2000" value="'+esc(r.port)+'"></div><div><label class="f">'+t('Network')+'</label><select id="xu_net">'+[['',t('Any')],['tcp','TCP'],['udp','UDP'],['tcp,udp','TCP + UDP']].map(function(o){return '<option value="'+o[0]+'"'+(r.network==o[0]?' selected':'')+'>'+o[1]+'</option>'}).join('')+'</select></div></div>'+
  '<label class="f">'+t('Sniffed protocol')+'</label><div class="ckrow">'+['http','tls','quic','bittorrent'].map(function(p){return '<label class="chk"><input type="checkbox" class="xu_pr" value="'+p+'" '+((r.protocol||'').split(',').indexOf(p)>=0?'checked':'')+'>'+p+'</label>'}).join('')+'</div>'+
  (d.inbounds.length?'<label class="f">'+t('Only from these inbounds')+'</label><div class="ckrow">'+d.inbounds.map(function(ib){return '<label class="chk"><input type="checkbox" class="xu_ib" value="'+esc(ib.id)+'" '+((r.inbound||[]).indexOf(ib.id)>=0?'checked':'')+'>'+esc(ib.remark||ib.id)+'</label>'}).join('')+'</div>':'')+
  ((d.user_list||[]).length?'<details style="margin-top:8px"'+((r.users||[]).length?' open':'')+'><summary class="muted">'+t('Only for these users')+'</summary><div class="ckrow">'+d.user_list.map(function(u){return '<label class="chk"><input type="checkbox" class="xu_u" value="'+u.id+'" '+((r.users||[]).indexOf(u.id)>=0?'checked':'')+'><span class="ltr">'+esc(u.name)+'</span></label>'}).join('')+'</div></details>':'')+
  '<label class="f">'+t('Send to')+'</label><select id="xu_o">'+tags.map(function(x){return '<option'+(r.outbound==x?' selected':'')+'>'+esc(x)+'</option>'}).join('')+'</select>'+
  '<button class="btn" style="width:100%;margin-top:14px" id="xu_go">'+t('OK')+'</button>');
 $$('[data-add]').forEach(function(b){b.onclick=function(){var ta=$(b.dataset.add=='domain'?'#xu_d':'#xu_i'),v=ta.value.trim();if(v.split(/\n/).indexOf(b.dataset.v)<0)ta.value=(v?v+'\n':'')+b.dataset.v}});
 $('#xu_go').onclick=function(){var nr={name:$('#xu_n').value.trim(),off:!!r.off,domain:$('#xu_d').value.trim(),ip:$('#xu_i').value.trim(),port:$('#xu_p').value.trim(),network:$('#xu_net').value,
   protocol:$$('.xu_pr').filter(function(c){return c.checked}).map(function(c){return c.value}).join(','),inbound:$$('.xu_ib').filter(function(c){return c.checked}).map(function(c){return c.value}),
   users:$$('.xu_u').filter(function(c){return c.checked}).map(function(c){return +c.value}),outbound:$('#xu_o').value};
  if(!nr.domain&&!nr.ip&&!nr.port&&!nr.network&&!nr.protocol&&!nr.inbound.length&&!nr.users.length)return toast(t('Give the rule at least one condition'),1);
  if(i>=0)XR.rules[i]=nr;else XR.rules.push(nr);closeModal();xrRoutingDraw();toast(t('Press Save routing to apply'))}}

// ---- settings tab
function xrSettings(d,el){
 el.innerHTML='<div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
  '<div class="srow"><div class="tx"><b>'+t('Xray is on')+'</b><small>'+t('Off: Xray stops on every server and the links leave the subscriptions')+'</small></div><label class="sw"><input type="checkbox" id="xs_on" '+(d.on?'checked':'')+'><span></span></label></div>'+
  '<div class="srow"><div class="tx"><b>'+t('IPv4 only')+'</b><small>'+t('For servers whose IPv6 does not work well')+'</small></div><label class="sw"><input type="checkbox" id="xs_v4" '+(d.ipv4?'checked':'')+'><span></span></label></div>'+
  '<div class="sgrid"><div><label class="f">'+t('Xray-core version')+'</label><input id="xs_v" class="ltr" placeholder="'+t('empty = latest')+'" value="'+esc(d.version)+'"><p class="hint">'+t('A release tag like v26.3.27')+'</p></div>'+
  '<div><label class="f">'+t('Log level')+'</label><select id="xs_ll">'+['none','error','warning','info','debug'].map(function(x){return '<option'+((d.log_level||'warning')==x?' selected':'')+'>'+x+'</option>'}).join('')+'</select></div>'+
  '</div>'+
  '<div class="sbar"><button class="btn" id="xs_go">'+t('Save')+'</button></div></div>';
 $('#xs_go').onclick=function(){api('PUT','/api/xray',{on:$('#xs_on').checked,ipv4:$('#xs_v4').checked,version:$('#xs_v').value,log_level:$('#xs_ll').value}).then(function(){toast(t('Saved'));xrLoad()}).catch(fail)}}

// ---- servers
function xrAddNode(){var go=function(){var d=XR.d,used=d.servers.map(function(x){return x.server}),ag=d.agents.filter(function(a){return used.indexOf(a.id)<0});
  modal(mhead(t('Add server'),'Xray')+'<p class="muted" style="margin:0 0 6px">'+t('Xray can run on the panel server or on any tunnel server. A new server gets a one-line install command.')+'</p><label class="f">'+t('Agent server')+'</label><select id="xa_sv"><option value="__new">'+t('New server (install command)')+'</option>'+ag.map(function(a){return '<option value="'+esc(a.id)+'">'+esc(a.id=='local'?a.name+' ('+t('Panel server')+')':a.name)+'</option>'}).join('')+'</select>'+
   '<div id="xa_nw"><label class="f">'+t('Server name')+'</label><input id="xa_nm" placeholder="Xray-DE"></div>'+xrDomainFields({address:'',ssl:true})+
   '<button class="btn" style="width:100%;margin-top:12px" id="xa_go">'+t('Save')+'</button><div id="xa_out"></div>');
  var sv=function(){$('#xa_nw').style.display=$('#xa_sv').value=='__new'?'':'none'};$('#xa_sv').onchange=sv;sv();xrDomainWire();
  $('#xa_go').onclick=function(){var me=this,nw=$('#xa_sv').value=='__new';me.disabled=true;
   (nw?api('POST','/api/tunnels/servers',{name:$('#xa_nm').value||'Xray'}):Promise.resolve({id:$('#xa_sv').value})).then(function(r){
    return api('POST','/api/xray/servers',{server:r.id,address:$('#xa_ad').value,ssl:$('#xa_ssl').checked}).then(function(){toast(t($('#xa_ssl').checked&&xrIsDomain($('#xa_ad').value)?'Saved: getting SSL (about a minute)':'Saved'));if(nw){me.style.display='none';$('#xa_out').innerHTML=tunCmdBox(r,r);$('#tn_cp').onclick=function(){copy($('#tn_cmd').textContent)}}else closeModal();xrLoad()})}).catch(function(e){me.disabled=false;fail(e)})}};
 if(XR.d)go();else xrLoad().then(go)}
function xrIsDomain(v){v=(v||'').trim();return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v)&&!/^[\d.]+$/.test(v)}
function xrDomainFields(x){
 return '<label class="f">'+t('Domain of this server (or IP)')+'</label><input id="xa_ad" class="ltr" placeholder="de.example.com" value="'+esc(x.address||'')+'"><p class="hint">'+t('Users connect to this address; empty = the IP the server reports from')+'</p>'+
  '<div class="srow" id="xa_sslw"><div class="tx"><b>'+t('Get SSL for this domain by itself')+'</b><small>'+t('certbot on this server gets a Let\'s Encrypt certificate for the domain (no e-mail needed) and renews it by itself; every TLS inbound of this server uses it. The domain must point to this server. Whatever uses port 80 (Caddy, nginx, an inbound …) is set aside for a few seconds and comes back by itself.')+'</small></div><label class="sw"><input type="checkbox" id="xa_ssl" '+(x.ssl!==false?'checked':'')+'><span></span></label></div>'}
function xrDomainWire(){var f=function(){var w=$('#xa_sslw');if(w)w.style.display=xrIsDomain($('#xa_ad').value)?'':'none'};$('#xa_ad').oninput=f;f()}
function xrSrvEdit(id){var x=XR.d.servers.filter(function(s){return s.server==id})[0];if(!x)return;
 modal(mhead(t('Edit'),x.name)+xrDomainFields({address:x.address,ssl:x.ssl||!x.address})+'<button class="btn" style="width:100%;margin-top:12px" id="xe_go">'+t('Save')+'</button>');xrDomainWire();
 $('#xe_go').onclick=function(){var ssl=$('#xa_ssl').checked&&xrIsDomain($('#xa_ad').value);api('POST','/api/xray/servers',{server:id,address:$('#xa_ad').value,ssl:ssl}).then(function(){closeModal();toast(t(ssl?'Saved: getting SSL (about a minute)':'Saved'));xrLoad();setTimeout(function(){xrLoad(true)},5000)}).catch(fail)}}
/** SSL of a server's domain, as the server reports it (certbot runs there) */
function xrCertErr(x){var st=x.status||{};return x.domain&&st.cert_errors&&st.cert_errors[x.domain]&&!(st.certs||[]).includes(x.domain)?st.cert_errors[x.domain]:''}
function xrCertChip(x){if(!x.domain)return '';var st=x.status||{};
 return (st.certs||[]).includes(x.domain)?'<span class="chipx g">SSL ✓</span>':xrCertErr(x)?'<span class="chipx r">SSL · '+t('error')+'</span>':'<span class="chipx y" title="'+esc(t('Taken with certbot on the server'))+'">SSL · '+t('waiting')+'</span>'}
function xrSrvDel(id){confirmDo(function(){api('DELETE','/api/xray/servers/'+encodeURIComponent(id)).then(function(){toast(t('Done'));xrLoad()}).catch(fail)})}
function xrPreview(id){api('GET','/api/xray/config/'+encodeURIComponent(id)).then(function(c){xrJsonModal(t('Config')+' · '+xrName(id),c)}).catch(fail)}
function xrJsonModal(title,v){var tx=JSON.stringify(v,null,2);modal(mhead(title)+'<pre class="ltr" style="max-height:60vh;overflow:auto;white-space:pre">'+esc(tx)+'</pre><button class="b2" style="width:100%;margin-top:8px" id="xj_cp">'+ic('copy',15)+' '+t('Copy')+'</button>','wide');$('#xj_cp').onclick=function(){copy(tx)}}

// ---- inbound actions
function xrIbDel(id){confirmDo(function(){api('DELETE','/api/xray/inbounds/'+encodeURIComponent(id)).then(function(){toast(t('Done'));xrLoad()}).catch(fail)})}
function xrToggle(id){var ib=XR.d.inbounds.filter(function(x){return x.id==id})[0];if(!ib)return;var b=Object.assign({},ib,{enabled:!ib.enabled});api('POST','/api/xray/inbounds',b).then(function(){xrLoad()}).catch(fail)}
function xrClone(id){api('POST','/api/xray/inbounds/'+encodeURIComponent(id)+'/clone').then(function(){toast(t('A copy was made (off until you check it)'));xrLoad()}).catch(fail)}
function xrReset(id){if(!confirm(t('Reset the traffic of this inbound to zero?')))return;api('POST','/api/xray/inbounds/'+encodeURIComponent(id)+'/reset').then(function(){toast(t('Done'));xrLoad()}).catch(fail)}
function xrIbJson(id){api('GET','/api/xray/inbounds/'+encodeURIComponent(id)+'/json').then(function(v){xrJsonModal('JSON',v)}).catch(fail)}
function xrClients(id){var ib=XR.d.inbounds.filter(function(x){return x.id==id})[0]||{};
 modal(mhead(t('Users and links'),ib.remark)+'<input id="xc_q" placeholder="'+t('Search')+'…" style="margin-bottom:8px"><div id="xc_l">'+t('Loading…')+'</div><div id="xc_qr"></div>','wide');
 api('GET','/api/xray/inbounds/'+encodeURIComponent(id)+'/clients').then(function(r){var list=r.clients||[];
  var draw=function(){var q=$('#xc_q').value.toLowerCase();var l=list.filter(function(c){return !q||c.name.toLowerCase().indexOf(q)>=0});
   $('#xc_l').innerHTML=l.length?l.map(function(c,i){return '<div class="vrow"><span class="dot '+(c.online?'g':c.active?'':'r')+'"></span><div class="nm"><b><bdi>'+esc(c.name)+'</bdi></b><small>'+N(bytes(c.used))+(c.limit_gb>0?' / '+N(c.limit_gb)+' GB':'')+(c.active?'':' · '+t('Inactive'))+'</small></div>'+
    (c.link?'<button class="ib" data-cp="'+i+'" title="'+t('Copy')+'">'+ic('copy',15)+'</button><button class="ib" data-qr="'+i+'" title="QR">'+ic('qr',15)+'</button>':'<span class="muted">'+t('No address')+'</span>')+'</div>'}).join(''):'<p class="muted">'+t('No users with Xray yet: tick Xray in a user\'s form')+'</p>';
   $$('#xc_l [data-cp]').forEach(function(b){b.onclick=function(){copy(l[+b.dataset.cp].link)}});
   $$('#xc_l [data-qr]').forEach(function(b){b.onclick=function(){var c=l[+b.dataset.qr];qrInto($('#xc_qr'),c.link);$('#xc_qr').insertAdjacentHTML('afterbegin','<p class="muted ltr" style="margin:10px 0 0;text-align:center">'+esc(c.name)+'</p>')}})};
  $('#xc_q').oninput=draw;draw()}).catch(fail)}

// ---- the inbound form
function xrInbound(id){var d=XR.d;if(!d)return xrLoad().then(function(){xrInbound(id)});if(!d.servers.length){toast(t('Add an Xray server first'),1);return xrAddNode()}
 var ib=d.inbounds.filter(function(x){return x.id==id})[0]||{enabled:true,protocol:'vless',network:'tcp',security:'reality',port:xrFreePort(d.servers[0].server),server:d.servers[0].server,flow:'xtls-rprx-vision',dest:'www.microsoft.com:443',names:'www.microsoft.com',fp:'chrome',sniffing:true,ss_method:'2022-blake3-aes-128-gcm',only:[],fallbacks:[],sniff_dest:[]};
 var opt=function(list,v){return list.map(function(o){o=[].concat(o);return '<option value="'+esc(o[0])+'"'+(String(o[0])==String(v)?' selected':'')+'>'+esc(o[1]||o[0])+'</option>'}).join('')};
 var inp=function(idn,label,v,ph,type){return '<div><label class="f">'+t(label)+'</label><input id="'+idn+'" class="ltr"'+(type?' type="'+type+'"':'')+' value="'+esc(v==null?'':v)+'" placeholder="'+esc(ph||'')+'"></div>'};
 var ck=function(idn,label,on,sub){return '<div class="srow"><div class="tx"><b>'+t(label)+'</b>'+(sub?'<small>'+t(sub)+'</small>':'')+'</div><label class="sw"><input type="checkbox" id="'+idn+'" '+(on?'checked':'')+'><span></span></label></div>'};
 var alpn=(ib.alpn||'').split(',').map(function(x){return x.trim()}).filter(Boolean),sd=ib.sniff_dest&&ib.sniff_dest.length?ib.sniff_dest:['http','tls','quic'];
 var exp=ib.expire?new Date(ib.expire*1000):null,expv=exp?exp.getFullYear()+'-'+p2(exp.getMonth()+1)+'-'+p2(exp.getDate()):'';
 var tabs=[['b','Basic'],['tr','Transport'],['sec','Security'],['sn','Sniffing'],['lk','Link and CDN'],['lim','Limits and users'],['fb','Fallbacks']];
 var h='<div class="ftabs" id="xi_tabs">'+tabs.map(function(x,i){return '<button type="button" data-ft="'+x[0]+'" class="'+(i?'':'on')+'">'+t(x[1])+'</button>'}).join('')+'</div>'+
  // basic
  '<div class="fsec on" data-fs="b"><div class="g2">'+inp('xi_rm','Remark',ib.remark,'DE-Reality')+'<div><label class="f">'+t('Agent server')+'</label><select id="xi_sv">'+opt(d.servers.map(function(x){return [x.server,x.name||x.server]}),ib.server)+'</select></div>'+
   '<div><label class="f">'+t('Protocol')+'</label><select id="xi_pr">'+opt([['vless','VLESS'],['vmess','VMess'],['trojan','Trojan'],['shadowsocks','Shadowsocks']],ib.protocol)+'</select></div>'+
   '<div><label class="f">'+t('Port')+'</label><div class="inl"><input id="xi_pt" class="ltr" type="number" min="1" max="65535" value="'+(ib.port||'')+'"><button type="button" class="ib" id="xi_rp" title="'+t('Random free port')+'">🎲</button></div></div>'+
   inp('xi_ls0','Listen address',ib.listen,'0.0.0.0')+'</div>'+
   '<div id="xi_ss" class="g2"><div><label class="f">'+t('Method')+'</label><select id="xi_sm">'+opt(['2022-blake3-aes-128-gcm','2022-blake3-aes-256-gcm','2022-blake3-chacha20-poly1305','chacha20-ietf-poly1305','aes-256-gcm','aes-128-gcm'],ib.ss_method)+'</select></div></div>'+
   '<div class="chipset" style="margin-top:12px"><span class="muted">'+t('Quick setup')+':</span>'+[['vr','VLESS + REALITY'],['vx','VLESS + XHTTP + REALITY'],['vw','VLESS + WS (CDN)'],['vg','VLESS + gRPC + REALITY'],['tt','Trojan + TLS'],['ss','Shadowsocks 2022']].map(function(x){return '<button type="button" data-pre="'+x[0]+'">'+x[1]+'</button>'}).join('')+'</div></div>'+
  // transport
  '<div class="fsec" data-fs="tr"><div class="g2"><div><label class="f">'+t('Transport')+'</label><select id="xi_nw">'+opt([['tcp','TCP (RAW)'],['ws','WebSocket'],['grpc','gRPC'],['httpupgrade','HTTPUpgrade'],['xhttp','XHTTP'],['kcp','mKCP']],ib.network)+'</select></div></div>'+
   '<div id="xi_tp" class="g2">'+inp('xi_pa','Path',ib.path,t('random if empty'))+inp('xi_ho','Host',ib.host,'')+'</div>'+
   '<div id="xi_wsx" class="g2">'+inp('xi_hb','Heartbeat (seconds, 0 = off)',ib.heartbeat||'','0','number')+'</div>'+
   '<div id="xi_xm" class="g2"><div><label class="f">'+t('Mode')+'</label><select id="xi_md">'+opt(['auto','packet-up','stream-up','stream-one'],ib.mode||'auto')+'</select></div>'+inp('xi_xp','Padding (bytes)',ib.x_padding,'100-1000')+'</div>'+
   '<div id="xi_gr"><div class="g2">'+inp('xi_svn','Service name',ib.service,t('random if empty'))+inp('xi_au','Authority (in the link)',ib.authority,'')+'</div>'+ck('xi_mm','Multi mode (in the link)',ib.multi_mode)+'</div>'+
   '<div id="xi_th">'+ck('xi_hh','HTTP header camouflage',ib.header=='http','The TCP stream starts like a plain HTTP request (path and Host above)')+'</div>'+
   '<div id="xi_kc"><div class="g2">'+inp('xi_km','MTU',ib.kcp_mtu||'','1350','number')+inp('xi_kt','TTI (ms)',ib.kcp_tti||'','50','number')+inp('xi_ku','Uplink (MB/s)',ib.kcp_up||'','5','number')+inp('xi_kd','Downlink (MB/s)',ib.kcp_down||'','20','number')+'</div>'+ck('xi_kg2','Congestion control',ib.kcp_cong)+'</div>'+
   '<div id="xi_ppw">'+ck('xi_pp','Accept PROXY protocol',ib.proxy_protocol,'Only when nginx / HAProxy in front sends it')+'</div></div>'+
  // security
  '<div class="fsec" data-fs="sec"><div id="xi_secw" class="g2"><div><label class="f">'+t('Security')+'</label><select id="xi_sc">'+opt([['none','None'],['tls','TLS'],['reality','REALITY']],ib.security)+'</select></div>'+
   '<div id="xi_fl"><label class="f">'+t('Flow')+'</label><select id="xi_flw">'+opt([['','none'],['xtls-rprx-vision','xtls-rprx-vision']],ib.flow||'')+'</select></div></div>'+
   '<div id="xi_tls"><div class="g2">'+inp('xi_sni','SNI',ib.sni,'example.com')+'<div><label class="f">'+t('Lowest TLS version')+'</label><select id="xi_tm">'+opt([['',t('Default')],'1.2','1.3'],ib.tls_min||'')+'</select></div></div>'+
    '<label class="f">ALPN</label><div class="ckrow">'+['h3','h2','http/1.1'].map(function(a){return '<label class="chk"><input type="checkbox" class="xi_al" value="'+a+'" '+((alpn.length?alpn:['h2','http/1.1']).indexOf(a)>=0?'checked':'')+'>'+a+'</label>'}).join('')+'</div>'+
    ck('xi_rs','Refuse unknown SNI',ib.reject_sni,'Only connections for the name above are answered')+
    '<label class="f">'+t('Certificate')+'</label><div class="ftabs" style="margin:0 0 6px"><button type="button" data-cm="auto" class="'+(ib.acme?'on':'')+'">'+t('Automatic (Let\'s Encrypt)')+'</button><button type="button" data-cm="pem" class="'+(ib.cert_file||ib.acme?'':'on')+'">'+t('Paste (PEM)')+'</button><button type="button" data-cm="file" class="'+(ib.cert_file&&!ib.acme?'on':'')+'">'+t('Files on the server')+'</button></div>'+
    '<div id="xi_cauto">'+xrCertAuto(ib)+'</div>'+
    '<div id="xi_cpem"><textarea id="xi_ce" rows="3" class="ltr" placeholder="-----BEGIN CERTIFICATE-----">'+esc(ib.cert||'')+'</textarea><textarea id="xi_ke" rows="3" class="ltr" style="margin-top:6px" placeholder="'+(ib.key=='set'?t('unchanged'):'-----BEGIN PRIVATE KEY-----')+'"></textarea></div>'+
    '<div id="xi_cfile" class="g2">'+inp('xi_cf','Certificate file',ib.cert_file,'/etc/letsencrypt/live/x/fullchain.pem')+inp('xi_kf','Key file',ib.key_file,'/etc/letsencrypt/live/x/privkey.pem')+'</div></div>'+
   '<div id="xi_rl"><label class="f">'+t('Target (dest)')+'</label><div class="inl"><input id="xi_de" class="ltr" value="'+esc(ib.dest||'')+'" placeholder="www.microsoft.com:443"><select id="xi_dp" style="flex:0 0 140px"><option value="">'+t('Suggestions')+'</option>'+REALITY_TARGETS.map(function(x){return '<option>'+x+'</option>'}).join('')+'</select></div>'+
    '<div class="g2">'+inp('xi_na','Server names',ib.names,'www.microsoft.com')+'<div><label class="f">'+t('Short IDs')+'</label><div class="inl"><input id="xi_si" class="ltr" value="'+esc(ib.short_ids||'')+'"><button type="button" class="ib" id="xi_sig" title="'+t('New')+'">🎲</button></div></div>'+
    inp('xi_pk','Private key',ib.private=='set'?'':ib.private,ib.private=='set'?t('unchanged'):'')+inp('xi_pb','Public key',ib.public,'')+inp('xi_sx','spiderX',ib.spx,'/')+
    '<div><label class="f">xver</label><select id="xi_xv">'+opt([0,1,2],ib.xver||0)+'</select></div>'+inp('xi_mt','Largest clock difference (ms, 0 = off)',ib.max_time_diff||'','0','number')+'</div>'+
    '<button type="button" class="b2" style="margin-top:8px" id="xi_kg">'+ic('refresh',14)+' '+t('New keys')+'</button></div>'+
   '<div id="xi_fpw" class="g2"><div><label class="f">'+t('Fingerprint')+'</label><select id="xi_fp">'+opt(['chrome','firefox','safari','ios','android','edge','360','qq','random','randomized'],ib.fp||'chrome')+'</select></div></div>'+
   '<p class="hint" id="xi_ssn">'+t('Shadowsocks has no TLS or REALITY: its own encryption is enough.')+'</p></div>'+
  // sniffing
  '<div class="fsec" data-fs="sn">'+ck('xi_sn','Sniffing',ib.sniffing,'Read the site name from the traffic (needed for domain rules)')+
   '<label class="f">'+t('Look at')+'</label><div class="ckrow">'+['http','tls','quic','fakedns'].map(function(x){return '<label class="chk"><input type="checkbox" class="xi_sd" value="'+x+'" '+(sd.indexOf(x)>=0?'checked':'')+'>'+x+'</label>'}).join('')+'</div>'+
   ck('xi_so','Use it for the destination too',ib.sniff_override,'Off = only for routing (recommended)')+ck('xi_sm2','Metadata only',ib.sniff_meta,'Do not read the content, only the connection details')+'</div>'+
  // link
  '<div class="fsec" data-fs="lk"><p class="muted" style="margin:0 0 6px">'+t('What the users\' links say. Leave empty unless a CDN or another address is in front of the server.')+'</p><div class="g2">'+inp('xi_lh','Link address',ib.link_host,t('automatic'))+inp('xi_lp','Link port',ib.link_port||'',String(ib.port||''))+inp('xi_ls','Link SNI',ib.link_sni,'')+'</div>'+
   ck('xi_lt','TLS at the CDN',ib.link_tls,'The CDN has the certificate; the server itself speaks plain WS / gRPC / XHTTP')+'</div>'+
  // limits
  '<div class="fsec" data-fs="lim"><div class="g2">'+inp('xi_tg','Total traffic of the inbound (GB, 0 = unlimited)',ib.total_gb||'','0','number')+'<div><label class="f">'+t('Stops on (empty = never)')+'</label><input id="xi_ex" type="date" class="ltr" value="'+expv+'"></div></div>'+
   '<p class="hint">'+t('When the traffic is used up or the date passes, the inbound stops by itself; users keep their own limits as well.')+'</p>'+
   '<label class="f">'+t('Only these users (empty = everyone with Xray)')+'</label><div class="row" style="gap:6px;flex-wrap:nowrap"><input id="xi_uq" placeholder="'+t('Search')+'…" style="flex:1"><button type="button" class="b2" id="xi_ua">'+t('All')+'</button><button type="button" class="b2" id="xi_un">'+t('None')+'</button></div>'+
   '<div class="ckrow" id="xi_ul" style="max-height:220px;overflow:auto">'+((d.user_list||[]).length?d.user_list.map(function(u){return '<label class="chk" data-un="'+esc(u.name.toLowerCase())+'"><input type="checkbox" class="xi_u" value="'+u.id+'" '+((ib.only||[]).indexOf(u.id)>=0?'checked':'')+'><span class="ltr">'+esc(u.name)+'</span></label>'}).join(''):'<p class="muted">'+t('No users with Xray yet: tick Xray in a user\'s form')+'</p>')+'</div></div>'+
  // fallbacks
  '<div class="fsec" data-fs="fb"><p class="muted" style="margin:0 0 6px">'+t('VLESS / Trojan over TCP with TLS: traffic that is not ours goes to these destinations (a website, another service).')+'</p><div id="xi_fbl"></div><button type="button" class="b2" id="xi_fba">'+ic('plus',14)+' '+t('Add fallback')+'</button></div>'+
  '<button class="btn" style="width:100%;margin-top:14px" id="xi_go">'+t('Save')+'</button>';
 modal(mhead(t(id?'Edit':'New inbound'),id?ib.remark:'Xray')+h,'wide');
 var FB=JSON.parse(JSON.stringify(ib.fallbacks||[]));
 var fbDraw=function(){$('#xi_fbl').innerHTML=FB.map(function(f,i){return '<div class="box" style="margin:0 0 8px"><div class="g2">'+
   ['dest','path','alpn','name'].map(function(k){return '<div><label class="f">'+t({dest:'Destination (port or address:port)',path:'Path',alpn:'ALPN',name:'SNI (name)'}[k])+'</label><input class="ltr xf" data-i="'+i+'" data-k="'+k+'" value="'+esc(f[k]||'')+'"></div>'}).join('')+
   '<div><label class="f">xver</label><select class="xf" data-i="'+i+'" data-k="xver">'+opt([0,1,2],f.xver||0)+'</select></div><div style="display:flex;align-items:flex-end"><button type="button" class="b2 bd" style="width:100%" data-fd="'+i+'">'+ic('trash',14)+' '+t('Delete')+'</button></div></div></div>'}).join('')||'<p class="muted">'+t('No fallbacks')+'</p>';
  $$('#xi_fbl .xf').forEach(function(e){e.oninput=e.onchange=function(){FB[+e.dataset.i][e.dataset.k]=e.dataset.k=='xver'?+e.value:e.value}});
  $$('#xi_fbl [data-fd]').forEach(function(b){b.onclick=function(){FB.splice(+b.dataset.fd,1);fbDraw()}})};
 fbDraw();$('#xi_fba').onclick=function(){FB.push({dest:'',path:'',alpn:'',name:'',xver:0});fbDraw()};
 $$('#xi_tabs [data-ft]').forEach(function(b){b.onclick=function(){$$('#xi_tabs [data-ft]').forEach(function(x){x.classList.toggle('on',x==b)});$$('.fsec').forEach(function(s){s.classList.toggle('on',s.dataset.fs==b.dataset.ft)})}});
 var srvDom=function(){var x=d.servers.filter(function(z){return z.server==$('#xi_sv').value})[0];return x&&x.domain||''};
 var cm=ib.acme?'auto':ib.cert_file?'file':(id?'pem':(srvDom()?'auto':'pem'));
 var sniPh=function(){var dm=srvDom();$('#xi_sni').placeholder=cm=='auto'&&dm?dm:'example.com';var h=$('#xi_cdom');if(h)h.innerHTML=dm?t('Empty SNI = the server\'s domain and certificate')+': <b class="ltr">'+esc(dm)+'</b>':t('This server has no domain: write one in SNI, or give the server a domain (Edit server).')};$$('[data-cm]').forEach(function(x){x.classList.toggle('on',x.dataset.cm==cm)});$$('[data-cm]').forEach(function(b){b.onclick=function(){cm=b.dataset.cm;$$('[data-cm]').forEach(function(x){x.classList.toggle('on',x==b)});ui()}});
 var show=function(i,on){var e=$(i);if(e)e.style.display=on?'':'none'};
 var ui=function(){var pr=$('#xi_pr').value,nw=$('#xi_nw').value,ss=pr=='shadowsocks';if(ss){$('#xi_nw').value='tcp';nw='tcp'}
  if($('#xi_sc').value=='reality'&&(['vless','trojan'].indexOf(pr)<0||['tcp','grpc','xhttp'].indexOf(nw)<0))$('#xi_sc').value='tls';
  var sc=ss?'none':$('#xi_sc').value;
  show('#xi_secw',!ss);show('#xi_ssn',ss);show('#xi_ss',ss);show('#xi_tp',['ws','httpupgrade','xhttp'].indexOf(nw)>=0||nw=='tcp'&&$('#xi_hh').checked);show('#xi_wsx',nw=='ws');show('#xi_xm',nw=='xhttp');show('#xi_gr',nw=='grpc');show('#xi_th',nw=='tcp'&&sc=='none'&&!ss);show('#xi_kc',nw=='kcp');show('#xi_ppw',nw!='kcp');
  show('#xi_fl',pr=='vless'&&nw=='tcp'&&sc!='none');show('#xi_tls',sc=='tls');show('#xi_rl',sc=='reality');show('#xi_fpw',sc!='none'||$('#xi_lt').checked);$('#xi_nw').disabled=ss;
  show('#xi_cpem',cm=='pem');show('#xi_cfile',cm=='file');show('#xi_cauto',cm=='auto');sniPh();
  var fbOk=(pr=='vless'||pr=='trojan')&&nw=='tcp'&&sc!='reality';$('#xi_tabs [data-ft="fb"]').style.display=fbOk?'':'none';
  [].forEach.call($('#xi_sc').options,function(o){if(o.value=='reality')o.disabled=['vless','trojan'].indexOf(pr)<0||['tcp','grpc','xhttp'].indexOf(nw)<0})};
 ['#xi_pr','#xi_nw','#xi_sc','#xi_lt','#xi_hh','#xi_sv'].forEach(function(s){$(s).onchange=ui});ui();
 $('#xi_dp').onchange=function(){if(!this.value)return;$('#xi_de').value=this.value;$('#xi_na').value=this.value.split(':')[0];this.value=''};
 $('#xi_sig').onclick=function(){var r='';for(var i=0;i<8;i++)r+=Math.floor(Math.random()*256).toString(16).padStart(2,'0');$('#xi_si').value=r};
 $('#xi_rp').onclick=function(){$('#xi_pt').value=xrFreePort($('#xi_sv').value,true)};
 $('#xi_kg').onclick=function(){api('POST','/api/xray/keys').then(function(k){$('#xi_pk').value=k.private;$('#xi_pb').value=k.public;if(!$('#xi_si').value)$('#xi_si').value=k.short_id}).catch(fail)};
 $('#xi_uq').oninput=function(){var q=this.value.toLowerCase();$$('#xi_ul [data-un]').forEach(function(l){l.style.display=!q||l.dataset.un.indexOf(q)>=0?'':'none'})};
 $('#xi_ua').onclick=function(){$$('.xi_u').forEach(function(c){if(c.parentNode.style.display!='none')c.checked=true})};$('#xi_un').onclick=function(){$$('.xi_u').forEach(function(c){c.checked=false})};
 $$('[data-pre]').forEach(function(b){b.onclick=function(){var k=b.dataset.pre,set=function(i,v){$(i).value=v};
  var P={vr:['vless','tcp','reality','xtls-rprx-vision',443],vx:['vless','xhttp','reality','',443],vw:['vless','ws','none','',8080],vg:['vless','grpc','reality','',443],tt:['trojan','tcp','tls','',443],ss:['shadowsocks','tcp','none','',8388]}[k];
  set('#xi_pr',P[0]);set('#xi_nw',P[1]);set('#xi_sc',P[2]);set('#xi_flw',P[3]);if(!$('#xi_rm').value)$('#xi_rm').value=b.textContent.replace(/\s+/g,'').replace(/\+/g,'-');
  var used=XR.d.inbounds.some(function(x){return x.id!=id&&x.server==$('#xi_sv').value&&x.port==P[4]});$('#xi_pt').value=used?xrFreePort($('#xi_sv').value,true):P[4];
  if(P[2]=='reality'&&!$('#xi_de').value){$('#xi_de').value='www.microsoft.com:443';$('#xi_na').value='www.microsoft.com'}if(k=='vw')$('#xi_lt').checked=false;ui();toast(t('Filled in: check the Security tab'))}});
 $('#xi_go').onclick=function(){var me=this,v=function(i){return $(i).value.trim()};
  var ex=v('#xi_ex'),expire=0;if(ex){var pd=ex.split('-');expire=Math.floor(new Date(+pd[0],+pd[1]-1,+pd[2],23,59,0).getTime()/1000)}
  var b={id:id||'',enabled:ib.enabled!==false,remark:v('#xi_rm'),server:$('#xi_sv').value,protocol:$('#xi_pr').value,port:+v('#xi_pt')||0,listen:v('#xi_ls0'),network:$('#xi_nw').value,security:$('#xi_pr').value=='shadowsocks'?'none':$('#xi_sc').value,
   path:v('#xi_pa'),host:v('#xi_ho'),mode:$('#xi_md').value,service:v('#xi_svn'),header:$('#xi_hh').checked?'http':'',flow:$('#xi_flw').value,ss_method:$('#xi_sm').value,ss_key:ib.ss_key||'',
   heartbeat:+v('#xi_hb')||0,x_padding:v('#xi_xp'),authority:v('#xi_au'),multi_mode:$('#xi_mm').checked,kcp_mtu:+v('#xi_km')||0,kcp_tti:+v('#xi_kt')||0,kcp_up:+v('#xi_ku')||0,kcp_down:+v('#xi_kd')||0,kcp_cong:$('#xi_kg2').checked,proxy_protocol:$('#xi_pp').checked,
   sni:v('#xi_sni'),alpn:$$('.xi_al').filter(function(c){return c.checked}).map(function(c){return c.value}).join(','),tls_min:$('#xi_tm').value,reject_sni:$('#xi_rs').checked,
   acme:cm=='auto',cert:cm=='pem'?$('#xi_ce').value.trim():'',key:cm=='pem'?($('#xi_ke').value.trim()||(ib.key=='set'?'set':'')):'',cert_file:cm=='file'?v('#xi_cf'):'',key_file:cm=='file'?v('#xi_kf'):'',fp:$('#xi_fp').value,
   dest:v('#xi_de'),names:v('#xi_na'),private:v('#xi_pk')||(ib.private=='set'?'set':''),public:v('#xi_pb'),short_ids:v('#xi_si'),spx:v('#xi_sx'),xver:+$('#xi_xv').value||0,max_time_diff:+v('#xi_mt')||0,
   sniffing:$('#xi_sn').checked,sniff_dest:$$('.xi_sd').filter(function(c){return c.checked}).map(function(c){return c.value}),sniff_override:$('#xi_so').checked,sniff_meta:$('#xi_sm2').checked,
   link_host:v('#xi_lh'),link_port:+v('#xi_lp')||0,link_tls:$('#xi_lt').checked,link_sni:v('#xi_ls'),total_gb:+v('#xi_tg')||0,expire:expire,
   only:$$('.xi_u').filter(function(c){return c.checked}).map(function(c){return +c.value}),fallbacks:FB.filter(function(f){return String(f.dest).trim()})};
  if(b.private&&b.private!='set'&&!b.public)return toast(t('Public key'),1);
  if(!b.port)return toast(t('the port is required'),1);
  if(b.acme&&b.security=='tls'&&!b.sni&&!srvDom())return toast(t('Write the domain in SNI'),1);
  me.disabled=true;api('POST','/api/xray/inbounds',b).then(function(){closeModal();toast(t('Saved'));xrLoad()}).catch(function(e){me.disabled=false;fail(e)})}}
function xrCertAuto(ib){
 var st=!ib.acme?'':ib.state=='nocert'?'<div class="vrow"><span class="dot '+(ib.cert_err?'r':'y')+'"></span><div class="nm"><b>'+(ib.cert_err?t('Certificate error'):t('Waiting for the certificate'))+'</b>'+(ib.cert_err?'<small class="ltr" style="color:var(--bad)">'+esc(ib.cert_err)+'</small>':'')+'</div></div>'
  :'<div class="vrow"><span class="dot g"></span><div class="nm"><b>SSL ✓</b><small>'+t('renewed by itself')+'</small></div></div>';
 return '<p class="hint" id="xi_cdom" style="margin-top:0"></p><p class="hint" style="margin-top:0">'+t('certbot on the server gets a Let\'s Encrypt certificate for this domain by itself (no e-mail needed) and renews it. The domain must point to the server; whatever uses port 80 is set aside for a few seconds and comes back by itself. The links use the domain.')+'</p>'+st}
function xrFreePort(sid,random){var used=(XR.d&&XR.d.inbounds||[]).filter(function(x){return x.server==sid}).map(function(x){return +x.port}),bad=[53,80,853,10085,10853,10854];
 if(!random&&used.indexOf(443)<0)return 443;for(var i=0;i<200;i++){var p=10000+Math.floor(Math.random()*50000);if(used.indexOf(p)<0&&bad.indexOf(p)<0)return p}return 20000}
