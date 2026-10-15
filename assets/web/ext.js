// Kanki Panel extensions (v3.4): Kanki DNS and Xray pages, node types, DNS / Xray access for users.
// Loaded before the main script; KEXT() runs once the main script has defined its tables.
function KEXT(){
 PROTOS.push(['xray','Xray'],['dns','DNS']);
 PCOL.xray='#e0a020';PCOL.dns='#2a9df4';
 ICO.dns='<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>';
 ICO.xray='<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>';
 PAGES.splice(3,0,['dns','Kanki DNS','dns'],['xray','Xray','xray']);
 NAVG.forEach(function(g){if(g[1].indexOf('nodes')>=0)g[1].splice(1,0,'dns','xray')});
 Object.assign(FA,{"Kanki DNS":"دی‌ان‌اس کانکی","Private smart DNS for your subscribers: sanctioned services go through your servers, everything else goes direct":"DNS هوشمند اختصاصی مشتری‌ها: سرویس‌های تحریمی از سرورهای شما رد می‌شوند و بقیه مستقیم",
 "DNS is on":"DNS روشن است","DNS domain":"دامنه‌ی DNS","Each DNS server gets a name under it, like de.dns.example.com":"هر سرور DNS یک اسم زیر آن می‌گیرد، مثل de.dns.example.com",
 "Upstream resolvers":"DNSهای بالادست","An allowed address stays open for (hours)":"مدت باز ماندن IP ثبت‌شده (ساعت)","Certificate and records":"گواهی SSL و رکوردها",
 "Provider":"سرویس DNS دامنه","Manual (paste a certificate)":"دستی (گواهی را خودت بگذار)","API token":"توکن API","unchanged":"بدون تغییر","E-mail for Let's Encrypt (optional)":"ایمیل برای Let's Encrypt (اختیاری)",
 "Set records and get the certificate now":"الان رکوردها را بساز و گواهی بگیر","Working… about a minute":"در حال انجام… حدود یک دقیقه","Certificate":"گواهی","none yet":"هنوز ندارد","issued":"صادر شده",
 "DNS servers":"سرورهای DNS","Exit (abroad)":"خروجی (خارج)","Relay (inside Iran)":"ریلی (داخل ایران)","Exit":"خروجی","Relay":"ریلی","Label":"برچسب","Answer IP":"IP پاسخ",
 "automatic":"خودکار","Running":"در حال اجرا","Not running":"اجرا نمی‌شود","Waiting for the server…":"در انتظار سرور…","Allowed addresses":"IPهای مجاز","Connections":"اتصال‌ها",
 "Add DNS server":"افزودن سرور DNS","Add relay":"افزودن ریلی","Agent server":"سرور (ایجنت)","New server (install command)":"سرور جدید (دستور نصب)","Its exit":"خروجی آن",
 "Transport to the exit":"ترنسپورت تا خروجی","Tunnel port on the relay":"پورت تانل روی ریلی","Note for subscribers":"یادداشت برای مشتری‌ها","Hidden from subscribers":"مخفی از مشتری‌ها",
 "Services":"سرویس‌ها","Routed names":"دامنه‌های مسیر‌دهی‌شده","Extra domains, one per line":"دامنه‌های اضافه، هر خط یکی","Users with DNS":"کاربران دارای DNS",
 "Remove from DNS":"حذف از DNS","Save services":"ذخیره سرویس‌ها","How it works":"چطور کار می‌کند","Node type":"نوع نود",
 "VPN node":"نود VPN","WireGuard · AmneziaWG · Hysteria2":"WireGuard · AmneziaWG · Hysteria2","Xray node":"نود Xray","VLESS · VMess · Trojan · Shadowsocks":"VLESS · VMess · Trojan · Shadowsocks",
 "DNS exit node":"نود DNS خروجی","Smart DNS abroad":"DNS هوشمند در خارج","DNS relay node":"نود ریلی DNS","Iran server in front of a DNS exit":"سرور ایران جلوی DNS خروجی",
 "Ports 53, 80, 443 and 853 must be free on this server: give DNS its own server.":"پورت‌های ۵۳، ۸۰، ۴۴۳ و ۸۵۳ روی این سرور باید آزاد باشند: برای DNS سرور جدا بگذار.",
 "Add an exit DNS server first":"اول یک سرور DNS خروجی اضافه کن","Server name":"نام سرور","Create":"ساخت","Other nodes":"نودهای دیگر","Open":"باز کردن",
 "only on request":"فقط با درخواست","cannot be routed":"قابل مسیردهی نیست","Last error":"آخرین خطا"});
}
var DN={d:null};
function p_dns(){$('#pg').innerHTML='<div class="ph"><div><h2>'+t('Kanki DNS')+'</h2><p>'+t('Private smart DNS for your subscribers: sanctioned services go through your servers, everything else goes direct')+'</p></div><div class="row" style="gap:6px"><button class="b2" onclick="dnsAdd(\'relay\')">+ '+t('Add relay')+'</button><button class="btn" onclick="dnsAdd(\'exit\')">+ '+t('Add DNS server')+'</button></div></div><div id="dn">'+t('Loading…')+'</div>';
 dnsLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)))dnsLoad(true)},5000)}
function dnsLoad(quiet){return api('GET','/api/dns').then(function(d){DN.d=d;if(S.page!='dns')return;if(quiet&&$('#dn_srv')){$('#dn_srv').innerHTML=dnsServers(d);$('#dn_cert').innerHTML=dnsCertState(d);return}dnsDraw(d)}).catch(fail)}
function dnsName(id){var a=(DN.d&&DN.d.agents)||[];for(var i=0;i<a.length;i++)if(a[i].id==id)return a[i].name;return id}
function dnsCertState(d){var c=d.cert||{};
 return '<p style="margin:6px 0">'+t('Certificate')+': '+(c.present?'<span class="badge g">'+t('issued')+(d.cert_at?' · '+ago(d.cert_at):'')+'</span>':'<span class="badge r">'+t('none yet')+'</span>')+(d.acme_busy?' <span class="badge">'+t('Working… about a minute')+'</span>':'')+'</p>'+
  (d.cert_names?'<p class="muted ltr" style="margin:0">'+esc(d.cert_names.split(',').join('  '))+'</p>':'')+
  (d.acme_err?'<div class="warnbox ltr">'+t('Last error')+': '+esc(d.acme_err)+'</div>':'')}
function dnsServers(d){if(!d.servers.length)return '<p class="muted">'+t('Add an exit DNS server first')+'</p>';
 return d.servers.map(function(x){var st=x.status||{},on=st.active,col=on?'var(--ok)':'var(--bad)',errs=(st.errors||[]).concat(st.deploy_error?[st.deploy_error]:[]).concat(st.error?[st.error]:[]);
  return '<div class="card" style="margin:0 0 8px;border-inline-start:3px solid '+col+'"><div class="row" style="justify-content:space-between;align-items:flex-start;gap:8px"><div style="min-width:0"><b>'+esc(x.name||x.server)+'</b> <span class="rotb">'+(x.role=='relay'?'🇮🇷 '+t('Relay')+' → '+esc(dnsName(x.exit)):'🌍 '+t('Exit'))+'</span>'+(x.hidden?' <span class="badge">'+t('Hidden from subscribers')+'</span>':'')+
   '<div class="muted ltr">'+esc(x.host||'—')+' · '+esc(x.answer_ip||'?')+'</div></div><span class="badge '+(on?'g':'r')+'">'+(x.status_at?(on?t('Running'):t('Not running')):t('Waiting for the server…'))+'</span></div>'+
   (on?'<p class="muted" style="margin:6px 0 0">'+t('Allowed addresses')+': <b>'+N(st.allowed||0)+'</b> · '+t('Connections')+': <b>'+N(st.conns||0)+'</b></p>':'')+
   (errs.length?'<div class="warnbox ltr" style="margin:6px 0 0">'+errs.map(esc).join('<br>')+'</div>':'')+
   '<div class="g2" style="margin-top:8px"><button class="b2" onclick="dnsEdit(\''+x.server+'\')">'+ic('edit',15)+' '+t('Edit')+'</button><button class="b2 bd" onclick="dnsDel(\''+x.server+'\')">'+ic('trash',15)+' '+t('Remove from DNS')+'</button></div></div>'}).join('')}
function dnsDraw(d){var el=$('#dn');if(!el)return;
 var kpi='<div class="card" style="padding:10px"><div class="tkpi" style="margin:0"><div><small>'+t('Status')+'</small><b>'+(d.on?t('On'):t('Off'))+'</b></div><div><small>'+t('Users with DNS')+'</small><b>'+N(d.users)+'</b></div><div><small>'+t('Routed names')+'</small><b>'+N(d.domains)+'</b></div><div><small>'+t('DNS servers')+'</small><b>'+N(d.servers.length)+'</b></div></div></div>';
 var set='<div class="card"><h3>'+t('Settings')+'</h3><label class="chk"><input type="checkbox" id="dn_on" '+(d.on?'checked':'')+'><span><b>'+t('DNS is on')+'</b></span></label>'+
  '<label class="f">'+t('DNS domain')+'</label><input id="dn_base" class="ltr" placeholder="dns.example.com" value="'+esc(d.base)+'"><small class="muted">'+t('Each DNS server gets a name under it, like de.dns.example.com')+'</small>'+
  '<div class="g2"><div><label class="f">'+t('Upstream resolvers')+'</label><input id="dn_up" class="ltr" value="'+esc(d.upstreams.join(', '))+'"></div><div><label class="f">'+t('An allowed address stays open for (hours)')+'</label><input id="dn_h" type="number" min="1" class="ltr" value="'+d.ip_hours+'"></div></div>'+
  '<button class="btn" style="width:100%;margin-top:12px" id="dn_save">'+t('Save')+'</button></div>';
 var cert='<div class="card"><h3>'+t('Certificate and records')+'</h3><div id="dn_cert">'+dnsCertState(d)+'</div>'+
  '<label class="f">'+t('Provider')+'</label><select id="dn_pv">'+[['',t('Manual (paste a certificate)')],['cloudflare','Cloudflare'],['arvan','ArvanCloud']].map(function(o){return '<option value="'+o[0]+'"'+(d.provider==o[0]?' selected':'')+'>'+o[1]+'</option>'}).join('')+'</select>'+
  '<div id="dn_auto"><div class="g2"><div><label class="f">'+t('API token')+'</label><input id="dn_tok" type="password" class="ltr" autocomplete="off" placeholder="'+(d.has_token?t('unchanged'):'')+'"></div><div><label class="f">'+t("E-mail for Let's Encrypt (optional)")+'</label><input id="dn_em" class="ltr" value="'+esc(d.email||'')+'"></div></div>'+
   '<button class="b2" style="width:100%;margin-top:10px" id="dn_iss">'+t('Set records and get the certificate now')+'</button></div>'+
  '<div id="dn_man"><label class="f">'+t('Certificate (PEM, full chain)')+'</label><textarea id="dn_c" rows="3" class="ltr" placeholder="-----BEGIN CERTIFICATE-----"></textarea><label class="f">'+t('Private key (PKCS#8 PEM)')+'</label><textarea id="dn_k" rows="3" class="ltr" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>'+
  '<button class="btn" style="width:100%;margin-top:12px" id="dn_csave">'+t('Save')+'</button></div>';
 el.innerHTML=kpi+'<div class="g2">'+set+cert+'</div><div class="card"><h3>'+t('DNS servers')+'</h3><div id="dn_srv">'+dnsServers(d)+'</div></div><div class="card"><h3>'+t('Services')+'</h3><div id="dn_svc"></div></div>';
 var pv=function(){var a=$('#dn_pv').value!='';$('#dn_auto').style.display=a?'':'none';$('#dn_man').style.display=a?'none':''};$('#dn_pv').onchange=pv;pv();
 $('#dn_save').onclick=function(){api('PUT','/api/dns',{on:$('#dn_on').checked,base:$('#dn_base').value,upstreams:$('#dn_up').value,ip_hours:+$('#dn_h').value||12}).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};
 $('#dn_csave').onclick=function(){var b={provider:$('#dn_pv').value,api_token:$('#dn_tok').value,email:$('#dn_em').value};if(!b.provider&&$('#dn_c').value.trim()){b.cert=$('#dn_c').value;b.key=$('#dn_k').value}
  api('PUT','/api/dns',b).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)};
 $('#dn_iss').onclick=function(){var me=this;me.disabled=true;api('PUT','/api/dns',{provider:$('#dn_pv').value,api_token:$('#dn_tok').value,email:$('#dn_em').value}).then(function(){return api('POST','/api/dns/cert')}).then(function(){toast(t('Working… about a minute'));setTimeout(function(){me.disabled=false;dnsLoad(true)},5000)}).catch(function(e){me.disabled=false;fail(e)})};
 dnsServices(d)}
function dnsGroupOn(d,id,g){if(g.locked)return false;if(g.opt_in)return d.opt.indexOf(id)>=0;return d.off.indexOf(id)<0}
function dnsServices(d){var cat=d.catalog||{},secs=cat.sections||[],svcs=cat.services||[],el=$('#dn_svc');
 var draw=function(icons){el.innerHTML=secs.map(function(sec){var list=svcs.filter(function(s){return s.section==sec.key});if(!list.length)return '';
   return '<h4 style="margin:14px 0 6px">'+esc(sec.label)+'</h4><div class="ncards">'+list.map(function(s){var icn=icons[s.key];
    return '<div class="card" style="margin:0;padding:10px"><div class="row" style="gap:8px">'+(icn?'<svg viewBox="0 0 24 24" width="22" height="22" style="flex:none"><path fill="#'+esc(icn.hex=='000000'?'888888':icn.hex)+'" d="'+esc(icn.path)+'"/></svg>':'<span class="ni">'+ic('dns',18)+'</span>')+'<b>'+esc(s.label)+'</b></div>'+
     s.groups.map(function(g){var id=s.key+'/'+g.key,on=dnsGroupOn(d,id,g);
      return '<label class="chk" style="margin-top:6px" title="'+esc(g.note||'')+'"><input type="checkbox" class="dn_g" data-id="'+esc(id)+'" data-opt="'+(g.opt_in?1:0)+'" '+(on?'checked':'')+(g.locked?' disabled':'')+'><span>'+esc(g.label)+' <small class="muted">('+N(g.domains.length)+')'+(g.locked?' · '+t('cannot be routed'):g.opt_in?' · '+t('only on request'):'')+'</small>'+(g.note?'<br><small class="muted">'+esc(g.note)+'</small>':'')+'</span></label>'}).join('')+'</div>'}).join('')+'</div>'}).join('')+
   '<label class="f" style="margin-top:14px">'+t('Extra domains, one per line')+'</label><textarea id="dn_cu" rows="4" class="ltr" placeholder="example.com">'+esc((d.custom||[]).join('\n'))+'</textarea>'+
   '<button class="btn" style="width:100%;margin-top:12px" id="dn_svs">'+t('Save services')+'</button>';
  $('#dn_svs').onclick=function(){var off=[],opt=[];$$('.dn_g').forEach(function(c){if(c.disabled)return;if(c.dataset.opt=='1'){if(c.checked)opt.push(c.dataset.id)}else if(!c.checked)off.push(c.dataset.id)});
   api('PUT','/api/dns',{off:off,opt:opt,custom:$('#dn_cu').value.split('\n').map(function(x){return x.trim()}).filter(Boolean)}).then(function(){toast(t('Saved'));dnsLoad()}).catch(fail)}};
 if(DN.icons)draw(DN.icons);else fetch('/assets/dns-icons.json').then(function(r){return r.json()}).then(function(j){DN.icons=j.icons||{};draw(DN.icons)}).catch(function(){DN.icons={};draw({})})}
function dnsForm(x,role){var d=DN.d,exits=d.servers.filter(function(s){return s.role=='exit'&&s.server!=(x&&x.server)}),agents=d.agents.filter(function(a){return !d.servers.some(function(s){return s.server==a.id&&(!x||s.server!=x.server)})});
 if(role=='relay'&&!exits.length){toast(t('Add an exit DNS server first'),1);return null}
 var h='<p class="muted" style="margin:0 0 6px">'+t('Ports 53, 80, 443 and 853 must be free on this server: give DNS its own server.')+'</p>';
 if(!x)h+='<label class="f">'+t('Agent server')+'</label><select id="dx_sv"><option value="__new">'+t('New server (install command)')+'</option>'+agents.map(function(a){return '<option value="'+esc(a.id)+'">'+esc(a.name)+'</option>'}).join('')+'</select><div id="dx_nw"><label class="f">'+t('Server name')+'</label><input id="dx_nm" placeholder="'+(role=='relay'?'Iran-DNS':'DNS-DE')+'"></div>';
 h+='<div class="g2"><div><label class="f">'+t('Label')+'</label><input id="dx_lb" class="ltr" placeholder="'+(role=='relay'?'ir1':'de')+'" value="'+esc(x?x.label:'')+'"></div><div><label class="f">'+t('Answer IP')+'</label><input id="dx_ip" class="ltr" placeholder="'+t('automatic')+'" value="'+esc(x?x.ip:'')+'"></div></div>';
 if(role=='relay')h+='<label class="f">'+t('Its exit')+'</label><select id="dx_ex">'+exits.map(function(s){return '<option value="'+esc(s.server)+'"'+(x&&x.exit==s.server?' selected':'')+'>'+esc(s.name)+'</option>'}).join('')+'</select>'+
  '<div class="g2"><div><label class="f">'+t('Transport to the exit')+'</label><select id="dx_tr">'+['tcpmux','dual','h2','hq','wss','ws','kcp','quic','tcp'].map(function(v){return '<option'+((x&&x.transport||'tcpmux')==v?' selected':'')+'>'+v+'</option>'}).join('')+'</select></div><div><label class="f">'+t('Tunnel port on the relay')+'</label><input id="dx_tp" type="number" class="ltr" value="'+((x&&x.tunnel_port)||8446)+'"></div></div>';
 h+='<label class="f">'+t('Note for subscribers')+'</label><input id="dx_nt" value="'+esc(x?x.note:'')+'"><label class="chk" style="margin-top:8px"><input type="checkbox" id="dx_hd" '+(x&&x.hidden?'checked':'')+'><span>'+t('Hidden from subscribers')+'</span></label>';
 return h+'<button class="btn" style="width:100%;margin-top:12px" id="dx_go">'+t('Save')+'</button><div id="dx_out"></div>'}
function dnsBody(role,sid){var b={server:sid,role:role,label:$('#dx_lb').value,ip:$('#dx_ip').value,note:$('#dx_nt').value,hidden:$('#dx_hd').checked};
 if(role=='relay'){b.exit=$('#dx_ex').value;b.transport=$('#dx_tr').value;b.tunnel_port=+$('#dx_tp').value||8446}return b}
function dnsAdd(role){var go=function(){var h=dnsForm(null,role);if(h===null)return;modal(mhead(t(role=='relay'?'Add relay':'Add DNS server'),t(role=='relay'?'Relay (inside Iran)':'Exit (abroad)'))+h);
  var sv=function(){$('#dx_nw').style.display=$('#dx_sv').value=='__new'?'':'none'};$('#dx_sv').onchange=sv;sv();
  $('#dx_go').onclick=function(){var me=this;me.disabled=true;var nw=$('#dx_sv').value=='__new';
   (nw?api('POST','/api/tunnels/servers',{name:$('#dx_nm').value||((role=='relay'?'DNS-relay-':'DNS-')+($('#dx_lb').value||''))}):Promise.resolve({id:$('#dx_sv').value})).then(function(r){
    return api('POST','/api/dns/servers',dnsBody(role,r.id)).then(function(){toast(t('Saved'));if(nw){$('#dx_go').style.display='none';$('#dx_out').innerHTML=tunCmdBox(r,r);$('#tn_cp').onclick=function(){copy($('#tn_cmd').textContent)}}else closeModal();dnsLoad()})}).catch(function(e){me.disabled=false;fail(e)})}};
 if(DN.d)go();else dnsLoad().then(go)}
function dnsEdit(id){var x=DN.d.servers.filter(function(s){return s.server==id})[0];if(!x)return;var h=dnsForm(x,x.role);if(h===null)return;
 modal(mhead(t('Edit'),x.name)+h);$('#dx_go').onclick=function(){api('POST','/api/dns/servers',dnsBody(x.role,id)).then(function(){toast(t('Saved'));closeModal();dnsLoad()}).catch(fail)}}
function dnsDel(id){confirmDo(function(){api('DELETE','/api/dns/servers/'+encodeURIComponent(id)).then(function(){toast(t('Done'));dnsLoad()}).catch(fail)})}

// ---- node types: the "Add node" button first asks which kind of node
var _nodeAdd=null;
function nodeAddTyped(){var tile=function(k,ico,title,sub){return '<button class="b2" data-nt="'+k+'" style="display:flex;gap:10px;align-items:center;text-align:start;padding:12px;width:100%;margin-bottom:8px"><span class="ni">'+ic(ico,20)+'</span><span><b>'+t(title)+'</b><br><small class="muted">'+t(sub)+'</small></span></button>'};
 modal(mhead(t('Node type'))+tile('vpn','nodes','VPN node','WireGuard · AmneziaWG · Hysteria2')+tile('xray','xray','Xray node','VLESS · VMess · Trojan · Shadowsocks')+tile('dns','dns','DNS exit node','Smart DNS abroad')+tile('relay','dns','DNS relay node','Iran server in front of a DNS exit'));
 $$('[data-nt]').forEach(function(b){b.onclick=function(){var k=b.dataset.nt;if(k=='vpn')return _nodeAdd();if(k=='xray'){closeModal();location.hash='#xray';setTimeout(function(){if(window.xrAddNode)xrAddNode()},300);return}
  dnsLoad().then(function(){dnsAdd(k=='relay'?'relay':'exit')})}})}
function p_xray(){$('#pg').innerHTML='<div class="ph"><div><h2>Xray</h2><p>VLESS · VMess · Trojan · Shadowsocks</p></div></div><div class="card"><p class="muted">'+t('Loading…')+'</p></div>'}
