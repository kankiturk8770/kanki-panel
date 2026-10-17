// Kanki Panel: the KANKI MIX page (v3.6). Our own UDP protocol on every VPN server, next to WireGuard,
// AmneziaWG and Hysteria2: game UDP on a raw datagram path (sent twice in gaming mode), TCP on KCP + FEC.
// The agent writes the built-in server to each server by itself; every user has their own key.
var KM_ICO='<path d="M6 11h4M8 9v4"/><circle cx="15.5" cy="12.5" r=".6"/><circle cx="17.5" cy="10.5" r=".6"/><path d="M7.5 6h9a5 5 0 0 1 4.8 6.3l-1 3.6a2.6 2.6 0 0 1-4.6.9L14.5 15h-5l-1.2 1.8a2.6 2.6 0 0 1-4.6-.9l-1-3.6A5 5 0 0 1 7.5 6z"/>';
var KM={d:null};
function kmFA(){if(kmFA.done||typeof FA=='undefined')return;kmFA.done=1;ICO.game=KM_ICO;Object.assign(FA,{
 "Our own protocol: games, low ping":"پروتکل خودمان: بازی، پینگ کم",
 "Our own protocol on every VPN server: game packets go straight (no queue, sent twice in gaming mode), websites over KCP + FEC.":"پروتکل خودمان روی همه‌ی سرورهای VPN: بسته‌های بازی مستقیم می‌روند (بدون صف، در حالت گیمینگ دوتایی)، سایت‌ها روی KCP + FEC.",
 "KANKI MIX is off: it runs on no server and is in no subscription.":"KANKI MIX خاموش است: روی هیچ سروری اجرا نمی‌شود و در هیچ اشتراکی نیست.",
 "Users with KANKI MIX":"کاربران KANKI MIX","Running servers":"سرورهای فعال","Online now":"آنلاین الان","Total traffic":"ترافیک کل",
 "Servers":"سرورها","Settings":"تنظیمات","Save":"ذخیره","Saved":"ذخیره شد","On":"روشن","Off":"خاموش",
 "KANKI MIX on":"KANKI MIX روشن","Default UDP port":"پورت UDP پیش‌فرض","Every server uses it unless it has its own port below.":"همه‌ی سرورها همین را دارند، مگر سروری که پایین پورت خودش را دارد.",
 "FEC for websites (TCP)":"FEC برای سایت‌ها (TCP)","Extra bytes that rebuild lost packets without asking again. Games do not use it (they have gaming mode).":"بایت اضافه که بسته‌ی گم‌شده را بدون درخواست دوباره می‌سازد. بازی‌ها از آن استفاده نمی‌کنند (حالت گیمینگ دارند).",
 "none":"هیچ","light":"سبک","normal":"معمولی","strong":"قوی","very strong":"خیلی قوی",
 "Gaming mode on in the app by default":"حالت گیمینگ در اپ پیش‌فرض روشن","Each game packet is sent twice: at 20% loss 92% arrive instead of 64%. Users can switch it off in the app.":"هر بسته‌ی بازی دو بار فرستاده می‌شود: با ۲۰٪ لاس، ۹۲٪ می‌رسد به جای ۶۴٪. کاربر در اپ می‌تواند خاموشش کند.",
 "Extra ports (port range)":"پورت‌های اضافه (بازه)","Like 4001-4010. They all lead to the main port; the app picks one at random on every connect, so blocking one port is not enough. Empty = off.":"مثلاً 4001-4010. همه به پورت اصلی می‌رسند؛ اپ هر بار یکی را تصادفی انتخاب می‌کند تا بستن یک پورت کافی نباشد. خالی = خاموش.",
 "Enable for all users":"روشن برای همه‌ی کاربران","Disable for all users":"خاموش برای همه‌ی کاربران",
 "KANKI MIX for every user?":"KANKI MIX برای همه‌ی کاربران روشن شود؟","Remove KANKI MIX from every user?":"KANKI MIX از همه‌ی کاربران برداشته شود؟",
 "users changed":"کاربر تغییر کرد","Running":"در حال اجرا","Not running":"اجرا نمی‌شود","Waiting for the server…":"منتظر سرور…","Off on this server":"روی این سرور خاموش",
 "Update the agent of this server (Servers › Update agent) to run KANKI MIX":"عامل این سرور را به‌روز کن (سرورها › به‌روزرسانی عامل) تا KANKI MIX اجرا شود",
 "Port of this server":"پورت این سرور","default":"پیش‌فرض","users":"کاربر","Main server":"سرور اصلی",
 "How it works":"چطور کار می‌کند",
 "1) Keep it on and pick the port (4000 is fine). 2) Tick KANKI MIX for users (or Enable for all users). 3) Every server installs it by itself within a minute; the Kanki app gets the kanki:// link from the subscription, users see no IP or key.":"۱) روشن بگذار و پورت را انتخاب کن (۴۰۰۰ خوب است). ۲) KANKI MIX را برای کاربران تیک بزن (یا «روشن برای همه‌ی کاربران»). ۳) هر سرور ظرف یک دقیقه خودش نصبش می‌کند؛ اپ کانکی لینک kanki:// را از اشتراک می‌گیرد و کاربر IP یا کلید نمی‌بیند.",
 "Each user has their own key (made from the subscription code): resetting the link gives a new key, disabling or expiring cuts the user off at once. Traffic and devices count like the other protocols.":"هر کاربر کلید خودش را دارد (از کد اشتراک ساخته می‌شود): ریست لینک کلید تازه می‌دهد، غیرفعال یا منقضی شدن کاربر را فوراً قطع می‌کند. مصرف و دستگاه‌ها مثل بقیه‌ی پروتکل‌ها شمرده می‌شوند.",
 "Coming next":"به‌زودی","Port hopping during the connection (a new port every few minutes)":"پورت‌هاپینگ وسط اتصال (هر چند دقیقه پورت تازه)",
 "Look like QUIC / HTTP3 on the wire":"شبیه QUIC / HTTP3 روی سیم","Several servers in one link, automatic switch when one is blocked":"چند سرور در یک لینک، تعویض خودکار وقتی یکی بسته شد",
 "Speed limit per user":"محدودیت سرعت برای هر کاربر",
 "Direct (the server's own address)":"مستقیم (آدرس خود سرور)","Through the tunnel (Iran server)":"از تانل (سرور ایران)",
 "Address":"آدرس","automatic":"خودکار","Route":"مسیر",
 "Direct: the app connects straight to the foreign server, lowest ping. Tunnel: the app connects to the Iran server; the tunnel to this server must forward this UDP port.":"مستقیم: اپ مستقیم به سرور خارج وصل می‌شود، کمترین پینگ. تانل: اپ به سرور ایران وصل می‌شود؛ تانل این سرور باید همین پورت UDP را فوروارد کند.",
 "address: a domain or an IP, like de.example.com":"آدرس: یک دامنه یا IP، مثل de.example.com","port":"پورت","the port must be 1-65535":"پورت باید ۱ تا ۶۵۵۳۵ باشد"})}

function p_kmix(){kmFA();
 $('#pg').innerHTML='<div class="ph"><div><h2>KANKI MIX</h2><p>'+t('Our own protocol on every VPN server: game packets go straight (no queue, sent twice in gaming mode), websites over KCP + FEC.')+'</p></div>'+
  '<div class="row" style="gap:6px"><button class="b2" onclick="kmAll(false)">'+t('Disable for all users')+'</button><button class="btn" onclick="kmAll(true)">'+ic('users',15)+' '+t('Enable for all users')+'</button></div></div><div id="km">'+t('Loading…')+'</div>';
 kmLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)))kmLoad(true)},8000)}
function kmLoad(quiet){return api('GET','/api/kmix').then(function(d){KM.d=d;if(S.page!='kmix')return d;
  if(quiet&&$('#km_srv')){$('#km_kv').innerHTML=kmKpis(d);$('#km_srv').innerHTML=kmServers(d);return d}kmDraw(d);return d}).catch(fail)}
function kmRun(x){return x.active===true}
function kmKpis(d){var s=d.settings,run=d.servers.filter(kmRun).length,on=d.servers.filter(function(x){return x.on}).length;
 return '<div><small>'+t('Status')+'</small><b style="color:'+(s.on?'var(--ok)':'var(--bad)')+'">'+(s.on?t('On'):t('Off'))+'</b></div>'+
  '<div><small>'+t('Users with KANKI MIX')+'</small><b>'+N(d.users)+' / '+N(d.users_total)+'</b></div>'+
  '<div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N(d.online)+'</b></div>'+
  '<div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(on)+'</b></div>'+
  '<div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(d.traffic_gb)+' GB</b></div>'}
function kmState(x){if(!x.on)return ['','Off on this server'];if(kmRun(x))return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
function kmServers(d){if(!d.servers.length)return '<p class="muted">—</p>';
 return d.servers.map(function(x){var st=kmState(x),port=x.port||x.want_port,old=x.on&&!x.installed&&x.online&&!x.error;
  return '<div class="vrow" style="flex-wrap:wrap;align-items:flex-start"><span class="dot '+(st[0]||'')+'" style="margin-top:6px"></span>'+
   '<div class="nm"><b>'+esc(x.name)+(x.main?' <span class="rotb">'+t('Main server')+'</span>':'')+'</b><small class="ltr">'+esc(x.endpoint||'?')+':'+esc(String(port))+(x.hop?' · +'+esc(x.hop):'')+(x.parity!=null?' · FEC 10+'+esc(String(x.parity)):'')+'</small></div>'+
   '<span class="chipx">'+N(x.users)+' '+t('users')+'</span><span class="chipx '+(st[0]||'')+'">'+t(st[1])+'</span>'+
   '<div class="row" style="gap:6px;width:100%;justify-content:flex-end;align-items:center"><small class="muted">'+t('Port of this server')+'</small>'+
   '<input class="ltr km_np" data-id="'+esc(x.id)+'" inputmode="numeric" style="width:96px" placeholder="'+esc(t('default'))+' '+N(d.settings.port)+'" value="'+esc(((d.settings.nodes||{})[x.id]||{}).port||'')+'">'+
   sw('',x.on,"kmNodeOn('"+esc(x.id)+"',this.checked)")+'</div>'+
   kmRouteRow(d,x)+
   (old?'<div class="warnbox" style="margin:6px 0 0;width:100%">'+t('Update the agent of this server (Servers › Update agent) to run KANKI MIX')+'</div>':'')+
   (x.on&&x.error?'<div class="warnbox ltr" style="margin:6px 0 0;width:100%">'+esc(x.error)+'</div>':'')+'</div>'}).join('')}
// direct (the foreign server's own address) or through the Iran tunnel, and an optional address of its own
function kmRouteRow(d,x){var o=(d.settings.nodes||{})[x.id]||{},tun=o.route=='tunnel',id=esc(x.id);
 return '<div class="row" style="gap:6px;width:100%;justify-content:flex-end;align-items:center;margin-top:6px"><small class="muted">'+t('Route')+'</small>'+
  '<select class="km_rt" data-id="'+id+'" onchange="kmSaveNodes()" style="width:auto">'+
   '<option value=""'+(tun?'':' selected')+'>'+t("Direct (the server's own address)")+' · '+esc(x.direct_host||'?')+'</option>'+
   '<option value="tunnel"'+(tun?' selected':'')+'>'+t('Through the tunnel (Iran server)')+' · '+esc(x.tunnel_host||'?')+'</option></select>'+
  '<input class="ltr km_host" data-id="'+id+'" style="width:170px" placeholder="'+esc(t('Address'))+': '+esc(t('automatic'))+'" value="'+esc(o.host||'')+'" onchange="kmSaveNodes()"></div>'}
function kmSaveNodes(){kmPut({nodes:kmNodes()})}
function kmDraw(d){var el=$('#km');if(!el)return;var s=d.settings;
 var par=[[0,'none'],[2,'light'],[3,'normal'],[5,'strong'],[8,'very strong']];
 el.innerHTML=(s.on?'':'<div class="warnbox">'+t('KANKI MIX is off: it runs on no server and is in no subscription.')+'</div>')+
  '<div class="kv k5" id="km_kv">'+kmKpis(d)+'</div>'+
  '<div class="g2"><div class="card"><div class="nh"><h3>'+ic('srv',16)+' '+t('Servers')+'</h3><a class="b2" href="#nodes">'+t('Servers')+'</a></div><div id="km_srv" style="margin-top:10px">'+kmServers(d)+'</div></div>'+
  '<div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
   '<div class="srow"><div class="tx"><b>'+t('KANKI MIX on')+'</b></div><label class="sw"><input type="checkbox" id="km_on" '+(s.on?'checked':'')+'><span></span></label></div>'+
   '<label class="f">'+t('Default UDP port')+'</label><input id="km_port" class="ltr" inputmode="numeric" value="'+esc(String(s.port))+'"><small class="muted">'+t('Every server uses it unless it has its own port below.')+'</small>'+
   '<label class="f">'+t('FEC for websites (TCP)')+'</label><select id="km_par">'+par.map(function(p){return '<option value="'+p[0]+'"'+(s.parity==p[0]?' selected':'')+'>'+t(p[1])+' · 10+'+p[0]+'</option>'}).join('')+
    (par.some(function(p){return p[0]==s.parity})?'':'<option value="'+s.parity+'" selected>10+'+s.parity+'</option>')+'</select><small class="muted">'+t('Extra bytes that rebuild lost packets without asking again. Games do not use it (they have gaming mode).')+'</small>'+
   '<div class="srow" style="margin-top:8px"><div class="tx"><b>'+t('Gaming mode on in the app by default')+'</b><small>'+t('Each game packet is sent twice: at 20% loss 92% arrive instead of 64%. Users can switch it off in the app.')+'</small></div><label class="sw"><input type="checkbox" id="km_gm" '+(s.gaming?'checked':'')+'><span></span></label></div>'+
   '<label class="f">'+t('Extra ports (port range)')+'</label><input id="km_hop" class="ltr" placeholder="4001-4010" value="'+esc(s.hop||'')+'"><small class="muted">'+t('Like 4001-4010. They all lead to the main port; the app picks one at random on every connect, so blocking one port is not enough. Empty = off.')+'</small>'+
   '<button class="btn" style="width:100%;margin-top:12px" id="km_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0 0 6px">'+t('1) Keep it on and pick the port (4000 is fine). 2) Tick KANKI MIX for users (or Enable for all users). 3) Every server installs it by itself within a minute; the Kanki app gets the kanki:// link from the subscription, users see no IP or key.')+'</p>'+
   '<p class="sub" style="margin:0">'+t('Each user has their own key (made from the subscription code): resetting the link gives a new key, disabling or expiring cuts the user off at once. Traffic and devices count like the other protocols.')+'</p>'+
   '<p class="sub" style="margin:6px 0 0">'+t('Direct: the app connects straight to the foreign server, lowest ping. Tunnel: the app connects to the Iran server; the tunnel to this server must forward this UDP port.')+'</p>'+
   '<label class="f">'+t('Coming next')+'</label><div class="chs" style="display:flex;gap:6px;flex-wrap:wrap">'+['Port hopping during the connection (a new port every few minutes)','Look like QUIC / HTTP3 on the wire','Several servers in one link, automatic switch when one is blocked','Speed limit per user'].map(function(x){return '<span class="chipx" style="opacity:.7">'+t(x)+'</span>'}).join('')+'</div></div>';
 $('#km_save').onclick=kmSave}
function kmNodes(){var d=KM.d,m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});
 $$('.km_np').forEach(function(i){var v=unN(i.value).trim(),o=m[i.dataset.id]||{};o.port=v?+v:0;m[i.dataset.id]=o});
 $$('.km_rt').forEach(function(i){var o=m[i.dataset.id]||{};o.route=i.value;m[i.dataset.id]=o});
 $$('.km_host').forEach(function(i){var o=m[i.dataset.id]||{};o.host=i.value.trim();m[i.dataset.id]=o});return m}
function kmPut(b,done){return api('PUT','/api/kmix',b).then(function(r){toast(t('Saved'));if(done)done(r);return kmLoad()}).catch(fail)}
function kmSave(){var p=unN($('#km_port').value).trim();if(!/^\d+$/.test(p)||+p<1||+p>65535)return toast(t('the port must be 1-65535'),1);
 kmPut({on:$('#km_on').checked,port:+p,parity:+$('#km_par').value,gaming:$('#km_gm').checked,hop:unN($('#km_hop').value).trim(),nodes:kmNodes()})}
function kmNodeOn(id,on){var m=kmNodes(),o=m[id]||{};o.off=!on;m[id]=o;kmPut({nodes:m})}
// from the node edit window: this server's own KANKI MIX port
function kmSetNodePort(id,port,done){var go=function(d){var m={};Object.keys(d.settings.nodes||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});var o=m[id]||{};o.port=+port||0;m[id]=o;kmPut({nodes:m},done)};
 if(!/^\d+$/.test(String(port))||+port<1||+port>65535)return toast(t('the port must be 1-65535'),1);
 api('GET','/api/kmix').then(function(d){KM.d=d;go(d)}).catch(fail)}
function kmAll(on){kmFA();if(!confirm(t(on?'KANKI MIX for every user?':'Remove KANKI MIX from every user?')))return;
 api('POST','/api/kmix/users',{on:on}).then(function(r){toast(t('Saved')+' · '+N(r.changed)+' '+t('users changed'));kmLoad()}).catch(fail)}
