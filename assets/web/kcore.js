// Kanki Panel: the Kanki Cores page. Three tunnel transports served to users as VPN cores for the
// Kanki app: Game-FEC (KCP + FEC, game packets as datagrams sent 2-3 times), HQ-QUIC (QUIC under a
// mask) and FakeTCP (UDP inside a fake TCP session). Each server runs them inside its agent; the
// app gets one kcore:// link per core and server from the subscription.
var KC={d:null};
function kcFA(){if(kcFA.done||typeof FA=='undefined')return;kcFA.done=1;Object.assign(FA,{
 "Kanki Cores":"هسته‌های کانکی",
 "Game-FEC, HQ-QUIC and FakeTCP from the tunnels, as VPN cores for the Kanki app. Game packets go as their own datagrams, small ones two or three times.":"گیم-FEC، HQ-QUIC و FakeTCP از تانل‌ها، به‌صورت هسته‌ی VPN برای اپ کانکی. بسته‌های بازی دیتاگرام جدا می‌روند و بسته‌های کوچک دو یا سه بار.",
 "Kanki Cores are off: they run on no server and are in no subscription.":"هسته‌های کانکی خاموش‌اند: روی هیچ سروری اجرا نمی‌شوند و در هیچ اشتراکی نیستند.",
 "Kanki Cores on":"هسته‌های کانکی روشن","Users with the cores":"کاربران هسته‌ها","Running servers":"سرورهای فعال","Online now":"آنلاین الان",
 "Port (0 = off)":"پورت (۰ = خاموش)","FEC of the stream (websites, game lobby)":"FEC جریان (سایت‌ها، لابی بازی)",
 "Copies of each game packet":"تعداد نسخه‌ی هر بسته‌ی بازی",
 "Only packets up to 400 bytes (PUBG, Free Fire, CoD: 40-300 bytes) are copied; downloads are sent once. Through 15% loss each way: 1 copy 72%, 2 copies 96%, 3 copies 99.8% of round trips arrive.":"فقط بسته‌های تا ۴۰۰ بایت (پابجی، فری‌فایر، کالاف: ۴۰ تا ۳۰۰ بایت) چندتایی می‌روند؛ دانلودها یک بار. با ۱۵٪ لاس در هر طرف: ۱ نسخه ۷۲٪، ۲ نسخه ۹۶٪، ۳ نسخه ۹۹٫۸٪ رفت‌وبرگشت‌ها می‌رسند.",
 "TLS name of HQ-QUIC":"نام TLS برای HQ-QUIC","FakeTCP needs a phone with root: on other phones the app uses Game-FEC or HQ-QUIC.":"FakeTCP روی گوشی بدون روت کار نمی‌کند: اپ روی بقیه‌ی گوشی‌ها از گیم-FEC یا HQ-QUIC استفاده می‌کند.",
 "Address the app dials":"آدرسی که اپ وصل می‌شود","automatic":"خودکار","Off on this server":"روی این سرور خاموش","Running":"در حال اجرا","Not running":"اجرا نمی‌شود",
 "Waiting for the server…":"منتظر سرور…","Update the agent of this server to run the cores":"عامل این سرور را به‌روز کن تا هسته‌ها اجرا شوند",
 "every core needs its own port":"هر هسته پورت جدا لازم دارد","the port must be 1-65535 (0 = off)":"پورت باید ۱ تا ۶۵۵۳۵ باشد (۰ = خاموش)",
 "1 (no copies)":"۱ (بدون نسخه‌ی اضافه)","2 (recommended)":"۲ (پیشنهادی)","3 (very lossy internet)":"۳ (اینترنت خیلی پرلاس)",
 "Who gets them":"چه کسانی می‌گیرند","Users with KANKI MIX or Kanki Cores ticked. Each has their own key (from the subscription code): a new link is a new key, an expired or disabled user is cut off at once.":"کاربرانی که KANKI MIX یا هسته‌های کانکی برایشان تیک خورده. هر کاربر کلید خودش را دارد (از کد اشتراک): لینک تازه یعنی کلید تازه، کاربر منقضی یا غیرفعال فوراً قطع می‌شود.",
 "Open these ports on the server's firewall at the data center too (UDP for Game-FEC and HQ-QUIC, TCP for FakeTCP).":"این پورت‌ها را در فایروال دیتاسنتر هم باز کن (UDP برای گیم-FEC و HQ-QUIC، TCP برای FakeTCP).",
 "off":"خاموش","Save":"ذخیره","Saved":"ذخیره شد","Servers":"سرورها","Settings":"تنظیمات","users":"کاربر","Main server":"سرور اصلی","Status":"وضعیت","On":"روشن","Off":"خاموش"})}

function p_kcore(){kcFA();
 $('#pg').innerHTML='<div class="ph"><div><h2>'+t('Kanki Cores')+'</h2><p>'+t('Game-FEC, HQ-QUIC and FakeTCP from the tunnels, as VPN cores for the Kanki app. Game packets go as their own datagrams, small ones two or three times.')+'</p></div></div><div id="kc">'+t('Loading…')+'</div>';
 kcLoad();clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)))kcLoad(true)},8000)}
function kcLoad(quiet){return api('GET','/api/kcore').then(function(d){KC.d=d;if(S.page!='kcore')return d;
  if(quiet&&$('#kc_srv')){$('#kc_kv').innerHTML=kcKpis(d);$('#kc_srv').innerHTML=kcServers(d);return d}kcDraw(d);return d}).catch(fail)}
function kcRunning(x){return x.ports&&Object.keys(x.ports).length>0}
function kcKpis(d){var s=d.settings,on=d.servers.filter(function(x){return x.on}).length;
 return '<div><small>'+t('Status')+'</small><b style="color:'+(s.on?'var(--ok)':'var(--bad)')+'">'+(s.on?t('On'):t('Off'))+'</b></div>'+
  '<div><small>'+t('Users with the cores')+'</small><b>'+N(d.users)+' / '+N(d.users_total)+'</b></div>'+
  '<div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N(d.online)+'</b></div>'+
  '<div><small>'+t('Running servers')+'</small><b>'+N(d.servers.filter(kcRunning).length)+' / '+N(on)+'</b></div>'}
function kcState(x){if(!x.on)return ['','Off on this server'];if(kcRunning(x))return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
function kcServers(d){if(!d.servers.length)return '<p class="muted">—</p>';
 return d.servers.map(function(x){var st=kcState(x),id=esc(x.id),o=x.opt||{};
  var chips=(d.kinds||[]).map(function(k){var p=x.ports&&x.ports[k.kind];return p?'<span class="chipx g ltr">'+esc(k.title)+' :'+N(p)+'</span>':''}).join('');
  return '<div class="vrow" style="flex-wrap:wrap;align-items:flex-start"><span class="dot '+(st[0]||'')+'" style="margin-top:6px"></span>'+
   '<div class="nm"><b>'+esc(x.name)+(x.main?' <span class="rotb">'+t('Main server')+'</span>':'')+'</b><small class="ltr">'+esc(x.host||'?')+'</small></div>'+
   '<span class="chipx">'+N(x.users)+' '+t('users')+'</span><span class="chipx '+(st[0]||'')+'">'+t(st[1])+'</span>'+
   '<div class="row" style="gap:6px;width:100%;flex-wrap:wrap">'+chips+'</div>'+
   '<div class="row" style="gap:6px;width:100%;justify-content:flex-end;align-items:center"><small class="muted">'+t('Address the app dials')+'</small>'+
   '<input class="ltr kc_host" data-id="'+id+'" style="width:170px" placeholder="'+esc(t('automatic'))+'" value="'+esc(o.host||'')+'" onchange="kcSaveNodes()">'+
   sw('',x.on,"kcNodeOn('"+id+"',this.checked)")+'</div>'+
   (x.on&&x.online&&!kcRunning(x)&&!x.error&&d.settings.on?'<div class="warnbox" style="margin:6px 0 0;width:100%">'+t('Update the agent of this server to run the cores')+'</div>':'')+
   (x.on&&x.error?'<div class="warnbox ltr" style="margin:6px 0 0;width:100%">'+esc(x.error)+'</div>':'')+'</div>'}).join('')}
function kcDraw(d){var el=$('#kc');if(!el)return;var s=d.settings;
 var fecs=[['off','off'],['10:2','10:2'],['8:3','8:3'],['6:3','6:3'],['4:2','4:2']];
 if(!fecs.some(function(f){return f[0]==s.fec}))fecs.push([s.fec,s.fec]);
 el.innerHTML=(s.on?'':'<div class="warnbox">'+t('Kanki Cores are off: they run on no server and are in no subscription.')+'</div>')+
  '<div class="kv k4" id="kc_kv">'+kcKpis(d)+'</div>'+
  '<div class="g2"><div class="card"><div class="nh"><h3>'+ic('srv',16)+' '+t('Servers')+'</h3><a class="b2" href="#nodes">'+t('Servers')+'</a></div><div id="kc_srv" style="margin-top:10px">'+kcServers(d)+'</div></div>'+
  '<div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
   '<div class="srow"><div class="tx"><b>'+t('Kanki Cores on')+'</b></div><label class="sw"><input type="checkbox" id="kc_on" '+(s.on?'checked':'')+'><span></span></label></div>'+
   (d.kinds||[]).map(function(k){return '<label class="f">'+esc(k.title)+' · '+t('Port (0 = off)')+(k.kind=='faketcp'?' · TCP':' · UDP')+'</label><input class="ltr kc_port" data-k="'+esc(k.kind)+'" inputmode="numeric" value="'+esc(String((s.ports||{})[k.kind]||0))+'">'}).join('')+
   '<small class="muted">'+t('FakeTCP needs a phone with root: on other phones the app uses Game-FEC or HQ-QUIC.')+' '+t("Open these ports on the server's firewall at the data center too (UDP for Game-FEC and HQ-QUIC, TCP for FakeTCP).")+'</small>'+
   '<label class="f">'+t('Copies of each game packet')+'</label><select id="kc_cp">'+[[1,'1 (no copies)'],[2,'2 (recommended)'],[3,'3 (very lossy internet)']].map(function(c){return '<option value="'+c[0]+'"'+(s.copies==c[0]?' selected':'')+'>'+t(c[1])+'</option>'}).join('')+'</select>'+
   '<small class="muted">'+t('Only packets up to 400 bytes (PUBG, Free Fire, CoD: 40-300 bytes) are copied; downloads are sent once. Through 15% loss each way: 1 copy 72%, 2 copies 96%, 3 copies 99.8% of round trips arrive.')+'</small>'+
   '<label class="f">'+t('FEC of the stream (websites, game lobby)')+'</label><select id="kc_fec">'+fecs.map(function(f){return '<option value="'+esc(f[0])+'"'+(s.fec==f[0]?' selected':'')+'>'+esc(f[0]=='off'?t('off'):f[1])+'</option>'}).join('')+'</select>'+
   '<label class="f">'+t('TLS name of HQ-QUIC')+'</label><input id="kc_sni" class="ltr" placeholder="www.cloudflare.com" value="'+esc(s.sni||'')+'">'+
   '<button class="btn" style="width:100%;margin-top:12px" id="kc_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><h3>'+t('Who gets them')+'</h3><p class="sub" style="margin:0">'+t('Users with KANKI MIX or Kanki Cores ticked. Each has their own key (from the subscription code): a new link is a new key, an expired or disabled user is cut off at once.')+'</p></div>';
 $('#kc_save').onclick=kcSave}
function kcNodes(){var d=KC.d,m={};((d&&d.servers)||[]).forEach(function(x){if(x.opt&&(x.opt.off||x.opt.host))m[x.id]=Object.assign({},x.opt)});
 $$('.kc_host').forEach(function(i){var o=m[i.dataset.id]||{};o.host=i.value.trim();m[i.dataset.id]=o});return m}
function kcPut(b){return api('PUT','/api/kcore',b).then(function(){toast(t('Saved'));return kcLoad()}).catch(fail)}
function kcSaveNodes(){kcPut({nodes:kcNodes()})}
function kcNodeOn(id,on){var m=kcNodes(),o=m[id]||{};o.off=!on;m[id]=o;kcPut({nodes:m})}
function kcSave(){var ports={},bad=false,seen={};
 $$('.kc_port').forEach(function(i){var v=unN(i.value).trim()||'0';if(!/^\d+$/.test(v)||+v>65535)bad=true;else{if(+v&&seen[v])bad='dup';seen[v]=1;ports[i.dataset.k]=+v}});
 if(bad)return toast(t(bad=='dup'?'every core needs its own port':'the port must be 1-65535 (0 = off)'),1);
 kcPut({on:$('#kc_on').checked,ports:ports,copies:+$('#kc_cp').value,fec:$('#kc_fec').value,sni:$('#kc_sni').value.trim(),nodes:kcNodes()})}
