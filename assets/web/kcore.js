// Kanki Panel: the Game-FEC, HQ-QUIC and FakeTCP pages. Three VPN protocols of our own for the
// Kanki app, each a section of its own like KANKI MIX, ticked per user like any other protocol.
// They run on every VPN server on ports of their own (apart from the tunnels); the app gets a
// kcore:// link per protocol and server from the subscription.
var KC={d:{},meta:{
 kgame:{name:'Game-FEC',net:'UDP',desc:'For games (PUBG…): game packets go as datagrams of their own, small ones two or three times; websites and the lobby over KCP + FEC. Nothing on the wire looks like a protocol.'},
 khq:{name:'HQ-QUIC',net:'UDP',desc:'QUIC under a mask with BBR: fast on lossy internet, nothing on the wire looks like QUIC. Game packets go as QUIC datagrams.'},
 kftcp:{name:'FakeTCP',net:'TCP',desc:'UDP inside a fake TCP session, for networks that cut or slow UDP. Needs a rooted phone (raw packets).'}}};
function kcFA(){if(kcFA.done||typeof FA=='undefined')return;kcFA.done=1;Object.assign(FA,{
 "For games (PUBG…): game packets go as datagrams of their own, small ones two or three times; websites and the lobby over KCP + FEC. Nothing on the wire looks like a protocol.":"برای بازی (پابجی و …): بسته‌های بازی دیتاگرام جدا می‌روند و بسته‌های کوچک دو یا سه بار؛ سایت‌ها و لابی روی KCP + FEC. روی سیم شبیه هیچ پروتکلی نیست.",
 "QUIC under a mask with BBR: fast on lossy internet, nothing on the wire looks like QUIC. Game packets go as QUIC datagrams.":"QUIC زیر ماسک با BBR: روی اینترنت پرلاس سریع، روی سیم شبیه QUIC نیست. بسته‌های بازی دیتاگرام QUIC می‌روند.",
 "UDP inside a fake TCP session, for networks that cut or slow UDP. Needs a rooted phone (raw packets).":"UDP داخل یک نشست TCP ساختگی، برای شبکه‌هایی که UDP را می‌بندند یا کند می‌کنند. گوشی روت‌شده لازم دارد (بسته‌ی خام).",
 "is off: it runs on no server and is in no subscription.":"خاموش است: روی هیچ سروری اجرا نمی‌شود و در هیچ اشتراکی نیست.",
 "Users with it":"کاربران این پروتکل","Running servers":"سرورهای فعال","Online now":"آنلاین الان","Total traffic":"ترافیک کل",
 "Default port":"پورت پیش‌فرض","Every server uses it unless it has its own port below.":"همه‌ی سرورها همین را دارند، مگر سروری که پایین پورت خودش را دارد.",
 "Copies of each game packet":"تعداد نسخه‌ی هر بسته‌ی بازی",
 "Only packets up to 400 bytes (PUBG: 40-300 bytes) are copied; downloads are sent once. Through 15% loss each way: 1 copy 72%, 2 copies 96%, 3 copies 99.8% of round trips arrive.":"فقط بسته‌های تا ۴۰۰ بایت (پابجی: ۴۰ تا ۳۰۰ بایت) چندتایی می‌روند؛ دانلودها یک بار. با ۱۵٪ لاس در هر طرف: ۱ نسخه ۷۲٪، ۲ نسخه ۹۶٪، ۳ نسخه ۹۹٫۸٪ رفت‌وبرگشت‌ها می‌رسند.",
 "1 (no copies)":"۱ (بدون نسخه‌ی اضافه)","2 (recommended)":"۲ (پیشنهادی)","3 (very lossy internet)":"۳ (اینترنت خیلی پرلاس)",
 "FEC of the stream (websites, game lobby)":"FEC جریان (سایت‌ها، لابی بازی)","off":"خاموش","TLS name":"نام TLS",
 "Port of this server":"پورت این سرور","default":"پیش‌فرض","Address the app dials":"آدرسی که اپ وصل می‌شود","automatic":"خودکار",
 "Off on this server":"روی این سرور خاموش","Running":"در حال اجرا","Not running":"اجرا نمی‌شود","Waiting for the server…":"منتظر سرور…",
 "Update the agent of this server to run it":"عامل این سرور را به‌روز کن تا اجرا شود",
 "Enable for all users":"روشن برای همه‌ی کاربران","Disable for all users":"خاموش برای همه‌ی کاربران","for every user?":"برای همه‌ی کاربران روشن شود؟","Remove from every user?":"از همه‌ی کاربران برداشته شود؟","users changed":"کاربر تغییر کرد",
 "How it works":"چطور کار می‌کند",
 "Tick it for a user (user form, or Enable for all users). Every server runs it by itself within a minute; the Kanki app gets the link from the subscription. Each user has their own key: a new link is a new key, an expired or disabled user is cut off at once. Open the port at the data center's firewall too.":"برای کاربر تیکش را بزن (فرم کاربر، یا «روشن برای همه‌ی کاربران»). هر سرور ظرف یک دقیقه خودش اجرایش می‌کند؛ اپ کانکی لینک را از اشتراک می‌گیرد. هر کاربر کلید خودش را دارد: لینک تازه یعنی کلید تازه، کاربر منقضی یا غیرفعال فوراً قطع می‌شود. پورت را در فایروال دیتاسنتر هم باز کن.",
 "the port must be 1-65535":"پورت باید ۱ تا ۶۵۵۳۵ باشد","Save":"ذخیره","Saved":"ذخیره شد","Servers":"سرورها","Settings":"تنظیمات","users":"کاربر","Main server":"سرور اصلی","Status":"وضعیت","On":"روشن","Off":"خاموش"})}

function kcPage(p){kcFA();var m=KC.meta[p];
 $('#pg').innerHTML='<div class="ph"><div><h2>'+esc(m.name)+'</h2><p>'+t(m.desc)+'</p></div>'+
  '<div class="row" style="gap:6px"><button class="b2" onclick="kcAll(\''+p+'\',false)">'+t('Disable for all users')+'</button><button class="btn" onclick="kcAll(\''+p+'\',true)">'+ic('users',15)+' '+t('Enable for all users')+'</button></div></div><div id="kc">'+t('Loading…')+'</div>';
 kcLoad(p);clearInterval(S.timer);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible'&&!(document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)))kcLoad(p,true)},8000)}
function p_kgame(){kcPage('kgame')}
function p_khq(){kcPage('khq')}
function p_kftcp(){kcPage('kftcp')}
function kcLoad(p,quiet){return api('GET','/api/kc/'+p).then(function(d){KC.d[p]=d;if(S.page!=p)return d;
  if(quiet&&$('#kc_srv')){$('#kc_kv').innerHTML=kcKpis(d);$('#kc_srv').innerHTML=kcServers(d);return d}kcDraw(d);return d}).catch(fail)}
function kcKpis(d){var s=d.settings,run=d.servers.filter(function(x){return x.port}).length,on=d.servers.filter(function(x){return x.on}).length;
 return '<div><small>'+t('Status')+'</small><b style="color:'+(s.on?'var(--ok)':'var(--bad)')+'">'+(s.on?t('On'):t('Off'))+'</b></div>'+
  '<div><small>'+t('Users with it')+'</small><b>'+N(d.users)+' / '+N(d.users_total)+'</b></div>'+
  '<div><small>'+t('Online now')+'</small><b style="color:var(--ok)">'+N(d.online)+'</b></div>'+
  '<div><small>'+t('Running servers')+'</small><b>'+N(run)+' / '+N(on)+'</b></div>'+
  '<div><small>'+t('Total traffic')+'</small><b class="ltr">'+N(d.traffic_gb)+' GB</b></div>'}
function kcState(x){if(!x.on)return ['','Off on this server'];if(x.port)return ['g','Running'];if(x.error)return ['r','Not running'];return ['y','Waiting for the server…']}
function kcServers(d){if(!d.servers.length)return '<p class="muted">—</p>';var p=d.proto,net=KC.meta[p].net;
 return d.servers.map(function(x){var st=kcState(x),id=esc(x.id),o=(d.settings.nodes||{})[x.id]||{};
  return '<div class="vrow" style="flex-wrap:wrap;align-items:flex-start"><span class="dot '+(st[0]||'')+'" style="margin-top:6px"></span>'+
   '<div class="nm"><b>'+esc(x.name)+(x.main?' <span class="rotb">'+t('Main server')+'</span>':'')+'</b><small class="ltr">'+esc(x.host||'?')+':'+esc(String(x.port||x.want_port))+' · '+net+'</small></div>'+
   '<span class="chipx">'+N(x.users)+' '+t('users')+'</span><span class="chipx '+(st[0]||'')+'">'+t(st[1])+'</span>'+
   '<div class="row" style="gap:6px;width:100%;justify-content:flex-end;align-items:center;flex-wrap:wrap"><small class="muted">'+t('Port of this server')+'</small>'+
   '<input class="ltr kc_np" data-id="'+id+'" inputmode="numeric" style="width:90px" placeholder="'+esc(t('default'))+' '+N(d.settings.port)+'" value="'+esc(o.port||'')+'" onchange="kcSaveNodes(\''+p+'\')">'+
   '<small class="muted">'+t('Address the app dials')+'</small><input class="ltr kc_host" data-id="'+id+'" style="width:160px" placeholder="'+esc(t('automatic'))+'" value="'+esc(o.host||'')+'" onchange="kcSaveNodes(\''+p+'\')">'+
   sw('',x.on,"kcNodeOn('"+p+"','"+id+"',this.checked)")+'</div>'+
   (x.on&&x.online&&!x.reports&&d.settings.on?'<div class="warnbox" style="margin:6px 0 0;width:100%">'+t('Update the agent of this server to run it')+'</div>':'')+
   (x.on&&x.error?'<div class="warnbox ltr" style="margin:6px 0 0;width:100%">'+esc(x.error)+'</div>':'')+'</div>'}).join('')}
function kcDraw(d){var el=$('#kc');if(!el)return;var s=d.settings,p=d.proto,m=KC.meta[p];
 var fecs=['off','10:2','8:3','6:3','4:2'];if(fecs.indexOf(s.fec)<0)fecs.push(s.fec);
 var copies='<label class="f">'+t('Copies of each game packet')+'</label><select id="kc_cp">'+[[1,'1 (no copies)'],[2,'2 (recommended)'],[3,'3 (very lossy internet)']].map(function(c){return '<option value="'+c[0]+'"'+(s.copies==c[0]?' selected':'')+'>'+t(c[1])+'</option>'}).join('')+'</select>'+
  '<small class="muted">'+t('Only packets up to 400 bytes (PUBG: 40-300 bytes) are copied; downloads are sent once. Through 15% loss each way: 1 copy 72%, 2 copies 96%, 3 copies 99.8% of round trips arrive.')+'</small>';
 el.innerHTML=(s.on?'':'<div class="warnbox">'+esc(m.name)+' '+t('is off: it runs on no server and is in no subscription.')+'</div>')+
  '<div class="kv k5" id="kc_kv">'+kcKpis(d)+'</div>'+
  '<div class="g2"><div class="card"><div class="nh"><h3>'+ic('srv',16)+' '+t('Servers')+'</h3><a class="b2" href="#nodes">'+t('Servers')+'</a></div><div id="kc_srv" style="margin-top:10px">'+kcServers(d)+'</div></div>'+
  '<div class="card"><h3>'+ic('settings',16)+' '+t('Settings')+'</h3>'+
   '<div class="srow"><div class="tx"><b>'+esc(m.name)+'</b></div><label class="sw"><input type="checkbox" id="kc_on" '+(s.on?'checked':'')+'><span></span></label></div>'+
   '<label class="f">'+t('Default port')+' · '+m.net+'</label><input id="kc_port" class="ltr" inputmode="numeric" value="'+esc(String(s.port))+'"><small class="muted">'+t('Every server uses it unless it has its own port below.')+'</small>'+
   (p=='kgame'?copies+'<label class="f">'+t('FEC of the stream (websites, game lobby)')+'</label><select id="kc_fec">'+fecs.map(function(f){return '<option value="'+esc(f)+'"'+(s.fec==f?' selected':'')+'>'+esc(f=='off'?t('off'):f)+'</option>'}).join('')+'</select>':'')+
   (p=='khq'?'<label class="f">'+t('TLS name')+'</label><input id="kc_sni" class="ltr" placeholder="www.cloudflare.com" value="'+esc(s.sni||'')+'">':'')+
   '<button class="btn" style="width:100%;margin-top:12px" id="kc_save">'+t('Save')+'</button></div></div>'+
  '<div class="card"><h3>'+t('How it works')+'</h3><p class="sub" style="margin:0">'+t('Tick it for a user (user form, or Enable for all users). Every server runs it by itself within a minute; the Kanki app gets the link from the subscription. Each user has their own key: a new link is a new key, an expired or disabled user is cut off at once. Open the port at the data center\'s firewall too.')+'</p></div>';
 $('#kc_save').onclick=function(){kcSave(p)}}
function kcNodes(p){var d=KC.d[p],m={};Object.keys((d&&d.settings.nodes)||{}).forEach(function(k){m[k]=Object.assign({},d.settings.nodes[k])});
 $$('.kc_np').forEach(function(i){var v=unN(i.value).trim(),o=m[i.dataset.id]||{};o.port=v?+v:0;m[i.dataset.id]=o});
 $$('.kc_host').forEach(function(i){var o=m[i.dataset.id]||{};o.host=i.value.trim();m[i.dataset.id]=o});return m}
function kcPut(p,b){return api('PUT','/api/kc/'+p,b).then(function(){toast(t('Saved'));return kcLoad(p)}).catch(fail)}
function kcSaveNodes(p){kcPut(p,{nodes:kcNodes(p)})}
function kcNodeOn(p,id,on){var m=kcNodes(p),o=m[id]||{};o.off=!on;m[id]=o;kcPut(p,{nodes:m})}
function kcSave(p){var v=unN($('#kc_port').value).trim();if(!/^\d+$/.test(v)||+v<1||+v>65535)return toast(t('the port must be 1-65535'),1);
 var b={on:$('#kc_on').checked,port:+v,nodes:kcNodes(p)};
 if($('#kc_cp'))b.copies=+$('#kc_cp').value;if($('#kc_fec'))b.fec=$('#kc_fec').value;if($('#kc_sni'))b.sni=$('#kc_sni').value.trim();kcPut(p,b)}
function kcAll(p,on){kcFA();var n=KC.meta[p].name;if(!confirm(on?n+' '+t('for every user?'):n+': '+t('Remove from every user?')))return;
 api('POST','/api/kc/'+p+'/users',{on:on}).then(function(r){toast(t('Saved')+' · '+N(r.changed)+' '+t('users changed'));kcLoad(p)}).catch(fail)}
