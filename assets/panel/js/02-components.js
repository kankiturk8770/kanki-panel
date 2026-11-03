// ==================================================================== the parts every page is built from
// (CLAUDE.md, design rules): a page head, one row of tabs, a row of numbers, a group with one add button,
// an item row (status, flag, name, main action; tags under it; the address last), a switch with its words,
// and a sheet of the rarer actions behind "⋯" (deleting is last, apart from the rest).
function kuHead(icon,title,desc,acts){return '<header class="ku-head"><span class="ku-hi">'+ic(icon,22)+'</span><div class="ku-ht"><h2>'+title+'</h2>'+(desc?'<p>'+desc+'</p>':'')+'</div>'+(acts?'<div class="ku-ha">'+acts+'</div>':'')+'</header>'}
// tabs: [[key, label]]; cnt: {key: number}
function kuTabs(page,tabs,cur,cnt){cnt=cnt||{};return tabs.map(function(x){return '<a href="#'+page+'/'+x[0]+'" class="'+(cur==x[0]?'on':'')+'">'+t(x[1])+(cnt[x[0]]?'<em>'+N(cnt[x[0]])+'</em>':'')+'</a>'}).join('')}
// numbers: [[label, value, colour class g|y|r|'']]
function kuStats(items){return '<div class="ku-stats">'+items.map(function(x){return '<div><small>'+x[0]+'</small><b class="'+(x[2]?'c-'+x[2]:'')+'">'+x[1]+'</b></div>'}).join('')+'</div>'}
function kuGroup(title,count,add,body,id){return '<section class="ku-group"'+(id?' id="'+id+'"':'')+'><div class="ku-gh"><b>'+title+'</b>'+(count!=null?'<span class="ku-n">'+N(count)+'</span>':'')+'<span class="sp"></span>'+(add||'')+'</div><div class="ku-gb">'+body+'</div></section>'}
// a switch always has its words; the whole line is the switch
function kuSwitch(label,on,cb,sub){return '<label class="ku-sw"><span class="ku-swt"><b>'+label+'</b>'+(sub?'<small>'+sub+'</small>':'')+'</span><span class="sw"><input type="checkbox" '+(on?'checked':'')+' onchange="'+cb+'"><span></span></span></label>'}
// a line inside a group: words on one side, buttons on the other
function kuLine(words,btns){return '<div class="ku-line"><span class="ku-lt">'+words+'</span><span class="ku-lb">'+btns+'</span></div>'}
// an item row that does not open: dot, flag, name, tags (line 2), address (line 3), main action and ⋯.
// name, tags and addr are HTML: every caller passes user, server or inbound names through esc()
function kuItem(o){return '<div class="ku-item'+(o.off?' off':'')+'"'+(o.click?' role="button" tabindex="0" onclick="'+o.click+'"':'')+'>'+
  '<div class="ku-i1"><span class="dot '+(o.dot||'')+'"></span>'+(o.flag||'')+'<b class="ku-nm">'+o.name+'</b><span class="sp"></span>'+(o.act||'')+
  (o.menu?'<button type="button" class="ib ku-more" aria-label="'+esc(t('More'))+'" onclick="event.stopPropagation();'+o.menu+'">⋯</button>':'')+'</div>'+
  (o.tags?'<div class="ku-i2">'+o.tags+'</div>':'')+(o.addr?'<div class="ku-i3 ltr">'+o.addr+'</div>':'')+(o.extra||'')+'</div>'}
function kuTag(text,c){return '<span class="ku-tag'+(c?' '+c:'')+'">'+text+'</span>'}
// the rarer actions of one thing: [[label, js, 'danger']]; the dangerous ones come last, apart
function kuMenu(title,sub,items){var safe=items.filter(function(x){return x[2]!='danger'}),bad=items.filter(function(x){return x[2]=='danger'});
 var b=function(x){return '<button type="button" class="ku-mi'+(x[2]=='danger'?' danger':'')+'" onclick="closeModal();'+x[1]+'">'+x[0]+'</button>'};
 modal(mhead(title,sub)+'<div class="ku-menu">'+safe.map(b).join('')+(bad.length?'<div class="ku-msep"></div>'+bad.map(b).join(''):'')+'</div>')}
// The Tunnel tab of a core: one table of every server, its direct address and the Iran address of its second
// config; «Edit» opens the same fields in a small window and saves them with the same call as before.
// rows: [{cc, name, direct, tun, note, st:[class,text], edit:js}]; on a phone each row is a small card.
function kuTunTable(rows){if(!rows.length)return '<p class="muted ku-empty">'+t('No server yet')+'</p>';
 var th='<thead><tr><th>'+t('Server')+'</th><th>'+t('Direct address')+'</th><th>'+t('Tunnel address in Iran')+'</th><th>'+t('Status')+'</th><th></th></tr></thead>';
 return '<div class="ku-tt-wrap"><table class="ku-tt">'+th+'<tbody>'+rows.map(function(r){
  return '<tr><td class="nm">'+flagOf(r.cc)+'<b>'+esc(r.name)+'</b></td>'+
   '<td data-l="'+esc(t('Direct address'))+'"><span class="ltr">'+(r.direct?esc(r.direct):'—')+'</span></td>'+
   '<td data-l="'+esc(t('Tunnel address in Iran'))+'">'+(r.tun?'<span class="ltr">'+esc(r.tun)+'</span>':'<span class="muted">'+t('No second config')+'</span>')+(r.note?'<small class="muted">'+r.note+'</small>':'')+'</td>'+
   '<td data-l="'+esc(t('Status'))+'"><span class="kxr-st '+(r.st[0]||'')+'">'+esc(r.st[1])+'</span></td>'+
   '<td class="ed"><button type="button" class="b2 sm" onclick="'+r.edit+'">'+ic('edit',14)+' '+t('Edit')+'</button></td></tr>'}).join('')+'</tbody></table></div>'}
// the address users reach a server on directly
function srvDirect(s){var n=(s&&s.node)||{};return n.effective_endpoint||n.endpoint||(window.srvIp?srvIp(s):'')||''}
window.CTS={};
function coreTunRows(core,g,list){
 return kuTunTable(list.map(function(s){var tn=s.tunnel||{},own=(tn.cores||{})[core]||'',srv=tn.on?(tn.host||tn.uses||''):'',use=own||srv,x=(tn.ports||[]).filter(function(z){return z.core==core})[0];
  CTS[core+'|'+s.key]=s;
  return {cc:s.cc,name:s.name,direct:srvDirect(s),tun:use?use+(x?':'+x.via:''):'',note:use&&!own?t('the tunnel domain of the server'):'',
   st:use?['g',x?t('Through a tunnel'):t('On')]:['',t('Off')],edit:"coreTunEdit('"+core+"','"+esc(s.key)+"','"+g+"')"}}))}
// the old fields of one server's second config, in a window
window.coreTunEdit=function(core,key,g){var s=CTS[core+'|'+key];if(!s)return;window.CTG=g;
 modal(mhead(t('Second config through the tunnel'),s.name)+coreTun(core,s))}

