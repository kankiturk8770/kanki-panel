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
// the Tunnel tab of a core: one row per server with the Iran address its second config goes through;
// a tap opens the address picker of that core on that server (coreTun)
function coreTunRows(core,g,list){if(!list.length)return '<p class="muted ku-empty">'+t('No server yet')+'</p>';
 return list.map(function(s){var tn=s.tunnel||{},own=(tn.cores||{})[core]||'',srv=tn.on?(tn.host||tn.uses||''):'',use=own||srv,x=(tn.ports||[]).filter(function(z){return z.core==core})[0];
  var head='<span class="dot '+(use?'g':'')+'"></span>'+flagOf(s.cc)+'<b>'+esc(s.name)+'</b><span class="sp"></span>'+
   (use?'<span class="kxr-st g ltr">'+esc(use)+(x?':'+x.via:'')+'</span>'+(own?'':'<small>'+t('the tunnel domain of the server')+'</small>'):'<span class="kxr-st">'+t('No second config')+'</span>');
  return accRow(g,s.key,head,function(){return coreTun(core,s)})}).join('')}

