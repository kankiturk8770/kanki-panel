var S={lang:localStorage.getItem('kk_lang')||'fa',theme:localStorage.getItem('kk_theme')||'dark',color:localStorage.getItem('kk_color')||'gold',token:localStorage.getItem('kk_tok')||'',me:null,page:'dash',users:[],nodes:[],ov:null,sel:{},q:'',filter:'all',pf:'all',sort:'new',size:12,pg:1,timer:null,timer2:null};
// a server is one word everywhere: nodes and tunnel servers are the same servers
var WFA=[[/سرورهای تانل/g,'سرورها'],[/سرور تانل/g,'سرور'],[/Nodeها/g,'سرورها'],[/نودهای/g,'سرورهای'],[/نودها/g,'سرورها'],[/نودی/g,'سروری'],[/نود/g,'سرور']],
 WEN=[[/\bTunnel servers\b/g,'Servers'],[/\btunnel servers\b/g,'servers'],[/\bTunnel server\b/g,'Server'],[/\btunnel server\b/g,'server'],[/\bNodes\b/g,'Servers'],[/\bnodes\b/g,'servers'],[/\bNode\b/g,'Server'],[/\bnode\b/g,'server']];
function t(k){var s=S.lang=='fa'&&FA[k]?FA[k]:k;if(typeof s!='string')return s;(S.lang=='fa'?WFA:WEN).forEach(function(r){s=s.replace(r[0],r[1])});return s}
function $(s,r){return (r||document).querySelector(s)}
// ---------------------------------------------------------------- calm refreshes
// The pages redraw their lists every few seconds. Swapping in new HTML rebuilt every element: an open
// drawer jumped back to its top, rows lost their scroll, entrance animations ran again and the page
// blinked. Inside a page, new HTML is now laid over what is there: an element that stays is kept and
// only what changed is touched. (A whole new page, a dialog or an emptied box is still built afresh.)
(function(){
var D=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');if(!D||!D.set)return;
// what the look layers add after a draw (drawer header, chips, pencils, edges …): left where it is
var DECO=/(^|\s)(k310dh|kd-crail|kd-pen|kd-edge|k310ki|k310sub|k38qa|k310strip|k310dash|k310res|k310orb|k310brand|kd-lay)(\s|$)/;
function deco(n){return n.nodeType==1&&DECO.test(n.getAttribute('class')||'')}
function key(n){return n.nodeType==1?(n.id||'')+'|'+(n.getAttribute('data-key')||'')+'|'+(n.getAttribute('data-acc')||''):''}
function same(a,b){return a.nodeType==b.nodeType&&a.nodeName==b.nodeName&&key(a)==key(b)}
function attrs(o,n){var i,a;
 for(i=o.attributes.length-1;i>=0;i--){a=o.attributes[i].name;if(!n.hasAttribute(a)&&!(o.nodeName=='CANVAS'&&(a=='width'||a=='height')))o.removeAttribute(a)}
 for(i=0;i<n.attributes.length;i++){a=n.attributes[i];if(o.getAttribute(a.name)!==a.value)o.setAttribute(a.name,a.value)}}
function node(o,n){if(o.nodeType!=1){if(o.nodeValue!==n.nodeValue)o.nodeValue=n.nodeValue;return}
 attrs(o,n);if(o.nodeName=='CANVAS'||o.nodeName=='TEXTAREA'&&o===document.activeElement)return;kids(o,n)}
function kids(o,n){var nk=Array.prototype.slice.call(n.childNodes),i=0;
 nk.forEach(function(c){while(o.childNodes[i]&&deco(o.childNodes[i]))i++;var cur=o.childNodes[i],m=null;
  if(cur&&same(cur,c))m=cur;
  else if(c.nodeType==1&&key(c)!='||')for(var j=i+1;j<o.childNodes.length;j++)if(same(o.childNodes[j],c)){m=o.childNodes[j];break}
  if(m){if(m!==cur)o.insertBefore(m,cur||null);node(m,c)}else o.insertBefore(c,cur||null);i=Array.prototype.indexOf.call(o.childNodes,m||c)+1});
 for(var k=o.childNodes.length-1;k>=i;k--){var x=o.childNodes[k];if(!deco(x))o.removeChild(x)}}
function calm(el){var pg=document.getElementById('pg');
 return pg&&el!==pg&&el.isConnected&&el.firstChild&&pg.contains(el)&&!el.closest('#modal,.msheet')}
Object.defineProperty(Element.prototype,'innerHTML',{configurable:true,enumerable:D.enumerable,get:D.get,set:function(h){
 if(h===''||h==null||this.namespaceURI!='http://www.w3.org/1999/xhtml'||!calm(this))return D.set.call(this,h);
 var tp=document.createElement('template');D.set.call(tp,h);kids(this,tp.content)}});
})();
function $$(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function toast(m,e){var x=$('#toast');x.textContent=m;x.className=e?'e':'';x.style.display='block';clearTimeout(x._t);x._t=setTimeout(function(){x.style.display='none'},2600)}
// a delete that leaves work on servers shows its progress (kdFollowRemoval)
var DELRX=/^\/api\/(tunnels\/servers\/[^/?]+|tunnels\/(?!servers|probe|cdntest)[^/?]+|servers\/[^/?]+|nodes\/[^/?]+|xray\/servers\/[^/?]+|dns\/servers\/[^/?]+)(\?.*)?$/;
function api(m,p,b,raw){var u=p;
 // a tunnel server is made in Servers
 if(m=='POST'&&p=='/api/tunnels/servers'&&b&&!b.gre_ip&&!b.addr){p='/api/servers';b={name:b.name,loc:b.loc||'abroad',vpn:b.loc!='iran'};raw=undefined}
 var o={method:m,headers:{}};if(S.token)o.headers.Authorization='Bearer '+S.token;
 if(b!==undefined&&!(b instanceof Blob)&&!(b instanceof ArrayBuffer)){o.headers['Content-Type']='application/json';o.body=JSON.stringify(b)}else if(b!==undefined)o.body=b;
 if(raw&&raw.headers)for(var k in raw.headers)o.headers[k]=raw.headers[k];
 var pr=fetch(p,o).then(function(r){if(r.status==401&&p!='/api/login'){logout(true);throw new Error('unauthorized')}
  if(raw&&raw.blob)return r.ok?r.blob().then(function(bl){return{blob:bl,name:((r.headers.get('content-disposition')||'').match(/filename="([^"]+)"/)||[])[1]}}):r.json().then(function(j){throw new Error(j.error||r.status)});
  return r.text().then(function(x){var j;try{j=x?JSON.parse(x):{}}catch(e){j={error:x}}if(!r.ok){var er=new Error(j.error||('HTTP '+r.status));er.data=j;throw er}return j})});
 if(m=='DELETE'&&DELRX.test(u||''))pr.then(function(r){if(r&&r.removal)kdFollowRemoval(r.removal)},function(){});
 pr.then(function(){netNote(false)},function(e){if(isNetErr(e))netNote(true)});
 return pr}
// «weak connection»: a request did not reach the panel; the page keeps what it shows and the note goes
// with the next answer
function isNetErr(e){return e instanceof TypeError&&/fetch|network|load failed/i.test(e.message)}
function netNote(on){var el=document.getElementById('netnote');if(!on){if(el)el.remove();return}
 if(el)return;el=document.createElement('div');el.id='netnote';el.setAttribute('role','status');el.textContent=t('Weak connection to the panel: showing the last data, trying again…');document.body.appendChild(el)}
function fail(e){if(!e||e.message=='unauthorized')return;
 // a request that did not reach the panel: the «weak connection» note says it once, not a toast per request
 if(isNetErr(e)){netNote(true);return}
 // a page drawn after the admin already left it: nothing to tell
 if(e instanceof TypeError&&/of (null|undefined)/.test(e.message)){console.warn(e);return}
 toast(t(e.message||String(e)),1)}
function copy(s){if(navigator.clipboard&&window.isSecureContext)navigator.clipboard.writeText(s).then(function(){toast(t('Copied'))});else{var a=document.createElement('textarea');a.value=s;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();toast(t('Copied'))}}
function bytes(n){n=+n||0;var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return n.toFixed(i>=3?2:0)+' '+u[i]}
function gbtxt(g){g=+g||0;return g<1?Math.round(g*1024)+' MB':g.toFixed(2)+' GB'}

// ---------------------------------------------------------------- Persian digits + Jalali (Shamsi) calendar
var PD='۰۱۲۳۴۵۶۷۸۹',AD='٠١٢٣٤٥٦٧٨٩';
function N(x){x=String(x==null?'':x);return S.lang=='fa'?x.replace(/\d/g,function(d){return PD.charAt(+d)}):x}
function unN(s){return String(s==null?'':s).replace(/[۰-۹]/g,function(d){return PD.indexOf(d)}).replace(/[٠-٩]/g,function(d){return AD.indexOf(d)})}
function dv(a,b){return Math.floor(a/b)}
function g2j(gy,gm,gd){var gdm=[0,31,59,90,120,151,181,212,243,273,304,334],gy2=gm>2?gy+1:gy,days=355666+365*gy+dv(gy2+3,4)-dv(gy2+99,100)+dv(gy2+399,400)+gd+gdm[gm-1],jy=-1595+33*dv(days,12053);
 days%=12053;jy+=4*dv(days,1461);days%=1461;if(days>365){jy+=dv(days-1,365);days=(days-1)%365}
 return [jy,days<186?1+dv(days,31):7+dv(days-186,30),1+(days<186?days%31:(days-186)%30)]}
function j2g(jy,jm,jd){jy+=1595;var days=-355668+365*jy+dv(jy,33)*8+dv(jy%33+3,4)+jd+(jm<7?(jm-1)*31:(jm-7)*30+186),gy=400*dv(days,146097);
 days%=146097;if(days>36524){days--;gy+=100*dv(days,36524);days%=36524;if(days>=365)days++}
 gy+=4*dv(days,1461);days%=1461;if(days>365){gy+=dv(days-1,365);days=(days-1)%365}
 var gd=days+1,leap=(gy%4==0&&gy%100!=0)||gy%400==0,sa=[0,31,leap?29:28,31,30,31,30,31,31,30,31,30,31],gm;
 for(gm=0;gm<13&&gd>sa[gm];gm++)gd-=sa[gm];return [gy,gm,gd]}
function p2(n){return (n<10?'0':'')+n}
// Jalali "1405/07/11" in Persian mode, "2026-10-03" in English mode (+ " HH:MM")
function jdate(ts,time){if(!ts)return '∞';var d=new Date(ts*1000),s;
 if(S.lang=='fa'){var j=g2j(d.getFullYear(),d.getMonth()+1,d.getDate());s=j[0]+'/'+p2(j[1])+'/'+p2(j[2])}else s=d.getFullYear()+'-'+p2(d.getMonth()+1)+'-'+p2(d.getDate());
 if(time)s+=' '+p2(d.getHours())+':'+p2(d.getMinutes());return N(s)}
function fmtDate(ts,withTime){return jdate(ts,withTime)}
function ago(ts){if(!ts)return t('never');var s=Math.max(0,Math.floor(Date.now()/1000-ts));if(s<60)return N(s)+' '+t('seconds ago');if(s<3600)return N(Math.floor(s/60))+' '+t('minutes ago');if(s<86400)return N(Math.floor(s/3600))+' '+t('hours ago');return jdate(ts,true)}
function leftTxt(ts){if(!ts)return t('Unlimited');var sec=ts-Date.now()/1000;if(sec<=0)return t('Expired');var d=Math.ceil(sec/86400);return sec<86400?t('less than a day'):N(d)+' '+t('days left')}

// ---------------------------------------------------------------- icons (stroke = currentColor)
var ICO={
 edit:'<path d="M4 20h4L19 9l-4-4L4 16v4z"/><path d="M14 6l4 4"/>',
 link:'<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
 qr:'<rect x="3.5" y="3.5" width="6.5" height="6.5" rx="1.2"/><rect x="14" y="3.5" width="6.5" height="6.5" rx="1.2"/><rect x="3.5" y="14" width="6.5" height="6.5" rx="1.2"/><path d="M14 14h3v3M20.5 14v.01M14 20.5h3.5M20.5 17.5v3"/>',
 reset:'<path d="M4 12a8 8 0 1 0 2.6-5.9"/><path d="M4 4v4.5h4.5"/>',
 trash:'<path d="M5 7h14M10 7V5h4v2M7 7l1 12h8l1-12"/>',
 dl:'<path d="M12 4v10M8 10.5l4 4 4-4M5 19h14"/>',
 ext:'<path d="M14 5h5v5M19 5l-8 8M17 14v4a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V8a1 1 0 0 1 1-1h4"/>',
 refresh:'<path d="M20 12a8 8 0 1 1-2.6-5.9"/><path d="M20 4v4.5h-4.5"/>',
 dash:'<rect x="3.5" y="3.5" width="7" height="8.5" rx="2"/><rect x="13.5" y="3.5" width="7" height="5.5" rx="2"/><rect x="13.5" y="12" width="7" height="8.5" rx="2"/><rect x="3.5" y="15.5" width="7" height="5" rx="2"/>',
 users:'<circle cx="9" cy="8.2" r="3.3"/><path d="M3.2 19.5c.4-3.3 2.7-5.2 5.8-5.2s5.4 1.9 5.8 5.2"/><path d="M15.6 5.2a3.2 3.2 0 0 1 0 6"/><path d="M17.4 14.6c2 .5 3.2 2.2 3.4 4.4"/>',
 nodes:'<rect x="3.5" y="4" width="17" height="6.5" rx="2.2"/><rect x="3.5" y="13.5" width="17" height="6.5" rx="2.2"/><path d="M7.2 7.25h.01M7.2 16.75h.01M11 7.25h6M11 16.75h6"/>',
 backup:'<ellipse cx="12" cy="6" rx="7.5" ry="3"/><path d="M4.5 6v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3V6"/><path d="M4.5 12v6c0 1.7 3.4 3 7.5 3s7.5-1.3 7.5-3v-6"/>',
 security:'<path d="M12 3.4l7 2.8v5.3c0 4.4-2.9 7.7-7 9-4.1-1.3-7-4.6-7-9V6.2l7-2.8z"/><path d="M8.9 12.1l2.2 2.2 4-4.3"/>',
 settings:'<path d="M4 7h8.5M17.5 7H20M4 17h3M12 17h8"/><circle cx="15" cy="7" r="2.5"/><circle cx="9.5" cy="17" r="2.5"/>',
 logout:'<path d="M9.5 4H6.5a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h3"/><path d="M15 8l4 4-4 4M19 12H9.5"/>',
 menu:'<path d="M4 7h16M4 12h16M4 17h10"/>',
 moon:'<path d="M20 14.2A8 8 0 1 1 9.8 4a6.6 6.6 0 0 0 10.2 10.2z"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',
 check:'<path d="M5 12.5l4.2 4.2L19 7"/>',
 sel:'<rect x="4" y="4" width="16" height="16" rx="4.5"/><path d="M8.5 12.2l2.5 2.5 4.5-5"/>',
 cpu:'<rect x="6" y="6" width="12" height="12" rx="2.5"/><rect x="9.5" y="9.5" width="5" height="5" rx="1"/><path d="M9 3v3M15 3v3M9 18v3M15 18v3M3 9h3M3 15h3M18 9h3M18 15h3"/>',
 ram:'<rect x="3" y="7.5" width="18" height="8.5" rx="2"/><path d="M7 7.5v8.5M11 7.5v8.5M15 7.5v8.5M6.5 16v2.5M17.5 16v2.5"/>',
 disk:'<rect x="3.5" y="5" width="17" height="14" rx="3"/><path d="M3.5 12h17"/><path d="M8 15.5h.01M11.5 15.5h5"/>',
 swap:'<path d="M6 8h12l-3.2-3.2M18 16H6l3.2 3.2"/>',
 image:'<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><circle cx="9" cy="10" r="1.6"/><path d="M4 17l5-4.5 3.5 3 3-2.5 4.5 4"/>',
 chev:'<path d="M6 9l6 6 6-6"/>',
 sos:'<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="3.5"/><path d="M6 6l3.5 3.5M18 6l-3.5 3.5M6 18l3.5-3.5M18 18l-3.5-3.5"/>',
 bell:'<path d="M6 16.5V11a6 6 0 1 1 12 0v5.5l1.5 2H4.5z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
 globe:'<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.6 2.6 3.8 5.4 3.8 8.5S14.6 17.9 12 20.5C9.4 17.9 8.2 15.1 8.2 12S9.4 6.1 12 3.5z"/>',
 shield2:'<path d="M12 3.4l7 2.8v5.3c0 4.4-2.9 7.7-7 9-4.1-1.3-7-4.6-7-9V6.2l7-2.8z"/><path d="M9 12h6M12 9v6"/>',
 brush:'<path d="M14.5 4.5l5 5-8.2 8.2a3 3 0 0 1-4.3 0l-.7-.7a3 3 0 0 1 0-4.3z"/><path d="M6.3 13l4.7 4.7M3.5 20.5c1.8 0 3-1 3-2.5"/>',
 box:'<path d="M4 7.5l8-4 8 4v9l-8 4-8-4z"/><path d="M4 7.5l8 4 8-4M12 11.5v9"/>',
 copy:'<rect x="8.5" y="8.5" width="11.5" height="11.5" rx="2.5"/><path d="M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5"/>',
 play:'<path d="M8 5.5v13l10.5-6.5z"/>',
 pause:'<path d="M8.5 5.5v13M15.5 5.5v13"/>',
 bot:'<rect x="4.5" y="8" width="15" height="11" rx="3.5"/><path d="M12 8V5"/><circle cx="12" cy="4" r="1.2"/><circle cx="9.3" cy="13.2" r="1.2"/><circle cx="14.7" cy="13.2" r="1.2"/><path d="M9.5 16.5h5M2.5 12.5v3M21.5 12.5v3"/>',
 traffic:'<path d="M4 19.5h16"/><path d="M7 16v-5M11 16V7M15 16v-7.5M19 16V4.5"/>',
 ports:'<path d="M9 3.5v4.5M15 3.5v4.5"/><path d="M6.5 8h11v3.5a5.5 5.5 0 0 1-11 0z"/><path d="M12 17v3.5"/>',
 send:'<path d="M20.5 3.5L3.5 10.5l7 2.5 2.5 7z"/><path d="M10.5 13l5-5"/>',
 term:'<rect x="3.5" y="4.5" width="17" height="15" rx="3"/><path d="M7.5 9.5l3 2.5-3 2.5M12.5 15h4"/>',
 gift:'<rect x="4" y="9" width="16" height="11" rx="2"/><path d="M4 13h16M12 9v11"/><path d="M12 9c-2.5 0-4.5-1-4.5-2.7S9.6 3.8 12 9zM12 9c2.5 0 4.5-1 4.5-2.7S14.4 3.8 12 9z"/>',
 card:'<rect x="3" y="6" width="18" height="12.5" rx="2.5"/><path d="M3 10.5h18M7 15h3.5"/>',
 move:'<path d="M4 8h13.5l-3.5-3.5M20 16H6.5l3.5 3.5"/>',
 tunnel:'<path d="M3 19v-7a9 9 0 0 1 18 0v7"/><path d="M7.5 19v-6.5a4.5 4.5 0 0 1 9 0V19"/><path d="M1.5 19h21"/>',
 srv:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M12 6.5h5M12 17.5h5"/>',
 dns:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/>',
 xray:'<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
 game:'<path d="M6 11h4M8 9v4"/><circle cx="15.5" cy="12.5" r=".6"/><circle cx="17.5" cy="10.5" r=".6"/><path d="M7.5 6h9a5 5 0 0 1 4.8 6.3l-1 3.6a2.6 2.6 0 0 1-4.6.9L14.5 15h-5l-1.2 1.8a2.6 2.6 0 0 1-4.6-.9l-1-3.6A5 5 0 0 1 7.5 6z"/>',
 more38:'<circle cx="5" cy="12" r="1.7"/><circle cx="12" cy="12" r="1.7"/><circle cx="19" cy="12" r="1.7"/>',
 sun38:'<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4"/>',
 k310sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6l1.4 1.4M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4L6 18M18 6l1.4-1.4"/>',
 k310online:'<path d="M5 12.5a10 10 0 0 1 14 0"/><path d="M8.5 15.8a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.2"/>',
 k310ok:'<circle cx="12" cy="12" r="8.5"/><path d="M8.5 12.3l2.4 2.4 4.6-4.9"/>',
 k310warn:'<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5v5.2l3 1.8"/>',
 k310off:'<circle cx="12" cy="12" r="8.5"/><path d="M6 6l12 12"/>',
 k310traffic:'<path d="M7 4v14M3.5 14.5L7 18l3.5-3.5"/><path d="M17 20V6M13.5 9.5L17 6l3.5 3.5"/>',
 pc:'<rect x="3.5" y="4.5" width="17" height="11" rx="2"/><path d="M8 19.5h8M12 15.5v4"/>',
 phone:'<rect x="7" y="3" width="10" height="18" rx="2.5"/><path d="M11 17.5h2"/>',
 cores:'<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>'
};
function ic(n,sz){sz=sz||18;return '<svg viewBox="0 0 24 24" width="'+sz+'" height="'+sz+'" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+ICO[n]+'</svg>'}
// logo: the uploaded image (Settings > Logo) or the first letter; cached so the login page can show it too
function logoOk(s){return /^data:image\/(png|jpeg|webp|gif|svg\+xml);base64,[A-Za-z0-9+\/=]+$/.test(s||'')}
function curLogo(){var l=(S.me&&S.me.logo)||(S.me?'':localStorage.getItem('kk_logo'))||'';return logoOk(l)?l:''}
function logoCls(){return 'logo'+(curLogo()?' has-img':' svgl')}
function logoInner(letter){var l=curLogo();return l?'<img src="'+l+'" alt="">':kLogo()}

// ---------------------------------------------------------------- tiny live-chart renderer (SVG, newest point on the right edge)
function smoothPath(pts){var i,d;if(pts.length<3){d='';for(i=0;i<pts.length;i++)d+=(i?'L':'M')+pts[i][0].toFixed(1)+' '+pts[i][1].toFixed(1);return d}
 d='M'+pts[0][0].toFixed(1)+' '+pts[0][1].toFixed(1);
 for(i=1;i<pts.length-1;i++)d+='Q'+pts[i][0].toFixed(1)+' '+pts[i][1].toFixed(1)+' '+((pts[i][0]+pts[i+1][0])/2).toFixed(1)+' '+((pts[i][1]+pts[i+1][1])/2).toFixed(1);
 var l=pts[pts.length-1];return d+'L'+l[0].toFixed(1)+' '+l[1].toFixed(1)}
// series: [{v:[numbers],c:'a'|'b'}]  o:{h,max,cap}
function areaChart(series,o){var W=300,H=o.h||100,cap=o.cap||60,mx=o.max||0,i,j,s;
 if(!o.max){for(i=0;i<series.length;i++)for(j=0;j<series[i].v.length;j++)if(series[i].v[j]>mx)mx=series[i].v[j];mx=mx>0?mx*1.2:1}
 var out='<svg viewBox="0 0 '+W+' '+H+'" preserveAspectRatio="none" aria-hidden="true">',step=W/(cap-1);
 for(i=1;i<4;i++)out+='<path class="gridl" d="M0 '+(H*i/4).toFixed(1)+'H'+W+'"/>';
 for(i=0;i<series.length;i++){s=series[i];if(!s.v.length)continue;var pts=[],n=s.v.length;
  for(j=0;j<n;j++)pts.push([W-(n-1-j)*step,H-2-Math.min(1,s.v[j]/mx)*(H-6)]);
  var line=smoothPath(pts),first=pts[0][0];
  out+='<path class="ar-'+s.c+'" d="'+line+'L'+W+' '+H+'L'+first.toFixed(1)+' '+H+'Z"/><path class="ln-'+s.c+'" d="'+line+'"/>'}
 return out+'</svg>'}

function applyLook(){document.documentElement.lang=S.lang;document.documentElement.dir=S.lang=='fa'?'rtl':'ltr';
 var b=document.body.classList;b.toggle('light',S.theme=='light');
 Array.prototype.slice.call(b).forEach(function(c){if(c.indexOf('c-')==0)b.remove(c)});if(S.color&&S.color!='gold')b.add('c-'+S.color);
 b.add('k38');if($('#side'))b.add('v37');V37.drawLooks()}
var PROTOS=[['wg','WireGuard'],['awg','AmneziaWG'],['hy2','Hysteria2'],['kmix','KANKI MIX'],['mtun','microtun'],['xray','Xray'],['dns','DNS']];
function pname(p){for(var i=0;i<PROTOS.length;i++)if(PROTOS[i][0]==p)return PROTOS[i][1];return p}
function modal(html,cls){var b=$('#mbox');b.className='mbox'+(cls?' '+cls:'');b.innerHTML=html;b.scrollTop=0;$('#modal').classList.add('on');document.body.style.overflow='hidden'}
function closeModal(){$('#modal').classList.remove('on');document.body.style.overflow=''}
document.addEventListener('keydown',function(e){if(e.key=='Escape'&&$('#modal').classList.contains('on'))closeModal()});
$('#modal').addEventListener('click',function(e){if(e.target.id=='modal')closeModal()});
function mhead(title,sub){return '<div class="mh"><div><b style="font-size:17px">'+esc(title)+'</b>'+(sub?'<small class="ltr">'+esc(sub)+'</small>':'')+'</div><button class="ib" onclick="closeModal()">✕</button></div>'}
function sw(id,on,cb){return '<label class="sw"><input type="checkbox" '+(on?'checked':'')+' onchange="'+cb+'"><span></span></label>'}
function confirmDo(fn){if(confirm(t('Are you sure?')))fn()}
function dl(blobRes){var a=document.createElement('a');a.href=URL.createObjectURL(blobRes.blob);a.download=blobRes.name||'download';document.body.appendChild(a);a.click();setTimeout(function(){URL.revokeObjectURL(a.href);a.remove()},2000)}

// ---------------------------------------------------------------- login
function loginView(otp){$('#app').innerHTML='';document.body.className='';applyLook();clearInterval(S.timer);clearInterval(S.timer2);clearInterval(S.timer3);
 var sun=function(){return ic(document.body.classList.contains('light')?'moon':'k310sun',17)};
 $('#app').innerHTML='<div class="login k310login"><i class="k310orb a"></i><i class="k310orb b"></i><div class="'+logoCls()+'">'+logoInner('K')+'</div><div class="k310brand">'+t('VPN management panel')+'</div>'+
 '<div class="card"><h3>'+esc(document.title)+'</h3><p class="k310sub">'+t('Sign in to continue')+'</p>'+
 '<label class="f">'+t('Username')+'</label><input id="lu" autocomplete="username" class="ltr">'+
 '<label class="f">'+t('Password')+'</label><input id="lp" type="password" autocomplete="current-password" class="ltr">'+
 '<div id="otpw" class="'+(otp?'':'hide')+'"><label class="f">'+t('2FA code')+'</label><input id="lo" inputmode="numeric" maxlength="6" class="ltr" autocomplete="one-time-code"></div>'+
 '<button class="btn" style="width:100%;margin-top:14px" id="lb">'+t('Login')+'</button>'+
 '<div class="row" style="justify-content:center;margin-top:10px"><button class="ib" id="ll" title="'+t('Language')+'" aria-label="'+t('Language')+'">'+(S.lang=='fa'?'EN':'FA')+'</button><button class="ib" id="lt" title="'+t('Light / dark')+'" aria-label="'+t('Light / dark')+'">'+sun()+'</button></div></div></div>';
 function go(){api('POST','/api/login',{username:$('#lu').value,password:$('#lp').value,otp:$('#lo').value}).then(function(r){S.token=r.token;localStorage.setItem('kk_tok',r.token);boot()}).catch(function(e){if(e.data&&e.data.need_otp){$('#otpw').classList.remove('hide');$('#lo').focus()}fail(e)})}
 $('#lb').onclick=go;$$('#lu,#lp,#lo').forEach(function(i){i.onkeydown=function(e){if(e.key=='Enter')go()}});
 $('#ll').onclick=function(){S.lang=S.lang=='fa'?'en':'fa';localStorage.setItem('kk_lang',S.lang);loginView(!$('#otpw').classList.contains('hide'))};
 $('#lt').onclick=function(){S.theme=S.theme=='light'?'dark':'light';localStorage.setItem('kk_theme',S.theme);applyLook();this.innerHTML=sun()};
}
function logout(silent){if(!silent&&S.token)api('POST','/api/logout').catch(function(){});S.token='';localStorage.removeItem('kk_tok');loginView()}

// ---------------------------------------------------------------- shell
var PAGES=[['dash','Dashboard','dash'],['users','Users','users'],['vpn','VPN services','shield2'],['nodes','Servers','nodes'],['kmix','KANKI MIX','game'],['mtun','microtun','game'],['xray','Xray','xray'],['antidpi','Anti-DPI tunnels','security'],['dns','Kanki DNS','dns'],['servers','Tunnel servers','srv'],['tunnels','Tunnels','tunnel'],['traffic','Traffic & stats','traffic'],['ports','Port management','ports'],['bot','Sales bot','bot'],['emergency','Emergency chat','sos'],['backup','Backup','backup'],['security','Security','security'],['settings','Settings','settings']];
function pgOf(k){for(var i=0;i<PAGES.length;i++)if(PAGES[i][0]==k)return PAGES[i];return PAGES[0]}
function decoratePh(){var ph=$('#pg .ph');if(!ph||ph.querySelector('.phi'))return;var d=ph.firstElementChild;if(!d||d.tagName!='DIV')return;
 var inner=document.createElement('div');while(d.firstChild)inner.appendChild(d.firstChild);
 var i=document.createElement('span');i.className='phi';i.innerHTML=ic(pgOf(S.page)[2],22);d.appendChild(i);d.appendChild(inner)}
window.addEventListener('hashchange',function(){if(!S.token||!S.me)return;var h=(location.hash||'#dash').slice(1).split('/');
 // moving between the tabs of the page already open: only the tab changes
 if(h[0]==S.page&&window['tab_'+S.page]&&$('#pg .ptabs')){S.sub=h[1]||'';navMark(S.page,S.sub);window['tab_'+S.page](S.sub);return}route()});
// every refresh timer of a page; route() stops them all when another page opens
function clearPageTimers(){clearInterval(S.timer);clearInterval(S.timer2);clearInterval(S.timer3);clearInterval(S.timer4);if(window.TS&&TS.timer){clearInterval(TS.timer);TS.timer=0}}
function autoRefresh(fn){clearInterval(S.timer);var sec=Math.max(5,(S.me&&S.me.refresh)||10);S.timer=setInterval(function(){if(!$('#modal').classList.contains('on')&&document.visibilityState=='visible')fn()},sec*1000)}
function boot(){api('GET','/api/me').then(function(me){S.me=me;try{localStorage.setItem('kk_logo',me.logo||'')}catch(e){}if(me.panel_name)document.title=me.panel_name;
  if(!localStorage.getItem('kk_color')&&me.color)S.color=me.color;if(!localStorage.getItem('kk_lang')&&me.lang)S.lang=me.lang;if(!localStorage.getItem('kk_theme')&&me.theme)S.theme=me.theme;
  applyLook();shell();route()}).catch(function(e){if(e.message!='unauthorized')loginView()})}

