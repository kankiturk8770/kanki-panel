// The sales bot as Telegram shows it: the messages and buttons of a tour (`bot_tour` in src/bot/bot.rs) drawn as
// a phone chat, one screenshot per step. Usage:
//   TOUR_OUT=/tmp/tour.json cargo test --release bot_tour -- --ignored
//   node scripts/bot_tour.js /tmp/tour.json /tmp/tour   (writes /tmp/tour/NN.png and /tmp/tour/all.html)
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const [, , src = '/tmp/bot_tour.json', outDir = '/tmp/bot_tour'] = process.argv;
const log = JSON.parse(fs.readFileSync(src, 'utf8'));
fs.mkdirSync(outDir, { recursive: true });

const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
// Telegram's HTML: only b, i, u, s, code, pre, a, tg-emoji; the rest is text
function tgHtml(t) {
  const allowed = /^<\/?(b|i|u|s|code|pre|tg-emoji|a)(\s[^>]*)?>$/;
  return String(t || '').split(/(<[^>]+>)/).map(p => p.startsWith('<') ? (allowed.test(p) ? p.replace(/<tg-emoji[^>]*>/, '<span class="ce">').replace('</tg-emoji>', '</span>') : esc(p)) : p).join('').replace(/\n/g, '<br>');
}
const colour = { success: '#2ea043', primary: '#2f81f7', danger: '#da3633' };
function kb(v) {
  const rows = (v.reply_markup && v.reply_markup.inline_keyboard) || [];
  return rows.map(r => '<div class="kr">' + r.map(b => `<div class="kb" style="${b.style ? 'background:' + colour[b.style] : ''}">${b.web_app ? '🌐 ' : b.url ? '↗ ' : ''}${esc(b.text)}</div>`).join('') + '</div>').join('');
}

// steps: what each chat got between two STEP marks (a new message, an edit of the last one, a file)
const steps = [];
let cur = null;
for (const { m, v } of log) {
  if (m === 'STEP') { cur = { title: v.title, msgs: [] }; steps.push(cur); continue; }
  if (!cur) continue;
  if (m === 'sendMessage') cur.msgs.push({ chat: v.chat_id, html: tgHtml(v.text), kb: kb(v) });
  else if (m === 'editMessageText') cur.msgs.push({ chat: v.chat_id, html: tgHtml(v.text), kb: kb(v), edit: true });
  else if (m === 'sendDocument') cur.msgs.push({ chat: v.chat_id, html: '📎 ' + esc(v.caption || 'file'), kb: kb(v) });
  else if (m === 'answerCallbackQuery' && v.text) cur.msgs.push({ chat: 0, html: '💬 ' + esc(v.text), kb: '', alert: true });
}

const css = `body{margin:0;background:#0e1621;font:15px/1.45 Vazirmatn,Tahoma,sans-serif;color:#f5f5f5}
.step{padding:10px 10px 16px;border-bottom:6px solid #000}
.st{font-size:13px;color:#8ba3bc;margin:4px 6px 8px;text-align:center}
.msg{direction:rtl;margin:6px 0;max-width:94%;background:#182533;border-radius:12px 12px 12px 4px;padding:8px 10px;word-wrap:break-word}
.msg.edit:before{content:"(ویرایش همان پیام)";display:block;font-size:11px;color:#6c8aa8;margin-bottom:2px}
.msg.alert{background:#2b3a4a;margin:6px auto;text-align:center;font-size:13px}
code{font-family:ui-monospace,monospace;color:#7ec8ff;background:rgba(255,255,255,.04);border-radius:4px;padding:0 2px;direction:ltr;unicode-bidi:embed}
.kr{display:flex;gap:4px;margin-top:4px;direction:rtl}
.kb{flex:1;min-width:0;unicode-bidi:plaintext;text-align:center;background:rgba(90,120,150,.35);border-radius:8px;padding:9px 6px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}`;
const page = body => `<!doctype html><html dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>${css}</style></head><body>${body}</body></html>`;
const stepHtml = (s, i) => `<div class="step"><div class="st">${i + 1}. ${esc(s.title)}</div>${s.msgs.map(m => `<div class="msg${m.edit ? ' edit' : ''}${m.alert ? ' alert' : ''}">${m.html}${m.kb}</div>`).join('')}</div>`;
fs.writeFileSync(path.join(outDir, 'all.html'), page(steps.map(stepHtml).join('')));

(async () => {
  const b = await chromium.launch();
  const p = await b.newPage({ viewport: { width: 390, height: 800 } });
  for (let i = 0; i < steps.length; i++) {
    await p.setContent(page(stepHtml(steps[i], i)));
    // a button whose text Telegram would cut: its text is wider than the button
    const cut = await p.evaluate(() => Array.from(document.querySelectorAll('.kb')).filter(e => e.scrollWidth > e.clientWidth + 1).map(e => e.textContent));
    if (cut.length) console.log('CUT', i + 1, steps[i].title, JSON.stringify(cut));
    await p.screenshot({ path: path.join(outDir, String(i + 1).padStart(2, '0') + '.png'), fullPage: true });
  }
  await b.close();
  console.log(steps.length, 'steps');
})();
