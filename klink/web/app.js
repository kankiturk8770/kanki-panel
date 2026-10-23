'use strict';

const $ = (id) => document.getElementById(id);
const state = { users: [], timer: null, busy: false };

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));
}

function toast(message, error = false) {
  const el = $('toast');
  el.textContent = message;
  el.className = `fixed bottom-5 left-1/2 z-50 -translate-x-1/2 rounded-xl border px-5 py-3 text-sm shadow-2xl ${error ? 'border-red-400/30 bg-red-950 text-red-100' : 'border-white/10 bg-slate-800 text-slate-100'}`;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => el.classList.add('hidden'), 3500);
}

async function api(url, options = {}) {
  const headers = {...(options.headers || {})};
  if (options.body) headers['Content-Type'] = 'application/json';
  if (options.method && options.method !== 'GET') headers['X-KLINK-Request'] = '1';
  const response = await fetch(url, {...options, headers, credentials: 'same-origin'});
  if (response.status === 401 && !url.endsWith('/login')) {
    showLogin();
    throw new Error('نشست مدیریت پایان یافته است');
  }
  if (!response.ok) {
    let message = `خطای ${response.status}`;
    try { message = (await response.json()).error || message; } catch (_) {}
    throw new Error(message);
  }
  if (response.status === 204) return null;
  return response.json();
}

function showLogin() {
  clearInterval(state.timer);
  $('panel-view').classList.add('hidden');
  $('login-view').classList.remove('hidden');
  $('login-view').classList.add('grid');
  $('password').value = '';
}

async function showPanel() {
  $('login-view').classList.add('hidden');
  $('login-view').classList.remove('grid');
  $('panel-view').classList.remove('hidden');
  await refreshAll();
  clearInterval(state.timer);
  state.timer = setInterval(() => { if (!document.hidden) refreshAll(true); }, 15000);
}

function formatBytes(bytes) {
  let n = Number(bytes || 0);
  if (!Number.isFinite(n)) return '—';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (Math.abs(n) >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${n.toLocaleString('fa-IR', {maximumFractionDigits: i ? 1 : 0})} ${units[i]}`;
}

function formatUptime(seconds) {
  const s = Number(seconds || 0), d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return [d && `${d} روز`, (d || h) && `${h} ساعت`, `${m} دقیقه`].filter(Boolean).join(' و ');
}

function persianNumber(value) { return Number(value || 0).toLocaleString('fa-IR'); }

async function refreshDashboard() {
  const data = await api('/api/dashboard');
  const online = data.core_online, core = data.core || {}, db = data.database || {};
  const badge = $('core-badge');
  badge.textContent = online ? '● هسته آنلاین' : '● هسته خارج از دسترس';
  badge.className = `rounded-full border px-3 py-1.5 text-xs ${online ? 'border-emerald-400/20 bg-emerald-400/10 text-emerald-300' : 'border-red-400/20 bg-red-400/10 text-red-300'}`;
  $('stat-online').textContent = online ? persianNumber(core.online_users) : '—';
  $('stat-sessions').textContent = online ? `${persianNumber(core.online_sessions)} نشست` : 'اتصال به هسته برقرار نیست';
  $('stat-users').textContent = persianNumber(db.users);
  $('stat-enabled').textContent = `${persianNumber(db.enabled)} فعال`;
  $('stat-rx').textContent = online ? formatBytes(core.rx_bytes) : '—';
  $('stat-tx').textContent = online ? formatBytes(core.tx_bytes) : '—';
  $('stat-uptime').textContent = online ? `آپ‌تایم ${formatUptime(core.uptime_seconds)}` : 'آپ‌تایم نامشخص';
  const ports = core.ports || [];
  $('ports').innerHTML = ports.length ? ports.map(p => `<div class="flex items-center gap-3 rounded-xl border border-white/10 bg-slate-950/50 px-4 py-3"><span class="h-2 w-2 rounded-full ${p.listening ? 'bg-emerald-400' : 'bg-red-400'}"></span><strong class="uppercase text-slate-200">${escapeHTML(p.network)}</strong><code dir="ltr" class="text-xs text-slate-400">${escapeHTML(p.address)}</code></div>`).join('') : '<span class="text-slate-500">پورت فعالی گزارش نشده است</span>';
  $('last-update').textContent = `به‌روزرسانی ${new Date().toLocaleTimeString('fa-IR')}`;
}

async function refreshUsers() {
  state.users = await api('/api/users');
  renderUsers();
}

async function refreshAll(quiet = false) {
  if (state.busy) return;
  state.busy = true;
  try {
    const results = await Promise.allSettled([refreshDashboard(), refreshUsers()]);
    if (!quiet && results.some(r => r.status === 'rejected')) toast('بخشی از اطلاعات به‌روزرسانی نشد', true);
  } finally { state.busy = false; }
}

function userStatus(user) {
  if (!user.enabled) return ['غیرفعال', 'bg-slate-700/50 text-slate-300'];
  if (user.expires_at && new Date(user.expires_at) <= new Date()) return ['منقضی', 'bg-red-400/10 text-red-300'];
  if (user.volume_limit > 0 && user.used_bytes >= user.volume_limit) return ['حجم تمام', 'bg-amber-400/10 text-amber-300'];
  return ['فعال', 'bg-emerald-400/10 text-emerald-300'];
}

function renderUsers() {
  const query = $('search').value.trim().toLocaleLowerCase('fa');
  const users = state.users.filter(u => u.name.toLocaleLowerCase('fa').includes(query));
  $('empty-users').classList.toggle('hidden', users.length > 0);
  $('users-body').innerHTML = users.map(u => {
    const [label, color] = userStatus(u);
    const percent = u.volume_limit > 0 ? Math.min(100, Math.max(0, u.used_bytes / u.volume_limit * 100)) : 0;
    const volume = u.volume_limit > 0 ? `${formatBytes(u.used_bytes)} / ${formatBytes(u.volume_limit)}` : `${formatBytes(u.used_bytes)} / نامحدود`;
    const expiry = u.expires_at ? new Date(u.expires_at).toLocaleDateString('fa-IR') : 'بدون انقضا';
    return `<tr class="transition hover:bg-white/[.025]">
      <td class="px-5 py-4"><div class="font-medium text-slate-100">${escapeHTML(u.name)}</div><div class="mt-1 text-xs text-slate-500">#${u.id}</div></td>
      <td class="px-4 py-4"><span class="badge ${color}">${label}</span></td>
      <td class="px-4 py-4"><div dir="ltr" class="text-right text-xs text-slate-300">${volume}</div>${u.volume_limit > 0 ? `<div class="progress-track"><div class="progress-bar ${percent > 90 ? '!bg-red-400' : ''}" style="width:${percent.toFixed(1)}%"></div></div>` : ''}</td>
      <td class="px-4 py-4 text-xs text-slate-400">${expiry}</td>
      <td class="px-4 py-4 text-slate-300">${u.device_limit === 0 ? 'نامحدود' : persianNumber(u.device_limit)}</td>
      <td class="px-4 py-4"><button class="action-button" data-action="link" data-id="${u.id}">نمایش لینک</button></td>
      <td class="px-5 py-4"><div class="flex gap-1.5"><button class="action-button" data-action="edit" data-id="${u.id}">ویرایش</button><button class="action-button" data-action="reset" data-id="${u.id}">صفرکردن</button><button class="action-button" data-action="rotate" data-id="${u.id}">چرخش توکن</button><button class="action-button !text-red-300" data-action="delete" data-id="${u.id}">حذف</button></div></td>
    </tr>`;
  }).join('');
}

function openEditor(user) {
  $('user-form').reset();
  $('form-error').classList.add('hidden');
  $('user-id').value = user?.id || '';
  $('dialog-title').textContent = user ? 'ویرایش کاربر' : 'ساخت کاربر';
  $('user-name').value = user?.name || '';
  $('user-volume').value = user ? (user.volume_limit_gb || 0) : 0;
  $('user-devices').value = user ? user.device_limit : 1;
  $('user-enabled').checked = user ? user.enabled : true;
  $('user-expiry').value = user?.expires_at ? new Date(new Date(user.expires_at).getTime() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '';
  $('user-dialog').showModal();
  setTimeout(() => $('user-name').focus(), 50);
}

function showLink(user) {
  $('subscription-link').value = user.subscription_url;
  $('download-config').href = user.subscription_url;
  $('link-dialog').showModal();
}

$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  const button = event.target.querySelector('button[type=submit]');
  button.disabled = true;
  $('login-error').classList.add('hidden');
  try {
    await api('/api/login', {method: 'POST', body: JSON.stringify({username: $('username').value, password: $('password').value})});
    await showPanel();
  } catch (error) {
    $('login-error').textContent = error.message === 'invalid credentials' ? 'نام کاربری یا رمز عبور درست نیست' : error.message;
    $('login-error').classList.remove('hidden');
  } finally { button.disabled = false; }
});

$('user-form').addEventListener('submit', async event => {
  event.preventDefault();
  const id = $('user-id').value;
  const body = {name: $('user-name').value, enabled: $('user-enabled').checked,
    volume_limit_gb: Number($('user-volume').value || 0), device_limit: Number($('user-devices').value || 0),
    expires_at: $('user-expiry').value || ''};
  $('save-user').disabled = true;
  try {
    await api(id ? `/api/users/${id}` : '/api/users', {method: id ? 'PUT' : 'POST', body: JSON.stringify(body)});
    $('user-dialog').close();
    toast(id ? 'کاربر ویرایش شد' : 'کاربر و کلید امن او ساخته شد');
    await refreshAll(true);
  } catch (error) {
    $('form-error').textContent = error.message;
    $('form-error').classList.remove('hidden');
  } finally { $('save-user').disabled = false; }
});

$('users-body').addEventListener('click', async event => {
  const button = event.target.closest('button[data-action]');
  if (!button) return;
  const user = state.users.find(u => u.id === Number(button.dataset.id));
  if (!user) return;
  const action = button.dataset.action;
  if (action === 'edit') return openEditor(user);
  if (action === 'link') return showLink(user);
  const confirmations = {delete: `کاربر «${user.name}» و دسترسی او حذف شود؟`, reset: `مصرف «${user.name}» صفر شود؟`, rotate: `توکن «${user.name}» بچرخد؟ لینک قبلی از کار می‌افتد.`};
  if (!confirm(confirmations[action])) return;
  button.disabled = true;
  try {
    if (action === 'delete') await api(`/api/users/${user.id}`, {method: 'DELETE'});
    else await api(`/api/users/${user.id}/${action === 'rotate' ? 'rotate-token' : action}`, {method: 'POST', body: '{}'});
    toast('عملیات با موفقیت انجام شد');
    await refreshAll(true);
  } catch (error) { toast(error.message, true); } finally { button.disabled = false; }
});

$('new-user').addEventListener('click', () => openEditor());
['close-dialog','cancel-user'].forEach(id => $(id).addEventListener('click', () => $('user-dialog').close()));
$('close-link').addEventListener('click', () => $('link-dialog').close());
$('refresh').addEventListener('click', () => refreshAll());
$('search').addEventListener('input', renderUsers);
$('logout').addEventListener('click', async () => { try { await api('/api/logout', {method: 'POST', body: '{}'}); } catch (_) {} showLogin(); });
$('copy-link').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText($('subscription-link').value); toast('لینک کپی شد'); }
  catch (_) { $('subscription-link').select(); document.execCommand('copy'); toast('لینک کپی شد'); }
});

(async function init() {
  try { await api('/api/me'); await showPanel(); } catch (_) { showLogin(); }
})();
