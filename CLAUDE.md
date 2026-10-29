# Kanki Panel — راهنمای Claude

پنل VPN کانکی به زبان Rust (axum + SQLite). یک فایل اجرایی (`kanki-panel`) همه کار می‌کند: پنل اصلی (`serve`)،
ایجنت سرورهای VPN (`node`)، ایجنت سرورهای تانل (`tunnel-agent`) و DNS. وب پنل یک صفحه است و داخل باینری جاسازی می‌شود.
اپ اندروید جدا است: ریپوی `kanki-app` (اشتراک را از `/sub/...` همین پنل می‌خواند).

## نقشه‌ی کد
| کار | فایل |
|---|---|
| شروع برنامه، دستورها، `App` | `src/main.rs` |
| دیتابیس و تنظیمات (`app.db.get/set`) | `src/core/db.rs` |
| API مدیریت، اشتراک (`sub_data`)، لینک WG/AWG/Hy2، دانلود کانفیگ | `src/http/api.rs` |
| صفحه‌ی «سرورها»: افزودن/ویرایش/حذف سرور، دستور نصب | `src/http/servers.rs` |
| تانل هر سرور و دامنه‌ی ایران **هر هسته** (کانفیگ دوم از راه تانل) | `src/http/twin.rs` |
| تانل‌های بین سرورها، سرورهای تانل، مسیر پورت‌ها (`port_entry_at`, `entry_host`) | `src/tunnel/panel.rs` |
| موتور و ترنسپورت‌های تانل (KCP, QUIC, hq, h2, game, faketcp, awg, hy2) | `src/tunnel/*.rs` |
| KANKI MIX | `src/vpn/kmix.rs` |
| microtun (پنل / سرور) | `src/vpn/microtun.rs` / `src/vpn/mtun.rs` |
| WireGuard و AmneziaWG، Hysteria2، OpenVPN، همگام‌سازی کاربران | `src/vpn/wg.rs`, `hy2.rs`, `ovpn.rs`, `sync.rs` |
| Xray (کانفیگ روی سرور / بخش پنل و لینک‌ها) | `src/xray/mod.rs` / `src/xray/panel.rs` |
| DNS کانکی | `src/dns/` |
| ربات فروش تلگرام، کانال، نویسنده‌ی هوش مصنوعی | `src/telegram/` |
| چت اضطراری | `src/emergency.rs` |
| ورود، توکن‌های API، 2FA | `src/http/auth.rs` |
| بکاپ، انتقال پنل، آپدیت خودکار | `src/http/backup.rs`, `migrate.rs`, `admin.rs` |
| لینک اشتراک روی سرور ایران / دامنه‌ی جدا | `src/http/subiran.rs`, `subdomain.rs` |

## وب پنل (`assets/web/`)
- `panel.js` همه‌ی صفحه‌ها است (یک فایل بزرگ، چند هزار خط). صفحه‌ها تابع `p_<page>` هستند: `p_vpn`، `p_xray`،
  `p_kmix`، `p_mtun` (با `kcPage`)، WG/AWG/Hy2 با `protoPage(p)` و `pvBody`. سرورها: `srvLoad`، `tunBox`،
  `srvSave`. ویجت دامنه‌ی تانل هر هسته: `coreTun(core, s)` و `srvIrHosts(s)`.
- جستجو در `panel.js` با `grep -n` روی اسم تابع؛ کل فایل را نخوان.
- هر متن UI داخل `t('English text')` است و ترجمه‌ی فارسی‌اش در دیکشنری همان فایل (`"English":"فارسی",`). متن تازه
  = یک خط تازه در دیکشنری.
- `index.html` قالب صفحه و CSS، `sub.html` صفحه‌ی اشتراک کاربر.
- بعد از تغییر: `node --check assets/web/panel.js`.

## تست و اجرا
- `cargo build` و `cargo test` (تست‌ها سوکت واقعی باز می‌کنند؛ حدود ۱ دقیقه).
- اجرای محلی برای دیدن UI: فایل `/etc/kanki/kanki.env` با `DATA_DIR=<پوشه‌ی موقت>` و `PANEL_PORT=18080` و
  `DOMAIN=panel.example.com`، بعد `kanki-panel reset-admin admin <pass>` و `kanki-panel serve`. توکن از
  `POST /api/login` و در مرورگر `localStorage.kk_tok`. Playwright نصب است. بعد از کار env را پاک کن.
- CI (`.github/workflows/release.yml`): هر برنچ تست می‌شود؛ فقط `main` ریلیز می‌دهد و سرورها خودشان آپدیت می‌شوند.
  پس main باید همیشه سالم باشد.

## قوانین هر تغییر
1. نسخه در `Cargo.toml` بالا برود (رفع اشکال: patch، قابلیت تازه: minor).
2. یک بخش تازه بالای `docs/CHANGES.md` (`# vX.Y.Z — عنوان`) و یک بخش «New in» کوتاه بالای `README.md`.
3. کامنت‌ها و سبک کد مثل کد اطراف: انگلیسی ساده، بدون اسم مدل در کامنت یا کامیت.
4. `cargo test` و `node --check` سبز باشند.
5. کار که تمام شد: commit، push به برنچ کار و Pull Request بساز. **قبل از مرج به main یک بار از صاحب ریپو بپرس**
   (main مستقیم روی سرورها / کاربران می‌رود). اگر تست یا CI قرمز است، اول درستش کن.
6. اگر ساختار پروژه عوض شد (فایل یا صفحه‌ی تازه)، همین `CLAUDE.md` را هم به‌روز کن.

## زبان
صاحب پروژه فارسی‌زبان است و دارد برنامه‌نویسی یاد می‌گیرد: جواب‌ها فارسی، کوتاه و ساده.
