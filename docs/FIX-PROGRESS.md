# رفع یافته‌های docs/SCAN-HALF1.md — وضعیت کار (برای ادامه بعد از قطع سهمیه)

صاحب پنل (2026-11-01): «همهٔ ۸۸ مورد را درست کن، بی‌صدا، بعد ببر گیت‌هاب، سبز که شد main کن و در گزارش بنویس.»
کار در ۶ گروه جدا (هر گروه فایل‌های خودش)، هر گروه یک برنچ:

| گروه | شناسه‌ها | برنچ روی گیت‌هاب | وضعیت |
|---|---|---|---|
| G1 هسته، ورود، دیتابیس | M15, L1–L10, سمت db: M2, M3, L17, L45 | `fix/fix-core-auth` (6f635f5) | تمام (۲۴۸ قبول) |
| G2 پنل | H2, M14, L11–L16, سمت API: L17 | `fix/worktree-agent-a638d271253e77a08` (c3978dd) | تمام (تست‌ها سبز جز تست‌های تانل هم‌زمان) |
| G3 سرورها و اشتراک | M16, L19–L28 | `fix/fix-servers-subscription` (14c60c2) | تمام (۲۴۱ تست قبول) |
| G4 هسته‌های VPN | H1, M8–M13, M26, L18, L29–L36 | `wip/fix-vpn` | در جریان |
| G5 ربات و مینی‌اپ | H3, M1, M4, M5, L37–L44, L46, L47، سمت ربات L45 | `fix/fix-bot-sales` (8377f4d) | تمام (۲۳۹ قبول؛ یک خط در backup.rs:372) |
| G6 کانال، چت، نصب | M6, M7, M17–M25, L48–L59 | `wip/fix-m6-l59-bot-emergency-install` | در جریان |

برنچ‌های `wip/*` عکس لحظه‌ای کار نیمه‌تمام‌اند (ممکن است کامپایل نشوند). قدم‌های باقی‌مانده: تمام کردن G1/G4/G5/G6، مرج همهٔ برنچ‌ها روی
`claude/panel-work-n233zr`، `cargo test` کامل، نسخه 3.25.3 + CHANGES/README، گزارش «رفع شد» در `CLAUDE.md` و `docs/SCAN-HALF1.md`، PR، سبز، مرج.
نکته‌های گروه‌ها: G2 در `auth.rs` تابع `identify_quiet` اضافه کرد (G1 هم `auth.rs` را عوض می‌کند: مرج با دقت). G3: همان ذخیرهٔ بی‌اعتبارسنجی
آدرس در `src/tunnel/panel.rs:2173,2188` هم هست (نیمهٔ دوم). G2: توکن join مخصوص هر سرور (`servers.rs`) در L13 پوشش داده نشد.

کارهای اتصال بعد از مرج (یادداشت G1): در `bot.rs` تابع `fulfill` برای تمدید پلن `self.db().renew_plan(o.4, p.days, p.gb)` صدا شود به‌جای `extend`
(بدون این M2 کامل نیست)؛ سه متن تازه به `08-translations.js`: "2FA is already on; turn it off with its code first"، "this username is
reserved, pick another"، "could not save the password, try again".
