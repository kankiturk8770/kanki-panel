# KLINK نسخه‌ی ۱

هسته‌ی پروکسی رمزنگاری‌شده و پنل مدیریت وب برای Ubuntu، پیاده‌شده با Go و بدون CGO. مخزن شامل سرور UDP/TCP، نشست‌های Noise_XK، مهاجرت شبکه، مالتی‌پلکس TCP/UDP، دیتابیس SQLite، کاربران حجمی و زمانی، لینک اشتراک و داشبورد زنده است.

> **توجه‌ی امنیتی:** KLINK یک پیاده‌سازی جدید پروتکل است و هنوز ممیزی امنیتی مستقل نشده است. پیش از استفاده‌ی گسترده‌ی عملیاتی، ممیزی رمزنگاری و فازینگ انجام دهید. هیچ پروتکلی را نمی‌توان «تضمیناً غیرقابل‌شناسایی» دانست. پروفایل `tls-mimic` فقط رکوردهای Application Data را می‌سازد و فینگرپرینت کامل ClientHello یا رفتار مرورگر را تقلید نمی‌کند.

## امکانات

- الگوی `Noise_XK` با X25519 و کلید عمومی ازپیش‌شناخته‌شده‌ی سرور.
- ChaCha20-Poly1305، BLAKE2s و HKDF؛ کلیدهای مستقل برای دو جهت.
- SessionID تصادفی ۱۲۸بیتی و مهاجرت آدرس یا UDP/TCP پس از احراز بسته.
- توالی ۶۴بیتی، پنجره‌ی anti-replay به اندازه‌ی ۱۰۲۴ بسته و rekey خودکار.
- قاب‌بندی TCP با طول ماسک‌شده‌ی وابسته به شمارنده؛ رمزنگاری اصلی در لایه‌ی AEAD.
- پروفایل‌های `random` و `tls-mimic` و رهاسازی بی‌صدا‌ی بسته‌های نامعتبر.
- مالتی‌پلکس چند جریان TCP و چند UDP association روی یک نشست.
- محدودیت حجم، انقضا و تعداد نشست/دستگاه هم‌زمان برای هر کاربر.
- لینک اشتراک با توکن ۲۵۶بیتی و JSON شامل کلیدها و endpointها.
- پنل فارسی RTL با Tailwind CSS، آمار آنلاین، پورت‌ها و مدیریت کامل کاربران.
- SQLite با WAL، بدون CGO، systemd و UFW.

## ساختار پروژه

```text
.
├── cmd/
│   ├── server/main.go          # هسته‌ی شبکه و API داخلی وضعیت
│   └── panel/
│       ├── main.go             # اجرای HTTP/TLS و هش رمز عبور
│       ├── api.go              # احراز مدیریت، CRUD و اشتراک
│       └── api_test.go
├── internal/
│   ├── crypto/                 # کلیدها، Noise، AEAD، rekey و replay
│   ├── transport/              # انتزاع Listener و UDP/TCP framing
│   ├── obfuscation/            # random و tls-mimic
│   ├── session/                # handshake، migration، quota و آمار
│   ├── mux/                    # جریان‌های TCP و UDP association
│   └── store/                  # schema و عملیات SQLite
├── web/                        # رابط مدیریت Tailwind
├── configs/                    # نمونه‌ی کانفیگ سرور و پنل
├── docs/PROTOCOL.md            # قالب بسته‌ها و قرارداد کلاینت
├── install.sh                  # نصب کامل Ubuntu
└── go.mod / go.sum
```

## نصب سریع روی Ubuntu

روی یک Ubuntu تازه، پروژه را باز کنید و در ریشه‌ی آن اجرا کنید:

```bash
sudo PUBLIC_HOST=vpn.example.com bash install.sh
```

اگر دامنه ندارید، آدرس IPv4 عمومی سرور را جای `vpn.example.com` بگذارید. اسکریپت این کارها را انجام می‌دهد:

1. نصب وابستگی‌ها و آخرین نسخه‌ی پایدار Go.
2. اجرای تست‌ها و ساخت `klink-server` و `klink-panel`.
3. ساخت کلید سرور، توکن API داخلی و رمز تصادفی ادمین.
4. ساخت `/etc/klink` و `/var/lib/klink`.
5. بازکردن SSH، پنل و پورت UDP/TCP پروکسی در UFW.
6. نصب و اجرای `klink-core.service` و `klink-panel.service`.

اطلاعات ورود در پایان نمایش داده می‌شود و فقط برای root در فایل زیر نیز ذخیره می‌شود:

```text
/root/klink-credentials.txt
```

تنظیمات اختیاری پیش از نصب:

```bash
sudo \
  PUBLIC_HOST=vpn.example.com \
  PROXY_PORT=443 \
  PANEL_PORT=8080 \
  SSH_PORT=22 \
  ADMIN_USERNAME=admin \
  bash install.sh
```

اجرای دوباره‌ی اسکریپت باینری‌ها را ارتقا می‌دهد، اما کانفیگ، کلید سرور و رمز ادمین موجود را حفظ می‌کند.

### HTTPS پنل

نصب پیش‌فرض پنل را روی HTTP ارائه می‌کند تا بدون دامنه نیز قابل اجرا باشد. برای استفاده‌ی واقعی HTTPS را فعال کنید. در `/etc/klink/panel.json` مقداردهی کنید:

```json
{
  "public_url": "https://panel.example.com",
  "tls_cert_file": "/etc/klink/panel.crt",
  "tls_key_file": "/etc/klink/panel.key",
  "secure_cookies": true
}
```

سپس `sudo systemctl restart klink-panel` را اجرا کنید. می‌توانید به‌جای TLS داخلی، پنل را فقط روی loopback بگذارید و از Caddy یا Nginx با HTTPS استفاده کنید. لینک اشتراک و کوکی مدیریت نباید روی HTTP عمومی منتقل شوند.

## ساخت کاربر و اتصال کلاینت

1. وارد پنل شوید و **ساخت کاربر** را بزنید.
2. حجم را برحسب GB وارد کنید؛ صفر یعنی نامحدود.
3. تعداد دستگاه صفر یعنی نامحدود؛ مقدار یک، فقط یک نشست هم‌زمان می‌پذیرد.
4. تاریخ انقضا اختیاری است.
5. پس از ذخیره، **نمایش لینک** را بزنید و لینک یا JSON را در اختیار همان کاربر بگذارید.

نمونه‌ی مسیر اشتراک:

```text
https://panel.example.com/sub/<43-character-random-token>
```

پاسخ JSON شامل `client_private_key`، `client_public_key`، `server_public_key`، فهرست `transports`، پروفایل obfuscation و تنظیمات rekey است. کلاینت موبایل باید این فایل را با HTTPS و `Cache-Control: no-store` دریافت کند. قالب دقیق بسته‌ها در `docs/PROTOCOL.md` آمده است.

اگر لینک افشا شد، عملیات **چرخش توکن** لینک قبلی را بی‌اعتبار می‌کند. کلید خصوصی کلاینت تغییر نمی‌کند. برای ابطال کامل دسترسی، کاربر را غیرفعال یا حذف کنید؛ هسته در بررسی دوره‌ای، حداکثر تقریباً ظرف یک دقیقه، تغییر را روی نشست‌های قبلی نیز اعمال می‌کند.

## اجرای دستی برای توسعه

به Go 1.26 یا جدیدتر نیاز است.

```bash
go mod download
go test ./...
go build ./cmd/server ./cmd/panel
```

کلید سرور بسازید:

```bash
go run ./cmd/server -genkey
```

رمز مدیریت را هش کنید:

```bash
KLINK_PASSWORD='a-long-random-password' go run ./cmd/panel -hash-password
```

دو فایل `configs/server.example.json` و `configs/panel.example.json` را کپی و مقداردهی کنید. مقدار `status_token` در سرور باید با `core_status_token` در پنل یکی باشد. سپس:

```bash
go run ./cmd/server -config /path/to/server.json
go run ./cmd/panel -config /path/to/panel.json
```

برای اجرای محلی، `web_root` را `web` و `public_url` را آدرس پنل قرار دهید.

## عملیات و عیب‌یابی

```bash
systemctl status klink-core klink-panel
journalctl -u klink-core -f
journalctl -u klink-panel -f
curl http://127.0.0.1:9091/healthz
```

- **پنل «هسته خارج از دسترس» می‌گوید:** اجرای core، توکن مشترک و آدرس `127.0.0.1:9091` را بررسی کنید.
- **کاربر ساخته می‌شود ولی وصل نمی‌شود:** کلید عمومی سرور، endpoint عمومی، بازبودن UDP/TCP در فایروال و حجم/انقضا را بررسی کنید.
- **اتصال پس از تغییر Wi-Fi/دیتا قطع می‌شود:** کلاینت باید همان SessionID و کلیدها را از مسیر جدید ادامه دهد؛ handshake جدید لازم نیست.
- **دستگاه دوم پذیرفته نمی‌شود:** مقدار device limit و نشست قبلی آنلاین را بررسی کنید.
- **حجم بلافاصله در SQLite دیده نمی‌شود:** هسته مصرف را تجمیع و هر ده ثانیه ذخیره می‌کند؛ داشبورد مقدار زنده را از core می‌گیرد.

## تست و بررسی

```bash
go test -race ./...
go vet ./...
```

تست‌ها شامل Noise_XK، تبادل دوجهته، rekey، عدم تخریب نشست با بسته‌ی جعلی، replay، round-trip هر دو obfuscation، framing با ارتقای ماسک، handshake واقعی UDP و TCP، مهاجرت آدرس، TCP/UDP mux، SQLite و API مدیریت/اشتراک هستند.

## نکات امنیتی و محدودیت‌های نسخه‌ی ۱

- کلیدهای خصوصی صادرشده برای اشتراک در SQLite نگه داشته می‌شوند تا پنل بتواند JSON را دوباره ارائه کند. از دیتابیس و backupها محافظت کنید. برای مدل امنیت بالاتر می‌توان در نسخه‌ی بعد فقط کلید عمومی را روی سرور نگه داشت و تولید کلید را به دستگاه کاربر منتقل کرد.
- رمز عبور ادمین با bcrypt بررسی می‌شود؛ کوکی `HttpOnly` و `SameSite=Strict` است و mutationها به header اختصاصی نیاز دارند.
- پاسخ به بسته‌ی خراب، replay یا کاربر ناشناخته ارسال نمی‌شود. لاگ‌ها نیز بسته‌ی خام را چاپ نمی‌کنند.
- obfuscation جای رمزنگاری را نمی‌گیرد. `tls-mimic` یک TLS stack واقعی یا uTLS نیست و نباید به‌عنوان تضمین عبور از DPI معرفی شود.
- rekey بدون handshake جدید انجام می‌شود؛ پنجره‌ی replay برای epoch جدید بازنشانی می‌شود.
- برای production از HTTPS پنل، backup رمزشده، محدودسازی دسترسی SSH و به‌روزرسانی سیستم استفاده کنید.
