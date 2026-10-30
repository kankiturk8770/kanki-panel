# بکاپ AmneziaVPN (آیفون، اندروید، ویندوز)

این پوشه برای اینه که بعداً پنل یا ربات بتونه برای هر مشتری **یک فایل `.backup` کامل** بسازه. مشتری اون فایل رو توی اپ AmneziaVPN با **Restore from backup** وارد می‌کنه و همه‌ی سرورهاش یک‌جا اضافه میشن.

این پوشه به کد پنل وصل نیست و فقط برای مستندات و نمونه‌ست.

```
amnezia/
├── README.md               همین توضیحات
├── tools/amnezia_backup.py ساخت بکاپ از فایل‌های .conf و تبدیل بین پلتفرم‌ها
└── samples/
    ├── ios.backup          نمونه بکاپ آیفون
    ├── android.backup      نمونه بکاپ اندروید
    ├── windows.backup      نمونه بکاپ ویندوز
    └── conf/               همون سه کانفیگی که نمونه‌ها ازشون ساخته شدن
```

> کلیدهای داخل `samples/` الکی و تصادفی‌ان و دامنه‌ها `example.com` هستن. این ریپو عمومیه، پس هیچ‌وقت بکاپ واقعی مشتری رو اینجا commit نکنید، چون کلید خصوصی همه‌ی سرورهاش داخلشه.

## فایل بکاپ چیه؟

فایل `.backup` یه **JSON ساده‌ست** (UTF-8). رمزنگاری یا فشرده‌سازی نداره. اپ موقع ساختن بکاپ، تنظیماتی رو که اسمشون با `Conf/` یا `Servers/` شروع میشه بیرون می‌ریزه و موقع ریستور همه رو برمی‌گردونه. فقط `Conf/installationUuid` و `Conf/proxyUrls/` توی بکاپ نمیرن.

منبع، کد خود کلاینت (amnezia-vpn/amnezia-client):
- `client/secureQSettings.cpp` → `backupAppConfig` / `restoreAppConfig`
- `client/core/controllers/settingsController.cpp` → `backupAppConfig` / `restoreAppConfigFromData`
- `client/core/repositories/secureServersRepository.cpp` → خوندن `Servers/serversList`

### کلیدهای سطح اول

| کلید | نوع | توضیح |
|---|---|---|
| `AppPlatform` | string | `iOS`، `Android`، `Windows`، `MacOS` یا `Linux` |
| `Servers/serversList` | **string** | لیست سرورها. یه آرایه‌ی JSON که **به‌صورت رشته** ذخیره شده (JSON داخل JSON) |
| `Servers/defaultServerId` | string | `storageServerId` سروری که پیش‌فرض انتخاب میشه |
| `Servers/defaultServerIndex` | int | همون، ولی برای نسخه‌های قدیمی اپ. اگه id پیدا نشه، از این استفاده میشه |
| `Conf/useAmneziaDns` | bool | DNS خود Amnezia |
| `Conf/routeMode` | int | اسپلیت تانل سایت‌ها: `0` همه از VPN، `1` فقط سایت‌های لیست، `2` همه به‌جز لیست |
| `Conf/killSwitchEnabled` / `Conf/strictKillSwitchEnabled` | bool | کیل‌سوییچ |
| `Conf/autoStart` | bool | اجرای خودکار (فقط ویندوز، مک و لینوکس) |
| `Conf/appsRouteMode` | int | اسپلیت تانل بر اساس اپ (فقط اندروید و ویندوز) |

### هر سرور داخل `Servers/serversList`

```json
{
  "description": "سرور 1",
  "hostName": "tr.example.com",
  "dns1": "1.1.1.1",
  "dns2": "8.8.8.8",
  "defaultContainer": "amnezia-awg",
  "storageServerId": "یک UUID یکتا",
  "containers": [{
    "container": "amnezia-awg",
    "awg": {
      "isThirdPartyConfig": true,
      "port": "51817",
      "transport_proto": "udp",
      "last_config": "<یک JSON دیگه، باز هم به‌صورت رشته>"
    }
  }]
}
```

- **`description`** همون اسمیه که مشتری توی اپ می‌بینه، پس میشه اسم سرور یا اسم مشتری رو اونجا گذاشت.
- **`container`** و کلید داخلش:
  - `amnezia-awg` با کلید `awg`: برای AmneziaWG کلاسیک (H1..H4 تصادفی).
  - `amnezia-wireguard` با کلید `wireguard`: برای WireGuard ساده، یا AWG 2.0 (با `I1`، که `H1..H4` برابر `1..4` هستن). برای AWG 2.0 داخل `last_config` باید `"isObfuscationEnabled": true` هم باشه.
- **`isThirdPartyConfig: true`** یعنی اپ این سرور رو مدیریت نمی‌کنه و فقط با کانفیگ وصل میشه. برای ما همیشه `true` هست.

### داخل `last_config`

```json
{
  "H1": "26945749", "H2": "...", "H3": "...", "H4": "...",
  "Jc": "5", "Jmin": "40", "Jmax": "70", "S1": "19", "S2": "114",
  "allowed_ips": ["0.0.0.0/0", "::/0"],
  "client_ip": "10.67.0.30/32",
  "client_priv_key": "...",
  "config": "[Interface]\nPrivateKey = ...\n...\n[Peer]\n...\n",
  "hostName": "tr.example.com",
  "port": 51817,
  "mtu": "1420",
  "persistent_keep_alive": "25",
  "psk_key": "...",
  "server_pub_key": "..."
}
```

`config` همون متن کامل فایل `.conf` هست. بقیه‌ی فیلدها از همون متن درمیان.

## فرق آیفون، اندروید و ویندوز

**محتوای سرورها در هر سه یکیه.** فرق فقط در چند کلید `Conf/` و `AppPlatform` هست:

| | iOS | Android | Windows |
|---|---|---|---|
| `AppPlatform` | `iOS` | `Android` | `Windows` |
| `Conf/appsRouteMode` | ندارد | دارد | دارد |
| `Conf/autoStart` | اثری نداره | اثری نداره | اعمال میشه |
| بعد از ریستور | کیل‌سوییچ و اتصال خودکار خاموش میشن | کیل‌سوییچ و اتصال خودکار خاموش میشن | همون مقدار بکاپ |

اپ موقع ریستور بکاپی که مال پلتفرم دیگه‌ای باشه رو **رد نمی‌کنه**. اگه `AppPlatform` با گوشی فرق داشته باشه، فقط لیست اپ‌های اسپلیت تانل پاک میشه (روی اندروید و ویندوز). پس حتی با یک فایل هم کار راه می‌افته، ولی تمیزتره که برای هر پلتفرم فایل خودش رو بدیم.

## ابزار `tools/amnezia_backup.py`

فقط به Python 3 نیاز داره.

```bash
# ساخت بکاپ از چند کانفیگ (اسم=فایل)
python3 amnezia/tools/amnezia_backup.py build --platform iOS -o Ali.backup \
    "سرور 1=tr.conf" "سرور 2=ir.conf"

# همون برای اندروید و ویندوز
python3 amnezia/tools/amnezia_backup.py build --platform Android -o Ali.backup "سرور 1=tr.conf"
python3 amnezia/tools/amnezia_backup.py build --platform Windows -o Ali.backup "سرور 1=tr.conf"

# تبدیل یک بکاپ موجود به پلتفرم دیگه
python3 amnezia/tools/amnezia_backup.py convert --platform iOS android.backup -o ios.backup
```

`--default 1` سرور دوم رو پیش‌فرض می‌کنه (شماره از صفر شروع میشه).

## ایده برای ربات و پنل

1. مشتری توی ربات Kanki-VPN (`@KankiVPN_bot`) دکمه‌ی «بکاپ Amnezia» رو می‌زنه و آیفون، اندروید یا ویندوز رو انتخاب می‌کنه.
2. پنل کانفیگ‌های WireGuard/AWG فعال اون مشتری رو جمع می‌کنه (همون متن `.conf`).
3. برای هر کانفیگ یک سرور می‌سازه (`server_from_conf`) و همه رو با `build_backup` در یک فایل می‌ذاره. اسم فایل رو اسم مشتری بذارید، مثلاً `Ali.backup`.
4. ربات فایل رو با `sendDocument` برای مشتری می‌فرسته و ویدیوی آموزشی همون پلتفرم رو هم کنارش می‌ذاره.

برای پیاده‌سازی در Rust (کد پنل) کافیه همین ساختار با `serde_json` ساخته بشه. فقط حواستون باشه `Servers/serversList` و `last_config` **رشته‌ی JSON** هستن، نه آبجکت.

### نکته‌های مهم

- **هر دستگاه کلید جدا لازم داره.** اگه یک کانفیگ (یک کلید خصوصی) هم‌زمان روی دو دستگاه وصل باشه، اتصال‌ها قطع و وصل میشن.
- **`storageServerId` باید برای هر سرور یکتا باشه.** اگه تکراری باشه اپ خودش یه id جدید می‌سازه و ممکنه سرور پیش‌فرض عوض بشه.
- **پسوند فایل باید `.backup` باشه**، چون اپ فقط همین پسوند رو نشون میده.
- **بکاپ همه‌ی تنظیمات فعلی اپ مشتری رو پاک می‌کنه.** موقع ریستور، خود اپ هم این هشدار رو میده.
- نمونه‌های این پوشه از روی کد کلاینت و یک بکاپ واقعی اندروید ساخته شدن، ولی روی دستگاه واقعی تست نشدن. قبل از اینکه ربات رو راه بندازید، یک بار روی هر پلتفرم امتحانشون کنید.
