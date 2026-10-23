# قرارداد پروتکل KLINK/1

این سند برای ساخت کلاینت مستقل یا اتصال هسته به gomobile است. تمام فیلدهای چندبایتی big-endian هستند.

## ۱. لایه‌ها

ترتیب پردازش ارسال:

```text
mux frame → AEAD channel → KLINK data header → obfuscation → UDP datagram / TCP frame
```

ترتیب دریافت برعکس است. هر خطای قالب، AEAD یا replay بدون پاسخ به فرستنده رها می‌شود.

## ۲. پوشش obfuscation

### `random`

```text
packet || random-padding(0..63 bytes) || padding-length(1 byte)
```

اگر packet حداقل ۱۲۰۰ بایت باشد، padding صفر است و فقط بایت طول اضافه می‌شود.

### `tls-mimic`

هر قطعه‌ی حداکثر ۱۶۳۸۴بایتی در قالب زیر قرار می‌گیرد:

```text
0x17 0x03 0x03 || uint16 fragment-length || fragment
```

این پروفایل فقط record wrapping است؛ ClientHello یا TLS handshake واقعی تولید نمی‌کند.

## ۳. Handshake با Noise_XK

نام کامل الگو:

```text
Noise_XK_25519_ChaChaPoly_BLAKE2s
Prologue = "KLINK/1"
```

کلاینت کلید عمومی استاتیک سرور را از subscription دارد. کلید عمومی استاتیک کلاینت در پیام سوم احراز و با رکورد کاربر در SQLite تطبیق داده می‌شود.

تمام handshakeها پس از obfuscation قالب مشترک دارند:

```text
uint8 version = 1
uint8 kind
byte[16] hello-id
byte[] noise-message-or-ack
```

| kind | فرستنده | محتوای پس از hello-id |
|---|---|---|
| 1 | کلاینت | Noise message 1 |
| 2 | سرور | Noise message 2 |
| 3 | کلاینت | Noise message 3 |
| 4 | سرور | `byte[16] session-id` |

`hello-id` باید تصادفی و برای هر handshake تازه باشد. ACK فقط SessionID را حمل می‌کند؛ احراز رمزنگاری قبلاً توسط Noise انجام شده است.

اگر ACK روی UDP نرسید، کلاینت می‌تواند **همان بایت‌های** پیام سوم را از همان مسیر تا ۳۰ ثانیه دوباره بفرستد؛ سرور همان ACK و همان SessionID را دوباره می‌فرستد و نشست تکراری نمی‌سازد.

### مواد کلید

پس از پیام سوم، دو `CipherState` حاصل از Noise Split صادر می‌شوند:

```text
noise-key-material = cs1-key(32 bytes) || cs2-key(32 bytes)
k1, k2 = HKDF-BLAKE2s(
    ikm  = noise-key-material,
    salt = empty,
    info = "klink/v1 channel keys",
    L    = 64
)
```

- `k1`: کلاینت → سرور.
- `k2`: سرور → کلاینت.
- ChannelBinding/handshake-hash عمومی Noise هرگز به‌تنهایی کلید محسوب نمی‌شود.
- همین مواد کلید محرمانه برای ارتقای ماسک TCP framing نیز استفاده می‌شود.

## ۴. بسته‌ی داده و AEAD

پس از obfuscation:

```text
uint8 version = 1
uint8 kind = 16
byte[16] session-id
uint64 epoch
uint64 sequence
byte[] ciphertext-and-16-byte-poly1305-tag
```

داده‌ی همراه AEAD، شانزده بایت `epoch || sequence` است. nonce دوازده‌بایتی:

```text
uint32(epoch) || uint64(sequence)
```

توالی در هر جهت مستقل و از یک شروع می‌شود. پنجره‌ی دریافت ۱۰۲۴ بسته است. SessionID رمز نمی‌شود چون برای یافتن نشست پیش از رمزگشایی لازم است؛ به‌تنهایی مجوز ارسال یا migration نیست.

### Rekey

هر جهت ارسال، مستقل و پیش از ارسال بسته، در یکی از این شرایط rekey می‌کند:

```text
sent-packets >= configured-rekey-packets
OR now - last-rekey >= configured-rekey-interval
```

کلید جدید:

```text
epoch = epoch + 1
key = HKDF-BLAKE2s(previous-key, empty, "klink/v1 rekey epoch=<decimal-epoch>", 32)
sequence = 0  // اولین Seal مقدار یک می‌سازد
```

گیرنده epoch جاری، بلافاصله بعدی، یا بلافاصله قبلی را می‌پذیرد و ابتدا AEAD را روی کلید کاندیدا احراز می‌کند؛ فقط پس از موفقیت کلید جدید را commit می‌کند. با epoch جدید پنجره‌ی replay تازه‌ای شروع می‌شود و پنجره‌ی epoch قبلی برای بسته‌هایی که پیش از rekey فرستاده شده‌اند ولی دیرتر رسیده‌اند نگه داشته می‌شود. بسته‌ی جعلیِ حامل epoch بعدی نباید وضعیت گیرنده را تغییر دهد.

## ۵. TCP framing

هر قاب روی TCP:

```text
uint16 masked-length
byte[length] obfuscated-klink-packet
```

حداکثر payload برابر ۶۵۵۳۵ بایت است. ماسک دو بایتی برای counter مشخص:

```text
mask = BLAKE2s(mask-seed(4 bytes) || uint64(counter))[0:2]
encoded-length = length XOR mask
```

- seed اولیه: چهار بایت اول `BLAKE2s("KLINK/1")`.
- seed پس از handshake: چهار بایت اول `BLAKE2s("klink/v1 frame mask" || noise-key-material)`.
- شمارنده‌ی خواندن و نوشتن مستقل‌اند و از صفر شروع می‌شوند.
- پیام‌های Noise ۱ تا ۳ با seed اولیه فرستاده می‌شوند.
- ACK و همه‌ی قاب‌های بعدی با seed ارتقایافته‌اند.
- ماسک‌کردن طول فقط obfuscation است؛ محرمانگی و صحت از AEAD می‌آید.

## ۶. Migration و تعویض UDP/TCP

برای UDP، کلاینت همان بسته‌ی داده‌ی معتبر را از آدرس جدید می‌فرستد. سرور فقط پس از AEAD و replay موفق، و فقط برای جدیدترین بسته (بزرگ‌ترین sequence در epoch جاری)، آدرس مقصد را جایگزین می‌کند؛ بسته‌ی قدیمیِ دیررسیده از مسیر قبلی نشست را برنمی‌گرداند.

برای شروع روی یک TCP connection جدید بدون handshake:

1. اولین data frame با framing اولیه و همان SessionID فرستاده می‌شود.
2. کلاینت بلافاصله پس از نوشتن آن، framer خود را با مواد کلید ارتقا می‌دهد.
3. سرور پس از احراز بسته، framing همان اتصال را ارتقا می‌دهد.
4. بسته‌های بعدی روی مسیر جدید ادامه می‌یابند.

اتصال‌های TCP جدید باید counterهای framing را از صفر شروع کنند. SessionID، کلیدها، epoch و sequenceهای نشست حفظ می‌شوند.

## ۷. Keepalive

متن رمزگشایی‌شده‌ی تک‌بایتی زیر keepalive است و به mux نمی‌رود:

```text
00
```

کلاینت باید پیش از `idle_timeout` سرور keepalive معتبر بفرستد. نمونه‌ی پیشنهادی: هر ۳۰ تا ۶۰ ثانیه.

## ۸. Mux

هر پیام mux متن رمزگشایی‌شده‌ی بسته‌ی داده است.

### Open

```text
uint8 kind = 1
uint32 stream-id
uint8 network       # 1=TCP، 2=UDP
uint16 target-port
uint16 host-length
byte[] target-host  # DNS name یا IP، بدون NUL
```

`stream-id` غیرصفر و در نشست یکتا باشد. برای UDP هر stream یک association به مقصد ثابت است.

### Data

```text
uint8 kind = 2
uint32 stream-id
byte[] payload
```

برای UDP، هر Data دقیقاً یک datagram است. برای TCP، ترتیب Data همان ترتیب بایت‌های جریان است. اندازه‌ی پیشنهادی قطعه‌ی TCP حداکثر ۱۶۳۸۴ بایت است؛ وقتی نشست روی انتقال UDP است سرور قطعه‌ها را حدود ۱۱۰۰ بایت می‌فرستد تا IP fragmentation رخ ندهد و کلاینت نیز باید همین کار را بکند.

> انتقال UDP تحویل مطمئن و مرتب ندارد؛ جریان‌های TCP را روی انتقال TCP بفرستید (به بخش محدودیت‌ها در README نگاه کنید).

هر نشست حداکثر ۱۰۲۴ جریان هم‌زمان دارد و Open بیشتر با Status=1 رد می‌شود. مقصدهای loopback، link-local، multicast و (به‌طور پیش‌فرض) شبکه‌های خصوصی با Status=1 رد می‌شوند. Close پیش از رسیدن Status، اتصال در حال برقراری را لغو می‌کند.

### Close

```text
uint8 kind = 3
uint32 stream-id
```

### Status، فقط سرور → کلاینت

```text
uint8 kind = 4
uint32 stream-id
uint8 status        # 0=opened، 1=failed
```

کلاینت نباید پیش از StatusOK روی یک stream تازه داده بفرستد. Close در هر دو جهت مجاز است.

## ۹. Subscription JSON

نمونه:

```json
{
  "klink_version": 1,
  "name": "mobile",
  "client_private_key": "base64-32-byte-private-key",
  "client_public_key": "base64-32-byte-public-key",
  "server_public_key": "base64-32-byte-server-key",
  "transports": [
    {"network": "udp", "endpoint": "vpn.example.com:443"},
    {"network": "tcp", "endpoint": "vpn.example.com:443"}
  ],
  "obfuscation": "random",
  "rekey_interval_seconds": 900,
  "rekey_packets": 1048576,
  "session_id_bits": 128
}
```

کلیدهای X25519 با Base64 استاندارد و padding کد می‌شوند. توکن اشتراک با Base64URL بدون padding است. توکن بخشی از پروتکل سیم نیست و فقط برای دریافت این JSON استفاده می‌شود.
