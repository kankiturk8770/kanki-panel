//! Smart channel manager for the sales bot.
//!
//! The bot (as an admin of your Telegram channel) writes and publishes posts on its own:
//! price lists made from your real plans, discount campaigns with a fresh code, tips, how-to
//! guides, free-trial and referral invitations, trust posts with live numbers, and greetings for
//! Iranian occasions (Nowruz, Yalda, …). Texts are put together from a word bank so posts do not
//! repeat, nothing is sent at night (quiet hours), and every post carries a "buy from the bot"
//! button. Discount codes made here work in the bot right away and expire on their own.

use crate::api::err;
use crate::guard;
use crate::util::{esc, now};
use crate::App;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::seq::SliceRandom;
use rand::Rng;
use serde_json::{json, Value};
use std::sync::Arc;

type St = State<Arc<App>>;

/// Iran time (UTC+3:30, no daylight saving)
const TZ: i64 = 12600;

pub const KINDS: &[(&str, &str)] = &[
    ("plans", "Price list"),
    ("offer", "Discount campaign"),
    ("tip", "Tip"),
    ("guide", "How to connect"),
    ("trial", "Free trial"),
    ("ref", "Invite friends"),
    ("trust", "Why us"),
    ("occasion", "Occasion greeting"),
    ("story", "Story"),
    ("day", "A day with us"),
    ("poll", "Question for the audience"),
    ("faq", "Q&A"),
    ("mood", "Short punch"),
    ("versus", "Before and after"),
];

const NEW_KINDS: &[&str] = &["story", "day", "poll", "faq", "mood", "versus"];

// ------------------------------------------------------------------ word bank

const HOOK: &[&str] = &[
    "اینترنت آزاد، بدون دردسر", "سرعت واقعی، نه وعده", "وصل بمون، هر جا که هستی", "دیگه با قطعی کنار نیا",
    "یه بار وصل شو، خیالت راحت", "اینترنت پرسرعت و پایدار", "بدون قطعی، بدون محدودیت", "اتصال امن و همیشگی",
    "پینگ پایین، سرعت بالا", "فیلترشکن حرفه‌ای با پشتیبانی واقعی",
    "اینترنت بی‌دردسر، حتی در ساعات شلوغی",
    "وصل شو و بی‌خیال قطع و وصل شدن",
    "هر اپراتوری داری، ما راهی داریم",
    "برای کار، درس و سرگرمی؛ همه‌چیز در یک اشتراک",
    "اشتراکی که با اپراتور تو هم‌خوانی دارد",
    "اینترنت آزاد برای کل خانواده",
    "تحویل فوری، شروع در چند ثانیه",
    "اول تست کن، بعد تصمیم بگیر",
    "پایدار برای کار و گیم و تماس تصویری",
    "ساده بخر، ساده وصل شو",
    "وصل شو، نفس بکش، لذت ببر",
    "اینترنتی که پای کارت می‌ایسته",
    "سریع، ساده، بی‌حاشیه",
    "از همون دقیقه‌ی اول فرقش رو حس می‌کنی",
    "این‌بار اینترنتت رو جدی بگیر",
    "کیفیت رو اولین بار که وصل شی می‌فهمی",
    "برای کسایی که وقتشون ارزش داره",
    "اینترنت تمیز، ذهن آروم",
    "یه قدم تا اینترنتی که همیشه می‌خواستی",
    "دنیا فقط یه کلیک اون‌طرف‌تره",
    "آروم بخر، تند وصل شو",
    "اینترنت بدون استرس، حالا ممکنه",
    "سرعتی که خودش حرف می‌زنه",
];
const BENEFIT: &[&str] = &[
    "⚡️ سرعت بالا روی همه اپراتورها (همراه اول، ایرانسل، رایتل، مخابرات)",
    "🛡 رمزنگاری کامل؛ اطلاعاتت فقط مال خودته",
    "🎮 پینگ پایین برای گیم و تماس تصویری",
    "📺 یوتیوب، اینستاگرام و تلگرام بدون لگ",
    "🔁 اگر یک سرور مشکل داشت، خودکار سرور دیگر",
    "📱 یک لینک برای اندروید، آیفون، ویندوز و مک",
    "🧑‍💻 پشتیبانی سریع و واقعی",
    "♻️ تمدید ساده با یک کلیک داخل ربات",
    "🌍 چند کشور مختلف در یک اشتراک",
    "🔒 بدون ثبت لاگ از فعالیت شما",
    "💳 پرداخت کارت به کارت و آنلاین",
    "⏱ تحویل خودکار و فوری بعد از پرداخت",
    "🧩 چند پروتکل در یک اشتراک: WireGuard، AmneziaWG و Hysteria2",
    "📊 حجم و زمان باقی‌مانده را همیشه از ربات می‌بینی",
    "🔄 اگر اپراتورت عوض شد، پروتکل را عوض کن و ادامه بده",
    "👨‍👩‍👧 پلن‌های چندکاربره برای خانواده",
    "🧪 تست رایگان قبل از خرید",
    "📩 هشدار قبل از اتمام اشتراک",
    "🛠 راهنمای نصب برای همهٔ دستگاه‌ها",
    "🚀 اتصال سریع بعد از پرداخت، بدون انتظار",
    "🎁 هدیه برای دعوت دوستان",
    "🌐 چند کشور برای انتخاب بهترین مسیر",
    "🔁 تمدید راحت از داخل ربات",
    "💬 پاسخ‌گویی به مشکلات اتصال",
    "💛 قیمت منصفانه، کیفیت بدون حاشیه",
    "🧘 آرامش خیال؛ اگه مشکلی پیش بیاد پشتیبان کنارته",
    "🎬 استریم روان برای فیلم و سریال",
    "📞 تماس تصویری شفاف و بدون وقفه",
    "🧠 پروتکل مناسب هر شبکه، بدون سردرگمی",
    "🎒 سبک و کم‌مصرف روی موبایل",
    "⏰ هر ساعت از شبانه‌روز در دسترس",
    "🗂 مدیریت ساده‌ی سرویس از داخل ربات",
];
const CTA: &[&str] = &[
    "👇 همین الان از ربات بخر و ظرف چند ثانیه وصل شو", "👇 برای خرید روی دکمه زیر بزن", "👇 خرید و تحویل فوری از ربات",
    "👇 اول تست بگیر، بعد خرید کن", "👇 جا نمونی؛ از ربات سفارش بده", "👇 فقط با یک کلیک، وصل شو",
    "👇 اول تست رایگان را امتحان کن",
    "👇 پلن مناسبت را از ربات انتخاب کن",
    "👇 همین حالا وصل شو",
    "👇 خرید ساده، تحویل خودکار",
    "👇 سؤال داری؟ از ربات بپرس",
    "👇 برای شروع روی دکمه بزن",
    "👇 همین الان شروعش کن",
    "👇 یه بار امتحان کن، فرقش رو می‌فهمی",
    "👇 دکمه‌ی پایین تنها قدم لازمه",
    "👇 زودتر وصل شو، دیرتر نگران شو",
    "👇 از ربات شروع کن؛ بقیه‌اش آسونه",
    "👇 وقتش رسیده؛ وصل شو",
];
const TIPS: &[&str] = &[
    "اگر سرعت کم شد، یک‌بار اتصال را قطع و وصل کن؛ معمولاً سرور بهتری انتخاب می‌شود.",
    "روی اینترنت همراه، پروتکل Hysteria2 معمولاً سریع‌تر و پایدارتر است.",
    "روی وای‌فای خانه، WireGuard کم‌مصرف‌ترین و سریع‌ترین گزینه است.",
    "اگر یک اپراتور اذیت می‌کند، AmneziaWG را امتحان کن؛ برای عبور از محدودیت ساخته شده.",
    "لینک اشتراکت را با کسی به اشتراک نگذار؛ تعداد اتصال همزمان محدود است.",
    "حجم و زمان باقی‌مانده را هر وقت خواستی از بخش «سرویس‌های من» در ربات ببین.",
    "قبل از تمام شدن اشتراک، ربات خبرت می‌کند تا بدون قطعی تمدید کنی.",
    "باتری زیاد مصرف می‌شود؟ در تنظیمات گوشی، بهینه‌سازی باتری را برای اپ خاموش کن تا وسط کار قطع نشود.",
    "برای بازی آنلاین، نزدیک‌ترین سرور با کمترین پینگ را انتخاب کن.",
    "اگر وصل نمی‌شوی، ساعت و تاریخ گوشی را روی خودکار بگذار؛ اختلاف ساعت اتصال را خراب می‌کند.",
    "اگر اپراتورت اینترنت همراه را کند می‌کند، پروتکل را عوض کن: Hysteria2 یا AmneziaWG.",
    "برای بازی آنلاین، پینگ از سرعت مهم‌تر است؛ نزدیک‌ترین سرور را انتخاب کن.",
    "قبل از گزارش مشکل، اپ را کامل ببند و دوباره باز کن؛ بیشتر مشکلات همین‌جا حل می‌شود.",
    "اگر یک سرور وصل نمی‌شود، سرور کشور دیگری را از لیست اپ امتحان کن.",
    "اپ را از بهینه‌سازی باتری و حالت صرفه‌جویی انرژی مستثنی کن تا وسط کار قطع نشود.",
    "اینترنت خانه کند است؟ اول بدون VPN تست سرعت بگیر؛ گاهی مشکل از مودم است.",
    "مودم را هفته‌ای یک‌بار خاموش و روشن کن؛ اتصال پایدارتر می‌شود.",
    "اگر پیام «تعداد اتصال» دیدی، یکی از دستگاه‌ها را قطع کن؛ اتصال همزمان محدود است.",
    "لینک اشتراک مخصوص خودت است؛ در گروه‌ها نفرستش.",
    "دانلود حجیم را روی وای‌فای انجام بده تا حجم اینترنت همراه نسوزد.",
    "حجم باقی‌مانده را از ربات ببین، لازم نیست حدس بزنی.",
    "اپ را به‌روز نگه دار؛ نسخهٔ جدید معمولاً پایدارتر است.",
    "وقتی VPN روشن است، پروکسی تلگرام را خاموش کن تا ترافیک دوباره تونل نشود.",
    "DNS خصوصی گوشی را روی «خودکار» بگذار؛ حالت دستی گاهی اتصال را خراب می‌کند.",
    "اگر وای‌فای و دیتا هر دو روشن‌اند و مشکل داری، یکی را قطع کن و دوباره وصل شو.",
    "بعد از عوض کردن مودم یا اپراتور، لینک اشتراک را در اپ به‌روزرسانی کن.",
    "هر دستگاه یک اتصال همزمان مصرف می‌کند؛ دستگاه‌های بدون استفاده را قطع کن.",
    "برای تماس تصویری پایدار، پروتکل‌های UDP مثل WireGuard و Hysteria2 بهترند.",
    "اگر شب‌ها که شلوغ است سرعت افت کرد، سرور دیگری را امتحان کن.",
    "بعد از آپدیت سیستم‌عامل گوشی، اگر VPN قطع شد، اپ را دوباره باز کن.",
    "کانفیگ جدید گرفتی؟ قدیمی را از اپ پاک کن تا قاطی نشوند.",
    "ویندوز: اپ را با دسترسی ادمین اجرا کن تا تونل درست ساخته شود.",
    "آیفون: اگر وصل نمی‌شود، VPN را در تنظیمات سیستم خاموش و دوباره روشن کن.",
    "اندروید: گزینهٔ «VPN همیشه روشن» را فعال کن تا ترافیک بدون محافظ نرود.",
    "روی وای‌فای عمومی، اطلاعات بانکی را بدون VPN وارد نکن.",
    "رمز تکراری نگذار و ورود دو مرحله‌ای را روی حساب‌های مهم فعال کن.",
    "اگر اپ خطای گواهی یا handshake داد، اول ساعت و تاریخ گوشی را چک کن.",
    "اینترنت ثابت و دیتا سرعت متفاوتی دارند؛ اگر یکی ضعیف بود، دیگری را امتحان کن.",
    "برای پشتیبانی سریع‌تر، نام اپراتور و نوع اینترنتت را بنویس.",
    "قبل از خرید، تست رایگان بگیر تا ببینی روی اپراتور خودت چطور کار می‌کند.",
    "دوستانت را دعوت کن؛ هدیه‌اش را از بخش «دعوت دوستان» می‌گیری.",
    "به‌روزرسانی خودکار برنامه‌ها را روی وای‌فای بگذار تا حجم نسوزد.",
    "اگر تماس قطع و وصل می‌شود، سرور نزدیک‌تر را انتخاب کن.",
    "دکمهٔ به‌روزرسانی اشتراک در اپ، سرورهای جدید را اضافه می‌کند.",
    "لینک اشتراک کار نکرد؟ دوباره از ربات کپی کن؛ شاید ناقص کپی شده.",
    "کش مرورگر را گاهی پاک کن تا سایت‌ها سریع‌تر باز شوند.",
    "حالت پرواز را ۱۰ ثانیه روشن و خاموش کن؛ ریست شبکه گاهی مشکل را حل می‌کند.",
    "کیفیت ویدیو را روی «خودکار» بگذار تا با سرعت اتصال هماهنگ شود.",
    "دو VPN را هم‌زمان روشن نکن؛ با هم تداخل دارند.",
    "فایروال یا آنتی‌ویروس را چک کن؛ گاهی اتصال VPN را می‌بندد.",
    "اگر سروری موقتاً وصل نشد، سرور دیگری را انتخاب کن؛ پشتیبانی موضوع را پیگیری می‌کند.",
    "تاریخ پایان اشتراک را از «سرویس‌های من» ببین و قبلش تمدید کن.",
    "پلن چندکاربره معمولاً از چند اشتراک جدا به‌صرفه‌تر است.",
    "روی تلویزیون هوشمند می‌توانی از هات‌اسپات گوشی که VPN روی آن روشن است وصل شوی.",
    "❓ سؤال: چند دستگاه می‌توانم وصل کنم؟ جواب: به تعداد کاربر پلن؛ در ربات پلن‌ها را ببین.",
    "❓ سؤال: اگر حجمم تمام شد چه کنم؟ جواب: از ربات تمدید یا افزایش حجم بگیر.",
    "❓ سؤال: تمدید چطور است؟ جواب: از «سرویس‌های من» تمدید را بزن و پرداخت کن.",
    "❓ سؤال: کدام پروتکل بهتر است؟ جواب: روی دیتا Hysteria2، روی وای‌فای WireGuard؛ اگر اذیت شد AmneziaWG.",
    "❓ سؤال: بعد از پرداخت چقدر طول می‌کشد؟ جواب: تحویل خودکار است و معمولاً چند ثانیه.",
    "❓ سؤال: اپ مناسب چیست؟ جواب: اندروید و آیفون Hiddify یا WireGuard، ویندوز و مک WireGuard.",
    "وقتی اتصال بالا می‌آید ولی سایت باز نمی‌شود، DNS گوشی را روی خودکار بگذار و دوباره وصل شو.",
    "هر چند هفته یک‌بار اپ و لینک اشتراک را به‌روز کن تا بهترین سرورها را داشته باشی.",
    "اگر سرعت بعد از چند ساعت افت کرد، یک‌بار قطع و وصل کن؛ اتصال تازه معمولاً بهتر است.",
    "در سفر یا محل جدید، اگر وصل نمی‌شد، پروتکل را عوض کن؛ هر شبکه رفتار متفاوتی دارد.",
    "اگه اپ بعد از قفل شدن گوشی قطع می‌شه، محدودیت باتری اون اپ رو روی «بدون محدودیت» بذار.",
    "قبل از سفر، لینک اشتراکت رو یه جای امن ذخیره کن تا هر وقت خواستی در دسترس باشه.",
    "اگه فقط یک اپ کند شده نه کل اینترنت، کش همون اپ رو پاک کن.",
    "اگه وای‌فای ضعیفه، یه بار حالت پرواز رو روشن و خاموش کن و دوباره وصل شو.",
    "برای تماس تصویری، به‌جای اینترنت همراه ضعیف، وای‌فای نزدیک روتر رو انتخاب کن.",
    "اپ رو به‌روز نگه دار؛ نسخه‌های جدید معمولاً پایدارترن.",
    "اگه یه کشور کند بود، کشور دیگه‌ای رو از لیست سرورها امتحان کن؛ فرق می‌کنه.",
    "هر چند وقت یه بار اشتراکت رو از «سرویس‌های من» چک کن تا غافلگیر نشی.",
];
const GUIDE: &[&str] = &[
    "1️⃣ از ربات اشتراک بخر یا تست بگیر\n2️⃣ لینک اشتراک را کپی کن\n3️⃣ اپ را باز کن و لینک را وارد کن\n4️⃣ روی اتصال بزن ✅",
    "📱 اندروید: اپ را از ربات دانلود کن، کد اشتراک را بزن و وصل شو.\n🍏 آیفون: WireGuard یا Hiddify را نصب کن و لینک را اضافه کن.\n💻 ویندوز / مک: WireGuard را نصب کن و فایل کانفیگ را وارد کن.",
    "🤖 اندروید:\n1️⃣ Hiddify یا WireGuard را نصب کن\n2️⃣ لینک اشتراک را از ربات کپی کن\n3️⃣ در اپ «افزودن از کلیپ‌بورد» را بزن\n4️⃣ دکمهٔ اتصال را بزن ✅",
    "🍏 آیفون:\n1️⃣ Hiddify یا WireGuard را از اپ‌استور نصب کن\n2️⃣ لینک یا QR را از ربات بگیر\n3️⃣ اضافه کن و اجازهٔ VPN را بده\n4️⃣ وصل شو ✅",
    "💻 ویندوز:\n1️⃣ WireGuard را نصب کن\n2️⃣ فایل کانفیگ را از ربات بگیر\n3️⃣ Import tunnel را بزن و فایل را انتخاب کن\n4️⃣ Activate را بزن ✅",
    "🍎 مک:\n1️⃣ WireGuard را از اپ‌استور نصب کن\n2️⃣ فایل کانفیگ را از ربات بگیر\n3️⃣ از فایل وارد کن و فعالش کن ✅",
    "🔧 وصل نمی‌شوی؟ سه قدم:\n1️⃣ ساعت و تاریخ گوشی را روی خودکار بگذار\n2️⃣ اپ را ببند و دوباره باز کن\n3️⃣ پروتکل یا سرور دیگر را امتحان کن\nهنوز مشکل داری؟ به پشتیبانی بنویس.",
    "♻️ تمدید:\n1️⃣ ربات را باز کن\n2️⃣ «سرویس‌های من» را بزن\n3️⃣ سرویس را انتخاب و تمدید کن\n4️⃣ پرداخت کن؛ بدون تغییر لینک ادامه می‌دهی.",
    "📊 مشاهدهٔ حجم:\nدر ربات «سرویس‌های من» را بزن؛ حجم باقی‌مانده و تاریخ پایان را همان‌جا می‌بینی.",
    "🔀 تغییر سرور یا پروتکل:\nدر اپ لیست سرورها را باز کن، کشور دیگری انتخاب کن. اگر کند بود، پروتکل را از WireGuard به Hysteria2 یا AmneziaWG عوض کن.",
];
const HASHTAG: &[&str] = &["#فیلترشکن", "#vpn", "#اینترنت_آزاد", "#وی_پی_ان", "#سرعت", "#پرسرعت", "#امن"];


// ------------------------------------------------------------------ mixable pools (v2.8.1)

const EMO: &[&str] = &["✨", "💫", "🔥", "💎", "🌟", "⚡️", "🎯", "🚀"];
const SCENE: &[&str] = &[
    "ساعت ۱۱ شبه، فیلمی که کل روز منتظرش بودی تازه شروع شده… و ناگهان «در حال اتصال…» 😮‍💨",
    "تماس تصویری مهمه، ده ثانیه به جواب دادن مونده و تصویر یخ می‌زنه. دیگه نه.",
    "وسط یه مسابقه‌ی حساس گیم، پینگ می‌ره بالا و همه‌چیز تموم می‌شه. حس بدیه، مگه نه؟ 🎮",
    "یادته آخرین بار کِی بدون این‌که به قطعی فکر کنی اینترنت داشتی؟ ما برای همون حس ساخته شدیم.",
    "صبح، یه قهوه‌ی خوب، یه اینترنتی که فقط کار می‌کنه. کل ماجرا همینه ☕️",
    "فایل مهم رو باید تا یه ساعت دیگه بفرستی و لودینگ هنوز ۳۰٪ـه… کی دوست داره این صحنه رو؟",
    "بهترین سرویس اونیه که یادت می‌ره داریش. فقط کار می‌کنه.",
    "دلت می‌خواد یه شب بدون «یه لحظه صبر کن، لود نمی‌شه» داشته باشی؟ 🌙",
    "یه ویدیو که بدون وقفه پخش می‌شه، یه پیام که همون لحظه می‌رسه؛ لذت‌های کوچیک ولی واقعی.",
    "کلاس آنلاین ساعت ۸ صبحه. استرس استاد کافیه؛ استرس اینترنت رو نمی‌خوای.",
    "مسافرتی و تو یه شهر جدید؟ اینترنتت باید همون‌جوری باشه که تو خونه بود. ✈️",
    "مامانت زنگ می‌زنه، تصویر واضحه، صدا قطع نمی‌شه. این‌جور لحظه‌ها قیمت ندارن 💛",
    "قرار نیست هر روز با اینترنت دعوا کنی. قراره از اینترنت استفاده کنی.",
    "وقتی همه شکایت می‌کنن، یکی هست که فقط سریالش رو می‌بینه. اون یکی می‌تونی تو باشی 😉",
    "یه کار فوری، یه دکمه‌ی ارسال، و هیچ دایره‌ی چرخونی روی صفحه. ✅",
    "خسته شدی از قطع و وصل شدن‌هایی که همیشه وسط کار مهم میان؟",
    "یه استوری، یه پست، یه ویدیو… همه بدون «در حال بارگذاری» 📲",
    "وقتی اینترنت درست کار کنه، خیلی از دغدغه‌ها خودبه‌خود حل می‌شن.",
    "یه شب که قراره بی‌دغدغه بگذره؛ فقط تو، گوشیت و یه اتصال پایدار 🌌",
    "دوست داری هر وقت گوشی رو برداشتی، همه‌چیز همون لحظه آماده باشه؟",
];
const BRIDGE: &[&str] = &[
    "ما دقیقاً برای همین لحظه‌ها اینجاییم.",
    "برای همین ساختیمش؛ ساده، سریع، پایدار.",
    "راهش ساده‌ست:",
    "قبل از این‌که دوباره اعصابت خرد شه:",
    "بذار یه بار برای همیشه راحتش کنیم:",
    "حالا فکر کن همه‌ی این‌ها حل شده:",
    "خبر خوب اینه که لازم نیست تحمل کنی:",
    "یه راه‌حل هست، و پیچیده نیست:",
];
const PUNCH: &[&str] = &[
    "اینترنت باید ساده باشه؛ ما فقط همین رو جدی گرفتیم.",
    "آروم بخر، سریع وصل شو، راحت زندگی کن.",
    "ما کارمون رو می‌کنیم؛ تو فقط وصل شو.",
    "وقتی همه‌چیز کار می‌کنه، کسی اسم ما رو نمی‌پرسه… ولی تو می‌دونی 😉",
    "کیفیت یعنی نیاز نباشه توضیح بدی.",
    "سرعت رو حس می‌کنی؛ لازم نیست قول بدیم.",
    "از اون سرویس‌هایی که بعد از یه هفته می‌گی: چرا زودتر نخریدم؟",
    "اینترنت خوب یعنی یادت نباشه اینترنت داری.",
    "وقتت ارزشمنده؛ پای لودینگ هدرش نده.",
    "یه بار امتحان کن؛ قضاوتش با خودت.",
    "بی‌حاشیه، بی‌دردسر، بی‌قطعی‌ترین تجربه‌ای که می‌تونی داشته باشی.",
    "هر روز بهتر وصل شو، هر روز راحت‌تر زندگی کن.",
    "خیالت راحت باشه؛ ما پشت اتصالت ایستادیم.",
    "جایی که اتصال تموم می‌شه، حوصله‌ی تو شروع می‌شه. ما نمی‌ذاریم به اونجا برسی.",
    "کار خوب سر و صدا نداره؛ فقط وصل می‌شه.",
    "دنیا منتظر توئه؛ فقط کافیه وصل شی.",
];
const MOMENT_NIGHT: &[&str] = &[
    "🌙 شب‌زنده‌دارا، امشب اینترنتتون قراره بی‌دردسر باشه.",
    "🌙 دیروقته و سریال هنوز نصفه‌ست؛ اینترنت نباید وسطش جا بذاره.",
    "🌌 شب آرومه؛ اتصالت هم باید همین‌طور باشه.",
];
const MOMENT_MORNING: &[&str] = &[
    "☀️ صبحی که با یه اینترنت درست شروع بشه، کل روز یه جور دیگه‌ست.",
    "☕️ قهوه‌ت رو بردار؛ اینترنتت آماده‌ست.",
    "🌅 روز تازه، شروع تازه؛ بدون قطعی.",
];
const MOMENT_NOON: &[&str] = &[
    "🌤 وسط روز، وسط کار؛ همون موقع که اینترنت نباید خرابکاری کنه.",
    "🍽 وقت استراحته؛ یه ویدیو، یه پیام، بدون لگ.",
    "⏱ ظهر شلوغه؛ اتصال تو نباید شلوغ باشه.",
];
const MOMENT_EVENING: &[&str] = &[
    "🌇 عصر خسته‌کننده‌ی بعد از کار؛ وقت یه سریال بی‌وقفه‌ست.",
    "🌆 برگشتی خونه؟ حالا نوبت اینترنتیه که کنارت باشه.",
    "🎧 عصر بخیر؛ یه آهنگ، یه ویدیو، بدون قطع شدن.",
];
const MOMENT_WEEKEND: &[&str] = &[
    "🎉 آخر هفته‌ست! وقتشه بی‌دغدغه تماشا کنی، بازی کنی و حرف بزنی.",
    "🛋 تعطیلی یعنی راحت؛ اینترنتت هم راحت باشه.",
    "🍿 آخر هفته، فیلم، تنقلات و یه اتصال بی‌نقص.",
];
const DAY_M: &[&str] = &[
    "پیام‌ها همون لحظه می‌رسن و صفحه‌ها بدون صبر باز می‌شن.",
    "اخبار، ایمیل، کار؛ همه‌چیز از اول صبح روان.",
    "قهوه می‌ریزی و تا دم‌کشیدنش، همه‌چیز آماده‌ست.",
    "کلاس آنلاین یا جلسه‌ی کاری؟ تصویر واضح، صدای شفاف.",
    "یه شروع بدون «چرا وصل نمی‌شه؟» 🙌",
];
const DAY_N: &[&str] = &[
    "تماس تصویری با خانواده، بدون یخ زدن تصویر.",
    "یه ویدیوی بلند بدون وقفه‌ی بافر.",
    "فایل‌های سنگین سریع‌تر از چیزی که فکر می‌کنی می‌رن.",
    "وسط کار، یه جست‌وجوی فوری؛ همون ثانیه جواب.",
    "استراحت ظهر با یه کلیپ بدون لگ 🍿",
];
const DAY_E: &[&str] = &[
    "سریال شب، بدون وقفه و بدون غر زدن 🎬",
    "یه دست گیم با پینگ پایین، آروم و رقابتی 🎮",
    "استوری، پست، چت؛ همه روان و سبک 📱",
    "گوشی رو می‌ذاری کنار و خیالت راحته که فردا هم همین‌طوره.",
    "آخر شب، یه آهنگ و یه اتصال که یادت نمی‌ره باهاش مشکل داشتی 🌙",
];
const VS: &[(&str, &str)] = &[
    ("منتظر لود شدن یه صفحه‌ی ساده می‌موندی", "صفحه‌ها همون لحظه باز می‌شن"),
    ("تماس تصویری وسط جمله قطع می‌شد", "تماس‌ها تمیز و بدون وقفه‌ست"),
    ("هر چند دقیقه باید سرور عوض می‌کردی", "وصل می‌شی و یادت می‌ره"),
    ("نگران تموم شدن حجم و تاریخ بودی", "حجم و زمان رو از ربات می‌بینی و قبل از اتمام خبرت می‌کنه"),
    ("برای تمدید باید پیام می‌دادی و منتظر می‌موندی", "تمدید با یه کلیک داخل ربات"),
    ("پینگ گیمت دست خودت نبود", "پینگ پایین و گیم روان"),
    ("وقتی مشکلی پیش می‌اومد کسی جواب نمی‌داد", "پشتیبانی سریع در دسترسه"),
    ("اپراتور عوض می‌شد و همه‌چیز می‌ریخت", "پروتکل رو عوض می‌کنی و ادامه می‌دی"),
];
const POLLS: &[(&str, &[&str])] = &[
    ("تو بیشتر برای چی وصل می‌شی؟", &["🎮 گیم", "🎬 فیلم و سریال", "💼 کار و درس", "📱 شبکه‌های اجتماعی"]),
    ("مهم‌ترین چیز تو یه فیلترشکن چیه؟", &["⚡️ سرعت", "🛡 امنیت", "🔁 پایداری", "💸 قیمت"]),
    ("اینترنتت بیشتر کجا اذیت می‌کنه؟", &["🏠 خونه", "📱 اینترنت همراه", "🏢 محل کار", "✈️ سفر"]),
    ("شب‌ها بیشتر چی می‌بینی؟", &["🎬 سریال", "▶️ یوتیوب", "📸 اینستاگرام", "🎧 موزیک و پادکست"]),
    ("کدوم ساعت روز اینترنت بیشتر اذیتت می‌کنه؟", &["☀️ صبح", "🌤 ظهر", "🌇 عصر", "🌙 شب"]),
    ("اگه فقط یه قابلیت می‌تونستی انتخاب کنی؟", &["🚀 سرعت بیشتر", "🔒 امنیت بیشتر", "📞 پشتیبانی سریع‌تر", "💰 قیمت کمتر"]),
];
const FAQS: &[(&str, &str)] = &[
    ("اشتراکم رو می‌شه روی چند دستگاه استفاده کرد؟", "تعداد اتصال همزمان به پلن بستگی داره؛ پلن‌های چندکاربره برای خانواده و چند دستگاه ساخته شدن."),
    ("تمدید چطوره؟", "از «سرویس‌های من» داخل ربات، سرویس رو انتخاب و تمدید کن؛ لینکت عوض نمی‌شه."),
    ("حجم و زمان باقی‌مانده رو از کجا ببینم؟", "از ربات، بخش «سرویس‌های من»؛ همه‌چیز همون‌جاست."),
    ("اگه با یه اپراتور وصل نشد چی؟", "پروتکل رو عوض کن (WireGuard، AmneziaWG یا Hysteria2)؛ هر شبکه یه پروتکل مناسب‌تر داره."),
    ("چطور پرداخت کنم؟", "کارت به کارت یا پرداخت آنلاین؛ بعدش اشتراک خودکار فعال می‌شه."),
    ("بعد از پرداخت چقدر منتظر بمونم؟", "تحویل خودکاره و معمولاً چند لحظه بیشتر طول نمی‌کشه."),
    ("اگه مشکل پیدا کردم؟", "به پشتیبانی پیام بده؛ جواب‌گویی به مشکلات اتصال جزو کار ماست."),
];

fn moment(r: &mut impl Rng, t: i64) -> &'static str {
    let h = ((t + TZ) % 86400) / 3600;
    let wd = (t + TZ).div_euclid(86400).rem_euclid(7); // 0 = Thursday, 1 = Friday
    if (wd == 0 || wd == 1) && r.gen_bool(0.4) {
        return pick(r, MOMENT_WEEKEND);
    }
    match h {
        5..=11 => pick(r, MOMENT_MORNING),
        12..=16 => pick(r, MOMENT_NOON),
        17..=20 => pick(r, MOMENT_EVENING),
        _ => pick(r, MOMENT_NIGHT),
    }
}

/// Channels that were set up before v2.8.1 saved a kind list without the new kinds; add them once.
fn migrate_kinds(app: &App) {
    if !app.db.get("ch_v3").is_empty() {
        return;
    }
    let v = app.db.get("ch_kinds");
    if !v.is_empty() {
        let mut have: Vec<String> = v.split(',').map(|x| x.to_string()).collect();
        for k in NEW_KINDS.iter() {
            if !have.iter().any(|x| x == k) {
                have.push(k.to_string());
            }
        }
        app.db.set("ch_kinds", &have.join(","));
    }
    app.db.set("ch_v3", "1");
}

fn pick<'a>(r: &mut impl Rng, v: &'a [&'a str]) -> &'a str {
    v.choose(r).copied().unwrap_or("")
}

fn toman(n: i64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    format!("{} تومان", out)
}

// ------------------------------------------------------------------ Jalali calendar

/// Gregorian -> Jalali (year, month, day)
pub fn jalali(gy: i64, gm: i64, gd: i64) -> (i64, i64, i64) {
    let g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let gy2 = if gm > 2 { gy + 1 } else { gy };
    let mut days = 355666 + (365 * gy) + ((gy2 + 3) / 4) - ((gy2 + 99) / 100) + ((gy2 + 399) / 400) + gd + g_d_m[(gm - 1) as usize];
    let mut jy = -1595 + (33 * (days / 12053));
    days %= 12053;
    jy += 4 * (days / 1461);
    days %= 1461;
    if days > 365 {
        jy += (days - 1) / 365;
        days = (days - 1) % 365;
    }
    let (jm, jd) = if days < 186 { (1 + days / 31, 1 + days % 31) } else { (7 + (days - 186) / 30, 1 + (days - 186) % 30) };
    (jy, jm, jd)
}

/// Unix time -> Gregorian date (UTC)
fn ymd(ts: i64) -> (i64, i64, i64) {
    let z = ts.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Today's Iranian occasion, if any: (name, greeting, suggested discount %)
fn occasion(ts: i64) -> Option<(&'static str, &'static str, i64)> {
    let (gy, gm, gd) = ymd(ts + TZ);
    let (_, jm, jd) = jalali(gy, gm, gd);
    match (jm, jd) {
        (12, 25..=29) | (12, 30) => Some(("Nowruz", "🌸 حال‌وهوای نوروز است! سال نو را با اینترنت آزاد شروع کن.", 25)),
        (1, 1..=4) => Some(("Nowruz", "🌷 نوروزتان پیروز! سال نو مبارک.", 25)),
        (1, 13) => Some(("Sizdah", "🌿 سیزده‌به‌در مبارک! طبیعت‌گردی با اینترنت بی‌دغدغه.", 15)),
        (9, 30) => Some(("Yalda", "🍉 شب یلدا مبارک! طولانی‌ترین شب سال را بدون قطعی بگذران.", 20)),
        (7, 1) => Some(("School", "📚 بازگشایی مدارس و دانشگاه‌ها؛ کلاس آنلاین بدون قطعی.", 10)),
        _ => {
            // Black Friday (fourth Friday of November) — widely known in Iran too
            if gm == 11 && (23..=29).contains(&gd) {
                let wd = (ts + TZ).div_euclid(86400).rem_euclid(7); // 0 = Thursday (1970-01-01)
                if wd == 1 {
                    return Some(("BlackFriday", "🖤 بلک‌فرایدی رسید! بزرگ‌ترین تخفیف سال.", 30));
                }
            }
            None
        }
    }
}

fn greeting(ts: i64) -> &'static str {
    let h = ((ts + TZ) % 86400) / 3600;
    match h {
        5..=11 => "☀️ صبح بخیر",
        12..=16 => "🌤 ظهر بخیر",
        17..=20 => "🌇 عصر بخیر",
        _ => "🌙 شب بخیر",
    }
}

// ------------------------------------------------------------------ data for posts

struct Facts {
    plans: Vec<(String, i64, f64, i64, i64, i64)>, // name, days, gb, toman, conns, countries
    users: i64,
    countries: i64,
    discount: Option<(String, i64, i64)>, // code, percent, expires
    trial: Option<(String, String)>,      // gb, days
    ref_gift: Option<(String, String)>,
}

fn facts(app: &App) -> Facts {
    let db = &app.db;
    let plans = db.with(|c| {
        let mut s = c.prepare("SELECT name,days,gb,toman,conns,COALESCE(countries,0) FROM plans WHERE active=1 ORDER BY toman").unwrap();
        let v: Vec<(String, i64, f64, i64, i64, i64)> = s
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        v
    });
    let t = now();
    let discount = db.with(|c| {
        c.query_row(
            "SELECT code,percent,COALESCE(expires,0) FROM discounts WHERE uses_left>0 AND (COALESCE(expires,0)=0 OR expires>?1) ORDER BY percent DESC LIMIT 1",
            [t],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?)),
        )
        .ok()
    });
    let countries = db.nodes().iter().filter(|n| n.enabled).count() as i64;
    Facts {
        plans,
        users: db.count("SELECT COUNT(*) FROM users WHERE enabled=1"),
        countries,
        discount,
        trial: if db.on("trial_on") { Some((db.get("trial_gb"), db.get("trial_days"))) } else { None },
        ref_gift: if db.get("ref_gb").parse::<f64>().unwrap_or(0.0) > 0.0 || db.get("ref_days").parse::<i64>().unwrap_or(0) > 0 {
            Some((db.get("ref_gb"), db.get("ref_days")))
        } else {
            None
        },
    }
}

fn plan_lines(f: &Facts, pct: i64) -> String {
    f.plans
        .iter()
        .take(8)
        .map(|(n, d, g, t, c, k)| {
            let vol = if *g > 0.0 { format!("{} گیگ", g) } else { "نامحدود".into() };
            let extra = format!("{}{}", if *c > 1 { format!(" · {} کاربره", c) } else { String::new() }, if *k > 0 { format!(" · {} کشور", k) } else { String::new() });
            let price = if pct > 0 {
                format!("<s>{}</s> ➜ <b>{}</b>", toman(*t), toman(t * (100 - pct) / 100))
            } else {
                format!("<b>{}</b>", toman(*t))
            };
            format!("🔹 {} — {} / {} روز{}\n      {}", esc(n), vol, d, extra, price)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn tags(r: &mut impl Rng) -> String {
    let mut v: Vec<&str> = HASHTAG.to_vec();
    v.shuffle(r);
    v.into_iter().take(3).collect::<Vec<_>>().join(" ")
}

fn sign(app: &App) -> String {
    let s = app.db.get("ch_sign");
    let bot = app.db.get("bot_username");
    if !s.is_empty() {
        s
    } else if !bot.is_empty() {
        format!("🤖 @{}", bot)
    } else {
        String::new()
    }
}

/// Builds one post. `kind` "auto" picks the best kind for the moment.
pub fn make_post(app: &App, kind: &str) -> (String, String) {
    let mut r = rand::thread_rng();
    let f = facts(app);
    let t = now();
    let kind = if kind == "auto" { auto_kind(app, &f, t) } else { kind.to_string() };
    let body = match kind.as_str() {
        "plans" if !f.plans.is_empty() => {
            let d = f.discount.as_ref().map(|x| x.1).unwrap_or(0);
            format!(
                "{}\n\n💎 <b>{}</b>\n\n{}\n\n{}\n{}{}\n\n{}",
                greeting(t), pick(&mut r, HOOK), plan_lines(&f, d), pick(&mut r, BENEFIT), pick(&mut r, BENEFIT),
                f.discount.as_ref().map(|(c, p, _)| format!("\n\n🎟 کد تخفیف <code>{}</code> = {}٪ تخفیف", esc(c), p)).unwrap_or_default(),
                pick(&mut r, CTA)
            )
        }
        "offer" => match &f.discount {
            Some((c, p, e)) => {
                let left = if *e > 0 { format!("\n⏳ فقط تا {} ساعت دیگر", ((e - t) / 3600).max(1)) } else { String::new() };
                format!(
                    "🔥 <b>تخفیف ویژه {}٪</b> 🔥\n\n{}\n\n🎟 کد تخفیف: <code>{}</code>{}\n\n{}\n\n{}",
                    p, pick(&mut r, HOOK), esc(c), left, plan_lines(&f, *p), pick(&mut r, CTA)
                )
            }
            None => return make_post(app, "plans"),
        },
        "tip" => format!("{}💡 <b>نکته امروز</b>\n\n{}\n\n{}", if r.gen_bool(0.5) { format!("{}\n\n", moment(&mut r, t)) } else { String::new() }, pick(&mut r, TIPS), pick(&mut r, CTA)),
        "guide" => format!("📖 <b>آموزش اتصال در ۱ دقیقه</b>\n\n{}\n\n{}", pick(&mut r, GUIDE), pick(&mut r, CTA)),
        "trial" => match &f.trial {
            Some((g, d)) => format!(
                "🎁 <b>تست رایگان!</b>\n\nقبل از خرید، {} گیگ و {} روز رایگان امتحان کن.\n\n{}\n{}\n\n👇 از ربات «تست رایگان» را بزن",
                g, d, pick(&mut r, BENEFIT), pick(&mut r, BENEFIT)
            ),
            None => return make_post(app, "tip"),
        },
        "ref" => match &f.ref_gift {
            Some((g, d)) => format!(
                "👥 <b>دوستاتو دعوت کن، هدیه بگیر!</b>\n\nبه ازای هر دوستی که با لینک تو خرید کند، {} گیگ و {} روز هدیه می‌گیری.\n\n👇 لینک دعوت اختصاصیت در ربات، بخش «دعوت دوستان»",
                g, d
            ),
            None => return make_post(app, "tip"),
        },
        "trust" => format!(
            "✅ <b>چرا ما؟</b>\n<i>{}</i>\n\n👤 بیش از {} کاربر فعال\n🌍 {} سرور در کشورهای مختلف\n{}\n{}\n{}\n\n{}",
            pick(&mut r, PUNCH), f.users.max(1), f.countries.max(1), pick(&mut r, BENEFIT), pick(&mut r, BENEFIT), pick(&mut r, BENEFIT), pick(&mut r, CTA)
        ),
        "occasion" => match occasion(t) {
            Some((_, g, _)) => format!(
                "{}\n\n{}{}\n\n{}",
                g, pick(&mut r, HOOK),
                f.discount.as_ref().map(|(c, p, _)| format!("\n\n🎟 به همین مناسبت: کد <code>{}</code> با {}٪ تخفیف", esc(c), p)).unwrap_or_default(),
                pick(&mut r, CTA)
            ),
            None => return make_post(app, "trust"),
        },
        "story" => format!(
            "{} {}\n\n{}\n\n{}\n\n{}\n\n<b>{}</b>\n\n{}",
            pick(&mut r, EMO), pick(&mut r, SCENE), moment(&mut r, t), pick(&mut r, BRIDGE), pick(&mut r, BENEFIT), pick(&mut r, PUNCH), pick(&mut r, CTA)
        ),
        "day" => format!(
            "{} <b>یه روز بی‌دغدغه با اینترنت درست‌وحسابی</b>\n\n🌅 <b>صبح</b>\n{}\n\n☀️ <b>ظهر</b>\n{}\n\n🌙 <b>شب</b>\n{}\n\n<b>{}</b>\n\n{}",
            pick(&mut r, EMO), pick(&mut r, DAY_M), pick(&mut r, DAY_N), pick(&mut r, DAY_E), pick(&mut r, PUNCH), pick(&mut r, CTA)
        ),
        "poll" => {
            let (q, opts) = *POLLS.choose(&mut r).unwrap();
            format!("{} <b>{}</b>\n\n{}\n\n👆 جوابت رو با ریاکشن بگو؛ می‌خوایم بهتر بشیم!\n\n{}", pick(&mut r, EMO), q, opts.join("\n"), pick(&mut r, CTA))
        }
        "faq" => {
            let (q, a) = *FAQS.choose(&mut r).unwrap();
            format!("{} <b>سؤال پرتکرار</b>\n\n❓ {}\n\n💬 {}\n\n{}", pick(&mut r, EMO), q, a, pick(&mut r, CTA))
        }
        "mood" => format!(
            "{} <b>{}</b>\n\n{}\n\n{}",
            pick(&mut r, EMO), pick(&mut r, PUNCH), pick(&mut r, HOOK), pick(&mut r, CTA)
        ),
        "versus" => {
            let pairs: Vec<&(&str, &str)> = VS.choose_multiple(&mut r, 3).collect();
            let lines: Vec<String> = pairs.iter().map(|p| format!("😩 قبلاً: {}\n😎 حالا: {}", p.0, p.1)).collect();
            format!("{} <b>قبل و بعد از اینترنت درست</b>\n\n{}\n\n<b>{}</b>\n\n{}", pick(&mut r, EMO), lines.join("\n\n"), pick(&mut r, PUNCH), pick(&mut r, CTA))
        }
        _ => return make_post(app, "tip"),
    };
    let s = sign(app);
    let text = format!("{}\n\n{}{}", body, tags(&mut r), if s.is_empty() { String::new() } else { format!("\n{}", s) });
    (kind, text)
}

/// Picks a kind: occasions first, a live discount next, otherwise rotate through the
/// kinds the admin enabled, avoiding the last two kinds that were posted.
fn auto_kind(app: &App, f: &Facts, t: i64) -> String {
    migrate_kinds(app);
    let enabled: Vec<String> = {
        let v = app.db.get("ch_kinds");
        if v.is_empty() { KINDS.iter().map(|k| k.0.to_string()).collect() } else { v.split(',').map(|s| s.to_string()).collect() }
    };
    let on = |k: &str| enabled.iter().any(|x| x == k);
    let recent = app.db.get("ch_recent");
    let last: Vec<&str> = recent.split(',').filter(|s| !s.is_empty()).collect();
    if on("occasion") && occasion(t).is_some() && !last.contains(&"occasion") {
        return "occasion".into();
    }
    if on("offer") && f.discount.is_some() && !last.iter().take(2).any(|k| *k == "offer") {
        return "offer".into();
    }
    let mut cand: Vec<&str> = KINDS.iter().map(|k| k.0).filter(|k| on(k) && *k != "occasion").filter(|k| !last.iter().take(2).any(|x| x == k)).collect();
    if cand.is_empty() {
        cand = vec!["plans", "tip"];
    }
    // the price list matters most: give it double weight
    if cand.contains(&"plans") {
        cand.push("plans");
    }
    cand.choose(&mut rand::thread_rng()).copied().unwrap_or("tip").to_string()
}

// ------------------------------------------------------------------ sending

fn buy_button(app: &App) -> Option<Value> {
    let bot = app.db.get("bot_username");
    if bot.is_empty() {
        return None;
    }
    Some(json!({"inline_keyboard": [[{"text": "🛒 خرید از ربات", "url": format!("https://t.me/{}?start=ch", bot)}],
        [{"text": "🎁 تست رایگان", "url": format!("https://t.me/{}?start=trial", bot)}]]}))
}

pub async fn send_to_channel(app: &App, text: &str) -> Result<(), String> {
    let token = crate::bot::bot_token(app);
    let ch = app.db.get("ch_id");
    if token.is_empty() {
        return Err("the sales bot is not set up".into());
    }
    if ch.is_empty() {
        return Err("channel is not set".into());
    }
    let chat: Value = ch.trim().parse::<i64>().map(Value::from).unwrap_or_else(|_| {
        let c = ch.trim().trim_start_matches("https://t.me/").trim_start_matches('@');
        Value::from(format!("@{}", c))
    });
    let mut body = json!({"chat_id": chat, "text": text, "parse_mode": "HTML", "disable_web_page_preview": true});
    if let Some(kb) = buy_button(app) {
        body["reply_markup"] = kb;
    }
    let r = app
        .http
        .post(format!("https://api.telegram.org/bot{}/sendMessage", token))
        .json(&body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    if v["ok"].as_bool() == Some(true) {
        app.db.set("ch_last", &now().to_string());
        let n: i64 = app.db.get("ch_count").parse().unwrap_or(0);
        app.db.set("ch_count", &(n + 1).to_string());
        Ok(())
    } else {
        Err(v["description"].as_str().unwrap_or("telegram error").to_string())
    }
}

fn remember(app: &App, kind: &str) {
    let r = app.db.get("ch_recent");
    let mut v: Vec<&str> = r.split(',').filter(|s| !s.is_empty()).collect();
    v.insert(0, kind);
    v.truncate(4);
    app.db.set("ch_recent", &v.join(","));
}

/// Makes a fresh discount code (e.g. KANKI20-7Q4M) that expires after `hours`.
pub fn new_campaign(app: &App, pct: i64, hours: i64, uses: i64) -> Result<String, String> {
    let pct = pct.clamp(1, 90);
    let tag: String = crate::util::rand_token(4).to_uppercase();
    let base = app.db.get("ch_code").trim().to_uppercase();
    let base = if base.is_empty() { "KANKI".to_string() } else { base };
    let code = format!("{}{}-{}", base, pct, tag);
    let exp = if hours > 0 { now() + hours * 3600 } else { 0 };
    app.db.exec(
        "INSERT OR REPLACE INTO discounts(code,percent,uses_left,expires) VALUES(?1,?2,?3,?4)",
        &[&code, &pct, &uses.max(1), &exp],
    )?;
    Ok(code)
}

/// Publishes posts on schedule: every `ch_hours`, never in quiet hours (01:00–08:00 Iran time).
/// On an occasion (Nowruz, Yalda…) with auto offers on, a time-limited code is made first.
pub async fn channel_loop(app: Arc<App>) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(120)).await;
        if !app.db.on("ch_on") || app.db.get("ch_id").is_empty() {
            continue;
        }
        let t = now();
        let h = ((t + TZ) % 86400) / 3600;
        if (1..8).contains(&h) {
            continue;
        }
        let every: i64 = app.db.get("ch_hours").parse::<i64>().unwrap_or(8).clamp(1, 72);
        let last: i64 = app.db.get("ch_last").parse().unwrap_or(0);
        if t - last < every * 3600 {
            continue;
        }
        if app.db.on("ch_auto_offer") {
            if let Some((name, _, pct)) = occasion(t) {
                let key = format!("{}-{}", name, ymd(t + TZ).0);
                if app.db.get("ch_occ_done") != key {
                    app.db.set("ch_occ_done", &key);
                    let _ = new_campaign(&app, pct, 48, 500);
                }
            }
        }
        let (kind, text) = make_post(&app, "auto");
        match send_to_channel(&app, &text).await {
            Ok(_) => {
                remember(&app, &kind);
                app.db.set("ch_status", "ok");
            }
            Err(e) => {
                // try again next interval, not every two minutes
                app.db.set("ch_last", &t.to_string());
                app.db.set("ch_status", &format!("error: {}", e));
            }
        }
    }
}

// ------------------------------------------------------------------ panel API

pub fn router() -> Router<Arc<App>> {
    Router::new()
        .route("/api/channel", get(ch_get).put(ch_put))
        .route("/api/channel/preview", post(ch_preview))
        .route("/api/channel/post", post(ch_post))
        .route("/api/channel/campaign", post(ch_campaign))
        .route("/api/discounts", get(disc_list).post(disc_add))
        .route("/api/discounts/:code", axum::routing::delete(disc_del))
}

async fn ch_get(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    migrate_kinds(&app);
    let db = &app.db;
    let kinds = db.get("ch_kinds");
    Json(json!({
        "on": db.on("ch_on"), "id": db.get("ch_id"), "hours": db.get("ch_hours").parse::<i64>().unwrap_or(8),
        "kinds": if kinds.is_empty() { KINDS.iter().map(|k| k.0).collect::<Vec<_>>().join(",") } else { kinds },
        "all_kinds": KINDS.iter().map(|k| json!({"id": k.0, "name": k.1})).collect::<Vec<_>>(),
        "sign": db.get("ch_sign"), "code": db.get("ch_code"), "auto_offer": db.on("ch_auto_offer"),
        "last": db.get("ch_last").parse::<i64>().unwrap_or(0), "count": db.get("ch_count").parse::<i64>().unwrap_or(0),
        "status": db.get("ch_status"), "bot": db.get("bot_username"),
        "occasion": occasion(now()).map(|o| o.0),
    }))
    .into_response()
}

async fn ch_put(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let db = &app.db;
    if let Some(v) = b["on"].as_bool() {
        db.set("ch_on", if v { "1" } else { "0" });
    }
    if let Some(v) = b["auto_offer"].as_bool() {
        db.set("ch_auto_offer", if v { "1" } else { "0" });
    }
    if let Some(v) = b["id"].as_str() {
        db.set("ch_id", v.trim());
    }
    if let Some(v) = b["hours"].as_i64().or_else(|| b["hours"].as_str().and_then(|s| s.parse().ok())) {
        db.set("ch_hours", &v.clamp(1, 72).to_string());
    }
    if let Some(v) = b["kinds"].as_str() {
        let ok: Vec<&str> = v.split(',').filter(|k| KINDS.iter().any(|x| x.0 == *k)).collect();
        db.set("ch_kinds", &ok.join(","));
    }
    if let Some(v) = b["sign"].as_str() {
        db.set("ch_sign", v.trim());
    }
    if let Some(v) = b["code"].as_str() {
        let c: String = v.trim().to_uppercase().chars().filter(|c| c.is_ascii_alphanumeric()).take(10).collect();
        db.set("ch_code", &c);
    }
    Json(json!({"ok": true})).into_response()
}

async fn ch_preview(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let (kind, text) = make_post(&app, b["kind"].as_str().unwrap_or("auto"));
    Json(json!({"kind": kind, "text": text})).into_response()
}

async fn ch_post(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let text = b["text"].as_str().unwrap_or("").to_string();
    if text.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, "text is empty");
    }
    match send_to_channel(&app, &text).await {
        Ok(_) => {
            if let Some(k) = b["kind"].as_str() {
                remember(&app, k);
            }
            Json(json!({"ok": true})).into_response()
        }
        Err(e) => err(StatusCode::BAD_GATEWAY, &e),
    }
}

async fn ch_campaign(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let pct = b["percent"].as_i64().unwrap_or(15);
    let hours = b["hours"].as_i64().unwrap_or(48);
    let uses = b["uses"].as_i64().unwrap_or(200);
    let code = match new_campaign(&app, pct, hours, uses) {
        Ok(c) => c,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e),
    };
    let (_, text) = make_post(&app, "offer");
    let posted = if b["post"].as_bool().unwrap_or(true) {
        match send_to_channel(&app, &text).await {
            Ok(_) => {
                remember(&app, "offer");
                Ok(())
            }
            Err(e) => Err(e),
        }
    } else {
        Ok(())
    };
    Json(json!({"ok": true, "code": code, "text": text, "posted": posted.is_ok(), "error": posted.err()})).into_response()
}

async fn disc_list(State(app): St, h: HeaderMap) -> Response {
    let _ = guard!(app, h, "settings");
    let t = now();
    // expired or used-up codes are removed so the list stays clean
    let _ = app.db.exec("DELETE FROM discounts WHERE uses_left<=0 OR (COALESCE(expires,0)>0 AND expires<?1)", &[&t]);
    let v: Vec<Value> = app.db.with(|c| {
        let mut s = c.prepare("SELECT code,percent,uses_left,COALESCE(expires,0) FROM discounts ORDER BY percent DESC").unwrap();
        let v: Vec<Value> = s
            .query_map([], |r| Ok(json!({"code": r.get::<_, String>(0)?, "percent": r.get::<_, i64>(1)?, "uses": r.get::<_, i64>(2)?, "expires": r.get::<_, i64>(3)?})))
            .unwrap()
            .filter_map(|x| x.ok())
            .collect();
        v
    });
    Json(json!(v)).into_response()
}

async fn disc_add(State(app): St, h: HeaderMap, Json(b): Json<Value>) -> Response {
    let _ = guard!(app, h, "settings");
    let code: String = b["code"].as_str().unwrap_or("").trim().to_uppercase().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(24).collect();
    if code.is_empty() {
        return err(StatusCode::BAD_REQUEST, "code is required");
    }
    let pct = b["percent"].as_i64().unwrap_or(10).clamp(1, 90);
    let uses = b["uses"].as_i64().unwrap_or(100).max(1);
    let hours = b["hours"].as_i64().unwrap_or(0).max(0);
    let exp = if hours > 0 { now() + hours * 3600 } else { 0 };
    match app.db.exec("INSERT OR REPLACE INTO discounts(code,percent,uses_left,expires) VALUES(?1,?2,?3,?4)", &[&code, &pct, &uses, &exp]) {
        Ok(_) => Json(json!({"ok": true, "code": code})).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, &e),
    }
}

async fn disc_del(State(app): St, h: HeaderMap, Path(code): Path<String>) -> Response {
    let _ = guard!(app, h, "settings");
    let _ = app.db.exec("DELETE FROM discounts WHERE code=?1", &[&code]);
    Json(json!({"ok": true})).into_response()
}
