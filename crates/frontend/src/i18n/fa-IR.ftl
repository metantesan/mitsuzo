app-title = Mitsuzo

nav-home = خانه
nav-how-it-works = نحوه کارکرد
nav-changelog = تغییرات
nav-download = دانلود

changelog-title = تغییرات
changelog-current = فعلی

disable-download = غیرفعال کردن دانلود (فقط پیش‌نمایش)
home-placeholder = محتوای خود را اینجا وارد کنید...
or-upload-file = یا یک فایل بارگذاری کنید:
choose-file = انتخاب فایل...
password-placeholder = رمز عبور برای رمزگذاری وارد کنید
password-auto-gen-hint = برای رمز عبور خودکار خالی بگذارید
try-count-label = تعداد تلاش (۰ برای نامحدود)
ttl-label = TTL به ثانیه
create-paste = ایجاد Paste

paste-created = Paste ایجاد شد!
paste-id = ID: { $id }
remember-password = لطفاً رمز عبور خود را به خاطر بسپارید.

view-existing-paste = مشاهده Paste موجود
enter-paste-id = ID پیست را وارد کنید
view-paste = مشاهده Paste

stats-title = آمار
stats-description = ایجاد شده = کل پیست‌های بارگذاری شده. رمزگشایی شده = بازدیدهای موفق. رمز عبور اشتباه = تلاش‌های ناموفق رمزگشایی.
all-time = همه زمان‌ها
today = امروز
created = ایجاد شده
decrypted = رمزگشایی شده
wrong-password = رمز عبور اشتباه


clear = پاک کردن

progress-validating = در حال اعتبارسنجی ورودی...
progress-processing-file = در حال پردازش فایل...
progress-processing-text = در حال پردازش متن...
progress-encrypting = در حال رمزگذاری محتوا...
progress-encrypting-percent = در حال رمزگذاری... { $percent }%
progress-initiating-upload = در حال شروع بارگذاری...
progress-preparing-upload = در حال آماده‌سازی بارگذاری...
progress-upload-percent = در حال بارگذاری... { $percent }%
progress-upload-kb = در حال بارگذاری... { $kb } KB ارسال شد
progress-upload-complete = بارگذاری کامل شد!
progress-finalizing = در حال نهایی‌سازی...
progress-reading-file = در حال خواندن فایل...
progress-file-loaded = فایل بارگذاری شد
progress-downloading-metadata = در حال دانلود metadata...
progress-deriving-key = در حال مشتق‌سازی کلید رمزگذاری...
progress-downloading-content = در حال دانلود محتوا...
progress-downloading-percent = در حال دانلود... { $percent }%
progress-downloading-kb = در حال دانلود... { $kb } KB
progress-decrypting = در حال رمزگشایی...
progress-decrypting-percent = در حال رمزگشایی... { $percent }%

error-password-empty = رمز عبور نمی‌تواند خالی باشد.
error-content-empty = محتوا نمی‌تواند خالی باشد.
error-ttl-invalid = TTL باید یک عدد معتبر باشد.
error-encryption-failed = رمزگذاری محتوا ناموفق بود: { $error }
error-parse-response-failed = پردازش پاسخ ناموفق بود: { $error }
error-empty-response = بدنه پاسخ خالی است
error-create-paste-failed = ایجاد Paste ناموفق بود: HTTP { $status }
error-send-request-failed = ارسال درخواست ناموفق بود: { $error }
error-decode-salt-failed = رمزگشایی پاسخ Salt ناموفق بود: { $error }
error-empty-salt-response = پاسخ Salt خالی است
error-get-salt-failed = دریافت Salt ناموفق بود: HTTP { $status }
error-salt-request-failed = ارسال درخواست Salt ناموفق بود: { $error }
error-argon2-params-failed = ایجاد پارامترهای Argon2 ناموفق بود: { $error }
error-key-derivation-failed = مشتق‌سازی کلید ناموفق بود: { $error }
error-decode-paste-failed = رمزگشایی پاسخ Paste ناموفق بود: { $error }
error-get-paste-failed = دریافت Paste ناموفق بود: HTTP { $status }
error-decryption-failed = رمزگشایی ناموفق بود: { $error }
error-read-file-failed = خواندن فایل ناموفق بود: { $error }

paste-view-title = مشاهده Paste
decrypt-password-placeholder = رمز عبور رمزگشایی را وارد کنید
decrypt-paste = رمزگشایی Paste
tries-left = تلاش‌های باقی‌مانده: { $count }
time-left = زمان باقی‌مانده: { $time } ثانیه
file-preview = پیش‌نمایش فایل
file-ready-download = فایل آماده دانلود است
download-file = دانلود فایل
enter-password-desc = رمز عبور را وارد کنید و روی «رمزگشایی Paste» کلیک کنید.

how-it-works = نحوه کارکرد
e2e-encryption = رمزگذاری E2E
e2e-desc = Pasteها در مرورگر شما قبل از ارسال رمزگذاری می‌شوند. Argon2id یک کلید اصلی ۳۲ بایتی تولید می‌کند، سپس HKDF-SHA256 آن را به دو کلید مستقل گسترش می‌دهد — یکی برای رمزگذاری و یکی برای اعتبارسنجی رمز عبور. کلیدها هرگز دستگاه شما را ترک نمی‌کنند.
e2e-item1 = Argon2id(password, salt) → کلید اصلی ۳۲ بایت (۱۹۴۵۶ KiB memory, 2 iterations)
e2e-item2 = HKDF-SHA256(master, "mitsuzo-encryption-key") → کلید رمزگذاری ۳۲ بایت
e2e-item3 = HKDF-SHA256(master, "mitsuzo-validation-key") → کلید اعتبارسنجی ۳۲ بایت
e2e-item4 = ChaCha20-Poly1305(encryption_key, derived_nonce, plaintext) → متن رمزگذاری‌شده
e2e-item5 = فایل‌های >۶۴KB به تکه‌های ۶۴KB تقسیم می‌شوند، هر کدام با nonce مشتق‌شده منحصربه‌فرد رمزگذاری می‌شوند
e2e-item6 = نمک ۱۶ بایت و nonce پایه ۱۲ بایت منحصربه‌فرد برای هر Paste
e2e-item7 = سرور هرگز رمز عبور یا متن اصلی شما را نمی‌بیند
zk-validation = اعتبارسنجی رمز عبور Zero-Knowledge
zk-desc = سرور رمز عبور شما را بدون دانستن آن اعتبارسنجی می‌کند. به این شکل:
zk-step1 = Argon2id + HKDF دو کلید encryption_key و validation_key از رمز عبور مشتق می‌کنند
zk-step2 = مرورگر HMAC-SHA256(validation_key, salt) را محاسبه کرده و به سرور می‌فرستد
zk-step3 = سرور فقط این hash را ذخیره می‌کند — نه key، salt یا password
zk-step4 = هنگام مشاهده، مرورگر کلیدها و hash را مجدداً مشتق کرده و در هدر X-Password-Hash ارسال می‌کند
zk-step5 = سرور hashها را با زمان ثابت (XOR-based) مقایسه می‌کند
zk-note = حتی سرور نفوذ شده نمی‌تواند Pasteها را رمزگشایی کند یا رمزهای عبور را بازیابی کند.
workflow-diagram = نمودار جریان کار
self-destructing = Pasteهای خودمخرب
self-destruct-desc = شما عمر Paste خود را کنترل می‌کنید. زمان حیات (TTL) و حداکثر تعداد تلاش را تعیین کنید.
sd-item1 = حذف خودکار پس از انقضای TTL (حداکثر ۱۲ ساعت)
sd-item2 = محدودیت تعداد تلاش برای امنیت بیشتر (۱-۱۰۰ تلاش)
sd-item3 = Paste هنگامی که تعداد تلاش به ۰ برسد دائماً حذف می‌شود
sd-item4 = تلاش‌های شکست‌خورده رمزگشایی به تعداد تلاش اضافه می‌شوند
proof-safety = اثبات امنیت
proof-safety-desc = امنیت داده‌های شما توسط رمزگذاری E2E تضمین شده است. سرور فقط تکه‌های رمزگذاری شده و HMAC کلید اعتبارسنجی را ذخیره می‌کند.
ps-item1 = حتی نفوذ به سرور نمی‌تواند داده‌های اصلی شما را افشا کند
ps-item2 = بدون در پشت — کلیدهای رمزگشایی فقط در مرورگر یا CLI شما وجود دارند
ps-item3 = Pasteهای خودمخرب پنجره آسیب‌پذیری را کم می‌کنند
ps-item4 = تلاش‌های ناموفق را می‌توان برای جلوگیری از حملات brute-force محدود کرد
cli-usage = کلاینت CLI
cli-desc = Mitsuzo یک کلاینت CLI کراس‌پلتفرم برای ایجاد و دریافت Paste از ترمینال نیز دارد.
cli-create = ایجاد: mitsuzo create [-f file] [-c tries] [-t ttl]
cli-get = دریافت: mitsuzo get <id> [-o output]
stats-title-section = آمار
stats-desc-section = سرور شمارنده‌های ناشناس استفاده را ثبت می‌کند.
stats-item1 = کل Pasteهای ایجاد شده (همه زمان‌ها / روزانه)
stats-item2 = کل رمزگشایی‌های موفق (همه زمان‌ها / روزانه)
stats-item3 = کل تلاش‌های ناموفق رمز عبور (همه زمان‌ها / روزانه)
stats-item4 = قابل مشاهده در صفحه اصلی و
cli-download-link = دانلود باینری‌های از پیش ساخته شده در GitHub
footer-created = ساخته شده توسط
footer-author = هیکاری
footer-github = گیت‌هاب
footer-tagline = برای یک نفر ساخته شد. برای هر کسی که به آن نیاز دارد.