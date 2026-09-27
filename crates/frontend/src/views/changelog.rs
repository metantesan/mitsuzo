use crate::components::APP_VERSION;
use dioxus::prelude::*;
use dioxus_i18n::prelude::*;
use dioxus_i18n::t;
use unic_langid::langid;

struct Change {
    version: &'static str,
    date: &'static str,
    items_en: Vec<&'static str>,
    items_fa: Vec<&'static str>,
}

fn get_changelog() -> Vec<Change> {
    vec![
        Change {
            version: "v0.12.4",
            date: "2026-09-27",
            items_en: vec![
                "Upgraded SeaORM and SeaORM Migration to 2.0.3",
                "Upgraded Orion to 0.18 and migrated the ChaCha20-Poly1305 API without changing the ciphertext format",
                "Refreshed Dependabot dependencies and patched vulnerable transitive crates",
                "Made the Rust dependency audit report successfully in GitHub Actions",
            ],
            items_fa: vec![
                "ارتقای SeaORM و SeaORM Migration به نسخه ۲.۰.۳",
                "ارتقای Orion به نسخه ۰.۱۸ و مهاجرت API رمزنگاری ChaCha20-Poly1305 بدون تغییر فرمت ciphertext",
                "به‌روزرسانی وابستگی‌های Dependabot و رفع آسیب‌پذیری‌های وابستگی‌های غیرمستقیم",
                "اصلاح گزارش‌دهی audit وابستگی‌های Rust در GitHub Actions",
            ],
        },
        Change {
            version: "v0.12.3",
            date: "2026-09-27",
            items_en: vec![
                "Added a verified CLI installer at /install.sh with platform detection and SHA-256 checksum validation",
                "Added a public installer endpoint so the live demo can provide the CLI directly",
                "Documented one-command CLI installation and remote-server configuration",
                "CLI releases now target Linux x86_64/ARM64, macOS Apple Silicon, and Windows x86_64/ARM64",
            ],
            items_fa: vec![
                "افزودن installer تأییدشده CLI در /install.sh با تشخیص پلتفرم و اعتبارسنجی checksum با SHA-256",
                "افزودن endpoint عمومی installer تا دمو بتواند CLI را مستقیماً ارائه کند",
                "مستندسازی نصب یک‌دستوری CLI و پیکربندی سرور راه دور",
                "انتشار CLI برای Linux x86_64/ARM64، macOS Apple Silicon و Windows x86_64/ARM64",
            ],
        },
        Change {
            version: "v0.12.2",
            date: "2026-09-27",
            items_en: vec![
                "Fixed SeaORM startup runtime nesting so the migrated storage layer initializes reliably in the backend",
                "Published the v0.12.2 Docker and CLI release artifacts",
            ],
            items_fa: vec![
                "رفع تو در تو شدن runtime در زمان راه‌اندازی SeaORM تا لایه ذخیره‌سازی مهاجرت‌یافته به‌صورت پایدار در backend راه‌اندازی شود",
                "انتشار artifactهای Docker و CLI برای نسخه v0.12.2",
            ],
        },
        Change {
            version: "v0.12.1",
            date: "2026-09-27",
            items_en: vec![
                "Added a separate rate limit for upload chunks to reduce bandwidth and storage abuse on public demo deployments",
                "Bumped the workspace version to v0.12.1 and published the release",
            ],
            items_fa: vec![
                "افزودن محدودیت نرخ جداگانه برای تکه‌های آپلود جهت کاهش سوءاستفاده از پهنای باند و فضای ذخیره‌سازی در دموهای عمومی",
                "ارتقای نسخه workspace به v0.12.1 و انتشار release",
            ],
        },
        Change {
            version: "v0.10.1",
            date: "2026-08",
            items_en: vec![
                "Fixed all Clippy warnings (denied as errors): account key material and the sender's ephemeral key are now named structs instead of nested tuples, and redundant Signal re-bindings were removed",
                "Fixed the CLI release workflow: the `cli` crate now ships a binary named `mitsuzo`, and the workflow builds and publishes it under its actual artifact name",
            ],
            items_fa: vec![
                "رفع تمام هشدارهای Clippy (سطح deny): کلیدهای حساب و کلید موقت فرستنده به جای تاپل‌های تو در تو به ساختارهای نام‌گذاری‌شده تبدیل شدند و بازتعریف‌های اضافیِ Signal حذف شد",
                "رفع workflow انتشار CLI: کِرِیت `cli` اکنون باینری به نام `mitsuzo` تولید می‌کند و workflow آن را با نام اصلیِ خروجی می‌سازد و منتشر می‌کند",
            ],
        },
        Change {
            version: "v0.10.0",
            date: "2026-08",
            items_en: vec![
                "User accounts: a BIP39 seed phrase deterministically derives an X25519 key pair — the private key is password-wrapped and kept only on your device (browser localStorage or ~/.config/mitsuzo/account.enc), while the server stores only the public key and display name",
                "Paste-to-user (recipient mode): pastes are encrypted to an account's public key, sealing the content key with X25519 ECDH; by symmetry both the recipient and the sender (via the retained ephemeral key) can decrypt",
                "Challenge-based authentication: single-use X25519 challenges (60s TTL) replace password-derived hashes for login, inbox access, name changes, and fetching recipient-mode pastes (X-Account-Proof)",
                "Account profile pages and a per-account inbox listing recipient-mode pastes addressed to you",
                "GET /api/paste/{id}/salt now advertises the auth mode explicitly (Password | Recipient) instead of requiring clients to infer it",
            ],
            items_fa: vec![
                "حساب‌های کاربری: عبارت بازیابی BIP39 به‌صورت قطعی یک جفت‌کلید X25519 مشتق می‌کند — کلید خصوصی با رمز حساب کپسوله شده و فقط روی دستگاه شما نگهداری می‌شود (localStorage مرورگر یا ~/.config/mitsuzo/account.enc)، در حالی که سرور فقط کلید عمومی و نام نمایشی را ذخیره می‌کند",
                "ارسال به کاربر (حالت گیرنده): Pasteها با کلید عمومی حساب رمزنگاری می‌شوند و کلید محتوا با X25519 ECDH مهر می‌شود؛ به دلیل تقارن، هم گیرنده و هم فرستنده (با کلید موقت) می‌توانند رمزگشایی کنند",
                "احراز هویت مبتنی بر چالش: چالش‌های یک‌بارمصرف X25519 (TTL ۶۰ ثانیه) جایگزین هش‌های مشتق‌شده از رمز عبور برای ورود، صندوق ورودی، تغییر نام و دریافت Pasteهای حالت گیرنده (X-Account-Proof) شده‌اند",
                "صفحات پروفایل حساب و صندوق ورودی مخصوص هر حساب که Pasteهای حالت گیرنده ارسال‌شده به شما را فهرست می‌کند",
                "GET /api/paste/{id}/salt اکنون حالت احراز هویت را صریحاً اعلام می‌کند (Password | Recipient) به جای اینکه کلاینت‌ها مجبور به حدس زدن آن باشند",
            ],
        },
        Change {
            version: "v0.9.2",
            date: "2026-08",
            items_en: vec![
                "All paste metadata now requires the password: /salt returns only the Argon2id salt (needed to derive the validation key), while the wrapped content key, nonce, chunk/file info, and try count travel in the metadata frame (length-prefixed GetPasteHeader) of the authenticated /data response, together with the ciphertext",
                "Fixed wrong-password attempts not decrementing the try count and not counting toward the failure stats: the client short-circuited before contacting the server, so failed attempts were never recorded",
                "Failed attempts now answer 401 with the remaining try count and TTL in the body, so the UI stays in sync with the server's try-count enforcement",
                "Web UI and `cli passwd` obtain the metadata/wrapped key from the data frame; changing the password still never re-encrypts the ciphertext",
            ],
            items_fa: vec![
                "تمام متادیتای Paste اکنون به رمز عبور نیاز دارد: /salt فقط salt (فرایند Argon2id) را برمی‌گرداند — که برای مشتق کردن کلید اعتبارسنجی لازم است — در حالی که کلید محتوای کپسوله‌شده، nonce، اطلاعات تکه/فایل و تعداد تلاش در فریم متادیتا (GetPasteHeader با پیشوند طول) پاسخ احرازهویت‌شده /data و همراه با ciphertext ارسال می‌شوند",
                "رفع مشکل کاهش نیافتن تعداد تلاش و شمارش نشدن آمار شکست در رمز عبورهای اشتباه: کلاینت قبل از تماس با سرور متوقف می‌شد و تلاش‌های ناموفق هرگز ثبت نمی‌شدند",
                "تلاش‌های ناموفق اکنون با ۴۰۱ و بدنه‌ای شامل تعداد تلاش و TTL باقی‌مانده پاسخ می‌دهند تا رابط کاربری با اجرای تعداد تلاش در سمت سرور هماهنگ بماند",
                "رابط کاربری و `cli passwd` متادیتا/کلید کپسوله‌شده را از فریم داده دریافت می‌کنند؛ تغییر رمز همچنان هرگز ciphertext را دوباره رمزگذاری نمی‌کند",
            ],
        },
        Change {
            version: "v0.9.1",
            date: "2026-08",
            items_en: vec![
                "Fixed Docker builds: removed the dev-only web proxy from Dioxus.toml, which newer dioxus-cli releases rejected",
                "Default BASE_URL now points to the local backend (http://localhost:3030) for same-origin development without the proxy",
            ],
            items_fa: vec![
                "رفع بیلد داکر: حذف پروکسی مخصوص توسعه از Dioxus.toml که نسخه‌های جدیدتر dioxus-cli آن را رد می‌کردند",
                "مقدار پیش‌فرض BASE_URL اکنون به بک‌اند محلی (http://localhost:3030) اشاره می‌کند تا توسعه بدون پروکسی و با آدرس نسبی امکان‌پذیر باشد",
            ],
        },
        Change {
            version: "v0.9.0",
            date: "2026-08",
            items_en: vec![
                "Envelope encryption: pastes are encrypted with a random per-paste content key, wrapped with the password-derived key (Argon2id + HKDF)",
                "Changeable password: re-wraps only the content key — paste data is never re-encrypted or re-uploaded",
                "New 'Change password' section in the web UI after decryption, and a `cli passwd <id>` subcommand",
                "New POST /api/paste/{id}/password endpoint with old-password authentication, try-count enforcement, and rate limiting",
                "Legacy pastes created before this version still decrypt via the old direct derived-key path",
                "Burn-after-read receipts are now derived from the content key, so they stay valid across password changes",
                "How It Works page, workflow diagram, and README updated to document the new key hierarchy",
                "New /docs page consolidating How It Works with a security model spec, API reference, and self-hosting guide",
            ],
            items_fa: vec![
                "رمزگذاری پاکتی: داده‌ها با یک کلید محتوای تصادفی مخصوص هر Paste رمزگذاری می‌شوند که با کلید مشتق‌شده از رمز عبور (Argon2id + HKDF) کپسوله می‌شود",
                "تغییر رمز عبور: فقط کلید محتوا دوباره کپسوله می‌شود — داده‌های Paste هرگز رمزگذاری یا بارگذاری مجدد نمی‌شوند",
                "بخش جدید «تغییر رمز عبور» در رابط کاربری پس از رمزگشایی و زیرفرمان `cli passwd <id>` در CLI",
                "ان‌پوینت جدید POST /api/paste/{id}/password با احرازهویت رمز قدیمی، اجرای تعداد تلاش و محدودیت نرخ",
                "Pasteهای قدیمیِ ساخته‌شده قبل از این نسخه همچنان از مسیر مستقیم مشتق کلید رمزگشایی می‌شوند",
                "رسید حذف پس از مشاهده اکنون از کلید محتوا مشتق می‌شود و با تغییر رمز عبور معتبر می‌ماند",
                "به‌روزرسانی صفحه نحوه کارکرد، نمودار جریان کار و README برای مستندسازی سلسله‌مراتب جدید کلیدها",
                "صفحه جدید /docs شامل نحوه کارکرد به‌همراه مستندات مدل امنیتی، مرجع API و راهنمای اجرای اختصاصی",
            ],
        },
        Change {
            version: "v0.8.0",
            date: "2026-08",
            items_en: vec![
                "Live demo runtime: run with `MITSUZO_DEMO_MODE=1` to cap pastes at a 1-minute TTL and a 5 MB max size",
                "Limits are configurable via `MITSUZO_MAX_TTL_SECONDS` and `MITSUZO_MAX_FILE_SIZE_BYTES`",
                "Show a 'Live demo' badge and a limit notice in the frontend",
                "Server now truly enforces the maximum TTL and paste size during upload",
            ],
            items_fa: vec![
                "رانتایم دموی زنده: با `MITSUZO_DEMO_MODE=1` عمر پیست‌ها به ۱ دقیقه و حداکثر اندازه به ۵ مگابایت محدود می‌شود",
                "محدودیت‌ها از طریق `MITSUZO_MAX_TTL_SECONDS` و `MITSUZO_MAX_FILE_SIZE_BYTES` قابل تنظیم‌اند",
                "نمایش نشان «دمو زنده» و اطلاع‌رسانی محدودیت‌ها در رابط کاربری",
                "اجرای واقعی محدودیت حداکثر TTL و اندازه پیست توسط سرور هنگام بارگذاری",
            ],
        },
        Change {
            version: "v0.7.5",
            date: "2026-08",
            items_en: vec!["Upgraded Dioxus to 0.7.10 to match the dx CLI"],
            items_fa: vec!["ارتقای Dioxus به نسخه 0.7.10 برای هماهنگی با dx CLI"],
        },
        Change {
            version: "v0.7.4",
            date: "2026-08",
            items_en: vec![
                "Fixed a deadlock in expired-paste cleanup that could freeze the server and stop it accepting connections",
            ],
            items_fa: vec![
                "رفع بن‌بست در پاک‌سازی پیست‌های منقضی‌شده که می‌توانست سرور را قفل کرده و پذیرش اتصال را متوقف کند",
            ],
        },
        Change {
            version: "v0.7.3",
            date: "2026-08",
            items_en: vec![
                "Removed signal handling and graceful shutdown — the shutdown watchdog thread could exit the process silently with no log and no container restart, leaving the app dead without a trace. Server now simply runs until stopped.",
            ],
            items_fa: vec![
                "حذف مدیریت سیگنال و خاموش‌شدن تدریجی — ترد واک‌داگ می‌توانست فرایند را بدون هیچ لاگ و بدون ری‌استارت کانتینر بی‌صدا متوقف کند و برنامه را بدون هیچ اثری از کار بیندازد. سرور اکنون به سادگی اجرا می‌شود تا زمانی که متوقف شود.",
            ],
        },
        Change {
            version: "v0.7.2",
            date: "2026-08",
            items_en: vec![
                "Success popup notification when copying to clipboard — green toast shown on every copy action",
            ],
            items_fa: vec!["اعلان موفقیت هنگام کپی در کلیپ‌بورد — نمایش پیام سبز در هر عملیات کپی"],
        },
        Change {
            version: "v0.7.1",
            date: "2026-08",
            items_en: vec![
                "ETag support with If-None-Match/304 responses for index.html and robots.txt",
                "Reliable graceful shutdown: signals caught on a dedicated thread, bounded DB flush, and a watchdog that force-exits within Docker's grace period",
            ],
            items_fa: vec![
                "پشتیبانی ETag با پاسخ‌های If-None-Match/304 برای index.html و robots.txt",
                "خاموش‌شدن تدریجی مطمئن: دریافت سیگنال‌ها در یک ترد جدا، محدودسازی زمان flush دیتابیس و واک‌داگ برای خروج اجباری در محدوده‌ی مهلت Docker",
            ],
        },
        Change {
            version: "v0.7.0",
            date: "2026-07",
            items_en: vec![
                "Refactored complex tuple types into named structs across the entire codebase",
                "Replaced unsafe unwrap() calls with proper error handling via eyre/color-eyre",
                "Added graceful shutdown with Sled DB flush on SIGTERM and Ctrl+C",
                "Fixed race condition in paste cleanup with a dedicated deletion mutex",
                "Removed duplicate code — merged serve_index/fallback_to_index, replaced compute_total_size with get_plaintext_size",
                "Mobile home page: preset buttons now stack vertically on small screens using grid layout",
                "Styled checkboxes to match the dark \"Warm Vault\" theme",
                "Added GitHub issue and PR templates",
            ],
            items_fa: vec![
                "بازنویسی نوع‌های تاپل پیچیده به ساختارهای نام‌گذاری‌شده در سراسر کدبیس",
                "جایگزینی فراخوانی‌های ناایمن unwrap() با مدیریت خطای مناسب با eyre/color-eyre",
                "افزودن خاموش‌شدن تدریجی با Sled DB flush در SIGTERM و Ctrl+C",
                "رفع شرط رقابتی در پاک‌سازی Paste با استفاده از قفل حذف",
                "حذف کد تکراری — ادغام serve_index/fallback_to_index و جایگزینی compute_total_size با get_plaintext_size",
                "صفحه اصلی موبایل: دکمه‌های پیش‌انتخاب با استفاده از grid به صورت عمودی در صفحه‌های کوچک",
                "استایل چک‌باکس‌ها مطابق با تم تیره «Warm Vault»",
                "افزودن قالب‌های issue و PR در گیت‌هاب",
            ],
        },
        Change {
            version: "v0.6.1",
            date: "2026-07",
            items_en: vec!["Burn receipt uses HKDF-SHA256 instead of HMAC + SHA256 double-hash"],
            items_fa: vec!["رسید حذف از HKDF-SHA256 به جای HMAC + SHA256 استفاده می‌کند"],
        },
        Change {
            version: "v0.6.0",
            date: "2026-07",
            items_en: vec![
                "Burn-after-read mode — paste auto-deletes after first successful decryption",
                "Cryptographic burn receipt (HMAC-SHA256 + SHA256) verifies client decrypted content",
                "Rate limiting on paste creation (10/minute per IP) to prevent spam",
                "Drag-and-drop file upload across the entire form area",
                "TTL preset buttons (5min, 1hr, 12hr) with custom fallback",
                "Try-count preset buttons (1, 5, 25, 100) with custom fallback",
                "Burn-after-read support in CLI with --burn-after-read flag",
            ],
            items_fa: vec![
                "حالت حذف پس از مشاهده — Paste پس از اولین رمزگشایی موفق حذف می‌شود",
                "رسید رمزنگاری (HMAC-SHA256 + SHA256) رمزگشایی محتوا را اثبات می‌کند",
                "محدودیت نرخ در ایجاد Paste (۱۰ بار در دقیقه به ازای هر IP)",
                "آپلود فایل با کشیدن و رها کردن در کل فرم",
                "دکمه‌های پیش‌انتخاب TTL (۵ دقیقه، ۱ ساعت، ۱۲ ساعت) با گزینه دلخواه",
                "دکمه‌های پیش‌انتخاب تعداد تلاش (۱، ۵، ۲۵، ۱۰۰) با گزینه دلخواه",
                "پشتیبانی از حذف پس از مشاهده در CLI با پرچم --burn-after-read",
            ],
        },
        Change {
            version: "v0.5.0",
            date: "2026-07",
            items_en: vec![
                "Chunked upload with resume support — split ciphertext into 16MB chunks",
                "Parallel upload (8 concurrent chunks) with retry and exponential backoff",
                "Parallel download via HTTP Range requests with retry",
                "Parallel encryption/decryption across all CPU cores",
                "New /data endpoint for raw ciphertext download with Range support",
                "Separate /chunks and /complete endpoints for resumable uploads",
                "CLI progress bars with percentage, ETA, and human-readable sizes",
                "Colored CLI output with spinners and status indicators",
                "Backward-incompatible: old monolithic POST endpoint replaced",
            ],
            items_fa: vec![
                "آپلود تکه‌تکه با قابلیت ادامه — تقسیم متن رمزگذاری‌شده به تکه‌های ۱۶MB",
                "آپلود موازی (۸ تکه هم‌زمان) با تلاش مجدد و پشتیبان نمایی",
                "دانلود موازی با درخواست‌های HTTP Range و تلاش مجدد",
                "رمزگذاری/رمزگشایی موازی روی همه هسته‌های CPU",
                "ان‌پوینت جدید /data برای دانلود خام ciphertext با پشتیبانی Range",
                "ان‌پوینت‌های مجزا /chunks و /complete برای آپلود قابل ادامه",
                "نوار پیشرفت در CLI با درصد، زمان تخمینی و اندازه‌های قابل خواندن",
                "خروجی رنگی CLI با اسپینر و نشانگر وضعیت",
                "شکستن سازگاری با نسخه‌های قبلی — ان‌پوینت قدیمی POST حذف شد",
            ],
        },
        Change {
            version: "v0.4.0",
            date: "2026-07",
            items_en: vec![
                "Complete visual overhaul — \"Warm Vault\" dark theme with amber accent palette",
                "Custom scrollbar, text selection, and focus ring styling across the entire UI",
                "Typography: Karla (UI) + JetBrains Mono (code) via Google Fonts",
                "Sticky navbar with backdrop blur, active page indicator underline, hover transitions",
                "Redesigned cards, inputs, buttons with consistent border and transition system",
                "All E2E encryption list items now properly use i18n translations (EN/FA)",
                "Fixed Persian translations: self-destruct description now says تلاش instead of بازدید",
                "Animated page transitions (fade-in) and slide-in popup notifications",
                "Navbar active route highlighting with animated underline indicator",
            ],
            items_fa: vec![
                "بازطراحی کامل ظاهری — تم تیره «Warm Vault» با پالت کهربایی",
                "استایل اختصاصی اسکرول‌بار، انتخاب متن، و حلقه فوکوس در سراسر رابط کاربری",
                "تایپوگرافی: Karla (رابط کاربری) + JetBrains Mono (کد) از Google Fonts",
                "نوار ناوبری چسبنده با افکت محو، نشانگر صفحه فعال، transition هاور",
                "بازطراحی کارت‌ها، ورودی‌ها، دکمه‌ها با سیستم حاشیه و transition یکپارچه",
                "تمام آیتم‌های لیست رمزگذاری E2E اکنون از ترجمه i18n استفاده می‌کنند",
                "رفع ترجمه فارسی توضیحات خودمخرب — تغییر «بازدید» به «تلاش»",
                "انیمیشن انتقال صفحه (fade-in) و اعلان پاپ‌آپ با slide-in",
                "نشانگر مسیر فعال در ناوبری با خط زیر متحرک",
            ],
        },
        Change {
            version: "v0.3.8",
            date: "2026-07",
            items_en: vec![
                "Preview support for text/*, application/json, video/*, audio/*, application/pdf",
                "Disable download (preview-only) checkbox for file uploads",
                "Fix profile warning — moved [profile.release] to workspace root",
            ],
            items_fa: vec![
                "پشتیبانی از پیش‌نمایش text/*, application/json, video/*, audio/*, application/pdf",
                "چک‌باکس غیرفعال کردن دانلود (فقط پیش‌نمایش) برای آپلود فایل",
                "رفع اخطار پروفایل — انتقال [profile.release] به ریشه ورک‌اسپیس",
            ],
        },
        Change {
            version: "v0.3.7",
            date: "2026-07",
            items_en: vec!["Catppuccin Mocha theme — new color palette across the entire UI"],
            items_fa: vec!["تم Catppuccin Mocha — پالت رنگی جدید در سراسر رابط کاربری"],
        },
        Change {
            version: "v0.3.6",
            date: "2026-07",
            items_en: vec![
                "Native Rust mermaid renderer (mermaid-rs-renderer) — pre-rendered SVG, no JS runtime",
                "WASM binary ~90% smaller (profile opts, debug stripping, wasm-opt)",
                "HKDF-based key derivation documented in How It Works page",
                "Language preference saved to localStorage and restored on reload",
                "EN/FA toggle buttons replace dropdown for one-click language switching",
                "Persian translation for stats labels, download, author, and GitHub",
                "GitHub link in footer, Download link in navbar",
                "Localized \"Leave empty for auto-generated password\" hint",
            ],
            items_fa: vec![
                "رندر بومی Mermaid با Rust — SVG پیش‌ساخته در زمان کامپایل، بدون JS در زمان اجرا",
                "بهینه‌سازی WASM با کاهش ~۹۰٪ حجم",
                "مستندسازی کلید مشتق‌شده با HKDF در صفحه نحوه کارکرد",
                "ذخیره زبان انتخاب‌شده در localStorage و بازیابی در بارگذاری بعدی",
                "دکمه‌های EN/FA برای تغییر زبان یک‌کلیکی",
                "ترجمه فارسی برچسب‌های آمار، دانلود، نویسنده و گیت‌هاب",
                "لینک گیت‌هاب در فوتر، لینک دانلود در نوار ناوبری",
                "راهنمای ترجمه‌شده «برای رمز عبور خودکار خالی بگذارید»",
            ],
        },
        Change {
            version: "v0.3.0",
            date: "2026-07",
            items_en: vec![
                "Zero-copy: framed protocol eliminates bitcode wrapping of large blobs",
                "Chunked encryption/decryption writes directly to buffer, no per-chunk allocation",
                "Streaming server responses — paste content streamed from disk without full memory load",
                "Progress bars for encryption and decryption with async yielding (no UI freeze)",
                "Client-side file size check against 1GB limit before processing",
                "Chunked file reading from JS File API — only 64KB in WASM at a time",
                "Added Persian i18n for progress and decryption messages",
            ],
            items_fa: vec![
                "بازنویسی با کپی صفر: پروتکل فریم‌بندی شده و حذف بیت‌کد از داده‌های حجیم",
                "رمزگذاری/رمزگشایی تکه‌تکه با نوشتن مستقیم در بافر، بدون تخصیص موقت",
                "پاسخ استریمینگ سرور — محتوای Paste مستقیماً از دیسک استریم می‌شود",
                "نوار پیشرفت برای رمزگذاری و رمزگشایی با تاخیرهای ناهمزمان (بدون هنگ کردن رابط)",
                "بررسی حجم فایل در سمت کاربر قبل از پردازش",
                "خواندن تکه‌تکه فایل از API فایل جاوااسکریپت — فقط 64KB در WASM در هر لحظه",
                "افزودن ترجمه فارسی برای پیام‌های پیشرفت و رمزگشایی",
            ],
        },
        Change {
            version: "v0.2.0",
            date: "2025-06",
            items_en: vec![
                "Key separation: derive encryption and validation keys independently from Argon2id",
                "HMAC-SHA256 for password validation instead of plain SHA-256",
                "Chunk-based encryption (64KB chunks) to reduce browser memory usage for large files",
                "Constant-time password hash comparison to prevent timing attacks",
                "Auto-generated random password when password field is left empty",
                "URL hash (#password) support for one-click paste sharing",
                "Hamburger navigation menu on mobile devices",
                "Switched ChaCha20Poly1305 implementation to the orion crate",
            ],
            items_fa: vec![
                "جداسازی کلیدها: استخراج مستقل کلید رمزگذاری و اعتبارسنجی از Argon2id",
                "استفاده از HMAC-SHA256 به جای SHA-256 ساده برای اعتبارسنجی رمز عبور",
                "رمزگذاری تکه‌تکه (64KB) برای کاهش مصرف حافظه مرورگر در فایل‌های حجیم",
                "مقایسه هش رمز عبور با زمان ثابت برای جلوگیری از حملات timing",
                "تولید خودکار رمز عبور تصادفی در صورت خالی گذاشتن فیلد رمز",
                "پشتیبانی از هش (#password) در URL برای اشتراک‌گذاری یک‌کلیکی Paste",
                "منوی همبرگری برای ناوبری در دستگاه‌های همراه",
                "مهاجرت پیاده‌سازی ChaCha20Poly1305 به کتابخانه orion",
            ],
        },
        Change {
            version: "v0.1.2",
            date: "2025-05",
            items_en: vec![
                "Add changelog page",
                "Strip Unicode bidi isolate characters from paste IDs",
                "Fix double % in upload/download progress display",
                "Replace native file input with localized \"Choose file\" button",
                "Fix Persian translation - keep technical terms in English",
            ],
            items_fa: vec![
                "افزودن صفحه تغییرات",
                "حذف کاراکترهای مخفی Unicode bidi از شناسه‌های Paste",
                "رفع نمایش درصد دوتایی در نوار پیشرفت بارگذاری/دانلود",
                "جایگزینی دکمه فایل محلی با دکمه «انتخاب فایل» ترجمه‌شده",
                "رفع ترجمه فارسی - حفظ اصطلاحات فنی به انگلیسی",
            ],
        },
        Change {
            version: "v0.1.1",
            date: "2025-05",
            items_en: vec!["Fix WASM panic when XHR callbacks modify Dioxus Signals"],
            items_fa: vec!["رفع خطای WASM هنگام تغییر Signalهای Dioxus توسط XHR callbackها"],
        },
    ]
}

#[component]
pub fn changelog_section() -> Element {
    let i18n = i18n();
    let is_fa = i18n.language() == langid!("fa-IR");
    let changelog = get_changelog();
    let current_version = APP_VERSION;

    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("changelog-title")}
            }
            {changelog.into_iter().map(|entry| {
                let is_current = entry.version == current_version;
                let version = entry.version.to_string();
                let date = entry.date.to_string();
                let items = if is_fa { entry.items_fa.clone() } else { entry.items_en.clone() };
                let card_class = if is_current {
                    "mb-4 p-4 bg-bg rounded-lg ring-2 ring-accent".to_string()
                } else {
                    "mb-4 p-4 bg-bg rounded-lg".to_string()
                };
                rsx! {
                    div {
                        class: "{card_class}",
                        div {
                            class: "flex items-center justify-between mb-3",
                            h3 {
                                class: "text-lg font-bold text-text",
                                "{version}"
                            }
                            span {
                                class: "text-sm text-muted",
                                "{date}"
                            }
                        }
                        if is_current {
                            span {
                                class: "inline-block mb-3 px-2 py-0.5 text-xs font-semibold bg-accent text-bg rounded",
                                {t!("changelog-current")}
                            }
                        }
                        ul {
                            class: "list-disc list-inside text-text-secondary space-y-1",
                            for item in items {
                                li { "{item}" }
                            }
                        }
                    }
                }
            })}
        }
    }
}
