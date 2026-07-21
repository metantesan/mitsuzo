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
            version: "v0.3.7",
            date: "2026-07",
            items_en: vec![
                "Catppuccin Mocha theme — new color palette across the entire UI",
            ],
            items_fa: vec![
                "تم Catppuccin Mocha — پالت رنگی جدید در سراسر رابط کاربری",
            ],
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
pub fn changelog_view() -> Element {
    let i18n = i18n();
    let is_fa = i18n.language() == langid!("fa-IR");
    let changelog = get_changelog();
    let current_version = APP_VERSION;

    rsx! {
        div {
            class: "container mx-auto p-4 max-w-3xl",
            h1 {
                class: "text-3xl font-bold text-text mb-8 text-center",
                {t!("changelog-title")}
            }
            {changelog.into_iter().map(|entry| {
                let is_current = entry.version == current_version;
                let version = entry.version.to_string();
                let date = entry.date.to_string();
                let items = if is_fa { entry.items_fa.clone() } else { entry.items_en.clone() };
                let card_class = if is_current {
                    "mb-6 p-5 bg-surface0 rounded-lg ring-2 ring-blue".to_string()
                } else {
                    "mb-6 p-5 bg-surface0 rounded-lg".to_string()
                };
                rsx! {
                    div {
                        class: "{card_class}",
                        div {
                            class: "flex items-center justify-between mb-3",
                            h2 {
                                class: "text-xl font-bold text-text",
                                "{version}"
                            }
                            span {
                                class: "text-sm text-overlay0",
                                "{date}"
                            }
                        }
                        if is_current {
                            span {
                                class: "inline-block mb-3 px-2 py-0.5 text-xs font-semibold bg-blue text-text rounded",
                                {t!("changelog-current")}
                            }
                        }
                        ul {
                            class: "list-disc list-inside text-subtext0 space-y-1",
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
