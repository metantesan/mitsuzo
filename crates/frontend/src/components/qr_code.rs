use base64::{Engine as _, engine::general_purpose};
use dioxus::prelude::*;
use dioxus_i18n::t;
use qrcode::QrCode as Qr;
use qrcode::render::svg;

/// A quiet, self-contained QR card for sharing a paste link.
///
/// The complete URL is encoded, including the password fragment when the
/// paste uses an auto-generated password. The browser never sends the
/// fragment to the server.
#[component]
pub fn QrCode(url: String) -> Element {
    let svg = Qr::new(url.as_bytes())
        .map(|code| {
            code.render::<svg::Color>()
                .min_dimensions(192, 192)
                .dark_color(svg::Color("#0a0a10"))
                .light_color(svg::Color("#ffffff"))
                .build()
        })
        .unwrap_or_default();
    let image_url = format!(
        "data:image/svg+xml;base64,{}",
        general_purpose::STANDARD.encode(svg.as_bytes())
    );

    rsx! {
        div {
            class: "flex shrink-0 flex-col items-center gap-2 rounded-lg bg-white p-3 text-center shadow-sm",
            img {
                class: "h-48 w-48",
                src: "{image_url}",
                alt: t!("qr-code-label"),
            }
            span {
                class: "text-[11px] font-medium text-bg/70",
                {t!("qr-scan-hint")}
            }
        }
    }
}
