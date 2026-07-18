mod components;
mod utils;
mod views;
use crate::views::paste_view as P;
use crate::views::{
    app_layout, changelog_view as Changelog, home_view as Home, how_it_works_view as HowItWorks,
    paste_view as Paste,
};
use components::PopupContext;
use dioxus::prelude::*;
use dioxus_i18n::prelude::*;
use unic_langid::langid;

pub const BASE_URL: &str = match option_env!("BASE_URL") {
    Some(url) => url,
    None => "http://localhost:3030",
};

#[derive(Routable, Clone)]
#[rustfmt::skip]
enum Route {
    #[layout(app_layout)]
    #[route("/")]
    Home {},
    #[route("/how-it-works")]
    HowItWorks {},
    #[route("/changelog")]
    Changelog {},
    #[route("/paste/:id")]
    Paste { id: String },
   #[route("/p/:id")]
   P{id:String},
}

pub fn sanitize_id(id: &str) -> String {
    id.chars()
        .filter(|c| {
            !matches!(
                c,
                '\u{2066}'
                    | '\u{2067}'
                    | '\u{2068}'
                    | '\u{2069}'
                    | '\u{200E}'
                    | '\u{200F}'
                    | '\u{202A}'
                    | '\u{202B}'
                    | '\u{202C}'
                    | '\u{202D}'
                    | '\u{202E}'
            )
        })
        .collect()
}

fn main() {
    wasm_logger::init(wasm_logger::Config::default());

    if let Some(storage) = web_sys::window().and_then(|w| w.session_storage().ok().flatten())
        && let Ok(hash) = web_sys::window().unwrap().location().hash()
        && !hash.is_empty()
        && hash != "#"
    {
        let _ = storage.set_item("paste_hash", &hash);
    }

    dioxus::launch(app);
}

fn app() -> Element {
    use_init_i18n(|| {
        I18nConfig::new(langid!("en-US"))
            .with_locale((langid!("en-US"), include_str!("i18n/en-US.ftl")))
            .with_locale((langid!("fa-IR"), include_str!("i18n/fa-IR.ftl")))
    });

    let popup_ctx = use_signal(PopupContext::new);
    use_context_provider(|| popup_ctx);

    rsx! {
        document::Stylesheet { href: asset!("assets/tailwind.css") },
        Router::<Route> {}
    }
}
