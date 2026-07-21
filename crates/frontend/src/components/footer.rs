use dioxus::prelude::*;
use dioxus_i18n::t;

pub const APP_VERSION: &str = match option_env!("APP_VERSION") {
    Some(v) => v,
    None => "dev",
};

#[component]
pub fn Footer() -> Element {
    rsx! {
        footer {
            class: "bg-gray-800 p-4 text-white text-center mt-8",
            "{APP_VERSION} · {t!(\"footer-created\")} ",
            a {
                href: "https://metantesan.com",
                class: "text-blue-400 hover:underline",
                {t!("footer-author")}
            }
            " · ",
            a {
                href: "https://github.com/metantesan/mitsuzo",
                class: "text-blue-400 hover:underline",
                {t!("footer-github")}
            }
            "."
        }
    }
}
