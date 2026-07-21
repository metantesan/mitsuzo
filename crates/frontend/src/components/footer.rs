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
            class: "bg-surface p-4 text-text-secondary text-sm text-center mt-auto border-t border-border",
            "{APP_VERSION} · {t!(\"footer-created\")} ",
            a {
                href: "https://metantesan.com",
                class: "text-accent hover:text-accent-hover transition-colors",
                {t!("footer-author")}
            }
            " · ",
            a {
                href: "https://github.com/metantesan/mitsuzo",
                class: "text-accent hover:text-accent-hover transition-colors",
                {t!("footer-github")}
            }
            "."
        }
    }
}
