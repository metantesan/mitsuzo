use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn cli_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("cli-usage")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("cli-desc")}
            }
            div {
                class: "bg-bg rounded p-4 font-mono text-sm text-success space-y-1",
                p { {t!("cli-create")} }
                p { {t!("cli-get")} }
                p { {t!("cli-passwd")} }
                p { {t!("cli-account")} }
            }
            p {
                class: "text-muted text-sm mt-2",
                a {
                    href: "https://github.com/metantesan/mitsuzo/releases",
                    class: "text-accent hover:underline",
                    {t!("cli-download-link")}
                }
            }
        }
    }
}
