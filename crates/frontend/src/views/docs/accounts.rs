use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn accounts_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("docs-accounts-title")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("docs-accounts-desc")}
            }
            ul {
                class: "list-disc list-inside text-text-secondary space-y-2",
                li { {t!("docs-accounts-item1")} }
                li { {t!("docs-accounts-item2")} }
                li { {t!("docs-accounts-item3")} }
                li { {t!("docs-accounts-item4")} }
                li { {t!("docs-accounts-item5")} }
            }
        }
    }
}
