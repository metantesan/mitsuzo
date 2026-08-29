use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn security_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("docs-security-title")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("docs-security-desc")}
            }
            ul {
                class: "list-disc list-inside text-text-secondary space-y-2",
                li { {t!("docs-security-item1")} }
                li { {t!("docs-security-item2")} }
                li { {t!("docs-security-item3")} }
                li { {t!("docs-security-item4")} }
                li { {t!("docs-security-item5")} }
                li { {t!("docs-security-item6")} }
                li { {t!("docs-security-item7")} }
            }
        }
    }
}
