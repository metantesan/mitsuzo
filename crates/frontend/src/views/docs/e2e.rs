use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn e2e_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("e2e-encryption")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("e2e-desc")}
            }
            ul {
                class: "list-disc list-inside text-text-secondary space-y-2",
                li { {t!("e2e-item1")} }
                li { {t!("e2e-item2")} }
                li { {t!("e2e-item3")} }
                li { {t!("e2e-item4")} }
                li { {t!("e2e-item5")} }
                li { {t!("e2e-item6")} }
                li { {t!("e2e-item7")} }
            }
        }
    }
}
