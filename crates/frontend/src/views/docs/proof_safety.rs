use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn proof_safety_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("proof-safety")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("proof-safety-desc")}
            }
            ul {
                class: "list-disc list-inside text-text-secondary space-y-2",
                li { {t!("ps-item1")} }
                li { {t!("ps-item2")} }
                li { {t!("ps-item3")} }
                li { {t!("ps-item4")} }
                li { {t!("ps-item5")} }
            }
        }
    }
}
