use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn burn_after_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("burn-after-title")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("burn-after-desc")}
            }
            ul {
                class: "list-disc list-inside text-text-secondary space-y-2",
                li { {t!("ba-item1")} }
                li { {t!("ba-item2")} }
                li { {t!("ba-item3")} }
                li { {t!("ba-item4")} }
            }
        }
    }
}
