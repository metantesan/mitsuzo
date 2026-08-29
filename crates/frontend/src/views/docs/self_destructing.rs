use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn self_destructing_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("self-destructing")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("self-destruct-desc")}
            }
            ul {
                class: "list-disc list-inside text-text-secondary space-y-2",
                li { {t!("sd-item1")} }
                li { {t!("sd-item2")} }
                li { {t!("sd-item3")} }
                li { {t!("sd-item4")} }
            }
        }
    }
}
