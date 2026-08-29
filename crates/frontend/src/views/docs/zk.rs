use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn zk_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("zk-validation")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("zk-desc")}
            }
            ol {
                class: "list-decimal list-inside text-text-secondary space-y-2 mb-4",
                li { {t!("zk-step1")} }
                li { {t!("zk-step2")} }
                li { {t!("zk-step3")} }
                li { {t!("zk-step4")} }
                li { {t!("zk-step5")} }
            }
            p {
                class: "text-muted text-sm italic",
                {t!("zk-note")}
            }
        }
    }
}
