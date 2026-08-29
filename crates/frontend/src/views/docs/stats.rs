use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn stats_section() -> Element {
    rsx! {
        section {
            class: "p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("stats-title-section")}
            }
            p {
                class: "text-text-secondary mb-4",
                {t!("stats-desc-section")}
            }
            ul {
                class: "list-disc list-inside text-text-secondary space-y-2",
                li { {t!("stats-item1")} }
                li { {t!("stats-item2")} }
                li { {t!("stats-item3")} }
                li { {t!("stats-item4")} " " code { "GET /api/paste/stats" } }
            }
        }
    }
}
