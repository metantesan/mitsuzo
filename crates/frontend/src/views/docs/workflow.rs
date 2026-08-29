use dioxus::prelude::*;
use dioxus_i18n::t;

use super::DIAGRAM_SVG;

#[component]
pub fn workflow_section() -> Element {
    rsx! {
        section {
            class: "mb-8 p-6 bg-surface rounded-lg",
            h2 {
                class: "text-2xl font-bold mb-4 text-accent",
                {t!("workflow-diagram")}
            }
            div {
                class: "mermaid overflow-auto",
                dangerous_inner_html: DIAGRAM_SVG,
            }
            p {
                class: "text-sm text-text-secondary mt-4",
                {t!("workflow-legend")}
            }
            ul {
                class: "list-disc list-inside text-sm text-text-secondary space-y-1 mt-2",
                li { {t!("workflow-legend-password")} }
                li { {t!("workflow-legend-recipient")} }
                li { {t!("workflow-legend-accounts")} }
            }
        }
    }
}
