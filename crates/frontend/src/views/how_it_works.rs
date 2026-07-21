use dioxus::prelude::*;
use dioxus_i18n::t;

const DIAGRAM_SVG: &str = include_str!(concat!(env!("OUT_DIR"), "/diagram.svg"));

#[component]
pub fn how_it_works_view() -> Element {
    rsx! {
        div {
            class: "max-w-3xl mx-auto px-4 py-8 text-text",
            h1 {
                class: "text-4xl font-extrabold mb-8 text-center",
                {t!("how-it-works")}
            }

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
            }

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
                }
            }

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
}
