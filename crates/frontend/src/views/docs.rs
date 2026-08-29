use dioxus::prelude::*;
use dioxus_i18n::t;

use crate::views::changelog_section;

const DIAGRAM_SVG: &str = include_str!(concat!(env!("OUT_DIR"), "/diagram.svg"));

#[component]
pub fn docs_view() -> Element {
    rsx! {
        div {
            class: "max-w-3xl mx-auto px-4 py-8 text-text",
            h1 {
                class: "text-4xl font-extrabold mb-4 text-center",
                {t!("docs-title")}
            }
            p {
                class: "text-text-secondary text-center mb-8",
                {t!("docs-intro")}
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

            section {
                class: "mb-8 p-6 bg-surface rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-accent",
                    {t!("docs-api-title")}
                }
                p {
                    class: "text-text-secondary mb-4",
                    {t!("docs-api-desc")}
                }
                div {
                    class: "space-y-3 text-sm",
                    api_row {
                        method: "POST",
                        path: "/api/paste",
                        desc: t!("docs-api-init"),
                    }
                    api_row {
                        method: "PUT",
                        path: "/api/paste/{{id}}/chunk/{{i}}",
                        desc: t!("docs-api-chunk-put"),
                    }
                    api_row {
                        method: "GET",
                        path: "/api/paste/{{id}}/chunks",
                        desc: t!("docs-api-chunks"),
                    }
                    api_row {
                        method: "POST",
                        path: "/api/paste/{{id}}/complete",
                        desc: t!("docs-api-complete"),
                    }
                    api_row {
                        method: "GET",
                        path: "/api/paste/{{id}}/salt",
                        desc: t!("docs-api-salt"),
                    }
                    api_row {
                        method: "GET",
                        path: "/api/paste/{{id}}/data",
                        desc: t!("docs-api-data"),
                    }
                    api_row {
                        method: "GET",
                        path: "/api/paste/{{id}}",
                        desc: t!("docs-api-get"),
                    }
                    api_row {
                        method: "POST",
                        path: "/api/paste/{{id}}/password",
                        desc: t!("docs-api-password"),
                    }
                    api_row {
                        method: "POST",
                        path: "/api/paste/{{id}}/burn",
                        desc: t!("docs-api-burn"),
                    }
                    api_row {
                        method: "GET",
                        path: "/api/paste/stats",
                        desc: t!("docs-api-stats"),
                    }
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
                    p { {t!("cli-passwd")} }
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
                class: "mb-8 p-6 bg-surface rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-accent",
                    {t!("docs-selfhost-title")}
                }
                p {
                    class: "text-text-secondary mb-4",
                    {t!("docs-selfhost-desc")}
                }
                h3 {
                    class: "text-lg font-bold mb-2 text-text",
                    {t!("docs-selfhost-docker")}
                }
                div {
                    class: "bg-bg rounded p-4 font-mono text-sm text-success mb-4 overflow-auto",
                    code { "docker run -p 3030:3030 ghcr.io/metantesan/mitsuzo:latest" }
                }
                h3 {
                    class: "text-lg font-bold mb-2 text-text",
                    {t!("docs-selfhost-env")}
                }
                div {
                    class: "overflow-auto mb-4",
                    table {
                        class: "w-full text-sm text-text-secondary",
                        thead {
                            tr {
                                class: "border-b border-border text-left",
                                th { class: "py-2 pr-4", "Variable" }
                                th { class: "py-2 pr-4", "Default" }
                                th { class: "py-2 pr-4", "Demo" }
                                th { class: "py-2", "Description" }
                            }
                        }
                        tbody {
                            tr {
                                class: "border-b border-border/50",
                                td { class: "py-2 pr-4 font-mono text-xs", "MITSUZO_DEMO_MODE" }
                                td { class: "py-2 pr-4", "unset" }
                                td { class: "py-2 pr-4", "1" }
                                td { class: "py-2", {t!("docs-env-demo-desc")} }
                            }
                            tr {
                                class: "border-b border-border/50",
                                td { class: "py-2 pr-4 font-mono text-xs", "MITSUZO_MAX_TTL_SECONDS" }
                                td { class: "py-2 pr-4", "43200 (12 h)" }
                                td { class: "py-2 pr-4", "60 (1 min)" }
                                td { class: "py-2", {t!("docs-env-ttl-desc")} }
                            }
                            tr {
                                td { class: "py-2 pr-4 font-mono text-xs", "MITSUZO_MAX_FILE_SIZE_BYTES" }
                                td { class: "py-2 pr-4", "1073741824 (1 GB)" }
                                td { class: "py-2 pr-4", "5242880 (5 MB)" }
                                td { class: "py-2", {t!("docs-env-size-desc")} }
                            }
                        }
                    }
                }
                h3 {
                    class: "text-lg font-bold mb-2 text-text",
                    {t!("docs-selfhost-build")}
                }
                div {
                    class: "bg-bg rounded p-4 font-mono text-sm text-success space-y-1 mb-4 overflow-auto",
                    p { "cd crates/frontend && dx build --release && cd ../.." }
                    p { "cargo build --release -p backend -p cli" }
                    p { "./target/release/backend" }
                }
                p {
                    class: "text-muted text-sm",
                    {t!("docs-selfhost-more")}
                }
            }

            changelog_section {}

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

#[component]
fn api_row(method: String, path: String, desc: String) -> Element {
    let method_color = match method.as_str() {
        "GET" => "bg-success/15 text-success",
        "POST" => "bg-accent/15 text-accent",
        "PUT" => "bg-accent-dim/15 text-accent-dim",
        _ => "bg-surface text-text-secondary",
    };
    rsx! {
        div {
            class: "flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3",
            span {
                class: "px-2 py-0.5 rounded font-mono text-xs font-bold {method_color} w-fit",
                "{method}"
            }
            code {
                class: "font-mono text-xs text-text",
                "{path}"
            }
            span {
                class: "text-text-secondary sm:ml-auto sm:text-right",
                "{desc}"
            }
        }
    }
}
