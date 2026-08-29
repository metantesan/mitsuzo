use dioxus::prelude::*;
use dioxus_i18n::t;

#[component]
pub fn selfhost_section() -> Element {
    rsx! {
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
    }
}
