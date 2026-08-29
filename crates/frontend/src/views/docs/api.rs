use dioxus::prelude::*;
use dioxus_i18n::t;

use super::api_row;

#[component]
pub fn api_section() -> Element {
    rsx! {
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
                api_row {
                    method: "POST",
                    path: "/api/account",
                    desc: t!("docs-api-account"),
                }
                api_row {
                    method: "GET",
                    path: "/api/account/{{kid}}",
                    desc: t!("docs-api-account-get"),
                }
                api_row {
                    method: "GET",
                    path: "/api/account/{{kid}}/challenge",
                    desc: t!("docs-api-account-challenge"),
                }
                api_row {
                    method: "POST",
                    path: "/api/account/{{kid}}/name",
                    desc: t!("docs-api-account-name"),
                }
            }
        }
    }
}
