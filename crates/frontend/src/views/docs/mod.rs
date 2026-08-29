use dioxus::prelude::*;
use dioxus_i18n::t;

use crate::views::changelog_section;

use self::{
    accounts::accounts_section, api::api_section, burn_after::burn_after_section, cli::cli_section,
    e2e::e2e_section, proof_safety::proof_safety_section, security::security_section,
    self_destructing::self_destructing_section, selfhost::selfhost_section, stats::stats_section,
    workflow::workflow_section, zk::zk_section,
};

const DIAGRAM_SVG: &str = include_str!(concat!(env!("OUT_DIR"), "/diagram.svg"));

pub mod accounts;
pub mod api;
pub mod burn_after;
pub mod cli;
pub mod e2e;
pub mod proof_safety;
pub mod security;
pub mod self_destructing;
pub mod selfhost;
pub mod stats;
pub mod workflow;
pub mod zk;

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

            e2e_section {}
            zk_section {}
            workflow_section {}
            self_destructing_section {}
            burn_after_section {}
            proof_safety_section {}
            security_section {}
            api_section {}
            cli_section {}
            selfhost_section {}
            accounts_section {}
            changelog_section {}
            stats_section {}
        }
    }
}

/// Shared row used inside the API reference section.
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
