use crate::components::{Footer, Navbar, Popup};
use dioxus::prelude::*;
use dioxus_i18n::prelude::*;
use unic_langid::langid;

#[component]
pub fn app_layout() -> Element {
    let i18n = i18n();
    let dir = if i18n.language() == langid!("fa-IR") {
        "rtl"
    } else {
        "ltr"
    };

    rsx! {
        div {
            class: "min-h-screen flex flex-col bg-bg text-text",
            dir: "{dir}",
            div {
                class: "fixed inset-0 pointer-events-none bg-gradient-to-b from-accent/5 via-transparent to-transparent"
            }
            Popup {}
            Navbar {},
            main {
                class: "flex-grow animate-fade-in",
                Outlet::<crate::Route> {}
            },
            Footer {}
        }
    }
}
