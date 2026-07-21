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
            class: "min-h-screen flex flex-col bg-base text-text",
            dir: "{dir}",
            Popup {}
            Navbar {},
            div {
                class: "flex-grow",
                Outlet::<crate::Route> {}
            },
            Footer {}
        }
    }
}
