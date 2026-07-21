use crate::Route;
use dioxus::prelude::*;
use dioxus_i18n::{prelude::*, t};
use unic_langid::langid;

const GITHUB_RELEASES: &str = "https://github.com/metantesan/mitsuzo/releases";

#[component]
pub fn Navbar() -> Element {
    let mut i18n = i18n();
    let mut menu_open = use_signal(|| false);
    let current_lang = i18n.language();

    rsx! {
        nav {
            class: "bg-surface0 p-4 text-text flex justify-between items-center",
            div {
                class: "text-2xl font-bold",
                Link {
                    to: Route::Home {},
                    {t!("app-title")}
                }
            }
            div {
                class: "hidden md:flex space-x-4 items-center",
                Link {
                    to: Route::Home {},
                    class: "hover:text-blue",
                    {t!("nav-home")}
                }
                Link {
                    to: Route::HowItWorks {},
                    class: "hover:text-blue",
                    {t!("nav-how-it-works")}
                }
                Link {
                    to: Route::Changelog {},
                    class: "hover:text-blue",
                    {t!("nav-changelog")}
                }
                a {
                    href: GITHUB_RELEASES,
                    class: "hover:text-green",
                    {t!("nav-download")}
                }
                div {
                    class: "flex border border-surface1 rounded overflow-hidden",
                    button {
                        class: if current_lang == langid!("en-US") { "px-2 py-1 text-sm bg-blue text-crust" } else { "px-2 py-1 text-sm bg-overlay0 hover:bg-overlay1 text-text" },
                        onclick: move |_| {
                            i18n.set_language(langid!("en-US"));
                            if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
                                let _ = s.set_item("mitsuzo-lang", "en-US");
                            }
                        },
                        "EN"
                    }
                    button {
                        class: if current_lang == langid!("fa-IR") { "px-2 py-1 text-sm bg-blue text-crust" } else { "px-2 py-1 text-sm bg-overlay0 hover:bg-overlay1 text-text" },
                        onclick: move |_| {
                            i18n.set_language(langid!("fa-IR"));
                            if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
                                let _ = s.set_item("mitsuzo-lang", "fa-IR");
                            }
                        },
                        "FA"
                    }
                }
            }
            button {
                class: "md:hidden flex flex-col space-y-1 p-2",
                onclick: move |_| {
                    let current = menu_open();
                    menu_open.set(!current);
                },
                span { class: "block w-6 h-0.5 bg-white" }
                span { class: "block w-6 h-0.5 bg-white" }
                span { class: "block w-6 h-0.5 bg-white" }
            }
            if menu_open() {
                div {
                    class: "fixed inset-0 bg-crust/50 z-40",
                    onclick: move |_| menu_open.set(false),
                }
                div {
                    class: "fixed top-0 right-0 w-64 h-full bg-surface0 z-50 p-6 flex flex-col space-y-4 shadow-lg",
                    button {
                        class: "self-end text-text text-2xl",
                        onclick: move |_| menu_open.set(false),
                        "✕"
                    }
                    Link {
                        to: Route::Home {},
                        class: "text-lg hover:text-blue",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-home")}
                    }
                    Link {
                        to: Route::HowItWorks {},
                        class: "text-lg hover:text-blue",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-how-it-works")}
                    }
                    Link {
                        to: Route::Changelog {},
                        class: "text-lg hover:text-blue",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-changelog")}
                    }
                    a {
                        href: GITHUB_RELEASES,
                        class: "text-lg hover:text-green",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-download")}
                    }
                    div {
                        class: "flex border border-surface1 rounded overflow-hidden mt-4",
                        button {
                            class: if current_lang == langid!("en-US") { "flex-1 px-2 py-1 text-sm bg-blue text-crust" } else { "flex-1 px-2 py-1 text-sm bg-overlay0 hover:bg-overlay1 text-text" },
                            onclick: move |_| {
                                i18n.set_language(langid!("en-US"));
                                if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
                                    let _ = s.set_item("mitsuzo-lang", "en-US");
                                }
                            },
                            "EN"
                        }
                        button {
                            class: if current_lang == langid!("fa-IR") { "flex-1 px-2 py-1 text-sm bg-blue text-crust" } else { "flex-1 px-2 py-1 text-sm bg-overlay0 hover:bg-overlay1 text-text" },
                            onclick: move |_| {
                                i18n.set_language(langid!("fa-IR"));
                                if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
                                    let _ = s.set_item("mitsuzo-lang", "fa-IR");
                                }
                            },
                            "FA"
                        }
                    }
                }
            }
        }
    }
}
