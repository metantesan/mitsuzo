use crate::Route;
use dioxus::prelude::*;
use dioxus_i18n::{prelude::*, t};
use unic_langid::langid;

#[component]
pub fn Navbar() -> Element {
    let mut i18n = i18n();
    let mut menu_open = use_signal(|| false);

    rsx! {
        nav {
            class: "bg-gray-800 p-4 text-white flex justify-between items-center",
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
                    class: "hover:text-blue-400",
                    {t!("nav-home")}
                }
                Link {
                    to: Route::HowItWorks {},
                    class: "hover:text-blue-400",
                    {t!("nav-how-it-works")}
                }
                Link {
                    to: Route::Changelog {},
                    class: "hover:text-blue-400",
                    {t!("nav-changelog")}
                }
                select {
                    class: "bg-gray-700 text-white rounded px-2 py-1 text-sm border border-gray-600",
                    value: i18n.language().to_string(),
                    onchange: move |evt| {
                        let lang = evt.value();
                        match lang.as_str() {
                            "en-US" => i18n.set_language(langid!("en-US")),
                            "fa-IR" => i18n.set_language(langid!("fa-IR")),
                            _ => {}
                        }
                    },
                    option {
                        value: "en-US",
                        "English"
                    }
                    option {
                        value: "fa-IR",
                        "فارسی"
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
                    class: "fixed inset-0 bg-gray-900/50 z-40",
                    onclick: move |_| menu_open.set(false),
                }
                div {
                    class: "fixed top-0 right-0 w-64 h-full bg-gray-800 z-50 p-6 flex flex-col space-y-4 shadow-lg",
                    button {
                        class: "self-end text-white text-2xl",
                        onclick: move |_| menu_open.set(false),
                        "✕"
                    }
                    Link {
                        to: Route::Home {},
                        class: "text-lg hover:text-blue-400",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-home")}
                    }
                    Link {
                        to: Route::HowItWorks {},
                        class: "text-lg hover:text-blue-400",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-how-it-works")}
                    }
                    Link {
                        to: Route::Changelog {},
                        class: "text-lg hover:text-blue-400",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-changelog")}
                    }
                    select {
                        class: "bg-gray-700 text-white rounded px-2 py-1 text-sm border border-gray-600 mt-4",
                        value: i18n.language().to_string(),
                        onchange: move |evt| {
                            let lang = evt.value();
                            match lang.as_str() {
                                "en-US" => i18n.set_language(langid!("en-US")),
                                "fa-IR" => i18n.set_language(langid!("fa-IR")),
                                _ => {}
                            }
                        },
                        option { value: "en-US", "English" }
                        option { value: "fa-IR", "فارسی" }
                    }
                }
            }
        }
    }
}
