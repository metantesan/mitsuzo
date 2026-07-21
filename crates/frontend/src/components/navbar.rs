use crate::Route;
use dioxus::prelude::*;
use dioxus_i18n::{prelude::*, t};
use unic_langid::langid;

const GITHUB_RELEASES: &str = "https://github.com/metantesan/mitsuzo/releases";

fn link_classes(active: bool) -> &'static str {
    if active {
        "text-accent after:w-full"
    } else {
        "text-text-secondary hover:text-accent after:w-0 hover:after:w-full"
    }
}

#[component]
pub fn Navbar() -> Element {
    let mut i18n = i18n();
    let mut menu_open = use_signal(|| false);
    let current_lang = i18n.language();
    let current_route = use_route::<Route>();

    let home_cls = format!(
        "px-3 py-1.5 text-sm font-medium relative transition-colors after:absolute after:bottom-0 after:left-1/2 after:-translate-x-1/2 after:h-0.5 after:bg-accent after:transition-all duration-200 {}",
        link_classes(current_route == Route::Home {})
    );
    let how_cls = format!(
        "px-3 py-1.5 text-sm font-medium relative transition-colors after:absolute after:bottom-0 after:left-1/2 after:-translate-x-1/2 after:h-0.5 after:bg-accent after:transition-all duration-200 {}",
        link_classes(current_route == Route::HowItWorks {})
    );
    let changelog_cls = format!(
        "px-3 py-1.5 text-sm font-medium relative transition-colors after:absolute after:bottom-0 after:left-1/2 after:-translate-x-1/2 after:h-0.5 after:bg-accent after:transition-all duration-200 {}",
        link_classes(current_route == Route::Changelog {})
    );

    let en_active = current_lang == langid!("en-US");
    let fa_active = current_lang == langid!("fa-IR");
    let is_rtl = fa_active;
    let menu_panel_cls = if is_rtl {
        "fixed top-0 left-0 w-64 h-full bg-elevated border-r border-border z-50 p-6 flex flex-col gap-4 shadow-2xl animate-slide-up"
    } else {
        "fixed top-0 right-0 w-64 h-full bg-elevated border-l border-border z-50 p-6 flex flex-col gap-4 shadow-2xl animate-slide-up"
    };

    rsx! {
        nav {
            class: "sticky top-0 z-30 bg-surface border-b border-border",
            div {
                class: "max-w-5xl mx-auto px-4 h-14 flex items-center justify-between",
                Link {
                    to: Route::Home {},
                    class: "text-lg font-bold text-accent tracking-tight hover:text-accent-hover transition-colors",
                    {t!("app-title")}
                }
                div {
                    class: "hidden md:flex items-center gap-1",
                    Link {
                        to: Route::Home {},
                        class: "{home_cls}",
                        {t!("nav-home")}
                    }
                    Link {
                        to: Route::HowItWorks {},
                        class: "{how_cls}",
                        {t!("nav-how-it-works")}
                    }
                    Link {
                        to: Route::Changelog {},
                        class: "{changelog_cls}",
                        {t!("nav-changelog")}
                    }
                    a {
                        href: GITHUB_RELEASES,
                        class: "px-3 py-1.5 text-sm font-medium text-text-secondary hover:text-accent transition-colors",
                        {t!("nav-download")}
                    }
                    div {
                        class: "ml-4 flex border border-border rounded overflow-hidden",
                        button {
                            class: if en_active { "px-3 py-1 text-xs font-semibold bg-accent text-bg transition-colors" } else { "px-3 py-1 text-xs font-medium text-text-secondary hover:text-text hover:bg-elevated transition-colors" },
                            onclick: move |_| {
                                i18n.set_language(langid!("en-US"));
                                if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
                                    let _ = s.set_item("mitsuzo-lang", "en-US");
                                }
                            },
                            "EN"
                        }
                        button {
                            class: if fa_active { "px-3 py-1 text-xs font-semibold bg-accent text-bg transition-colors" } else { "px-3 py-1 text-xs font-medium text-text-secondary hover:text-text hover:bg-elevated transition-colors" },
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
                    class: "md:hidden flex flex-col gap-1 p-2 text-text-secondary hover:text-accent transition-colors",
                    onclick: move |_| {
                        let current = menu_open();
                        menu_open.set(!current);
                    },
                    span { class: "block w-5 h-0.5 bg-current rounded" }
                    span { class: "block w-5 h-0.5 bg-current rounded" }
                    span { class: "block w-5 h-0.5 bg-current rounded" }
                }
            }
            if menu_open() {
                div {
                    class: "fixed inset-0 bg-black/50 z-40",
                    onclick: move |_| menu_open.set(false),
                }
                div {
                    class: "{menu_panel_cls}",
                    div {
                        class: "flex items-center justify-between mb-2",
                        span {
                            class: "text-sm font-semibold text-accent tracking-widest uppercase",
                            {t!("app-title")}
                        }
                        button {
                            class: "text-text-secondary hover:text-text transition-colors text-lg",
                            onclick: move |_| menu_open.set(false),
                            "✕"
                        }
                    }
                    Link {
                        to: Route::Home {},
                        class: "text-sm font-medium text-text-secondary hover:text-accent transition-colors",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-home")}
                    }
                    Link {
                        to: Route::HowItWorks {},
                        class: "text-sm font-medium text-text-secondary hover:text-accent transition-colors",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-how-it-works")}
                    }
                    Link {
                        to: Route::Changelog {},
                        class: "text-sm font-medium text-text-secondary hover:text-accent transition-colors",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-changelog")}
                    }
                    a {
                        href: GITHUB_RELEASES,
                        class: "text-sm font-medium text-text-secondary hover:text-accent transition-colors",
                        onclick: move |_| menu_open.set(false),
                        {t!("nav-download")}
                    }
                    div {
                        class: "flex border border-border rounded overflow-hidden mt-4",
                        button {
                            class: if en_active { "flex-1 px-3 py-1.5 text-xs font-semibold bg-accent text-bg transition-colors" } else { "flex-1 px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text hover:bg-elevated transition-colors" },
                            onclick: move |_| {
                                i18n.set_language(langid!("en-US"));
                                if let Some(s) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
                                    let _ = s.set_item("mitsuzo-lang", "en-US");
                                }
                            },
                            "EN"
                        }
                        button {
                            class: if fa_active { "flex-1 px-3 py-1.5 text-xs font-semibold bg-accent text-bg transition-colors" } else { "flex-1 px-3 py-1.5 text-xs font-medium text-text-secondary hover:text-text hover:bg-elevated transition-colors" },
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
