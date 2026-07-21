use dioxus::prelude::*;

#[derive(Clone, Debug)]
pub struct ErrorMessage {
    pub message: String,
}

#[derive(Clone, Copy)]
pub struct PopupContext {
    pub message: Signal<Option<ErrorMessage>>,
}

impl PopupContext {
    pub fn new() -> Self {
        Self {
            message: Signal::new(None),
        }
    }

    pub fn show_error(&mut self, msg: impl Into<String>) {
        self.message.set(Some(ErrorMessage {
            message: msg.into(),
        }));
    }

    pub fn clear(&mut self) {
        self.message.set(None);
    }
}

impl Default for PopupContext {
    fn default() -> Self {
        Self::new()
    }
}

#[component]
pub fn Popup() -> Element {
    let mut ctx = use_context::<Signal<PopupContext>>();
    let error_opt = ctx.read().message.read().clone();

    rsx! {
        if let Some(err) = error_opt {
            div {
                class: "fixed top-4 left-1/2 transform -translate-x-1/2 z-50 bg-red-600 text-white px-6 py-4 rounded-lg shadow-lg max-w-md w-full text-center",
                button {
                    class: "absolute top-1 right-2 text-white hover:text-gray-300 text-xl leading-none",
                    onclick: move |_| {
                        ctx.write().clear();
                    },
                    "\u{00d7}"
                }
                div {
                    class: "font-semibold",
                    "{err.message}"
                }
            }
        } else {
            Fragment {}
        }
    }
}
