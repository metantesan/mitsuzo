use dioxus::prelude::*;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum PopupKind {
    Error,
    Success,
}

#[derive(Clone, Debug)]
pub struct PopupMessage {
    pub kind: PopupKind,
    pub message: String,
}

#[derive(Clone, Copy)]
pub struct PopupContext {
    pub message: Signal<Option<PopupMessage>>,
}

impl PopupContext {
    pub fn new() -> Self {
        Self {
            message: Signal::new(None),
        }
    }

    pub fn show_error(&mut self, msg: impl Into<String>) {
        self.message.set(Some(PopupMessage {
            kind: PopupKind::Error,
            message: msg.into(),
        }));
    }

    pub fn show_success(&mut self, msg: impl Into<String>) {
        self.message.set(Some(PopupMessage {
            kind: PopupKind::Success,
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
    let msg_opt = ctx.read().message.read().clone();
    let style_class = match msg_opt.as_ref().map(|m| m.kind) {
        Some(PopupKind::Error) => "bg-danger/10 border-danger/30",
        Some(PopupKind::Success) => "bg-success/10 border-success/30",
        None => "",
    };

    rsx! {
        if let Some(msg) = msg_opt {
            div {
                class: "fixed top-4 left-1/2 -translate-x-1/2 z-50 border {style_class} text-text px-6 py-4 rounded-xl shadow-2xl max-w-md w-full text-center backdrop-blur-sm animate-slide-up",
                button {
                    class: "absolute top-1 right-2 text-text-secondary hover:text-text text-xl leading-none transition-colors",
                    onclick: move |_| {
                        ctx.write().clear();
                    },
                    "\u{00d7}"
                }
                div {
                    class: "font-semibold",
                    "{msg.message}"
                }
            }
        } else {
            Fragment {}
        }
    }
}
