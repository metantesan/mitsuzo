//! The components module contains all shared components for our app. Components are the building blocks of dioxus apps.
//! They can be used to defined common UI elements like buttons, forms, and modals.

mod navbar;
pub use navbar::Navbar;

mod footer;
pub use footer::APP_VERSION;
pub use footer::Footer;

mod popup;
pub use popup::{Popup, PopupContext};
