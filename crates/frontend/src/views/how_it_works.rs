use dioxus::prelude::*;
use dioxus_i18n::t;

const DIAGRAM_SVG: &str = include_str!(concat!(env!("OUT_DIR"), "/diagram.svg"));

#[component]
pub fn how_it_works_view() -> Element {

    rsx! {
        div {
            class: "container mx-auto p-4 text-white max-w-4xl",
            h1 {
                class: "text-4xl font-extrabold mb-8 text-center",
                {t!("how-it-works")}
            }

            section {
                class: "mb-8 p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-blue-400",
                    {t!("e2e-encryption")}
                }
                p {
                    class: "text-gray-300 mb-4",
                    {t!("e2e-desc")}
                }
                ul {
                    class: "list-disc list-inside text-gray-300 space-y-2",
                    li { code { "Argon2id(password, salt)" } " → 32-byte master key (19456 KiB memory, 2 iterations)" }
                    li { code { "HKDF-SHA256(master, \"mitsuzo-encryption-key\")" } " → 32-byte encryption key" }
                    li { code { "HKDF-SHA256(master, \"mitsuzo-validation-key\")" } " → 32-byte validation key" }
                    li { code { "ChaCha20-Poly1305(encryption_key, derived_nonce, plaintext)" } " → ciphertext" }
                    li { "Files >64KB are split into 64KB chunks, each encrypted with a unique derived nonce" }
                    li { "Unique 16-byte salt and 12-byte base nonce per paste" }
                    li { "Server never sees your password or plaintext" }
                }
            }

            section {
                class: "mb-8 p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-blue-400",
                    {t!("zk-validation")}
                }
                p {
                    class: "text-gray-300 mb-4",
                    {t!("zk-desc")}
                }
                ol {
                    class: "list-decimal list-inside text-gray-300 space-y-2 mb-4",
                    li { {t!("zk-step1")} }
                    li { {t!("zk-step2")} }
                    li { {t!("zk-step3")} }
                    li { {t!("zk-step4")} }
                    li { {t!("zk-step5")} }
                }
                p {
                    class: "text-gray-400 text-sm italic",
                    {t!("zk-note")}
                }
            }

            section {
                class: "mb-8 p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-blue-400",
                    {t!("workflow-diagram")}
                }
                div {
                    class: "mermaid overflow-auto",
                    dangerous_inner_html: DIAGRAM_SVG,
                }
            }

            section {
                class: "mb-8 p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-blue-400",
                    {t!("self-destructing")}
                }
                p {
                    class: "text-gray-300 mb-4",
                    {t!("self-destruct-desc")}
                }
                ul {
                    class: "list-disc list-inside text-gray-300 space-y-2",
                    li { {t!("sd-item1")} }
                    li { {t!("sd-item2")} }
                    li { {t!("sd-item3")} }
                    li { {t!("sd-item4")} }
                }
            }

            section {
                class: "mb-8 p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-blue-400",
                    {t!("proof-safety")}
                }
                p {
                    class: "text-gray-300 mb-4",
                    {t!("proof-safety-desc")}
                }
                ul {
                    class: "list-disc list-inside text-gray-300 space-y-2",
                    li { {t!("ps-item1")} }
                    li { {t!("ps-item2")} }
                    li { {t!("ps-item3")} }
                    li { {t!("ps-item4")} }
                }
            }

            section {
                class: "mb-8 p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-blue-400",
                    {t!("cli-usage")}
                }
                p {
                    class: "text-gray-300 mb-4",
                    {t!("cli-desc")}
                }
                div {
                    class: "bg-gray-900 rounded p-4 font-mono text-sm text-green-400 space-y-1",
                    p { {t!("cli-create")} }
                    p { {t!("cli-get")} }
                }
                p {
                    class: "text-gray-400 text-sm mt-2",
                    a {
                        href: "https://github.com/metantesan/mitsuzo/releases",
                        class: "text-blue-400 hover:underline",
                        "Download pre-built binaries on GitHub"
                    }
                }
            }

            section {
                class: "p-6 bg-gray-800 rounded-lg",
                h2 {
                    class: "text-2xl font-bold mb-4 text-blue-400",
                    {t!("stats-title-section")}
                }
                p {
                    class: "text-gray-300 mb-4",
                    {t!("stats-desc-section")}
                }
                ul {
                    class: "list-disc list-inside text-gray-300 space-y-2",
                    li { "Total pastes created (all-time / daily)" }
                    li { "Total successful decryptions (all-time / daily)" }
                    li { "Total failed password attempts (all-time / daily)" }
                    li { "Viewable at the homepage and " code { "GET /api/paste/stats" } }
                }
            }
        }
    }
}
