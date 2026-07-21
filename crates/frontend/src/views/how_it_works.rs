use dioxus::prelude::*;
use dioxus_i18n::t;
use wasm_bindgen::JsCast;

const MERMAID_JS: &str = include_str!("../../assets/mermaid.min.js");

#[component]
pub fn how_it_works_view() -> Element {
    use_effect(|| {
        let window = web_sys::window().unwrap();
        let document = window.document().unwrap();

        let script = document.create_element("script").unwrap();
        let script: web_sys::HtmlScriptElement = script.dyn_into().unwrap();
        let _ = script.set_text(MERMAID_JS);
        document.body().unwrap().append_child(&script).unwrap();

        let init_fn = js_sys::Function::new_with_args(
            "",
            r#"
                mermaid.initialize({startOnLoad:false,theme:'dark'});
                setTimeout(function() { mermaid.run(); }, 100);
            "#,
        );
        let _ = init_fn.call0(&wasm_bindgen::JsValue::NULL);
    });

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
                    {t!("e2e-desc", algo1: "ChaCha20-Poly1305", algo2: "Argon2id")}
                }
                ul {
                    class: "list-disc list-inside text-gray-300 space-y-2",
                    li { code { "Argon2id(password, salt)" } " → 64 bytes: 32-byte encryption_key + 32-byte validation_key" }
                    li { "Encryption: " code { "ChaCha20-Poly1305(encryption_key, nonce, plaintext)" } " → ciphertext" }
                    li { "Files larger than 64KB are split into chunks, each encrypted with a unique nonce" }
                    li { {t!("e2e-item3")} }
                    li { {t!("e2e-item4")} }
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
                    li { {t!("zk-step1", algo1: "Argon2id")} }
                    li { {t!("zk-step2", hash: "HMAC-SHA256")} }
                    li { {t!("zk-step3")} }
                    li { {t!("zk-step4", header: "X-Password-Hash")} }
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
                    class: "mermaid",
                    {r#"
sequenceDiagram
    participant U as User
    participant B as Browser
    participant S as Server

    Note over U,S:CREATE PASTE
    U->>B:Text/File + Password (or empty for auto-generated)
    B->>B:Generate random salt (16 bytes)
    B->>B:raw = Argon2id(password, salt, 64 bytes)
    B->>B:Split: encryption_key[0..32] + validation_key[32..64]
    B->>B:If file >64KB, split into chunks, encrypt each with derived nonce
    B->>B:Encrypt with ChaCha20-Poly1305(encryption_key)
    B->>B:hash = HMAC-SHA256(validation_key, salt)
    B->>S:POST /api/paste {encrypted_chunks,nonce,salt,hash,total_chunks}
    Note right of S:Stores: id → (encrypted,nonce,salt,hash,total_chunks)
    S->>B:Return paste ID

    Note over U,S:VIEW PASTE (via link with #password in URL hash)
    U->>B:Paste ID + Password (auto-extracted from hash)
    B->>S:GET /api/paste/{id}/salt
    S->>B:Return {salt,try_count,ttl,total_chunks}
    B->>B:raw = Argon2id(password, salt, 64 bytes)
    B->>B:Split: encryption_key + validation_key
    B->>B:hash = HMAC-SHA256(validation_key, salt)
    B->>S:GET /api/paste/{id} + Header X-Password-Hash
    alt Hash matches
        S->>B:Return {encrypted_chunks,nonce,total_chunks}
        B->>B:Split chunks, decrypt each with derived nonce
        B->>B:Reassemble plaintext
        B->>U:Display plaintext
    else Hash mismatch
        S->>S:try_count--
        S->>S:if try_count==0, delete paste
        S->>B:401 Unauthorized
    end
"#}
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
                class: "p-6 bg-gray-800 rounded-lg",
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
        }
    }
}
