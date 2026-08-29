use crate::BASE_URL;
use crate::Route;
use crate::components::PopupContext;
use crate::utils::{do_xhr_get, do_xhr_post};
use base64::{Engine as _, engine::general_purpose};
use bip39::Mnemonic;
use dioxus::prelude::*;
use dioxus_i18n::t;
use mitsuzo_types::{
    AccountKeyBlob, AccountProfileResponse, ChallengeResponse, ChangeNameRequest, DataType,
    InboxResponse, PasteInboxListing, RegisterAccountRequest,
};
use mitsuzo_utils::{
    derive_account_scalar, kid_from_pubkey, lock_account_key, open_challenge, pubkey_from_scalar,
    unlock_account_key,
};
use serde::{Deserialize, Serialize};

pub const ACCOUNT_STORAGE_KEY: &str = "mitsuzo-account";

/// Decrypted account state, held in memory only while logged in.
#[derive(Clone, PartialEq)]
pub struct AccountSession {
    pub scalar: [u8; 32],
    pub kid: [u8; 32],
    pub kid_prefix: [u8; 20],
    pub pubkey: [u8; 32],
    pub name: String,
}

impl AccountSession {
    pub fn kid_prefix_hex(&self) -> String {
        hex(&self.kid_prefix)
    }
}

/// Recipient picked from a profile page's "Send encrypted message" button.
#[derive(Clone, PartialEq)]
pub struct RecipientTarget {
    pub kid: [u8; 32],
    pub kid_prefix: [u8; 20],
    pub pubkey: [u8; 32],
    pub name: String,
}

impl RecipientTarget {
    pub fn kid_prefix_hex(&self) -> String {
        hex(&self.kid_prefix)
    }
}

/// Sender-held ephemeral key for a created recipient paste, kept for the
/// current session so the sender can reopen their own paste (in-session).
#[derive(Clone, PartialEq)]
pub struct RecipientEphemeral {
    pub paste_id: String,
    pub recipient_kid: [u8; 32],
    pub ephemeral_priv: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PersistedAccount {
    pub name: String,
    /// Full 32-byte kid, hex.
    pub kid: String,
    /// Base64 of the 32-byte public key.
    pub pubkey: String,
    /// Base64 of the bitcode-encoded `AccountKeyBlob`.
    pub blob: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

pub fn persisted_account() -> Option<PersistedAccount> {
    let s = storage()?;
    let raw = s.get_item(ACCOUNT_STORAGE_KEY).ok().flatten()?;
    serde_json::from_str(&raw).ok()
}

fn save_persisted(account: &PersistedAccount) {
    if let Some(s) = storage()
        && let Ok(raw) = serde_json::to_string(account)
    {
        let _ = s.set_item(ACCOUNT_STORAGE_KEY, &raw);
    }
}

pub fn use_account() -> Signal<Option<AccountSession>> {
    use_context::<Signal<Option<AccountSession>>>()
}

pub fn use_recipient_target() -> Signal<Option<RecipientTarget>> {
    use_context::<Signal<Option<RecipientTarget>>>()
}

pub fn use_recipient_ephemerals() -> Signal<Vec<RecipientEphemeral>> {
    use_context::<Signal<Vec<RecipientEphemeral>>>()
}

/// Generate a 24-word BIP39 mnemonic and the derived account key material.
pub fn new_account_key() -> Result<(String, [u8; 32], [u8; 32], [u8; 32]), String> {
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy).map_err(|e| format!("Failed to generate entropy: {}", e))?;
    let mnemonic = Mnemonic::from_entropy(&entropy)
        .map_err(|e| format!("Mnemonic generation failed: {}", e))?;
    let phrase = mnemonic.to_string();
    let seed = mnemonic.to_seed("");
    let scalar = derive_account_scalar(&seed);
    let pubkey = pubkey_from_scalar(&scalar);
    let kid = kid_from_pubkey(&pubkey);
    Ok((phrase, scalar, pubkey, kid))
}

/// Recover the key material from an existing seed phrase.
pub fn account_key_from_mnemonic(phrase: &str) -> Result<([u8; 32], [u8; 32], [u8; 32]), String> {
    let mnemonic =
        Mnemonic::parse(phrase.trim()).map_err(|e| format!("Invalid seed phrase: {}", e))?;
    let seed = mnemonic.to_seed("");
    let scalar = derive_account_scalar(&seed);
    let pubkey = pubkey_from_scalar(&scalar);
    let kid = kid_from_pubkey(&pubkey);
    Ok((scalar, pubkey, kid))
}

/// Persist the password-encrypted blob plus public metadata to localStorage.
fn persist_account(
    name: &str,
    scalar: &[u8; 32],
    pubkey: &[u8; 32],
    password: &str,
) -> Result<AccountKeyBlob, String> {
    let blob = lock_account_key(scalar, password)?;
    let kid = kid_from_pubkey(pubkey);
    save_persisted(&PersistedAccount {
        name: name.to_string(),
        kid: hex(&kid),
        pubkey: general_purpose::STANDARD.encode(pubkey),
        blob: general_purpose::STANDARD.encode(bitcode::encode(&blob)),
    });
    Ok(blob)
}

fn parse_hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap_or("ff"), 16).unwrap())
        .collect()
}

/// Load the local account blob and unlock it with the account password.
pub fn unlock_local_account(password: &str) -> Result<AccountSession, String> {
    let persisted = persisted_account().ok_or_else(|| "No local account found".to_string())?;
    let blob_bytes = general_purpose::STANDARD
        .decode(&persisted.blob)
        .map_err(|e| format!("Corrupt account blob: {}", e))?;
    let blob: AccountKeyBlob =
        bitcode::decode(&blob_bytes).map_err(|e| format!("Corrupt account blob: {}", e))?;
    let scalar = unlock_account_key(&blob, password)?;
    let kid = parse_hex(&persisted.kid);
    let pubkey = general_purpose::STANDARD
        .decode(&persisted.pubkey)
        .map_err(|_| "Corrupt account pubkey".to_string())?;
    let mut kid_arr = [0u8; 32];
    let mut pubkey_arr = [0u8; 32];
    kid_arr.copy_from_slice(&kid);
    pubkey_arr.copy_from_slice(&pubkey);
    let mut prefix = [0u8; 20];
    prefix.copy_from_slice(&kid_arr[..20]);
    Ok(AccountSession {
        scalar,
        kid: kid_arr,
        kid_prefix: prefix,
        pubkey: pubkey_arr,
        name: persisted.name,
    })
}

/// Register the account with the server (server recomputes kid; 409 if taken).
pub async fn register_on_server(
    session: &AccountSession,
) -> Result<AccountProfileResponse, String> {
    let request = RegisterAccountRequest {
        kid: session.kid,
        pubkey: session.pubkey,
        name: session.name.clone(),
    };
    let response = do_xhr_post(
        &format!("{}/api/account", BASE_URL),
        bitcode::encode(&request),
        |_, _| {},
    )
    .await?;
    if response.status >= 200 && response.status < 300 {
        let body = response.body.ok_or_else(|| "Empty response".to_string())?;
        bitcode::decode::<AccountProfileResponse>(&body).map_err(|e| format!("Bad response: {}", e))
    } else if response.status == 409 {
        Err(t!("account-error-already-exists").to_string())
    } else {
        Err(t!(
            "account-register-failed",
            status: response.status.to_string()
        )
        .to_string())
    }
}

/// Solve a server-issued challenge with the account (or ephemeral) scalar.
pub fn solve_account_challenge(
    scalar: &[u8; 32],
    challenge: &ChallengeResponse,
) -> Result<[u8; 32], String> {
    open_challenge(
        scalar,
        &challenge.ephemeral_pub,
        &challenge.nonce,
        &challenge.sealed,
    )
}

/// Change the account display name via the challenge flow.
pub async fn change_account_name_remote(
    kid_prefix: &[u8; 20],
    scalar: &[u8; 32],
    name: &str,
) -> Result<AccountProfileResponse, String> {
    let url = format!("{}/api/account/{}/challenge", BASE_URL, hex(kid_prefix));
    let challenge_resp = do_xhr_get(&url, vec![], |_, _| {}).await?;
    if !(challenge_resp.status >= 200 && challenge_resp.status < 300) {
        return Err(t!("account-challenge-failed").to_string());
    }
    let challenge: ChallengeResponse = challenge_resp
        .body
        .and_then(|b| bitcode::decode(&b).ok())
        .ok_or_else(|| t!("account-challenge-failed").to_string())?;
    let response_nonce = solve_account_challenge(scalar, &challenge)
        .map_err(|_| t!("account-challenge-solve-failed").to_string())?;
    let request = ChangeNameRequest {
        name: name.to_string(),
        challenge_response: response_nonce,
    };
    let result = do_xhr_post(
        &format!("{}/api/account/{}/name", BASE_URL, hex(kid_prefix)),
        bitcode::encode(&request),
        |_, _| {},
    )
    .await?;
    if result.status >= 200 && result.status < 300 {
        result
            .body
            .and_then(|b| bitcode::decode::<AccountProfileResponse>(&b).ok())
            .ok_or_else(|| "Bad response".to_string())
    } else {
        Err(t!(
            "account-name-change-failed",
            status: result.status.to_string()
        )
        .to_string())
    }
}

/// Fetch this account's inbox: prove ownership via the challenge flow, then
/// list recipient-mode pastes addressed to the account.
pub async fn fetch_inbox(session: &AccountSession) -> Result<Vec<PasteInboxListing>, String> {
    let kid_hex = hex(&session.kid);

    let challenge_resp = do_xhr_get(
        &format!("{}/api/account/{}/challenge", BASE_URL, kid_hex),
        vec![],
        |_, _| {},
    )
    .await?;
    if !(200..300).contains(&challenge_resp.status) {
        return Err(t!("account-challenge-failed").to_string());
    }
    let challenge: ChallengeResponse = challenge_resp
        .body
        .and_then(|b| bitcode::decode(&b).ok())
        .ok_or_else(|| t!("account-challenge-failed").to_string())?;
    let nonce = solve_account_challenge(&session.scalar, &challenge)
        .map_err(|_| t!("account-challenge-solve-failed").to_string())?;

    let proof = format!(
        "{}:{}",
        hex(&session.kid),
        general_purpose::STANDARD.encode(nonce)
    );
    let resp = do_xhr_get(
        &format!("{}/api/account/{}/inbox", BASE_URL, kid_hex),
        vec![("X-Account-Proof".to_string(), proof)],
        |_, _| {},
    )
    .await?;
    if !(200..300).contains(&resp.status) {
        return Err(t!("inbox-load-failed").to_string());
    }
    let body = resp
        .body
        .ok_or_else(|| t!("error-empty-response").to_string())?;
    bitcode::decode::<InboxResponse>(&body)
        .map(|d| d.pastes)
        .map_err(|e| format!("Bad inbox response: {}", e))
}

fn inbox_entry_label(p: &PasteInboxListing) -> String {
    match &p.filename {
        Some(name) => name.clone(),
        None => match p.data_type {
            DataType::Text => t!("inbox-entry-text").to_string(),
            DataType::File => t!("inbox-entry-file").to_string(),
        },
    }
}

#[derive(Clone)]
enum RegState {
    None,
    Backup {
        mnemonic: String,
        scalar: [u8; 32],
        pubkey: [u8; 32],
        kid: [u8; 32],
    },
}

#[component]
pub fn account_view() -> Element {
    let account = use_account();
    let mut popup_ctx = use_context::<Signal<PopupContext>>();

    let mut name_input = use_signal(String::new);
    let mut password_input = use_signal(String::new);
    let mut confirm_input = use_signal(String::new);
    let mut import_phrase = use_signal(String::new);
    let mut unlock_password = use_signal(String::new);
    let busy = use_signal(|| false);
    let reg = use_signal(|| RegState::None);
    let mut backed_up = use_signal(|| false);
    let mut new_name = use_signal(String::new);
    let navigator = use_navigator();
    let inbox_loading = use_signal(|| false);
    let inbox: Signal<Option<Vec<PasteInboxListing>>> = use_signal(|| None);
    let inbox_loaded = use_signal(|| false);

    let existing = persisted_account();

    let create_account_action = {
        let name_input = name_input;
        let password_input = password_input;
        let confirm_input = confirm_input;
        let mut busy = busy;
        let mut reg = reg;
        move |_| {
            let name = name_input.read().trim().to_string();
            let password = password_input.read().clone();
            let confirm = confirm_input.read().clone();
            if name.is_empty() {
                popup_ctx.write().show_error(t!("account-name-empty"));
                return;
            }
            if password != confirm || password.is_empty() {
                popup_ctx
                    .write()
                    .show_error(t!("account-password-mismatch"));
                return;
            }
            if *busy.read() {
                return;
            }
            busy.set(true);
            let mut popup_ctx = popup_ctx;
            let mut password_input = password_input;
            let mut name_input = name_input;
            spawn(async move {
                let result: Result<(), String> = async {
                    let (phrase, scalar, pubkey, kid) = new_account_key()?;
                    // Keep the name + password in memory for the backup step.
                    password_input.set(password);
                    name_input.set(name);
                    reg.set(RegState::Backup {
                        mnemonic: phrase,
                        scalar,
                        pubkey,
                        kid,
                    });
                    Ok(())
                }
                .await;
                // Unblock the UI regardless: the backup step uses its own button.
                busy.set(false);
                if let Err(e) = result {
                    popup_ctx.write().show_error(e);
                }
            });
        }
    };

    let finalize_registration = {
        let mut busy = busy;
        let mut reg = reg;
        let mut backed_up = backed_up;
        let mut account = account;
        move |_| {
            if !*backed_up.read() {
                popup_ctx.write().show_error(t!("account-backup-required"));
                return;
            }
            let RegState::Backup {
                mnemonic: _,
                scalar,
                pubkey,
                kid,
            } = reg.read().clone()
            else {
                return;
            };
            let name = name_input.read().clone();
            let password = password_input.read().clone();
            if name.is_empty() || password.is_empty() {
                return;
            }
            if *busy.read() {
                return;
            }
            busy.set(true);
            let mut popup_ctx = popup_ctx;
            spawn(async move {
                let mut prefix = [0u8; 20];
                prefix.copy_from_slice(&kid[..20]);
                let session = AccountSession {
                    scalar,
                    kid,
                    kid_prefix: prefix,
                    pubkey,
                    name: name.clone(),
                };
                // Persist the encrypted blob locally first...
                if let Err(e) = persist_account(&name, &scalar, &pubkey, &password) {
                    popup_ctx.write().show_error(e);
                    busy.set(false);
                    return;
                }
                // ...then register on the server.
                match register_on_server(&session).await {
                    Ok(profile) => {
                        account.set(Some(AccountSession {
                            name: profile.name,
                            ..session
                        }));
                        reg.set(RegState::None);
                        backed_up.set(false);
                        password_input.set(String::new());
                        name_input.set(String::new());
                        popup_ctx.write().show_success(t!("account-registered"));
                    }
                    Err(e) => {
                        popup_ctx.write().show_error(e);
                    }
                }
                busy.set(false);
            });
        }
    };

    let import_account_action = {
        let import_phrase = import_phrase;
        let name_input = name_input;
        let mut password_input = password_input;
        let mut confirm_input = confirm_input;
        let mut busy = busy;
        let mut account = account;
        move |_| {
            let phrase = import_phrase.read().clone();
            let name = name_input.read().trim().to_string();
            let password = password_input.read().clone();
            let confirm = confirm_input.read().clone();
            if name.is_empty() {
                popup_ctx.write().show_error(t!("account-name-empty"));
                return;
            }
            if password != confirm || password.is_empty() {
                popup_ctx
                    .write()
                    .show_error(t!("account-password-mismatch"));
                return;
            }
            if *busy.read() {
                return;
            }
            busy.set(true);
            let mut popup_ctx = popup_ctx;
            spawn(async move {
                let result: Result<(), String> = async {
                    let (scalar, pubkey, kid) = account_key_from_mnemonic(&phrase)?;
                    persist_account(&name, &scalar, &pubkey, &password)?;
                    let mut prefix = [0u8; 20];
                    prefix.copy_from_slice(&kid[..20]);
                    let session = AccountSession {
                        scalar,
                        kid,
                        kid_prefix: prefix,
                        pubkey,
                        name,
                    };
                    match register_on_server(&session).await {
                        Ok(profile) => {
                            account.set(Some(AccountSession {
                                name: profile.name,
                                ..session
                            }));
                            popup_ctx.write().show_success(t!("account-registered"));
                        }
                        Err(e) => return Err(e),
                    }
                    Ok(())
                }
                .await;
                password_input.set(String::new());
                confirm_input.set(String::new());
                busy.set(false);
                if let Err(e) = result {
                    popup_ctx.write().show_error(e);
                }
            });
        }
    };

    let unlock_action = {
        let mut unlock_password = unlock_password;
        let mut busy = busy;
        let mut account = account;
        move |_| {
            if *busy.read() {
                return;
            }
            busy.set(true);
            let password = unlock_password.read().clone();
            let mut popup_ctx = popup_ctx;
            spawn(async move {
                match unlock_local_account(&password) {
                    Ok(session) => {
                        account.set(Some(session));
                        unlock_password.set(String::new());
                        popup_ctx.write().show_success(t!("account-unlocked"));
                    }
                    Err(e) => popup_ctx.write().show_error(e),
                }
                busy.set(false);
            });
        }
    };

    let change_name_action = {
        let mut new_name = new_name;
        let mut busy = busy;
        let mut account = account;
        move |_| {
            let Some(session) = account.read().clone() else {
                return;
            };
            let name = new_name.read().trim().to_string();
            if name.is_empty() {
                popup_ctx.write().show_error(t!("account-name-empty"));
                return;
            }
            if *busy.read() {
                return;
            }
            busy.set(true);
            let mut popup_ctx = popup_ctx;
            spawn(async move {
                match change_account_name_remote(&session.kid_prefix, &session.scalar, &name).await
                {
                    Ok(profile) => {
                        let mut updated = session;
                        updated.name = profile.name;
                        account.set(Some(updated));
                        if let Some(p) = persisted_account() {
                            save_persisted(&PersistedAccount {
                                name: name.clone(),
                                ..p
                            });
                        }
                        new_name.set(String::new());
                        popup_ctx.write().show_success(t!("account-name-changed"));
                    }
                    Err(e) => popup_ctx.write().show_error(e),
                }
                busy.set(false);
            });
        }
    };

    let logout_action = {
        let mut account = account;
        move |_| {
            account.set(None);
        }
    };

    let load_inbox = {
        let account = account;
        let inbox = inbox;
        let mut inbox_loading = inbox_loading;
        let popup_ctx = popup_ctx;
        move |_| {
            if *inbox_loading.read() {
                return;
            }
            let Some(session) = account.read().clone() else {
                return;
            };
            inbox_loading.set(true);
            let mut inbox = inbox;
            let mut inbox_loading = inbox_loading;
            let mut popup_ctx = popup_ctx;
            spawn(async move {
                match fetch_inbox(&session).await {
                    Ok(pastes) => inbox.set(Some(pastes)),
                    Err(e) => popup_ctx.write().show_error(e),
                }
                inbox_loading.set(false);
            });
        }
    };

    // Load the inbox once automatically when the account becomes available.
    use_effect({
        let account = account;
        let inbox = inbox;
        let mut inbox_loading = inbox_loading;
        let popup_ctx = popup_ctx;
        let mut inbox_loaded = inbox_loaded;
        move || {
            if *inbox_loaded.read() || account.read().is_none() {
                return;
            }
            inbox_loaded.set(true);
            let Some(session) = account.read().clone() else {
                return;
            };
            inbox_loading.set(true);
            let mut inbox = inbox;
            let mut inbox_loading = inbox_loading;
            let mut popup_ctx = popup_ctx;
            spawn(async move {
                match fetch_inbox(&session).await {
                    Ok(pastes) => inbox.set(Some(pastes)),
                    Err(e) => popup_ctx.write().show_error(e),
                }
                inbox_loading.set(false);
            });
        }
    });

    let rsx_kid = account
        .read()
        .as_ref()
        .map(|a| format!("0x{}", a.kid_prefix_hex()));

    let backup_mnemonic: Option<String> = match &*reg.read() {
        RegState::Backup { mnemonic, .. } => Some(mnemonic.clone()),
        _ => None,
    };
    let copy_seed_action = {
        let mnemonic = backup_mnemonic.clone();
        let mut popup_ctx = popup_ctx;
        move |_| match crate::utils::copy_to_clipboard(mnemonic.as_deref().unwrap_or("")) {
            Ok(()) => popup_ctx.write().show_success(t!("copy-success")),
            Err(e) => popup_ctx.write().show_error(e),
        }
    };

    rsx! {
            div {
                class: "max-w-2xl mx-auto px-4 py-8",
                h1 {
                    class: "text-3xl font-bold text-center mb-8 tracking-tight",
                    {t!("account-title")}
                }

                if let Some(session) = account.read().as_ref() {
                    div {
                        class: "bg-surface p-6 rounded-lg shadow-lg",
                        div {
                            class: "flex justify-between items-center mb-6",
                            h2 {
                                class: "text-xl font-semibold",
                                {t!("account-logged-in")}
                            }
                            button {
                                class: "px-3 py-1.5 text-sm bg-elevated text-text hover:text-danger rounded transition-colors",
                                onclick: logout_action,
                                {t!("account-logout")}
                            }
                        }
                        div {
                            class: "space-y-3 mb-6",
                            div {
                                p { class: "text-sm text-muted", {t!("account-name-label")} }
                                p { "{session.name}" }
                            }
                            div {
                                p { class: "text-sm text-muted", {t!("account-kid-label")} }
                                p { class: "font-mono text-sm break-all", "{rsx_kid.as_deref().unwrap_or(\"\")}" }
                            }
                            div {
                                p { class: "text-sm text-muted", {t!("account-pubkey-label")} }
                                p { class: "font-mono text-xs break-all text-text-secondary", "{hex(&session.pubkey)}" }
                            }
                        }
                        div {
                            class: "border-t border-border pt-4",
                            h3 {
                                class: "text-lg font-semibold mb-2",
                                {t!("account-change-name")}
                            }
    div {
                                    class: "flex flex-col sm:flex-row gap-3",
                                    input {
                                        class: "flex-1 p-3 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                        placeholder: "{t!(\"account-name-placeholder\")}",
                                        oninput: move |evt| new_name.set(evt.value()),
                                        value: "{new_name}",
                                    }
                                    button {
                                        class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover transition-all duration-200 disabled:opacity-50",
                                        disabled: *busy.read(),
                                        onclick: change_name_action,
                                        {t!("account-save-name")}
                                    }
                                }
                            }
                        }
                        div {
                            class: "border-t border-border pt-4 mt-6",
                            div {
                                class: "flex justify-between items-center mb-3",
                                h3 {
                                    class: "text-lg font-semibold",
                                    {t!("account-inbox-title")}
                                }
                                button {
                                    class: "px-3 py-1.5 text-sm bg-elevated text-text font-semibold rounded hover:bg-accent hover:text-bg transition-all duration-200 disabled:opacity-50",
                                    disabled: *inbox_loading.read(),
                                    onclick: load_inbox,
                                    {t!("account-inbox-refresh")}
                                }
                            }
                            if *inbox_loading.read() {
                                p { class: "text-sm text-muted", {t!("loading")} }
                            } else {
                                match inbox.read().as_ref() {
                                    Some(pastes) if pastes.is_empty() => {
                                        rsx! { p { class: "text-sm text-muted", {t!("account-inbox-empty")} } }
                                    }
                                    Some(pastes) => {
                                        rsx! {
                                            div {
                                                class: "space-y-2",
                                                {pastes.iter().map(|p| {
                                                    let id = p.id.clone();
                                                    let desc = inbox_entry_label(p);
                                                    let navigator = navigator;
                                                    rsx! {
                                                        button {
                                                            class: "w-full p-3 bg-bg rounded-lg border border-border flex justify-between items-center text-left hover:border-accent transition-all duration-200",
                                                            onclick: move |_| { let _ = navigator.push(Route::Paste { id: id.clone() }); },
                                                            span { class: "text-accent font-semibold break-all", "{desc}" }
                                                            span { class: "text-muted text-xs font-mono shrink-0 ml-2", "{id}" }
                                                        }
                                                    }
                                                })}
                                            }
                                        }
                                    }
                                    None => {
                                        rsx! { p { class: "text-sm text-muted", {t!("account-inbox-load-hint")} } }
                                    }
                                }
                            }
                        }
                } else if let Some(existing) = existing {
                    div {
                        class: "bg-surface p-6 rounded-lg shadow-lg",
                        h2 {
                            class: "text-xl font-semibold mb-2",
                            {t!("account-unlock-title")}
                        }
                        p {
                            class: "text-sm text-muted mb-4",
                            {t!("account-unlock-desc", name: existing.name)}
                        }
                        div {
                            class: "space-y-3",
                            input {
                                class: "w-full p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                r#type: "password",
                                placeholder: "{t!(\"account-password-placeholder\")}",
                                oninput: move |evt| unlock_password.set(evt.value()),
                                value: "{unlock_password}",
                            }
                            button {
                                class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover transition-all duration-200 disabled:opacity-50",
                                disabled: *busy.read(),
                                onclick: unlock_action,
                                {t!("account-login-button")}
                            }
                        }
                    }
                } else {
                    div {
                        class: "space-y-6",
                        div {
                            class: "bg-surface p-6 rounded-lg shadow-lg",
                            h2 {
                                class: "text-xl font-semibold mb-4",
                                {t!("account-register-title")}
                            }
                            div {
                                class: "space-y-3",
                                input {
                                    class: "w-full p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                    placeholder: "{t!(\"account-name-placeholder\")}",
                                    oninput: move |evt| name_input.set(evt.value()),
                                    value: "{name_input}",
                                }
                                input {
                                    class: "w-full p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                    r#type: "password",
                                    placeholder: "{t!(\"account-password-placeholder\")}",
                                    autocomplete: "new-password",
                                    oninput: move |evt| password_input.set(evt.value()),
                                    value: "{password_input}",
                                }
                                input {
                                    class: "w-full p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                    r#type: "password",
                                    placeholder: "{t!(\"account-confirm-placeholder\")}",
                                    autocomplete: "new-password",
                                    oninput: move |evt| confirm_input.set(evt.value()),
                                    value: "{confirm_input}",
                                }
                                textarea {
                                    class: "w-full p-4 bg-bg text-text rounded-lg border border-border focus:outline-none focus:ring-2 focus:ring-accent",
                                    rows: "3",
                                    placeholder: "{t!(\"account-import-placeholder\")}",
                                    oninput: move |evt| import_phrase.set(evt.value()),
                                    value: "{import_phrase}",
                                }
                                button {
                                    class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover transition-all duration-200 disabled:opacity-50",
                                    disabled: *busy.read(),
                                    onclick: create_account_action,
                                    {t!("account-create-button")}
                                }
                                button {
                                    class: "px-6 py-3 bg-elevated text-text font-semibold rounded-lg hover:bg-surface transition-all duration-200 disabled:opacity-50",
                                    disabled: *busy.read(),
                                    onclick: import_account_action,
                                    {t!("account-import-button")}
                                }
                            }
                        }

                        if let Some(mnemonic) = backup_mnemonic.as_ref() {
                            div {
                                class: "bg-surface p-6 rounded-lg shadow-lg border border-accent",
                                h2 {
                                    class: "text-xl font-semibold mb-2 text-accent",
                                    {t!("account-backup-title")}
                                }
                                p {
                                    class: "text-sm text-muted mb-4",
                                    {t!("account-backup-desc")}
                                }
                                div {
                                    class: "bg-bg rounded p-4 mb-4 grid grid-cols-2 sm:grid-cols-3 gap-2 font-mono text-sm",
                                    {mnemonic.split(' ').map(|word| rsx! { span { class: "px-1", "{word}" } })}
                                }
                                button {
                                    class: "mb-4 px-4 py-2 bg-elevated text-text font-semibold rounded-lg hover:bg-surface transition-all duration-200",
                                    onclick: copy_seed_action,
                                    {t!("account-copy-seed")}
                                }
                                label {
                                    class: "flex items-center gap-2 text-sm text-muted mb-4 select-none cursor-pointer",
                                    input {
                                        r#type: "checkbox",
                                        oninput: move |evt| backed_up.set(evt.checked()),
                                    }
                                    {t!("account-backup-confirm")}
                                }
                                button {
                                    class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover transition-all duration-200 disabled:opacity-50",
                                    disabled: *busy.read(),
                                    onclick: finalize_registration,
                                    {t!("account-finish-button")}
                                }
                            }
                        }
                    }
                }
            }
        }
}

#[component]
pub fn user_view(id: String) -> Element {
    let profile: Signal<Option<AccountProfileResponse>> = use_signal(|| None);
    let loading = use_signal(|| true);
    let not_found = use_signal(|| false);
    let navigator = use_navigator();
    let recipient = use_recipient_target();

    use_effect({
        let loading = loading;
        let not_found = not_found;
        move || {
            if !*loading.read() {
                return;
            }
            let id = id.clone();
            let mut profile = profile;
            let mut loading = loading;
            let mut not_found = not_found;
            spawn(async move {
                let url = format!("{}/api/account/{}", BASE_URL, id);
                let result = do_xhr_get(&url, vec![], |_, _| {}).await;
                match result {
                    Ok(r) if r.status >= 200 && r.status < 300 => {
                        if let Some(body) = r.body
                            && let Ok(decoded) = bitcode::decode::<AccountProfileResponse>(&body)
                        {
                            profile.set(Some(decoded));
                        } else {
                            not_found.set(true);
                        }
                    }
                    _ => not_found.set(true),
                }
                loading.set(false);
            });
        }
    });

    let send_action = {
        let mut recipient = recipient;
        let navigator = navigator;
        move |_| {
            let Some(p) = profile.read().clone() else {
                return;
            };
            recipient.set(Some(RecipientTarget {
                kid: p.kid,
                kid_prefix: p.kid_prefix,
                pubkey: p.pubkey,
                name: p.name,
            }));
            navigator.push(Route::Home {});
        }
    };

    rsx! {
        div {
            class: "max-w-2xl mx-auto px-4 py-8",
            if *loading.read() {
                p {
                    class: "text-center text-muted",
                    {t!("loading")}
                }
            } else if let Some(p) = profile.read().as_ref() {
                div {
                    class: "bg-surface p-8 rounded-lg shadow-lg text-center",
                    h1 {
                        class: "text-3xl font-bold mb-2",
                        "{p.name}"
                    }
                    p {
                        class: "text-muted text-sm mb-6 font-mono break-all",
                        "0x{hex(&p.kid_prefix)}"
                    }
                    div {
                        class: "mb-6",
                        p { class: "text-xs text-muted mb-1", {t!("user-pubkey-label")} }
                        p { class: "font-mono text-xs break-all text-text-secondary", "{hex(&p.pubkey)}" }
                    }
                    button {
                        class: "px-6 py-3 bg-accent text-bg font-semibold rounded-lg hover:bg-accent-hover transition-all duration-200",
                        onclick: send_action,
                        {t!("user-send-message")}
                    }
                }
            } else {
                div {
                    class: "text-center text-muted",
                    {t!("user-not-found")}
                }
            }
        }
    }
}
