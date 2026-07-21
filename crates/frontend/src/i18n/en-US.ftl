app-title = Mitsuzo

nav-home = Home
nav-how-it-works = How It Works
nav-changelog = Changelog
nav-download = Download

changelog-title = Changelog
changelog-current = current

home-placeholder = Enter your paste here...
or-upload-file = Or Upload a File:
choose-file = Choose a file...
password-placeholder = Enter a password for encryption
password-auto-gen-hint = Leave empty for auto-generated password
try-count-label = Try Count (0 for infinite)
ttl-label = TTL in seconds
create-paste = Create Paste

paste-created = Paste created!
paste-id = ID: { $id }
remember-password = Please remember your password for decryption.

view-existing-paste = View Existing Paste
enter-paste-id = Enter Paste ID
view-paste = View Paste

stats-title = Stats
stats-description = Created = total pastes uploaded. Decrypted = successful views. Wrong Password = failed decrypt attempts.
all-time = All Time
today = Today
created = Created
decrypted = Decrypted
wrong-password = Wrong Password


clear = Clear

progress-validating = Validating input...
progress-processing-file = Processing file...
progress-processing-text = Processing text...
progress-encrypting = Encrypting content...
progress-encrypting-percent = Encrypting... { $percent }%
progress-preparing-upload = Preparing upload...
progress-upload-percent = Uploading... { $percent }%
progress-upload-kb = Uploading... { $kb } KB sent
progress-upload-complete = Upload complete!
progress-reading-file = Reading file...
progress-file-loaded = File loaded
progress-downloading-metadata = Downloading metadata...
progress-deriving-key = Deriving encryption key...
progress-downloading-content = Downloading content...
progress-downloading-percent = Downloading... { $percent }%
progress-downloading-kb = Downloading... { $kb } KB
progress-decrypting = Decrypting...
progress-decrypting-percent = Decrypting... { $percent }%

error-password-empty = Password cannot be empty.
error-content-empty = Content cannot be empty.
error-ttl-invalid = TTL must be a valid number.
error-encryption-failed = Failed to encrypt content: { $error }
error-parse-response-failed = Failed to parse response: { $error }
error-empty-response = Empty response body
error-create-paste-failed = Failed to create paste: HTTP { $status }
error-send-request-failed = Failed to send request: { $error }
error-decode-salt-failed = Failed to decode salt response: { $error }
error-empty-salt-response = Empty salt response
error-get-salt-failed = Failed to get salt: HTTP { $status }
error-salt-request-failed = Failed to send salt request: { $error }
error-argon2-params-failed = Failed to create Argon2 params: { $error }
error-key-derivation-failed = Failed to derive key: { $error }
error-decode-paste-failed = Failed to decode paste response: { $error }
error-get-paste-failed = Failed to get paste: HTTP { $status }
error-decryption-failed = Decryption failed: { $error }
error-read-file-failed = Failed to read file: { $error }

paste-view-title = View Paste
decrypt-password-placeholder = Enter Decryption Password
decrypt-paste = Decrypt Paste
tries-left = Tries left: { $count }
time-left = Time left: { $time } seconds
file-preview = File Preview
file-ready-download = File Ready for Download
download-file = Download File
enter-password-desc = Enter password and click 'Decrypt Paste' to view content.

how-it-works = How It Works
e2e-encryption = End-to-End Encryption
e2e-desc = Pastes are encrypted in your browser before upload. Argon2id derives a 32-byte master key, then HKDF-SHA256 expands it into two independent keys — one for encryption, one for password validation. Keys never leave your device.
e2e-item1 = Argon2id(password, salt, m_cost=19456, t_cost=2) → 32-byte master key
e2e-item2 = HKDF-SHA256(master, "mitsuzo-encryption-key") → 32-byte encryption key
e2e-item3 = HKDF-SHA256(master, "mitsuzo-validation-key") → 32-byte validation key
e2e-item4 = Files >64KB split into 64KB chunks, each encrypted with a unique derived nonce
e2e-item5 = Server never sees your password or plaintext
zk-validation = Zero-Knowledge Password Validation
zk-desc = The server validates your password without ever knowing it. Here's how:
zk-step1 = Argon2id + HKDF derive encryption_key and validation_key from your password
zk-step2 = Browser computes HMAC-SHA256(validation_key, salt) and sends this hash to the server
zk-step3 = Server stores only this hash — never the key, salt, or password
zk-step4 = When viewing, browser re-derives keys and hash, sending it in the X-Password-Hash header
zk-step5 = Server compares hashes in constant time (XOR-based) — a match proves the password is correct without revealing anything
zk-note = Even a compromised server cannot decrypt pastes or recover passwords.
workflow-diagram = Workflow Diagram
self-destructing = Self-Destructing Pastes
self-destruct-desc = You control how long your paste lives. Set a time-to-live (TTL) and optionally a maximum number of views.
sd-item1 = Automatic deletion after TTL expires (max 12 hours)
sd-item2 = Optional try-count limit for extra security (1-100 attempts)
sd-item3 = Paste permanently deleted when try-count reaches 0
sd-item4 = Failed decryption attempts count toward try-count
proof-safety = Proof of Safety
proof-safety-desc = Your data's safety is guaranteed by end-to-end encryption. The server only stores encrypted chunks and an HMAC of the validation key. Even a full server compromise cannot expose plaintext.
ps-item1 = Even server compromise cannot expose your plaintext data
ps-item2 = No backdoors — decryption keys exist only in your browser or CLI
ps-item3 = Self-destructing pastes minimize exposure window
ps-item4 = Failed attempts can be capped to prevent brute-force attacks
cli-usage = CLI Client
cli-desc = Mitsuzo also provides a cross-platform CLI client for creating and retrieving pastes from the terminal.
cli-create = Create: mitsuzo create [-f file] [-c tries] [-t ttl]
cli-get = Get: mitsuzo get <id> [-o output]
stats-title-section = Statistics
stats-desc-section = The server tracks anonymous usage counters. These help monitor overall health and activity.
footer-created = Created by
footer-author = hikari
footer-github = GitHub