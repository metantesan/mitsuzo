#![cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]

#[cfg(not(target_arch = "x86_64"))]
compile_error!("encryption benchmarks are for native x86_64 targets only");

use mitsuzo_utils::{
    Argon2idHkdfSha256, ContentCipherKind, KeyAgreement, PasswordKeyDerivation, X25519,
    compute_burn_receipt, compute_password_hash, derive_account_scalar, derive_recipient_cek_key,
    ecdh_shared_secret, encrypt_setup, open_content_key_for_recipient, pubkey_from_scalar,
    seal_content_key_for_recipient, unwrap_content_key, wrap_content_key,
};
use std::{hint::black_box, time::Instant};

const CONTENT_SIZES_AND_ITERS: &[(usize, usize)] = &[
    (64, 10_000),
    (1024, 5_000),
    (64 * 1024, 256),
    (1024 * 1024, 16),
];
const SAMPLES: usize = 5;
const LARGE_STREAM_MIB: usize = 1000;
const LARGE_STREAM_SAMPLES: usize = 2;
const CHUNK_SIZE: usize = 64 * 1024;
const DECRYPT_CIPHERTEXT_POOL: usize = 256;

fn measure_ns(iterations: usize, mut operation: impl FnMut()) -> f64 {
    for _ in 0..iterations.min(3) {
        operation();
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..iterations {
            operation();
        }
        samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0 / iterations as f64);
    }
    samples.sort_by(f64::total_cmp);
    samples[SAMPLES / 2]
}

fn mb_per_second(bytes: usize, ns_per_op: f64) -> f64 {
    bytes as f64 * 1_000_000_000.0 / ns_per_op / 1_000_000.0
}

fn benchmark_cipher(cipher: ContentCipherKind, size: usize, iterations: usize) -> (f64, f64) {
    let key = [0x42; 32];
    let nonce = vec![0x17; cipher.nonce_len()];
    let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();

    let mut encrypted = Vec::with_capacity(size + 16);
    let mut encryption_index = 0u32;
    let encryption_ns = measure_ns(iterations, || {
        let index = encryption_index;
        encryption_index = encryption_index.wrapping_add(1);
        encrypted.clear();
        cipher
            .encrypt_chunk(
                black_box(&key),
                black_box(&nonce),
                black_box(index),
                black_box(&plaintext),
                &mut encrypted,
            )
            .expect("benchmark encryption should succeed");
        black_box(&encrypted);
    });

    // Create the input once so decryption timing excludes encryption setup.
    encrypted.clear();
    cipher
        .encrypt_chunk(&key, &nonce, 0, &plaintext, &mut encrypted)
        .expect("benchmark ciphertext setup should succeed");
    let mut decrypted = Vec::with_capacity(size);
    let decryption_ns = measure_ns(iterations, || {
        decrypted.clear();
        cipher
            .decrypt_chunk(
                black_box(&key),
                black_box(&nonce),
                black_box(0),
                black_box(&encrypted),
                &mut decrypted,
            )
            .expect("benchmark decryption should succeed");
        black_box(&decrypted);
    });

    (encryption_ns, decryption_ns)
}

fn benchmark_content_ciphers() {
    println!("\nContent encryption comparison (median of {SAMPLES} samples)");
    println!(
        "bytes | operation | ChaCha20-Poly1305 MB/s | XChaCha20-Poly1305 MB/s | X/ChaCha time"
    );

    for &(size, iterations) in CONTENT_SIZES_AND_ITERS {
        let (chacha_encrypt_ns, chacha_decrypt_ns) =
            benchmark_cipher(ContentCipherKind::ChaCha20Poly1305, size, iterations);
        let (xchacha_encrypt_ns, xchacha_decrypt_ns) =
            benchmark_cipher(ContentCipherKind::XChaCha20Poly1305, size, iterations);

        for (operation, chacha_ns, xchacha_ns) in [
            ("encrypt", chacha_encrypt_ns, xchacha_encrypt_ns),
            ("decrypt", chacha_decrypt_ns, xchacha_decrypt_ns),
        ] {
            println!(
                "{size:>7} | {operation:<8} | {:>25.1} | {:>26.1} | {:>13.2}x",
                mb_per_second(size, chacha_ns),
                mb_per_second(size, xchacha_ns),
                xchacha_ns / chacha_ns,
            );
        }
    }

    benchmark_large_streams();
}

fn nonce_for_sample(cipher: ContentCipherKind, sample: usize) -> Vec<u8> {
    let mut nonce = vec![0x17; cipher.nonce_len()];
    nonce[0..4].copy_from_slice(&(sample as u32).to_le_bytes());
    nonce
}

fn benchmark_large_stream(cipher: ContentCipherKind, total_bytes: usize) -> (f64, f64) {
    let key = [0x42; 32];
    let plaintext = vec![0x5a; CHUNK_SIZE];
    let chunk_count = total_bytes.div_ceil(CHUNK_SIZE);
    let final_chunk_size = total_bytes - (chunk_count - 1) * CHUNK_SIZE;
    let mut encrypted = Vec::with_capacity(CHUNK_SIZE + 16);
    let mut encryption_samples = Vec::with_capacity(LARGE_STREAM_SAMPLES);

    for sample in 0..LARGE_STREAM_SAMPLES {
        let nonce = nonce_for_sample(cipher, sample);
        let start = Instant::now();
        for index in 0..chunk_count {
            let chunk_len = if index + 1 == chunk_count {
                final_chunk_size
            } else {
                CHUNK_SIZE
            };
            encrypted.clear();
            cipher
                .encrypt_chunk(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(index as u32),
                    black_box(&plaintext[..chunk_len]),
                    &mut encrypted,
                )
                .expect("large stream encryption should succeed");
            black_box(&encrypted);
        }
        encryption_samples.push(start.elapsed().as_secs_f64());
    }

    // Precompute a bounded pool of ciphertext chunks, each with its matching
    // nonce index, so decrypt throughput does not include encryption time or
    // require holding a 1000 MiB ciphertext in memory.
    let mut decryption_samples = Vec::with_capacity(LARGE_STREAM_SAMPLES);
    let mut decrypted = Vec::with_capacity(CHUNK_SIZE);
    for sample in 0..LARGE_STREAM_SAMPLES {
        let nonce = nonce_for_sample(cipher, sample + LARGE_STREAM_SAMPLES);
        let mut ciphertext_pool = Vec::with_capacity(DECRYPT_CIPHERTEXT_POOL);
        for index in 0..DECRYPT_CIPHERTEXT_POOL {
            let mut ciphertext = Vec::with_capacity(CHUNK_SIZE + 16);
            cipher
                .encrypt_chunk(&key, &nonce, index as u32, &plaintext, &mut ciphertext)
                .expect("large stream ciphertext setup should succeed");
            ciphertext_pool.push(ciphertext);
        }
        let mut final_ciphertext = Vec::new();
        if final_chunk_size < CHUNK_SIZE {
            cipher
                .encrypt_chunk(
                    &key,
                    &nonce,
                    (chunk_count - 1) as u32,
                    &plaintext[..final_chunk_size],
                    &mut final_ciphertext,
                )
                .expect("final chunk ciphertext setup should succeed");
        }

        let start = Instant::now();
        for index in 0..chunk_count {
            let is_partial_final_chunk = index + 1 == chunk_count && final_chunk_size < CHUNK_SIZE;
            let (nonce_index, ciphertext) = if is_partial_final_chunk {
                (index, final_ciphertext.as_slice())
            } else {
                let pool_index = index % DECRYPT_CIPHERTEXT_POOL;
                (pool_index, ciphertext_pool[pool_index].as_slice())
            };
            decrypted.clear();
            cipher
                .decrypt_chunk(
                    black_box(&key),
                    black_box(&nonce),
                    black_box(nonce_index as u32),
                    black_box(ciphertext),
                    &mut decrypted,
                )
                .expect("large stream decryption should succeed");
            black_box(&decrypted);
        }
        decryption_samples.push(start.elapsed().as_secs_f64());
    }

    (
        encryption_samples.iter().sum::<f64>() / LARGE_STREAM_SAMPLES as f64,
        decryption_samples.iter().sum::<f64>() / LARGE_STREAM_SAMPLES as f64,
    )
}

fn benchmark_large_streams() {
    let total_bytes = LARGE_STREAM_MIB * 1024 * 1024;
    println!(
        "\nSingle-threaded streaming comparison: {LARGE_STREAM_MIB} MiB per pass, mean of {} samples",
        LARGE_STREAM_SAMPLES
    );
    println!("operation | ChaCha20-Poly1305 MB/s | XChaCha20-Poly1305 MB/s | X/ChaCha time");

    let (chacha_encrypt_s, chacha_decrypt_s) =
        benchmark_large_stream(ContentCipherKind::ChaCha20Poly1305, total_bytes);
    let (xchacha_encrypt_s, xchacha_decrypt_s) =
        benchmark_large_stream(ContentCipherKind::XChaCha20Poly1305, total_bytes);

    for (operation, chacha_s, xchacha_s) in [
        ("encrypt", chacha_encrypt_s, xchacha_encrypt_s),
        ("decrypt", chacha_decrypt_s, xchacha_decrypt_s),
    ] {
        println!(
            "{operation:<8} | {:>25.1} | {:>26.1} | {:>13.2}x",
            total_bytes as f64 / 1_000_000.0 / chacha_s,
            total_bytes as f64 / 1_000_000.0 / xchacha_s,
            xchacha_s / chacha_s,
        );
    }
}

fn benchmark_crypto_primitives() {
    println!("\nKey setup and wrapping primitives (median of {SAMPLES} samples)");
    let password = "benchmark-only-password";
    let salt = [0x31; 16];
    let content_key = [0x54; 32];
    let kek = [0x62; 32];
    let (wrap_nonce, wrapped_key) = wrap_content_key(&content_key, &kek).unwrap();

    report("Argon2id + HKDF-SHA256", 8, || {
        black_box(Argon2idHkdfSha256::derive(black_box(password), black_box(&salt)).unwrap());
    });
    report("Password paste envelope setup", 8, || {
        black_box(encrypt_setup(black_box(password), black_box(&content_key)).unwrap());
    });
    report("Password key wrap (ChaCha20-Poly1305)", 2_000, || {
        black_box(wrap_content_key(black_box(&content_key), black_box(&kek)).unwrap());
    });
    report("Password key unwrap (ChaCha20-Poly1305)", 2_000, || {
        black_box(
            unwrap_content_key(
                black_box(&wrapped_key),
                black_box(&wrap_nonce),
                black_box(&kek),
            )
            .unwrap(),
        );
    });
    report("Password validation HMAC-SHA256", 20_000, || {
        black_box(compute_password_hash(
            black_box(&content_key),
            black_box(&salt),
        ));
    });
    report("Burn receipt HKDF-SHA256", 20_000, || {
        black_box(compute_burn_receipt(black_box(&content_key)));
    });

    let account_seed = [0x26; 64];
    let sender_private = [0x11; 32];
    let recipient_private = [0x72; 32];
    let sender_public = pubkey_from_scalar(&sender_private);
    let recipient_public = pubkey_from_scalar(&recipient_private);
    let shared = ecdh_shared_secret(&sender_private, &recipient_public).unwrap();
    let (recipient_nonce, recipient_wrapped) =
        seal_content_key_for_recipient(&sender_private, &recipient_public, &content_key).unwrap();

    report("Account X25519 scalar derivation", 20_000, || {
        black_box(derive_account_scalar(black_box(&account_seed)));
    });
    report("X25519 public key derivation", 10_000, || {
        black_box(pubkey_from_scalar(black_box(&sender_private)));
    });
    report("X25519 ECDH shared secret", 10_000, || {
        black_box(
            X25519::shared_secret(black_box(&sender_private), black_box(&recipient_public))
                .unwrap(),
        );
    });
    report("Recipient CEK HKDF-SHA256", 20_000, || {
        black_box(derive_recipient_cek_key(black_box(&shared)));
    });
    report(
        "Recipient envelope seal (X25519 + HKDF + AEAD)",
        1_000,
        || {
            black_box(
                seal_content_key_for_recipient(
                    black_box(&sender_private),
                    black_box(&recipient_public),
                    black_box(&content_key),
                )
                .unwrap(),
            );
        },
    );
    report(
        "Recipient envelope open (X25519 + HKDF + AEAD)",
        1_000,
        || {
            black_box(
                open_content_key_for_recipient(
                    black_box(&recipient_private),
                    black_box(&sender_public),
                    black_box(&recipient_nonce),
                    black_box(&recipient_wrapped),
                )
                .unwrap(),
            );
        },
    );
}

fn report(label: &str, iterations: usize, mut operation: impl FnMut()) {
    let ns_per_op = measure_ns(iterations, &mut operation);
    println!("{label:<54} {ns_per_op:>12.1} ns/op");
}

fn main() {
    println!("Mitsuzo encryption benchmarks · native x86_64 · release profile");
    benchmark_content_ciphers();
    benchmark_crypto_primitives();
}
