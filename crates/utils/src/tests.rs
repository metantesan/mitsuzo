use crate::*;

#[test]
fn wrap_unwrap_round_trip() {
    let cek = generate_content_key().unwrap();
    let kek = generate_content_key().unwrap();
    let (wrap_nonce, wrapped) = wrap_content_key(&cek, &kek).unwrap();
    assert_ne!(&wrapped[..32], cek);
    let unwrapped = unwrap_content_key(&wrapped, &wrap_nonce, &kek).unwrap();
    assert_eq!(unwrapped, cek);
}

#[test]
fn unwrap_with_wrong_kek_fails() {
    let cek = generate_content_key().unwrap();
    let kek = generate_content_key().unwrap();
    let wrong_kek = generate_content_key().unwrap();
    let (wrap_nonce, wrapped) = wrap_content_key(&cek, &kek).unwrap();
    assert!(unwrap_content_key(&wrapped, &wrap_nonce, &wrong_kek).is_err());
}

#[test]
fn key_wrap_rejects_tampered_ciphertext_and_nonce() {
    let cek = [41u8; 32];
    let kek = [42u8; 32];
    let (nonce, wrapped) = wrap_content_key(&cek, &kek).unwrap();
    let mut altered = wrapped;
    altered[17] ^= 1;
    assert!(unwrap_content_key(&altered, &nonce, &kek).is_err());
    let mut altered_nonce = nonce;
    altered_nonce[0] ^= 1;
    assert!(unwrap_content_key(&wrapped, &altered_nonce, &kek).is_err());
}

#[test]
fn chacha_chunk_nonce_derivation_is_unique_through_counter_boundary() {
    let base = [92u8; 12];
    let indices = [0, 1, 2, u32::MAX - 1, u32::MAX];
    let nonces: Vec<_> = indices
        .into_iter()
        .map(|index| derive_chunk_nonce(&base, index))
        .collect();
    for i in 0..nonces.len() {
        for j in i + 1..nonces.len() {
            assert_ne!(nonces[i], nonces[j]);
        }
    }
}

#[test]
fn password_change_rewrap_only() {
    let plaintext = b"hello mitsuzo".repeat(1000);
    let old_password = "correct horse battery staple";
    let new_password = "new password 42";

    let cek = generate_content_key().unwrap();
    let setup = encrypt_setup(old_password, &cek).unwrap();

    // Encrypt with the random CEK (envelope scheme)
    let mut ciphertext = Vec::new();
    let total_chunks = encrypt_into(&plaintext, &cek, &setup.base_nonce, &mut ciphertext).unwrap();

    // Change password: unwrap with old KEK, rewrap with new KEK
    let (old_kek, _) = derive_keys(old_password, &setup.salt).unwrap();
    let unwrapped_cek =
        unwrap_content_key(&setup.wrapped_key, &setup.wrap_nonce, &old_kek).unwrap();
    assert_eq!(unwrapped_cek, cek);

    let new_setup = encrypt_setup(new_password, &unwrapped_cek).unwrap();

    // Ciphertext is untouched; password-based (legacy) decryption now fails,
    // but CEK-based decryption succeeds after unwrapping from the new wrap.
    let (new_kek, _) = derive_keys(new_password, &new_setup.salt).unwrap();
    let recovered_cek =
        unwrap_content_key(&new_setup.wrapped_key, &new_setup.wrap_nonce, &new_kek).unwrap();
    assert_eq!(recovered_cek, cek);

    let mut decrypted = Vec::new();
    assert!(
        decrypt_into(
            &ciphertext,
            &setup.base_nonce,
            new_password,
            &setup.salt,
            total_chunks,
            &mut decrypted
        )
        .is_err()
    );
    decrypted.clear();
    decrypt_with_key_into(
        &ciphertext,
        &recovered_cek,
        &setup.base_nonce,
        &mut decrypted,
    )
    .unwrap();
    assert_eq!(decrypted, plaintext);

    // Old password no longer unwraps the new wrap
    assert!(unwrap_content_key(&new_setup.wrapped_key, &new_setup.wrap_nonce, &old_kek).is_err());
}

#[test]
fn burn_receipt_stable_across_password_change() {
    let cek = generate_content_key().unwrap();
    let _setup = encrypt_setup("old", &cek).unwrap();
    let receipt_before = compute_burn_receipt(&cek);
    let receipt_after = compute_burn_receipt(&cek);
    assert_eq!(receipt_before, receipt_after);
}

#[test]
fn legacy_direct_key_still_decrypts() {
    let plaintext = b"legacy paste data".repeat(3);
    let password = "legacy password";

    // Old scheme: encryption key derived directly from the password
    let setup_salt = [7u8; 16];
    let (encryption_key, _validation_key) = derive_keys(password, &setup_salt).unwrap();
    let base_nonce = [9u8; 12];
    let mut ciphertext = Vec::new();
    let total_chunks =
        encrypt_into(&plaintext, &encryption_key, &base_nonce, &mut ciphertext).unwrap();

    // Legacy decrypt path: derive keys and decrypt directly
    let mut decrypted = Vec::new();
    decrypt_into(
        &ciphertext,
        &base_nonce,
        password,
        &setup_salt,
        total_chunks,
        &mut decrypted,
    )
    .unwrap();
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chunked_envelope_round_trip() {
    let plaintext: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let password = "chunky";
    let cek = generate_content_key().unwrap();
    let setup = encrypt_setup(password, &cek).unwrap();

    let mut ciphertext = Vec::new();
    let total_chunks = encrypt_into(&plaintext, &cek, &setup.base_nonce, &mut ciphertext).unwrap();

    let (kek, _) = derive_keys(password, &setup.salt).unwrap();
    let unwrapped = unwrap_content_key(&setup.wrapped_key, &setup.wrap_nonce, &kek).unwrap();

    let mut decrypted = Vec::with_capacity(plaintext.len());
    for i in 0..total_chunks {
        let (start, end) = get_chunk_bounds(total_chunks, i, ciphertext.len());
        decrypt_chunk_into(
            &ciphertext[start..end],
            &unwrapped,
            &setup.base_nonce,
            i,
            &mut decrypted,
        )
        .unwrap();
    }
    assert_eq!(decrypted, plaintext);
}

#[test]
fn account_scalar_pubkey_round_trip() {
    let (scalar, pubkey) = generate_x25519_keypair().unwrap();
    assert_eq!(pubkey_from_scalar(&scalar), pubkey);
    // Clamped scalars are invariant under a second clamp.
    let repub = pubkey_from_scalar(&scalar);
    assert_eq!(repub, pubkey);
    // kid is a stable SHA-256 of the pubkey with the 20-byte prefix.
    let kid = kid_from_pubkey(&pubkey);
    assert_eq!(kid.len(), 32);
    let prefix = kid_prefix_from_pubkey(&pubkey);
    assert_eq!(&kid[..20], prefix);
}

#[test]
fn account_id_query_binding_accepts_only_matching_full_or_prefix_ids() {
    let kid = [0xab; 32];
    assert!(account_id_matches_query(&"ab".repeat(32), &kid));
    assert!(account_id_matches_query(
        &format!("0x{}", "AB".repeat(20)),
        &kid
    ));
    assert!(!account_id_matches_query(&"cd".repeat(32), &kid));
    assert!(!account_id_matches_query("recipient-name", &kid));
}

#[test]
fn ecdh_symmetry() {
    let (priv_a, pub_a) = generate_x25519_keypair().unwrap();
    let (priv_b, pub_b) = generate_x25519_keypair().unwrap();
    let s1 = ecdh_shared_secret(&priv_a, &pub_b).unwrap();
    let s2 = ecdh_shared_secret(&priv_b, &pub_a).unwrap();
    assert_eq!(s1, s2);
}

#[test]
fn challenge_seal_open_round_trip() {
    let (account_priv, account_pub) = generate_x25519_keypair().unwrap();
    let (eph_priv, eph_pub) = generate_x25519_keypair().unwrap();
    let secret = generate_content_key().unwrap();
    let (nonce, sealed) = seal_challenge(&eph_priv, &account_pub, &secret).unwrap();
    let opened = open_challenge(&account_priv, &eph_pub, &nonce, &sealed).unwrap();
    assert_eq!(opened, secret);
}

#[test]
fn challenge_open_with_wrong_key_fails() {
    let (_account_priv, account_pub) = generate_x25519_keypair().unwrap();
    let (eph_priv, eph_pub) = generate_x25519_keypair().unwrap();
    let (other_priv, _) = generate_x25519_keypair().unwrap();
    let secret = generate_content_key().unwrap();
    let (nonce, sealed) = seal_challenge(&eph_priv, &account_pub, &secret).unwrap();
    assert!(open_challenge(&other_priv, &eph_pub, &nonce, &sealed).is_err());
}

#[test]
fn account_key_lock_unlock_round_trip() {
    let (scalar, _) = generate_x25519_keypair().unwrap();
    let blob = lock_account_key(&scalar, "hunter2-secret").unwrap();
    assert_ne!(&blob.wrapped[..32], &scalar);
    let unlocked = unlock_account_key(&blob, "hunter2-secret").unwrap();
    assert_eq!(unlocked, scalar);
    // Wrong password fails.
    assert!(unlock_account_key(&blob, "wrong-password").is_err());
    // Same blob is stable across calls (deterministic from password).
    let blob2 = lock_account_key(&scalar, "hunter2-secret").unwrap();
    assert_ne!(blob2.salt, blob.salt);
    assert!(unlock_account_key(&blob2, "hunter2-secret").unwrap() == scalar);
}

#[test]
fn recipient_envelope_opens_for_both_ends() {
    let cek = generate_content_key().unwrap();
    let (recipient_priv, recipient_pub) = generate_x25519_keypair().unwrap();
    let (eph_priv, eph_pub) = generate_x25519_keypair().unwrap();

    // Sender seals to the recipient.
    let (nonce, sealed_cek) =
        seal_content_key_for_recipient(&eph_priv, &recipient_pub, &cek).unwrap();

    // Recipient opens with their account scalar.
    let by_recipient =
        open_content_key_for_recipient(&recipient_priv, &eph_pub, &nonce, &sealed_cek).unwrap();
    assert_eq!(by_recipient, cek);

    // Sender (holding the ephemeral key) opens the same envelope.
    let by_sender =
        open_content_key_for_recipient(&eph_priv, &recipient_pub, &nonce, &sealed_cek).unwrap();
    assert_eq!(by_sender, cek);

    // A stranger cannot.
    let (stranger, _) = generate_x25519_keypair().unwrap();
    assert!(open_content_key_for_recipient(&stranger, &eph_pub, &nonce, &sealed_cek).is_err());
}

#[test]
fn derived_scalar_reproducible_from_seed() {
    let seed = [42u8; 64];
    let scalar = derive_account_scalar(&seed);
    assert_eq!(derive_account_scalar(&seed), scalar);
    // Clamped.
    assert_eq!(scalar[0] & 7, 0);
    assert_eq!(scalar[31] & 0x80, 0);
    assert_ne!(scalar[31] & 0x40, 0);
    let pubkey = pubkey_from_scalar(&scalar);
    assert_eq!(kid_from_pubkey(&pubkey), kid_from_pubkey(&pubkey));
}

#[test]
fn size_math_equivalence() {
    // The CLI/frontend formula must agree with get_ciphertext_size.
    #[allow(clippy::all)]
    fn legacy_formula(total_size: u64, total_chunks: u32) -> usize {
        let full = CHUNK_SIZE + 16;
        if total_chunks <= 1 {
            (total_size as usize) + 16
        } else if (total_size as usize) < (total_chunks as usize - 1) * CHUNK_SIZE {
            0
        } else {
            let full_bytes = (total_chunks as usize - 1) * full;
            let last = (total_size as usize) - (total_chunks as usize - 1) * CHUNK_SIZE + 16;
            full_bytes + last
        }
    }

    for (size, chunks) in [
        (0u64, 1u32),
        (1, 1),
        (CHUNK_SIZE as u64, 1),
        (CHUNK_SIZE as u64 - 1, 1),
        (CHUNK_SIZE as u64 + 1, 2),
        (2 * CHUNK_SIZE as u64, 2),
        (2 * CHUNK_SIZE as u64 + 5, 3),
    ] {
        assert_eq!(
            get_ciphertext_size(size as usize),
            legacy_formula(size, chunks),
            "size={size} chunks={chunks}"
        );
    }
}

#[test]
fn chacha_failed_authentication_preserves_and_cleans_output() {
    let key = [11u8; 32];
    let nonce = [12u8; 12];
    let mut ciphertext = Vec::new();
    encrypt_chunk_into(b"authenticated", &key, &nonce, 0, &mut ciphertext).unwrap();
    ciphertext[0] ^= 0x80;

    let mut output = b"existing prefix".to_vec();
    let original = output.clone();
    assert!(decrypt_chunk_into(&ciphertext, &key, &nonce, 0, &mut output).is_err());
    assert_eq!(output, original);

    for malformed in [&[][..], &[0u8][..], &[0u8; 15][..]] {
        assert!(decrypt_chunk_into(malformed, &key, &nonce, 0, &mut output).is_err());
        assert_eq!(output, original);
    }
}

#[test]
fn chunked_decrypt_failure_rolls_back_earlier_authenticated_chunks() {
    let password = "chunk rollback";
    let salt = [103u8; 16];
    let key = derive_keys(password, &salt).unwrap().0;
    let nonce = [102u8; 12];
    let plaintext = vec![0x5a; CHUNK_SIZE + 10];
    let mut ciphertext = Vec::new();
    let chunks = encrypt_into(&plaintext, &key, &nonce, &mut ciphertext).unwrap();
    *ciphertext.last_mut().unwrap() ^= 1;

    let mut output = b"prefix".to_vec();
    let original = output.clone();
    let result = decrypt_into(&ciphertext, &nonce, password, &salt, chunks, &mut output);
    assert!(result.is_err());
    assert_eq!(output, original);
}

#[test]
fn plaintext_size_rejects_malformed_tag_lengths_and_overlong_chunks() {
    for len in [0, 1, 15] {
        assert!(get_plaintext_size(1, len).is_err(), "len={len}");
        assert!(
            get_plaintext_size(2, CHUNK_SIZE + 16 + len).is_err(),
            "len={len}"
        );
    }
    assert_eq!(get_plaintext_size(1, 16).unwrap(), 0);
    assert_eq!(get_plaintext_size(1, 17).unwrap(), 1);
    assert_eq!(get_plaintext_size(1, 65_552).unwrap(), CHUNK_SIZE);
    assert_eq!(get_plaintext_size(2, 65_552 + 16).unwrap(), CHUNK_SIZE);
    assert!(get_plaintext_size(1, 65_553).is_err());
    assert!(get_plaintext_size(2, 65_552).is_err());
    assert!(get_plaintext_size(0, 16).is_err());
    assert!(get_plaintext_size(u32::MAX, usize::MAX).is_err());
}

#[test]
fn file_commitment_authenticates_identity_length_metadata_and_chunk_count() {
    let key = [31u8; 32];
    let nonce = [32u8; 24];
    let metadata = b"file|report.pdf|application/pdf";
    let context = Blake3CommitmentContext {
        paste_id: "123456",
        total_chunks: 3,
        plaintext_len: 140_000,
        metadata,
    };
    let plaintext_hash = blake3_digest(b"the authenticated plaintext").unwrap();
    let mut commitment = Vec::new();
    encrypt_blake3_commitment(
        ContentCipherKind::XChaCha20Poly1305,
        &key,
        &nonce,
        context,
        &plaintext_hash,
        &mut commitment,
    )
    .unwrap();
    assert_eq!(
        verify_blake3_commitment(
            ContentCipherKind::XChaCha20Poly1305,
            &key,
            &nonce,
            &commitment,
            context
        )
        .unwrap(),
        plaintext_hash
    );

    verify_blake3_commitment(
        ContentCipherKind::XChaCha20Poly1305,
        &key,
        &nonce,
        &commitment,
        context,
    )
    .unwrap();
    assert!(
        verify_blake3_commitment(
            ContentCipherKind::XChaCha20Poly1305,
            &key,
            &nonce,
            &commitment,
            Blake3CommitmentContext {
                paste_id: "654321",
                ..context
            },
        )
        .is_err()
    );
    assert!(
        verify_blake3_commitment(
            ContentCipherKind::XChaCha20Poly1305,
            &key,
            &nonce,
            &commitment,
            Blake3CommitmentContext {
                total_chunks: 2,
                ..context
            },
        )
        .is_err()
    );
    assert!(
        verify_blake3_commitment(
            ContentCipherKind::XChaCha20Poly1305,
            &key,
            &nonce,
            &commitment,
            Blake3CommitmentContext {
                plaintext_len: 140_001,
                ..context
            },
        )
        .is_err()
    );
    assert!(
        verify_blake3_commitment(
            ContentCipherKind::XChaCha20Poly1305,
            &key,
            &nonce,
            &commitment,
            Blake3CommitmentContext {
                metadata: b"file|changed.pdf|application/pdf",
                ..context
            },
        )
        .is_err()
    );

    commitment.pop();
    assert!(
        verify_blake3_commitment(
            ContentCipherKind::XChaCha20Poly1305,
            &key,
            &nonce,
            &commitment,
            context,
        )
        .is_err()
    );
}

#[test]
fn blake3_integrity_round_trips_empty_single_and_multichunk_content() {
    for cipher in [
        ContentCipherKind::ChaCha20Poly1305,
        ContentCipherKind::XChaCha20Poly1305,
    ] {
        let key = [71u8; 32];
        let nonce12 = [72u8; 12];
        let nonce24 = [73u8; 24];
        let nonce: &[u8] = if cipher == ContentCipherKind::XChaCha20Poly1305 {
            &nonce24
        } else {
            &nonce12
        };
        for size in [0usize, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 200_000] {
            let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let chunks = if size == 0 {
                1
            } else {
                size.div_ceil(CHUNK_SIZE) as u32
            };
            let mut ciphertext = Vec::new();
            for index in 0..chunks {
                let start = index as usize * CHUNK_SIZE;
                let end = (start + CHUNK_SIZE).min(size);
                cipher
                    .encrypt_chunk(&key, nonce, index, &plaintext[start..end], &mut ciphertext)
                    .unwrap();
            }
            let metadata = mitsuzo_types::blake3_metadata_binding(
                "456789",
                &mitsuzo_types::DataType::File,
                &Some("sample.bin".into()),
                &Some("application/octet-stream".into()),
                chunks,
                size as u64,
                true,
                false,
            );
            let context = Blake3CommitmentContext {
                paste_id: "456789",
                total_chunks: chunks,
                plaintext_len: size as u64,
                metadata: &metadata,
            };
            let plaintext_hash = blake3_digest(&plaintext).unwrap();
            encrypt_blake3_commitment(
                cipher,
                &key,
                nonce,
                context,
                &plaintext_hash,
                &mut ciphertext,
            )
            .unwrap();
            let data_len = ciphertext.len() - mitsuzo_types::BLAKE3_COMMITMENT_CIPHERTEXT_LEN;
            assert_eq!(
                verify_blake3_commitment(cipher, &key, nonce, &ciphertext[data_len..], context)
                    .unwrap(),
                plaintext_hash
            );
            assert!(
                verify_blake3_commitment(cipher, &key, nonce, &ciphertext[..data_len], context,)
                    .is_err()
            );
            let mut decrypted = Vec::new();
            for index in 0..chunks {
                let (start, end) = get_chunk_bounds(chunks, index, data_len);
                cipher
                    .decrypt_chunk(&key, nonce, index, &ciphertext[start..end], &mut decrypted)
                    .unwrap();
            }
            assert_eq!(decrypted, plaintext, "cipher={cipher:?}, size={size}");
            assert_eq!(blake3_digest(&decrypted).unwrap(), plaintext_hash);
        }
    }
}
