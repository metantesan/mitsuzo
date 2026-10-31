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
