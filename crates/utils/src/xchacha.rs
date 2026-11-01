use orion::hazardous::aead::xchacha20poly1305;
use zeroize::Zeroize;

/// Derive a distinct XChaCha nonce for each chunk of a paste.
pub fn derive_xchacha_chunk_nonce(base_nonce: &[u8; 24], chunk_index: u32) -> [u8; 24] {
    let mut nonce = *base_nonce;
    for (byte, index) in nonce[20..].iter_mut().zip(chunk_index.to_le_bytes()) {
        *byte ^= index;
    }
    nonce
}

pub fn encrypt_xchacha_chunk_into(
    plaintext: &[u8],
    encryption_key: &[u8; 32],
    base_nonce: &[u8; 24],
    chunk_index: u32,
    output: &mut Vec<u8>,
) -> Result<(), String> {
    let key = xchacha20poly1305::SecretKey::try_from(encryption_key.as_slice())
        .map_err(|e| format!("Invalid key: {e:?}"))?;
    let nonce = xchacha20poly1305::Nonce::from(derive_xchacha_chunk_nonce(base_nonce, chunk_index));
    let offset = output.len();
    let end = offset
        .checked_add(plaintext.len())
        .and_then(|len| len.checked_add(16))
        .ok_or_else(|| "Ciphertext output length overflow".to_string())?;
    output.resize(end, 0);
    if let Err(e) = xchacha20poly1305::XChaCha20Poly1305::seal(
        &key,
        &nonce,
        plaintext,
        None,
        &mut output[offset..],
    ) {
        output.truncate(offset);
        return Err(format!("Failed to encrypt: {e:?}"));
    }
    Ok(())
}

pub fn decrypt_xchacha_chunk_into(
    ciphertext: &[u8],
    encryption_key: &[u8; 32],
    base_nonce: &[u8; 24],
    chunk_index: u32,
    output: &mut Vec<u8>,
) -> Result<(), String> {
    if ciphertext.len() < 16 {
        return Err("Ciphertext too short".to_string());
    }
    let key = xchacha20poly1305::SecretKey::try_from(encryption_key.as_slice())
        .map_err(|e| format!("Invalid key: {e:?}"))?;
    let nonce = xchacha20poly1305::Nonce::from(derive_xchacha_chunk_nonce(base_nonce, chunk_index));
    let offset = output.len();
    let end = offset
        .checked_add(ciphertext.len() - 16)
        .ok_or_else(|| "Plaintext output length overflow".to_string())?;
    output.resize(end, 0);
    if let Err(e) = xchacha20poly1305::XChaCha20Poly1305::open(
        &key,
        &nonce,
        ciphertext,
        None,
        &mut output[offset..],
    ) {
        output[offset..].zeroize();
        output.truncate(offset);
        return Err(format!("Failed to decrypt: {e:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod xchacha_tests {
    use super::*;

    #[test]
    fn chunks_round_trip_and_reject_tampering_or_wrong_index() {
        let key = [7; 32];
        let nonce = [9; 24];
        let mut ciphertext = Vec::new();
        encrypt_xchacha_chunk_into(b"secret", &key, &nonce, 2, &mut ciphertext).unwrap();
        let mut plaintext = Vec::new();
        decrypt_xchacha_chunk_into(&ciphertext, &key, &nonce, 2, &mut plaintext).unwrap();
        assert_eq!(plaintext, b"secret");
        assert!(decrypt_xchacha_chunk_into(&ciphertext, &key, &nonce, 3, &mut Vec::new()).is_err());
        ciphertext[0] ^= 1;
        let mut output = b"unchanged".to_vec();
        assert!(decrypt_xchacha_chunk_into(&ciphertext, &key, &nonce, 2, &mut output).is_err());
        assert_eq!(output, b"unchanged");
        for malformed in [&[][..], &[0u8][..], &[0u8; 15][..]] {
            assert!(decrypt_xchacha_chunk_into(malformed, &key, &nonce, 2, &mut output).is_err());
            assert_eq!(output, b"unchanged");
        }
    }

    #[test]
    fn multiple_chunks_use_distinct_nonces_and_round_trip() {
        let key = [3; 32];
        let nonce = [4; 24];
        assert_ne!(
            derive_xchacha_chunk_nonce(&nonce, 0),
            derive_xchacha_chunk_nonce(&nonce, 1)
        );
        assert_ne!(
            derive_xchacha_chunk_nonce(&nonce, u32::MAX - 1),
            derive_xchacha_chunk_nonce(&nonce, u32::MAX)
        );
        assert_ne!(
            derive_xchacha_chunk_nonce(&nonce, 0),
            derive_xchacha_chunk_nonce(&nonce, u32::MAX)
        );
        let chunks: [&[u8]; 3] = [b"first", b"second", b""];
        let mut ciphertext = Vec::new();
        let mut ranges = Vec::new();
        for (index, chunk) in chunks.iter().enumerate() {
            let start = ciphertext.len();
            encrypt_xchacha_chunk_into(chunk, &key, &nonce, index as u32, &mut ciphertext).unwrap();
            ranges.push(start..ciphertext.len());
        }
        let mut plaintext = Vec::new();
        for (index, range) in ranges.into_iter().enumerate() {
            decrypt_xchacha_chunk_into(
                &ciphertext[range],
                &key,
                &nonce,
                index as u32,
                &mut plaintext,
            )
            .unwrap();
        }
        assert_eq!(plaintext, b"firstsecond");
    }

    #[test]
    fn reordered_duplicated_and_cross_file_chunks_are_rejected() {
        let key = [14; 32];
        let nonce = [15; 24];
        let other_key = [16; 32];
        let mut first = Vec::new();
        let mut second = Vec::new();
        encrypt_xchacha_chunk_into(b"chunk zero", &key, &nonce, 0, &mut first).unwrap();
        encrypt_xchacha_chunk_into(b"chunk one", &key, &nonce, 1, &mut second).unwrap();

        assert!(decrypt_xchacha_chunk_into(&second, &key, &nonce, 0, &mut Vec::new()).is_err());
        assert!(decrypt_xchacha_chunk_into(&first, &key, &nonce, 1, &mut Vec::new()).is_err());
        assert!(
            decrypt_xchacha_chunk_into(&first, &other_key, &nonce, 0, &mut Vec::new()).is_err()
        );
    }
}
