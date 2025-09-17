//! Encryption implementation.
use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{AeadMutInPlace as _, KeyInit as _},
};
use aes_kw::KekAes128;
use sha2::{Digest as _, Sha256};

/// Content encryption algorithm.
pub fn content(
    plaintext: &[u8],
    key: [u8; 16],
    iv: [u8; 12],
) -> Result<(Vec<u8>, [u8; 16]), aes_gcm::Error> {
    // The static additional authenticated data used in the Safe TXE format.
    // This is the base64url encoding of {"enc":"A128GCM"} without padding.
    const AAD: &[u8] = br#"eyJlbmMiOiJBMTI4R0NNIn0"#;

    let key = Key::<Aes128Gcm>::from(key);
    let iv = Nonce::from(iv);

    let mut cipher = Aes128Gcm::new(&key);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(&iv, AAD, &mut ciphertext)?;

    Ok((ciphertext, tag.into()))
}

/// Content key encryption algorithm.
pub fn key(key: [u8; 16], shared_secret: [u8; 32]) -> Result<[u8; 24], aes_kw::Error> {
    let kek = kdf(shared_secret);
    let mut encrypted_key = [0u8; 24];
    kek.wrap(&key, &mut encrypted_key)?;
    Ok(encrypted_key)
}

/// Key derivation algorithm from a shared secret to a key encryption key.
fn kdf<const N: usize>(shared_secret: [u8; N]) -> KekAes128 {
    // Concat KDF algorithm from NIST SP 800-56A, with fixed parameters for
    // a 128-bit key, the SHA-256 as the hash function, and "other info".
    const KEY_LEN: usize = 16;
    const OTHER_INFO: &[u8] = b"\x00\x00\x00\x0e\x45\x43\x44\x48\x2d\x45\x53\x2b\x41\x31\x32\
          \x38\x4b\x57\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80";
    const HASH_LEN: usize = 32;
    const REPS: usize = KEY_LEN.div_ceil(HASH_LEN);

    let mut dk = [[0; HASH_LEN]; REPS];
    for i in 0..REPS {
        let index = (i as u32).wrapping_add(1);
        let mut hasher = Sha256::new();
        hasher.update(index.to_be_bytes());
        hasher.update(shared_secret);
        hasher.update(OTHER_INFO);
        let digest = hasher.finalize().into();
        unsafe { *dk.get_unchecked_mut(i) = digest };
    }

    let k = unsafe { dk.as_ptr().cast::<[u8; KEY_LEN]>().read() };
    KekAes128::from(k)
}
