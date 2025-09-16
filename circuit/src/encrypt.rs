//! Encryption implementation.
use aes_gcm::{
    Aes128Gcm, Key, Nonce,
    aead::{AeadMutInPlace as _, KeyInit as _},
};

/// Content encryption algorithm.
pub fn content(
    plaintext: &[u8],
    key: [u8; 16],
    iv: [u8; 12],
) -> Result<(Vec<u8>, [u8; 16]), aes_gcm::Error> {
    // The static additional authenticated data used in the Safe TXE format.
    const AAD: &[u8] = br#"{"enc":"A128GCM"}"#;

    let key = Key::<Aes128Gcm>::from(key);
    let iv = Nonce::from(iv);

    let mut cipher = Aes128Gcm::new(&key);
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher.encrypt_in_place_detached(&iv, AAD, &mut ciphertext)?;

    Ok((ciphertext, tag.into()))
}

/// Content key encryption algorithm.
pub fn key(
    content_key: [u8; 16],
    public_key: [u8; 32],
    private_key: [u8; 32],
) -> Result<[u8; 24], aes_gcm::Error> {
    let _ = (content_key, public_key, private_key);
    Ok([0; 24])
}
