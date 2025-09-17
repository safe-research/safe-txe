pub mod capi;
mod ecdh;
mod encrypt;
mod macros;
mod rlp;
mod safe;

use crate::{
    macros::{unwrap, verify},
    safe::SafeTransaction,
};

/// The input to the circuit.
pub struct Input<'a> {
    /// The public input.
    pub public: PublicInput<'a>,
    /// The private input.
    pub private: PrivateInput<'a>,
}

/// The public input to the circuit.
pub struct PublicInput<'a> {
    /// The Safe transaction struct hash.
    pub struct_hash: [u8; 32],
    /// The Safe transaction nonce.
    pub nonce: [u8; 32],
    /// The encrypted Safe transaction. The Safe transaction with `nonce` must
    /// hash to `struct_hash`.
    pub ciphertext: &'a [u8],
    /// The initialization vector used for encryption.
    pub iv: [u8; 12],
    /// The authentication tag.
    pub tag: [u8; 16],
    /// The recipient encrypted keys and ephemeral public keys.
    pub recipients: &'a [PublicRecipient],
}

/// Public input per recipient.
pub struct PublicRecipient {
    /// The encrypted content key for the recipient.
    pub encrypted_key: [u8; 24],
    /// The ephemeral public key used for ECDH.
    pub ephemeral_public_key: [u8; 32],
}

/// The private input to the circuit. Should be omitted when verifying.
pub struct PrivateInput<'a> {
    /// The RLP encoded Safe transaction.
    pub transaction: &'a [u8],
    /// The symmetric content encryption key used to encrypt the RPL encoded
    /// Safe transaction using AES-GCM.
    pub content_key: [u8; 16],
    /// The recipient public keys and ephemeral private keys.
    pub recipients: &'a [PrivateRecipient],
}

/// Private input per recipient.
pub struct PrivateRecipient {
    /// The recipient's public key used for encryption.
    pub public_key: [u8; 32],
    /// The ephemeral private key used for ECDH.
    pub ephemeral_private_key: [u8; 32],
}

/// The private input to the verifier program.
pub fn circuit(input: &Input) {
    // Verify the transaction matches the struct hash.
    let transaction = unwrap!(SafeTransaction::decode(input.private.transaction));
    verify!(
        transaction.struct_hash(input.public.nonce) == input.public.struct_hash,
        "struct hash mismatch"
    );

    // Verify the content encryption integrity.
    let (ciphertext, tag) = unwrap!(encrypt::content(
        input.private.transaction,
        input.private.content_key,
        input.public.iv
    ));
    verify!(ciphertext == input.public.ciphertext, "ciphertext mismatch");
    verify!(tag == input.public.tag, "tag mismatch");

    // Verify the key wrapping integrity.
    verify!(input.public.recipients.len() == input.private.recipients.len(), "recipient mismatch");
    for (public, private) in input.public.recipients.iter().zip(input.private.recipients.iter()) {
        // Verify the ephemeral key integrity.
        let ephemeral_public_key = ecdh::public_key(private.ephemeral_private_key);
        verify!(ephemeral_public_key == public.ephemeral_public_key, "ephemeral key mismatch");

        // Verify the content key encryption.
        let shared_secret = ecdh::shared_secret(
            private.ephemeral_private_key,
            private.public_key,
        );
        let encrypted_key = unwrap!(encrypt::key(
            input.private.content_key,
            shared_secret,
        ));
        verify!(
            encrypted_key == public.encrypted_key,
            "encrypted key mismatch"
        );
    }
}
