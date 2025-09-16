pub mod capi;
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
    /// The recipients of the encrypted Safe transaction.
    pub recipients: &'a [Recipient],
}

/// The private input to the circuit. Should be omitted when verifying.
pub struct PrivateInput<'a> {
    /// The RLP encoded Safe transaction.
    pub transaction: &'a [u8],
    /// The symmetric content encryption key used to encrypt the RPL encoded
    /// Safe transaction using AES-GCM.
    pub content_key: [u8; 16],
    /// The proposer's private X25519 encryption key.
    pub private_key: [u8; 32],
}

/// A recipient.
#[derive(Default)]
#[repr(C)]
pub struct Recipient {
    /// The recipient's public X25519 encryption key.
    pub public_key: [u8; 32],
    /// The encrypted content key for the recipient.
    pub encrypted_key: [u8; 24],
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
    for recipient in input.public.recipients {
        let encrypted_key = unwrap!(encrypt::key(
            input.private.content_key,
            input.private.private_key,
            recipient.public_key,
        ));
        verify!(
            encrypted_key == recipient.encrypted_key,
            "encrypted key mismatch"
        );
    }
}
