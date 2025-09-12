/// The public input to the verifier program.
pub struct PublicInput<'a> {
    /// The Safe transaction struct hash.
    pub struct_hash: [u8; 32],
    /// The Safe transaction nonce.
    pub nonce: u64,
    /// The encrypted Safe transaction. The Safe transaction with `nonce` must
    /// hash to `struct_hash`.
    pub ciphertext: &'a [u8],
    /// The initialization vector used for encryption.
    pub iv: [u8; 12],
    /// The recipients of the encrypted Safe transaction.
    pub recipients: &'a [Recipient],
}

/// The private input that is passed to the prover, but omitted from the
/// verifier.
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
pub struct Recipient {
    /// The recipient's public X25519 encryption key.
    pub public_key: [u8; 32],
    /// The encrypted content key for the recipient.
    pub encrypted_key: [u8; 40],
}

/// The private input to the verifier program.
pub fn circuit(public: PublicInput, private: PrivateInput) {

}
