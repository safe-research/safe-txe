pub mod capi;
mod ecdh;
mod encrypt;
mod hex;
mod macros;
mod rlp;
mod safe;

use crate::{
    macros::{unwrap, verify},
    safe::SafeTransaction,
};
use std::{borrow::Cow, env, iter};

/// The input to the circuit.
pub struct Input<'a> {
    /// The public input.
    pub public: PublicInput<'a>,
    /// The private input.
    pub private: PrivateInput<'a>,
}

impl Input<'static> {
    /// Gets circuit input from arguments.
    pub fn from_args() -> Self {
        let [_, public, private] = unwrap!(env::args().collect::<Vec<_>>().try_into());
        Self::decode(&public, &private)
    }

    fn decode(public: &str, private: &str) -> Self {
        let public = unwrap!(hex::decode(public));
        let private = unwrap!(hex::decode(private));
        Self {
            public: unwrap!(rlp::Decoder::new(&public).decode_struct(|decoder| {
                Ok(PublicInput {
                    struct_hash: decoder.bytes_array()?,
                    nonce: decoder.uint()?,
                    ciphertext: decoder.bytes()?.to_vec().into(),
                    iv: decoder.bytes_array()?,
                    tag: decoder.bytes_array()?,
                    recipients: decoder
                        .vec(|item| {
                            item.decode_struct(|decoder| {
                                Ok(PublicRecipient {
                                    encrypted_key: decoder.bytes_array()?,
                                    ephemeral_public_key: decoder.bytes_array()?,
                                })
                            })
                        })?
                        .into(),
                })
            })),
            private: unwrap!(rlp::Decoder::new(&private).decode_struct(|decoder| {
                Ok(PrivateInput {
                    transaction: decoder.bytes()?.to_vec().into(),
                    content_encryption_key: decoder.bytes_array()?,
                    recipients: decoder
                        .vec(|item| {
                            item.decode_struct(|decoder| {
                                Ok(PrivateRecipient {
                                    public_key: decoder.bytes_array()?,
                                    ephemeral_private_key: decoder.bytes_array()?,
                                })
                            })
                        })?
                        .into(),
                })
            })),
        }
    }
}

/// The public input to the circuit.
pub struct PublicInput<'a> {
    /// The Safe transaction struct hash.
    pub struct_hash: [u8; 32],
    /// The Safe transaction nonce.
    pub nonce: [u8; 32],
    /// The encrypted Safe transaction. The Safe transaction with `nonce` must
    /// hash to `struct_hash`.
    pub ciphertext: Cow<'a, [u8]>,
    /// The initialization vector used for encryption.
    pub iv: [u8; 12],
    /// The authentication tag.
    pub tag: [u8; 16],
    /// The recipient encrypted keys and ephemeral public keys.
    pub recipients: Cow<'a, [PublicRecipient]>,
}

/// Public input per recipient.
#[derive(Clone)]
pub struct PublicRecipient {
    /// The encrypted content key for the recipient.
    pub encrypted_key: [u8; 24],
    /// The ephemeral public key used for ECDH.
    pub ephemeral_public_key: [u8; 32],
}

/// The private input to the circuit. Should be omitted when verifying.
pub struct PrivateInput<'a> {
    /// The RLP encoded Safe transaction.
    pub transaction: Cow<'a, [u8]>,
    /// The symmetric content encryption key used to encrypt the RPL encoded
    /// Safe transaction using AES-GCM.
    pub content_encryption_key: [u8; 16],
    /// The recipient public keys and ephemeral private keys.
    pub recipients: Cow<'a, [PrivateRecipient]>,
}

/// Private input per recipient.
#[derive(Clone)]
pub struct PrivateRecipient {
    /// The recipient's public key used for encryption.
    pub public_key: [u8; 32],
    /// The ephemeral private key used for ECDH.
    pub ephemeral_private_key: [u8; 32],
}

/// The private input to the verifier program.
pub fn circuit(input: &Input) {
    // Verify the transaction matches the struct hash.
    let transaction = unwrap!(SafeTransaction::decode(&input.private.transaction));
    verify!(
        transaction.struct_hash(input.public.nonce) == input.public.struct_hash,
        "struct hash mismatch"
    );

    // Verify the content encryption integrity.
    let (ciphertext, tag) = unwrap!(encrypt::content(
        &input.private.transaction,
        input.private.content_encryption_key,
        input.public.iv
    ));
    verify!(
        *ciphertext == *input.public.ciphertext,
        "ciphertext mismatch"
    );
    verify!(tag == input.public.tag, "tag mismatch");

    // Verify the key wrapping integrity.
    verify!(
        input.public.recipients.len() == input.private.recipients.len(),
        "recipient mismatch"
    );
    for (public, private) in iter::zip(&*input.public.recipients, &*input.private.recipients) {
        // Verify the ephemeral key integrity.
        let ephemeral_public_key = ecdh::public_key(private.ephemeral_private_key);
        verify!(
            ephemeral_public_key == public.ephemeral_public_key,
            "ephemeral key mismatch"
        );

        // Verify the content key encryption.
        let shared_secret = ecdh::shared_secret(private.ephemeral_private_key, private.public_key);
        let encrypted_key = unwrap!(encrypt::key(
            input.private.content_encryption_key,
            shared_secret,
        ));
        verify!(
            encrypted_key == public.encrypted_key,
            "encrypted key mismatch"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit() {
        let input = Input::decode(
            "0xf90145a0f25354b37bde8dfdfbeb638a3e010cdd09ff6a319dbfb0ab12589de2\
               5d3352be820539b84bbf39261d44916617d853e3538b2a096ffd7ce3236210e6\
               13ed4decca6e32e4696c4f8c24734cce38a1ce3a1500f74f58b575188b33d4e8\
               ed8961aa9f0f6407db788e7f1fd5af28db6001fb8cb05c984165f2d23a28000d\
               4b9008e67b91dcd38c7a1f48b93b59ffe1b8f8b4f83a98590a3a98e58dadf522\
               baa91357ec1d0f4f5305c6dd885745a0fb74a081098bcfe6e6c1840bea1194b9\
               2c7e41912fc2347cbe0cbc7fa4a4857af83a986de31be4920402f1348ebd4431\
               6a35ca7a0af9657d863b03a01083b3b5529465bb436d52ccf5c887da31a687ad\
               778ffe0c0bc58b0d81811333f83a983f04b1dd42337e71b0421be845c9bc1e2a\
               7fcf9c45c62681a072cda02de475ad6f654f66796160377c65a26684a4f1d4b2\
               9dcb225ca180bd29",
            "0xf9012cb84bf84994a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a102840304\
               05060107080994a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a294a3a3a3a3\
               a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a390c3ba3d49dd84aaf39f49478324bc31\
               69f8ccf842a032487b2e70917797e376aed50c85902eea2c42ba4fad257a6c6b\
               b93e47e80b2fa068dd94fb8d7ca504c59fdcfd1413d7202eecbbb252ab3bbcdb\
               6e4697b4d3e463f842a0029bfe0f900e8ac0e6a98aa3ffde0ad93b46f52a5a37\
               43b9ce88296ca2385168a02065df9b0385a913255081ca19e9153391e41e3ff8\
               f3c2426c2878114cd2be66f842a0201ef1b77e2b56130b358749711812f6fcc6\
               d1543c425c32f5f5c0408731f20aa0b01923b73b27127f61932b21501a516475\
               922f0aa50f5b56cff2eeafa0521c4b",
        );
        circuit(&input);
    }
}
