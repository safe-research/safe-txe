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
    pub content_encryption_key: [u8; 16],
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
        input.private.content_encryption_key,
        input.public.iv
    ));
    verify!(ciphertext == input.public.ciphertext, "ciphertext mismatch");
    verify!(tag == input.public.tag, "tag mismatch");

    // Verify the key wrapping integrity.
    verify!(
        input.public.recipients.len() == input.private.recipients.len(),
        "recipient mismatch"
    );
    for (public, private) in input
        .public
        .recipients
        .iter()
        .zip(input.private.recipients.iter())
    {
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
        let input = Input {
            public: PublicInput {
                struct_hash: *b"\xf2\x53\x54\xb3\x7b\xde\x8d\xfd\xfb\xeb\x63\x8a\x3e\x01\x0c\xdd\
                                \x09\xff\x6a\x31\x9d\xbf\xb0\xab\x12\x58\x9d\xe2\x5d\x33\x52\xbe",
                nonce: *b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\
                          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x39",
                ciphertext: b"\xbf\x39\x26\x1d\x44\x91\x66\x17\xd8\x53\xe3\x53\x8b\x2a\x09\x6f\
                              \xfd\x7c\xe3\x23\x62\x10\xe6\x13\xed\x4d\xec\xca\x6e\x32\xe4\x69\
                              \x6c\x4f\x8c\x24\x73\x4c\xce\x38\xa1\xce\x3a\x15\x00\xf7\x4f\x58\
                              \xb5\x75\x18\x8b\x33\xd4\xe8\xed\x89\x61\xaa\x9f\x0f\x64\x07\xdb\
                              \x78\x8e\x7f\x1f\xd5\xaf\x28\xdb\x60\x01\xfb",
                iv: *b"\xb0\x5c\x98\x41\x65\xf2\xd2\x3a\x28\x00\x0d\x4b",
                tag: *b"\x08\xe6\x7b\x91\xdc\xd3\x8c\x7a\x1f\x48\xb9\x3b\x59\xff\xe1\xb8",
                recipients: &[
                    PublicRecipient {
                        encrypted_key:
                            *b"\x59\x0a\x3a\x98\xe5\x8d\xad\xf5\x22\xba\xa9\x13\x57\xec\x1d\x0f\
                               \x4f\x53\x05\xc6\xdd\x88\x57\x45",
                        ephemeral_public_key:
                            *b"\xfb\x74\xa0\x81\x09\x8b\xcf\xe6\xe6\xc1\x84\x0b\xea\x11\x94\xb9\
                               \x2c\x7e\x41\x91\x2f\xc2\x34\x7c\xbe\x0c\xbc\x7f\xa4\xa4\x85\x7a",
                    },
                    PublicRecipient {
                        encrypted_key:
                            *b"\x6d\xe3\x1b\xe4\x92\x04\x02\xf1\x34\x8e\xbd\x44\x31\x6a\x35\xca\
                               \x7a\x0a\xf9\x65\x7d\x86\x3b\x03",
                        ephemeral_public_key:
                            *b"\x10\x83\xb3\xb5\x52\x94\x65\xbb\x43\x6d\x52\xcc\xf5\xc8\x87\xda\
                               \x31\xa6\x87\xad\x77\x8f\xfe\x0c\x0b\xc5\x8b\x0d\x81\x81\x13\x33",
                    },
                    PublicRecipient {
                        encrypted_key:
                            *b"\x3f\x04\xb1\xdd\x42\x33\x7e\x71\xb0\x42\x1b\xe8\x45\xc9\xbc\x1e\
                               \x2a\x7f\xcf\x9c\x45\xc6\x26\x81",
                        ephemeral_public_key:
                            *b"\x72\xcd\xa0\x2d\xe4\x75\xad\x6f\x65\x4f\x66\x79\x61\x60\x37\x7c\
                               \x65\xa2\x66\x84\xa4\xf1\xd4\xb2\x9d\xcb\x22\x5c\xa1\x80\xbd\x29",
                    },
                ],
            },
            private: PrivateInput {
                transaction: b"\xf8\x49\x94\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\xa1\
                               \xa1\xa1\xa1\xa1\xa1\xa1\xa1\x02\x84\x03\x04\x05\x06\x01\x07\x08\
                               \x09\x94\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2\xa2\
                               \xa2\xa2\xa2\xa2\xa2\xa2\x94\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\
                               \xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3\xa3",
                content_encryption_key:
                    *b"\xc3\xba\x3d\x49\xdd\x84\xaa\xf3\x9f\x49\x47\x83\x24\xbc\x31\x69",
                recipients: &[
                    PrivateRecipient {
                        public_key:
                            *b"\x32\x48\x7b\x2e\x70\x91\x77\x97\xe3\x76\xae\xd5\x0c\x85\x90\x2e\
                               \xea\x2c\x42\xba\x4f\xad\x25\x7a\x6c\x6b\xb9\x3e\x47\xe8\x0b\x2f",
                        ephemeral_private_key:
                            *b"\x68\xdd\x94\xfb\x8d\x7c\xa5\x04\xc5\x9f\xdc\xfd\x14\x13\xd7\x20\
                               \x2e\xec\xbb\xb2\x52\xab\x3b\xbc\xdb\x6e\x46\x97\xb4\xd3\xe4\x63",
                    },
                    PrivateRecipient {
                        public_key:
                            *b"\x02\x9b\xfe\x0f\x90\x0e\x8a\xc0\xe6\xa9\x8a\xa3\xff\xde\x0a\xd9\
                               \x3b\x46\xf5\x2a\x5a\x37\x43\xb9\xce\x88\x29\x6c\xa2\x38\x51\x68",
                        ephemeral_private_key:
                            *b"\x20\x65\xdf\x9b\x03\x85\xa9\x13\x25\x50\x81\xca\x19\xe9\x15\x33\
                               \x91\xe4\x1e\x3f\xf8\xf3\xc2\x42\x6c\x28\x78\x11\x4c\xd2\xbe\x66",
                    },
                    PrivateRecipient {
                        public_key:
                            *b"\x20\x1e\xf1\xb7\x7e\x2b\x56\x13\x0b\x35\x87\x49\x71\x18\x12\xf6\
                               \xfc\xc6\xd1\x54\x3c\x42\x5c\x32\xf5\xf5\xc0\x40\x87\x31\xf2\x0a",
                        ephemeral_private_key:
                            *b"\xb0\x19\x23\xb7\x3b\x27\x12\x7f\x61\x93\x2b\x21\x50\x1a\x51\x64\
                               \x75\x92\x2f\x0a\xa5\x0f\x5b\x56\xcf\xf2\xee\xaf\xa0\x52\x1c\x4b",
                    },
                ],
            },
        };
        circuit(&input);
    }
}
