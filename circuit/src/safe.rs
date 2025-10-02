//! Safe smart account data structures and methods.

use crate::rlp;
use sha3::{Digest as _, Keccak256};

pub struct SafeTransaction<'a> {
    to: [u8; 20],
    value: [u8; 32],
    data: &'a [u8],
    operation: Operation,
    safe_tx_gas: [u8; 32],
    gas_gas: [u8; 32],
    gas_price: [u8; 32],
    gas_token: [u8; 20],
    refund_reciver: [u8; 20],
}

impl<'a> SafeTransaction<'a> {
    /// RLP-decodes a Safe transaction with the given `nonce`.
    pub fn decode(encoded: &'a [u8]) -> Result<Self, rlp::Error> {
        rlp::Decoder::new(encoded).decode_struct(|decoder| {
            Ok(SafeTransaction {
                to: decoder.address()?,
                value: decoder.uint()?,
                data: decoder.bytes()?,
                operation: decoder.bool()?.into(),
                safe_tx_gas: decoder.uint()?,
                gas_gas: decoder.uint()?,
                gas_price: decoder.uint()?,
                gas_token: decoder.address()?,
                refund_reciver: decoder.address()?,
            })
        })
    }

    /// Returns the Safe transaction ERC-712 struct hash.
    pub fn struct_hash(&self, nonce: [u8; 32]) -> [u8; 32] {
        let mut hasher = Keccak256::new();
        hasher.update(
            b"\xbb\x83\x10\xd4\x86\x36\x8d\xb6\xbd\x6f\x84\x94\x02\xfd\xd7\x3a\
              \xd5\x3d\x31\x6b\x5a\x4b\x26\x44\xad\x6e\xfe\x0f\x94\x12\x86\xd8",
        );
        hasher.update(address_to_word(self.to));
        hasher.update(self.value);
        hasher.update(Keccak256::digest(self.data));
        hasher.update(self.operation.as_word());
        hasher.update(self.safe_tx_gas);
        hasher.update(self.gas_gas);
        hasher.update(self.gas_price);
        hasher.update(address_to_word(self.gas_token));
        hasher.update(address_to_word(self.refund_reciver));
        hasher.update(nonce);
        hasher.finalize().into()
    }
}

pub enum Operation {
    Call,
    Delegatecall,
}

impl Operation {
    /// The operation as an EVM word.
    fn as_word(&self) -> [u8; 32] {
        match self {
            Operation::Call => [0u8; 32],
            Operation::Delegatecall => {
                let mut op = [0u8; 32];
                op[31] = 1;
                op
            }
        }
    }
}

impl From<bool> for Operation {
    fn from(value: bool) -> Self {
        if value {
            Operation::Delegatecall
        } else {
            Operation::Call
        }
    }
}

fn address_to_word(address: [u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    unsafe {
        address
            .as_ptr()
            .copy_to_nonoverlapping(word.as_mut_ptr().add(12), 20)
    };
    word
}
