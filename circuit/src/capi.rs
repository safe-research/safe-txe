//! External C interface for the circuit.

use crate::{Input, PrivateInput, PublicInput};
use std::slice;

/// Input to circuit.
pub struct CInput {
    /// The public input.
    pub public: CPublicInput,
    /// The private input.
    pub private: CPrivateInput,
}

impl CInput {
    /// Creates a new input.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the C arrays are valid.
    pub unsafe fn to_input<'a>(&'a self) -> Input<'a> {
        Input {
            public: PublicInput {
                struct_hash: self.public.struct_hash,
                nonce: self.public.nonce,
                ciphertext: unsafe { self.public.ciphertext.as_slice() },
                iv: self.public.iv,
                tag: self.public.tag,
                recipients: unsafe { self.public.recipients.as_slice() },
            },
            private: PrivateInput {
                transaction: unsafe { self.private.transaction.as_slice() },
                content_key: self.private.content_key,
                private_key: self.private.private_key,
            },
        }
    }
}

/// The public input circuit.
#[derive(Default)]
#[repr(C)]
pub struct CPublicInput {
    /// The Safe transaction struct hash.
    pub struct_hash: [u8; 32],
    /// The Safe transaction nonce.
    pub nonce: [u8; 32],
    /// The encrypted Safe transaction. The Safe transaction with `nonce` must
    /// hash to `struct_hash`.
    pub ciphertext: CArray<u8>,
    /// The initialization vector used for encryption.
    pub iv: [u8; 12],
    /// The authentication tag.
    pub tag: [u8; 16],
    /// The recipients of the encrypted Safe transaction.
    pub recipients: CArray<crate::Recipient>,
}

/// The private input to the circuit. This is omitted when verifying.
#[derive(Default)]
#[repr(C)]
pub struct CPrivateInput {
    /// The RLP encoded Safe transaction.
    pub transaction: CArray<u8>,
    /// The symmetric content encryption key used to encrypt the RPL encoded
    /// Safe transaction using AES-GCM.
    pub content_key: [u8; 16],
    /// The proposer's private X25519 encryption key.
    pub private_key: [u8; 32],
}

/// A C slice.
#[derive(Default)]
#[repr(C)]
pub struct CArray<T> {
    /// The pointer to the first element.
    pub data: *mut T,
    /// The number of elements.
    pub len: usize,
}

impl<T> CArray<T> {
    /// Allocates data for a new slice.
    ///
    /// The caller is responsible for freeing the allocated memory.
    pub fn new(len: usize) -> Self
    where
        T: Default,
    {
        let mut data = Box::new_uninit_slice(len);
        for item in &mut data {
            item.write(T::default());
        }
        let data = unsafe { data.assume_init() };
        let data = Box::into_raw(data).cast();
        Self { data, len }
    }
}

impl<T> CArray<T> {
    /// Creates a slice from a raw pointer and length.
    unsafe fn as_slice<'a>(&self) -> &'a [T] {
        unsafe { slice::from_raw_parts(self.data, self.len) }
    }
}

impl<T> Drop for CArray<T> {
    fn drop(&mut self) {
        if !self.data.is_null() {
            drop(unsafe { Vec::<T>::from_raw_parts(self.data, self.len, self.len) });
        }
    }
}

/// Allocates memory for the public and private inputs.
#[unsafe(no_mangle)]
pub extern "C" fn txe_input_new(transaction_len: usize, recipients_len: usize) -> *mut CInput {
    Box::into_raw(Box::new(CInput {
        public: CPublicInput {
            ciphertext: CArray::new(transaction_len),
            recipients: CArray::new(recipients_len),
            ..Default::default()
        },
        private: CPrivateInput {
            transaction: CArray::new(transaction_len),
            ..Default::default()
        },
    }))
}

/// Allocates memory for the public and private inputs.
///
/// # Safety
///
/// The caller must ensure that `input` is a valid pointer that was allocated
/// with [`txe_input_new`], and has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn txe_input_free(input: *mut CInput) {
    drop(unsafe { Box::from_raw(input) });
}

/// Executes the Safe transaction circuit.
///
/// # Safety
///
/// The caller must ensure that `input` is a valid pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn txe_circuit(input: *const CInput) {
    #[cfg(target_arch = "wasm32")]
    wasm::set_panic_hook();

    let input = unsafe { (*input).to_input() };
    crate::circuit(&input);
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::{panic::{self, PanicHookInfo}, sync::Once};

    #[link(wasm_import_module = "env")]
    unsafe extern "C" {
        fn log(str: *const u8, len: usize);
    }

    fn panic_hook(info: &PanicHookInfo) {
        let message = format!("ERROR: {info}");
        unsafe {
            log(message.as_ptr(), message.len());
        }
    }

    pub fn set_panic_hook() {
        static SET_HOOK: Once = Once::new();
         SET_HOOK.call_once(|| {
             panic::set_hook(Box::new(panic_hook));
         });
    }
}
