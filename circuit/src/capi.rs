//! External C interface for the circuit.

use crate::{Input, PrivateInput, PrivateRecipient, PublicInput, PublicRecipient};
use std::slice;

/// FFI-safe circuit input data.
#[repr(C)]
pub struct CInput {
    pub public: CPublicInput,
    pub private: CPrivateInput,
}

impl CInput {
    fn to_input(&self) -> Input<'_> {
        Input {
            public: PublicInput {
                struct_hash: self.public.struct_hash,
                nonce: self.public.nonce,
                ciphertext: unsafe { self.public.ciphertext.as_slice().into() },
                iv: self.public.iv,
                tag: self.public.tag,
                recipients: {
                    let recipients = unsafe { self.public.recipients.as_slice() };
                    recipients
                        .iter()
                        .map(|r| PublicRecipient {
                            encrypted_key: r.encrypted_key,
                            ephemeral_public_key: r.ephemeral_public_key,
                        })
                        .collect()
                },
            },
            private: PrivateInput {
                transaction: unsafe { self.private.transaction.as_slice().into() },
                content_encryption_key: self.private.content_encryption_key,
                recipients: {
                    let recipients = unsafe { self.private.recipients.as_slice() };
                    recipients
                        .iter()
                        .map(|r| PrivateRecipient {
                            public_key: r.public_key,
                            ephemeral_private_key: r.ephemeral_private_key,
                        })
                        .collect()
                },
            },
        }
    }
}

#[derive(Default)]
#[repr(C)]
pub struct CPublicInput {
    pub struct_hash: [u8; 32],
    pub nonce: [u8; 32],
    pub ciphertext: CArray<u8>,
    pub iv: [u8; 12],
    pub tag: [u8; 16],
    pub recipients: CArray<CPublicRecipient>,
}

#[derive(Default)]
#[repr(C)]
pub struct CPublicRecipient {
    pub encrypted_key: [u8; 24],
    pub ephemeral_public_key: [u8; 32],
}

#[derive(Default)]
#[repr(C)]
pub struct CPrivateInput {
    pub transaction: CArray<u8>,
    pub content_encryption_key: [u8; 16],
    pub recipients: CArray<CPrivateRecipient>,
}

#[derive(Default)]
#[repr(C)]
pub struct CPrivateRecipient {
    pub public_key: [u8; 32],
    pub ephemeral_private_key: [u8; 32],
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
            recipients: CArray::new(recipients_len),
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
    #[cfg(all(debug_assertions, target_arch = "wasm32"))]
    wasm::set_panic_hook();

    let input = unsafe { &*input }.to_input();
    crate::circuit(&input);
}

#[cfg(all(debug_assertions, target_arch = "wasm32"))]
mod wasm {
    use std::{
        panic::{self, PanicHookInfo},
        sync::Once,
    };

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
