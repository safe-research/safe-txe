//! External C interface for the circuit.

use crate::{Input, PrivateInput, PrivateRecipient, PublicInput, PublicRecipient, hex, rlp};
use std::ffi::{CStr, c_char};

/// Circuit execution result.
#[repr(C)]
pub enum CircuitResult {
    /// The circuit executed successfully.
    Success = 0,
    /// The circuit failed to execute.
    Failure = -1,
}

/// Executes the Safe transaction circuit.
///
/// # Safety
///
/// The caller must ensure that `public` and `private` are valid pointers to
/// null-terminated C strings.
#[cfg_attr(not(target_arch = "wasm32"), unsafe(no_mangle))]
pub unsafe extern "C" fn txe_circuit(
    public: *const c_char,
    private: *const c_char,
) -> CircuitResult {
    let Some(public) = arg(public, |decoder| {
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
    }) else {
        return CircuitResult::Failure;
    };

    let Some(private) = arg(private, |decoder| {
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
    }) else {
        return CircuitResult::Failure;
    };

    let input = Input { public, private };
    match crate::circuit(&input) {
        Ok(()) => CircuitResult::Success,
        Err(_) => CircuitResult::Failure,
    }
}

fn arg<T, F>(s: *const c_char, f: F) -> Option<T>
where
    F: FnOnce(&mut rlp::Decoder) -> Result<T, rlp::Error>,
{
    let s = unsafe { CStr::from_ptr(s) }.to_str().ok()?;
    let hex = hex::decode(s).ok()?;
    let mut decoder = rlp::Decoder::new(&hex);
    decoder.decode_struct(f).ok()
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use std::{
        ffi::c_char,
        mem::MaybeUninit,
        panic::{self, PanicHookInfo},
    };

    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        fn args_get(argv: *mut *mut c_char, argb: *mut c_char) -> i32;
        fn args_sizes_get(argc: *mut usize, argb_size: *mut usize) -> i32;
        fn proc_exit(code: i32) -> !;
    }

    #[cfg(debug_assertions)]
    #[link(wasm_import_module = "env")]
    unsafe extern "C" {
        fn log(str: *const u8, len: usize);
    }

    #[unsafe(export_name = "_start")]
    pub unsafe extern "C" fn start() -> ! {
        panic::set_hook(Box::new(panic_hook));

        let (argc, argb_size) = unsafe {
            let mut argc = MaybeUninit::uninit();
            let mut argb_size = MaybeUninit::uninit();
            let result = args_sizes_get(argc.as_mut_ptr(), argb_size.as_mut_ptr());
            if result != 0 {
                exit(1);
            };
            (argc.assume_init(), argb_size.assume_init())
        };
        if argc != 3 {
            exit(1);
        }

        let mut argb = Box::<[c_char]>::new_uninit_slice(argb_size);
        let result = {
            let argv = unsafe {
                let mut argv = MaybeUninit::<[*mut c_char; 3]>::uninit();
                let result = args_get(argv.as_mut_ptr().cast(), argb.as_mut_ptr().cast());
                if result != 0 {
                    exit(1);
                }
                argv.assume_init()
            };

            let [_, public, private] = argv;
            unsafe { super::txe_circuit(public, private) }
        };

        exit(result as _);
    }

    fn exit(code: i32) -> ! {
        unsafe { proc_exit(code) }
    }

    fn panic_hook(info: &PanicHookInfo) {
        #[cfg(debug_assertions)]
        {
            let message = format!("ERROR: {info}");
            unsafe {
                log(message.as_ptr(), message.len());
            }
        }
        #[cfg(not(debug_assertions))]
        let _ = info;
        exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit() {
        let public = c"0xf90145a0f25354b37bde8dfdfbeb638a3e010cdd09ff6a319dbfb0ab12589de2\
                         5d3352be820539b84bbf39261d44916617d853e3538b2a096ffd7ce3236210e6\
                         13ed4decca6e32e4696c4f8c24734cce38a1ce3a1500f74f58b575188b33d4e8\
                         ed8961aa9f0f6407db788e7f1fd5af28db6001fb8cb05c984165f2d23a28000d\
                         4b9008e67b91dcd38c7a1f48b93b59ffe1b8f8b4f83a98590a3a98e58dadf522\
                         baa91357ec1d0f4f5305c6dd885745a0fb74a081098bcfe6e6c1840bea1194b9\
                         2c7e41912fc2347cbe0cbc7fa4a4857af83a986de31be4920402f1348ebd4431\
                         6a35ca7a0af9657d863b03a01083b3b5529465bb436d52ccf5c887da31a687ad\
                         778ffe0c0bc58b0d81811333f83a983f04b1dd42337e71b0421be845c9bc1e2a\
                         7fcf9c45c62681a072cda02de475ad6f654f66796160377c65a26684a4f1d4b2\
                         9dcb225ca180bd29";
        let private = c"0xf9012cb84bf84994a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a102840304\
                          05060107080994a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a294a3a3a3a3\
                          a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a390c3ba3d49dd84aaf39f49478324bc31\
                          69f8ccf842a032487b2e70917797e376aed50c85902eea2c42ba4fad257a6c6b\
                          b93e47e80b2fa068dd94fb8d7ca504c59fdcfd1413d7202eecbbb252ab3bbcdb\
                          6e4697b4d3e463f842a0029bfe0f900e8ac0e6a98aa3ffde0ad93b46f52a5a37\
                          43b9ce88296ca2385168a02065df9b0385a913255081ca19e9153391e41e3ff8\
                          f3c2426c2878114cd2be66f842a0201ef1b77e2b56130b358749711812f6fcc6\
                          d1543c425c32f5f5c0408731f20aa0b01923b73b27127f61932b21501a516475\
                          922f0aa50f5b56cff2eeafa0521c4b";

        unsafe { txe_circuit(public.as_ptr(), private.as_ptr()) };
    }
}
