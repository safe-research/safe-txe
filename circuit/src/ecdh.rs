//! Elliptic Curve Diffie-Hellman (ECDH) key exchange implementation.

use curve25519_dalek::{MontgomeryPoint};

/// Compute the public key.
pub fn public_key(private_key: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(private_key).to_bytes()
}

/// Compute a shared secret.
pub fn shared_secret(private_key: [u8; 32], public_key: [u8; 32]) -> [u8; 32] {
    MontgomeryPoint(public_key).mul_clamped(private_key).to_bytes()
}
