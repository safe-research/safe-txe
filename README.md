# Safe Transaction Encryption Format

This repository contains the specification and a reference TypeScript for the Safe Transaction Encryption (TXE) format. Additionally, this repository includes a Rust verifier that is intended to be translated to a ZKP circuit to verify the integrity of a TXE bundle.

The Safe TXE format is a standardized encoding for encrytped Safe transactions over Secret Harbour. It is basically a binary format of JWE:
1. The payload is an RLP-encoded Safe transaction
2. Encryption using `A128GCM` (AES in GCM mode with 128-bit key)
3. Key wrapping is done using `ECDH-ES+A128KW` (Elliptic Curve Diffie-Hellman with the wrapped content encryption key encrypted with AES with a 128-bit key) on the `X25519` curve
