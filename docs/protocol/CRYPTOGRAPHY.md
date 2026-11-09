# Cryptographic Primitives

## Ed25519

- **Purpose**: Block signing, vote signing, DID authentication
- **Library**: ed25519-dalek
- **Key size**: 32-byte public key, 64-byte signature
- **Why**: Fast on constrained devices (ESP32), well-studied, deterministic

### Critical Invariant

Signatures are computed over **raw Blake3 hash bytes** (32 bytes), NOT
over hex-encoded strings (64 bytes). This was a bug in PoC v0.2 and
is enforced by the API design.

## Blake3

- **Purpose**: Block hashing, DID derivation
- **Output**: 32 bytes (256 bits)
- **Why**: Faster than SHA-256, SIMD-optimized, tree-hashable for parallelism

## ChaCha20-Poly1305

- **Purpose**: Local encryption of private keys and wallet data
- **Library**: chacha20poly1305 (planned)
- **Nonce**: 12 bytes (96 bits)
- **Why**: Constant-time, no padding oracle attacks, efficient in software
- **Status (post-CRIT-002 / PR #41)**: **stub**. The
  `arxia_crypto::chacha20::{encrypt, decrypt}` symbols exist with
  signatures `Result<Vec<u8>, Unimplemented>` and currently return
  `Err(Unimplemented)`. They previously panicked via `todo!()`, which
  was the CRIT-002 finding; the new return shape forces any caller to
  handle the not-yet-implemented case at compile time. A real
  implementation will land in a dedicated commit; until then, **do not
  assume on-disk encryption is active**.

## SLIP39 (Shamir Secret Sharing)

- **Purpose**: Seed backup and recovery
- **Threshold**: Configurable k-of-n (e.g., 2-of-3)
- **Encoding**: Mnemonic word shares
- **Status (post-CRIT-003 / PR #41)**: **stub**.
  `arxia_crypto::slip39::{split_seed, reconstruct_seed}` return
  `Result<_, Unimplemented> = Err(Unimplemented)`. Same posture as
  ChaCha20-Poly1305 above: the public surface is preserved so
  callers fail at compile time rather than runtime, but no actual
  Shamir Secret Sharing happens. Real implementation deferred to a
  dedicated commit.

## ESP32 Performance

No ESP32 timing for Ed25519, Blake3 or ChaCha20 is measured or published in this repository yet.
