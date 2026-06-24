//! KC-2.1 (PCC-3188) — Secure-Enclave + ECIES probe. **Throwaway spike, not production.**
//!
//! Settles ADR-004 Checkpoint 1 (D1): does the `security-framework` crate expose enough
//! Secure-Enclave surface to keep `forbid(unsafe_code)` on every SPA crate, or is the
//! quarantined raw-FFI `spa-se-bridge` fallback needed?
//!
//! Using **only safe `security-framework` APIs** (this file contains zero `unsafe`, so the
//! cli crate keeps `[lints] workspace = true` → `unsafe_code = "forbid"` intact), the probe:
//!   1. Generates a non-exportable P-256 key whose private half lives in the Secure Enclave
//!      (`Token::SecureEnclave` + `kSecAccessControlPrivateKeyUsage`).
//!   2. ECIES-encrypts a random 32-byte secret to the key's PUBLIC half, using
//!      `Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM` — the ADR-004 §D3 pin.
//!   3. Decrypts the ciphertext back THROUGH the Enclave and asserts the 32 bytes round-trip.
//!
//! Nothing in `src/` depends on this example and `persistence.rs` is untouched, per ADR-004
//! ("Until both [checkpoints] are confirmed, `persistence.rs` is not modified").
//!
//! ## Run (Apple silicon)
//! ```sh
//! cargo build --example se_probe -p spa-recovery-cli
//! codesign -s - target/debug/examples/se_probe   # ad-hoc signature: enough for an SE key (ADR-004 §D2)
//! target/debug/examples/se_probe
//! ```
//! Exit 0 + "PROBE PASSED" on a successful round-trip; non-zero on any failure.

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use core_foundation::base::CFOptionFlags;
    use rand_core::{OsRng, RngCore};
    use security_framework::access_control::SecAccessControl;
    use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};

    // ADR-004 §D3 / Open-question 3 ECIES pin: cofactor X9.63 KDF, SHA-256, AES-GCM.
    const ECIES: Algorithm = Algorithm::ECIESEncryptionCofactorX963SHA256AESGCM;

    // kSecAccessControlPrivateKeyUsage (security_framework_sys::access_control) == 1 << 30.
    // The safe `security-framework` crate does NOT re-export this constant and its
    // `create_with_flags` takes a raw `CFOptionFlags`, so we restate the value here.
    // Referencing a plain `const` value is safe code — no `unsafe` is introduced.
    const PRIVATE_KEY_USAGE: CFOptionFlags = 1 << 30;

    eprintln!("se_probe: Secure-Enclave + ECIES probe (ADR-004 Checkpoint 1 / PCC-3188)");

    // 1. Generate an SE-resident P-256 key. No keychain location is set, so the key is
    //    non-permanent (kSecAttrIsPermanent=false) — it needs only an ad-hoc code signature,
    //    not a provisioned keychain-access-group. The private half is non-exportable and
    //    never leaves the Enclave.
    let access_control = SecAccessControl::create_with_flags(PRIVATE_KEY_USAGE)?;
    let mut opts = GenerateKeyOptions::default();
    opts.set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave)
        .set_access_control(access_control)
        .set_label("spa-se-probe-pcc3188");
    let se_key: SecKey = SecKey::new(&opts)?;
    eprintln!("  [1/3] generated non-exportable SE P-256 key");

    // 2. ECIES-encrypt a fresh 32-byte secret to the PUBLIC half. Ciphertext is safe in the
    //    clear: only this Enclave's private key can unwrap it.
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let public_key = se_key
        .public_key()
        .ok_or("SE key exposed no public half")?;
    let ciphertext = public_key.encrypt_data(ECIES, &secret)?;
    eprintln!(
        "  [2/3] ECIES-encrypted 32-byte secret to SE public key ({} bytes ciphertext)",
        ciphertext.len()
    );

    // 3. Decrypt back THROUGH the Enclave. Apple symbol: `SecKeyCreateDecryptedData`. The
    //    security-framework crate exposes it as `SecKey::decrypt_data` — there is no
    //    `create_decrypted_data` method on the safe wrapper (encrypt side: `encrypt_data`
    //    ↔ `SecKeyCreateEncryptedData`). Recording that crate-vs-Apple naming gap is part of
    //    this probe's D1 finding.
    let recovered = se_key.decrypt_data(ECIES, &ciphertext)?;
    eprintln!("  [3/3] decrypted via the Enclave ({} bytes)", recovered.len());

    if recovered.as_slice() != secret.as_slice() {
        return Err(format!(
            "round-trip MISMATCH: got {} bytes, expected the original 32",
            recovered.len()
        )
        .into());
    }

    println!("PROBE PASSED: 32-byte secret round-tripped through an SE-resident P-256 key.");
    println!("VERDICT (D1): security-framework crate is SUFFICIENT — no spa-se-bridge shim needed.");
    Ok(())
}

// Secure Enclave is Apple-only. Keep the workspace building (and `cargo test --workspace`
// green) on non-Apple CI per ADR-004 §D4.
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
fn main() {
    eprintln!("se_probe: Secure Enclave is Apple-only; this probe is a no-op on this target.");
}
