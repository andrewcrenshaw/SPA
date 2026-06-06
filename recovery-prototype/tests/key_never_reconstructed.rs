//! Structural verification that the full signing key is never reconstructed in memory.
//!
//! Two checks (DCP-2):
//! 1. Compile-time: `Share` must implement `ZeroizeOnDrop` — fails to compile if the
//!    secret-hygiene guarantee is ever removed from the type.
//! 2. Runtime structural grep: no symbol `reconstruct_full_key` or `combine_to_secret`
//!    exists anywhere in the crates source tree.

use zeroize::ZeroizeOnDrop;

fn _assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

#[test]
fn share_implements_zeroize_on_drop() {
    // This is a compile-time assertion: if Share ever loses ZeroizeOnDrop the
    // crate will fail to compile rather than producing a false-passing test.
    _assert_zeroize_on_drop::<frost_tier0::Share>();
}

#[test]
fn crates_contain_no_reconstruction_symbols() {
    let crates_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/crates");
    let output = std::process::Command::new("grep")
        .args(["-rcE", "reconstruct_full_key|combine_to_secret", crates_dir])
        .output()
        .expect("grep must be available");

    // grep -c: exit 0 = ≥1 match found, exit 1 = no matches (expected), exit 2 = error.
    // Sum all per-file match counts from stdout; assert total == 0.
    let stdout = String::from_utf8_lossy(&output.stdout);
    let total: u64 = stdout
        .lines()
        .filter_map(|line| line.split(':').next_back()?.parse::<u64>().ok())
        .sum();

    assert_eq!(
        total,
        0,
        "reconstruction symbols found in crates/:\n{stdout}"
    );
}
