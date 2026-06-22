//! End-to-end integration tests for the full Tier-0 lifecycle.

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

fn recovery(tmp: &TempDir) -> Command {
    let mut cmd = Command::cargo_bin("recovery").unwrap();
    cmd.env("SPA_RECOVERY_HOME", tmp.path());
    cmd
}

// ── e2e_onboard ───────────────────────────────────────────────────────────────

#[test]
fn e2e_onboard() {
    let tmp = TempDir::new().unwrap();

    recovery(&tmp)
        .args(["onboard", "--user", "alice"])
        .assert()
        .success()
        .stdout(contains("onboarded: alice"))
        .stdout(contains(
            "shares: device.share cloud.share recovery_code.share",
        ))
        .stdout(contains("state: Onboarded"));

    // Three share files exist
    for name in ["device.share", "cloud.share", "recovery_code.share"] {
        assert!(
            tmp.path().join("alice").join(name).exists(),
            "{name} missing"
        );
    }

    // Identity anchor receipt exists
    let receipts_path = tmp.path().join("alice").join("receipts.json");
    assert!(receipts_path.exists(), "receipts.json missing");
    let receipts: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&receipts_path).unwrap()).unwrap();
    let arr = receipts.as_array().unwrap();
    assert_eq!(arr.len(), 1, "expected exactly one anchor receipt");
    assert_eq!(
        arr[0]["kind"].as_str().unwrap(),
        "recovery_initiation",
        "anchor must be recovery_initiation"
    );
    assert!(
        arr[0]["prev_hash"].is_null(),
        "anchor must have no prev_hash"
    );
}

// ── e2e_sign ──────────────────────────────────────────────────────────────────

#[test]
fn e2e_sign() {
    let tmp = TempDir::new().unwrap();

    recovery(&tmp)
        .args(["onboard", "--user", "bob"])
        .assert()
        .success();

    recovery(&tmp)
        .args(["sign", "--user", "bob", "--message", "hello-spa"])
        .assert()
        .success()
        .stdout(contains("signature:"))
        .stdout(contains("verified: ok"));
}

// ── e2e_recover ───────────────────────────────────────────────────────────────

#[test]
fn e2e_recover() {
    let tmp = TempDir::new().unwrap();

    recovery(&tmp)
        .args(["onboard", "--user", "carol"])
        .assert()
        .success();

    recovery(&tmp)
        .args(["lose-device", "--user", "carol"])
        .assert()
        .success()
        .stdout(contains("device share removed"));

    recovery(&tmp)
        .args(["recover", "--user", "carol"])
        .assert()
        .success()
        .stdout(contains("state: Cooldown"));

    // Advance past the 48-hour cooldown (172801 s = 48h + 1s)
    recovery(&tmp)
        .args(["cooldown-advance", "--user", "carol", "--secs", "172801"])
        .env("SPA_TEST_CLOCK", "1")
        .assert()
        .success()
        .stdout(contains("Probation"));

    // Advance past the 24-hour probation (86401 s = 24h + 1s)
    recovery(&tmp)
        .args(["cooldown-advance", "--user", "carol", "--secs", "86401"])
        .env("SPA_TEST_CLOCK", "1")
        .assert()
        .success()
        .stdout(contains("Live"));
}

// ── e2e_audit ─────────────────────────────────────────────────────────────────

#[test]
fn e2e_audit() {
    let tmp = TempDir::new().unwrap();

    recovery(&tmp)
        .args(["onboard", "--user", "dave"])
        .assert()
        .success();

    recovery(&tmp)
        .args(["lose-device", "--user", "dave"])
        .assert()
        .success();

    recovery(&tmp)
        .args(["recover", "--user", "dave"])
        .assert()
        .success();

    recovery(&tmp)
        .args(["audit", "--user", "dave"])
        .assert()
        .success()
        .stdout(contains("chain: ok"));
}

// ── DCP-2: cooldown-advance refused without SPA_TEST_CLOCK ───────────────────

#[test]
fn cooldown_advance_refused_without_test_clock() {
    let tmp = TempDir::new().unwrap();

    recovery(&tmp)
        .args(["onboard", "--user", "eve"])
        .assert()
        .success();

    // Deliberately do NOT set SPA_TEST_CLOCK
    Command::cargo_bin("recovery")
        .unwrap()
        .env("SPA_RECOVERY_HOME", tmp.path())
        .env_remove("SPA_TEST_CLOCK")
        .args(["cooldown-advance", "--user", "eve", "--secs", "1"])
        .assert()
        .failure()
        .stderr(contains("SPA_TEST_CLOCK=1"));
}
