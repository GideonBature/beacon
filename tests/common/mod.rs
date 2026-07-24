//! Shared helpers for Beacon integration tests.

#![allow(dead_code)]

use beacon::ClaimMini;

#[must_use]
pub fn valid_claim() -> ClaimMini {
    ClaimMini::make_valid(
        [0x01; 32],
        100_000,
        40_000,
        [0x10; 32],
        [0x11; 32],
        [0x12; 32],
        [0x13; 32],
    )
}

#[must_use]
pub fn invalid_claim() -> ClaimMini {
    let mut c = valid_claim();
    c.total_out = 250_000;
    c
}

pub fn temp_dir(prefix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "beacon-itest-{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}
