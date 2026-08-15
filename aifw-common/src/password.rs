//! Password / secret hashing with explicitly-pinned Argon2id parameters.
//!
//! Every place that writes a credential hash into `aifw.db` — the API's
//! runtime user management, the first-boot wizard (`aifw-setup`), the
//! unattended seed loader, and `aifw users add` — must produce the same
//! hash shape so the first admin account is never weaker than the ones
//! created later (SEC-M4 #301). `Argon2::default()` is deliberately not
//! used anywhere: its parameters silently change when the `argon2` crate
//! bumps its defaults.
//!
//! Parameters are the OWASP 2023 recommendation for Argon2id:
//! `m = 19 456 KiB (≈19 MiB), t = 2, p = 1`.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{SaltString, rand_core::OsRng},
};

use crate::error::{AifwError, Result};

/// Argon2id memory cost in KiB.
pub const ARGON2_M_COST_KIB: u32 = 19_456;
/// Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 2;
/// Argon2id parallelism (lanes).
pub const ARGON2_P_COST: u32 = 1;

/// PHC-string prefix every hash produced by [`hash_password`] starts with.
/// Handy for tests and for spotting a legacy/default-parameter hash.
pub const ARGON2_PHC_PREFIX: &str = "$argon2id$v=19$m=19456,t=2,p=1$";

fn params() -> Params {
    // The constants above are compile-time fixed and within the crate's
    // documented bounds, so construction cannot fail.
    Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, None)
        .expect("pinned argon2 params are valid")
}

/// The single hasher configuration used across all AiFw binaries.
pub fn hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params())
}

/// Hash `password` (or any secret: API key, refresh token, recovery code)
/// with a fresh random salt. Returns the PHC-encoded string.
pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| AifwError::Crypto(format!("argon2 hash failed: {e}")))
}

/// Verify `password` against a PHC-encoded hash. Malformed hashes verify
/// as `false` rather than erroring, so callers can treat any stored value
/// uniformly. Hashes written with older parameters still verify — the
/// parameters are read from the PHC string, not from [`hasher`].
pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_round_trips() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
    }

    #[test]
    fn hash_uses_pinned_argon2id_params() {
        let h = hash_password("x").unwrap();
        assert!(h.starts_with(ARGON2_PHC_PREFIX), "got: {h}");
    }

    #[test]
    fn malformed_hash_never_verifies() {
        assert!(!verify_password("x", ""));
        assert!(!verify_password("x", "not-a-phc-string"));
    }

    #[test]
    fn hash_with_other_params_still_verifies() {
        // A hash written by an older build with different parameters must
        // keep working so existing accounts survive the upgrade — the
        // params come from the PHC string, not from `hasher()`.
        let salt = SaltString::generate(&mut OsRng);
        let other = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(4096, 3, 1, None).unwrap(),
        )
        .hash_password(b"legacy-pw", &salt)
        .unwrap()
        .to_string();
        assert!(!other.starts_with(ARGON2_PHC_PREFIX), "got: {other}");
        assert!(verify_password("legacy-pw", &other));
        assert!(!verify_password("wrong", &other));
    }
}
