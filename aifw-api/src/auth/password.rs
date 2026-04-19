//! Password hashing with explicitly-pinned Argon2id parameters.
//!
//! Using `Argon2::default()` was portable but exposed us to silent
//! strengthening/weakening whenever the `argon2` crate bumped its
//! defaults. We now pin the OWASP 2023 parameters: Argon2id, 19 MiB
//! memory, 2 passes, 1 lane.
//!
//! [`dummy_hash`] returns a process-wide dummy hash used by the login
//! handler to keep verification time constant when the supplied
//! username does not exist. Unlike the previous hardcoded constant,
//! this one is produced from a real random password using the same
//! parameters as real users, so the attacker can't fingerprint the
//! nonexistent-user path from hash parameters or verification time.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::{SaltString, rand_core::OsRng},
};
use axum::http::StatusCode;
use std::sync::OnceLock;
use uuid::Uuid;

/// OWASP 2023 Argon2id parameters:
///   m = 19 456 KiB (≈ 19 MiB)
///   t = 2
///   p = 1
fn params() -> Params {
    Params::new(19_456, 2, 1, None).expect("argon2 params are valid")
}

fn hasher() -> Argon2<'static> {
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params())
}

pub fn hash_password(password: &str) -> Result<String, StatusCode> {
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    hasher()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// Dummy hash used by the login handler to keep nonexistent-user timing
/// indistinguishable from a real failing password verify.
///
/// Generated lazily on first call from a random 32-byte password so the
/// hash parameters and structure exactly match real users. Stored in a
/// `OnceLock` so every login pays exactly one initialization cost.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        // 256-bit random "password" built from two v4 UUIDs.
        let source = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        hash_password(&source).expect("dummy hash must succeed")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_verifies() {
        let h = hash_password("hunter2").unwrap();
        assert!(verify_password("hunter2", &h));
        assert!(!verify_password("hunter3", &h));
    }

    #[test]
    fn hash_uses_argon2id_with_pinned_params() {
        let h = hash_password("x").unwrap();
        // Encoded hash starts with the algorithm + version + params.
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "got: {h}");
    }

    #[test]
    fn dummy_hash_is_stable_and_verifies_for_nothing_useful() {
        let a = dummy_hash();
        let b = dummy_hash();
        assert_eq!(a, b);
        // A guessed password shouldn't verify.
        assert!(!verify_password("password", a));
        assert!(!verify_password("", a));
    }
}
