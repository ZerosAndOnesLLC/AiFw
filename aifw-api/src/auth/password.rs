//! Password hashing for the API — a thin adapter over the workspace-wide
//! [`aifw_common::password`] module so every binary (API, setup wizard,
//! seed loader, CLI) writes identical Argon2id hashes (SEC-M4 #301).
//!
//! The pinned parameters (OWASP 2023: Argon2id, 19 MiB, t=2, p=1) live in
//! `aifw-common`; this file only maps errors to `StatusCode` for handler
//! ergonomics and owns the login-timing [`dummy_hash`].
//!
//! [`dummy_hash`] returns a process-wide dummy hash used by the login
//! handler to keep verification time constant when the supplied
//! username does not exist. It is produced from a real random password
//! using the same parameters as real users, so the attacker can't
//! fingerprint the nonexistent-user path from hash parameters or
//! verification time.

use axum::http::StatusCode;
use std::sync::OnceLock;
use uuid::Uuid;

pub fn hash_password(password: &str) -> Result<String, StatusCode> {
    aifw_common::password::hash_password(password).map_err(|e| {
        tracing::error!(error = %e, "auth: password hashing failed");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    aifw_common::password::verify_password(password, hash)
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

    /// Random per-test secret so no credential literal lives in the tree.
    fn random_secret() -> String {
        Uuid::new_v4().simple().to_string()
    }

    #[test]
    fn hash_verifies() {
        let pw = random_secret();
        let h = hash_password(&pw).unwrap();
        assert!(verify_password(&pw, &h));
        assert!(!verify_password(&random_secret(), &h));
    }

    #[test]
    fn hash_uses_argon2id_with_pinned_params() {
        let h = hash_password(&random_secret()).unwrap();
        assert!(
            h.starts_with(aifw_common::password::ARGON2_PHC_PREFIX),
            "got: {h}"
        );
    }

    #[test]
    fn dummy_hash_is_stable_and_verifies_for_nothing_useful() {
        let a = dummy_hash();
        let b = dummy_hash();
        assert_eq!(a, b);
        assert!(!verify_password(&random_secret(), a));
        assert!(!verify_password("", a));
    }
}
