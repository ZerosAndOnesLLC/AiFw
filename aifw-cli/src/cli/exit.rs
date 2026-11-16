//! Exit codes — a stable contract for scripts.
//!
//! | code | meaning                                   |
//! |------|-------------------------------------------|
//! | 0    | success                                   |
//! | 1    | any other error                           |
//! | 2    | usage error (bad flags/arguments)         |
//! | 3    | not authenticated (HTTP 401)              |
//! | 4    | permission denied (HTTP 403)              |
//! | 5    | not found (HTTP 404)                      |
//! | 6    | rejected by validation (HTTP 400/422)     |
//! | 7    | API unreachable or TLS/pin failure        |
//! | 8    | fan-out: some contexts failed             |
//! | 9    | commit-confirm: change was rolled back    |

use aifw_client::ClientError;

pub const OK: i32 = 0;
pub const ERROR: i32 = 1;
pub const USAGE: i32 = 2;
pub const UNAUTHENTICATED: i32 = 3;
pub const FORBIDDEN: i32 = 4;
pub const NOT_FOUND: i32 = 5;
pub const VALIDATION: i32 = 6;
pub const UNREACHABLE: i32 = 7;
pub const PARTIAL: i32 = 8;
pub const ROLLED_BACK: i32 = 9;

/// CLI-level failures that carry their own exit code.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("{0}")]
    Usage(String),
    /// User declined a confirmation prompt (or --no-input forbade asking).
    #[error("{0}")]
    Aborted(String),
    #[error("{failed} of {total} contexts failed")]
    Partial { failed: usize, total: usize },
    #[error("the change was rolled back: {0}")]
    RolledBack(String),
    /// A check command (e.g. `cluster verify`) found problems; already reported.
    #[error("{0}")]
    CheckFailed(String),
}

/// Map an error chain to an exit code.
pub fn code_for(err: &anyhow::Error) -> i32 {
    for cause in err.chain() {
        if let Some(c) = cause.downcast_ref::<ClientError>() {
            return client_code(c);
        }
        if let Some(c) = cause.downcast_ref::<CliError>() {
            return match c {
                CliError::Usage(_) => USAGE,
                CliError::Aborted(_) | CliError::CheckFailed(_) => ERROR,
                CliError::Partial { .. } => PARTIAL,
                CliError::RolledBack(_) => ROLLED_BACK,
            };
        }
    }
    ERROR
}

pub fn client_code(e: &ClientError) -> i32 {
    match e {
        ClientError::Unauthorized(_) => UNAUTHENTICATED,
        ClientError::Forbidden(_) => FORBIDDEN,
        ClientError::NotFound(_) => NOT_FOUND,
        ClientError::Validation(_) => VALIDATION,
        ClientError::Unreachable { .. } | ClientError::Tls { .. } => UNREACHABLE,
        _ => ERROR,
    }
}

/// Short machine-readable error kind for `-o json` error output.
pub fn kind_for(code: i32) -> &'static str {
    match code {
        USAGE => "usage",
        UNAUTHENTICATED => "unauthenticated",
        FORBIDDEN => "forbidden",
        NOT_FOUND => "not_found",
        VALIDATION => "validation",
        UNREACHABLE => "unreachable",
        PARTIAL => "partial",
        ROLLED_BACK => "rolled_back",
        _ => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_client_errors_through_context() {
        let e = anyhow::Error::new(ClientError::Forbidden("x".into())).context("listing rules");
        assert_eq!(code_for(&e), FORBIDDEN);
        let cases = [
            (ClientError::Unauthorized(String::new()), UNAUTHENTICATED),
            (ClientError::NotFound(String::new()), NOT_FOUND),
            (ClientError::Validation(String::new()), VALIDATION),
            (
                ClientError::Unreachable {
                    url: String::new(),
                    reason: String::new(),
                },
                UNREACHABLE,
            ),
            (
                ClientError::Tls {
                    url: String::new(),
                    reason: String::new(),
                },
                UNREACHABLE,
            ),
            (
                ClientError::Server {
                    status: 500,
                    message: String::new(),
                },
                ERROR,
            ),
        ];
        for (err, code) in cases {
            assert_eq!(client_code(&err), code);
        }
    }

    #[test]
    fn maps_cli_errors() {
        assert_eq!(code_for(&CliError::Usage("x".into()).into()), USAGE);
        assert_eq!(
            code_for(
                &CliError::Partial {
                    failed: 1,
                    total: 2
                }
                .into()
            ),
            PARTIAL
        );
        assert_eq!(
            code_for(&CliError::RolledBack("x".into()).into()),
            ROLLED_BACK
        );
        assert_eq!(code_for(&anyhow::anyhow!("plain")), ERROR);
        assert_eq!(kind_for(VALIDATION), "validation");
    }
}
