//! Flags accepted by every command.

use clap::Args;

use super::output::Format;

#[derive(Debug, Clone, Default, Args)]
pub struct GlobalArgs {
    /// Saved context to talk to (see `aifw context`); comma-separate names
    /// to fan a read-only command out across several appliances
    #[arg(long, global = true, env = "AIFW_CONTEXT", value_name = "NAME")]
    pub context: Option<String>,

    /// Run a read-only command against every saved context
    #[arg(long, global = true, conflicts_with = "context")]
    pub all_contexts: bool,

    /// How many contexts a fan-out talks to at once
    #[arg(long, global = true, default_value_t = 8, value_name = "N")]
    pub parallel: usize,

    /// API base URL, overriding the context (e.g. https://10.0.0.1:8080)
    #[arg(long, global = true, env = "AIFW_API_URL", value_name = "URL")]
    pub url: Option<String>,

    /// API key or bearer token, overriding stored credentials
    #[arg(
        long,
        global = true,
        env = "AIFW_TOKEN",
        hide_env_values = true,
        value_name = "KEY"
    )]
    pub api_key: Option<String>,

    /// Pin the API's TLS certificate (SHA-256, hex; colons allowed)
    #[arg(long, global = true, value_name = "SHA256")]
    pub pin: Option<String>,

    /// Output format
    #[arg(
        short = 'o',
        long = "output",
        global = true,
        value_enum,
        value_name = "FORMAT"
    )]
    pub output: Option<Format>,

    /// Never prompt; fail instead when input would be needed
    #[arg(long, global = true)]
    pub no_input: bool,

    /// Request timeout in seconds (slow operations use their own longer default)
    #[arg(long = "request-timeout", global = true, value_name = "SECS")]
    pub request_timeout: Option<u64>,
}

impl GlobalArgs {
    /// Context names requested with `--context a,b` (empty when unset).
    pub fn context_names(&self) -> Vec<String> {
        self.context
            .as_deref()
            .map(|s| {
                s.split(',')
                    .map(str::trim)
                    .filter(|n| !n.is_empty())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    }
}
