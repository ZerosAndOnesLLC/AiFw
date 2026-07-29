//! Typed errors for the syslog client (repo error-handling policy #188).

/// Delivery/connection errors from the syslog client.
#[derive(Debug, thiserror::Error)]
pub enum SyslogError {
    /// No server host configured for a send/test.
    #[error("host is required")]
    HostRequired,
    /// DNS resolution exceeded the I/O timeout.
    #[error("DNS lookup for {target} timed out")]
    ResolveTimeout {
        /// `host:port` being resolved
        target: String,
    },
    /// DNS resolution failed.
    #[error("cannot resolve {target}: {source}")]
    Resolve {
        /// `host:port` being resolved
        target: String,
        /// Underlying resolver error
        source: std::io::Error,
    },
    /// Resolution succeeded but returned no addresses.
    #[error("no addresses for {target}")]
    NoAddresses {
        /// `host:port` being resolved
        target: String,
    },
    /// Local UDP socket could not be bound.
    #[error("cannot bind UDP socket: {0}")]
    Bind(#[source] std::io::Error),
    /// TCP connect exceeded the I/O timeout (all addresses tried).
    #[error("connect to {target} timed out")]
    ConnectTimeout {
        /// `host:port` being connected to
        target: String,
    },
    /// TCP connect failed (all addresses tried; last error kept).
    #[error("cannot connect to {target}: {source}")]
    Connect {
        /// `host:port` being connected to
        target: String,
        /// Underlying connect error
        source: std::io::Error,
    },
    /// Send exceeded the I/O timeout.
    #[error("{transport} send timed out")]
    SendTimeout {
        /// `"UDP"` or `"TCP"`
        transport: &'static str,
    },
    /// Send failed at the socket layer.
    #[error("{transport} send failed: {source}")]
    Send {
        /// `"UDP"` or `"TCP"`
        transport: &'static str,
        /// Underlying socket error
        source: std::io::Error,
    },
}
