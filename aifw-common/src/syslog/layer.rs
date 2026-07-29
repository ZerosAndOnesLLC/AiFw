//! `tracing` layer that forwards application log events to remote syslog.

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use super::client::SyslogHandle;
use super::config::Category;

/// Forwards `tracing` events to remote syslog as the App category.
///
/// Attach to a `tracing_subscriber::registry()` alongside the normal fmt
/// layer. Filtering is self-contained: the layer checks the App category
/// toggle and `app_min_level` per event, so console filtering (EnvFilter on
/// the fmt layer) never starves the forwarder.
pub struct SyslogLayer {
    handle: SyslogHandle,
    app_name: &'static str,
}

impl SyslogLayer {
    /// `app_name` becomes the syslog APP-NAME/TAG (e.g. `aifw-api`).
    pub fn new(handle: SyslogHandle, app_name: &'static str) -> Self {
        Self { handle, app_name }
    }
}

fn level_to_severity(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 3,
        Level::WARN => 4,
        Level::INFO => 6,
        // TRACE has no syslog equivalent below debug
        Level::DEBUG | Level::TRACE => 7,
    }
}

impl<S: Subscriber> Layer<S> for SyslogLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        // Recursion guard: the syslog client's own diagnostics (delivery
        // failures etc.) must never be forwarded through itself.
        if meta.target().starts_with("aifw_common::syslog") {
            return;
        }
        if !self.handle.enabled_for(Category::App) {
            return;
        }
        let severity = level_to_severity(meta.level());
        if severity > self.handle.config().app_min_severity() {
            return;
        }
        let mut visitor = MsgVisitor::default();
        event.record(&mut visitor);
        let mut body = visitor.message;
        if !visitor.fields.is_empty() {
            if !body.is_empty() {
                body.push(' ');
            }
            body.push_str(&visitor.fields);
        }
        let msg = format!("[{}] {}", meta.target(), body);
        self.handle
            .enqueue(Category::App, severity, self.app_name, msg);
    }
}

/// Per-event filter for the stdout `fmt` layer implementing the
/// "stop storing logs locally" toggle for app logs.
///
/// The appliance's `/var/log/aifw/*.log` files are `daemon(8)` stdout
/// redirects, so silencing stdout stops file growth with no rc.d changes or
/// service restarts. The gate closes only for events the forwarder will
/// actually accept: remote forwarding on, `disable_local` set, app-log
/// forwarding enabled, AND the event at or above `app_min_level` — so at
/// the configuration level an event is never dropped from both
/// destinations at once. (Delivery failures while the gate is closed are
/// still possible — that is the disk-vs-remote trade the toggle opts into —
/// and are visible in the dropped/error counters.)
pub struct LocalStorageGate {
    handle: SyslogHandle,
}

impl LocalStorageGate {
    /// Wrap a handle from the process's `SyslogManager`.
    pub fn new(handle: SyslogHandle) -> Self {
        Self { handle }
    }
}

impl<S: Subscriber> tracing_subscriber::layer::Filter<S> for LocalStorageGate {
    fn enabled(&self, meta: &tracing::Metadata<'_>, _cx: &Context<'_, S>) -> bool {
        let cfg = self.handle.config();
        if !(cfg.enabled && cfg.disable_local && cfg.app_enabled) {
            return true;
        }
        // Below-min-level events are NOT forwarded (SyslogLayer filters
        // them), so they must keep going to stdout — silencing them here
        // would drop them from both destinations.
        level_to_severity(meta.level()) > cfg.app_min_severity()
    }
}

/// Collects the `message` field and renders the rest as `key=value` pairs.
#[derive(Default)]
struct MsgVisitor {
    message: String,
    fields: String,
}

impl MsgVisitor {
    fn push_field(&mut self, name: &str, value: impl std::fmt::Display) {
        if !self.fields.is_empty() {
            self.fields.push(' ');
        }
        // Infallible: fmt::Write on String never errors.
        use std::fmt::Write;
        let _ = write!(self.fields, "{name}={value}");
    }
}

impl Visit for MsgVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            use std::fmt::Write;
            let _ = write!(self.message, "{value:?}");
        } else {
            self.push_field(field.name(), format_args!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            self.push_field(field.name(), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::client::SyslogManager;
    use super::super::config::{SyslogConfig, Transport};
    use super::*;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::timeout;
    use tracing_subscriber::layer::SubscriberExt;

    // Note: the SyslogManager is dropped inside setup(); only the handle
    // embedded in the layer keeps the pipeline alive. This doubles as a
    // regression test for the writer task surviving a manager drop with
    // queued messages still to deliver.
    async fn setup(min_level: &str) -> (UdpSocket, tracing::Dispatch) {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let mgr = SyslogManager::start();
        mgr.apply(SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port,
            transport: Transport::Udp,
            app_enabled: true,
            app_min_level: min_level.into(),
            ..Default::default()
        });
        let subscriber =
            tracing_subscriber::registry().with(SyslogLayer::new(mgr.handle(), "aifw-test"));
        (server, tracing::Dispatch::new(subscriber))
    }

    async fn recv_with_timeout(server: &UdpSocket, ms: u64) -> Option<String> {
        let mut buf = [0u8; 4096];
        match timeout(Duration::from_millis(ms), server.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn local_storage_gate_silences_layer_only_when_forwarding() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tracing_subscriber::Layer as _;

        struct CountLayer(Arc<AtomicUsize>);
        impl<S: Subscriber> tracing_subscriber::layer::Layer<S> for CountLayer {
            fn on_event(&self, _e: &Event<'_>, _c: Context<'_, S>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let mgr = SyslogManager::start();
        let count = Arc::new(AtomicUsize::new(0));
        let subscriber = tracing_subscriber::registry()
            .with(CountLayer(count.clone()).with_filter(LocalStorageGate::new(mgr.handle())));
        let dispatch = tracing::Dispatch::new(subscriber);

        // Gate closed: forwarding on + disable_local + app category on.
        mgr.apply(SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            disable_local: true,
            app_enabled: true,
            ..Default::default()
        });
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "test_app", "must be silenced");
        });
        assert_eq!(count.load(Ordering::Relaxed), 0, "gate should silence");

        // disable_local off → gate open again.
        mgr.apply(SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            app_enabled: true,
            ..Default::default()
        });
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "test_app", "must pass");
        });
        assert_eq!(count.load(Ordering::Relaxed), 1, "gate should open");

        // app forwarding off → never silence (logs must go somewhere).
        mgr.apply(SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            disable_local: true,
            app_enabled: false,
            ..Default::default()
        });
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "test_app", "must also pass");
        });
        assert_eq!(count.load(Ordering::Relaxed), 2, "no forwarding, no gate");

        // Gate closed but min level warn: info is NOT forwarded, so it must
        // keep reaching stdout; warn IS forwarded, so it is silenced.
        mgr.apply(SyslogConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            disable_local: true,
            app_enabled: true,
            app_min_level: "warn".into(),
            ..Default::default()
        });
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "test_app", "below min level, must pass");
            tracing::warn!(target: "test_app", "forwarded, must be silenced");
        });
        assert_eq!(
            count.load(Ordering::Relaxed),
            3,
            "info passes (not forwarded), warn silenced (forwarded)"
        );
    }

    #[tokio::test]
    async fn forwards_events_with_fields() {
        let (server, dispatch) = setup("info").await;
        // Explicit target: the test module's own path starts with
        // aifw_common::syslog, which the recursion guard (correctly) drops.
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "test_app", user = "admin", attempts = 3, "login succeeded");
        });
        let got = recv_with_timeout(&server, 5000)
            .await
            .expect("event should be forwarded");
        assert!(got.contains("aifw-test"), "got: {got}");
        assert!(got.contains("login succeeded"), "got: {got}");
        assert!(got.contains("user=admin"), "got: {got}");
        assert!(got.contains("attempts=3"), "got: {got}");
        assert!(got.starts_with("<134>"), "local0.info PRI, got: {got}");
    }

    #[tokio::test]
    async fn respects_min_level() {
        let (server, dispatch) = setup("warn").await;
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::info!(target: "test_app", "too quiet to forward");
            tracing::warn!(target: "test_app", "loud enough");
        });
        let got = recv_with_timeout(&server, 5000)
            .await
            .expect("warn event should be forwarded");
        assert!(got.contains("loud enough"), "got: {got}");
        // The info event was filtered — nothing else arrives.
        assert!(recv_with_timeout(&server, 200).await.is_none());
    }

    #[tokio::test]
    async fn recursion_guard_drops_own_events() {
        let (server, dispatch) = setup("debug").await;
        tracing::dispatcher::with_default(&dispatch, || {
            tracing::warn!(
                target: "aifw_common::syslog::client",
                "delivery failing"
            );
        });
        assert!(
            recv_with_timeout(&server, 300).await.is_none(),
            "syslog-internal event must not be forwarded"
        );
    }
}
