//! Async client for the aifw-ids IPC.
//!
//! For read methods the client maintains a small TTL cache so that hot
//! API endpoints (dashboard refresh) don't hammer the socket. Write
//! methods (`SetConfig`, `Reload`, `SetRule`) invalidate cached entries.

use crate::framing::{read_frame, write_frame};
use crate::proto::{AlertSummary, IdsStats, IpcRequest, IpcResponse, RuleSummary, RulesetSummary};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::net::UnixStream;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum IdsClientError {
    #[error("ids service unavailable: {0}")]
    Unavailable(String),
    #[error("ids service timeout")]
    Timeout,
    #[error("ids server error: {0}")]
    Server(String),
    #[error("framing error: {0}")]
    Framing(#[from] crate::framing::FrameError),
    #[error("unexpected response shape")]
    UnexpectedResponse,
}

const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
struct CacheEntry<T: Clone> {
    value: T,
    expires_at: Instant,
}

#[derive(Default)]
struct Cache {
    config: Option<CacheEntry<aifw_common::ids::IdsConfig>>,
    stats: Option<CacheEntry<IdsStats>>,
    rulesets: Option<CacheEntry<Vec<RulesetSummary>>>,
    rules: std::collections::HashMap<String, CacheEntry<Option<RuleSummary>>>,
    alerts_tail: Option<CacheEntry<Vec<AlertSummary>>>,
}

pub struct IdsClient {
    socket_path: PathBuf,
    cache: Arc<Mutex<Cache>>,
}

impl IdsClient {
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            cache: Arc::new(Mutex::new(Cache::default())),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    async fn raw_call(&self, req: IpcRequest) -> Result<IpcResponse, IdsClientError> {
        let connect = UnixStream::connect(&self.socket_path);
        let mut stream = match tokio::time::timeout(REQUEST_TIMEOUT, connect).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(IdsClientError::Unavailable(e.to_string())),
            Err(_) => return Err(IdsClientError::Timeout),
        };
        let io = async {
            write_frame(&mut stream, &req).await?;
            let resp: IpcResponse = read_frame(&mut stream).await?;
            Ok::<_, IdsClientError>(resp)
        };
        match tokio::time::timeout(REQUEST_TIMEOUT, io).await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(IdsClientError::Timeout),
        }
    }

    pub async fn get_config(&self) -> Result<aifw_common::ids::IdsConfig, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.config
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::GetConfig).await?;
        match resp {
            IpcResponse::Config(c) => {
                let mut cache = self.cache.lock().await;
                cache.config = Some(CacheEntry {
                    value: c.clone(),
                    expires_at: Instant::now() + Duration::from_secs(5),
                });
                Ok(c)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn set_config(&self, config: aifw_common::ids::IdsConfig) -> Result<(), IdsClientError> {
        let resp = self.raw_call(IpcRequest::SetConfig { config }).await?;
        match resp {
            IpcResponse::Ok => {
                self.invalidate_all().await;
                Ok(())
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn reload(&self) -> Result<(), IdsClientError> {
        let resp = self.raw_call(IpcRequest::Reload).await?;
        self.invalidate_all().await;
        match resp {
            IpcResponse::Ok => Ok(()),
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn get_stats(&self) -> Result<IdsStats, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.stats
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::GetStats).await?;
        match resp {
            IpcResponse::Stats(s) => {
                let mut cache = self.cache.lock().await;
                cache.stats = Some(CacheEntry {
                    value: s.clone(),
                    expires_at: Instant::now() + Duration::from_secs(2),
                });
                Ok(s)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn list_rulesets(&self) -> Result<Vec<RulesetSummary>, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.rulesets
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::ListRulesets).await?;
        match resp {
            IpcResponse::Rulesets(rs) => {
                let mut cache = self.cache.lock().await;
                cache.rulesets = Some(CacheEntry {
                    value: rs.clone(),
                    expires_at: Instant::now() + Duration::from_secs(30),
                });
                Ok(rs)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn get_rule(&self, id: &str) -> Result<Option<RuleSummary>, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.rules.get(id)
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.value.clone());
            }
        }
        let resp = self.raw_call(IpcRequest::GetRule { id: id.to_string() }).await?;
        match resp {
            IpcResponse::Rule(r) => {
                let mut cache = self.cache.lock().await;
                cache.rules.insert(
                    id.to_string(),
                    CacheEntry {
                        value: r.clone(),
                        expires_at: Instant::now() + Duration::from_secs(60),
                    },
                );
                Ok(r)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn set_rule(&self, id: &str, enabled: bool) -> Result<(), IdsClientError> {
        let resp = self
            .raw_call(IpcRequest::SetRule {
                id: id.to_string(),
                enabled,
            })
            .await?;
        match resp {
            IpcResponse::Ok => {
                let mut cache = self.cache.lock().await;
                cache.rules.remove(id);
                cache.rulesets = None;
                Ok(())
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    pub async fn tail_alerts(&self, count: u32) -> Result<Vec<AlertSummary>, IdsClientError> {
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = &cache.alerts_tail
                && entry.expires_at > Instant::now()
                && entry.value.len() >= count as usize
            {
                return Ok(entry.value.iter().take(count as usize).cloned().collect());
            }
        }
        let resp = self.raw_call(IpcRequest::TailAlerts { count }).await?;
        match resp {
            IpcResponse::Alerts(a) => {
                let mut cache = self.cache.lock().await;
                cache.alerts_tail = Some(CacheEntry {
                    value: a.clone(),
                    expires_at: Instant::now() + Duration::from_secs(1),
                });
                Ok(a)
            }
            IpcResponse::Error(e) => Err(IdsClientError::Server(e)),
            _ => Err(IdsClientError::UnexpectedResponse),
        }
    }

    async fn invalidate_all(&self) {
        let mut cache = self.cache.lock().await;
        cache.config = None;
        cache.stats = None;
        cache.rulesets = None;
        cache.rules.clear();
        cache.alerts_tail = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::IpcResponse;
    use crate::server::{IpcHandler, serve};
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::net::UnixListener;

    struct CountingHandler {
        count: Arc<AtomicU32>,
    }

    #[async_trait]
    impl IpcHandler for CountingHandler {
        async fn handle(&self, req: IpcRequest) -> IpcResponse {
            self.count.fetch_add(1, Ordering::SeqCst);
            match req {
                IpcRequest::GetStats => IpcResponse::Stats(IdsStats {
                    mode: "alert".into(),
                    running: true,
                    rules_loaded: 1,
                    flow_count: 0,
                    flow_reassembly_bytes: 0,
                    packets_inspected: 0,
                    alerts_total: 0,
                    drops_total: 0,
                    packets_per_sec: 0.0,
                    bytes_per_sec: 0.0,
                    uptime_secs: 1,
                }),
                _ => IpcResponse::Error("unsupported".into()),
            }
        }
    }

    #[tokio::test]
    async fn cache_avoids_redundant_calls() {
        let path = std::env::temp_dir().join(format!("aifw-cli-test-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let count = Arc::new(AtomicU32::new(0));
        let handler = Arc::new(CountingHandler {
            count: count.clone(),
        });
        let server = tokio::spawn(serve(listener, handler));

        let client = IdsClient::new(&path);
        let _ = client.get_stats().await.unwrap();
        let _ = client.get_stats().await.unwrap();
        let _ = client.get_stats().await.unwrap();

        // The 2-second TTL should have absorbed the second and third call.
        assert_eq!(count.load(Ordering::SeqCst), 1);

        server.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn unavailable_when_socket_missing() {
        let path = std::env::temp_dir().join(format!("aifw-noexist-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let client = IdsClient::new(&path);
        let result = client.get_stats().await;
        assert!(matches!(result, Err(IdsClientError::Unavailable(_))));
    }
}
