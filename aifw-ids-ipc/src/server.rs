//! Server-side loop: accept connections, read one request, call handler,
//! write one response, close. No persistent connection state.

use crate::framing::{FrameError, read_frame, write_frame};
use crate::proto::{IpcRequest, IpcResponse};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::net::UnixListener;

#[async_trait]
pub trait IpcHandler: Send + Sync + 'static {
    async fn handle(&self, req: IpcRequest) -> IpcResponse;
}

/// Run the accept loop. Blocks until `listener` errors. Each accepted
/// connection is served on its own tokio task.
pub async fn serve<H: IpcHandler>(listener: UnixListener, handler: Arc<H>) {
    loop {
        let (mut stream, _addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let req: IpcRequest = match read_frame(&mut stream).await {
                Ok(r) => r,
                Err(FrameError::Io(_)) => return, // client closed
                Err(e) => {
                    let _ = write_frame(&mut stream, &IpcResponse::Error(e.to_string())).await;
                    return;
                }
            };
            let resp = handler.handle(req).await;
            let _ = write_frame(&mut stream, &resp).await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::IdsStats;
    use std::path::PathBuf;
    use tokio::net::UnixStream;

    struct StubHandler;

    #[async_trait]
    impl IpcHandler for StubHandler {
        async fn handle(&self, req: IpcRequest) -> IpcResponse {
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
    async fn serves_one_request() {
        let path = std::env::temp_dir().join(format!("aifw-ipc-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(serve(listener, Arc::new(StubHandler)));

        let mut client = UnixStream::connect(&path).await.unwrap();
        write_frame(&mut client, &IpcRequest::GetStats).await.unwrap();
        let resp: IpcResponse = read_frame(&mut client).await.unwrap();
        assert!(matches!(resp, IpcResponse::Stats(_)));

        server.abort();
        let _ = std::fs::remove_file(PathBuf::from(&path));
    }
}
