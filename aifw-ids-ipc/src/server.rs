//! Server-side loop: accept connections, read one request, call handler,
//! write one response, close. No persistent connection state.
//!
//! Hardening:
//! - Per-connection timeout (`READ_TIMEOUT`) covers read+handle+write so a
//!   stalled client cannot pin a worker forever (slowloris-style DoS where
//!   the client sends a 16 MiB length prefix and then drips bytes).
//! - Concurrent connection cap (`MAX_INFLIGHT`) bounds in-flight requests
//!   via a semaphore — beyond the cap, new accepts wait for a permit
//!   instead of unboundedly spawning tasks.
//! - Peer-UID check: we only accept connections from processes running as
//!   the same UID as the server itself. The IPC socket lives at 0660
//!   root:aifw on disk, so any aifw-uid process (rdns, trafficcop, rdhcpd,
//!   rtime) could otherwise call privileged IDS ops like `SetConfig`.

use crate::framing::{FrameError, read_frame, write_frame};
use crate::proto::{IpcRequest, IpcResponse};
use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

/// Max time a single connection may spend in read+handle+write before we
/// drop it. Must accommodate the slowest legitimate IPC call (config
/// roundtrips against an idle DB) but small enough to bound DoS impact.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Max concurrent in-flight IPC requests. Beyond this, the accept loop
/// awaits a permit before spawning the next task. 64 is well above any
/// observed legitimate fan-out (aifw-api fires ~1 request/sec).
const MAX_INFLIGHT: usize = 64;

#[async_trait]
pub trait IpcHandler: Send + Sync + 'static {
    async fn handle(&self, req: IpcRequest) -> IpcResponse;
}

/// Get the peer UID of a connected Unix socket.
///
/// Linux: `getsockopt(SO_PEERCRED)` via nix.
/// FreeBSD/macOS: `getpeereid(2)` via libc.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    use std::os::fd::{AsFd, AsRawFd};
    // nix 0.31 wants a BorrowedFd-like target; AsFd gives us that without
    // taking ownership of the underlying tokio stream.
    let _ = stream.as_raw_fd();
    getsockopt(&stream.as_fd(), PeerCredentials)
        .ok()
        .map(|c| c.uid())
}

#[cfg(any(target_os = "freebsd", target_os = "macos"))]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut uid: nix::libc::uid_t = 0;
    let mut gid: nix::libc::gid_t = 0;
    // SAFETY: stream's fd is valid for the duration of this call; the
    // out-params are stack-allocated u32s. getpeereid only reads the fd
    // and writes uid/gid.
    let r = unsafe { nix::libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if r == 0 { Some(uid) } else { None }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn peer_uid(_stream: &UnixStream) -> Option<u32> {
    // Other Unixes: skip the check (best-effort). Production targets are
    // FreeBSD; Linux is dev/CI only.
    None
}

/// Run the accept loop. Blocks until `listener` errors. Each accepted
/// connection is served on its own tokio task, bounded by a semaphore.
pub async fn serve<H: IpcHandler>(listener: UnixListener, handler: Arc<H>) {
    let sem = Arc::new(Semaphore::new(MAX_INFLIGHT));
    // SAFETY: geteuid is async-signal-safe and never fails per POSIX.
    let server_uid: u32 = unsafe { nix::libc::geteuid() } as u32;

    loop {
        // Block accepts when at capacity. acquire_owned never errors here
        // because we never close the semaphore.
        let permit = match sem.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };

        let (stream, _addr) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                drop(permit);
                continue;
            }
        };

        // Peer-UID auth — reject any caller whose euid differs from ours.
        // Closes the lateral-movement path: a compromised aifw-uid sibling
        // (trafficcop etc.) could otherwise call SetConfig and disable IDS.
        match peer_uid(&stream) {
            Some(uid) if uid == server_uid => {}
            Some(uid) => {
                tracing::warn!(peer_uid = uid, "rejecting unauthorized peer");
                let mut s = stream;
                let _ = tokio::time::timeout(
                    READ_TIMEOUT,
                    write_frame(&mut s, &IpcResponse::Error("unauthorized peer".into())),
                )
                .await;
                drop(permit);
                continue;
            }
            None => {
                // Couldn't read peer creds — treat as failure-closed.
                tracing::warn!("could not determine peer uid; rejecting");
                drop(permit);
                continue;
            }
        }

        let handler = handler.clone();
        tokio::spawn(async move {
            // The whole read+handle+write cycle has to complete inside
            // READ_TIMEOUT; otherwise we close the connection silently.
            let _ = tokio::time::timeout(READ_TIMEOUT, handle_one(stream, handler)).await;
            drop(permit);
        });
    }
}

async fn handle_one<H: IpcHandler>(mut stream: UnixStream, handler: Arc<H>) {
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
