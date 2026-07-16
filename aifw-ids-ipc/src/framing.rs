//! Length-prefixed JSON framing over an async stream.
//!
//! Format: 4-byte big-endian u32 length, then exactly that many UTF-8
//! bytes of JSON. The 4 GiB max body is enforced; we additionally cap to
//! 16 MiB to defend against accidental huge requests.

use serde::{Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Upfront allocation cap for a frame body. Typical IPC frames are well
/// under this; larger bodies grow the buffer as bytes actually arrive
/// instead of trusting the length prefix (PERF-H13 #357).
const INITIAL_BODY_CAPACITY: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {0} bytes (max {max})", max = MAX_FRAME_BYTES)]
    TooLarge(u32),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub async fn read_frame<T, R>(reader: &mut R) -> Result<T, FrameError>
where
    T: DeserializeOwned,
    R: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if (len as usize) > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    // PERF-H13 (#357): `vec![0u8; len]` zero-filled up to 16 MiB that
    // read_exact immediately overwrote, and committed the full claimed
    // length before a single body byte arrived. `take(len).read_to_end`
    // appends into uninitialized spare capacity (no memset) and grows
    // with the bytes actually received, so a client claiming a huge
    // frame but sending nothing can't pin 16 MiB per connection.
    let mut buf = Vec::with_capacity((len as usize).min(INITIAL_BODY_CAPACITY));
    let read = (&mut *reader)
        .take(len as u64)
        .read_to_end(&mut buf)
        .await?;
    if read < len as usize {
        return Err(FrameError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "frame body truncated",
        )));
    }
    let msg = serde_json::from_slice(&buf)?;
    Ok(msg)
}

pub async fn write_frame<T, W>(writer: &mut W, msg: &T) -> Result<(), FrameError>
where
    T: Serialize,
    W: AsyncWriteExt + Unpin,
{
    let body = serde_json::to_vec(msg)?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(body.len() as u32));
    }
    let len = (body.len() as u32).to_be_bytes();
    writer.write_all(&len).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::IpcRequest;
    use tokio::io::duplex;

    #[tokio::test]
    async fn round_trip_request() {
        let (mut a, mut b) = duplex(64 * 1024);
        let sent = IpcRequest::GetStats;
        write_frame(&mut a, &sent).await.unwrap();
        let received: IpcRequest = read_frame(&mut b).await.unwrap();
        assert!(matches!(received, IpcRequest::GetStats));
    }

    #[tokio::test]
    async fn truncated_body_errors() {
        let (mut a, mut b) = duplex(64 * 1024);
        // Claim 100 bytes, deliver 5, then EOF.
        a.write_all(&100u32.to_be_bytes()).await.unwrap();
        a.write_all(b"short").await.unwrap();
        drop(a);
        let result: Result<IpcRequest, _> = read_frame(&mut b).await;
        assert!(matches!(result, Err(FrameError::Io(_))));
    }

    #[tokio::test]
    async fn round_trips_body_larger_than_initial_capacity() {
        let (mut a, mut b) = duplex(1024 * 1024);
        // A body that exceeds INITIAL_BODY_CAPACITY must still arrive intact.
        let sent = IpcRequest::GetRule {
            id: "x".repeat(super::INITIAL_BODY_CAPACITY * 2),
        };
        let write = async {
            write_frame(&mut a, &sent).await.unwrap();
        };
        let read = async { read_frame::<IpcRequest, _>(&mut b).await.unwrap() };
        let (_, received) = tokio::join!(write, read);
        match received {
            IpcRequest::GetRule { id } => {
                assert_eq!(id.len(), super::INITIAL_BODY_CAPACITY * 2)
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_oversized() {
        let (mut a, mut b) = duplex(64 * 1024);
        // Hand-craft a 4-byte length prefix that claims 100 MiB.
        let len: u32 = 100 * 1024 * 1024;
        a.write_all(&len.to_be_bytes()).await.unwrap();
        let result: Result<IpcRequest, _> = read_frame(&mut b).await;
        assert!(matches!(result, Err(FrameError::TooLarge(_))));
    }
}
