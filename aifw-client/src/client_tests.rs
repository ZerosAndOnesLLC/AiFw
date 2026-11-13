//! Client behaviour against a tiny in-process mock of the API: URL
//! building, credential headers, error mapping, session refresh rotation,
//! login outcomes and uploads.

use super::*;
use axum::{
    Json, Router,
    extract::{Multipart, State},
    http::{HeaderMap, StatusCode as AxStatus},
    routing::{get, post},
};
use std::sync::Mutex as StdMutex;

#[derive(Default)]
struct Mock {
    /// Access token currently accepted by `/api/v1/me`.
    valid_access: StdMutex<String>,
    /// Refresh token currently accepted.
    valid_refresh: StdMutex<String>,
    refreshes: StdMutex<u32>,
    last_auth: StdMutex<Option<String>>,
}

type S = Arc<Mock>;

async fn me(State(m): State<S>, h: HeaderMap) -> std::result::Result<Json<Value>, AxStatus> {
    let auth = h
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    *m.last_auth.lock().unwrap() = auth.clone();
    let ok = match auth.as_deref() {
        Some(a) if a.starts_with("ApiKey ") => a == "ApiKey aifw_good",
        Some(a) => a == format!("Bearer {}", m.valid_access.lock().unwrap()),
        None => false,
    };
    if ok {
        Ok(Json(serde_json::json!({ "username": "admin" })))
    } else {
        Err(AxStatus::UNAUTHORIZED)
    }
}

async fn refresh(
    State(m): State<S>,
    Json(b): Json<Value>,
) -> std::result::Result<Json<Value>, AxStatus> {
    let presented = b["refresh_token"].as_str().unwrap_or_default().to_string();
    if presented != *m.valid_refresh.lock().unwrap() {
        return Err(AxStatus::UNAUTHORIZED);
    }
    let mut n = m.refreshes.lock().unwrap();
    *n += 1;
    let access = format!("access-{n}");
    let refresh = format!("refresh-{n}");
    *m.valid_access.lock().unwrap() = access.clone();
    *m.valid_refresh.lock().unwrap() = refresh.clone();
    Ok(Json(serde_json::json!({
        "access_token": access,
        "refresh_token": refresh,
        "access_expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        "refresh_expires_at": null,
        "token_type": "Bearer",
    })))
}

async fn login(Json(b): Json<Value>) -> std::result::Result<Json<Value>, AxStatus> {
    match (b["username"].as_str(), b["password"].as_str()) {
        (Some("admin"), Some("pw")) => Ok(Json(serde_json::json!({
            "tokens": { "access_token": "a0", "refresh_token": "r0" },
            "totp_required": false
        }))),
        (Some("mfa"), Some("pw")) => Ok(Json(
            serde_json::json!({ "tokens": null, "totp_required": true }),
        )),
        _ => Err(AxStatus::UNAUTHORIZED),
    }
}

async fn totp(Json(b): Json<Value>) -> std::result::Result<Json<Value>, AxStatus> {
    if b["totp_code"] == "123456" {
        Ok(Json(
            serde_json::json!({ "access_token": "a1", "refresh_token": "r1" }),
        ))
    } else {
        Err(AxStatus::UNAUTHORIZED)
    }
}

async fn upload(mut mp: Multipart) -> Json<Value> {
    let mut out = serde_json::Map::new();
    while let Some(f) = mp.next_field().await.unwrap() {
        let name = f.name().unwrap_or_default().to_string();
        let file = f.file_name().map(str::to_string);
        let data = f.bytes().await.unwrap();
        out.insert(
            name,
            serde_json::json!({ "file": file, "len": data.len(), "text": String::from_utf8_lossy(&data) }),
        );
    }
    Json(Value::Object(out))
}

async fn start() -> (String, S) {
    let m: S = Arc::new(Mock::default());
    *m.valid_refresh.lock().unwrap() = "refresh-0".into();
    let app = Router::new()
        .route("/api/v1/me", get(me))
        .route("/api/v1/auth/refresh", post(refresh))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/totp/login", post(totp))
        .route("/api/v1/upload", post(upload))
        .route("/api/v1/empty", post(|| async { AxStatus::NO_CONTENT }))
        .route(
            "/api/v1/bad",
            get(|| async {
                (
                    AxStatus::BAD_REQUEST,
                    Json(serde_json::json!({ "error": "bad cidr" })),
                )
            }),
        )
        .route("/api/v1/missing", get(|| async { AxStatus::NOT_FOUND }))
        .route("/api/v1/forbidden", get(|| async { AxStatus::FORBIDDEN }))
        .route(
            "/api/v1/boom",
            get(|| async { AxStatus::INTERNAL_SERVER_ERROR }),
        )
        .with_state(m.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), m)
}

#[derive(Default)]
struct MemStore(StdMutex<Vec<TokenPair>>);
impl SessionStore for MemStore {
    fn save(&self, t: &TokenPair) -> std::result::Result<(), String> {
        self.0.lock().unwrap().push(t.clone());
        Ok(())
    }
}

#[test]
fn url_building() {
    let c = Client::builder("https://fw.example:8080/").build().unwrap();
    assert_eq!(c.url("/rules"), "https://fw.example:8080/api/v1/rules");
    assert_eq!(c.url("rules/1"), "https://fw.example:8080/api/v1/rules/1");
    assert_eq!(c.url("/api/v1/ws"), "https://fw.example:8080/api/v1/ws");
}

#[test]
fn rejects_bad_urls() {
    assert!(matches!(
        Client::builder("ftp://x").build(),
        Err(ClientError::Local(_))
    ));
    assert!(matches!(
        Client::builder("not a url").build(),
        Err(ClientError::Local(_))
    ));
}

#[tokio::test]
async fn api_key_header_is_sent() {
    let (base, m) = start().await;
    let c = Client::builder(&base)
        .auth(crate::credential_from_token("aifw_good"))
        .build()
        .unwrap();
    assert_eq!(c.get("/me").await.unwrap()["username"], "admin");
    assert_eq!(
        m.last_auth.lock().unwrap().as_deref(),
        Some("ApiKey aifw_good")
    );

    let bad = Client::builder(&base)
        .auth(crate::credential_from_token("aifw_bad"))
        .build()
        .unwrap();
    assert!(matches!(
        bad.get("/me").await,
        Err(ClientError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn error_mapping_and_empty_bodies() {
    let (base, _) = start().await;
    let c = Client::builder(&base).build().unwrap();
    match c.get("/bad").await {
        Err(ClientError::Validation(m)) => assert_eq!(m, "bad cidr"),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        c.get("/missing").await,
        Err(ClientError::NotFound(_))
    ));
    assert!(matches!(
        c.get("/forbidden").await,
        Err(ClientError::Forbidden(_))
    ));
    assert!(matches!(
        c.get("/boom").await,
        Err(ClientError::Server { status: 500, .. })
    ));
    assert_eq!(c.post_empty("/empty").await.unwrap(), Value::Null);
}

#[tokio::test]
async fn unreachable_is_classified() {
    // Bind then drop to get a port nothing listens on.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let c = Client::builder(format!("http://127.0.0.1:{port}"))
        .build()
        .unwrap();
    assert!(matches!(
        c.get("/me").await,
        Err(ClientError::Unreachable { .. })
    ));
}

#[tokio::test]
async fn session_refreshes_on_401_and_persists_rotation() {
    let (base, m) = start().await;
    let store = Arc::new(MemStore::default());
    // Access token the server no longer accepts; refresh token still valid.
    let session = Session {
        access_token: "stale".into(),
        refresh_token: "refresh-0".into(),
        access_expires_at: None,
    };
    let c = Client::builder(&base)
        .auth(Auth::Session(session))
        .session_store(store.clone())
        .build()
        .unwrap();
    assert_eq!(c.get("/me").await.unwrap()["username"], "admin");
    assert_eq!(*m.refreshes.lock().unwrap(), 1);
    let saved = store.0.lock().unwrap().clone();
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0].refresh_token, "refresh-1");

    // Subsequent calls use the rotated token without refreshing again.
    c.get("/me").await.unwrap();
    assert_eq!(*m.refreshes.lock().unwrap(), 1);
}

#[tokio::test]
async fn session_refreshes_before_expiry() {
    let (base, m) = start().await;
    *m.valid_access.lock().unwrap() = "current".into();
    let session = Session {
        access_token: "current".into(),
        refresh_token: "refresh-0".into(),
        access_expires_at: Some(chrono::Utc::now() + chrono::Duration::seconds(5)),
    };
    let c = Client::builder(&base)
        .auth(Auth::Session(session))
        .build()
        .unwrap();
    c.get("/me").await.unwrap();
    assert_eq!(*m.refreshes.lock().unwrap(), 1, "refreshed pre-emptively");
}

#[tokio::test]
async fn revoked_refresh_token_is_unauthorized() {
    let (base, _) = start().await;
    let session = Session {
        access_token: "stale".into(),
        refresh_token: "revoked".into(),
        access_expires_at: None,
    };
    let c = Client::builder(&base)
        .auth(Auth::Session(session))
        .build()
        .unwrap();
    assert!(matches!(
        c.get("/me").await,
        Err(ClientError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn bearer_401_is_not_retried() {
    let (base, m) = start().await;
    let c = Client::builder(&base)
        .auth(Auth::Bearer("nope".into()))
        .build()
        .unwrap();
    assert!(matches!(
        c.get("/me").await,
        Err(ClientError::Unauthorized(_))
    ));
    assert_eq!(*m.refreshes.lock().unwrap(), 0);
}

#[tokio::test]
async fn login_outcomes() {
    let (base, _) = start().await;
    let c = Client::builder(&base).build().unwrap();
    match c.login("admin", "pw").await.unwrap() {
        LoginOutcome::Tokens(t) => assert_eq!(t.access_token, "a0"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        c.login("mfa", "pw").await.unwrap(),
        LoginOutcome::TotpRequired
    );
    assert!(matches!(
        c.login("admin", "x").await,
        Err(ClientError::Unauthorized(_))
    ));
    assert_eq!(
        c.totp_login("mfa", "pw", "123456")
            .await
            .unwrap()
            .access_token,
        "a1"
    );
    assert!(c.totp_login("mfa", "pw", "000000").await.is_err());
}

#[tokio::test]
async fn multipart_upload() {
    let (base, _) = start().await;
    let c = Client::builder(&base).build().unwrap();
    let v = c
        .upload(
            "/upload",
            Upload {
                files: vec![
                    UploadFile {
                        field: "file".into(),
                        file_name: "db.zip".into(),
                        bytes: b"hello".to_vec(),
                    },
                    UploadFile {
                        field: "second".into(),
                        file_name: "b.csv".into(),
                        bytes: b"x".to_vec(),
                    },
                ],
                fields: vec![("kind".into(), "geoip".into())],
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(v["file"]["file"], "db.zip");
    assert_eq!(v["file"]["len"], 5);
    assert_eq!(v["kind"]["text"], "geoip");
    assert_eq!(v["second"]["file"], "b.csv");
}

#[tokio::test]
async fn pinned_https_rejects_wrong_certificate() {
    // TLS server with a fresh self-signed cert.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let fp = tls::fingerprint_der(cert.der());
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
        rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut s) = acceptor.accept(sock).await else {
                    return;
                };
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                    .await;
                let _ = s.shutdown().await;
            });
        }
    });
    let base = format!("https://127.0.0.1:{port}");

    // First-contact probe sees the fingerprint.
    let probe = Client::builder(&base).accept_any_cert().build().unwrap();
    assert_eq!(
        probe.probe_fingerprint().await.unwrap().as_deref(),
        Some(fp.as_str())
    );

    // Correct pin (colon form accepted) works.
    let colon: String = fp
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap().to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    let ok = Client::builder(&base).pin(colon).build().unwrap();
    assert!(ok.get("/x").await.is_ok());

    // Wrong pin fails as a TLS error.
    let bad = Client::builder(&base).pin("00".repeat(32)).build().unwrap();
    assert!(matches!(bad.get("/x").await, Err(ClientError::Tls { .. })));
}
