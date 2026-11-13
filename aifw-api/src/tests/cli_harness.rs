//! Harness for CLI integration tests: the real router served over TCP on
//! 127.0.0.1, plus `aifw` commands run in-process (`aifw_cli::run`) with
//! a scratch config directory and captured stdio.

use super::*;
use std::path::PathBuf;

pub(super) struct Cli {
    pub base: String,
    pub dir: PathBuf,
    pub pool: sqlx::SqlitePool,
}

/// Result of one `aifw` invocation.
pub(super) struct Run {
    pub code: i32,
    pub out: String,
    pub err: String,
}

impl Run {
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.out).unwrap_or_else(|e| {
            panic!(
                "stdout is not JSON ({e}):\n{}\nstderr:\n{}",
                self.out, self.err
            )
        })
    }

    #[track_caller]
    pub fn ok(&self) -> &Self {
        assert_eq!(
            self.code, 0,
            "expected success\nstdout:\n{}\nstderr:\n{}",
            self.out, self.err
        );
        self
    }

    #[track_caller]
    pub fn code(&self, code: i32) -> &Self {
        assert_eq!(
            self.code, code,
            "unexpected exit code\nstdout:\n{}\nstderr:\n{}",
            self.out, self.err
        );
        self
    }
}

pub(super) const ADMIN_USER: &str = "admin";
pub(super) const ADMIN_PASS: &str = "TestPass123";

impl Cli {
    /// Fresh in-memory API on a random port; the first admin is registered.
    pub async fn start() -> Self {
        let state = crate::create_app_state_in_memory(plain_auth_settings())
            .await
            .unwrap();
        let pool = state.pool.clone();
        let app = crate::build_router(state, None, "*", false);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let dir = std::env::temp_dir().join(format!(
            "aifw-cli-it-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cli = Self {
            base: format!("http://{addr}"),
            dir,
            pool,
        };
        cli.http()
            .post(cli.url("/auth/register"))
            .json(&json!({ "username": ADMIN_USER, "password": ADMIN_PASS }))
            .send()
            .await
            .unwrap();
        cli
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}/api/v1{path}", self.base)
    }

    pub fn http(&self) -> reqwest::Client {
        reqwest::Client::new()
    }

    pub fn config_dir(&self) -> PathBuf {
        self.dir.join("cfg")
    }

    /// On-box paths that don't exist, so tests never touch /usr/local or
    /// mint a root key.
    pub fn env(&self) -> aifw_cli::Env {
        aifw_cli::Env {
            config_dir: self.config_dir(),
            onbox: aifw_cli::cli::onbox::OnBox {
                cert: self.dir.join("onbox/cert.pem"),
                cli_key: self.dir.join("onbox/cli.key"),
                daemon_key: self.dir.join("onbox/daemon.key"),
                db: self.dir.join("onbox/aifw.db"),
            },
        }
    }

    /// Run `aifw <args>` with `stdin`.
    pub async fn run_stdin(&self, args: &[&str], stdin: &str) -> Run {
        let io = aifw_cli::Io::buffered(stdin);
        let (out, err) = io.captures().unwrap();
        let mut argv = vec!["aifw"];
        argv.extend_from_slice(args);
        let code = aifw_cli::run(argv, io, self.env()).await;
        Run {
            code,
            out: out.contents(),
            err: err.contents(),
        }
    }

    pub async fn run(&self, args: &[&str]) -> Run {
        self.run_stdin(args, "").await
    }

    /// Log the CLI in as the admin, saving context `t`.
    pub async fn login_admin(&self) {
        self.run_stdin(
            &[
                "login",
                &self.base,
                "--context",
                "t",
                "-u",
                ADMIN_USER,
                "--password-stdin",
            ],
            &format!("{ADMIN_PASS}\n"),
        )
        .await
        .ok();
    }

    /// Admin bearer token, for setting up state directly through the API.
    pub async fn admin_token(&self) -> String {
        let v: Value = self
            .http()
            .post(self.url("/auth/login"))
            .json(&json!({ "username": ADMIN_USER, "password": ADMIN_PASS }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["tokens"]["access_token"].as_str().unwrap().to_string()
    }

    /// Mint an API key through the API as the admin.
    pub async fn mint_key(&self, body: Value) -> String {
        let token = self.admin_token().await;
        let v: Value = self
            .http()
            .post(self.url("/auth/api-keys"))
            .bearer_auth(token)
            .json(&body)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        v["key"].as_str().unwrap().to_string()
    }

    pub fn credentials(&self) -> toml::Table {
        let text =
            std::fs::read_to_string(self.config_dir().join("credentials.toml")).unwrap_or_default();
        text.parse().unwrap()
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
