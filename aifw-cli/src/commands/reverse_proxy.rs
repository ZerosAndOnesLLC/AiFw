//! `aifw reverse-proxy …` — TrafficCop reverse proxy via the API: service
//! control plus CRUD over every routing collection.

use clap::Subcommand;

use crate::cli::output::Col;
use crate::cli::{Ctx, Format, col, wide};

#[derive(Debug, Subcommand)]
pub enum ReverseProxyCmd {
    /// Service status and object counts
    Status,
    /// Start the reverse proxy
    Start,
    /// Stop the reverse proxy
    Stop,
    /// Restart the reverse proxy
    Restart,
    /// Validate the generated config
    Validate,
    /// Generate config, write YAML, and reload (stops it if disabled)
    Apply,
    /// Global settings (enabled, log level, access log, …)
    Config {
        /// Replace the settings from a JSON/YAML file (- for stdin)
        #[arg(short = 'f', long = "file")]
        file: Option<String>,
    },
    /// Recent log lines
    Logs {
        #[arg(long, default_value_t = 200)]
        lines: u32,
        /// Only lines containing this text
        #[arg(long)]
        search: Option<String>,
        #[arg(short = 'F', long)]
        follow: bool,
    },
    /// Entrypoints
    Entrypoints(Coll),
    /// HTTP routers
    HttpRouters(Coll),
    /// HTTP services
    HttpServices(Coll),
    /// HTTP middlewares
    HttpMiddlewares(Coll),
    /// TCP routers
    TcpRouters(Coll),
    /// TCP services
    TcpServices(Coll),
    /// UDP routers
    UdpRouters(Coll),
    /// UDP services
    UdpServices(Coll),
    /// TLS certificates
    TlsCerts(Coll),
    /// TLS options
    TlsOptions(Coll),
    /// ACME certificate resolvers
    CertResolvers(Coll),
    // ---- legacy list shortcuts ----
    #[command(hide = true)]
    Routers {
        #[arg(long)]
        json: bool,
    },
    #[command(hide = true)]
    Services {
        #[arg(long)]
        json: bool,
    },
    #[command(hide = true)]
    Middlewares {
        #[arg(long)]
        json: bool,
    },
    /// (Replaced by `config`; the generated YAML is not exposed by the API)
    #[command(hide = true)]
    ShowConfig,
}

use super::resource::{Coll, Crud, Resource};

fn cols_for(path: &str) -> Vec<Col> {
    let mut c = vec![col("ID", "/id"), col("NAME", "/name")];
    if path.contains("routers") {
        c.extend([
            col("RULE", "/rule"),
            col("SERVICE", "/service"),
            wide("ENTRYPOINTS", "/entry_points"),
            wide("PRIORITY", "/priority"),
        ]);
    } else if path.ends_with("entrypoints") {
        c.push(col("ADDRESS", "/address"));
    } else if path.contains("services") {
        c.push(col("TYPE", "/service_type"));
    } else if path.contains("middlewares") {
        c.push(col("TYPE", "/middleware_type"));
    }
    c.push(col("ENABLED", "/enabled"));
    c
}

fn res(path: &str) -> Resource {
    Resource {
        path: path.to_string(),
        what: "object",
        cols: cols_for(path),
    }
}

async fn coll(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    path: &str,
    c: Coll,
) -> anyhow::Result<()> {
    super::resource::coll(ctx, client, &res(path), c).await
}

async fn crud(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    path: &str,
    cmd: Crud,
) -> anyhow::Result<()> {
    super::resource::crud(ctx, client, &res(path), cmd).await
}

/// The old `routers` / `services` / `middlewares` list shortcuts.
async fn legacy_list(
    ctx: &mut Ctx,
    client: &aifw_client::Client,
    path: &str,
    json: bool,
) -> anyhow::Result<()> {
    if json {
        ctx.force_format(Format::Json);
    }
    crud(ctx, client, path, Crud::List).await
}

pub async fn run(ctx: &mut Ctx, cmd: ReverseProxyCmd) -> anyhow::Result<()> {
    let client = ctx.client()?;
    let base = "/reverse-proxy";
    match cmd {
        ReverseProxyCmd::Status => {
            let v = client.get("/reverse-proxy/status").await?;
            ctx.detail(
                &v,
                &[
                    ("Running", "/running"),
                    ("Version", "/version"),
                    ("Entrypoints", "/entrypoints"),
                    ("HTTP routers", "/http_routers"),
                    ("HTTP services", "/http_services"),
                    ("HTTP middlewares", "/http_middlewares"),
                    ("TCP routers", "/tcp_routers"),
                    ("UDP routers", "/udp_routers"),
                ],
            )
        }
        ReverseProxyCmd::Start => {
            let v = client.post_empty("/reverse-proxy/start").await?;
            ctx.service_message(&v, "Started")
        }
        ReverseProxyCmd::Stop => {
            let v = client.post_empty("/reverse-proxy/stop").await?;
            ctx.service_message(&v, "Stopped")
        }
        ReverseProxyCmd::Restart => {
            let v = client.post_empty("/reverse-proxy/restart").await?;
            ctx.service_message(&v, "Restarted")
        }
        ReverseProxyCmd::Validate => {
            let v = client.post_empty("/reverse-proxy/validate").await?;
            ctx.service_message(&v, "Configuration valid")
        }
        ReverseProxyCmd::Apply => {
            let v = client.post_empty("/reverse-proxy/apply").await?;
            ctx.service_message(&v, "Applied")
        }
        ReverseProxyCmd::Config { file } => {
            let v = match file {
                Some(f) => {
                    let body = crate::cli::body::read(&mut ctx.io, &f)?;
                    client.put("/reverse-proxy/config", &body).await?
                }
                None => client.get("/reverse-proxy/config").await?,
            };
            ctx.raw(&v)
        }
        ReverseProxyCmd::ShowConfig => {
            ctx.io.eprintln("note: the generated YAML isn't exposed by the API; showing the global settings (`aifw reverse-proxy config`).");
            ctx.raw(&client.get("/reverse-proxy/config").await?)
        }
        ReverseProxyCmd::Logs {
            lines,
            search,
            follow,
        } => {
            let mut path = format!("/reverse-proxy/logs?lines={lines}");
            if let Some(s) = search {
                let q: String = url::form_urlencoded::byte_serialize(s.as_bytes()).collect();
                path.push_str(&format!("&search={q}"));
            }
            super::logs::tail(ctx, &client, &path, follow).await
        }
        ReverseProxyCmd::Routers { json } => {
            legacy_list(ctx, &client, "/reverse-proxy/http/routers", json).await
        }
        ReverseProxyCmd::Services { json } => {
            legacy_list(ctx, &client, "/reverse-proxy/http/services", json).await
        }
        ReverseProxyCmd::Middlewares { json } => {
            legacy_list(ctx, &client, "/reverse-proxy/http/middlewares", json).await
        }
        ReverseProxyCmd::Entrypoints(c) => {
            coll(ctx, &client, &format!("{base}/entrypoints"), c).await
        }
        ReverseProxyCmd::HttpRouters(c) => {
            coll(ctx, &client, &format!("{base}/http/routers"), c).await
        }
        ReverseProxyCmd::HttpServices(c) => {
            coll(ctx, &client, &format!("{base}/http/services"), c).await
        }
        ReverseProxyCmd::HttpMiddlewares(c) => {
            coll(ctx, &client, &format!("{base}/http/middlewares"), c).await
        }
        ReverseProxyCmd::TcpRouters(c) => {
            coll(ctx, &client, &format!("{base}/tcp/routers"), c).await
        }
        ReverseProxyCmd::TcpServices(c) => {
            coll(ctx, &client, &format!("{base}/tcp/services"), c).await
        }
        ReverseProxyCmd::UdpRouters(c) => {
            coll(ctx, &client, &format!("{base}/udp/routers"), c).await
        }
        ReverseProxyCmd::UdpServices(c) => {
            coll(ctx, &client, &format!("{base}/udp/services"), c).await
        }
        ReverseProxyCmd::TlsCerts(c) => coll(ctx, &client, &format!("{base}/tls/certs"), c).await,
        ReverseProxyCmd::TlsOptions(c) => {
            coll(ctx, &client, &format!("{base}/tls/options"), c).await
        }
        ReverseProxyCmd::CertResolvers(c) => {
            coll(ctx, &client, &format!("{base}/cert-resolvers"), c).await
        }
    }
}
