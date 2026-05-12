//! `/api/v1/routes` handlers — static-route CRUD + a read-only
//! `netstat`-backed system-routing-table view. Extracted from the
//! legacy 4000-line `routes.rs` God module (#187).

use super::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StaticRoute {
    pub id: String,
    pub destination: String,
    pub gateway: String,
    pub interface: Option<String>,
    pub metric: i32,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub fib: u32,
}

#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    pub destination: String,
    pub gateway: String,
    pub interface: Option<String>,
    pub metric: Option<i32>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
    #[serde(default)]
    pub fib: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct SystemRoute {
    pub destination: String,
    pub gateway: String,
    pub flags: String,
    pub interface: String,
}

pub async fn list_static_routes(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<StaticRoute>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>, i32, bool, Option<String>, String, i64)>(
        "SELECT id, destination, gateway, interface, metric, enabled, description, created_at, COALESCE(fib,0) FROM static_routes ORDER BY fib ASC, metric ASC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;
    let routes: Vec<StaticRoute> = rows
        .into_iter()
        .map(
            |(id, dest, gw, iface, metric, enabled, desc, ca, fib)| StaticRoute {
                id,
                destination: dest,
                gateway: gw,
                interface: iface,
                metric,
                enabled,
                description: desc,
                created_at: ca,
                fib: fib as u32,
            },
        )
        .collect();
    Ok(Json(ApiResponse { data: routes }))
}

pub(crate) fn validate_route_target(s: &str) -> Result<(), StatusCode> {
    // Accept IP or CIDR (e.g., "10.0.0.0/8", "192.168.1.1", "default")
    if s == "default" {
        return Ok(());
    }
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        ip_str
            .parse::<std::net::IpAddr>()
            .map_err(|_| bad_request())?;
        let prefix: u8 = prefix_str.parse().map_err(|_| bad_request())?;
        if prefix > 128 {
            return Err(bad_request());
        }
    } else {
        s.parse::<std::net::IpAddr>().map_err(|_| bad_request())?;
    }
    Ok(())
}

pub async fn create_static_route(
    State(state): State<AppState>,
    Json(req): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<ApiResponse<StaticRoute>>), StatusCode> {
    validate_route_target(&req.destination)?;
    validate_route_target(&req.gateway)?;
    if let Some(ref iface) = req.interface {
        aifw_core::validation::validate_interface_name(iface).map_err(|_| bad_request())?;
    }
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let metric = req.metric.unwrap_or(0);
    let enabled = req.enabled.unwrap_or(true);
    let fib = req.fib.unwrap_or(0);

    sqlx::query(
        "INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at, fib) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&id).bind(&req.destination).bind(&req.gateway).bind(req.interface.as_deref())
    .bind(metric).bind(enabled).bind(req.description.as_deref()).bind(&now).bind(fib as i64)
    .execute(&state.pool)
    .await
    .map_err(|_| bad_request())?;

    // Apply to system if enabled
    if enabled {
        apply_route_to_system(
            &req.destination,
            &req.gateway,
            req.interface.as_deref(),
            fib,
        )
        .await;
    }

    let route = StaticRoute {
        id,
        destination: req.destination,
        gateway: req.gateway,
        interface: req.interface,
        metric,
        enabled,
        description: req.description,
        created_at: now,
        fib,
    };
    Ok((StatusCode::CREATED, Json(ApiResponse { data: route })))
}

pub async fn update_static_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateRouteRequest>,
) -> Result<Json<ApiResponse<StaticRoute>>, StatusCode> {
    validate_route_target(&req.destination)?;
    validate_route_target(&req.gateway)?;
    if let Some(ref iface) = req.interface {
        aifw_core::validation::validate_interface_name(iface).map_err(|_| bad_request())?;
    }
    // Get old route to remove from system
    let old = sqlx::query_as::<_, (String, String, Option<String>, bool, i64)>(
        "SELECT destination, gateway, interface, enabled, COALESCE(fib,0) FROM static_routes WHERE id = ?1",
    )
    .bind(&id).fetch_optional(&state.pool).await.map_err(|_| internal())?
    .ok_or(StatusCode::NOT_FOUND)?;

    if old.3 {
        // was enabled, remove old route (from the FIB it was in)
        remove_route_from_system(&old.0, &old.1, old.4 as u32).await;
    }

    let metric = req.metric.unwrap_or(0);
    let enabled = req.enabled.unwrap_or(true);
    let fib = req.fib.unwrap_or(0);

    sqlx::query(
        "UPDATE static_routes SET destination = ?2, gateway = ?3, interface = ?4, metric = ?5, enabled = ?6, description = ?7, fib = ?8 WHERE id = ?1",
    )
    .bind(&id).bind(&req.destination).bind(&req.gateway).bind(req.interface.as_deref())
    .bind(metric).bind(enabled).bind(req.description.as_deref()).bind(fib as i64)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if enabled {
        apply_route_to_system(
            &req.destination,
            &req.gateway,
            req.interface.as_deref(),
            fib,
        )
        .await;
    }

    let now = chrono::Utc::now().to_rfc3339();
    let route = StaticRoute {
        id,
        destination: req.destination,
        gateway: req.gateway,
        interface: req.interface,
        metric,
        enabled,
        description: req.description,
        created_at: now,
        fib,
    };
    Ok(Json(ApiResponse { data: route }))
}

pub async fn delete_static_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, bool, i64)>(
        "SELECT destination, gateway, enabled, COALESCE(fib,0) FROM static_routes WHERE id = ?1",
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await
    .map_err(|_| internal())?
    .ok_or(StatusCode::NOT_FOUND)?;

    if row.2 {
        remove_route_from_system(&row.0, &row.1, row.3 as u32).await;
    }

    sqlx::query("DELETE FROM static_routes WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    Ok(Json(MessageResponse {
        message: format!("Route to {} deleted", row.0),
    }))
}

pub(crate) async fn apply_route_to_system(
    destination: &str,
    gateway: &str,
    interface: Option<&str>,
    fib: u32,
) {
    let fib_s = fib.to_string();
    let mut args: Vec<&str> = Vec::new();
    args.push("/sbin/route");
    if fib > 0 {
        args.push("-fib");
        args.push(&fib_s);
    }
    args.push("add");
    args.push(destination);
    args.push(gateway);
    if let Some(iface) = interface {
        args.push("-interface");
        args.push(iface);
    }
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(&args)
        .output()
        .await;
    match output {
        Ok(o) if o.status.success() => {
            tracing::info!(destination, gateway, fib, "route added");
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            tracing::warn!(destination, gateway, fib, error = %err, "route add failed");
        }
        Err(e) => {
            tracing::warn!(destination, gateway, fib, error = %e, "route command failed");
        }
    }
}

async fn remove_route_from_system(destination: &str, gateway: &str, fib: u32) {
    let fib_s = fib.to_string();
    let mut args: Vec<&str> = Vec::new();
    args.push("/sbin/route");
    if fib > 0 {
        args.push("-fib");
        args.push(&fib_s);
    }
    args.push("delete");
    args.push(destination);
    args.push(gateway);
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(&args)
        .output()
        .await;
    match output {
        Ok(o) if o.status.success() => {
            tracing::info!(destination, gateway, fib, "route removed");
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            tracing::debug!(destination, gateway, fib, error = %err, "route delete failed (may not exist)");
        }
        Err(e) => {
            tracing::warn!(destination, gateway, fib, error = %e, "route command failed");
        }
    }
}

/// Apply all enabled static routes from the database. Called on API startup.
pub async fn apply_all_routes(pool: &sqlx::SqlitePool) {
    let routes: Vec<(String, String, Option<String>, i64)> = match sqlx::query_as(
        "SELECT destination, gateway, interface, COALESCE(fib,0) FROM static_routes WHERE enabled = 1 ORDER BY fib ASC, metric ASC"
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load static routes for startup");
            return;
        }
    };

    if routes.is_empty() {
        return;
    }

    tracing::info!(count = routes.len(), "applying static routes on startup");
    for (dest, gw, iface, fib) in &routes {
        apply_route_to_system(dest, gw, iface.as_deref(), *fib as u32).await;
    }
}
