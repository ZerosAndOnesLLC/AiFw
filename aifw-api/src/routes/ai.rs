//! `/api/v1/settings/ai` handlers — provider configuration, connection
//! test, and model enumeration, plus the curl/fetch HTTP helpers those
//! last two rely on (FreeBSD ships `fetch`, not always `curl`).

use super::*;

pub async fn get_ai_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    async fn get_val(pool: &sqlx::SqlitePool, key: &str) -> Option<String> {
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = ?1")
            .bind(key)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .map(|r| r.0)
    }

    let pool = &state.pool;
    let providers = ["openai", "claude", "lm_studio", "ollama"];
    let mut configs = Vec::new();

    for p in &providers {
        let enabled = get_val(pool, &format!("ai_{p}_enabled"))
            .await
            .map(|v| v == "true")
            .unwrap_or(false);
        let api_key = get_val(pool, &format!("ai_{p}_api_key"))
            .await
            .unwrap_or_default();
        let endpoint = get_val(pool, &format!("ai_{p}_endpoint"))
            .await
            .unwrap_or_default();
        let model = get_val(pool, &format!("ai_{p}_model"))
            .await
            .unwrap_or_default();
        let tls_insecure = get_val(pool, &format!("ai_{p}_tls_insecure"))
            .await
            .map(|v| v == "true")
            .unwrap_or(false);

        configs.push(serde_json::json!({
            "provider": p,
            "enabled": enabled,
            "api_key_set": !api_key.is_empty(),
            "endpoint": endpoint,
            "model": model,
            "tls_insecure": tls_insecure,
        }));
    }

    let global_enabled = get_val(pool, "ai_enabled")
        .await
        .map(|v| v == "true")
        .unwrap_or(false);
    let active_provider = get_val(pool, "ai_active_provider")
        .await
        .unwrap_or_default();

    Ok(Json(serde_json::json!({
        "enabled": global_enabled,
        "active_provider": active_provider,
        "providers": configs,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAiSettingsRequest {
    pub enabled: Option<bool>,
    pub active_provider: Option<String>,
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub provider_enabled: Option<bool>,
    /// SEC-H4 (#289): opt-in skip of TLS cert verification for a provider,
    /// for local endpoints with self-signed certs. Off unless explicitly set.
    pub tls_insecure: Option<bool>,
}

pub async fn update_ai_settings(
    State(state): State<AppState>,
    Json(req): Json<UpdateAiSettingsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    async fn save_val(pool: &sqlx::SqlitePool, key: &str, val: &str) {
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES (?1, ?2)")
            .bind(key)
            .bind(val)
            .execute(pool)
            .await;
    }

    let pool = &state.pool;

    if let Some(enabled) = req.enabled {
        save_val(pool, "ai_enabled", if enabled { "true" } else { "false" }).await;
    }
    if let Some(ref active) = req.active_provider {
        save_val(pool, "ai_active_provider", active).await;
    }

    if let Some(ref provider) = req.provider {
        let valid = ["openai", "claude", "lm_studio", "ollama"];
        if !valid.contains(&provider.as_str()) {
            return Err(bad_request());
        }
        if let Some(ref key) = req.api_key {
            save_val(pool, &format!("ai_{provider}_api_key"), key).await;
        }
        if let Some(ref endpoint) = req.endpoint {
            save_val(pool, &format!("ai_{provider}_endpoint"), endpoint).await;
        }
        if let Some(ref model) = req.model {
            save_val(pool, &format!("ai_{provider}_model"), model).await;
        }
        if let Some(insecure) = req.tls_insecure {
            save_val(
                pool,
                &format!("ai_{provider}_tls_insecure"),
                if insecure { "true" } else { "false" },
            )
            .await;
        }
        if let Some(enabled) = req.provider_enabled {
            save_val(
                pool,
                &format!("ai_{provider}_enabled"),
                if enabled { "true" } else { "false" },
            )
            .await;
        }
    }

    Ok(Json(serde_json::json!({ "message": "AI settings saved" })))
}

// --- AI HTTP helpers (curl with fetch fallback for FreeBSD) ---

async fn http_get_status(
    url: &str,
    auth: &str,
    provider: &str,
    tls_insecure: bool,
) -> Result<(String, bool), String> {
    // Reject non-http(s) schemes up front — gates both the curl and the
    // fetch fallback (FreeBSD `fetch` honors file://).
    crate::ai_analysis::require_http_url(url)?;
    // Try curl first, fall back to fetch (FreeBSD built-in)
    let result = if let Ok(output) = build_curl_status(url, auth, provider, tls_insecure).await {
        output
    } else if let Ok(output) = build_fetch_status(url).await {
        output
    } else {
        return Err("No HTTP client available".to_string());
    };
    Ok(result)
}

async fn build_curl_status(
    url: &str,
    auth: &str,
    provider: &str,
    tls_insecure: bool,
) -> Result<(String, bool), String> {
    let mut args: Vec<String> = vec!["-s"].into_iter().map(String::from).collect();
    if tls_insecure {
        args.push("-k".to_string());
    }
    args.extend(
        [
            "--connect-timeout",
            "5",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
        ]
        .into_iter()
        .map(String::from),
    );
    if !auth.is_empty() {
        if provider == "claude" {
            args.extend([
                "-H".to_string(),
                format!("x-api-key: {auth}"),
                "-H".to_string(),
                "anthropic-version: 2023-06-01".to_string(),
            ]);
        } else {
            args.extend(["-H".to_string(), format!("Authorization: {auth}")]);
        }
    }
    args.push(url.to_string());
    let output = tokio::process::Command::new("curl")
        .args(&args)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err("curl failed".to_string());
    }
    let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let ok = code.starts_with('2');
    Ok((code, ok))
}

async fn build_fetch_status(url: &str) -> Result<(String, bool), String> {
    // FreeBSD fetch: -o /dev/null returns 0 on success
    let output = tokio::process::Command::new("/usr/bin/fetch")
        .args(["-T", "5", "-o", "/dev/null", url])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    let ok = output.status.success();
    Ok((
        if ok {
            "200".to_string()
        } else {
            "000".to_string()
        },
        ok,
    ))
}

async fn http_get_body(
    url: &str,
    auth: &str,
    provider: &str,
    tls_insecure: bool,
) -> Result<String, String> {
    // Reject non-http(s) schemes up front — gates the fetch fallback too.
    crate::ai_analysis::require_http_url(url)?;
    // Try curl first
    if let Ok(body) = build_curl_body(url, auth, provider, tls_insecure).await {
        return Ok(body);
    }
    // Fallback to fetch
    let output = tokio::process::Command::new("/usr/bin/fetch")
        .args(["-T", "5", "-qo", "-", url])
        .output()
        .await
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn build_curl_body(
    url: &str,
    auth: &str,
    provider: &str,
    tls_insecure: bool,
) -> Result<String, String> {
    let mut args: Vec<String> = vec!["-s"].into_iter().map(String::from).collect();
    if tls_insecure {
        args.push("-k".to_string());
    }
    args.extend(["--connect-timeout", "5"].into_iter().map(String::from));
    if !auth.is_empty() {
        if provider == "claude" {
            args.extend([
                "-H".to_string(),
                format!("x-api-key: {auth}"),
                "-H".to_string(),
                "anthropic-version: 2023-06-01".to_string(),
            ]);
        } else {
            args.extend(["-H".to_string(), format!("Authorization: {auth}")]);
        }
    }
    args.push(url.to_string());
    let output = tokio::process::Command::new("curl")
        .args(&args)
        .output()
        .await
        .map_err(|e| e.to_string())?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err("curl not available".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- AI Provider Model List & Connection Test ---

pub async fn test_ai_provider(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let provider = req
        .get("provider")
        .and_then(|v| v.as_str())
        .ok_or(bad_request())?;
    let pool = &state.pool;

    // Load provider config
    async fn get_val(pool: &sqlx::SqlitePool, key: &str) -> String {
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = ?1")
            .bind(key)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .map(|r| r.0)
            .unwrap_or_default()
    }

    let api_key = get_val(pool, &format!("ai_{provider}_api_key")).await;
    let endpoint = get_val(pool, &format!("ai_{provider}_endpoint")).await;
    let model = get_val(pool, &format!("ai_{provider}_model")).await;
    let stored_insecure = get_val(pool, &format!("ai_{provider}_tls_insecure")).await == "true";

    // Allow request overrides for testing before saving
    let endpoint = req
        .get("endpoint")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or(endpoint);
    let api_key = req
        .get("api_key")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or(api_key);
    let tls_insecure = req
        .get("tls_insecure")
        .and_then(|v| v.as_bool())
        .unwrap_or(stored_insecure);

    if endpoint.is_empty() {
        return Ok(Json(
            serde_json::json!({ "success": false, "error": "No endpoint configured" }),
        ));
    }

    // Build the models URL based on provider type
    let (models_url, auth_header) = match provider {
        "openai" | "lm_studio" => {
            let url = format!("{}/models", endpoint.trim_end_matches('/'));
            let auth = if api_key.is_empty() {
                String::new()
            } else {
                format!("Bearer {api_key}")
            };
            (url, auth)
        }
        "claude" => {
            // Anthropic doesn't have a /models endpoint — just test with a minimal message
            let url = format!("{}/v1/messages", endpoint.trim_end_matches('/'));
            let auth = api_key.clone();
            (url, auth)
        }
        "ollama" => {
            let url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
            (url, String::new())
        }
        _ => return Err(bad_request()),
    };

    // Test connectivity — try curl, fall back to fetch (FreeBSD built-in)
    let (status_code, success) =
        match http_get_status(&models_url, &auth_header, provider, tls_insecure).await {
            Ok((code, ok)) => (code, ok),
            Err(_) => return Err(internal()),
        };

    Ok(Json(serde_json::json!({
        "success": success,
        "status_code": status_code,
        "endpoint": endpoint,
        "model": model,
    })))
}

pub async fn list_ai_models(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let provider = q.get("provider").ok_or(bad_request())?;
    let pool = &state.pool;

    async fn get_val(pool: &sqlx::SqlitePool, key: &str) -> String {
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = ?1")
            .bind(key)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten()
            .map(|r| r.0)
            .unwrap_or_default()
    }

    let api_key = get_val(pool, &format!("ai_{provider}_api_key")).await;
    let endpoint = get_val(pool, &format!("ai_{provider}_endpoint")).await;
    let tls_insecure = get_val(pool, &format!("ai_{provider}_tls_insecure")).await == "true";

    if endpoint.is_empty() {
        return Ok(Json(
            serde_json::json!({ "models": [], "error": "No endpoint configured" }),
        ));
    }

    let (url, auth_args): (String, Vec<String>) = match provider.as_str() {
        "openai" | "lm_studio" => {
            let url = format!("{}/models", endpoint.trim_end_matches('/'));
            let mut a = vec![];
            if !api_key.is_empty() {
                a.push("-H".to_string());
                a.push(format!("Authorization: Bearer {api_key}"));
            }
            (url, a)
        }
        "ollama" => {
            let url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
            (url, vec![])
        }
        "claude" => {
            // Anthropic doesn't expose a models list API — return known models
            return Ok(Json(serde_json::json!({
                "models": [
                    "claude-sonnet-4-20250514",
                    "claude-opus-4-20250514",
                    "claude-haiku-4-20250414",
                    "claude-3-5-sonnet-20241022",
                    "claude-3-5-haiku-20241022"
                ]
            })));
        }
        _ => return Err(bad_request()),
    };

    let auth = if auth_args.len() >= 2 {
        auth_args[1].clone()
    } else {
        String::new()
    };
    let body = http_get_body(&url, &auth, provider.as_str(), tls_insecure)
        .await
        .unwrap_or_default();

    // Parse response — OpenAI returns { data: [{id: "model-name"}, ...] }, Ollama returns { models: [{name: "model"}, ...] }
    let models: Vec<String> = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            data.iter()
                .filter_map(|m| m.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()))
                .collect()
        } else if let Some(models) = json.get("models").and_then(|d| d.as_array()) {
            models
                .iter()
                .filter_map(|m| {
                    m.get("name")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string())
                })
                .collect()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    Ok(Json(serde_json::json!({ "models": models })))
}
