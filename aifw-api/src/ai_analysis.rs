//! AI-assisted alert analysis — reviews critical/high IDS alerts using the
//! configured LLM provider and classifies them automatically.

use axum::{extract::State, http::StatusCode, Json};
use sqlx::SqlitePool;
use uuid::Uuid;

use crate::AppState;

/// Run AI analysis on unreviewed critical/high alerts.
/// Called periodically by a background task or manually via API.
pub async fn run_analysis(pool: &SqlitePool) -> Result<u32, String> {
    // 1. Check if AI is enabled and get active provider
    let enabled = get_config(pool, "ai_enabled").await.map(|v| v == "true").unwrap_or(false);
    if !enabled {
        return Ok(0);
    }

    let provider = get_config(pool, "ai_active_provider").await.unwrap_or_default();
    if provider.is_empty() {
        return Err("No active AI provider configured".into());
    }

    let api_key = get_config(pool, &format!("ai_{provider}_api_key")).await.unwrap_or_default();
    let endpoint = get_config(pool, &format!("ai_{provider}_endpoint")).await.unwrap_or_default();
    let model = get_config(pool, &format!("ai_{provider}_model")).await.unwrap_or_default();

    if endpoint.is_empty() {
        return Err("AI provider endpoint not configured".into());
    }

    // 2. Get unreviewed critical/high alerts that haven't been AI-analyzed yet.
    //    Group by signature_id to avoid asking about the same rule multiple times.
    let alerts: Vec<(String, Option<i64>, String, i64, String, Option<i64>, String, Option<i64>, String, Option<String>, Option<String>)> = sqlx::query_as(
        r#"SELECT id, signature_id, signature_msg, severity, src_ip, src_port, dst_ip, dst_port, protocol, payload_excerpt,
           (SELECT group_concat(key || '=' || value, '; ') FROM json_each(metadata) WHERE metadata IS NOT NULL) as meta_str
           FROM ids_alerts
           WHERE classification = 'unreviewed' AND ai_analyzed = 0 AND severity <= 2
           ORDER BY severity ASC, timestamp DESC
           LIMIT 20"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("query failed: {e}"))?;

    if alerts.is_empty() {
        return Ok(0);
    }

    // 3. Group by signature_id to deduplicate
    let mut analyzed_sigs: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let mut classified = 0u32;

    for alert in &alerts {
        let alert_id = &alert.0;
        let sig_id = alert.1.unwrap_or(0);
        let sig_msg = &alert.2;
        let severity = alert.3;
        let src_ip = &alert.4;
        let src_port = alert.5.map(|p| p.to_string()).unwrap_or_default();
        let dst_ip = &alert.6;
        let dst_port = alert.7.map(|p| p.to_string()).unwrap_or_default();
        let protocol = &alert.8;
        let payload = alert.9.as_deref().unwrap_or("(none)");

        // Skip if we already analyzed this signature in this batch
        if sig_id > 0 && analyzed_sigs.contains(&sig_id) {
            // Apply the same classification as the first alert with this sig
            let _ = sqlx::query("UPDATE ids_alerts SET ai_analyzed = 1 WHERE id = ?")
                .bind(alert_id).execute(pool).await;
            continue;
        }

        // 4. Build the prompt
        let sev_label = match severity {
            1 => "Critical",
            2 => "High",
            _ => "Medium",
        };

        let prompt = format!(
            r#"You are a network security analyst reviewing an IDS alert from an Emerging Threats (ET Open) ruleset on a FreeBSD firewall.

Alert Details:
- Signature: {sig_msg} (SID: {sig_id})
- Severity: {sev_label}
- Source: {src_ip}:{src_port} → Destination: {dst_ip}:{dst_port}
- Protocol: {protocol}
- Payload excerpt: {payload}

Classify this alert as one of:
- "false_positive" — benign traffic that matched an overly broad rule (e.g., encrypted HTTPS matching exploit patterns, normal DNS responses, standard software update traffic)
- "confirmed" — genuinely suspicious or malicious activity that warrants investigation
- "investigating" — unclear, needs more context

Respond with ONLY a JSON object, no markdown, no explanation outside the JSON:
{{"classification": "false_positive|confirmed|investigating", "reason": "brief 1-2 sentence explanation"}}"#
        );

        // 5. Call the AI provider
        let start = std::time::Instant::now();
        let response = call_ai_provider(&provider, &endpoint, &api_key, &model, &prompt).await;
        let duration_ms = start.elapsed().as_millis() as i64;

        match response {
            Ok(ai_response) => {
                // 6. Parse the response
                let (classification, reason) = parse_ai_response(&ai_response);

                // 7. Apply classification to this alert and all alerts with same signature
                if sig_id > 0 {
                    let _ = sqlx::query(
                        "UPDATE ids_alerts SET classification = ?, analyst_notes = ?, ai_analyzed = 1, acknowledged = 1 WHERE signature_id = ? AND classification = 'unreviewed'"
                    )
                    .bind(&classification)
                    .bind(&format!("AI ({provider}): {reason}"))
                    .bind(sig_id)
                    .execute(pool).await;
                    analyzed_sigs.insert(sig_id);
                } else {
                    let _ = sqlx::query(
                        "UPDATE ids_alerts SET classification = ?, analyst_notes = ?, ai_analyzed = 1, acknowledged = 1 WHERE id = ?"
                    )
                    .bind(&classification)
                    .bind(&format!("AI ({provider}): {reason}"))
                    .bind(alert_id)
                    .execute(pool).await;
                }

                // 8. Log to audit
                let log_id = Uuid::new_v4().to_string();
                let _ = sqlx::query(
                    "INSERT INTO ai_audit_log (id, alert_id, signature_id, signature_msg, provider, model, prompt, response, classification, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                .bind(&log_id)
                .bind(alert_id)
                .bind(sig_id)
                .bind(sig_msg)
                .bind(&provider)
                .bind(&model)
                .bind(&prompt)
                .bind(&ai_response)
                .bind(&classification)
                .bind(duration_ms)
                .execute(pool).await;

                classified += 1;
                tracing::info!(sig_id, classification = %classification, reason = %reason, "AI classified alert");
            }
            Err(e) => {
                tracing::warn!(sig_id, error = %e, "AI analysis failed");
                // Mark as analyzed to avoid retrying immediately
                let _ = sqlx::query("UPDATE ids_alerts SET ai_analyzed = 1 WHERE id = ?")
                    .bind(alert_id).execute(pool).await;

                // Log the failure
                let log_id = Uuid::new_v4().to_string();
                let _ = sqlx::query(
                    "INSERT INTO ai_audit_log (id, alert_id, signature_id, signature_msg, provider, model, prompt, response, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
                )
                .bind(&log_id)
                .bind(alert_id)
                .bind(sig_id)
                .bind(sig_msg)
                .bind(&provider)
                .bind(&model)
                .bind(&prompt)
                .bind(&format!("ERROR: {e}"))
                .bind(duration_ms)
                .execute(pool).await;
            }
        }
    }

    Ok(classified)
}

/// Call the AI provider's chat completion API.
async fn call_ai_provider(provider: &str, endpoint: &str, api_key: &str, model: &str, prompt: &str) -> Result<String, String> {
    let (url, body) = match provider {
        "openai" | "lm_studio" => {
            let url = format!("{}/chat/completions", endpoint.trim_end_matches('/'));
            let body = serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": 200,
            });
            (url, body)
        }
        "claude" => {
            let url = format!("{}/v1/messages", endpoint.trim_end_matches('/'));
            let body = serde_json::json!({
                "model": model,
                "max_tokens": 200,
                "messages": [{"role": "user", "content": prompt}],
            });
            (url, body)
        }
        "ollama" => {
            let url = format!("{}/api/chat", endpoint.trim_end_matches('/'));
            let body = serde_json::json!({
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": false,
            });
            (url, body)
        }
        _ => return Err(format!("unknown provider: {provider}")),
    };

    let body_str = serde_json::to_string(&body).map_err(|e| e.to_string())?;

    let mut args = vec![
        "-sk".to_string(),
        "--connect-timeout".to_string(), "30".to_string(),
        "-m".to_string(), "60".to_string(),
        "-X".to_string(), "POST".to_string(),
        "-H".to_string(), "Content-Type: application/json".to_string(),
    ];

    match provider {
        "claude" => {
            args.extend(["-H".to_string(), format!("x-api-key: {api_key}")]);
            args.extend(["-H".to_string(), "anthropic-version: 2023-06-01".to_string()]);
        }
        "openai" | "lm_studio" if !api_key.is_empty() => {
            args.extend(["-H".to_string(), format!("Authorization: Bearer {api_key}")]);
        }
        _ => {}
    }

    args.extend(["-d".to_string(), body_str, url]);

    let output = tokio::process::Command::new("curl")
        .args(args.iter().map(|s| s.as_str()).collect::<Vec<_>>())
        .output()
        .await
        .map_err(|e| format!("curl failed: {e}"))?;

    if !output.status.success() {
        return Err(format!("HTTP error: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let response_body = String::from_utf8_lossy(&output.stdout).to_string();

    // Extract the text content from the response
    let json: serde_json::Value = serde_json::from_str(&response_body)
        .map_err(|e| format!("JSON parse error: {e} — body: {}", &response_body[..200.min(response_body.len())]))?;

    // OpenAI / LM Studio format: { choices: [{ message: { content: "..." } }] }
    if let Some(content) = json.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        return Ok(content.to_string());
    }

    // Claude format: { content: [{ text: "..." }] }
    if let Some(content) = json.get("content")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("text"))
        .and_then(|t| t.as_str())
    {
        return Ok(content.to_string());
    }

    // Ollama format: { message: { content: "..." } }
    if let Some(content) = json.get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
    {
        return Ok(content.to_string());
    }

    Err(format!("Could not extract content from response: {}", &response_body[..300.min(response_body.len())]))
}

/// Parse the AI response to extract classification and reason.
fn parse_ai_response(response: &str) -> (String, String) {
    // Try to parse as JSON
    let cleaned = response.trim().trim_start_matches("```json").trim_start_matches("```").trim_end_matches("```").trim();

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(cleaned) {
        let classification = json.get("classification")
            .and_then(|c| c.as_str())
            .unwrap_or("investigating")
            .to_string();
        let reason = json.get("reason")
            .and_then(|r| r.as_str())
            .unwrap_or("AI analysis completed")
            .to_string();

        // Validate classification
        let valid = ["confirmed", "false_positive", "investigating"];
        let classification = if valid.contains(&classification.as_str()) {
            classification
        } else {
            "investigating".to_string()
        };

        return (classification, reason);
    }

    // Fallback: try to extract from plain text
    let lower = response.to_lowercase();
    if lower.contains("false_positive") || lower.contains("false positive") || lower.contains("benign") {
        ("false_positive".to_string(), response.chars().take(200).collect())
    } else if lower.contains("confirmed") || lower.contains("malicious") || lower.contains("suspicious") {
        ("confirmed".to_string(), response.chars().take(200).collect())
    } else {
        ("investigating".to_string(), response.chars().take(200).collect())
    }
}

async fn get_config(pool: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|r| r.0)
}

// ── API Endpoints ────────────────────────────────────────────

/// Manually trigger AI analysis of unreviewed alerts.
pub async fn trigger_analysis(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    match run_analysis(&state.pool).await {
        Ok(count) => Ok(Json(serde_json::json!({
            "message": format!("{count} alerts classified by AI"),
            "classified": count,
        }))),
        Err(e) => Ok(Json(serde_json::json!({
            "message": format!("AI analysis failed: {e}"),
            "error": e,
            "classified": 0,
        }))),
    }
}

/// Get AI audit log entries.
pub async fn get_audit_log(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let limit = q.get("limit").and_then(|v| v.parse::<u32>().ok()).unwrap_or(50);

    let rows: Vec<(String, Option<String>, Option<i64>, String, String, String, String, String, Option<String>, Option<i64>, String)> = sqlx::query_as(
        "SELECT id, alert_id, signature_id, signature_msg, provider, model, prompt, response, classification, duration_ms, created_at FROM ai_audit_log ORDER BY created_at DESC LIMIT ?"
    )
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let entries: Vec<serde_json::Value> = rows.into_iter().map(|r| {
        serde_json::json!({
            "id": r.0,
            "alert_id": r.1,
            "signature_id": r.2,
            "signature_msg": r.3,
            "provider": r.4,
            "model": r.5,
            "prompt_preview": r.6.chars().take(100).collect::<String>(),
            "response": r.7,
            "classification": r.8,
            "duration_ms": r.9,
            "created_at": r.10,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "entries": entries })))
}
