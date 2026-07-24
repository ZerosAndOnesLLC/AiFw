//! FQ-CoDel shaper API: CRUD plus explicit apply/status operations.

use super::*;
use aifw_common::QueueConfig;

#[derive(Debug, Serialize)]
pub struct ShaperStatus {
    pub configured: usize,
    pub active: usize,
    pub backend: &'static str,
    pub verified: bool,
}

pub async fn list_shaper_queues(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<QueueConfig>>>, StatusCode> {
    let queues = state
        .shaping_engine
        .list_queues()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: queues }))
}

pub async fn create_shaper_queue(
    State(state): State<AppState>,
    Json(queue): Json<QueueConfig>,
) -> Result<(StatusCode, Json<ApiResponse<QueueConfig>>), StatusCode> {
    let created = state
        .shaping_engine
        .add_queue(queue)
        .await
        .map_err(|_| bad_request())?;
    state
        .shaping_engine
        .apply_queues()
        .await
        .map_err(|_| internal())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: created })))
}

pub async fn delete_shaper_queue(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let id = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .shaping_engine
        .delete_queue(id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    state
        .shaping_engine
        .apply_queues()
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "shaper queue deleted and live state reapplied".into(),
    }))
}

pub async fn update_shaper_queue(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(mut queue): Json<QueueConfig>,
) -> Result<Json<ApiResponse<QueueConfig>>, StatusCode> {
    queue.id = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let updated = state
        .shaping_engine
        .update_queue(queue)
        .await
        .map_err(|_| bad_request())?;
    state
        .shaping_engine
        .apply_queues()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: updated }))
}

pub async fn apply_shaper(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    state
        .shaping_engine
        .apply_queues()
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: "shaper configuration applied and verified".into(),
    }))
}

pub async fn shaper_status(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ShaperStatus>>, StatusCode> {
    let queues = state
        .shaping_engine
        .list_queues()
        .await
        .map_err(|_| internal())?;
    let active = queues
        .iter()
        .filter(|queue| queue.status == aifw_common::QueueStatus::Active)
        .count();
    let verified = if cfg!(target_os = "freebsd") && active > 0 {
        tokio::process::Command::new("dnctl")
            .args(["pipe", "list"])
            .output()
            .await
            .map(|output| output.status.success())
            .unwrap_or(false)
    } else {
        active == 0
    };
    Ok(Json(ApiResponse {
        data: ShaperStatus {
            configured: queues.len(),
            active,
            backend: if cfg!(target_os = "freebsd") {
                "dummynet"
            } else {
                "mock"
            },
            verified,
        },
    }))
}
