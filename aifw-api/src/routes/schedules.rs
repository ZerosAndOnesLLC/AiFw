//! `/api/v1/schedules` handlers — time-of-day windows that AiFw rules
//! can reference. Extracted from the legacy 4000-line `routes.rs` God
//! module (#187).

use super::*;

#[derive(Debug, Serialize, Deserialize)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub time_ranges: String, // e.g. "08:00-17:00" or "08:00-12:00,13:00-17:00"
    pub days_of_week: String, // e.g. "mon,tue,wed,thu,fri"
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
}

impl StringOrVec {
    fn into_string(self) -> String {
        match self {
            StringOrVec::Single(s) => s,
            StringOrVec::Multiple(v) => v.join(","),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub name: String,
    pub description: Option<String>,
    pub time_ranges: StringOrVec,
    pub days_of_week: Option<StringOrVec>,
    pub enabled: Option<bool>,
}

pub async fn list_schedules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Schedule>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, String, String, bool, String)>(
        "SELECT id, name, description, time_ranges, days_of_week, enabled, created_at FROM schedules ORDER BY name ASC",
    ).fetch_all(&state.pool).await.map_err(|_| internal())?;
    let schedules: Vec<Schedule> = rows
        .into_iter()
        .map(|(id, name, desc, tr, dow, en, ca)| Schedule {
            id,
            name,
            description: desc,
            time_ranges: tr,
            days_of_week: dow,
            enabled: en,
            created_at: ca,
        })
        .collect();
    Ok(Json(ApiResponse { data: schedules }))
}

fn validate_time_ranges(s: &str) -> bool {
    // Accepts "HH:MM-HH:MM" or comma-separated ranges
    for range in s.split(',') {
        let parts: Vec<&str> = range.trim().split('-').collect();
        if parts.len() != 2 {
            return false;
        }
        for part in &parts {
            let hm: Vec<&str> = part.split(':').collect();
            if hm.len() != 2 {
                return false;
            }
            let h: u8 = match hm[0].parse() {
                Ok(v) => v,
                Err(_) => return false,
            };
            let m: u8 = match hm[1].parse() {
                Ok(v) => v,
                Err(_) => return false,
            };
            if h > 23 || m > 59 {
                return false;
            }
        }
    }
    true
}

fn validate_days_of_week(s: &str) -> bool {
    const VALID: &[&str] = &["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    s.split(',').all(|d| VALID.contains(&d.trim()))
}

pub async fn create_schedule(
    State(state): State<AppState>,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Schedule>>), StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let time_ranges = req.time_ranges.into_string();
    if !validate_time_ranges(&time_ranges) {
        return Err(bad_request());
    }
    let dow = req
        .days_of_week
        .map(|d| d.into_string())
        .unwrap_or_else(|| "mon,tue,wed,thu,fri,sat,sun".to_string());
    if !validate_days_of_week(&dow) {
        return Err(bad_request());
    }
    let enabled = req.enabled.unwrap_or(true);
    sqlx::query("INSERT INTO schedules (id, name, description, time_ranges, days_of_week, enabled, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)")
        .bind(&id).bind(&req.name).bind(req.description.as_deref()).bind(&time_ranges).bind(&dow).bind(enabled).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            data: Schedule {
                id,
                name: req.name,
                description: req.description,
                time_ranges,
                days_of_week: dow,
                enabled,
                created_at: now,
            },
        }),
    ))
}

pub async fn update_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<Json<ApiResponse<Schedule>>, StatusCode> {
    let time_ranges = req.time_ranges.into_string();
    if !validate_time_ranges(&time_ranges) {
        return Err(bad_request());
    }
    let dow = req
        .days_of_week
        .map(|d| d.into_string())
        .unwrap_or_else(|| "mon,tue,wed,thu,fri,sat,sun".to_string());
    if !validate_days_of_week(&dow) {
        return Err(bad_request());
    }
    let enabled = req.enabled.unwrap_or(true);
    let result = sqlx::query("UPDATE schedules SET name=?2, description=?3, time_ranges=?4, days_of_week=?5, enabled=?6 WHERE id=?1")
        .bind(&id).bind(&req.name).bind(req.description.as_deref()).bind(&time_ranges).bind(&dow).bind(enabled)
        .execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    let now = chrono::Utc::now().to_rfc3339();
    Ok(Json(ApiResponse {
        data: Schedule {
            id,
            name: req.name,
            description: req.description,
            time_ranges,
            days_of_week: dow,
            enabled,
            created_at: now,
        },
    }))
}

pub async fn delete_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM schedules WHERE id=?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    // Unlink from rules
    let _ = sqlx::query("UPDATE rules SET schedule_id = NULL WHERE schedule_id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await;
    Ok(Json(MessageResponse {
        message: format!("Schedule {id} deleted"),
    }))
}
