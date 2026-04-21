//! Time-series query endpoints backed by the in-memory RRD in `aifw-metrics`.
//!
//! `/api/v1/metrics/list`            — registered series names
//! `/api/v1/metrics/series?name=…&range_secs=…`  — points for the best tier covering that range

use aifw_metrics::{
    backend::MetricsBackend,
    series::{MetricPoint, MetricSeries},
};
use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct SeriesListResponse {
    pub names: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SeriesQuery {
    pub name: String,
    /// How far back to read, in seconds. Determines which tier is used.
    pub range_secs: Option<u64>,
    /// Cap the returned points (defaults to whatever the tier holds for the range).
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct SeriesPoint {
    pub t: i64, // unix epoch seconds
    pub v: f64, // aggregated value (the series' configured aggregation)
    pub min: f64,
    pub max: f64,
}

#[derive(Debug, Serialize)]
pub struct SeriesResponse {
    pub name: String,
    pub tier: String,
    pub interval_secs: u64,
    pub points: Vec<SeriesPoint>,
}

pub async fn list(State(state): State<AppState>) -> Result<Json<SeriesListResponse>, StatusCode> {
    let mut names = state
        .metrics_store
        .list_metrics()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    names.sort();
    Ok(Json(SeriesListResponse { names }))
}

pub async fn query(
    State(state): State<AppState>,
    Query(q): Query<SeriesQuery>,
) -> Result<Json<SeriesResponse>, StatusCode> {
    let range = q.range_secs.unwrap_or(1_800); // default: last 30 min
    let tier = MetricSeries::best_tier_for_range(range);
    let interval = tier.interval_secs();

    // How many points from this tier cover the requested range?
    // Fall back to whatever the tier currently holds if the range exceeds the tier's window.
    let points_needed = ((range + interval - 1) / interval) as usize;
    let effective_limit = q
        .limit
        .map(|l| l.min(points_needed))
        .unwrap_or(points_needed);

    let res = state
        .metrics_store
        .query(&q.name, tier, Some(effective_limit))
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    let points: Vec<SeriesPoint> = res
        .points
        .into_iter()
        .map(|p: MetricPoint| SeriesPoint {
            t: p.timestamp.timestamp(),
            v: p.value,
            min: p.min,
            max: p.max,
        })
        .collect();

    Ok(Json(SeriesResponse {
        name: q.name,
        tier: tier.label().to_string(),
        interval_secs: interval,
        points,
    }))
}
