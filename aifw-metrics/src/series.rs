use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ring::RingBuffer;

/// A single metric data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: DateTime<Utc>,
    pub value: f64,
    pub min: f64,
    pub max: f64,
    pub count: u64,
}

impl MetricPoint {
    pub fn new(value: f64) -> Self {
        Self {
            timestamp: Utc::now(),
            value,
            min: value,
            max: value,
            count: 1,
        }
    }

    pub fn with_timestamp(mut self, ts: DateTime<Utc>) -> Self {
        self.timestamp = ts;
        self
    }
}

/// Aggregation method for consolidating points
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Aggregation {
    Average,
    Sum,
    Min,
    Max,
    Last,
}

/// Aggregate a slice of MetricPoints into a single consolidated point
pub fn aggregate(points: &[MetricPoint], method: Aggregation) -> Option<MetricPoint> {
    if points.is_empty() {
        return None;
    }

    let total_count: u64 = points.iter().map(|p| p.count).sum();
    let min = points.iter().map(|p| p.min).fold(f64::INFINITY, f64::min);
    let max = points.iter().map(|p| p.max).fold(f64::NEG_INFINITY, f64::max);
    let ts = points.last().unwrap().timestamp;

    let value = match method {
        Aggregation::Average => {
            let sum: f64 = points.iter().map(|p| p.value * p.count as f64).sum();
            sum / total_count as f64
        }
        Aggregation::Sum => points.iter().map(|p| p.value).sum(),
        Aggregation::Min => min,
        Aggregation::Max => max,
        Aggregation::Last => points.last().unwrap().value,
    };

    Some(MetricPoint {
        timestamp: ts,
        value,
        min,
        max,
        count: total_count,
    })
}

/// Resolution tier for the RRD
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// 1-second resolution, last 5 minutes (300 points)
    Realtime,
    /// 1-minute resolution, last 24 hours (1440 points)
    Minute,
    /// 1-hour resolution, last 30 days (720 points)
    Hour,
    /// 1-day resolution, last 1 year (365 points)
    Day,
}

impl Tier {
    pub fn capacity(&self) -> usize {
        match self {
            Tier::Realtime => 300,
            Tier::Minute => 1440,
            Tier::Hour => 720,
            Tier::Day => 365,
        }
    }

    pub fn interval_secs(&self) -> u64 {
        match self {
            Tier::Realtime => 1,
            Tier::Minute => 60,
            Tier::Hour => 3600,
            Tier::Day => 86400,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tier::Realtime => "realtime",
            Tier::Minute => "minute",
            Tier::Hour => "hour",
            Tier::Day => "day",
        }
    }

    /// How many lower-tier points to consolidate
    pub fn consolidation_ratio(&self) -> usize {
        match self {
            Tier::Realtime => 1,
            Tier::Minute => 60,  // 60 x 1s -> 1m
            Tier::Hour => 60,    // 60 x 1m -> 1h
            Tier::Day => 24,     // 24 x 1h -> 1d
        }
    }
}

/// A multi-resolution time series for a single metric
#[derive(Debug, Clone)]
pub struct MetricSeries {
    pub name: String,
    pub aggregation: Aggregation,
    pub realtime: RingBuffer<MetricPoint>,
    pub minute: RingBuffer<MetricPoint>,
    pub hour: RingBuffer<MetricPoint>,
    pub day: RingBuffer<MetricPoint>,
    /// Accumulator for consolidation from realtime -> minute
    minute_acc: Vec<MetricPoint>,
    /// Accumulator for consolidation from minute -> hour
    hour_acc: Vec<MetricPoint>,
    /// Accumulator for consolidation from hour -> day
    day_acc: Vec<MetricPoint>,
}

impl MetricSeries {
    pub fn new(name: &str, aggregation: Aggregation) -> Self {
        Self {
            name: name.to_string(),
            aggregation,
            realtime: RingBuffer::new(Tier::Realtime.capacity()),
            minute: RingBuffer::new(Tier::Minute.capacity()),
            hour: RingBuffer::new(Tier::Hour.capacity()),
            day: RingBuffer::new(Tier::Day.capacity()),
            minute_acc: Vec::new(),
            hour_acc: Vec::new(),
            day_acc: Vec::new(),
        }
    }

    /// Record a new value. Handles automatic consolidation into higher tiers.
    pub fn record(&mut self, value: f64) {
        let point = MetricPoint::new(value);
        self.realtime.push(point.clone());

        // Accumulate for minute consolidation
        self.minute_acc.push(point);
        if self.minute_acc.len() >= Tier::Minute.consolidation_ratio()
            && let Some(agg) = aggregate(&self.minute_acc, self.aggregation) {
                self.minute.push(agg.clone());
                self.minute_acc.clear();

                // Accumulate for hour consolidation
                self.hour_acc.push(agg);
                if self.hour_acc.len() >= Tier::Hour.consolidation_ratio()
                    && let Some(agg) = aggregate(&self.hour_acc, self.aggregation) {
                        self.hour.push(agg.clone());
                        self.hour_acc.clear();

                        // Accumulate for day consolidation
                        self.day_acc.push(agg);
                        if self.day_acc.len() >= Tier::Day.consolidation_ratio()
                            && let Some(agg) = aggregate(&self.day_acc, self.aggregation) {
                                self.day.push(agg);
                                self.day_acc.clear();
                            }
                    }
            }
    }

    /// Get data points for a given tier
    pub fn get_tier(&self, tier: Tier) -> Vec<&MetricPoint> {
        match tier {
            Tier::Realtime => self.realtime.values(),
            Tier::Minute => self.minute.values(),
            Tier::Hour => self.hour.values(),
            Tier::Day => self.day.values(),
        }
    }

    /// Get the last N points from a tier
    pub fn get_last(&self, tier: Tier, n: usize) -> Vec<&MetricPoint> {
        match tier {
            Tier::Realtime => self.realtime.last_n(n),
            Tier::Minute => self.minute.last_n(n),
            Tier::Hour => self.hour.last_n(n),
            Tier::Day => self.day.last_n(n),
        }
    }

    /// Get the latest value
    pub fn latest(&self) -> Option<f64> {
        self.realtime.latest().map(|p| p.value)
    }

    /// Auto-select the best tier for a time range in seconds
    pub fn best_tier_for_range(range_secs: u64) -> Tier {
        if range_secs <= 300 {
            Tier::Realtime
        } else if range_secs <= 86400 {
            Tier::Minute
        } else if range_secs <= 2_592_000 {
            Tier::Hour
        } else {
            Tier::Day
        }
    }
}
