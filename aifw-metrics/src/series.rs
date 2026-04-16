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

/// Resolution tier for the RRD. Intervals × capacities give the retention
/// window for each tier:
///   Live  1 s   × 1 800   = 30 min
///   Short 10 s  × 2 160   = 6 hours
///   Mid   60 s  × 10 080  = 7 days
///   Long  300 s × 8 640   = 30 days
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Live,
    Short,
    Mid,
    Long,
}

impl Tier {
    pub fn capacity(&self) -> usize {
        match self {
            Tier::Live => 1800,    // 30 min at 1 s
            Tier::Short => 2160,   // 6 hours at 10 s
            Tier::Mid => 10080,    // 7 days at 60 s
            Tier::Long => 8640,    // 30 days at 300 s
        }
    }

    pub fn interval_secs(&self) -> u64 {
        match self {
            Tier::Live => 1,
            Tier::Short => 10,
            Tier::Mid => 60,
            Tier::Long => 300,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Tier::Live => "live",
            Tier::Short => "short",
            Tier::Mid => "mid",
            Tier::Long => "long",
        }
    }

    /// How many points of the preceding tier fold into one of this tier.
    pub fn consolidation_ratio(&self) -> usize {
        match self {
            Tier::Live => 1,
            Tier::Short => 10, // 10 × 1 s  -> 1 × 10 s
            Tier::Mid => 6,    // 6 × 10 s  -> 1 × 60 s
            Tier::Long => 5,   // 5 × 60 s  -> 1 × 300 s
        }
    }
}

/// A multi-resolution time series for a single metric
#[derive(Debug, Clone)]
pub struct MetricSeries {
    pub name: String,
    pub aggregation: Aggregation,
    pub live: RingBuffer<MetricPoint>,
    pub short: RingBuffer<MetricPoint>,
    pub mid: RingBuffer<MetricPoint>,
    pub long: RingBuffer<MetricPoint>,
    short_acc: Vec<MetricPoint>,
    mid_acc: Vec<MetricPoint>,
    long_acc: Vec<MetricPoint>,
}

impl MetricSeries {
    pub fn new(name: &str, aggregation: Aggregation) -> Self {
        Self {
            name: name.to_string(),
            aggregation,
            live: RingBuffer::new(Tier::Live.capacity()),
            short: RingBuffer::new(Tier::Short.capacity()),
            mid: RingBuffer::new(Tier::Mid.capacity()),
            long: RingBuffer::new(Tier::Long.capacity()),
            short_acc: Vec::new(),
            mid_acc: Vec::new(),
            long_acc: Vec::new(),
        }
    }

    /// Record a new value. Handles automatic consolidation into higher tiers.
    pub fn record(&mut self, value: f64) {
        let point = MetricPoint::new(value);
        self.live.push(point.clone());

        self.short_acc.push(point);
        if self.short_acc.len() >= Tier::Short.consolidation_ratio()
            && let Some(agg) = aggregate(&self.short_acc, self.aggregation) {
                self.short.push(agg.clone());
                self.short_acc.clear();

                self.mid_acc.push(agg);
                if self.mid_acc.len() >= Tier::Mid.consolidation_ratio()
                    && let Some(agg) = aggregate(&self.mid_acc, self.aggregation) {
                        self.mid.push(agg.clone());
                        self.mid_acc.clear();

                        self.long_acc.push(agg);
                        if self.long_acc.len() >= Tier::Long.consolidation_ratio()
                            && let Some(agg) = aggregate(&self.long_acc, self.aggregation) {
                                self.long.push(agg);
                                self.long_acc.clear();
                            }
                    }
            }
    }

    /// Get data points for a given tier
    pub fn get_tier(&self, tier: Tier) -> Vec<&MetricPoint> {
        match tier {
            Tier::Live => self.live.values(),
            Tier::Short => self.short.values(),
            Tier::Mid => self.mid.values(),
            Tier::Long => self.long.values(),
        }
    }

    /// Get the last N points from a tier
    pub fn get_last(&self, tier: Tier, n: usize) -> Vec<&MetricPoint> {
        match tier {
            Tier::Live => self.live.last_n(n),
            Tier::Short => self.short.last_n(n),
            Tier::Mid => self.mid.last_n(n),
            Tier::Long => self.long.last_n(n),
        }
    }

    /// Get the latest value
    pub fn latest(&self) -> Option<f64> {
        self.live.latest().map(|p| p.value)
    }

    /// Pick the tier whose window covers the requested range with the finest
    /// resolution available. Queries for ranges longer than the Long tier's
    /// retention (30 days) still fall through to Long.
    pub fn best_tier_for_range(range_secs: u64) -> Tier {
        if range_secs <= 1_800 {
            Tier::Live
        } else if range_secs <= 21_600 {
            Tier::Short
        } else if range_secs <= 604_800 {
            Tier::Mid
        } else {
            Tier::Long
        }
    }
}
