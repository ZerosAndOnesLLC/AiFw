#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::backend::MetricsBackend;
    use crate::ring::RingBuffer;
    use crate::series::*;
    use crate::store::MetricsStore;
    use crate::collector::MetricsCollector;

    // --- RingBuffer tests ---

    #[test]
    fn test_ring_buffer_basic() {
        let mut rb = RingBuffer::new(5);
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);

        rb.push(1);
        rb.push(2);
        rb.push(3);
        assert_eq!(rb.len(), 3);

        let vals: Vec<&i32> = rb.values();
        assert_eq!(vals, vec![&1, &2, &3]);
    }

    #[test]
    fn test_ring_buffer_wrap() {
        let mut rb = RingBuffer::new(3);
        rb.push(1);
        rb.push(2);
        rb.push(3);
        rb.push(4); // overwrites 1
        rb.push(5); // overwrites 2

        assert_eq!(rb.len(), 3);
        let vals: Vec<&i32> = rb.values();
        assert_eq!(vals, vec![&3, &4, &5]);
    }

    #[test]
    fn test_ring_buffer_latest() {
        let mut rb = RingBuffer::new(5);
        rb.push(10);
        rb.push(20);
        rb.push(30);
        assert_eq!(rb.latest(), Some(&30));
    }

    #[test]
    fn test_ring_buffer_last_n() {
        let mut rb = RingBuffer::new(10);
        for i in 0..10 {
            rb.push(i);
        }
        let last3: Vec<&i32> = rb.last_n(3);
        assert_eq!(last3, vec![&7, &8, &9]);
    }

    #[test]
    fn test_ring_buffer_empty_latest() {
        let rb: RingBuffer<i32> = RingBuffer::new(5);
        assert_eq!(rb.latest(), None);
    }

    #[test]
    fn test_ring_buffer_clear() {
        let mut rb = RingBuffer::new(5);
        rb.push(1);
        rb.push(2);
        rb.clear();
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);
    }

    // --- MetricPoint / Aggregation tests ---

    #[test]
    fn test_metric_point() {
        let p = MetricPoint::new(42.0);
        assert_eq!(p.value, 42.0);
        assert_eq!(p.min, 42.0);
        assert_eq!(p.max, 42.0);
        assert_eq!(p.count, 1);
    }

    #[test]
    fn test_aggregate_average() {
        let points = vec![
            MetricPoint::new(10.0),
            MetricPoint::new(20.0),
            MetricPoint::new(30.0),
        ];
        let agg = aggregate(&points, Aggregation::Average).unwrap();
        assert!((agg.value - 20.0).abs() < 0.01);
        assert_eq!(agg.min, 10.0);
        assert_eq!(agg.max, 30.0);
        assert_eq!(agg.count, 3);
    }

    #[test]
    fn test_aggregate_sum() {
        let points = vec![MetricPoint::new(5.0), MetricPoint::new(15.0)];
        let agg = aggregate(&points, Aggregation::Sum).unwrap();
        assert_eq!(agg.value, 20.0);
    }

    #[test]
    fn test_aggregate_min_max() {
        let points = vec![
            MetricPoint::new(5.0),
            MetricPoint::new(100.0),
            MetricPoint::new(1.0),
        ];
        assert_eq!(aggregate(&points, Aggregation::Min).unwrap().value, 1.0);
        assert_eq!(aggregate(&points, Aggregation::Max).unwrap().value, 100.0);
    }

    #[test]
    fn test_aggregate_last() {
        let points = vec![MetricPoint::new(1.0), MetricPoint::new(2.0), MetricPoint::new(3.0)];
        assert_eq!(aggregate(&points, Aggregation::Last).unwrap().value, 3.0);
    }

    #[test]
    fn test_aggregate_empty() {
        assert!(aggregate(&[], Aggregation::Average).is_none());
    }

    // --- MetricSeries tests ---

    #[test]
    fn test_series_record_and_latest() {
        let mut series = MetricSeries::new("test", Aggregation::Average);
        series.record(42.0);
        assert_eq!(series.latest(), Some(42.0));
        assert_eq!(series.realtime.len(), 1);
    }

    #[test]
    fn test_series_consolidation_to_minute() {
        let mut series = MetricSeries::new("test", Aggregation::Average);

        // Record 60 points -> should trigger 1 minute consolidation
        for i in 0..60 {
            series.record(i as f64);
        }

        assert_eq!(series.realtime.len(), 60);
        assert_eq!(series.minute.len(), 1);

        let min_point = series.minute.latest().unwrap();
        // Average of 0..59 = 29.5
        assert!((min_point.value - 29.5).abs() < 0.01);
        assert_eq!(min_point.min, 0.0);
        assert_eq!(min_point.max, 59.0);
    }

    #[test]
    fn test_series_multiple_minute_consolidations() {
        let mut series = MetricSeries::new("test", Aggregation::Sum);

        // Record 180 points -> 3 minute consolidations
        for _ in 0..180 {
            series.record(1.0);
        }

        assert_eq!(series.minute.len(), 3);
    }

    #[test]
    fn test_series_tier_selection() {
        assert_eq!(MetricSeries::best_tier_for_range(60), Tier::Realtime);
        assert_eq!(MetricSeries::best_tier_for_range(300), Tier::Realtime);
        assert_eq!(MetricSeries::best_tier_for_range(3600), Tier::Minute);
        assert_eq!(MetricSeries::best_tier_for_range(86400), Tier::Minute);
        assert_eq!(MetricSeries::best_tier_for_range(604800), Tier::Hour);
        assert_eq!(MetricSeries::best_tier_for_range(31536000), Tier::Day);
    }

    #[test]
    fn test_tier_properties() {
        assert_eq!(Tier::Realtime.capacity(), 300);
        assert_eq!(Tier::Minute.capacity(), 1440);
        assert_eq!(Tier::Hour.capacity(), 720);
        assert_eq!(Tier::Day.capacity(), 365);
        assert_eq!(Tier::Realtime.interval_secs(), 1);
        assert_eq!(Tier::Day.interval_secs(), 86400);
    }

    // --- MetricsStore tests ---

    #[tokio::test]
    async fn test_store_record_and_query() {
        let store = MetricsStore::new();
        store.record("cpu", 50.0).await.unwrap();
        store.record("cpu", 60.0).await.unwrap();

        let result = store.query("cpu", Tier::Realtime, None).await.unwrap();
        assert_eq!(result.points.len(), 2);
        assert_eq!(result.name, "cpu");
    }

    #[tokio::test]
    async fn test_store_latest() {
        let store = MetricsStore::new();
        store.record("mem", 1024.0).await.unwrap();
        store.record("mem", 2048.0).await.unwrap();

        let latest = store.latest("mem").await.unwrap();
        assert_eq!(latest, Some(2048.0));
    }

    #[tokio::test]
    async fn test_store_list_metrics() {
        let store = MetricsStore::new();
        store.record("a", 1.0).await.unwrap();
        store.record("b", 2.0).await.unwrap();
        store.record("c", 3.0).await.unwrap();

        let mut names = store.list_metrics().await.unwrap();
        names.sort();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[tokio::test]
    async fn test_store_summary() {
        let store = MetricsStore::new();
        store.record("x", 10.0).await.unwrap();
        store.record("y", 20.0).await.unwrap();

        let summary = store.summary().await.unwrap();
        assert_eq!(summary.len(), 2);
    }

    #[tokio::test]
    async fn test_store_query_last_n() {
        let store = MetricsStore::new();
        for i in 0..100 {
            store.record("seq", i as f64).await.unwrap();
        }

        let result = store.query("seq", Tier::Realtime, Some(5)).await.unwrap();
        assert_eq!(result.points.len(), 5);
        assert_eq!(result.points.last().unwrap().value, 99.0);
    }

    #[tokio::test]
    async fn test_store_register_aggregation() {
        let store = MetricsStore::new();
        store.register("counter", Aggregation::Sum).await;
        store.register("gauge", Aggregation::Last).await;

        store.record("counter", 1.0).await.unwrap();
        store.record("gauge", 42.0).await.unwrap();

        assert_eq!(store.latest("counter").await.unwrap(), Some(1.0));
        assert_eq!(store.latest("gauge").await.unwrap(), Some(42.0));
    }

    #[tokio::test]
    async fn test_store_missing_metric() {
        let store = MetricsStore::new();
        let result = store.query("nonexistent", Tier::Realtime, None).await;
        assert!(result.is_err());
    }

    // --- Collector tests ---

    #[tokio::test]
    async fn test_collector_collects_pf_metrics() {
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn aifw_pf::PfBackend> = mock.clone();
        let store = Arc::new(MetricsStore::new());

        let mut collector = MetricsCollector::new(pf, store.clone());
        collector.register_metrics().await;
        collector.collect_once().await;

        // Should have recorded pf metrics
        let states = store.latest("pf.states").await.unwrap();
        assert!(states.is_some());

        let running = store.latest("pf.running").await.unwrap();
        assert_eq!(running, Some(1.0)); // mock is running
    }

    #[tokio::test]
    async fn test_collector_computes_rates() {
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn aifw_pf::PfBackend> = mock.clone();
        let store = Arc::new(MetricsStore::new());

        let mut collector = MetricsCollector::new(pf, store.clone());
        collector.register_metrics().await;

        // First collection (baseline)
        collector.collect_once().await;
        // Second collection (rate = delta / interval)
        collector.collect_once().await;

        let bps_in = store.latest("traffic.bps_in").await.unwrap();
        assert!(bps_in.is_some()); // rate was computed
    }
}
