#[cfg(test)]
mod tests {
    use crate::pflog::PfLogParser;
    use crate::query::{ConnectionFilter, ConnectionQuery};
    use crate::stats::ConntrackStats;
    use crate::tracker::ConnectionTracker;
    use aifw_pf::{PfBackend, PfMock, PfState};
    use chrono::Utc;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    fn make_states() -> Vec<PfState> {
        vec![
            PfState {
                id: 1,
                protocol: "tcp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 12345,
                dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_port: 80,
                state: "ESTABLISHED:ESTABLISHED".to_string(),
                packets_in: 100,
                packets_out: 50,
                bytes_in: 50000,
                bytes_out: 5000,
                age_secs: 120,
            },
            PfState {
                id: 2,
                protocol: "tcp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 12346,
                dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_port: 443,
                state: "ESTABLISHED:ESTABLISHED".to_string(),
                packets_in: 200,
                packets_out: 100,
                bytes_in: 100000,
                bytes_out: 10000,
                age_secs: 60,
            },
            PfState {
                id: 3,
                protocol: "udp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
                src_port: 54321,
                dst_addr: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                dst_port: 53,
                state: "SINGLE:NO_TRAFFIC".to_string(),
                packets_in: 1,
                packets_out: 1,
                bytes_in: 100,
                bytes_out: 50,
                age_secs: 5,
            },
            PfState {
                id: 4,
                protocol: "icmp".to_string(),
                src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
                src_port: 0,
                dst_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                dst_port: 0,
                state: "0:0".to_string(),
                packets_in: 1,
                packets_out: 1,
                bytes_in: 64,
                bytes_out: 64,
                age_secs: 7200,
            },
        ]
    }

    #[test]
    fn test_filter_by_protocol() {
        let states = make_states();
        let filter = ConnectionFilter {
            protocol: Some("tcp".to_string()),
            ..Default::default()
        };
        let result = ConnectionQuery::filter(&states, &filter);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_filter_by_dst_port() {
        let states = make_states();
        let filter = ConnectionFilter {
            dst_port: Some(443),
            ..Default::default()
        };
        let result = ConnectionQuery::filter(&states, &filter);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].dst_port, 443);
    }

    #[test]
    fn test_filter_by_src_addr() {
        let states = make_states();
        let filter = ConnectionFilter {
            src_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200))),
            ..Default::default()
        };
        let result = ConnectionQuery::filter(&states, &filter);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].protocol, "udp");
    }

    #[test]
    fn test_filter_by_age_range() {
        let states = make_states();
        let filter = ConnectionFilter {
            min_age_secs: Some(60),
            max_age_secs: Some(300),
            ..Default::default()
        };
        let result = ConnectionQuery::filter(&states, &filter);
        assert_eq!(result.len(), 2); // 120s and 60s
    }

    #[test]
    fn test_count() {
        let states = make_states();
        let filter = ConnectionFilter {
            protocol: Some("tcp".to_string()),
            ..Default::default()
        };
        assert_eq!(ConnectionQuery::count(&states, &filter), 2);
    }

    #[test]
    fn test_top_talkers() {
        let states = make_states();
        let talkers = ConnectionQuery::top_talkers(&states, 3);
        assert!(!talkers.is_empty());
        // 10.0.0.1 is top talker (receives bytes_in from 3 connections)
        assert_eq!(talkers[0].0, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn test_by_protocol() {
        let states = make_states();
        let by_proto = ConnectionQuery::connections_by_protocol(&states);
        assert_eq!(by_proto[0].0, "tcp");
        assert_eq!(by_proto[0].1, 2);
    }

    #[test]
    fn test_stats_from_states() {
        let states = make_states();
        let stats = ConntrackStats::from_states(&states);
        assert_eq!(stats.total_connections, 4);
        assert_eq!(stats.tcp_connections, 2);
        assert_eq!(stats.udp_connections, 1);
        assert_eq!(stats.icmp_connections, 1);
        assert_eq!(stats.total_bytes_in, 150164);
        assert_eq!(stats.max_age_secs, 7200);
    }

    #[test]
    fn test_stats_empty() {
        let stats = ConntrackStats::from_states(&[]);
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.avg_age_secs, 0);
    }

    #[tokio::test]
    async fn test_tracker_refresh_and_query() {
        let mock = Arc::new(PfMock::new());
        mock.inject_states(make_states()).await;
        let pf: Arc<dyn PfBackend> = mock.clone();

        let tracker = ConnectionTracker::new(pf);
        tracker.refresh().await.unwrap();

        assert_eq!(tracker.total_count().await, 4);

        let tcp_filter = ConnectionFilter {
            protocol: Some("tcp".to_string()),
            ..Default::default()
        };
        assert_eq!(tracker.count(&tcp_filter).await, 2);

        let conns = tracker.search(&tcp_filter).await;
        assert_eq!(conns.len(), 2);
    }

    #[tokio::test]
    async fn test_tracker_stats() {
        let mock = Arc::new(PfMock::new());
        mock.inject_states(make_states()).await;
        let pf: Arc<dyn PfBackend> = mock.clone();

        let tracker = ConnectionTracker::new(pf);
        tracker.refresh().await.unwrap();

        let stats = tracker.stats().await;
        assert_eq!(stats.total_connections, 4);
        assert_eq!(stats.tcp_connections, 2);
    }

    #[tokio::test]
    async fn test_tracker_expired_connections() {
        let mock = Arc::new(PfMock::new());
        mock.inject_states(make_states()).await;
        let pf: Arc<dyn PfBackend> = mock.clone();

        let tracker = ConnectionTracker::new(pf).with_expiry_threshold(3600);
        tracker.refresh().await.unwrap();

        let expired = tracker.expired_connections().await;
        assert_eq!(expired.len(), 1); // only the ICMP one at 7200s
        assert_eq!(expired[0].protocol, "icmp");
    }

    #[tokio::test]
    async fn test_tracker_top_talkers() {
        let mock = Arc::new(PfMock::new());
        mock.inject_states(make_states()).await;
        let pf: Arc<dyn PfBackend> = mock.clone();

        let tracker = ConnectionTracker::new(pf);
        tracker.refresh().await.unwrap();

        let talkers = tracker.top_talkers(2).await;
        assert_eq!(talkers.len(), 2);
    }

    #[test]
    fn test_pflog_parse_line() {
        let line = "rule 5/(match) block in on em0: 192.168.1.100.12345 > 10.0.0.1.80: tcp 60";
        let entry = PfLogParser::parse_line(line, Utc::now()).unwrap();
        assert_eq!(entry.rule_number, 5);
        assert_eq!(entry.action, crate::pflog::PfLogAction::Block);
        assert_eq!(entry.direction, crate::pflog::PfLogDirection::In);
        assert_eq!(entry.interface, "em0");
        assert_eq!(entry.src_addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert_eq!(entry.src_port, 12345);
        assert_eq!(entry.dst_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(entry.dst_port, 80);
        assert_eq!(entry.protocol, "tcp");
        assert_eq!(entry.length, 60);
    }

    #[test]
    fn test_pflog_parse_pass() {
        let line = "rule 10/(match) pass out on em0: 10.0.0.1.443 > 192.168.1.100.54321: tcp 1460";
        let entry = PfLogParser::parse_line(line, Utc::now()).unwrap();
        assert_eq!(entry.action, crate::pflog::PfLogAction::Pass);
        assert_eq!(entry.direction, crate::pflog::PfLogDirection::Out);
        assert_eq!(entry.dst_port, 54321);
    }

    #[test]
    fn test_pflog_parse_empty() {
        assert!(PfLogParser::parse_line("", Utc::now()).is_none());
    }
}
