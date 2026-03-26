#[cfg(test)]
mod tests {
    use crate::backend::PfBackend;
    use crate::mock::PfMock;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_mock_add_get_rules() {
        let mock = PfMock::new();
        mock.add_rule("aifw", "block in quick proto tcp to any port 22")
            .await
            .unwrap();
        mock.add_rule("aifw", "pass in quick proto tcp to any port 443")
            .await
            .unwrap();

        let rules = mock.get_rules("aifw").await.unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].contains("port 22"));
        assert!(rules[1].contains("port 443"));
    }

    #[tokio::test]
    async fn test_mock_flush_rules() {
        let mock = PfMock::new();
        mock.add_rule("aifw", "block in quick").await.unwrap();
        mock.flush_rules("aifw").await.unwrap();
        let rules = mock.get_rules("aifw").await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_mock_load_rules() {
        let mock = PfMock::new();
        mock.add_rule("aifw", "old rule").await.unwrap();
        mock.load_rules(
            "aifw",
            &[
                "pass in quick proto tcp to any port 80".to_string(),
                "block in quick".to_string(),
            ],
        )
        .await
        .unwrap();

        let rules = mock.get_rules("aifw").await.unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].contains("port 80"));
    }

    #[tokio::test]
    async fn test_mock_table_operations() {
        let mock = PfMock::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let ip2 = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));

        mock.add_table_entry("blocklist", ip1).await.unwrap();
        mock.add_table_entry("blocklist", ip2).await.unwrap();
        // duplicate should be ignored
        mock.add_table_entry("blocklist", ip1).await.unwrap();

        let entries = mock.get_table_entries("blocklist").await.unwrap();
        assert_eq!(entries.len(), 2);

        mock.remove_table_entry("blocklist", ip1).await.unwrap();
        let entries = mock.get_table_entries("blocklist").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].addr, ip2);

        mock.flush_table("blocklist").await.unwrap();
        let entries = mock.get_table_entries("blocklist").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_mock_stats() {
        let mock = PfMock::new();
        mock.add_rule("aifw", "rule1").await.unwrap();
        mock.add_rule("aifw", "rule2").await.unwrap();
        mock.add_rule("other", "rule3").await.unwrap();

        let stats = mock.get_stats().await.unwrap();
        assert_eq!(stats.rules_count, 3);
        assert!(stats.running);
    }

    #[tokio::test]
    async fn test_mock_is_running() {
        let mock = PfMock::new();
        assert!(mock.is_running().await.unwrap());
        mock.set_running(false).await;
        assert!(!mock.is_running().await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_separate_anchors() {
        let mock = PfMock::new();
        mock.add_rule("aifw", "rule1").await.unwrap();
        mock.add_rule("other", "rule2").await.unwrap();

        assert_eq!(mock.get_rules("aifw").await.unwrap().len(), 1);
        assert_eq!(mock.get_rules("other").await.unwrap().len(), 1);
        assert_eq!(mock.get_rules("nonexistent").await.unwrap().len(), 0);
    }
}
