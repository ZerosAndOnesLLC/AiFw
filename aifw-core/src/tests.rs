#[cfg(test)]
mod tests {
    use aifw_common::*;
    use aifw_pf::PfBackend;
    use std::sync::Arc;

    use crate::db::Database;
    use crate::engine::RuleEngine;
    use crate::validation::validate_rule;

    fn make_test_rule() -> Rule {
        Rule::new(
            Action::Block,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange {
                    start: 22,
                    end: 22,
                }),
            },
        )
    }

    #[test]
    fn test_validate_valid_rule() {
        let rule = make_test_rule();
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_invalid_port_range() {
        let mut rule = make_test_rule();
        rule.rule_match.dst_port = Some(PortRange {
            start: 9000,
            end: 80,
        });
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_port_requires_tcp_udp() {
        let mut rule = make_test_rule();
        rule.protocol = Protocol::Icmp;
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_priority_bounds() {
        let mut rule = make_test_rule();
        rule.priority = -1;
        assert!(validate_rule(&rule).is_err());

        rule.priority = 10001;
        assert!(validate_rule(&rule).is_err());

        rule.priority = 0;
        assert!(validate_rule(&rule).is_ok());

        rule.priority = 10000;
        assert!(validate_rule(&rule).is_ok());
    }

    #[test]
    fn test_validate_invalid_prefix() {
        let mut rule = make_test_rule();
        rule.rule_match.src_addr =
            Address::Network(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 0)), 33);
        assert!(validate_rule(&rule).is_err());
    }

    #[test]
    fn test_validate_empty_table_name() {
        let mut rule = make_test_rule();
        rule.rule_match.src_addr = Address::Table(String::new());
        assert!(validate_rule(&rule).is_err());
    }

    #[tokio::test]
    async fn test_engine_add_list_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db, pf);

        let rule = make_test_rule();
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();

        let rules = engine.list_rules().await.unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, id);
    }

    #[tokio::test]
    async fn test_engine_delete_rule() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db, pf);

        let rule = make_test_rule();
        let id = rule.id;
        engine.add_rule(rule).await.unwrap();
        engine.delete_rule(id).await.unwrap();

        let rules = engine.list_rules().await.unwrap();
        assert!(rules.is_empty());
    }

    #[tokio::test]
    async fn test_engine_delete_nonexistent() {
        let db = Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let engine = RuleEngine::new(db, pf);

        let result = engine.delete_rule(uuid::Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_engine_apply_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db, pf);

        engine.add_rule(make_test_rule()).await.unwrap();

        let mut rule2 = Rule::new(
            Action::Pass,
            Direction::In,
            Protocol::Tcp,
            RuleMatch {
                src_addr: Address::Any,
                src_port: None,
                dst_addr: Address::Any,
                dst_port: Some(PortRange {
                    start: 443,
                    end: 443,
                }),
            },
        );
        rule2.priority = 50;
        engine.add_rule(rule2).await.unwrap();

        engine.apply_rules().await.unwrap();

        let pf_rules = mock.get_rules("aifw").await.unwrap();
        assert_eq!(pf_rules.len(), 2);
        // Lower priority first
        assert!(pf_rules[0].contains("443"));
        assert!(pf_rules[1].contains("22"));
    }

    #[tokio::test]
    async fn test_engine_flush_rules() {
        let db = Database::new_in_memory().await.unwrap();
        let mock = Arc::new(aifw_pf::PfMock::new());
        let pf: Arc<dyn PfBackend> = mock.clone();
        let engine = RuleEngine::new(db, pf);

        engine.add_rule(make_test_rule()).await.unwrap();
        engine.apply_rules().await.unwrap();

        let before = mock.get_rules("aifw").await.unwrap();
        assert_eq!(before.len(), 1);

        engine.flush_rules().await.unwrap();
        let after = mock.get_rules("aifw").await.unwrap();
        assert!(after.is_empty());
    }

    #[tokio::test]
    async fn test_db_roundtrip() {
        let db = Database::new_in_memory().await.unwrap();

        let rule = make_test_rule();
        let id = rule.id;
        db.insert_rule(&rule).await.unwrap();

        let fetched = db.get_rule(id).await.unwrap().unwrap();
        assert_eq!(fetched.id, id);
        assert_eq!(fetched.action, Action::Block);
        assert_eq!(fetched.direction, Direction::In);
        assert_eq!(fetched.protocol, Protocol::Tcp);
        assert_eq!(fetched.rule_match.dst_port.as_ref().unwrap().start, 22);
    }

    #[tokio::test]
    async fn test_db_list_ordering() {
        let db = Database::new_in_memory().await.unwrap();

        let mut r1 = make_test_rule();
        r1.priority = 200;
        let mut r2 = make_test_rule();
        r2.priority = 50;
        let mut r3 = make_test_rule();
        r3.priority = 100;

        db.insert_rule(&r1).await.unwrap();
        db.insert_rule(&r2).await.unwrap();
        db.insert_rule(&r3).await.unwrap();

        let rules = db.list_rules().await.unwrap();
        assert_eq!(rules[0].priority, 50);
        assert_eq!(rules[1].priority, 100);
        assert_eq!(rules[2].priority, 200);
    }
}
