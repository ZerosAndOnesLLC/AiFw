use super::*;

// --- Geo-IP engine tests ---

async fn create_geoip_engine() -> crate::geoip::GeoIpEngine {
    let db = Database::new_in_memory().await.unwrap();
    let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let engine = crate::geoip::GeoIpEngine::new(db.pool().clone(), pf);
    engine.migrate().await.unwrap();
    engine
}

#[tokio::test]
async fn test_geoip_rule_crud() {
    let engine = create_geoip_engine().await;

    let rule = GeoIpRule::new(CountryCode::new("CN").unwrap(), GeoIpAction::Block);
    let id = rule.id;
    engine.add_rule(rule).await.unwrap();

    let rules = engine.list_rules().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].country.0, "CN");
    assert_eq!(rules[0].action, GeoIpAction::Block);

    engine.delete_rule(id).await.unwrap();
    assert!(engine.list_rules().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_geoip_db_load_and_lookup() {
    let engine = create_geoip_engine().await;

    let blocks = "network,geoname_id,registered_country_geoname_id\n\
                   1.0.0.0/24,2077456,2077456\n\
                   1.0.1.0/24,1814991,1814991\n\
                   5.0.0.0/8,1814991,1814991\n";
    let locations = "geoname_id,locale_code,continent_code,continent_name,country_iso_code\n\
                     2077456,en,OC,Oceania,AU\n\
                     1814991,en,AS,Asia,CN\n";

    let count = engine.load_database(blocks, locations).await.unwrap();
    assert!(count > 0);

    let (countries, _) = engine.db_stats().await;
    assert_eq!(countries, 2); // AU and CN

    // Lookup AU IP
    let result = engine.lookup("1.0.0.1".parse().unwrap()).await;
    assert_eq!(result.country.unwrap().0, "AU");

    // Lookup CN IP
    let result = engine.lookup("1.0.1.100".parse().unwrap()).await;
    assert_eq!(result.country.unwrap().0, "CN");

    // Lookup unknown
    let result = engine.lookup("192.168.1.1".parse().unwrap()).await;
    assert!(result.country.is_none());
}

#[tokio::test]
async fn test_geoip_country_cidrs() {
    let engine = create_geoip_engine().await;

    let blocks = "network,geoname_id,x\n1.0.0.0/24,100,100\n1.0.1.0/24,100,100\n";
    let locations = "geoname_id,x,x,x,country_iso_code\n100,en,AS,Asia,JP\n";

    engine.load_database(blocks, locations).await.unwrap();

    let cidrs = engine.get_country_cidrs("JP").await;
    assert!(!cidrs.is_empty());

    let cidrs_unknown = engine.get_country_cidrs("ZZ").await;
    assert!(cidrs_unknown.is_empty());
}

#[tokio::test]
async fn test_geoip_apply_rules() {
    let db = Database::new_in_memory().await.unwrap();
    let mock = Arc::new(aifw_pf::PfMock::new());
    let pf: Arc<dyn PfBackend> = mock.clone();
    let engine = crate::geoip::GeoIpEngine::new(db.pool().clone(), pf);
    engine.migrate().await.unwrap();

    engine
        .add_rule(GeoIpRule::new(
            CountryCode::new("RU").unwrap(),
            GeoIpAction::Block,
        ))
        .await
        .unwrap();

    engine
        .add_rule(GeoIpRule::new(
            CountryCode::new("US").unwrap(),
            GeoIpAction::Allow,
        ))
        .await
        .unwrap();

    engine.apply_rules().await.unwrap();

    let pf_rules = mock.get_rules("aifw-geoip").await.unwrap();
    assert_eq!(pf_rules.len(), 4); // 2 tables + 2 rules
    assert!(pf_rules.iter().any(|r| r.contains("geoip_ru")));
    assert!(pf_rules.iter().any(|r| r.contains("geoip_us")));
    assert!(pf_rules.iter().any(|r| r.contains("block drop")));
    assert!(pf_rules.iter().any(|r| r.contains("pass")));
}
