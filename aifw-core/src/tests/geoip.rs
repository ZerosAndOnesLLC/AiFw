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
    engine.add(rule).await.unwrap();

    let rules = engine.list().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].country.0, "CN");
    assert_eq!(rules[0].action, GeoIpAction::Block);

    engine.delete(id).await.unwrap();
    assert!(engine.list().await.unwrap().is_empty());
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
        .add(GeoIpRule::new(
            CountryCode::new("RU").unwrap(),
            GeoIpAction::Block,
        ))
        .await
        .unwrap();

    engine
        .add(GeoIpRule::new(
            CountryCode::new("US").unwrap(),
            GeoIpAction::Allow,
        ))
        .await
        .unwrap();

    engine.apply_rules().await.unwrap();

    let pf_rules = mock.get_rules("aifw-geoip").await.unwrap();
    assert_eq!(
        pf_rules.len(),
        2,
        "rules only — no table lines in the anchor (#704)"
    );
    assert!(pf_rules.iter().all(|r| !r.starts_with("table")));
    assert!(pf_rules.iter().any(|r| r.contains("geoip_ru")));
    assert!(pf_rules.iter().any(|r| r.contains("geoip_us")));
    assert!(pf_rules.iter().any(|r| r.contains("block drop")));
    assert!(pf_rules.iter().any(|r| r.contains("pass")));
}

const BLOCKS_V4: &str = "network,geoname_id,registered_country_geoname_id\n\
                         1.0.0.0/24,2077456,2077456\n\
                         1.0.2.0/24,1814991,1814991\n\
                         1.0.3.0/24,1814991,1814991\n";
const BLOCKS_V6: &str = "network,geoname_id,registered_country_geoname_id\n\
                         2001:db8::/32,1814991,1814991\n";
const LOCATIONS: &str = "geoname_id,locale_code,continent_code,continent_name,country_iso_code\n\
                         2077456,en,OC,Oceania,AU\n\
                         1814991,en,AS,Asia,CN\n";

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn engine_with_scratch_dir() -> (crate::geoip::GeoIpEngine, Arc<aifw_pf::PfMock>, Scratch) {
    let db = Database::new_in_memory().await.unwrap();
    let mock = Arc::new(aifw_pf::PfMock::new());
    let pf: Arc<dyn PfBackend> = mock.clone();
    let engine = crate::geoip::GeoIpEngine::new(db.pool().clone(), pf);
    engine.migrate().await.unwrap();
    let dir = std::env::temp_dir().join(format!("aifw-geoip-{}", uuid::Uuid::new_v4()));
    engine.set_db_dir(&dir).await.unwrap();
    (engine, mock, Scratch(dir))
}

fn zip_of(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts: zip::write::SimpleFileOptions = Default::default();
    for (name, body) in files {
        w.start_file(format!("GeoLite2-Country-CSV_20261001/{name}"), opts)
            .unwrap();
        w.write_all(body.as_bytes()).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[tokio::test]
async fn import_archive_installs_files_and_fills_root_tables() {
    let (engine, mock, scratch) = engine_with_scratch_dir().await;
    assert!(
        engine.load_from_dir().await.unwrap().is_none(),
        "fresh install"
    );
    let st = engine.status().await.unwrap();
    assert!(!st.loaded && !st.has_license_key && st.next_refresh.is_none());

    let zip = zip_of(&[
        ("GeoLite2-Country-Blocks-IPv4.csv", BLOCKS_V4),
        ("GeoLite2-Country-Blocks-IPv6.csv", BLOCKS_V6),
        ("GeoLite2-Country-Locations-en.csv", LOCATIONS),
        ("COPYRIGHT.txt", "ignored"),
    ]);
    let n = engine.import_archive(zip, "upload").await.unwrap();
    assert_eq!(n, 3, "AU /24, CN aligned pair of /24 → one /23, CN v6 /32");
    assert!(scratch.0.join("GeoLite2-Country-Blocks-IPv6.csv").exists());
    assert!(!scratch.0.join("COPYRIGHT.txt").exists());

    // A fresh engine over the same directory restores the index from disk.
    let db = Database::new_in_memory().await.unwrap();
    let again = crate::geoip::GeoIpEngine::new(db.pool().clone(), mock.clone());
    again.migrate().await.unwrap();
    again.set_db_dir(&scratch.0).await.unwrap();
    assert_eq!(again.load_from_dir().await.unwrap(), Some(3));

    engine
        .add(GeoIpRule::new(
            CountryCode::new("CN").unwrap(),
            GeoIpAction::Block,
        ))
        .await
        .unwrap();
    engine.apply_rules().await.unwrap();
    let views = engine.list_views().await.unwrap();
    assert_eq!(views[0].cidr_count, 2);
    assert_eq!(views[0].table, "geoip_cn");
    assert_eq!(mock.get_table_entries("geoip_cn").await.unwrap().len(), 2);
    assert_eq!(mock.get_rules("aifw-geoip").await.unwrap().len(), 1);
    let st = engine.status().await.unwrap();
    assert!(st.loaded);
    assert_eq!(st.source.as_deref(), Some("upload"));
    assert_eq!((st.countries, st.cidrs), (2, 3));

    // Deleting the only rule for a country empties its table and the anchor.
    let id = views[0].rule.id;
    engine.delete(id).await.unwrap();
    engine.apply_rules().await.unwrap();
    assert!(mock.get_table_entries("geoip_cn").await.unwrap().is_empty());
    assert!(mock.get_rules("aifw-geoip").await.unwrap().is_empty());
}

#[tokio::test]
async fn import_rejects_bad_releases_and_keeps_the_old_one() {
    let (engine, _mock, _scratch) = engine_with_scratch_dir().await;
    let mut files = std::collections::HashMap::new();
    files.insert(
        "GeoLite2-Country-Blocks-IPv4.csv".to_string(),
        BLOCKS_V4.to_string(),
    );
    files.insert(
        "GeoLite2-Country-Locations-en.csv".to_string(),
        LOCATIONS.to_string(),
    );
    assert_eq!(
        engine
            .import_csv_files(files.clone(), "upload")
            .await
            .unwrap(),
        2
    );

    // Missing locations file.
    let mut no_loc = files.clone();
    no_loc.remove("GeoLite2-Country-Locations-en.csv");
    assert!(engine.import_csv_files(no_loc, "upload").await.is_err());
    // Unexpected file name.
    let mut extra = files.clone();
    extra.insert("evil.sh".into(), "x".into());
    assert!(engine.import_csv_files(extra, "upload").await.is_err());
    // Parses to nothing (City release, wrong columns).
    let mut empty = files.clone();
    empty.insert(
        "GeoLite2-Country-Blocks-IPv4.csv".into(),
        "network,geoname_id\n".into(),
    );
    assert!(engine.import_csv_files(empty, "upload").await.is_err());
    assert!(
        engine
            .import_archive(b"not a zip".to_vec(), "upload")
            .await
            .is_err()
    );

    // The working index is untouched.
    assert_eq!(engine.db_stats().await, (2, 2));
}

#[tokio::test]
async fn license_key_is_sealed_and_drives_the_schedule() {
    let (engine, _mock, _scratch) = engine_with_scratch_dir().await;
    assert!(engine.set_license_key(Some("bad key!")).await.is_err());
    engine
        .set_license_key(Some("AbCdEf0123456789_x"))
        .await
        .unwrap();
    assert_eq!(
        engine.license_key().await.unwrap().as_deref(),
        Some("AbCdEf0123456789_x")
    );
    let raw: String =
        sqlx::query_scalar("SELECT value FROM geoip_config WHERE key = 'license_key'")
            .fetch_one(engine_pool(&engine))
            .await
            .unwrap();
    assert!(crate::secrets::is_sealed(&raw));

    // Never downloaded: due now. Disabled interval: never.
    assert!(engine.refresh_due().await.unwrap());
    engine.set_update_interval_hours(0).await.unwrap();
    assert!(!engine.refresh_due().await.unwrap());
    assert!(engine.set_update_interval_hours(100_000).await.is_err());
    engine.set_update_interval_hours(168).await.unwrap();

    // A failed attempt backs off instead of retrying every tick.
    engine.record_refresh(Err("HTTP 401".into())).await.unwrap();
    assert!(!engine.refresh_due().await.unwrap());
    let st = engine.status().await.unwrap();
    assert_eq!(st.last_error.as_deref(), Some("HTTP 401"));
    assert!(st.has_license_key);
    assert!(st.next_refresh.is_some());

    engine.set_license_key(None).await.unwrap();
    assert!(engine.license_key().await.unwrap().is_none());
    assert!(engine.status().await.unwrap().next_refresh.is_none());

    // Account ID: numeric only, shown in status, clearable.
    assert!(engine.set_account_id(Some("abc")).await.is_err());
    engine.set_account_id(Some(" 123456 ")).await.unwrap();
    assert_eq!(
        engine.account_id().await.unwrap().as_deref(),
        Some("123456")
    );
    assert_eq!(
        engine.status().await.unwrap().account_id.as_deref(),
        Some("123456")
    );
    engine.set_account_id(None).await.unwrap();
    assert!(engine.account_id().await.unwrap().is_none());
}

fn engine_pool(engine: &crate::geoip::GeoIpEngine) -> &sqlx::SqlitePool {
    engine.pool()
}
