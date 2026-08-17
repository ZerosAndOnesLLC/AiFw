//! #298: master-key lifecycle. Runs as its own test binary (own process)
//! so the module's OnceLock starts fresh and the key path can be pointed at
//! a temp dir before first use.

use aifw_core::secrets;

#[test]
fn key_file_is_created_restricted_and_reused() {
    let dir = std::env::temp_dir().join(format!("aifw-secrets-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let key_path = dir.join("secrets.key");
    // configure_from_db_path derives <db dir>/secrets.key
    secrets::configure_from_db_path(&dir.join("aifw.db"));
    assert_eq!(secrets::key_path(), key_path);

    let sealed = secrets::seal("s3cret").expect("seal");
    assert!(secrets::is_sealed(&sealed));
    assert!(
        !secrets::is_ephemeral(),
        "a creatable path must yield a persistent key"
    );
    assert!(key_path.is_file(), "key file created on first seal");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "key file must be 0600");
    }
    let hex = std::fs::read_to_string(&key_path).unwrap();
    assert_eq!(hex.trim().len(), 64, "32 bytes hex");

    assert_eq!(secrets::open(&sealed).unwrap(), "s3cret");
    let _ = std::fs::remove_dir_all(&dir);
}
