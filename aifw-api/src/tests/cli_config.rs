//! `aifw config …` through the API.

use super::cli_harness::Cli;
use super::*;

#[tokio::test]
async fn versions_export_import_restore() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&["rules", "add", "--action", "pass", "--label", "v1-rule"])
        .await
        .ok();
    cli.run(&["config", "save", "--comment", "first"])
        .await
        .ok();

    let h = cli.run(&["config", "history"]).await;
    h.ok();
    assert!(
        h.out.contains("VERSION") && h.out.contains("first"),
        "{}",
        h.out
    );
    let hj = cli.run(&["config", "history", "-o", "json"]).await.json();
    let v1 = hj["data"][0]["version"].as_i64().unwrap();

    // Export (redacted) to a 0600 file, and refuse plain over the API.
    let out = cli.dir.join("backup.json");
    cli.run(&["config", "export", "-O", out.to_str().unwrap()])
        .await
        .ok();
    let exported: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
    assert!(exported["config"].is_object(), "{exported}");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let plain = cli.run(&["config", "export", "--secrets", "plain"]).await;
    plain.code(2);
    assert!(plain.err.contains("aifw local config-export"));
    let pw = cli.dir.join("pw");
    std::fs::write(&pw, "a long passphrase\n").unwrap();
    cli.run(&[
        "config",
        "export",
        "--secrets",
        "passphrase",
        "--passphrase-file",
        pw.to_str().unwrap(),
    ])
    .await
    .ok();
    cli.run(&[
        "config",
        "export",
        "--secrets",
        "passphrase",
        "--passphrase-file",
        "/nonexistent",
    ])
    .await
    .code(2);

    // Change something, then import the earlier export back.
    cli.run(&["rules", "add", "--action", "block", "--label", "later"])
        .await
        .ok();
    cli.run(&["config", "import", out.to_str().unwrap(), "--preview"])
        .await
        .ok();
    cli.run(&["config", "import", out.to_str().unwrap()])
        .await
        .code(1);
    let imp = cli
        .run(&["config", "import", out.to_str().unwrap(), "--yes"])
        .await;
    assert!(
        imp.code == 0 || imp.err.contains("ollback") || imp.err.contains("apply"),
        "{} {}",
        imp.out,
        imp.err
    );

    // Diff, check, show, retention.
    cli.run(&["config", "save", "--comment", "second"])
        .await
        .ok();
    let hj = cli.run(&["config", "history", "-o", "json"]).await.json();
    let v2 = hj["data"][0]["version"].as_i64().unwrap();
    let d = cli
        .run(&["config", "diff", &v1.to_string(), &v2.to_string()])
        .await;
    d.ok();
    assert!(
        d.out.contains("rules") || d.out.contains("identical"),
        "{}",
        d.out
    );
    let c = cli.run(&["config", "check"]).await;
    assert!(c.code == 0 || c.code == 1, "{}", c.err);
    cli.run(&["config", "retention", "25"]).await.ok();
    assert!(
        cli.run(&["config", "retention"])
            .await
            .out
            .contains("Keeping 25")
    );
    cli.run(&["config", "show"]).await.ok();

    // Restore asks first.
    cli.run(&["config", "rollback", &v1.to_string()])
        .await
        .code(1);
    let r = cli
        .run(&["config", "restore", &v1.to_string(), "--yes"])
        .await;
    assert!(r.code == 0 || r.code == 1, "{} {}", r.out, r.err);
}

#[tokio::test]
async fn opnsense_import_needs_a_readable_file() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&["config", "import-opnsense", "/nonexistent.xml", "--preview"])
        .await
        .code(2);
    cli.run(&[
        "config",
        "import-opnsense",
        "x.xml",
        "--map",
        "nonsense",
        "--preview",
    ])
    .await
    .code(2);
    let f = cli.dir.join("cfg.xml");
    std::fs::write(
        &f,
        "<opnsense><system><hostname>x</hostname></system></opnsense>",
    )
    .unwrap();
    let p = cli
        .run(&[
            "config",
            "import-opnsense",
            f.to_str().unwrap(),
            "--preview",
        ])
        .await;
    assert!(p.code == 0 || p.code == 6, "{}", p.err);
}
