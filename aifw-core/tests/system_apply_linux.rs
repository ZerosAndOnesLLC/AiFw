#![cfg(not(target_os = "freebsd"))]

use aifw_core::system_apply::{
    apply_general, apply_banner, apply_console, apply_ssh, collect_info,
    GeneralInput, BannerInput, ConsoleInput, SshInput, ApplyReport,
};

#[tokio::test]
async fn linux_apply_general_is_noop_ok() {
    let r: ApplyReport = apply_general(&GeneralInput {
        hostname: "testhost".into(),
        domain: "example.com".into(),
        timezone: "UTC".into(),
    }).await;
    assert!(r.ok);
    assert!(!r.requires_reboot);
    assert!(r.requires_service_restart.is_none());
}

#[tokio::test]
async fn linux_apply_console_reports_requires_reboot() {
    let r = apply_console(&ConsoleInput {
        kind: aifw_core::ConsoleKind::Serial,
        baud: 115200,
    }).await;
    assert!(r.ok);
    assert!(r.requires_reboot);
}

#[tokio::test]
async fn linux_apply_ssh_reports_sshd_restart() {
    let r = apply_ssh(&SshInput { enabled: true, port: 22, password_auth: false, permit_root_login: false }).await;
    assert!(r.ok);
    assert_eq!(r.requires_service_restart.as_deref(), Some("sshd"));
}

#[tokio::test]
async fn linux_apply_banner_is_noop_ok() {
    let r = apply_banner(&BannerInput { login_banner: "hi".into(), motd: "there".into() }).await;
    assert!(r.ok);
}

#[tokio::test]
async fn linux_collect_info_returns_stub() {
    let info = collect_info().await;
    assert!(!info.os_version.is_empty());
    assert!(info.cpu_count >= 1);
    assert!(info.mem_total_bytes > 0);
}

#[tokio::test]
async fn linux_motd_marker_is_false() {
    use aifw_core::system_apply::motd_user_edited_marker_set;
    assert!(!motd_user_edited_marker_set().await);
}
