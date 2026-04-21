//! FreeBSD apply implementations — filled in Tasks 5–9.
#![cfg(target_os = "freebsd")]

use super::{ApplyReport, GeneralInput, BannerInput, ConsoleInput, SshInput, SystemInfo};

pub async fn apply_general(_i: &GeneralInput) -> ApplyReport { ApplyReport::ok() }
pub async fn apply_banner(_i: &BannerInput) -> ApplyReport { ApplyReport::ok() }
pub async fn apply_console(_i: &ConsoleInput) -> ApplyReport { ApplyReport::ok_requires_reboot() }
pub async fn apply_ssh(_i: &SshInput) -> ApplyReport { ApplyReport::ok_requires_restart("sshd") }
pub async fn collect_info() -> SystemInfo { SystemInfo::default() }
pub async fn motd_user_edited_marker_set() -> bool { false }
