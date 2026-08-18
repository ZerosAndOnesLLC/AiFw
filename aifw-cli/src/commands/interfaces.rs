//! `aifw interfaces …`.

// ============================================================
// Interfaces
// ============================================================

pub async fn interfaces_list() -> anyhow::Result<()> {
    let output = std::process::Command::new("ifconfig").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!(
        "{:<12} {:<18} {:<18} {:<6}",
        "Interface", "IPv4", "MAC", "Status"
    );
    println!("{}", "-".repeat(60));

    let mut name = String::new();
    let mut ipv4 = String::from("-");
    let mut mac = String::from("-");
    let mut status = "down";

    for line in stdout.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if !name.is_empty() && !name.starts_with("lo") && !name.starts_with("pflog") {
                println!("{:<12} {:<18} {:<18} {:<6}", name, ipv4, mac, status);
            }
            name = line.split(':').next().unwrap_or("").to_string();
            ipv4 = "-".to_string();
            mac = "-".to_string();
            status = if line.contains("UP") { "up" } else { "down" };
        }
        let trimmed = line.trim();
        if trimmed.starts_with("inet ") {
            ipv4 = trimmed.split_whitespace().nth(1).unwrap_or("-").to_string();
        }
        if trimmed.starts_with("ether ") {
            mac = trimmed.split_whitespace().nth(1).unwrap_or("-").to_string();
        }
    }
    if !name.is_empty() && !name.starts_with("lo") && !name.starts_with("pflog") {
        println!("{:<12} {:<18} {:<18} {:<6}", name, ipv4, mac, status);
    }
    Ok(())
}
