// FreeBSD pf backend using pfctl CLI commands
// Bridges to pfctl until raw /dev/pf ioctl is implemented

use crate::backend::PfBackend;
use crate::error::PfError;
use crate::types::{PfState, PfStats, PfTableEntry};
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::process::Command;

fn parse_addr_port(s: &str) -> (IpAddr, u16) {
    // Format: "192.168.1.1:12345" or "[::1]:443"
    if let Some(idx) = s.rfind(':') {
        let addr_str = &s[..idx];
        let port_str = &s[idx + 1..];
        let addr = addr_str
            .trim_matches(|c| c == '[' || c == ']')
            .parse::<IpAddr>()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        let port = port_str.parse::<u16>().unwrap_or(0);
        (addr, port)
    } else {
        (IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
    }
}

fn extract_counter(line: &str, key: &str) -> Option<u64> {
    let idx = line.find(key)?;
    let after = &line[idx + key.len()..];
    after.split_whitespace().next()?.parse().ok()
}

pub struct PfIoctl;

impl PfIoctl {
    pub fn new() -> Result<Self, PfError> {
        Ok(Self)
    }
}

impl Drop for PfIoctl {
    fn drop(&mut self) {}
}

async fn pfctl(args: &[&str]) -> Result<String, PfError> {
    let output = Command::new("/usr/local/bin/sudo")
        .arg("/sbin/pfctl")
        .args(args)
        .output()
        .await
        .map_err(|e| PfError::DeviceOpen(format!("pfctl exec failed: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // pfctl often writes info to stderr even on success, only error on real failures
        if stderr.contains("ERROR") || stderr.contains("syntax error") {
            return Err(PfError::Rule(stderr.to_string()));
        }
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[async_trait]
impl PfBackend for PfIoctl {
    async fn add_rule(&self, anchor: &str, rule: &str) -> Result<(), PfError> {
        let mut child = Command::new("/usr/local/bin/sudo")
            .args(["/sbin/pfctl", "-a", anchor, "-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| PfError::Rule(format!("pfctl add_rule spawn failed: {e}")))?;
        if let Some(ref mut stdin) = child.stdin {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(rule.as_bytes()).await;
        }
        let output = child
            .wait_with_output()
            .await
            .map_err(|e| PfError::Rule(format!("pfctl add_rule failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("syntax error") {
                return Err(PfError::Rule(stderr.to_string()));
            }
        }
        Ok(())
    }

    async fn flush_rules(&self, anchor: &str) -> Result<(), PfError> {
        pfctl(&["-a", anchor, "-Fr"]).await?;
        Ok(())
    }

    async fn load_rules(&self, anchor: &str, rules: &[String]) -> Result<(), PfError> {
        if rules.is_empty() {
            return self.flush_rules(anchor).await;
        }
        let ruleset = rules.join("\n");
        tracing::debug!(anchor, rules = %ruleset, "loading pf rules");

        // Write to temp file then load — avoids shell quoting issues with echo
        let tmp = format!("/tmp/aifw_pf_{}.conf", anchor.replace('/', "_"));
        tokio::fs::write(&tmp, &ruleset)
            .await
            .map_err(|e| PfError::Rule(format!("failed to write temp rules: {e}")))?;

        let output = Command::new("/usr/local/bin/sudo")
            .args(["/sbin/pfctl", "-a", anchor, "-f", &tmp])
            .output()
            .await
            .map_err(|e| PfError::Rule(format!("pfctl load_rules failed: {e}")))?;

        let _ = tokio::fs::remove_file(&tmp).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PfError::Rule(format!("rule error: {}", stderr)));
        }
        Ok(())
    }

    async fn get_rules(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let out = pfctl(&["-a", anchor, "-sr"]).await?;
        Ok(out
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    async fn get_states(&self) -> Result<Vec<PfState>, PfError> {
        let out = pfctl(&["-ss", "-vv"]).await?;
        // Parse pfctl -ss -vv output (multi-line per state):
        // all tcp 192.168.1.1:12345 -> 10.0.0.1:443 ESTABLISHED:ESTABLISHED
        //    age 00:20:53, expires in 05:00:00, 950:2935 pkts, 65306:3890325 bytes, ...
        let mut states: Vec<PfState> = Vec::new();
        let mut current: Option<PfState> = None;

        for line in out.lines() {
            if line.is_empty() || line.starts_with("No ") {
                continue;
            }

            if !line.starts_with(' ') && !line.starts_with('\t') {
                // New state line — save previous if any
                if let Some(s) = current.take() {
                    states.push(s);
                }

                // Anchor on the direction arrow (`->` or `<-`). pfctl's
                // header line shape is:
                //   <iface_or_all> <proto> <left> [(<nat_map>)] <arrow> <right> <state>...
                // Indexing fixed offsets like parts[4]/parts[5] breaks on
                // NAT'd states where parts[3] is the parenthesized natmap,
                // so the dst/state would be "->" / "<right>" instead of
                // "<right>" / "<state>". Find the arrow first; everything
                // hangs off that.
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 5 {
                    continue;
                }
                let arrow_idx = parts.iter().position(|p| *p == "->" || *p == "<-");
                let Some(ai) = arrow_idx else { continue };
                if ai + 2 >= parts.len() {
                    continue;
                }

                let proto = parts.get(1).unwrap_or(&"").to_string();
                let arrow = parts[ai];
                // The state field is immediately after the arrow's right
                // operand. ESTABLISHED:ESTABLISHED, FIN_WAIT_2, etc.
                let state_str = parts[ai + 2].to_string();

                // For `->` the left side is the originator (src) and the
                // right is the destination. For `<-` it's reversed: the
                // right side is the originator and the left is the dst.
                // Either way, src_addr is whoever opened the connection.
                let (lhs, rhs) = (parts[2], parts[ai + 1]);
                let (src, dst) = if arrow == "->" {
                    (lhs, rhs)
                } else {
                    (rhs, lhs)
                };

                let (src_addr, src_port) = parse_addr_port(src);
                let (dst_addr, dst_port) = parse_addr_port(dst);

                // First field is the interface in verbose output ("em0",
                // "vtnet0"); "all"/"in"/"out" mean no interface tag.
                let iface = parts
                    .first()
                    .filter(|s| {
                        let s = *s;
                        !matches!(*s, "all" | "in" | "out") && s.chars().any(|c| c.is_ascii_digit())
                    })
                    .map(|s| s.to_string());
                current = Some(PfState {
                    id: 0,
                    protocol: proto,
                    src_addr,
                    src_port,
                    dst_addr,
                    dst_port,
                    state: state_str,
                    packets_in: 0,
                    packets_out: 0,
                    bytes_in: 0,
                    bytes_out: 0,
                    age_secs: 0,
                    iface,
                    rtable: None,
                });
            } else if let Some(ref mut s) = current {
                // Detail line — extract bytes, packets, age
                let trimmed = line.trim();
                // Parse "NNN:NNN pkts, NNN:NNN bytes"
                if let Some(pkts_pos) = trimmed.find(" pkts,") {
                    // Walk back to find the pkts pair
                    let before_pkts = &trimmed[..pkts_pos];
                    if let Some(pair) = before_pkts
                        .rsplit(", ")
                        .next()
                        .or(before_pkts.rsplit(' ').next())
                    {
                        let pair = pair.trim().trim_start_matches(", ");
                        if let Some((a, b)) = pair.split_once(':') {
                            s.packets_in = a.trim().parse().unwrap_or(0);
                            s.packets_out = b.trim().parse().unwrap_or(0);
                        }
                    }
                }
                if let Some(bytes_pos) = trimmed.find(" bytes") {
                    let before_bytes = &trimmed[..bytes_pos];
                    if let Some(pair) = before_bytes.rsplit(", ").next()
                        && let Some((a, b)) = pair.split_once(':')
                    {
                        s.bytes_in = a.trim().parse().unwrap_or(0);
                        s.bytes_out = b.trim().parse().unwrap_or(0);
                    }
                }
                // Parse age
                if let Some(age_pos) = trimmed.find("age ") {
                    let age_str = &trimmed[age_pos + 4..];
                    if let Some(comma) = age_str.find(',') {
                        let duration = &age_str[..comma];
                        let parts: Vec<&str> = duration.split(':').collect();
                        if parts.len() == 3 {
                            let h: u64 = parts[0].parse().unwrap_or(0);
                            let m: u64 = parts[1].parse().unwrap_or(0);
                            let sec: u64 = parts[2].parse().unwrap_or(0);
                            s.age_secs = h * 3600 + m * 60 + sec;
                        }
                    }
                }
            }
        }
        if let Some(s) = current {
            states.push(s);
        }
        Ok(states)
    }

    async fn get_stats(&self) -> Result<PfStats, PfError> {
        let out = pfctl(&["-si"]).await.unwrap_or_default();
        let mut stats = PfStats::default();

        for line in out.lines() {
            let line = line.trim();
            if line.starts_with("Status:") {
                stats.running = line.contains("Enabled");
            }
            if line.contains("current entries") {
                // "  current entries                       18"
                for token in line.split_whitespace() {
                    if let Ok(n) = token.parse::<u64>() {
                        stats.states_count = n;
                        break;
                    }
                }
            }
        }

        // Get rule count
        let rules_out = pfctl(&["-sr"]).await.unwrap_or_default();
        stats.rules_count = rules_out.lines().filter(|l| !l.is_empty()).count() as u64;

        // Get packet/byte counters from pfctl -vvsI (interface stats)
        // Sum all non-loopback interfaces
        let iface_out = pfctl(&["-vvsI"]).await.unwrap_or_default();
        let mut current_iface = String::new();
        for line in iface_out.lines() {
            let trimmed = line.trim();
            // Interface header line (not indented)
            if !line.starts_with('\t') && !line.starts_with(' ') && !trimmed.is_empty() {
                current_iface = trimmed.trim_end_matches(" (skip)").to_string();
            }
            // Skip loopback, pflog, and "all" aggregate
            if current_iface == "all"
                || current_iface.starts_with("lo")
                || current_iface.starts_with("pflog")
            {
                continue;
            }
            // Parse: In4/Pass:    [ Packets: 390261             Bytes: 430240864          ]
            if trimmed.starts_with("In4/Pass:") || trimmed.starts_with("In6/Pass:") {
                if let Some(pkts) = extract_counter(trimmed, "Packets:") {
                    stats.packets_in += pkts;
                }
                if let Some(bytes) = extract_counter(trimmed, "Bytes:") {
                    stats.bytes_in += bytes;
                }
            }
            if trimmed.starts_with("Out4/Pass:") || trimmed.starts_with("Out6/Pass:") {
                if let Some(pkts) = extract_counter(trimmed, "Packets:") {
                    stats.packets_out += pkts;
                }
                if let Some(bytes) = extract_counter(trimmed, "Bytes:") {
                    stats.bytes_out += bytes;
                }
            }
        }

        Ok(stats)
    }

    async fn add_table_entry(&self, table: &str, addr: IpAddr) -> Result<(), PfError> {
        pfctl(&["-t", table, "-T", "add", &addr.to_string()]).await?;
        Ok(())
    }

    async fn remove_table_entry(&self, table: &str, addr: IpAddr) -> Result<(), PfError> {
        pfctl(&["-t", table, "-T", "delete", &addr.to_string()]).await?;
        Ok(())
    }

    async fn flush_table(&self, table: &str) -> Result<(), PfError> {
        pfctl(&["-t", table, "-T", "flush"]).await?;
        Ok(())
    }

    async fn get_table_entries(&self, table: &str) -> Result<Vec<PfTableEntry>, PfError> {
        let out = pfctl(&["-t", table, "-T", "show"]).await?;
        let entries: Vec<PfTableEntry> = out
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() {
                    return None;
                }
                let addr: IpAddr = line.split('/').next()?.parse().ok()?;
                let prefix: u8 = line
                    .split('/')
                    .nth(1)
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(if addr.is_ipv4() { 32 } else { 128 });
                Some(PfTableEntry {
                    addr,
                    prefix,
                    packets: 0,
                    bytes: 0,
                })
            })
            .collect();
        Ok(entries)
    }

    async fn is_running(&self) -> Result<bool, PfError> {
        let out = pfctl(&["-si"]).await.unwrap_or_default();
        Ok(out.contains("Status: Enabled"))
    }

    async fn load_nat_rules(&self, anchor: &str, rules: &[String]) -> Result<(), PfError> {
        if rules.is_empty() {
            return self.flush_nat_rules(anchor).await;
        }
        let ruleset = rules.join("\n");
        tracing::debug!(anchor, rules = %ruleset, "loading pf NAT rules");

        let tmp = format!("/tmp/aifw_pf_nat_{}.conf", anchor.replace('/', "_"));
        tokio::fs::write(&tmp, &ruleset)
            .await
            .map_err(|e| PfError::Rule(format!("failed to write temp NAT rules: {e}")))?;

        let output = Command::new("/usr/local/bin/sudo")
            .args(["/sbin/pfctl", "-a", anchor, "-N", "-f", &tmp])
            .output()
            .await
            .map_err(|e| PfError::Rule(format!("pfctl load_nat failed: {e}")))?;

        let _ = tokio::fs::remove_file(&tmp).await;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PfError::Rule(format!("NAT rule error: {}", stderr)));
        }
        Ok(())
    }

    async fn get_nat_rules(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let out = pfctl(&["-a", anchor, "-sn"]).await?;
        Ok(out
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    async fn flush_nat_rules(&self, anchor: &str) -> Result<(), PfError> {
        pfctl(&["-a", anchor, "-Fn"]).await?;
        Ok(())
    }

    async fn load_queues(&self, anchor: &str, queues: &[String]) -> Result<(), PfError> {
        if queues.is_empty() {
            return self.flush_queues(anchor).await;
        }
        let ruleset = queues.join("\n");
        let tmp = format!("/tmp/aifw_pf_queue_{}.conf", anchor.replace('/', "_"));
        tokio::fs::write(&tmp, &ruleset)
            .await
            .map_err(|e| PfError::Rule(format!("failed to write temp queue rules: {e}")))?;
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/sbin/pfctl", "-a", anchor, "-f", &tmp])
            .output()
            .await
            .map_err(|e| PfError::Rule(format!("pfctl load_queues failed: {e}")))?;
        let _ = tokio::fs::remove_file(&tmp).await;
        Ok(())
    }

    async fn get_queues(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let out = pfctl(&["-a", anchor, "-sq"]).await?;
        Ok(out
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect())
    }

    async fn flush_queues(&self, anchor: &str) -> Result<(), PfError> {
        pfctl(&["-a", anchor, "-Fq"]).await?;
        Ok(())
    }

    async fn set_interface_fib(&self, iface: &str, fib: u32) -> Result<(), PfError> {
        let output = Command::new("/usr/local/bin/sudo")
            .args(["/sbin/ifconfig", iface, "fib", &fib.to_string()])
            .output()
            .await
            .map_err(|e| PfError::Other(format!("ifconfig fib exec failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(PfError::Other(format!(
                "ifconfig {iface} fib {fib} failed: {stderr}"
            )));
        }
        Ok(())
    }

    async fn get_interface_fib(&self, iface: &str) -> Result<u32, PfError> {
        let output = Command::new("/sbin/ifconfig")
            .arg(iface)
            .output()
            .await
            .map_err(|e| PfError::Other(format!("ifconfig exec failed: {e}")))?;
        if !output.status.success() {
            return Err(PfError::Other(format!("ifconfig {iface} failed")));
        }
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            if let Some(idx) = line.find("fib: ")
                && let Some(fib) = line[idx + 5..].split_whitespace().next()
            {
                return fib
                    .parse()
                    .map_err(|e| PfError::Other(format!("parse fib: {e}")));
            }
        }
        Ok(0)
    }

    async fn list_fibs(&self) -> Result<u32, PfError> {
        let output = Command::new("/sbin/sysctl")
            .args(["-n", "net.fibs"])
            .output()
            .await
            .map_err(|e| PfError::Other(format!("sysctl exec failed: {e}")))?;
        if !output.status.success() {
            return Ok(1);
        }
        let s = String::from_utf8_lossy(&output.stdout);
        Ok(s.trim().parse().unwrap_or(1))
    }

    async fn kill_states_on_iface(&self, iface: &str) -> Result<u64, PfError> {
        let out = pfctl(&["-k", "0.0.0.0/0", "-k", "0.0.0.0/0", "-i", iface]).await?;
        Ok(parse_killed_count(&out))
    }

    async fn kill_states_for_label(&self, label: &str) -> Result<u64, PfError> {
        // pfctl has no direct "kill states by label" — labels live on rules, not
        // on states in a queryable form. We list states verbosely, find entries
        // whose rule label matches, and kill each by src/dst pair.
        let out = pfctl(&["-ss", "-v"]).await?;
        let mut killed: u64 = 0;
        let mut current: Option<(String, String)> = None;
        for line in out.lines() {
            let trimmed = line.trim_start();
            if !line.starts_with(char::is_whitespace) {
                // Header line: "<proto> <iface> <src> -> <dst> <state>"
                // or for ICMP: "<proto> <iface> <src> -> <dst> (id:N) <state>"
                current = parse_state_endpoints(line);
            } else if (trimmed.contains(&format!("label \"{label}\""))
                || trimmed.contains(&format!("@0 {label}")))
                && let Some((src, dst)) = current.as_ref()
            {
                if pfctl(&["-k", src, "-k", dst]).await.is_ok() {
                    killed += 1;
                }
                current = None;
            }
        }
        Ok(killed)
    }
}

fn parse_killed_count(s: &str) -> u64 {
    // pfctl prints "killed N states" on success
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("killed ")
            && let Some(n_str) = rest.split_whitespace().next()
        {
            return n_str.parse().unwrap_or(0);
        }
    }
    0
}

/// Parse "<proto> <iface> <src> -> <dst> ..." from pfctl -ss -v output,
/// returning (src_stripped_of_port, dst_stripped_of_port).
fn parse_state_endpoints(line: &str) -> Option<(String, String)> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // Expected shape: proto iface src <dir> dst (state)
    // Direction is one of -> <- <->
    let arrow_idx = fields
        .iter()
        .position(|f| matches!(*f, "->" | "<-" | "<->"))?;
    if arrow_idx < 2 || arrow_idx + 1 >= fields.len() {
        return None;
    }
    let src = strip_port(fields[arrow_idx - 1]);
    let dst = strip_port(fields[arrow_idx + 1]);
    Some((src, dst))
}

fn strip_port(s: &str) -> String {
    // IPv6 bracket form: [::1]:443
    if let Some(close) = s.find(']') {
        return s[1..close].to_string();
    }
    // IPv4 x.y.z.w:port
    match s.rfind(':') {
        Some(i) if s[..i].chars().all(|c| c.is_ascii_digit() || c == '.') => s[..i].to_string(),
        _ => s.to_string(),
    }
}
