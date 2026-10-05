//! The curated feed catalog.

/// How a feed's body is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One address or CIDR per line (plain text or JSON lines with a
    /// `cidr`/`ip` field); `#` and `;` start comments.
    Lines,
    /// DShield `block.txt`: tab-separated start, end, prefix length, …
    DShield,
}

/// A blocklist the plugin knows how to fetch.
#[derive(Debug, Clone)]
pub struct Feed {
    /// Stable id stored in settings
    pub id: &'static str,
    /// Display name
    pub name: &'static str,
    /// Download URL (https)
    pub url: &'static str,
    /// Body format
    pub format: Format,
    /// One-line description for the settings form
    pub description: &'static str,
    /// Enabled on a fresh install
    pub default_on: bool,
}

/// Every built-in feed. Ids are stored in operator settings — never rename
/// one; retire it instead.
pub const CATALOG: &[Feed] = &[
    Feed {
        id: "spamhaus-drop",
        name: "Spamhaus DROP (IPv4)",
        url: "https://www.spamhaus.org/drop/drop_v4.json",
        format: Format::Lines,
        description: "Netblocks hijacked or leased by professional spam and cybercrime \
                      operations. Very low false-positive rate. Includes the former EDROP list.",
        default_on: true,
    },
    Feed {
        id: "spamhaus-drop-v6",
        name: "Spamhaus DROP (IPv6)",
        url: "https://www.spamhaus.org/drop/drop_v6.json",
        format: Format::Lines,
        description: "The IPv6 edition of Spamhaus DROP.",
        default_on: true,
    },
    Feed {
        id: "feodo",
        name: "abuse.ch Feodo Tracker",
        url: "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
        format: Format::Lines,
        description: "Active botnet command-and-control servers (Dridex, Emotet, QakBot…).",
        default_on: true,
    },
    Feed {
        id: "dshield",
        name: "DShield top attackers",
        url: "https://feeds.dshield.org/block.txt",
        format: Format::DShield,
        description: "The 20 /24 networks reporting the most attacks to the SANS Internet \
                      Storm Center over the last three days.",
        default_on: true,
    },
    Feed {
        id: "firehol-level1",
        name: "FireHOL Level 1",
        url: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        format: Format::Lines,
        description: "A maximum-protection aggregate (DROP, Feodo, DShield, bogons…) with \
                      minimal false positives. Overlaps the lists above.",
        default_on: false,
    },
    Feed {
        id: "et-compromised",
        name: "Emerging Threats compromised hosts",
        url: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        format: Format::Lines,
        description: "Hosts known to be compromised and actively attacking.",
        default_on: false,
    },
    Feed {
        id: "cins-army",
        name: "CINS Army",
        url: "https://cinsscore.com/list/ci-badguys.txt",
        format: Format::Lines,
        description: "Up to 15,000 addresses with a poor Collective Intelligence score. \
                      More aggressive; occasional false positives.",
        default_on: false,
    },
];

/// Look a catalog feed up by id.
pub fn find(id: &str) -> Option<&'static Feed> {
    CATALOG.iter().find(|f| f.id == id)
}
