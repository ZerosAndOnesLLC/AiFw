//! `quick-xml`-based parser for OPNsense / pfSense `config.xml`.
//!
//! Builds a small DOM (`Node`) once and then walks it with structural
//! accessors (`child`, `children`, `text`, `has_child`). This avoids the
//! repeated-substring traps the previous string-find parser fell into —
//! source vs destination port disambiguation is structural, self-closing
//! tags are detected at the event layer, and CDATA / attributes / comments
//! all parse without exploding.

use super::types::*;
use quick_xml::Reader;
use quick_xml::events::Event;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Default)]
pub struct Node {
    pub name: String,
    pub text: String,
    pub children: Vec<Node>,
}

impl Node {
    pub fn child<'a>(&'a self, name: &str) -> Option<&'a Node> {
        self.children.iter().find(|c| c.name == name)
    }

    pub fn children<'a>(&'a self, name: &str) -> impl Iterator<Item = &'a Node> {
        self.children.iter().filter(move |c| c.name == name)
    }

    pub fn has_child(&self, name: &str) -> bool {
        self.children.iter().any(|c| c.name == name)
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("XML error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("not an OPNsense or pfSense configuration (root element was {0:?})")]
    WrongRoot(String),
    #[error("malformed configuration: {0}")]
    Malformed(String),
}

/// Parse a `config.xml` payload into a typed `OpnConfig`.
pub fn parse(xml: &str) -> Result<OpnConfig, ParseError> {
    let root = parse_dom(xml)?;
    let kind = match root.name.as_str() {
        "opnsense" => ConfigKind::Opnsense,
        "pfsense" => ConfigKind::Pfsense,
        other => return Err(ParseError::WrongRoot(other.to_string())),
    };

    let mut cfg = OpnConfig {
        kind,
        version: root.child("version").map(|n| n.text.clone()),
        ..Default::default()
    };

    if let Some(sys) = root.child("system") {
        cfg.system = parse_system(sys);
    }
    if let Some(aliases) = root.child("aliases") {
        cfg.aliases = aliases.children("alias").map(parse_alias).collect();
    }
    // OPNsense pre-23.x sometimes nested aliases under <OPNsense><Firewall><Alias>
    if let Some(opn) = root.child("OPNsense")
        && let Some(fw) = opn.child("Firewall")
        && let Some(alias_root) = fw.child("Alias")
        && let Some(aliases_node) = alias_root.child("aliases")
    {
        for a in aliases_node.children("alias") {
            cfg.aliases.push(parse_alias(a));
        }
    }
    if let Some(gws) = root.child("gateways") {
        cfg.gateways = gws.children("gateway_item").map(parse_gateway).collect();
    }
    if let Some(filter) = root.child("filter") {
        cfg.rules = filter.children("rule").map(parse_rule).collect();
    }
    if let Some(nat) = root.child("nat") {
        cfg.nat = parse_nat(nat);
    }
    if let Some(routes) = root.child("staticroutes") {
        let gw_map: HashMap<String, String> = cfg
            .gateways
            .iter()
            .map(|g| (g.name.clone(), g.gateway.clone()))
            .collect();
        cfg.routes = routes
            .children("route")
            .map(|r| parse_route(r, &gw_map))
            .collect();
    }

    cfg.interface_names = collect_interface_names(&cfg);
    Ok(cfg)
}

fn parse_dom(xml: &str) -> Result<Node, ParseError> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    reader.config_mut().expand_empty_elements = false;
    let mut buf: Vec<u8> = Vec::new();
    let mut stack: Vec<Node> = vec![Node {
        name: "__root__".into(),
        ..Default::default()
    }];

    loop {
        match reader.read_event_into(&mut buf) {
            Err(e) => return Err(ParseError::Xml(e)),
            Ok(Event::Eof) => break,
            Ok(Event::Decl(_)) | Ok(Event::Comment(_)) | Ok(Event::PI(_)) | Ok(Event::DocType(_)) => {}
            Ok(Event::Start(e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .map_err(|err| ParseError::Malformed(err.to_string()))?
                    .to_string();
                stack.push(Node {
                    name,
                    ..Default::default()
                });
            }
            Ok(Event::End(_)) => {
                if stack.len() <= 1 {
                    return Err(ParseError::Malformed("unbalanced end tag".into()));
                }
                let node = stack.pop().expect("stack invariant");
                stack.last_mut().unwrap().children.push(node);
            }
            Ok(Event::Empty(e)) => {
                let name = std::str::from_utf8(e.name().as_ref())
                    .map_err(|err| ParseError::Malformed(err.to_string()))?
                    .to_string();
                stack.last_mut().unwrap().children.push(Node {
                    name,
                    ..Default::default()
                });
            }
            Ok(Event::Text(t)) => {
                let s = t
                    .unescape()
                    .map_err(|err| ParseError::Malformed(err.to_string()))?
                    .into_owned();
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    let last = stack.last_mut().unwrap();
                    if last.text.is_empty() {
                        // First text run: keep the raw whitespace from the
                        // event so multi-line `<address>10.0.0.5\n10.0.0.6
                        // </address>` content survives the splitter that
                        // alias parsing relies on.
                        last.text = s;
                    } else {
                        // Subsequent run (quick-xml occasionally splits text
                        // across events): always insert a single newline as
                        // a safe separator. Without this, two split events
                        // could concatenate IPs into "10.0.0.510.0.0.6".
                        last.text.push('\n');
                        last.text.push_str(&s);
                    }
                }
            }
            Ok(Event::CData(c)) => {
                // CDATA contents are preserved as-is; OPNsense uses CDATA in
                // a few places (notes, scripts) and we should not lose them.
                let s = std::str::from_utf8(c.as_ref())
                    .map_err(|err| ParseError::Malformed(err.to_string()))?
                    .to_string();
                let last = stack.last_mut().unwrap();
                if !last.text.is_empty() {
                    last.text.push('\n');
                }
                last.text.push_str(&s);
            }
        }
        buf.clear();
    }

    if stack.len() != 1 {
        return Err(ParseError::Malformed("unclosed tags".into()));
    }
    let mut root_holder = stack.pop().expect("stack invariant");
    // Find the actual document element (skip any whitespace-only siblings).
    let doc_root = root_holder
        .children
        .drain(..)
        .find(|c| !c.name.is_empty())
        .ok_or_else(|| ParseError::Malformed("no root element".into()))?;
    Ok(doc_root)
}

fn parse_system(node: &Node) -> OpnSystem {
    OpnSystem {
        hostname: node.child("hostname").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        domain: node.child("domain").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        dns_servers: node
            .children("dnsserver")
            .map(|n| n.text.clone())
            .filter(|s| !s.is_empty())
            .collect(),
        timezone: node.child("timezone").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        timeservers: node
            .child("timeservers")
            .map(|n| {
                n.text
                    .split_whitespace()
                    .map(String::from)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    }
}

fn parse_endpoint(node: &Node) -> OpnEndpoint {
    OpnEndpoint {
        address: node.child("address").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        network: node.child("network").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        any: node.has_child("any"),
        not: node.has_child("not"),
        port: node.child("port").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
    }
}

fn parse_rule(node: &Node) -> OpnRule {
    let interface_field = node
        .child("interface")
        .map(|n| n.text.clone())
        .unwrap_or_default();
    // OPNsense floating rules use a comma-separated list. Single-iface rules
    // pass through as a one-element vec.
    let interface = if interface_field.is_empty() {
        Vec::new()
    } else {
        interface_field
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    let floating = node.child("floating").map(|n| n.text == "yes").unwrap_or(false);
    // OPNsense `<quick>` semantics depend on whether the rule is floating.
    // Non-floating rules default to quick=yes (first match wins, the pf
    // default for AiFw rules). Floating rules default to quick=no (last
    // match wins) to match OPNsense's UI default. Explicit `<quick>` always
    // overrides.
    let quick = match node.child("quick") {
        Some(n) => n.text != "0" && !n.text.eq_ignore_ascii_case("no"),
        None => !floating,
    };

    OpnRule {
        action: node.child("type").map(|n| n.text.clone()).unwrap_or_else(|| "pass".into()),
        direction: node.child("direction").map(|n| n.text.clone()).unwrap_or_else(|| "in".into()),
        interface,
        floating,
        ipprotocol: node.child("ipprotocol").map(|n| AddrFamily::parse(&n.text)).unwrap_or(AddrFamily::Inet),
        protocol: node.child("protocol").map(|n| n.text.clone()).unwrap_or_else(|| "any".into()),
        source: node.child("source").map(parse_endpoint).unwrap_or_default(),
        destination: node.child("destination").map(parse_endpoint).unwrap_or_default(),
        disabled: node.has_child("disabled"),
        log: node.has_child("log"),
        quick,
        descr: node.child("descr").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
    }
}

fn parse_nat(node: &Node) -> OpnNat {
    let mut nat = OpnNat::default();
    for r in node.children("rule") {
        nat.port_forwards.push(OpnNatPortForward {
            interface: r.child("interface").map(|n| n.text.clone()).unwrap_or_else(|| "wan".into()),
            protocol: r.child("protocol").map(|n| n.text.clone()).unwrap_or_else(|| "tcp".into()),
            source: r.child("source").map(parse_endpoint).unwrap_or_default(),
            destination: r.child("destination").map(parse_endpoint).unwrap_or_default(),
            target: r.child("target").map(|n| n.text.clone()).unwrap_or_default(),
            local_port: r.child("local-port").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
            disabled: r.has_child("disabled"),
            descr: r.child("descr").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        });
    }
    if let Some(out) = node.child("outbound") {
        if let Some(mode) = out.child("mode") {
            nat.mode = Some(mode.text.clone());
        }
        for r in out.children("rule") {
            nat.outbound.push(OpnNatOutbound {
                interface: r.child("interface").map(|n| n.text.clone()).unwrap_or_else(|| "wan".into()),
                protocol: r.child("protocol").map(|n| n.text.clone()).unwrap_or_else(|| "any".into()),
                source: r.child("source").map(parse_endpoint).unwrap_or_default(),
                destination: r.child("destination").map(parse_endpoint).unwrap_or_default(),
                target: r.child("target").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
                disabled: r.has_child("disabled"),
                descr: r.child("descr").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
                nonat: r.has_child("nonat"),
                staticnatport: r.has_child("staticnatport"),
            });
        }
    }
    for r in node.children("onetoone") {
        nat.onetoone.push(OpnNatOneToOne {
            interface: r.child("interface").map(|n| n.text.clone()).unwrap_or_else(|| "wan".into()),
            external: r.child("external").map(|n| n.text.clone()).unwrap_or_default(),
            internal: r.child("internal").map(|n| n.text.clone()).unwrap_or_default(),
            destination: r.child("destination").map(parse_endpoint).unwrap_or_default(),
            disabled: r.has_child("disabled"),
            descr: r.child("descr").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        });
    }
    nat
}

fn parse_alias(node: &Node) -> OpnAlias {
    // Alias content lives in either <content>...</content> (one-per-line) or
    // <address>1.2.3.4 5.6.7.8</address> (whitespace-separated, older form).
    let content_text = node
        .child("content")
        .map(|n| n.text.clone())
        .or_else(|| node.child("address").map(|n| n.text.clone()))
        .unwrap_or_default();
    let content: Vec<String> = content_text
        .split(|c: char| c.is_whitespace())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    OpnAlias {
        name: node.child("name").map(|n| n.text.clone()).unwrap_or_default(),
        kind: node
            .child("type")
            .map(|n| n.text.clone())
            .unwrap_or_else(|| "host".into()),
        content,
        descr: node.child("descr").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        disabled: node.has_child("disabled"),
    }
}

fn parse_gateway(node: &Node) -> OpnGateway {
    OpnGateway {
        name: node.child("name").map(|n| n.text.clone()).unwrap_or_default(),
        interface: node.child("interface").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
        gateway: node.child("gateway").map(|n| n.text.clone()).unwrap_or_default(),
        ipprotocol: node
            .child("ipprotocol")
            .map(|n| AddrFamily::parse(&n.text))
            .unwrap_or(AddrFamily::Inet),
    }
}

fn parse_route(node: &Node, gw_map: &HashMap<String, String>) -> OpnRoute {
    let gateway_name = node
        .child("gateway")
        .map(|n| n.text.clone())
        .unwrap_or_default();
    // Resolve named gateway to its IP. If the resolved value is `dynamic`
    // (DHCP-derived in OPNsense), pass that through as-is so the importer can
    // skip and report it instead of inserting bogus rows.
    let gateway = gw_map
        .get(&gateway_name)
        .cloned()
        .unwrap_or_else(|| gateway_name.clone());

    OpnRoute {
        network: node.child("network").map(|n| n.text.clone()).unwrap_or_default(),
        gateway,
        gateway_name,
        disabled: node.has_child("disabled"),
        descr: node.child("descr").map(|n| n.text.clone()).filter(|s| !s.is_empty()),
    }
}

fn collect_interface_names(cfg: &OpnConfig) -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for r in &cfg.rules {
        for i in &r.interface {
            set.insert(i.clone());
        }
    }
    for n in &cfg.nat.port_forwards {
        set.insert(n.interface.clone());
    }
    for n in &cfg.nat.outbound {
        set.insert(n.interface.clone());
    }
    for n in &cfg.nat.onetoone {
        set.insert(n.interface.clone());
    }
    set.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: &str = r#"<?xml version="1.0"?>
<opnsense>
  <version>25.7</version>
  <system>
    <hostname>fw1</hostname>
    <domain>example.com</domain>
    <dnsserver>1.1.1.1</dnsserver>
    <dnsserver>9.9.9.9</dnsserver>
  </system>
  <aliases>
    <alias>
      <name>my_servers</name>
      <type>host</type>
      <content>10.0.0.5
10.0.0.6</content>
      <descr>web tier</descr>
    </alias>
  </aliases>
  <gateways>
    <gateway_item>
      <name>WAN_DHCP</name>
      <interface>wan</interface>
      <gateway>1.2.3.1</gateway>
      <ipprotocol>inet</ipprotocol>
    </gateway_item>
  </gateways>
  <filter>
    <rule>
      <type>pass</type>
      <interface>lan</interface>
      <ipprotocol>inet6</ipprotocol>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination>
        <network>lanip</network>
        <port>22</port>
      </destination>
      <descr>SSH to firewall</descr>
      <log/>
    </rule>
    <rule>
      <type>block</type>
      <interface>wan,lan</interface>
      <floating>yes</floating>
      <protocol>any</protocol>
      <source><address>10.0.0.0/8</address><port>1024</port></source>
      <destination><address>![<![CDATA[8.8.8.8]]>]</address><port>53</port></destination>
      <disabled>1</disabled>
    </rule>
  </filter>
  <nat>
    <outbound>
      <mode>hybrid</mode>
      <rule>
        <interface>wan</interface>
        <source><network>lan</network></source>
        <destination><any/></destination>
        <descr>masq</descr>
      </rule>
    </outbound>
    <rule>
      <interface>wan</interface>
      <protocol>tcp</protocol>
      <source><any/></source>
      <destination>
        <network>wanip</network>
        <port>443</port>
      </destination>
      <target>10.0.0.10</target>
      <local-port>443</local-port>
      <descr>HTTPS forward</descr>
    </rule>
  </nat>
  <staticroutes>
    <route>
      <network>192.0.2.0/24</network>
      <gateway>WAN_DHCP</gateway>
      <descr>Test net</descr>
    </route>
  </staticroutes>
</opnsense>
"#;

    #[test]
    fn parses_root_kind_and_version() {
        let cfg = parse(TINY).expect("parse");
        assert_eq!(cfg.kind, ConfigKind::Opnsense);
        assert_eq!(cfg.version.as_deref(), Some("25.7"));
    }

    #[test]
    fn parses_system_dns_and_hostname() {
        let cfg = parse(TINY).unwrap();
        assert_eq!(cfg.system.hostname.as_deref(), Some("fw1"));
        assert_eq!(cfg.system.dns_servers, vec!["1.1.1.1", "9.9.9.9"]);
    }

    #[test]
    fn rule_keeps_destination_port_distinct_from_source_port() {
        let cfg = parse(TINY).unwrap();
        let ssh = cfg.rules.iter().find(|r| r.descr.as_deref() == Some("SSH to firewall")).unwrap();
        assert!(ssh.source.any);
        assert_eq!(ssh.destination.port.as_deref(), Some("22"));
        assert_eq!(ssh.source.port, None); // proves first-match bug is gone
    }

    #[test]
    fn rule_carries_ipv6_address_family() {
        let cfg = parse(TINY).unwrap();
        let ssh = cfg.rules.iter().find(|r| r.descr.as_deref() == Some("SSH to firewall")).unwrap();
        assert_eq!(ssh.ipprotocol, AddrFamily::Inet6);
    }

    #[test]
    fn self_closing_disabled_and_log_detected() {
        let cfg = parse(TINY).unwrap();
        let ssh = cfg.rules.iter().find(|r| r.descr.as_deref() == Some("SSH to firewall")).unwrap();
        assert!(ssh.log, "<log/> self-closing");
        let blocked = cfg.rules.iter().find(|r| r.action == "block").unwrap();
        assert!(blocked.disabled, "<disabled>1</disabled>");
    }

    #[test]
    fn floating_rule_has_multiple_interfaces() {
        let cfg = parse(TINY).unwrap();
        let floating = cfg.rules.iter().find(|r| r.floating).unwrap();
        assert_eq!(floating.interface, vec!["wan", "lan"]);
    }

    #[test]
    fn aliases_parsed() {
        let cfg = parse(TINY).unwrap();
        assert_eq!(cfg.aliases.len(), 1);
        assert_eq!(cfg.aliases[0].name, "my_servers");
        assert_eq!(cfg.aliases[0].content, vec!["10.0.0.5", "10.0.0.6"]);
    }

    #[test]
    fn gateway_resolution_in_static_route() {
        let cfg = parse(TINY).unwrap();
        let route = &cfg.routes[0];
        assert_eq!(route.gateway, "1.2.3.1");
        assert_eq!(route.gateway_name, "WAN_DHCP");
    }

    #[test]
    fn nat_port_forward_preserves_target_and_port_separately() {
        let cfg = parse(TINY).unwrap();
        let pf = &cfg.nat.port_forwards[0];
        assert_eq!(pf.target, "10.0.0.10");
        assert_eq!(pf.local_port.as_deref(), Some("443"));
        assert_eq!(pf.destination.port.as_deref(), Some("443"));
    }

    #[test]
    fn outbound_nat_mode_and_rules() {
        let cfg = parse(TINY).unwrap();
        assert_eq!(cfg.nat.mode.as_deref(), Some("hybrid"));
        assert_eq!(cfg.nat.outbound.len(), 1);
    }

    #[test]
    fn rejects_non_opnsense_root() {
        let xml = r#"<?xml version="1.0"?><wireguard><peer/></wireguard>"#;
        assert!(matches!(parse(xml), Err(ParseError::WrongRoot(_))));
    }

    #[test]
    fn handles_xml_declaration_and_comments() {
        let xml = r#"<?xml version="1.0"?>
<!-- a comment -->
<opnsense>
  <system><hostname>x</hostname></system>
</opnsense>"#;
        let cfg = parse(xml).unwrap();
        assert_eq!(cfg.system.hostname.as_deref(), Some("x"));
    }

    #[test]
    fn pfsense_root_recognized() {
        let xml = r#"<?xml version="1.0"?><pfsense><system><hostname>p</hostname></system></pfsense>"#;
        let cfg = parse(xml).unwrap();
        assert_eq!(cfg.kind, ConfigKind::Pfsense);
    }
}
