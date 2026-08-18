//! Shared parsers and engine constructors used by several command groups.

use aifw_common::{Action, Direction, PortRange};
use aifw_core::{Database, NatEngine, RuleEngine};
use std::path::Path;
use std::sync::Arc;

pub(super) fn parse_port(s: &str) -> anyhow::Result<PortRange> {
    if let Some((start, end)) = s.split_once(':') {
        Ok(PortRange {
            start: start.parse()?,
            end: end.parse()?,
        })
    } else {
        let port: u16 = s.parse()?;
        Ok(PortRange {
            start: port,
            end: port,
        })
    }
}

pub(super) fn parse_action(s: &str) -> anyhow::Result<Action> {
    match s {
        "pass" => Ok(Action::Pass),
        "block" => Ok(Action::Block),
        "block-drop" => Ok(Action::BlockDrop),
        "block-return" => Ok(Action::BlockReturn),
        _ => anyhow::bail!("unknown action: {s} (use pass, block, block-drop, block-return)"),
    }
}

pub(super) fn parse_direction(s: &str) -> anyhow::Result<Direction> {
    match s {
        "in" => Ok(Direction::In),
        "out" => Ok(Direction::Out),
        "any" => Ok(Direction::Any),
        _ => anyhow::bail!("unknown direction: {s} (use in, out, any)"),
    }
}

pub(super) async fn create_engine(db_path: &Path) -> anyhow::Result<RuleEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    Ok(RuleEngine::new(db.pool().clone(), pf))
}

pub(super) async fn create_nat_engine(db_path: &Path) -> anyhow::Result<NatEngine> {
    let db = Database::new(db_path).await?;
    let pf = Arc::from(aifw_pf::create_backend());
    // "aifw-nat" — must match the API/daemon anchor; NAT loads replace every
    // rule class in their anchor since #531.
    Ok(NatEngine::new(db.pool().clone(), pf).with_anchor("aifw-nat".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_single_and_range() {
        assert_eq!(parse_port("22").unwrap(), PortRange { start: 22, end: 22 });
        assert_eq!(
            parse_port("8000:8080").unwrap(),
            PortRange {
                start: 8000,
                end: 8080
            }
        );
        assert!(parse_port("x").is_err());
        assert!(parse_port("70000").is_err(), "u16 overflow rejected");
        assert!(parse_port("1:2:3").is_err());
    }

    #[test]
    fn parse_action_and_direction_vocabulary() {
        assert_eq!(parse_action("pass").unwrap(), Action::Pass);
        assert_eq!(parse_action("block").unwrap(), Action::Block);
        assert_eq!(parse_action("block-drop").unwrap(), Action::BlockDrop);
        assert_eq!(parse_action("block-return").unwrap(), Action::BlockReturn);
        let e = parse_action("deny").unwrap_err().to_string();
        assert!(e.contains("pass, block, block-drop, block-return"), "{e}");
        assert_eq!(parse_direction("in").unwrap(), Direction::In);
        assert_eq!(parse_direction("out").unwrap(), Direction::Out);
        assert_eq!(parse_direction("any").unwrap(), Direction::Any);
        assert!(parse_direction("inbound").is_err());
    }
}
