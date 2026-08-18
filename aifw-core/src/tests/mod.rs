//! Engine unit tests, one module per engine (#447). Shared fixtures live
//! here; every submodule starts with `use super::*;`.

#![allow(clippy::module_inception)]

pub(super) use aifw_common::*;
pub(super) use aifw_pf::PfBackend;
pub(super) use std::sync::Arc;

pub(super) use crate::db::Database;
pub(super) use crate::engine::RuleEngine;
pub(super) use crate::validation::validate_rule;

mod config;
mod geoip;
mod ha;
mod nat;
mod rules;
mod shaping;
mod tls;
mod vpn;
