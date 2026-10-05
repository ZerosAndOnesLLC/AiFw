use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;

use crate::context::PluginContext;
use crate::hooks::*;
use crate::manager::PluginManager;
use crate::plugin::*;

/// Minimal plugin used across the manager tests: subscribes to `LogEvent`
/// and returns a fixed action.
struct TestPlugin {
    name: &'static str,
    reply: HookAction,
}

impl TestPlugin {
    fn boxed(name: &'static str, reply: HookAction) -> Box<dyn Plugin> {
        Box::new(Self { name, reply })
    }
}

#[async_trait]
impl Plugin for TestPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: self.name.to_string(),
            version: "0.0.0".to_string(),
            description: "test".to_string(),
            author: "test".to_string(),
            hooks: vec![HookPoint::LogEvent],
        }
    }

    async fn init(&mut self, _config: &PluginConfig, _ctx: &PluginContext) -> crate::Result<()> {
        Ok(())
    }

    async fn on_hook(&self, _event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        self.reply.clone()
    }

    async fn shutdown(&mut self) -> crate::Result<()> {
        Ok(())
    }
}

fn make_ctx() -> PluginContext {
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
    PluginContext::new(pf)
}

fn enabled() -> PluginConfig {
    PluginConfig {
        enabled: true,
        settings: Default::default(),
    }
}

fn log_event() -> HookEvent {
    HookEvent {
        hook: HookPoint::LogEvent,
        data: HookEventData::Log {
            action: "rule_added".to_string(),
            details: "block ssh".to_string(),
            source: "engine".to_string(),
        },
    }
}

#[tokio::test]
async fn register_and_list() {
    let mut mgr = PluginManager::new(make_ctx());
    mgr.register(TestPlugin::boxed("a", HookAction::Continue), enabled())
        .await
        .unwrap();

    assert_eq!(mgr.count(), 1);
    assert_eq!(mgr.running_count(), 1);
    let list = mgr.list_plugins();
    assert_eq!(list[0].0.name, "a");
    assert_eq!(list[0].1, PluginState::Running);
}

#[tokio::test]
async fn duplicate_register_rejected() {
    let mut mgr = PluginManager::new(make_ctx());
    mgr.register(TestPlugin::boxed("a", HookAction::Continue), enabled())
        .await
        .unwrap();
    assert!(
        mgr.register(TestPlugin::boxed("a", HookAction::Continue), enabled())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn dispatch_filters_continue() {
    let mut mgr = PluginManager::new(make_ctx());
    mgr.register(TestPlugin::boxed("quiet", HookAction::Continue), enabled())
        .await
        .unwrap();
    mgr.register(TestPlugin::boxed("blocker", HookAction::Block), enabled())
        .await
        .unwrap();

    let actions = mgr.dispatch(&log_event()).await;
    assert_eq!(actions, vec![HookAction::Block]);
}

#[tokio::test]
async fn disabled_plugin_is_stopped_and_not_dispatched() {
    let mut mgr = PluginManager::new(make_ctx());
    mgr.register(
        TestPlugin::boxed("off", HookAction::Block),
        PluginConfig::default(),
    )
    .await
    .unwrap();

    assert_eq!(mgr.running_count(), 0);
    assert_eq!(mgr.list_plugins()[0].1, PluginState::Stopped);
    assert!(mgr.dispatch_set().is_empty());
}

#[tokio::test]
async fn context_table_prefix_enforced() {
    let ctx = make_ctx();
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    ctx.add_to_table("plugin_test", ip).await.unwrap();
    ctx.remove_from_table("plugin_test", ip).await.unwrap();
    assert!(ctx.add_to_table("system_table", ip).await.is_err());
    assert!(ctx.remove_from_table("system_table", ip).await.is_err());
}
