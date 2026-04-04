#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use crate::context::PluginContext;
    use crate::examples::ip_reputation::IpReputationPlugin;
    use crate::examples::logging::LoggingPlugin;
    use crate::examples::webhook::WebhookPlugin;
    use crate::hooks::*;
    use crate::manager::PluginManager;
    use crate::plugin::*;
    use crate::wasm::{WasmPlugin, WasmPluginConfig};

    fn make_ctx() -> PluginContext {
        let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
        PluginContext::new(pf)
    }

    fn default_config() -> PluginConfig {
        PluginConfig {
            enabled: true,
            settings: Default::default(),
        }
    }

    fn make_rule_event(src: IpAddr, action: &str) -> HookEvent {
        HookEvent {
            hook: HookPoint::PreRule,
            data: HookEventData::Rule {
                src_ip: Some(src),
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                src_port: Some(12345),
                dst_port: Some(80),
                protocol: "tcp".to_string(),
                action: action.to_string(),
                rule_id: None,
            },
        }
    }

    fn make_connection_event(src: IpAddr) -> HookEvent {
        HookEvent {
            hook: HookPoint::ConnectionNew,
            data: HookEventData::Connection {
                src_ip: src,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: 54321,
                dst_port: 443,
                protocol: "tcp".to_string(),
                state: "NEW".to_string(),
            },
        }
    }

    fn make_log_event() -> HookEvent {
        HookEvent {
            hook: HookPoint::LogEvent,
            data: HookEventData::Log {
                action: "rule_added".to_string(),
                details: "block ssh".to_string(),
                source: "engine".to_string(),
            },
        }
    }

    // --- Plugin Manager tests ---

    #[tokio::test]
    async fn test_manager_register_and_list() {
        let ctx = make_ctx();
        let mut mgr = PluginManager::new(ctx);

        let plugin = Box::new(LoggingPlugin::new());
        mgr.register(plugin, default_config()).await.unwrap();

        assert_eq!(mgr.count(), 1);
        assert_eq!(mgr.running_count(), 1);

        let list = mgr.list_plugins();
        assert_eq!(list[0].0.name, "custom-logger");
        assert_eq!(list[0].1, PluginState::Running);
    }

    #[tokio::test]
    async fn test_manager_unload() {
        let ctx = make_ctx();
        let mut mgr = PluginManager::new(ctx);

        mgr.register(Box::new(LoggingPlugin::new()), default_config())
            .await
            .unwrap();
        assert_eq!(mgr.count(), 1);

        mgr.unload("custom-logger").await.unwrap();
        assert_eq!(mgr.count(), 0);
    }

    #[tokio::test]
    async fn test_manager_duplicate_register() {
        let ctx = make_ctx();
        let mut mgr = PluginManager::new(ctx);

        mgr.register(Box::new(LoggingPlugin::new()), default_config())
            .await
            .unwrap();

        let result = mgr
            .register(Box::new(LoggingPlugin::new()), default_config())
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_manager_dispatch() {
        let ctx = make_ctx();
        let mut mgr = PluginManager::new(ctx);

        mgr.register(Box::new(LoggingPlugin::new()), default_config())
            .await
            .unwrap();

        let event = make_log_event();
        let actions = mgr.dispatch(&event).await;
        // LoggingPlugin always returns Continue
        assert!(actions.is_empty()); // Continue actions are filtered out
    }

    #[tokio::test]
    async fn test_manager_disabled_plugin() {
        let ctx = make_ctx();
        let mut mgr = PluginManager::new(ctx);

        let config = PluginConfig {
            enabled: false,
            settings: Default::default(),
        };
        mgr.register(Box::new(LoggingPlugin::new()), config)
            .await
            .unwrap();

        assert_eq!(mgr.count(), 1);
        assert_eq!(mgr.running_count(), 0);

        let list = mgr.list_plugins();
        assert_eq!(list[0].1, PluginState::Stopped);
    }

    #[tokio::test]
    async fn test_manager_shutdown_all() {
        let ctx = make_ctx();
        let mut mgr = PluginManager::new(ctx);

        mgr.register(Box::new(LoggingPlugin::new()), default_config())
            .await
            .unwrap();
        mgr.register(Box::new(WebhookPlugin::new()), default_config())
            .await
            .unwrap();

        assert_eq!(mgr.count(), 2);
        mgr.shutdown_all().await;
        assert_eq!(mgr.count(), 0);
    }

    // --- IP Reputation plugin tests ---

    #[tokio::test]
    async fn test_ip_reputation_blocks_bad_ip() {
        let ctx = make_ctx();
        let mut plugin = IpReputationPlugin::new();
        plugin.init(&default_config(), &ctx).await.unwrap();

        let bad_ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        plugin.add_bad_ip(bad_ip).await;

        let event = make_rule_event(bad_ip, "pass");
        let action = plugin.on_hook(&event, &ctx).await;
        assert_eq!(action, HookAction::Block);
    }

    #[tokio::test]
    async fn test_ip_reputation_allows_good_ip() {
        let ctx = make_ctx();
        let mut plugin = IpReputationPlugin::new();
        plugin.init(&default_config(), &ctx).await.unwrap();

        let good_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let event = make_rule_event(good_ip, "pass");
        let action = plugin.on_hook(&event, &ctx).await;
        assert_eq!(action, HookAction::Continue);
    }

    #[tokio::test]
    async fn test_ip_reputation_connection_hook() {
        let ctx = make_ctx();
        let mut plugin = IpReputationPlugin::new();
        plugin.init(&default_config(), &ctx).await.unwrap();

        let bad_ip = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        plugin.add_bad_ip(bad_ip).await;

        let event = make_connection_event(bad_ip);
        let action = plugin.on_hook(&event, &ctx).await;
        assert_eq!(action, HookAction::Block);
    }

    // --- Logging plugin tests ---

    #[tokio::test]
    async fn test_logging_captures_events() {
        let ctx = make_ctx();
        let mut plugin = LoggingPlugin::new();
        plugin.init(&default_config(), &ctx).await.unwrap();

        plugin.on_hook(&make_log_event(), &ctx).await;
        plugin.on_hook(&make_rule_event(IpAddr::V4(Ipv4Addr::LOCALHOST), "pass"), &ctx).await;

        assert_eq!(plugin.entry_count().await, 2);
        let entries = plugin.get_entries().await;
        assert_eq!(entries[0].hook, HookPoint::LogEvent);
        assert_eq!(entries[1].hook, HookPoint::PreRule);
    }

    // --- Webhook plugin tests ---

    #[tokio::test]
    async fn test_webhook_notifies_on_block() {
        let ctx = make_ctx();
        let mut plugin = WebhookPlugin::new();
        plugin.init(&default_config(), &ctx).await.unwrap();

        // Post-rule block event
        let event = HookEvent {
            hook: HookPoint::PostRule,
            data: HookEventData::Rule {
                src_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                dst_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                src_port: Some(12345),
                dst_port: Some(80),
                protocol: "tcp".to_string(),
                action: "block".to_string(),
                rule_id: None,
            },
        };

        plugin.on_hook(&event, &ctx).await;
        assert_eq!(plugin.notification_count().await, 1);
        let notifs = plugin.get_notifications().await;
        assert_eq!(notifs[0].event_type, "rule_block");
    }

    #[tokio::test]
    async fn test_webhook_ignores_pass() {
        let ctx = make_ctx();
        let mut plugin = WebhookPlugin::new();
        plugin.init(&default_config(), &ctx).await.unwrap();

        let event = HookEvent {
            hook: HookPoint::PostRule,
            data: HookEventData::Rule {
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                protocol: "tcp".to_string(),
                action: "pass".to_string(),
                rule_id: None,
            },
        };

        plugin.on_hook(&event, &ctx).await;
        assert_eq!(plugin.notification_count().await, 0);
    }

    // --- WASM plugin tests ---

    #[tokio::test]
    async fn test_wasm_plugin_lifecycle() {
        let ctx = make_ctx();
        let config = WasmPluginConfig {
            name: Some("test-wasm".to_string()),
            hooks: vec![HookPoint::PreRule],
            ..Default::default()
        };
        let mut plugin = WasmPlugin::new(config);

        assert_eq!(plugin.state(), PluginState::Loaded);
        assert_eq!(plugin.info().name, "test-wasm");

        plugin.init(&default_config(), &ctx).await.unwrap();
        assert_eq!(plugin.state(), PluginState::Running);

        let event = make_rule_event(IpAddr::V4(Ipv4Addr::LOCALHOST), "pass");
        let action = plugin.on_hook(&event, &ctx).await;
        assert_eq!(action, HookAction::Continue); // stub returns Continue

        plugin.shutdown().await.unwrap();
        assert_eq!(plugin.state(), PluginState::Stopped);
    }

    // --- Plugin context tests ---

    #[tokio::test]
    async fn test_context_store() {
        let ctx = make_ctx();
        ctx.store_set("key1", "value1").await;
        assert_eq!(ctx.store_get("key1").await, Some("value1".to_string()));
        assert_eq!(ctx.store_get("nonexistent").await, None);
    }

    #[tokio::test]
    async fn test_context_table_operations() {
        let ctx = make_ctx();
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        // Plugins can only modify tables with "plugin_" prefix
        ctx.add_to_table("plugin_test", ip).await.unwrap();
        ctx.remove_from_table("plugin_test", ip).await.unwrap();

        // Non-prefixed table should be rejected
        assert!(ctx.add_to_table("system_table", ip).await.is_err());
        assert!(ctx.remove_from_table("system_table", ip).await.is_err());
    }
}
