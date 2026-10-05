use super::*;

use std::sync::Arc;

use aifw_plugins::{
    ActionInfo, HookPoint, Plugin, PluginContext, PluginInfo, PluginSettings, SettingField,
};

/// Plugin with a typed setting, a secret, and an action.
struct Demo;

#[async_trait::async_trait]
impl Plugin for Demo {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "demo".into(),
            title: "Demo".into(),
            version: "1.0.0".into(),
            description: "test plugin".into(),
            author: "test".into(),
            hooks: vec![HookPoint::Timer],
        }
    }

    fn settings_schema(&self) -> Vec<SettingField> {
        vec![
            SettingField::integer("interval", "Interval", 1, 60, 10),
            SettingField::text("api_key", "API key", 64).secret(),
        ]
    }

    fn actions(&self) -> Vec<ActionInfo> {
        vec![ActionInfo::new("ping", "Ping", "replies pong")]
    }

    async fn init(&mut self, _s: &PluginSettings, ctx: &PluginContext) -> aifw_plugins::Result<()> {
        ctx.info("demo up");
        Ok(())
    }

    async fn run_action(
        &self,
        _action: &str,
        _args: Value,
        _ctx: &PluginContext,
    ) -> aifw_plugins::Result<Value> {
        Ok(json!("pong"))
    }

    async fn status(&self, _ctx: &PluginContext) -> Value {
        json!({"healthy": true})
    }
}

async fn plugin_app() -> TestServer {
    let (_, settings) = test_app().await;
    let mut state = crate::create_app_state_in_memory(settings).await.unwrap();
    let factory: aifw_plugins::registry::Factory = Arc::new(|| Box::new(Demo) as Box<dyn Plugin>);
    state.plugin_manager = Arc::new(
        aifw_plugins::PluginManager::with_factories(
            state.pf.clone(),
            state.pool.clone(),
            vec![factory],
        )
        .unwrap(),
    );
    TestServer::new(crate::build_router(state, None, "*", false))
}

#[tokio::test]
async fn plugin_lifecycle_round_trip() {
    let server = plugin_app().await;
    let token = create_user_and_login(&server).await;

    let list: Value = server
        .get("/api/v1/plugins")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list["total"], 1);
    assert_eq!(list["plugins"][0]["state"], "stopped");
    assert!(!list["hooks"].as_array().unwrap().is_empty());

    // Enable.
    let resp = server
        .put("/api/v1/plugins/demo/enabled")
        .authorization_bearer(&token)
        .json(&json!({"enabled": true}))
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["state"], "running");

    // Settings: invalid value → 400 with a readable message.
    let resp = server
        .patch("/api/v1/plugins/demo/settings")
        .authorization_bearer(&token)
        .json(&json!({"values": {"interval": 500}}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    assert!(
        resp.json::<Value>()["message"]
            .as_str()
            .unwrap()
            .contains("between 1 and 60")
    );

    // Valid value + secret; the secret is never echoed back.
    let resp = server
        .patch("/api/v1/plugins/demo/settings")
        .authorization_bearer(&token)
        .json(&json!({"values": {"interval": 30}, "secrets": {"api_key": "hunter2"}}))
        .await;
    resp.assert_status_ok();
    let text = resp.text();
    assert!(!text.contains("hunter2"));
    let detail: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(detail["values"]["interval"], 30);
    assert_eq!(detail["secrets_set"], json!(["api_key"]));
    assert_eq!(detail["state"], "running");

    let detail: Value = server
        .get("/api/v1/plugins/demo")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(detail["schema"].as_array().unwrap().len(), 2);
    assert!(!detail.to_string().contains("hunter2"));

    // Status, action, logs.
    let status: Value = server
        .get("/api/v1/plugins/demo/status")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(status["healthy"], true);
    let action: Value = server
        .post("/api/v1/plugins/demo/actions/ping")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(action["result"], "pong");
    let logs: Value = server
        .get("/api/v1/plugins/demo/logs?limit=50")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(
        logs["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["message"] == "demo up")
    );

    // Disable keeps it listed.
    server
        .put("/api/v1/plugins/demo/enabled")
        .authorization_bearer(&token)
        .json(&json!({"enabled": false}))
        .await
        .assert_status_ok();
    let list: Value = server
        .get("/api/v1/plugins")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list["plugins"][0]["state"], "stopped");

    // Action on a stopped plugin → 400 explaining why.
    server
        .post("/api/v1/plugins/demo/actions/ping")
        .authorization_bearer(&token)
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn unknown_plugin_and_action_are_404() {
    let server = plugin_app().await;
    let token = create_user_and_login(&server).await;
    server
        .get("/api/v1/plugins/nope")
        .authorization_bearer(&token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .put("/api/v1/plugins/nope/enabled")
        .authorization_bearer(&token)
        .json(&json!({"enabled": true}))
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .put("/api/v1/plugins/demo/enabled")
        .authorization_bearer(&token)
        .json(&json!({"enabled": true}))
        .await
        .assert_status_ok();
    server
        .post("/api/v1/plugins/demo/actions/nope")
        .authorization_bearer(&token)
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn plugin_changes_are_audited() {
    let server = plugin_app().await;
    let token = create_user_and_login(&server).await;
    server
        .put("/api/v1/plugins/demo/enabled")
        .authorization_bearer(&token)
        .json(&json!({"enabled": true}))
        .await
        .assert_status_ok();
    let audit: Value = server
        .get("/api/v1/logs")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(
        audit.to_string().contains("plugin 'demo' enabled"),
        "audit log should record the enable: {audit}"
    );
}
