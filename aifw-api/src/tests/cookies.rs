use super::*;

#[tokio::test]
async fn test_login_sets_httponly_session_cookies() {
    let (server, _) = test_app().await;
    let cookies = login_cookies(&server).await;

    assert_eq!(cookies.len(), 2, "expected access + refresh cookies");
    for c in &cookies {
        assert!(c.contains("HttpOnly"), "{c}");
        assert!(c.contains("SameSite=Strict"), "{c}");
    }
    let access = cookies.iter().find(|c| c.starts_with("aifw_at=")).unwrap();
    assert!(access.contains("Path=/;"), "{access}");
    let refresh = cookies.iter().find(|c| c.starts_with("aifw_rt=")).unwrap();
    assert!(refresh.contains("Path=/api/v1/auth;"), "{refresh}");
}

#[tokio::test]
async fn test_cookie_authenticates_requests() {
    let (server, _) = test_app().await;
    let cookies = login_cookies(&server).await;
    let access = cookie_from(&cookies, "aifw_at");

    // No Authorization header — the cookie alone must authenticate.
    let resp = server
        .get("/api/v1/auth/me")
        .add_header("cookie", format!("aifw_at={access}"))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["username"], "admin");
}

#[tokio::test]
async fn test_cookie_write_requires_csrf_header() {
    let (server, _) = test_app().await;
    let cookies = login_cookies(&server).await;
    let access = cookie_from(&cookies, "aifw_at");

    // Unsafe method with cookie auth but no CSRF header → 403.
    let resp = server
        .post("/api/v1/auth/ws-ticket")
        .add_header("cookie", format!("aifw_at={access}"))
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);

    // Same request with the custom header succeeds.
    let resp = server
        .post("/api/v1/auth/ws-ticket")
        .add_header("cookie", format!("aifw_at={access}"))
        .add_header("x-aifw-csrf", "1")
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn test_bearer_writes_do_not_need_csrf_header() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Header-auth clients are CSRF-immune; no custom header required.
    let resp = server
        .post("/api/v1/auth/ws-ticket")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn test_refresh_via_cookie_rotates_session() {
    let (server, _) = test_app().await;
    let cookies = login_cookies(&server).await;
    let refresh = cookie_from(&cookies, "aifw_rt");

    // No JSON body — the refresh token rides the cookie.
    let resp = server
        .post("/api/v1/auth/refresh")
        .add_header("cookie", format!("aifw_rt={refresh}"))
        .await;
    resp.assert_status_ok();

    let rotated = set_cookies(&resp);
    let new_access = cookie_from(&rotated, "aifw_at");
    let new_refresh = cookie_from(&rotated, "aifw_rt");
    assert_ne!(new_refresh, refresh, "refresh token must rotate");

    // The rotated access cookie authenticates.
    server
        .get("/api/v1/auth/me")
        .add_header("cookie", format!("aifw_at={new_access}"))
        .await
        .assert_status_ok();

    // The old refresh token was revoked by the rotation.
    let resp = server
        .post("/api/v1/auth/refresh")
        .add_header("cookie", format!("aifw_rt={refresh}"))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout_via_cookies_clears_and_revokes() {
    let (server, _) = test_app().await;
    let cookies = login_cookies(&server).await;
    let access = cookie_from(&cookies, "aifw_at");
    let refresh = cookie_from(&cookies, "aifw_rt");

    // Cookie-only logout: no body, no Authorization header.
    let resp = server
        .post("/api/v1/auth/logout")
        .add_header("cookie", format!("aifw_at={access}; aifw_rt={refresh}"))
        .add_header("x-aifw-csrf", "1")
        .await;
    resp.assert_status_ok();
    for c in set_cookies(&resp) {
        assert!(c.contains("Max-Age=0"), "logout must expire cookies: {c}");
    }

    // Access token was revoked (JTI) — cookie no longer authenticates.
    let resp = server
        .get("/api/v1/auth/me")
        .add_header("cookie", format!("aifw_at={access}"))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    // Refresh token was revoked too.
    let resp = server
        .post("/api/v1/auth/refresh")
        .add_header("cookie", format!("aifw_rt={refresh}"))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_totp_required_login_sets_no_cookies() {
    let (server, _) = test_app().await;
    // First login normally to create the user, then enable TOTP.
    let token = create_user_and_login(&server).await;
    let resp = server
        .post("/api/v1/auth/totp/setup")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let secret = body["secret"].as_str().unwrap().to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    server
        .post("/api/v1/auth/totp/verify")
        .authorization_bearer(&token)
        .json(&json!({"code": code}))
        .await
        .assert_status_ok();

    // Password-only login now returns totp_required and must NOT install
    // session cookies.
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "TestPass123"}))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["totp_required"], true);
    assert!(set_cookies(&resp).is_empty(), "no cookies before 2FA");
}
