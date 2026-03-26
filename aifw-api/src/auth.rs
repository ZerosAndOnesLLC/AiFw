use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString, password_hash::rand_core::OsRng};
use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub token_expiry_hours: i64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt_secret: Uuid::new_v4().to_string(),
            token_expiry_hours: 24,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user id
    pub username: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub token: String,
    pub expires_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ApiKey {
    pub id: Uuid,
    pub name: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub prefix: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key: String,
    pub prefix: String,
}

// --- Password hashing ---

pub fn hash_password(password: &str) -> Result<String, StatusCode> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// --- JWT ---

pub fn create_token(user: &User, config: &AuthConfig) -> Result<LoginResponse, StatusCode> {
    let now = Utc::now();
    let exp = now + Duration::hours(config.token_expiry_hours);

    let claims = Claims {
        sub: user.id.to_string(),
        username: user.username.clone(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(LoginResponse {
        token,
        expires_at: exp.to_rfc3339(),
    })
}

pub fn verify_token(token: &str, config: &AuthConfig) -> Result<TokenData<Claims>, StatusCode> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(config.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)
}

// --- DB operations ---

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            prefix TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn create_user(
    pool: &SqlitePool,
    req: &CreateUserRequest,
) -> Result<User, StatusCode> {
    let pw_hash = hash_password(&req.password)?;
    let user = User {
        id: Uuid::new_v4(),
        username: req.username.clone(),
        password_hash: pw_hash,
        created_at: Utc::now().to_rfc3339(),
    };

    sqlx::query("INSERT INTO users (id, username, password_hash, created_at) VALUES (?1, ?2, ?3, ?4)")
        .bind(user.id.to_string())
        .bind(&user.username)
        .bind(&user.password_hash)
        .bind(&user.created_at)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::CONFLICT)?;

    Ok(user)
}

pub async fn get_user_by_username(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<User>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, username, password_hash, created_at FROM users WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(row.map(|(id, username, password_hash, created_at)| User {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        username,
        password_hash,
        created_at,
    }))
}

pub async fn create_api_key(
    pool: &SqlitePool,
    user_id: Uuid,
    name: &str,
) -> Result<CreateApiKeyResponse, StatusCode> {
    let raw_key = format!("aifw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let prefix = raw_key[..12].to_string();
    let key_hash = hash_password(&raw_key)?;

    let id = Uuid::new_v4();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO api_keys (id, name, key_hash, prefix, user_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(&key_hash)
    .bind(&prefix)
    .bind(user_id.to_string())
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(CreateApiKeyResponse {
        id,
        name: name.to_string(),
        key: raw_key,
        prefix,
    })
}

pub async fn verify_api_key(pool: &SqlitePool, key: &str) -> Result<String, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String)>(
        "SELECT ak.key_hash, u.id, u.username FROM api_keys ak JOIN users u ON ak.user_id = u.id",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for (key_hash, user_id, _username) in rows {
        if verify_password(key, &key_hash) {
            return Ok(user_id);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

// --- Middleware ---

pub async fn auth_middleware(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user_id = if let Some(token) = auth_header.strip_prefix("Bearer ") {
        let token_data = verify_token(token, &state.auth_config)?;
        token_data.claims.sub
    } else if let Some(key) = auth_header.strip_prefix("ApiKey ") {
        verify_api_key(&state.pool, key).await?
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    request.extensions_mut().insert(AuthUser(user_id));
    Ok(next.run(request).await)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthUser(pub String);
