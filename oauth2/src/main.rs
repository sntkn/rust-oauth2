use std::env;

use async_redis_session::RedisSessionStore;
use axum::{
    debug_handler,
    extract::{Extension, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Local};
use jsonwebtoken::DecodingKey;
use jwt::{decode_token, generate_token, TokenClaims};
use oauth2::handler::{authorization, authorize};
use regex::Regex;
use serde::{Deserialize, Serialize};
use session_manager::manage_session;
use str::generate_random_string;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use validator::{Validate, ValidationError};

use oauth2::app_state::AppState;
use oauth2::repository::db_repository;
use oauth2::util::jwt;
use oauth2::util::session_manager;
use oauth2::util::str;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let store = RedisSessionStore::new("redis://localhost:6379/").unwrap();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let repo = db_repository::Repository::new(db_url).await.unwrap();

    let state = AppState { store, repo };

    let session_router = Router::new()
        .route("/authorize", get(authorize::invoke)) // http://localhost:3000/authorize?response_type=code&state=3&client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback
        .route("/authorization", post(authorization::invoke))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            session_middleware,
        ));
    let token_router = Router::new().route("/token", post(create_token));
    let auth_router = Router::new()
        .route("/me", get(me).put(edit_user))
        .route("/signout", post(signout))
        .route("/introspect", post(introspect))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = session_router
        .merge(token_router)
        .merge(auth_router)
        .with_state(state);

    let listner = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listner, app).await.unwrap();
}

async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();
    // Authorization ヘッダからアクセストークン取得
    let authorization = headers
        .get("Authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .unwrap();

    let token = authorization.split(' ').last().unwrap();

    // JWTを解析
    let decoding_key = DecodingKey::from_secret(b"some-secret");
    let token_message = decode_token(token, &decoding_key)
        .or(Err(StatusCode::UNAUTHORIZED))?
        .claims;

    // JWTの有効期限をチェック
    if token_message.exp < Local::now().naive_local().and_utc().timestamp() {
        return Err(StatusCode::FORBIDDEN);
    }

    // アクセストークン取得（token and user_id）
    let token_result = state.repo.find_token(token_message.sub.to_string()).await;
    let token = token_result
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if token.user_id != token_message.jti {
        return Err(StatusCode::FORBIDDEN);
    }

    req.extensions_mut().insert(token_message);

    Ok(next.run(req).await)
}

async fn session_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (session, jar) = manage_session(&state.store, req.headers()).await;

    req.extensions_mut().insert(session);
    req.extensions_mut().insert(jar);

    Ok(next.run(req).await)
}

#[derive(Debug, Deserialize, Validate)]
struct CreateTokenInput {
    #[serde(default)]
    #[validate(custom(function = "uuid"))]
    code: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'grant_type' can not be empty"))]
    grant_type: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'refresh_token' can not be empty"))]
    refresh_token: String,
}

#[derive(Debug, Deserialize, Validate)]
struct EditUserInput {
    #[validate(length(
        min = 1,
        max = 100,
        message = "Parameter 'name' must be between 1 and 100 characters"
    ))]
    name: String,
}

#[derive(Serialize)]
struct AuthorizeJson {
    client_id: String,
    redirect_uri: String,
    state: String,
    response_type: String,
}

fn uuid(id: &str) -> Result<(), ValidationError> {
    // Define the regular expression pattern for UUIDv4
    let pattern =
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .expect("Failed to compile UUID regex pattern");

    if !pattern.is_match(id) {
        let mut error = ValidationError::new("Invalid UUID format");
        error.add_param(std::borrow::Cow::Borrowed("pattern"), &pattern.to_string());
        return Err(error);
    }

    Ok(())
}

#[debug_handler]
async fn create_token(
    State(state): State<AppState>,
    input: Json<CreateTokenInput>,
) -> Result<impl IntoResponse, StatusCode> {
    // issue token
    if input.grant_type == "authorization_code" {
        if input.code.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        // コードの存在チェック
        let code = state
            .repo
            .find_code(input.code.to_string())
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or(StatusCode::FORBIDDEN)?;
        // コードの有効期限チェック
        if code.expires_at.unwrap() < Local::now().naive_local() {
            return Err(StatusCode::FORBIDDEN);
        }
        // トークン登録
        let token = generate_random_string(32);
        let token_expires_at = Local::now().naive_local() + Duration::minutes(10);
        let now = Local::now().naive_local().into();
        let params = db_repository::CreateTokenParams {
            access_token: token.to_string(),
            user_id: code.user_id,
            client_id: code.client_id,
            expires_at: token_expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_token(params).await.unwrap(); // TODO

        // トークン生成(JWT)
        let token_claims = TokenClaims {
            sub: token.to_string(),
            jti: code.user_id,
            exp: token_expires_at.and_utc().timestamp(),
            iat: now.unwrap().and_utc().timestamp(),
        };
        let access_jwt = generate_token(&token_claims, b"some-secret").unwrap();

        // コード無効化
        let _ = state.repo.revoke_code(code.code.to_string()).await.unwrap();

        // リフレッシュトークン生成
        let expires_at = Local::now().naive_local() + Duration::days(90);
        let now = Local::now().naive_local().into();
        let refresh_token = generate_random_string(64);
        let params = db_repository::CreateRefreshTokenParams {
            refresh_token: refresh_token.to_string(),
            access_token: token.to_string(),
            expires_at: expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_refresh_token(params).await.unwrap(); // TODO

        // トークン返却
        let response = TokenResponse {
            access_token: access_jwt,
            refresh_token: refresh_token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: token_expires_at.and_utc().timestamp(),
        };
        Ok(Json(response))
    // refresh token
    } else if input.grant_type == "refresh_token" {
        // リフレッシュトークンの存在チェック
        let old_refresh_token = state
            .repo
            .find_refresh_token(input.refresh_token.to_string())
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // 有効期限切れチェック
        if old_refresh_token.expires_at.unwrap() < Local::now().naive_local() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        // old token 取得
        let old_token = state
            .repo
            .find_token(old_refresh_token.access_token.to_string())
            .await
            .unwrap()
            .unwrap();

        let new_access_token = generate_random_string(32);
        let token_expires_at = Local::now().naive_local() + Duration::minutes(10);
        let now = Local::now().naive_local().into();
        let params = db_repository::CreateTokenParams {
            access_token: new_access_token.to_string(),
            user_id: old_token.user_id,
            client_id: old_token.client_id,
            expires_at: token_expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_token(params).await.unwrap(); // TODO

        // リフレッシュトークン
        let expires_at = Local::now().naive_local() + Duration::days(90);
        let now = Local::now().naive_local().into();
        let refresh_token = generate_random_string(64);
        let params = db_repository::CreateRefreshTokenParams {
            refresh_token: refresh_token.to_string(),
            access_token: new_access_token.to_string(),
            expires_at: expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_refresh_token(params).await.unwrap(); // TODO

        // リフレッシュトークン、トークン無効化
        let _ = state
            .repo
            .revoke_refresh_token(old_refresh_token.refresh_token.to_string())
            .await
            .unwrap();
        let _ = state
            .repo
            .revoke_token(old_token.access_token.to_string())
            .await
            .unwrap();

        // トークン生成(JWT)
        let token_claims = TokenClaims {
            sub: new_access_token.to_string(),
            jti: old_token.user_id,
            exp: token_expires_at.and_utc().timestamp(),
            iat: now.unwrap().and_utc().timestamp(),
        };
        let access_jwt = generate_token(&token_claims, b"some-secret").unwrap();

        // トークン返却
        let response = TokenResponse {
            access_token: access_jwt,
            refresh_token: refresh_token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: token_expires_at.and_utc().timestamp(),
        };
        Ok(Json(response))
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }
}

async fn me(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<impl IntoResponse, StatusCode> {
    // ユーザー情報取得
    let user = state
        .repo
        .find_user(claims.jti)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // ユーザー情報返却
    let response = UserResponse {
        id: user.id.to_string(),
        name: user.name.to_string(),
        email: user.email.to_string(),
    };
    Ok(Json(response))
}

async fn edit_user(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    input: Json<EditUserInput>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = state
        .repo
        .edit_user(claims.jti, input.name.to_string())
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // ユーザー情報返却
    let response = UserResponse {
        id: user.id.to_string(),
        name: user.name.to_string(),
        email: user.email.to_string(),
    };
    Ok(Json(response))
}

async fn signout(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<impl IntoResponse, StatusCode> {
    // アクセストークンを破棄
    state
        .repo
        .revoke_token(claims.sub.to_string())
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // リフレッシュトークンを破棄
    state
        .repo
        .revoke_refresh_token_by_token(claims.sub.to_string())
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(())
}

async fn introspect(
    Extension(claims): Extension<TokenClaims>,
) -> Result<impl IntoResponse, StatusCode> {
    Ok(Json(claims))
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: i64,
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    name: String,
    email: String,
}
