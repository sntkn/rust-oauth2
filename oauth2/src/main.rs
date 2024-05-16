use std::env;

use async_redis_session::RedisSessionStore;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
    routing::{get, post},
    Router,
};
use chrono::Local;
use jsonwebtoken::DecodingKey;
use jwt::decode_token;
use oauth2::handler::{authorization, authorize, create_token, introspect, me, signout};
use session_manager::manage_session;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use oauth2::app_state::AppState;
use oauth2::repository::db_repository;
use oauth2::util::jwt;
use oauth2::util::session_manager;

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
    let token_router = Router::new().route("/token", post(create_token::invoke));
    let auth_router = Router::new()
        .route("/me", get(me::invoke))
        .route("/signout", post(signout::invoke))
        .route("/introspect", post(introspect::invoke))
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
