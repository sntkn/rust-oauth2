use std::env;

use async_redis_session::RedisSessionStore;
use axum::{
    routing::{get, post},
    Router,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use oauth2::app_state::AppState;
use oauth2::handler::{authorization, authorize, create_token, introspect, me, signout, signup};
use oauth2::middleware;
use oauth2::repository::db_repository;

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
        .route("/signup", get(signup::new))
        .route("/signup", post(signup::create))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::session_middleware,
        ));
    let token_router = Router::new().route("/token", post(create_token::invoke));
    let auth_router = Router::new()
        .route("/me", get(me::invoke))
        .route("/signout", post(signout::invoke))
        .route("/introspect", post(introspect::invoke))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    let app = session_router
        .merge(token_router)
        .merge(auth_router)
        .with_state(state);

    let listner = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listner, app).await.unwrap();
}
