use api::app_state::AppState;
use api::handler::{article, user};
use api::middleware;
use api::repository;
use axum::{
    routing::{get, post, put},
    Router,
};
use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let repo = repository::Repository::new(db_url).await.unwrap();
    let state = AppState { repo };

    let router = Router::new()
        .route("/articles", get(article::find_all))
        .route("/articles/:id", get(article::find_one));

    let token_router = Router::new()
        .route("/user", get(user::find).put(user::update))
        .route("/articles", post(article::create))
        .route(
            "/articles/:id",
            put(article::update).delete(article::delete),
        )
        .route("/articles/:id/publish", post(article::publish))
        .layer(axum::middleware::from_fn(middleware::auth_middleware));

    let app = router.merge(token_router).with_state(state);

    let listner = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();

    axum::serve(listner, app).await.unwrap();
}
