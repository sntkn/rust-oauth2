mod entity;
mod repository;

use axum::{
    extract::{Extension, Path, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::env;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[derive(Clone)]
struct AppState {
    repo: repository::Repository,
}

#[tokio::main]
async fn main() {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let repo = repository::Repository::new(db_url).await.unwrap();
    let state = AppState { repo };

    let router = Router::new()
        .route("/user", get(find_user).put(edit_user))
        .layer(axum::middleware::from_fn(auth_middleware))
        .with_state(state);

    let listner = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();

    axum::serve(listner, router).await.unwrap();
}

#[derive(Serialize, Deserialize)]
struct User {
    id: Uuid,
    name: String,
    email: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TokenClaims {
    sub: String, // access_token
    jti: Uuid,   // user_id
    exp: i64,
    iat: i64,
}

#[derive(Debug, Deserialize, Validate)]
struct EditUserInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'user' can not be empty"))]
    name: Option<String>,

    #[validate(length(min = 1, message = "Paramater 'email' can not be empty"))]
    #[validate(email)]
    email: Option<String>,
}

async fn find_user(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let user = state
        .repo
        .find_user(claims.jti)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::NOT_FOUND)?;

    let data = User {
        id: user.id,
        name: user.name,
        email: user.email,
    };
    let data = serde_json::json!(data);

    Ok(Json(data))
}

async fn edit_user(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    input: Json<EditUserInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let params = repository::EditUserParams {
        name: input.name.clone(),
        email: input.email.clone(),
    };

    let user = state
        .repo
        .edit_user(claims.jti, params)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let data = User {
        id: user.id,
        name: user.name,
        email: user.email,
    };
    let data = serde_json::json!(data);

    Ok(Json(data))
}

async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = req.headers();
    // Authorization ヘッダからアクセストークン取得
    let authorization = headers
        .get("Authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .unwrap();
    let token = authorization.split(' ').last().unwrap();

    // トークンをAuthにチェックしてもらう
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:3000/introspect")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    if response.status().is_success() {
        let body = response.text().await.unwrap();
        let auth_response: TokenClaims = serde_json::from_str(&body).unwrap();
        println!("Response: {}", body);
        req.extensions_mut().insert(auth_response);
        Ok(next.run(req).await)
    } else {
        println!("Request Failed with status: {}", response.status());
        Err(response.status())
    }
}
