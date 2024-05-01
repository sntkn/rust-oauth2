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
        .route("/user", get(handler_json))
        .layer(axum::middleware::from_fn(auth_middleware));
    let listner = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();
    axum::serve(listner, router).await.unwrap();
}

#[derive(Serialize, Deserialize)]
struct User {
    name: String,
    mail: String,
    age: u32,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TokenClaims {
    sub: String, // access_token
    jti: Uuid,   // user_id
    exp: i64,
    iat: i64,
}

async fn handler_json(Path(id): Path<usize>) -> Json<serde_json::Value> {
    let data = [
        User {
            name: String::from("Taro"),
            mail: String::from("taro@yamada"),
            age: 39,
        },
        User {
            name: String::from("Hanako"),
            mail: String::from("hanako@flower"),
            age: 28,
        },
        User {
            name: String::from("Sachiko"),
            mail: String::from("sachiko@happy"),
            age: 17,
        },
    ];
    let item = &data[id];
    let data = serde_json::json!(item);
    Json(data)
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
        .get("http://localhost:3000/introspect")
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
