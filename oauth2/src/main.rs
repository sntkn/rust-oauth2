use axum::{routing::get, Json, Router};
use serde::Serialize;

#[tokio::main]
async fn main() {
    let router = Router::new().route("/", get(hello_world));
    let listner = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listner, router).await.unwrap();
}

async fn hello_world() -> Json<HelloWorld> {
    let hello = HelloWorld {
        text: "Hello World".to_string(),
    };
    Json(hello)
}

#[derive(Serialize)]
struct HelloWorld {
    text: String,
}
