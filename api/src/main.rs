use axum::{
    extract::Path,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

#[tokio::main]
async fn main() {
    let router = Router::new().route("/user", get(handler_json)); // json を返す
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
