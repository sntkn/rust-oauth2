use askama::Template;
use axum::{
    extract,
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::Serialize;

#[tokio::main]
async fn main() {
    let router = Router::new()
        .route("/", get(hello_world))
        .route("/greet/:name", get(greet))
        .route("/authorize", get(authorize));
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

async fn greet(extract::Path(name): extract::Path<String>) -> impl IntoResponse {
    let template = HelloTemplate { name };
    HtmlTemplate(template)
}

async fn authorize() -> impl IntoResponse {
    let template = AuthorizeTemplate {};
    // validattion
    // response type が code であること
    // state が 存在すること
    // client_id が そんざいすること
    // redirect_uri が一致すること

    // リクエストパラメータをセッションに保存する
    // ログインフォームを表示する

    HtmlTemplate(template)
}

// ログインチェック
// ログイン NG の場合、ログインフォームにリダイレクト
// OK の場合、セッションを発行しログイン状態にする
// 認可コードを生成する
// 認可コードとstate を保存する
// redirect_uri に認可コードと共にリダイレクトする

#[derive(Template)]
#[template(path = "hello.html")]
struct HelloTemplate {
    name: String,
}

#[derive(Template)]
#[template(path = "authorize.html")]
struct AuthorizeTemplate {}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}
