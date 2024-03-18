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
        .route("/greet/:name", get(greet));
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

#[derive(Template)]
#[template(path = "hello.html")]
struct HelloTemplate {
    name: String,
}

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
