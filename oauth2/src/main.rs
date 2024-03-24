use std::env;
mod entity;

use crate::entity::oauth2_clients::Entity as OAuth2ClientEntity;

use askama::Template;
use axum::{
    extract::{self, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Json, Router,
};
use axum_valid::Valid;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use validator::Validate;

#[tokio::main]
async fn main() {
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let conn: DatabaseConnection = Database::connect(db_url).await.unwrap();

    let state = AppState { conn };

    let router = Router::new()
        .route("/", get(hello_world))
        .route("/greet/:name", get(greet))
        .route("/authorize", get(authorize))
        .with_state(state);
    let listner = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listner, router).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    conn: DatabaseConnection,
}

async fn hello_world(state: State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let client = OAuth2ClientEntity::find().one(&state.conn).await.unwrap();

    match client {
        Some(client) => Ok(Json(HelloWorld {
            text: client.name.to_string(),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Serialize)]
struct HelloWorld {
    text: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct AuthorizeInput {
    #[validate(length(min = 1, message = "Paramater 'response_type' can not be empty"))]
    pub response_type: String,
    #[validate(length(min = 1, message = "Paramater 'state' can not be empty"))]
    pub state: String,
    #[validate(length(min = 1, message = "Paramater 'client_id' can not be empty"))]
    pub client_id: String,
    #[validate(length(min = 1, message = "Paramater 'redirect_uri' can not be empty"))]
    pub redirect_uri: String,
}

//#[async_trait]
//impl<T, S> FromRequest<S> for ValidatedForm<T>
//where
//    T: DeserializeOwned + Validate,
//    S: Send + Sync,
//{
//    type Rejection = (StatusCode, String);//

//    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
//        let Json(value) = Json::<T>::from_request(req, state)
//            .await
//            .map_err(|rejection| {
//                let message = format!("Json parse error: [{}]", rejection);
//                (StatusCode::BAD_REQUEST, message)
//            })?;
//        value.validate().map_err(|rejection| {
//            let message = format!("Validation error: [{}]", rejection).replace('\n', ", ");
//            (StatusCode::BAD_REQUEST, message)
//        })?;
//        Ok(ValidatedForm(value))
//    }
//}

async fn greet(extract::Path(name): extract::Path<String>) -> impl IntoResponse {
    let template = HelloTemplate { name };
    HtmlTemplate(template)
}

async fn authorize(Valid(Query(input)): Valid<Query<AuthorizeInput>>) -> impl IntoResponse {
    let template = AuthorizeTemplate { state: input.state };

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
struct AuthorizeTemplate {
    state: String,
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
