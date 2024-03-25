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
use regex::Regex;
use sea_orm::*;
use serde::{Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let conn: DatabaseConnection = Database::connect(db_url).await.unwrap();

    let state = AppState { conn };

    let router = Router::new()
        .route("/", get(hello_world))
        .route("/greet/:name", get(greet))
        .route("/authorize", get(authorize)) // http://localhost:3000/authorize?response_type=code&state=3&client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback
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
    #[validate(custom(function = "match_code"))]
    pub response_type: String,
    #[validate(length(min = 1, message = "Paramater 'state' can not be empty"))]
    pub state: String,
    #[validate(length(min = 1, message = "Paramater 'client_id' can not be empty"))]
    #[validate(custom(function = "uuid"))]
    pub client_id: String,
    #[validate(length(min = 1, message = "Paramater 'redirect_uri' can not be empty"))]
    #[validate(url)]
    pub redirect_uri: String,
}

pub fn match_code(v: &str) -> Result<(), ValidationError> {
    if v == "code" {
        Ok(())
    } else {
        Err(ValidationError::new(
            "Paramater 'response_type' should be 'code'",
        ))
    }
}

pub fn uuid(id: &str) -> Result<(), ValidationError> {
    // Define the regular expression pattern for UUIDv4
    let pattern =
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .expect("Failed to compile UUID regex pattern");

    if !pattern.is_match(id) {
        let mut error = ValidationError::new("Invalid UUID format");
        error.add_param(std::borrow::Cow::Borrowed("pattern"), &pattern.to_string());
        return Err(error);
    }

    Ok(())
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

async fn authorize(
    Valid(Query(input)): Valid<Query<AuthorizeInput>>,
    state: State<AppState>,
) -> Result<impl IntoResponse, StatusCode> {
    let parsed_uuid = Uuid::parse_str(&input.client_id).unwrap();
    // client_id が そんざいすること
    let client = OAuth2ClientEntity::find_by_id(parsed_uuid)
        .one(&state.conn)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::FORBIDDEN)?;

    // redirect_uri が一致すること
    if input.redirect_uri != client.redirect_uris {
        return Err(StatusCode::FORBIDDEN);
    }

    let template = AuthorizeTemplate {
        state: input.state,
        client_id: client.id.to_string(),
    };

    // リクエストパラメータをセッションに保存する
    // ログインフォームを表示する
    Ok(HtmlTemplate(template))
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
    client_id: String,
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
