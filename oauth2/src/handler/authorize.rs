use async_session::Session;
use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::extract::cookie::CookieJar;
use flash_message::FlashMessage;
use serde::{Deserialize, Serialize};
use session_manager::{marshal_to_session, remove_session, unmarshal_from_session};
use uuid::Uuid;
use validator::Validate;

use crate::app_state::AppState;
use crate::util::flash_message;
use crate::util::session_manager;
use crate::validation::{validate_code, validate_uuid};

#[derive(Debug, Deserialize, Validate)]
pub struct AuthorizeInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'response_type' can not be empty"))]
    #[validate(custom(function = "validate_code"))]
    response_type: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'state' can not be empty"))]
    state: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'client_id' can not be empty"))]
    #[validate(custom(function = "validate_uuid"))]
    client_id: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'redirect_uri' can not be empty"))]
    #[validate(url)]
    redirect_uri: String,
}

#[derive(Debug, Deserialize, Default, Serialize)]
struct AuthorizeValue {
    response_type: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct AuthorizationInputValue {
    email: Option<String>,
    password: Option<String>,
}

#[derive(Serialize)]
struct AuthorizeJson {
    client_id: String,
    redirect_uri: String,
    state: String,
    response_type: String,
}

pub async fn invoke(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Extension(jar): Extension<CookieJar>,
    Query(mut input): Query<AuthorizeInput>,
) -> Result<(CookieJar, impl IntoResponse), StatusCode> {
    // セッションをまず取得して、さらにリクエストパラメータがあったら上書きする
    let auth_val: AuthorizeValue = unmarshal_from_session(&session, "auth".to_string()).await;

    if input.response_type.is_empty() && auth_val.response_type.is_some() {
        input.response_type = auth_val.response_type.unwrap();
    }
    if input.state.is_empty() && auth_val.state.is_some() {
        input.state = auth_val.state.unwrap();
    }
    if input.client_id.is_empty() && auth_val.client_id.is_some() {
        input.client_id = auth_val.client_id.unwrap();
    }
    if input.redirect_uri.is_empty() && auth_val.redirect_uri.is_some() {
        input.redirect_uri = auth_val.redirect_uri.unwrap();
    }

    if let Err(errors) = input.validate() {
        println!("{:#?}", errors);
        return Err(StatusCode::UNAUTHORIZED);
    }

    let parsed_uuid = Uuid::parse_str(&input.client_id).unwrap();
    // client_id が そんざいすること
    let client = state
        .repo
        .find_client(parsed_uuid)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::FORBIDDEN)?;

    // redirect_uri が一致すること
    let redirect_uri = input.redirect_uri;
    if redirect_uri != client.redirect_uris {
        return Err(StatusCode::FORBIDDEN);
    }

    let json = AuthorizeJson {
        client_id: client.id.to_string(),
        redirect_uri,
        state: input.state,
        response_type: input.response_type,
    };

    marshal_to_session(&state.store, &session, "auth".to_string(), &json).await;

    let input_val: AuthorizationInputValue =
        unmarshal_from_session(&session, "authorization_input".to_string()).await;

    remove_session(&state.store, &session, "authorization_input".to_string()).await;

    let mut flash_message = FlashMessage::new(&state.store, &session).await;

    let messages = flash_message.pull().await;

    let tera = tera::Tera::new("templates/**/*").unwrap();

    let mut context = tera::Context::new();
    context.insert("client_id", &client.id.to_string());
    context.insert("title", "Rust OAuth 2.0 Authorization");
    context.insert("email", &input_val.email);
    context.insert("password", &input_val.password);
    context.insert("flash_messages", &messages);

    // ログインフォームを表示する
    match tera.render("index.html", &context) {
        Ok(output) => Ok((jar, axum::response::Html(output))),
        Err(e) => {
            eprintln!("Error rendering template: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}
