use async_session::Session;
use axum::{
    extract::{Extension, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use axum_extra::extract::cookie::CookieJar;
use flash_message::FlashMessage;
use regex::Regex;
use serde::{Deserialize, Serialize};
use session_manager::{marshal_to_session, remove_session, unmarshal_from_session};
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::app_state::AppState;
use crate::util::flash_message;
use crate::util::session_manager;

#[derive(Debug, Deserialize, Validate)]
pub struct AuthorizeInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'response_type' can not be empty"))]
    #[validate(custom(function = "match_code"))]
    response_type: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'state' can not be empty"))]
    state: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'client_id' can not be empty"))]
    #[validate(custom(function = "uuid"))]
    client_id: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'redirect_uri' can not be empty"))]
    #[validate(url)]
    redirect_uri: String,
}

fn match_code(v: &str) -> Result<(), ValidationError> {
    if v == "code" {
        Ok(())
    } else {
        Err(ValidationError::new(
            "Paramater 'response_type' should be 'code'",
        ))
    }
}

fn uuid(id: &str) -> Result<(), ValidationError> {
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

    let tera = tera::Tera::new("templates/*").unwrap();

    let mut context = tera::Context::new();
    context.insert("client_id", &client.id.to_string());
    context.insert("title", "Rust OAuth 2.0 Authorization");
    context.insert("email", &input_val.email);
    context.insert("password", &input_val.password);
    context.insert("flash_messages", &messages);

    // ログインフォームを表示する
    let output: Result<String, tera::Error> = tera.render("index.html", &context);
    Ok((jar, axum::response::Html(output.unwrap())))
}
