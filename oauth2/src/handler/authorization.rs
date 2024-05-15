use async_session::Session;
use axum::{
    debug_handler,
    extract::{Extension, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Form,
};
use bcrypt::verify;
use chrono::{Duration, Local};
use flash_message::FlashMessage;
use serde::{Deserialize, Serialize};
use session_manager::{marshal_to_session, unmarshal_from_session};
use str::generate_random_string;
use url::Url;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::app_state::AppState;
use crate::repository::db_repository;
use crate::util::flash_message;
use crate::util::session_manager;
use crate::util::str;

#[derive(Debug, Deserialize, Serialize, Default)]
struct AuthorizationInputValue {
    email: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize, Validate, Serialize)]
pub struct AuthorizationInput {
    #[validate(length(min = 1, message = "Paramater 'email' can not be empty"))]
    #[validate(email)]
    email: String,

    #[validate(length(min = 1, message = "Paramater 'password' can not be empty"))]
    #[validate(custom(function = "validate_password"))]
    password: String,
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let mut has_whitespace = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_lower |= c.is_lowercase();
        has_upper |= c.is_uppercase();
        has_digit |= c.is_ascii_digit();
    }
    if !has_whitespace && has_upper && has_lower && has_digit && password.len() >= 8 {
        Ok(())
    } else {
        Err(ValidationError::new("Password Validation Failed"))
    }
}

#[derive(Debug, Deserialize, Default, Serialize)]
struct AuthorizeValue {
    response_type: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
}

// ログインチェック
// ログイン NG の場合、ログインフォームにリダイレクト
// OK の場合、セッションを発行しログイン状態にする
// 認可コードを生成する
// 認可コードとstate を保存する
// redirect_uri に認可コードと共にリダイレクトする
#[debug_handler]
pub async fn invoke(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Form(input): Form<AuthorizationInput>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth: AuthorizeValue = unmarshal_from_session(&session, "auth".to_string()).await;

    marshal_to_session(
        &state.store,
        &session,
        "authorization_input".to_string(),
        &input,
    )
    .await;

    let mut flash_message = FlashMessage::new(&state.store, &session).await;

    if let Err(errors) = input.validate() {
        for (field, errors) in errors.field_errors() {
            for error in errors {
                flash_message.push(format!("{}: {}", field, error.code));
            }
        }
        flash_message.store().await;
        Ok(Redirect::to("/authorize"))
    } else {
        let user_result = state
            .repo
            .find_user_by_email(input.email.to_string())
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

        let user = match user_result {
            Some(u) => u,
            None => {
                flash_message.push("Login failed: user not match".to_string());
                flash_message.store().await;
                return Ok(Redirect::to("authorization"));
            }
        };

        if !verify(&input.password, &user.password).unwrap() {
            flash_message.push("Login failed: password not match".to_string());
            flash_message.store().await;

            return Ok(Redirect::to("authorization"));
        }

        let code = generate_random_string(32);
        let datetime = Local::now().naive_local().into();
        let expires_at = Local::now().naive_local() + Duration::hours(1);
        let client_id = Uuid::parse_str(&auth.client_id.unwrap()).unwrap();
        let redirect_uri = auth.redirect_uri.unwrap();
        let params = db_repository::CreateCodeParams {
            code: code.clone(),
            user_id: user.id,
            client_id,
            expires_at: expires_at.into(),
            redirect_uri: redirect_uri.clone(),
            created_at: datetime,
            updated_at: datetime,
        };

        let _ = state.repo.create_code(params).await.unwrap(); // TODO: check

        let qs = vec![("code", code.to_string())];
        let url = Url::parse_with_params(&redirect_uri, qs).unwrap();

        //println!("{:#?}", auth);
        Ok(Redirect::to(url.as_ref()))
    }
}
