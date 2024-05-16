use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use jwt::TokenClaims;
use serde::Serialize;

use crate::app_state::AppState;
use crate::util::jwt;

#[derive(Serialize)]
struct UserResponse {
    id: String,
    name: String,
    email: String,
}

pub async fn invoke(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<impl IntoResponse, StatusCode> {
    // ユーザー情報取得
    let user = state
        .repo
        .find_user(claims.jti)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // ユーザー情報返却
    let response = UserResponse {
        id: user.id.to_string(),
        name: user.name.to_string(),
        email: user.email.to_string(),
    };
    Ok(Json(response))
}
