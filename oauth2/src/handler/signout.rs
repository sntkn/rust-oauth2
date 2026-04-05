use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
};

use crate::app_state::AppState;
use crate::util::request_context::AuthClaims;

pub async fn invoke(
    State(state): State<AppState>,
    AuthClaims(claims): AuthClaims,
) -> Result<impl IntoResponse, StatusCode> {
    // アクセストークンを破棄
    state
        .repo
        .revoke_token(claims.sub.to_string())
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // リフレッシュトークンを破棄
    state
        .repo
        .revoke_refresh_token_by_token(claims.sub.to_string())
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    Ok(())
}
