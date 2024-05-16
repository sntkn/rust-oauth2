use axum::{
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use jwt::TokenClaims;

use crate::app_state::AppState;
use crate::util::jwt;

pub async fn invoke(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
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
