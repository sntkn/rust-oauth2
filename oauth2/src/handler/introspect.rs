use axum::{http::StatusCode, response::IntoResponse, Extension, Json};
use jwt::TokenClaims;

use crate::util::jwt;

pub async fn invoke(
    Extension(claims): Extension<TokenClaims>,
) -> Result<impl IntoResponse, StatusCode> {
    Ok(Json(claims))
}
