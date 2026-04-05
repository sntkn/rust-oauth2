use axum::{http::StatusCode, response::IntoResponse, Json};

use crate::util::request_context::AuthClaims;

pub async fn invoke(
    AuthClaims(claims): AuthClaims,
) -> Result<impl IntoResponse, StatusCode> {
    Ok(Json(claims))
}
