use crate::app_state::AppState;
use crate::middleware::TokenClaims;
use crate::repository;
use axum::{
    extract::{Extension, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Serialize, Deserialize)]
pub struct User {
    id: Uuid,
    name: String,
    email: String,
}

pub async fn find(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let user = state
        .repo
        .find_user(claims.jti)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::NOT_FOUND)?;

    let data = User {
        id: user.id,
        name: user.name,
        email: user.email,
    };
    let data = serde_json::json!(data);

    Ok(Json(data))
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdateInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'user' can not be empty"))]
    name: Option<String>,

    #[validate(length(min = 1, message = "Paramater 'email' can not be empty"))]
    #[validate(email)]
    email: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    input: Json<UpdateInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let params = repository::EditUserParams {
        name: input.name.clone(),
        email: input.email.clone(),
    };

    let user = state
        .repo
        .edit_user(claims.jti, params)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let data = User {
        id: user.id,
        name: user.name,
        email: user.email,
    };
    let data = serde_json::json!(data);

    Ok(Json(data))
}
