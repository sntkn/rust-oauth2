use axum::{debug_handler, extract::State, http::StatusCode, response::IntoResponse, Json};
use chrono::{Duration, Local};
use jwt::{generate_token, TokenClaims};
use serde::{Deserialize, Serialize};
use str::generate_random_string;
use validator::Validate;

use crate::app_state::AppState;
use crate::repository::db_repository;
use crate::util::jwt;
use crate::util::str;
use crate::validation::validate_uuid;

#[derive(Debug, Deserialize, Validate)]
pub struct CreateTokenInput {
    #[serde(default)]
    #[validate(custom(function = "validate_uuid"))]
    code: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'grant_type' can not be empty"))]
    grant_type: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'refresh_token' can not be empty"))]
    refresh_token: String,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: i64,
}

#[debug_handler]
pub async fn invoke(
    State(state): State<AppState>,
    input: Json<CreateTokenInput>,
) -> Result<impl IntoResponse, StatusCode> {
    // issue token
    if input.grant_type == "authorization_code" {
        if input.code.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        // コードの存在チェック
        let code = state
            .repo
            .find_code(input.code.to_string())
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or(StatusCode::FORBIDDEN)?;
        // コードの有効期限チェック
        if code.expires_at.unwrap() < Local::now().naive_local() {
            return Err(StatusCode::FORBIDDEN);
        }
        // トークン登録
        let token = generate_random_string(32);
        let token_expires_at = Local::now().naive_local() + Duration::minutes(10);
        let now = Local::now().naive_local().into();
        let params = db_repository::CreateTokenParams {
            access_token: token.to_string(),
            user_id: code.user_id,
            client_id: code.client_id,
            expires_at: token_expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_token(params).await.unwrap(); // TODO

        // トークン生成(JWT)
        let token_claims = TokenClaims {
            sub: token.to_string(),
            jti: code.user_id,
            exp: token_expires_at.and_utc().timestamp(),
            iat: now.unwrap().and_utc().timestamp(),
        };
        let access_jwt = generate_token(&token_claims, b"some-secret").unwrap();

        // コード無効化
        let _ = state.repo.revoke_code(code.code.to_string()).await.unwrap();

        // リフレッシュトークン生成
        let expires_at = Local::now().naive_local() + Duration::days(90);
        let now = Local::now().naive_local().into();
        let refresh_token = generate_random_string(64);
        let params = db_repository::CreateRefreshTokenParams {
            refresh_token: refresh_token.to_string(),
            access_token: token.to_string(),
            expires_at: expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_refresh_token(params).await.unwrap(); // TODO

        // トークン返却
        let response = TokenResponse {
            access_token: access_jwt,
            refresh_token: refresh_token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: token_expires_at.and_utc().timestamp(),
        };
        Ok(Json(response))
    // refresh token
    } else if input.grant_type == "refresh_token" {
        // リフレッシュトークンの存在チェック
        let old_refresh_token = state
            .repo
            .find_refresh_token(input.refresh_token.to_string())
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // 有効期限切れチェック
        if old_refresh_token.expires_at.unwrap() < Local::now().naive_local() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        // old token 取得
        let old_token = state
            .repo
            .find_token(old_refresh_token.access_token.to_string())
            .await
            .unwrap()
            .unwrap();

        let new_access_token = generate_random_string(32);
        let token_expires_at = Local::now().naive_local() + Duration::minutes(10);
        let now = Local::now().naive_local().into();
        let params = db_repository::CreateTokenParams {
            access_token: new_access_token.to_string(),
            user_id: old_token.user_id,
            client_id: old_token.client_id,
            expires_at: token_expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_token(params).await.unwrap(); // TODO

        // リフレッシュトークン
        let expires_at = Local::now().naive_local() + Duration::days(90);
        let now = Local::now().naive_local().into();
        let refresh_token = generate_random_string(64);
        let params = db_repository::CreateRefreshTokenParams {
            refresh_token: refresh_token.to_string(),
            access_token: new_access_token.to_string(),
            expires_at: expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = state.repo.create_refresh_token(params).await.unwrap(); // TODO

        // リフレッシュトークン、トークン無効化
        let _ = state
            .repo
            .revoke_refresh_token(old_refresh_token.refresh_token.to_string())
            .await
            .unwrap();
        let _ = state
            .repo
            .revoke_token(old_token.access_token.to_string())
            .await
            .unwrap();

        // トークン生成(JWT)
        let token_claims = TokenClaims {
            sub: new_access_token.to_string(),
            jti: old_token.user_id,
            exp: token_expires_at.and_utc().timestamp(),
            iat: now.unwrap().and_utc().timestamp(),
        };
        let access_jwt = generate_token(&token_claims, b"some-secret").unwrap();

        // トークン返却
        let response = TokenResponse {
            access_token: access_jwt,
            refresh_token: refresh_token.to_string(),
            token_type: "Bearer".to_string(),
            expires_in: token_expires_at.and_utc().timestamp(),
        };
        Ok(Json(response))
    } else {
        return Err(StatusCode::BAD_REQUEST);
    }
}
