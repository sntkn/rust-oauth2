use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use chrono::Local;
use jsonwebtoken::DecodingKey;
use jwt::decode_token;
use session_manager::manage_session;

use crate::app_state::AppState;
use crate::util::jwt;
use crate::util::session_manager;

pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let headers = req.headers();
    // Authorization ヘッダからアクセストークン取得
    let authorization = headers
        .get("Authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .unwrap();

    let token = authorization.split(' ').last().unwrap();

    // JWTを解析
    let decoding_key = DecodingKey::from_secret(b"some-secret");
    let token_message = decode_token(token, &decoding_key)
        .or(Err(StatusCode::UNAUTHORIZED))?
        .claims;

    // JWTの有効期限をチェック
    if token_message.exp < Local::now().naive_local().and_utc().timestamp() {
        return Err(StatusCode::FORBIDDEN);
    }

    // アクセストークン取得（token and user_id）
    let token_result = state.repo.find_token(token_message.sub.to_string()).await;
    let token = token_result
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if token.user_id != token_message.jti {
        return Err(StatusCode::FORBIDDEN);
    }

    req.extensions_mut().insert(token_message);

    Ok(next.run(req).await)
}

pub async fn session_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (session, jar) = manage_session(&state.store, req.headers()).await;

    req.extensions_mut().insert(session);
    req.extensions_mut().insert(jar);

    Ok(next.run(req).await)
}
