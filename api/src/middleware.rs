use axum::{extract::Request, http::StatusCode, middleware::Next, response::Response};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenClaims {
    pub sub: String, // access_token
    pub jti: Uuid,   // user_id
    pub exp: i64,
    pub iat: i64,
}

pub async fn auth_middleware(mut req: Request, next: Next) -> Result<Response, StatusCode> {
    let headers = req.headers();
    // Authorization ヘッダからアクセストークン取得
    let authorization = headers
        .get("Authorization")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .unwrap();
    let token = authorization.split(' ').last().unwrap();

    // トークンをAuthにチェックしてもらう
    let client = reqwest::Client::new();
    let response = client
        .post("http://localhost:3000/introspect")
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    if response.status().is_success() {
        let body = response.text().await.unwrap();
        let auth_response: TokenClaims = serde_json::from_str(&body).unwrap();
        println!("Response: {}", body);
        req.extensions_mut().insert(auth_response);
        Ok(next.run(req).await)
    } else {
        println!("Request Failed with status: {}", response.status());
        Err(response.status())
    }
}
