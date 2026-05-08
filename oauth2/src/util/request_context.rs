use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};

use crate::util::jwt::TokenClaims;

#[derive(Clone)]
pub struct AuthClaims(pub TokenClaims);

impl<S> FromRequestParts<S> for AuthClaims
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let claims = parts
            .extensions
            .get::<TokenClaims>()
            .cloned()
            .ok_or(StatusCode::UNAUTHORIZED)?;

        Ok(Self(claims))
    }
}
