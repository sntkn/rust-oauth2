use async_session::Session;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use axum_extra::extract::cookie::CookieJar;

use crate::util::jwt::TokenClaims;

#[derive(Clone)]
pub struct SessionContext {
    pub session: Session,
    pub jar: CookieJar,
}

impl<S> FromRequestParts<S> for SessionContext
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let session = parts
            .extensions
            .get::<Session>()
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
        let jar = parts
            .extensions
            .get::<CookieJar>()
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Self { session, jar })
    }
}

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
