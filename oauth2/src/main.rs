use std::env;
mod entity;
mod repository;

use askama::Template;
use async_redis_session::RedisSessionStore;
use async_session::{Session, SessionStore};
use axum::{
    debug_handler,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use axum_extra::extract::cookie::{Cookie as EntityCookie, CookieJar};
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::{Duration, Local};
use jsonwebtoken::{
    decode, encode, errors::Error as JwtError, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let store = RedisSessionStore::new("redis://localhost:6379/").unwrap();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let repo = repository::Repository::new(db_url).await.unwrap();

    let state = AppState { store, repo };

    let router = Router::new()
        .route("/authorize", get(authorize)) // http://localhost:3000/authorize?response_type=code&state=3&client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback
        .route("/authorization", post(authorization))
        .route("/token", post(create_token))
        .route("/me", get(me))
        //.layer(middleware::from_fn_with_state(
        //    state.clone(),
        //    print_request_response,
        //))
        .with_state(state);
    let listner = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listner, router).await.unwrap();
}

//async fn print_request_response(
//    State(state): State<AppState>,
//    req: Request,
//    next: Next,
//) -> Result<(CookieJar, impl IntoResponse), (StatusCode, String)> {
//    println!("================== middleware =================");
//    let session = Session::new();
//    let cookie_value = state.store.store_session(session).await.unwrap().unwrap();
//
//    let jar = CookieJar::from_headers(req.headers());
//
//    let cc = EntityCookie::new("session_id", cookie_value);
//
//    let cookie = jar.get("session_id").unwrap_or(&cc);
//
//    let j = jar.clone().add(cookie.clone());
//
//    Ok((j, next.run(req).await))
//}

async fn load_session(store: &RedisSessionStore, headers: &HeaderMap) -> (Session, CookieJar) {
    let session = Session::new();
    let jar = CookieJar::from_headers(headers);
    let cookie = {
        let cookie_value = store.store_session(session).await.unwrap().unwrap();
        let cookie_entity = EntityCookie::new("session_id", cookie_value);
        let cookie = jar.get("session_id").unwrap_or(&cookie_entity);
        cookie.clone()
    };
    let jar = jar.add(cookie.clone());
    let session = store
        .load_session(cookie.value().to_string())
        .await
        .unwrap()
        .unwrap();
    (session, jar)
}

async fn unmarshal_from_session<T: DeserializeOwned>(session: &Session, key: String) -> T {
    let sess_val = session.get::<String>(&key).unwrap_or("{}".to_string());
    serde_json::from_str(&sess_val).unwrap()
}

async fn marshal_to_session<T: Serialize>(
    store: &RedisSessionStore,
    session: &Session,
    key: String,
    val: &T,
) {
    let v = serde_json::to_string(&val).unwrap();
    let mut session_clone = session.clone();

    session_clone.insert(&key.to_string(), v).unwrap();

    store.store_session(session_clone).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    //session: SessionToken,
    store: RedisSessionStore,
    repo: repository::Repository,
}

#[derive(Debug, Deserialize, Validate)]
struct AuthorizeInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'response_type' can not be empty"))]
    #[validate(custom(function = "match_code"))]
    response_type: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'state' can not be empty"))]
    state: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'client_id' can not be empty"))]
    #[validate(custom(function = "uuid"))]
    client_id: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'redirect_uri' can not be empty"))]
    #[validate(url)]
    redirect_uri: String,
}
#[derive(Debug, Deserialize)]
struct AuthorizeValue {
    response_type: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize, Validate)]
struct AuthorizationInput {
    #[validate(length(min = 1, message = "Paramater 'email' can not be empty"))]
    #[validate(email)]
    email: String,

    #[validate(length(min = 1, message = "Paramater 'password' can not be empty"))]
    #[validate(custom(function = "validate_password"))]
    password: String,
}

#[derive(Debug, Deserialize, Validate)]
struct CreateTokenInput {
    #[serde(default)]
    #[validate(custom(function = "uuid"))]
    code: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'grant_type' can not be empty"))]
    grant_type: String,

    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'refresh_token' can not be empty"))]
    refresh_token: String,
}

#[derive(Serialize)]
struct AuthorizeJson {
    client_id: String,
    redirect_uri: String,
    state: String,
    response_type: String,
}

fn validate_password(password: &str) -> Result<(), ValidationError> {
    let mut has_whitespace = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;

    for c in password.chars() {
        has_whitespace |= c.is_whitespace();
        has_lower |= c.is_lowercase();
        has_upper |= c.is_uppercase();
        has_digit |= c.is_ascii_digit();
    }
    if !has_whitespace && has_upper && has_lower && has_digit && password.len() >= 8 {
        Ok(())
    } else {
        Err(ValidationError::new("Password Validation Failed"))
    }
}

fn match_code(v: &str) -> Result<(), ValidationError> {
    if v == "code" {
        Ok(())
    } else {
        Err(ValidationError::new(
            "Paramater 'response_type' should be 'code'",
        ))
    }
}

fn uuid(id: &str) -> Result<(), ValidationError> {
    // Define the regular expression pattern for UUIDv4
    let pattern =
        Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
            .expect("Failed to compile UUID regex pattern");

    if !pattern.is_match(id) {
        let mut error = ValidationError::new("Invalid UUID format");
        error.add_param(std::borrow::Cow::Borrowed("pattern"), &pattern.to_string());
        return Err(error);
    }

    Ok(())
}

//#[async_trait]
//impl<T, S> FromRequest<S> for ValidatedForm<T>
//where
//    T: DeserializeOwned + Validate,
//    S: Send + Sync,
//{
//    type Rejection = (StatusCode, String);//

//    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
//        let Json(value) = Json::<T>::from_request(req, state)
//            .await
//            .map_err(|rejection| {
//                let message = format!("Json parse error: [{}]", rejection);
//                (StatusCode::BAD_REQUEST, message)
//            })?;
//        value.validate().map_err(|rejection| {
//            let message = format!("Validation error: [{}]", rejection).replace('\n', ", ");
//            (StatusCode::BAD_REQUEST, message)
//        })?;
//        Ok(ValidatedForm(value))
//    }
//}

async fn authorize(
    state: State<AppState>,
    headers: HeaderMap,
    Query(mut input): Query<AuthorizeInput>,
) -> Result<(CookieJar, impl IntoResponse), StatusCode> {
    let (session, jar) = load_session(&state.store, &headers).await;
    // セッションをまず取得して、さらにリクエストパラメータがあったら上書きする
    let auth_val: AuthorizeValue = unmarshal_from_session(&session, "auth".to_string()).await;

    if input.response_type.is_empty() && auth_val.response_type.is_some() {
        input.response_type = auth_val.response_type.unwrap();
    }
    if input.state.is_empty() && auth_val.state.is_some() {
        input.state = auth_val.state.unwrap();
    }
    if input.client_id.is_empty() && auth_val.client_id.is_some() {
        input.client_id = auth_val.client_id.unwrap();
    }
    if input.redirect_uri.is_empty() && auth_val.redirect_uri.is_some() {
        input.redirect_uri = auth_val.redirect_uri.unwrap();
    }

    if let Err(errors) = input.validate() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let parsed_uuid = Uuid::parse_str(&input.client_id).unwrap();
    // client_id が そんざいすること
    let client = &state
        .repo
        .find_client(parsed_uuid)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::FORBIDDEN)?;

    // redirect_uri が一致すること
    let redirect_uri = input.redirect_uri;
    if redirect_uri != client.redirect_uris {
        return Err(StatusCode::FORBIDDEN);
    }

    let template = AuthorizeTemplate {
        state: input.state.clone(),
        client_id: client.id.to_string(),
    };

    let json = AuthorizeJson {
        client_id: client.id.to_string(),
        redirect_uri,
        state: input.state,
        response_type: input.response_type,
    };

    marshal_to_session(&state.store, &session, "auth".to_string(), &json).await;

    // リクエストパラメータをセッションに保存する
    //ssession.insert("auth", val).unwrap();
    let val = session.get::<String>("auth").unwrap();
    state.store.store_session(session).await.unwrap();
    // ログインフォームを表示する
    Ok((jar, HtmlTemplate(template)))
}

// ログインチェック
// ログイン NG の場合、ログインフォームにリダイレクト
// OK の場合、セッションを発行しログイン状態にする
// 認可コードを生成する
// 認可コードとstate を保存する
// redirect_uri に認可コードと共にリダイレクトする
#[debug_handler]
async fn authorization(
    state: State<AppState>,
    headers: HeaderMap,
    input: Form<AuthorizationInput>,
) -> Result<impl IntoResponse, StatusCode> {
    if let Err(errors) = input.validate() {
        println!("{:#?}", errors);
        Ok(Redirect::to("/autorize"))
    } else {
        let (session, _jar) = load_session(&state.store, &headers).await;
        let auth: AuthorizeValue = unmarshal_from_session(&session, "auth".to_string()).await;
        let user = &state
            .repo
            .find_user_by_email(input.email.to_string())
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or(StatusCode::FORBIDDEN)?; // TODO: redirect to authorize

        if !verify(&input.password, &user.password).unwrap() {
            let pp = hash(&input.password, DEFAULT_COST).unwrap();
            println!("password: {}, {}", pp, user.password);
            return Err(StatusCode::FORBIDDEN); // TODO: redirect to authorize
        }
        let code = generate_random_string(32);
        let datetime = Local::now().naive_local().into();
        let expires_at = Local::now().naive_local() + Duration::hours(1);
        let client_id = Uuid::parse_str(&auth.client_id.unwrap()).unwrap();
        let redirect_uri = auth.redirect_uri.unwrap();
        let params = repository::CreateCodeParams {
            code: code.clone(),
            user_id: user.id,
            client_id,
            expires_at: expires_at.into(),
            redirect_uri: redirect_uri.clone(),
            created_at: datetime,
            updated_at: datetime,
        };

        let _ = &state.repo.create_code(params).await.unwrap(); // TODO: check

        let qs = vec![("code", code.to_string())];
        let url = Url::parse_with_params(&redirect_uri, qs).unwrap();

        //println!("{:#?}", auth);
        Ok(Redirect::to(url.as_ref()))
    }
}

#[debug_handler]
async fn create_token(
    state: State<AppState>,
    input: Json<CreateTokenInput>,
) -> Result<impl IntoResponse, StatusCode> {
    // issue token
    if input.grant_type == "authorization_code" {
        if input.code.is_empty() {
            return Err(StatusCode::BAD_REQUEST);
        }
        // コードの存在チェック
        let code = &state
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
        let params = repository::CreateTokenParams {
            access_token: token.to_string(),
            user_id: code.user_id,
            client_id: code.client_id,
            expires_at: token_expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = &state.repo.create_token(params).await.unwrap(); // TODO

        // トークン生成(JWT)
        let token_claims = TokenClaims {
            sub: token.to_string(),
            jti: code.user_id,
            exp: token_expires_at.and_utc().timestamp(),
            iat: now.unwrap().and_utc().timestamp(),
        };
        let access_jwt = generate_token(&token_claims, b"some-secret").unwrap();

        // コード無効化
        let _ = &state.repo.revoke_code(code.code.to_string()).await.unwrap();

        // リフレッシュトークン生成
        let expires_at = Local::now().naive_local() + Duration::days(90);
        let now = Local::now().naive_local().into();
        let refresh_token = generate_random_string(64);
        let params = repository::CreateRefreshTokenParams {
            refresh_token: refresh_token.to_string(),
            access_token: token.to_string(),
            expires_at: expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = &state.repo.create_refresh_token(params).await.unwrap(); // TODO

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
        let old_refresh_token = &state
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
        let old_token = &state
            .repo
            .find_token(old_refresh_token.access_token.to_string())
            .await
            .unwrap()
            .unwrap();

        let new_access_token = generate_random_string(32);
        let token_expires_at = Local::now().naive_local() + Duration::minutes(10);
        let now = Local::now().naive_local().into();
        let params = repository::CreateTokenParams {
            access_token: new_access_token.to_string(),
            user_id: old_token.user_id,
            client_id: old_token.client_id,
            expires_at: token_expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = &state.repo.create_token(params).await.unwrap(); // TODO

        // リフレッシュトークン
        let expires_at = Local::now().naive_local() + Duration::days(90);
        let now = Local::now().naive_local().into();
        let refresh_token = generate_random_string(64);
        let params = repository::CreateRefreshTokenParams {
            refresh_token: refresh_token.to_string(),
            access_token: new_access_token.to_string(),
            expires_at: expires_at.into(),
            created_at: now,
            updated_at: now,
        };
        let _ = &state.repo.create_refresh_token(params).await.unwrap(); // TODO

        // リフレッシュトークン、トークン無効化
        let _ = &state
            .repo
            .revoke_refresh_token(old_refresh_token.refresh_token.to_string())
            .await
            .unwrap();
        let _ = &state
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

async fn me(state: State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse, StatusCode> {
    // Authorization ヘッダからアクセストークン取得
    let authorization = headers.get("Authorization").unwrap().to_str().unwrap();
    let token = authorization.split(' ').last().unwrap();
    println!("{}", token);

    // JWTを解析
    let decoding_key = DecodingKey::from_secret(b"some-secret");
    let token_message =
        decode::<TokenClaims>(token, &decoding_key, &Validation::new(Algorithm::HS256))
            .unwrap()
            .claims;

    // JWTの有効期限をチェック
    if token_message.exp < Local::now().naive_local().and_utc().timestamp() {
        return Err(StatusCode::FORBIDDEN);
    }

    println!("{}", token_message.sub);

    // アクセストークン取得（token and user_id）
    let token = &state
        .repo
        .find_token(token_message.sub)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if token.user_id != token_message.jti {
        return Err(StatusCode::FORBIDDEN);
    }

    // ユーザー情報取得
    let user = &state
        .repo
        .find_user(token_message.jti)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // ユーザー情報返却
    let response = UserResponse {
        id: user.id.to_string(),
        name: user.name.to_string(),
        email: user.email.to_string(),
    };
    Ok(Json(response))
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenClaims {
    sub: String, // access_token
    jti: Uuid,   // user_id
    exp: i64,
    iat: i64,
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    expires_in: i64,
}

#[derive(Serialize)]
struct UserResponse {
    id: String,
    name: String,
    email: String,
}

fn generate_token<T: Serialize>(claims: &T, secret: &[u8]) -> Result<String, JwtError> {
    let encoding_key = EncodingKey::from_secret(secret);
    encode(&Header::default(), claims, &encoding_key)
}

fn generate_random_string(len: usize) -> String {
    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect();
    String::from_utf8(random_bytes).unwrap()
}

#[derive(Template)]
#[template(path = "hello.html")]
struct HelloTemplate {
    name: String,
}

#[derive(Template)]
#[template(path = "authorize.html")]
struct AuthorizeTemplate {
    state: String,
    client_id: String,
}

struct HtmlTemplate<T>(T);

impl<T> IntoResponse for HtmlTemplate<T>
where
    T: Template,
{
    fn into_response(self) -> Response {
        match self.0.render() {
            Ok(html) => Html(html).into_response(),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to render template. Error: {}", err),
            )
                .into_response(),
        }
    }
}
