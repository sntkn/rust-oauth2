use std::env;

use async_redis_session::RedisSessionStore;
use async_session::Session;
use axum::{
    debug_handler,
    extract::{Extension, Query, Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use axum_extra::extract::cookie::CookieJar;
use bcrypt::verify;
use chrono::{Duration, Local};
use jsonwebtoken::{
    decode, encode, errors::Error as JwtError, Algorithm, DecodingKey, EncodingKey, Header,
    Validation,
};
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use session_manager::{manage_session, marshal_to_session, remove_session, unmarshal_from_session};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use url::Url;
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::repository::db_repository;
use crate::util::session_manager;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let store = RedisSessionStore::new("redis://localhost:6379/").unwrap();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let repo = db_repository::Repository::new(db_url).await.unwrap();

    let state = AppState { store, repo };

    let session_router = Router::new()
        .route("/authorize", get(authorize)) // http://localhost:3000/authorize?response_type=code&state=3&client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback
        .route("/authorization", post(authorization))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            session_middleware,
        ));
    let token_router = Router::new().route("/token", post(create_token));
    let auth_router = Router::new()
        .route("/me", get(me).put(edit_user))
        .route("/signout", post(signout))
        .route("/introspect", post(introspect))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = session_router
        .merge(token_router)
        .merge(auth_router)
        .with_state(state);

    let listner = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listner, app).await.unwrap();
}

async fn auth_middleware(
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
    let token_message =
        decode::<TokenClaims>(token, &decoding_key, &Validation::new(Algorithm::HS256))
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

async fn session_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let (session, jar) = manage_session(&state.store, req.headers()).await;

    req.extensions_mut().insert(session);
    req.extensions_mut().insert(jar);

    Ok(next.run(req).await)
}

//#[derive(Clone)]
//struct SessionData {
//    store: Arc<RedisSessionStore>,
//    session: Session,
//    jar: CookieJar,
//}
//
//impl SessionData {
//    async fn new(store: Arc<RedisSessionStore>, jar: CookieJar) -> SessionData {
//        let session = Session::new();
//        let cookie = {
//            let cookie_value = store.store_session(session.clone()).await.unwrap().unwrap();
//            let cookie_entity = EntityCookie::new("session_id", cookie_value);
//            let cookie = jar.get("session_id").unwrap_or(&cookie_entity);
//            cookie.clone()
//        };
//        let jar = jar.add(cookie.clone());
//        let session = store
//            .load_session(cookie.value().to_string())
//            .await
//            .unwrap()
//            .unwrap();
//        SessionData {
//            store,
//            session,
//            jar,
//        }
//    }
//
//    async fn unmarshal_from_session<T: DeserializeOwned + Serialize + Default>(
//        &mut self,
//        key: String,
//    ) -> T {
//        let sess_val =
//            self.session.get::<String>(&key).unwrap_or_else(|| {
//                match serde_json::to_value(&T::default()) {
//                    Ok(val) => match val {
//                        Value::Array(_) => "[]".to_string(),
//                        _ => "{}".to_string(),
//                    },
//                    Err(_) => "{}".to_string(),
//                }
//            });
//        serde_json::from_str(&sess_val).unwrap()
//    }
//
//    async fn marshal_to_session<T: Serialize>(&mut self, key: String, val: &T) {
//        let v = serde_json::to_string(&val).unwrap();
//        let mut session_clone = self.session.clone();
//
//        session_clone.insert(&key.to_string(), v).unwrap();
//
//        self.store.store_session(session_clone).await.unwrap();
//    }
//
//    async fn remove_session(&mut self, key: String) {
//        let mut session_clone = self.session.clone();
//
//        session_clone.remove(&key.to_string());
//
//        self.store.store_session(session_clone).await.unwrap();
//    }
//}

struct FlashMessage<'a> {
    store: &'a RedisSessionStore,
    session: &'a Session,
    messages: Vec<String>,
}

impl<'a> FlashMessage<'a> {
    async fn new(store: &'a RedisSessionStore, session: &'a Session) -> FlashMessage<'a> {
        FlashMessage {
            store,
            session,
            messages: Vec::new(),
        }
    }

    fn push(&mut self, message: String) {
        self.messages.push(message);
    }

    async fn store(&mut self) {
        marshal_to_session(
            self.store,
            self.session,
            "flash_message".to_string(),
            &self.messages,
        )
        .await;
    }

    async fn pull(&mut self) -> Vec<String> {
        let val: Vec<String> =
            unmarshal_from_session(self.session, "flash_message".to_string()).await;
        remove_session(self.store, self.session, "flash_message".to_string()).await;
        val
    }
}

#[derive(Clone)]
struct AppState {
    //session: SessionToken,
    store: RedisSessionStore,
    repo: db_repository::Repository,
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

#[derive(Debug, Deserialize, Default, Serialize)]
struct AuthorizeValue {
    response_type: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
struct AuthorizationInputValue {
    email: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize, Validate, Serialize)]
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

#[derive(Debug, Deserialize, Validate)]
struct EditUserInput {
    #[validate(length(
        min = 1,
        max = 100,
        message = "Parameter 'name' must be between 1 and 100 characters"
    ))]
    name: String,
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

async fn authorize(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Extension(jar): Extension<CookieJar>,
    Query(mut input): Query<AuthorizeInput>,
) -> Result<(CookieJar, impl IntoResponse), StatusCode> {
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
        println!("{:#?}", errors);
        return Err(StatusCode::UNAUTHORIZED);
    }

    let parsed_uuid = Uuid::parse_str(&input.client_id).unwrap();
    // client_id が そんざいすること
    let client = state
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

    let json = AuthorizeJson {
        client_id: client.id.to_string(),
        redirect_uri,
        state: input.state,
        response_type: input.response_type,
    };

    marshal_to_session(&state.store, &session, "auth".to_string(), &json).await;

    let input_val: AuthorizationInputValue =
        unmarshal_from_session(&session, "authorization_input".to_string()).await;

    remove_session(&state.store, &session, "authorization_input".to_string()).await;

    let mut flash_message = FlashMessage::new(&state.store, &session).await;

    let messages = flash_message.pull().await;

    let tera = tera::Tera::new("templates/*").unwrap();

    let mut context = tera::Context::new();
    context.insert("client_id", &client.id.to_string());
    context.insert("title", "Rust OAuth 2.0 Authorization");
    context.insert("email", &input_val.email);
    context.insert("password", &input_val.password);
    context.insert("flash_messages", &messages);

    // ログインフォームを表示する
    let output: Result<String, tera::Error> = tera.render("index.html", &context);
    Ok((jar, axum::response::Html(output.unwrap())))
}

// ログインチェック
// ログイン NG の場合、ログインフォームにリダイレクト
// OK の場合、セッションを発行しログイン状態にする
// 認可コードを生成する
// 認可コードとstate を保存する
// redirect_uri に認可コードと共にリダイレクトする
#[debug_handler]
async fn authorization(
    State(state): State<AppState>,
    Extension(session): Extension<Session>,
    Form(input): Form<AuthorizationInput>,
) -> Result<impl IntoResponse, StatusCode> {
    let auth: AuthorizeValue = unmarshal_from_session(&session, "auth".to_string()).await;

    marshal_to_session(
        &state.store,
        &session,
        "authorization_input".to_string(),
        &input,
    )
    .await;

    let mut flash_message = FlashMessage::new(&state.store, &session).await;

    if let Err(errors) = input.validate() {
        for (field, errors) in errors.field_errors() {
            for error in errors {
                flash_message.push(format!("{}: {}", field, error.code));
            }
        }
        flash_message.store().await;
        Ok(Redirect::to("/authorize"))
    } else {
        let user_result = state
            .repo
            .find_user_by_email(input.email.to_string())
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

        let user = match user_result {
            Some(u) => u,
            None => {
                flash_message.push("Login failed: user not match".to_string());
                flash_message.store().await;
                return Ok(Redirect::to("authorization"));
            }
        };

        if !verify(&input.password, &user.password).unwrap() {
            flash_message.push("Login failed: password not match".to_string());
            flash_message.store().await;

            return Ok(Redirect::to("authorization"));
        }

        let code = generate_random_string(32);
        let datetime = Local::now().naive_local().into();
        let expires_at = Local::now().naive_local() + Duration::hours(1);
        let client_id = Uuid::parse_str(&auth.client_id.unwrap()).unwrap();
        let redirect_uri = auth.redirect_uri.unwrap();
        let params = db_repository::CreateCodeParams {
            code: code.clone(),
            user_id: user.id,
            client_id,
            expires_at: expires_at.into(),
            redirect_uri: redirect_uri.clone(),
            created_at: datetime,
            updated_at: datetime,
        };

        let _ = state.repo.create_code(params).await.unwrap(); // TODO: check

        let qs = vec![("code", code.to_string())];
        let url = Url::parse_with_params(&redirect_uri, qs).unwrap();

        //println!("{:#?}", auth);
        Ok(Redirect::to(url.as_ref()))
    }
}

#[debug_handler]
async fn create_token(
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

async fn me(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
) -> Result<impl IntoResponse, StatusCode> {
    // ユーザー情報取得
    let user = state
        .repo
        .find_user(claims.jti)
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

async fn edit_user(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    input: Json<EditUserInput>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = state
        .repo
        .edit_user(claims.jti, input.name.to_string())
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    // ユーザー情報返却
    let response = UserResponse {
        id: user.id.to_string(),
        name: user.name.to_string(),
        email: user.email.to_string(),
    };
    Ok(Json(response))
}

async fn signout(
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

async fn introspect(
    Extension(claims): Extension<TokenClaims>,
) -> Result<impl IntoResponse, StatusCode> {
    Ok(Json(claims))
}

#[derive(Serialize, Deserialize, Debug, Clone)]
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
