use std::env;
mod entity;

use crate::entity::oauth2_clients::Entity as OAuth2ClientEntity;
use crate::entity::oauth2_codes::ActiveModel as OAuth2CodeModel;
use crate::entity::oauth2_codes::Entity as OAuth2CodeEntity;
use crate::entity::users::Entity as UserEntity;

use askama::Template;
use async_redis_session::RedisSessionStore;
use async_session::{Session, SessionStore};
use axum::{
    debug_handler,
    extract::{self, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use axum_extra::extract::cookie::{Cookie as EntityCookie, CookieJar};
use chrono::{Duration, Local};
use regex::Regex;
use sea_orm::*;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;
use validator::{Validate, ValidationError};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();
    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let conn: DatabaseConnection = Database::connect(db_url).await.unwrap();

    let store = RedisSessionStore::new("redis://localhost:6379/").unwrap();
    //let session = Session::new();
    //let cookie_value = store.store_session(session).await.unwrap().unwrap();
    //let session = store.load_session(cookie_value).await.unwrap().unwrap();
    //let cookie = store.store_session(session).await.unwrap().unwrap();
    //let t = SessionToken(cookie);

    let state = AppState { conn, store };

    let router = Router::new()
        .route("/", get(hello_world))
        .route("/greet/:name", get(greet))
        .route("/authorize", get(authorize)) // http://localhost:3000/authorize?response_type=code&state=3&client_id=550e8400-e29b-41d4-a716-446655440000&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback
        .route("/authorization", post(authorization))
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
    let cookie_value = store.store_session(session).await.unwrap().unwrap();
    let jar = CookieJar::from_headers(headers);
    let cc = EntityCookie::new("session_id", cookie_value);
    let cookie = jar.get("session_id").unwrap_or(&cc);
    let jc = jar.clone().add(cookie.clone());
    let cv = cookie.value();
    println!("cookie: {:?}", cv);
    let session = store.load_session(cv.to_string()).await.unwrap().unwrap();
    (session, jc)
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
    conn: DatabaseConnection,
    //session: SessionToken,
    store: RedisSessionStore,
}

async fn hello_world(state: State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let client = OAuth2ClientEntity::find().one(&state.conn).await.unwrap();

    match client {
        Some(client) => Ok(Json(HelloWorld {
            text: client.name.to_string(),
        })),
        None => Err(StatusCode::NOT_FOUND),
    }
}

#[derive(Serialize)]
struct HelloWorld {
    text: String,
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

async fn greet(extract::Path(name): extract::Path<String>) -> impl IntoResponse {
    let template = HelloTemplate { name };
    HtmlTemplate(template)
}

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
    println!("{:?}", input);

    if let Err(errors) = input.validate() {
        println!("{:#?}", errors);
        return Err(StatusCode::UNAUTHORIZED);
    }

    let parsed_uuid = Uuid::parse_str(&input.client_id).unwrap();
    // client_id が そんざいすること
    let client = OAuth2ClientEntity::find_by_id(parsed_uuid)
        .one(&state.conn)
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
    println!("session is {:#?}", &val);
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
    println!("{:#?}", input);
    if let Err(errors) = input.validate() {
        println!("{:#?}", errors);
        Ok(Redirect::to("/autorize"))
    } else {
        let (session, _jar) = load_session(&state.store, &headers).await;
        let auth: AuthorizeValue = unmarshal_from_session(&session, "auth".to_string()).await;
        let user = UserEntity::find()
            .filter(crate::entity::users::Column::Email.eq(input.email.to_string()))
            .one(&state.conn)
            .await
            .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
            .ok_or(StatusCode::FORBIDDEN)?; // TODO: redirect to authorize
        if user.password != input.password {
            return Err(StatusCode::FORBIDDEN); // TODO: redirect to authorize
        }
        let code = Uuid::new_v4();
        let datetime = Local::now().naive_local().into();
        let expires_at = Local::now().naive_local() + Duration::hours(1);
        let client_id = Uuid::parse_str(&auth.client_id.unwrap()).unwrap();
        let oauth2_code = OAuth2CodeModel {
            code: ActiveValue::Set(code.to_string()),
            user_id: ActiveValue::set(user.id),
            client_id: ActiveValue::set(client_id),
            expires_at: ActiveValue::set(expires_at.into()),
            redirect_uri: ActiveValue::set(auth.redirect_uri.unwrap()),
            scope: ActiveValue::set("*".to_string()),
            revoked_at: ActiveValue::set(None),
            created_at: ActiveValue::set(datetime),
            updated_at: ActiveValue::set(datetime),
        };

        oauth2_code.insert(&state.conn).await.unwrap(); // TODO: check

        //println!("{:#?}", auth);
        Ok(Redirect::to("/autorize"))
    }
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
