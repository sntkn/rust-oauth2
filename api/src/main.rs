use api::app_state::AppState;
use api::middleware;
use api::repository;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Json, Router,
};
use chrono::NaiveDateTime;
use sea_orm::IntoActiveModel;
use serde::{Deserialize, Serialize};
use std::env;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use uuid::Uuid;
use validator::Validate;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "debug".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let db_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let repo = repository::Repository::new(db_url).await.unwrap();
    let state = AppState { repo };

    let router = Router::new()
        .route("/articles", get(find_articles))
        .route("/articles/:id", get(find_article));

    let token_router = Router::new()
        .route("/user", get(find_user).put(edit_user))
        .route("/articles", post(create_article))
        .route("/articles/:id", put(update_article).delete(delete_article))
        .route("/articles/:id/publish", post(publish_article))
        .layer(axum::middleware::from_fn(middleware::auth_middleware));

    let app = router.merge(token_router).with_state(state);

    let listner = tokio::net::TcpListener::bind("127.0.0.1:3001")
        .await
        .unwrap();

    axum::serve(listner, app).await.unwrap();
}

#[derive(Serialize, Deserialize)]
struct User {
    id: Uuid,
    name: String,
    email: String,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
struct TokenClaims {
    sub: String, // access_token
    jti: Uuid,   // user_id
    exp: i64,
    iat: i64,
}

#[derive(Debug, Deserialize, Validate)]
struct EditUserInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'user' can not be empty"))]
    name: Option<String>,

    #[validate(length(min = 1, message = "Paramater 'email' can not be empty"))]
    #[validate(email)]
    email: Option<String>,
}

async fn find_user(
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

async fn edit_user(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    input: Json<EditUserInput>,
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

#[derive(Serialize, Deserialize)]
struct Article {
    id: Uuid,
    title: String,
    content: String,
    author_id: Uuid,
    published_at: Option<NaiveDateTime>,
    deleted_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

async fn find_articles(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let resarticles = state
        .repo
        .find_articles()
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let mut data = Vec::new();

    for article in resarticles {
        data.push(Article {
            id: article.id,
            title: article.title,
            content: article.content,
            author_id: article.author_id,
            published_at: article.published_at,
            deleted_at: article.deleted_at,
            created_at: article.created_at,
            updated_at: article.updated_at,
        });
    }
    let data = serde_json::json!(data);

    Ok(Json(data))
}

async fn find_article(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let article = state
        .repo
        .find_article(id)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::NOT_FOUND)?;

    let data = Article {
        id: article.id,
        title: article.title,
        content: article.content,
        author_id: article.author_id,
        published_at: article.published_at,
        deleted_at: article.deleted_at,
        created_at: article.created_at,
        updated_at: article.updated_at,
    };

    let res = serde_json::json!(data);

    Ok(Json(res))
}

#[derive(Debug, Deserialize, Validate)]
struct CreateArticleInput {
    #[validate(length(min = 1, message = "Paramater 'title' can not be empty"))]
    title: String,

    #[validate(length(min = 1, message = "Paramater 'content' can not be empty"))]
    #[validate(email)]
    content: String,
}

async fn create_article(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    Json(input): Json<CreateArticleInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let params = repository::CreateArticleParams {
        author_id: claims.jti,
        title: input.title.clone(),
        content: input.content.clone(),
    };

    let article = state
        .repo
        .create_article(params)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let data = Article {
        id: article.id,
        title: article.title,
        content: article.content,
        author_id: article.author_id,
        published_at: article.published_at,
        deleted_at: article.deleted_at,
        created_at: article.created_at,
        updated_at: article.updated_at,
    };

    let res = serde_json::json!(data);

    Ok(Json(res))
}

#[derive(Debug, Deserialize, Validate)]
struct EditArticleInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'title' can not be empty"))]
    title: Option<String>,

    #[validate(length(min = 1, message = "Paramater 'content' can not be empty"))]
    #[validate(email)]
    content: Option<String>,
}

async fn update_article(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<Uuid>,
    Json(input): Json<EditArticleInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let article = state
        .repo
        .find_article(id)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::NOT_FOUND)?;

    // check author
    if article.author_id != claims.jti {
        return Err(StatusCode::FORBIDDEN);
    }

    let params = repository::UpdateArticleParams {
        title: input.title.clone(),
        content: input.content.clone(),
    };

    let updated_article = state
        .repo
        .update_article(article.into_active_model(), params)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let data = Article {
        id: updated_article.id,
        title: updated_article.title,
        content: updated_article.content,
        author_id: updated_article.author_id,
        published_at: updated_article.published_at,
        deleted_at: updated_article.deleted_at,
        created_at: updated_article.created_at,
        updated_at: updated_article.updated_at,
    };

    let res = serde_json::json!(data);

    Ok(Json(res))
}

async fn delete_article(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let article = state
        .repo
        .find_article(id)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::NOT_FOUND)?;

    // check author
    if article.author_id != claims.jti {
        return Err(StatusCode::FORBIDDEN);
    }

    let deleted_article = state
        .repo
        .delete_article(article.into_active_model())
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let data = Article {
        id: deleted_article.id,
        title: deleted_article.title,
        content: deleted_article.content,
        author_id: deleted_article.author_id,
        published_at: deleted_article.published_at,
        deleted_at: deleted_article.deleted_at,
        created_at: deleted_article.created_at,
        updated_at: deleted_article.updated_at,
    };

    let res = serde_json::json!(data);

    Ok(Json(res))
}

#[derive(Debug, Deserialize)]
struct PublishArticleInput {
    publish: bool,
}

async fn publish_article(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<Uuid>,
    Json(input): Json<PublishArticleInput>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let article = state
        .repo
        .find_article(id)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?
        .ok_or(StatusCode::NOT_FOUND)?;

    // check author
    if article.author_id != claims.jti {
        return Err(StatusCode::FORBIDDEN);
    }

    let published_article = state
        .repo
        .publish_article(article.into_active_model(), input.publish)
        .await
        .or(Err(StatusCode::INTERNAL_SERVER_ERROR))?;

    let data = Article {
        id: published_article.id,
        title: published_article.title,
        content: published_article.content,
        author_id: published_article.author_id,
        published_at: published_article.published_at,
        deleted_at: published_article.deleted_at,
        created_at: published_article.created_at,
        updated_at: published_article.updated_at,
    };

    let res = serde_json::json!(data);

    Ok(Json(res))
}
