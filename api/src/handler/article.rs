use crate::app_state::AppState;
use crate::middleware::TokenClaims;
use crate::repository;
use axum::{
    extract::{Extension, Path, State},
    http::StatusCode,
    Json,
};
use chrono::NaiveDateTime;
use sea_orm::IntoActiveModel;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

#[derive(Serialize, Deserialize)]
pub struct Article {
    id: Uuid,
    title: String,
    content: String,
    author_id: Uuid,
    published_at: Option<NaiveDateTime>,
    deleted_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

pub async fn find_all(
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

pub async fn find_one(
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
pub struct CreateInput {
    #[validate(length(min = 1, message = "Paramater 'title' can not be empty"))]
    title: String,

    #[validate(length(min = 1, message = "Paramater 'content' can not be empty"))]
    #[validate(email)]
    content: String,
}

pub async fn create(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    Json(input): Json<CreateInput>,
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
pub struct UpdateInput {
    #[serde(default)]
    #[validate(length(min = 1, message = "Paramater 'title' can not be empty"))]
    title: Option<String>,

    #[validate(length(min = 1, message = "Paramater 'content' can not be empty"))]
    #[validate(email)]
    content: Option<String>,
}

pub async fn update(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<Uuid>,
    Json(input): Json<UpdateInput>,
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

pub async fn delete(
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
pub struct PublishInput {
    publish: bool,
}

pub async fn publish(
    State(state): State<AppState>,
    Extension(claims): Extension<TokenClaims>,
    Path(id): Path<Uuid>,
    Json(input): Json<PublishInput>,
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
