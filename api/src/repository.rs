use crate::entity::{
    articles,
    users::{self},
};
use chrono::Local;
use sea_orm::*;
use uuid::Uuid;

pub struct EditUserParams {
    pub name: Option<String>,
    pub email: Option<String>,
}

pub struct CreateArticleParams {
    pub author_id: Uuid,
    pub title: String,
    pub content: String,
}

pub struct UpdateArticleParams {
    pub title: Option<String>,
    pub content: Option<String>,
}

#[derive(Clone)]
pub struct Repository {
    db: DbConn,
}

impl Repository {
    pub async fn new(db_url: String) -> Result<Repository, DbErr> {
        let conn: DatabaseConnection = Database::connect(db_url).await?;
        Ok(Repository { db: conn })
    }

    pub async fn find_user(&self, id: Uuid) -> Result<Option<users::Model>, DbErr> {
        users::Entity::find_by_id(id).one(&self.db).await
    }

    pub async fn edit_user(&self, id: Uuid, params: EditUserParams) -> Result<users::Model, DbErr> {
        let mut user = self
            .find_user(id)
            .await?
            .ok_or_else(|| DbErr::Custom("User not found.".to_owned()))?
            .into_active_model();

        if let Some(name) = params.name {
            user.name = Set(name);
        }
        if let Some(email) = params.email {
            user.email = Set(email)
        }
        user.update(&self.db).await
    }

    pub async fn find_articles(&self) -> Result<Vec<articles::Model>, DbErr> {
        articles::Entity::find()
            .order_by_desc(articles::Column::CreatedAt)
            .all(&self.db)
            .await
    }

    pub async fn find_article(&self, id: Uuid) -> Result<Option<articles::Model>, DbErr> {
        articles::Entity::find_by_id(id).one(&self.db).await
    }

    pub async fn find_articles_by_author(
        &self,
        author_id: Uuid,
    ) -> Result<Vec<articles::Model>, DbErr> {
        articles::Entity::find()
            .filter(articles::Column::AuthorId.eq(author_id))
            .order_by_desc(articles::Column::CreatedAt)
            .all(&self.db)
            .await
    }

    pub async fn create_article(
        &self,
        payload: CreateArticleParams,
    ) -> Result<articles::Model, DbErr> {
        let id = Uuid::new_v4();
        let article = articles::ActiveModel {
            id: ActiveValue::set(id),
            author_id: ActiveValue::set(payload.author_id),
            title: ActiveValue::set(payload.title),
            content: ActiveValue::set(payload.content),
            created_at: ActiveValue::set(Some(Local::now().naive_local())),
            updated_at: ActiveValue::set(Some(Local::now().naive_local())),
        };

        article.insert(&self.db).await
    }

    pub async fn update_article(
        &self,
        id: Uuid,
        payload: UpdateArticleParams,
    ) -> Result<articles::Model, DbErr> {
        let mut article = self
            .find_article(id)
            .await?
            .ok_or_else(|| DbErr::Custom("Article not found.".to_owned()))?
            .into_active_model();

        if let Some(title) = payload.title {
            article.title = Set(title);
        }
        if let Some(content) = payload.content {
            article.content = Set(content)
        }
        article.updated_at = Set(Some(Local::now().naive_local()));
        article.update(&self.db).await
    }
}
