use crate::entity::{
    articles,
    users::{self, Column},
};
use sea_orm::*;
use uuid::Uuid;

pub struct EditUserParams {
    pub name: Option<String>,
    pub email: Option<String>,
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
}
