use crate::entity::users;
use chrono::{Local, NaiveDateTime};
use sea_orm::*;
use uuid::Uuid;

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

    pub async fn edit_user(&self, id: Uuid, name: String) -> Result<users::Model, DbErr> {
        let mut user = self
            .find_user(id)
            .await?
            .ok_or_else(|| DbErr::Custom("User not found.".to_owned()))?
            .into_active_model();

        user.name = Set(name);
        user.update(&self.db).await
    }
}
