use crate::entity::{oauth2_clients, oauth2_codes, users};
use chrono::NaiveDateTime;
use sea_orm::*;
use uuid::Uuid;

pub struct CreateCodeParams {
    pub code: String,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub expires_at: Option<NaiveDateTime>,
    pub redirect_uri: String,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
}

#[derive(Clone)]
pub struct Repository {
    db: DbConn,
}

impl Repository {
    pub fn new(db: DbConn) -> Repository {
        Repository { db }
    }

    pub async fn find_client(&self, id: Uuid) -> Result<Option<oauth2_clients::Model>, DbErr> {
        oauth2_clients::Entity::find_by_id(id).one(&self.db).await
    }

    pub async fn find_user_by_email(&self, email: String) -> Result<Option<users::Model>, DbErr> {
        users::Entity::find()
            .filter(users::Column::Email.eq(email))
            .one(&self.db)
            .await
    }

    pub async fn create_code(
        &self,
        payload: CreateCodeParams,
    ) -> Result<(oauth2_codes::Model), DbErr> {
        let oauth2_code = oauth2_codes::ActiveModel {
            code: ActiveValue::set(payload.code),
            user_id: ActiveValue::set(payload.user_id),
            client_id: ActiveValue::set(payload.client_id),
            expires_at: ActiveValue::set(payload.expires_at),
            redirect_uri: ActiveValue::set(payload.redirect_uri),
            scope: ActiveValue::set("*".to_string()),
            revoked_at: ActiveValue::set(None),
            created_at: ActiveValue::set(payload.created_at),
            updated_at: ActiveValue::set(payload.updated_at),
        };

        oauth2_code.insert(&self.db).await
    }
}
