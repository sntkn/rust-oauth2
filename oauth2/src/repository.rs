use crate::entity::{oauth2_clients, oauth2_codes, oauth2_tokens, users};
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

pub struct CreateTokenParams {
    pub access_token: String,
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub expires_at: Option<NaiveDateTime>,
    pub created_at: Option<NaiveDateTime>,
    pub updated_at: Option<NaiveDateTime>,
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
    ) -> Result<oauth2_codes::Model, DbErr> {
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

    pub async fn find_code(&self, code: Uuid) -> Result<Option<oauth2_codes::Model>, DbErr> {
        oauth2_codes::Entity::find_by_id(code).one(&self.db).await
    }

    pub async fn create_token(
        &self,
        payload: CreateTokenParams,
    ) -> Result<oauth2_tokens::Model, DbErr> {
        let oauth2_token = oauth2_tokens::ActiveModel {
            access_token: ActiveValue::set(payload.access_token),
            user_id: ActiveValue::set(payload.user_id),
            client_id: ActiveValue::set(payload.client_id),
            scope: ActiveValue::set("*".to_string()),
            revoked_at: ActiveValue::set(None),
            expires_at: ActiveValue::set(payload.expires_at),
            created_at: ActiveValue::set(payload.created_at),
            updated_at: ActiveValue::set(payload.updated_at),
        };

        oauth2_token.insert(&self.db).await
    }
}
