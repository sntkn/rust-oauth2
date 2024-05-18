use crate::entity::{oauth2_clients, oauth2_codes, oauth2_refresh_tokens, oauth2_tokens, users};
use bcrypt::{hash, DEFAULT_COST};
use chrono::{Local, NaiveDateTime};
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

pub struct CreateRefreshTokenParams {
    pub refresh_token: String,
    pub access_token: String,
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

    pub async fn find_user(&self, id: Uuid) -> Result<Option<users::Model>, DbErr> {
        users::Entity::find_by_id(id).one(&self.db).await
    }

    pub async fn create_user(
        &self,
        email: String,
        password: String,
    ) -> Result<users::Model, DbErr> {
        let id = Uuid::new_v4();
        let hashed_password = hash(password, DEFAULT_COST)
            .map_err(|_| DbErr::Custom("Error hashing password.".to_owned()))?;
        let name = match email.find('@') {
            Some(at_pos) => {
                // `@`の前の部分を取得
                &email[..at_pos]
            }
            None => return Err(DbErr::Custom("Error name not found.".to_owned())),
        };

        let user = users::ActiveModel {
            id: ActiveValue::set(id),
            name: ActiveValue::set(name.to_string()),
            email: ActiveValue::set(email),
            password: ActiveValue::set(hashed_password),
            created_at: ActiveValue::set(Some(Local::now().naive_local())),
            updated_at: ActiveValue::set(Some(Local::now().naive_local())),
        };

        user.insert(&self.db).await
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

    pub async fn find_code(&self, code: String) -> Result<Option<oauth2_codes::Model>, DbErr> {
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

    pub async fn create_refresh_token(
        &self,
        payload: CreateRefreshTokenParams,
    ) -> Result<oauth2_refresh_tokens::Model, DbErr> {
        let oauth2_refresh_token = oauth2_refresh_tokens::ActiveModel {
            refresh_token: ActiveValue::set(payload.refresh_token),
            access_token: ActiveValue::set(payload.access_token),
            revoked_at: ActiveValue::set(None),
            expires_at: ActiveValue::set(payload.expires_at),
            created_at: ActiveValue::set(payload.created_at),
            updated_at: ActiveValue::set(payload.updated_at),
        };

        oauth2_refresh_token.insert(&self.db).await
    }

    pub async fn revoke_code(&self, code: String) -> Result<oauth2_codes::Model, DbErr> {
        let mut oauth2_code = oauth2_codes::Entity::find_by_id(code)
            .one(&self.db)
            .await?
            .ok_or_else(|| DbErr::Custom("Code not found.".to_owned()))?
            .into_active_model();

        oauth2_code.revoked_at = Set(Some(Local::now().naive_local()));
        oauth2_code.update(&self.db).await
    }

    pub async fn find_token(
        &self,
        access_token: String,
    ) -> Result<Option<oauth2_tokens::Model>, DbErr> {
        oauth2_tokens::Entity::find_by_id(access_token)
            .filter(oauth2_tokens::Column::RevokedAt.is_null())
            .one(&self.db)
            .await
    }

    pub async fn find_refresh_token(
        &self,
        refresh_token: String,
    ) -> Result<Option<oauth2_refresh_tokens::Model>, DbErr> {
        oauth2_refresh_tokens::Entity::find_by_id(refresh_token)
            .filter(oauth2_refresh_tokens::Column::RevokedAt.is_null())
            .one(&self.db)
            .await
    }

    pub async fn revoke_refresh_token(
        &self,
        refresh_token: String,
    ) -> Result<oauth2_refresh_tokens::Model, DbErr> {
        let mut oauth2_refresh_token = oauth2_refresh_tokens::Entity::find_by_id(refresh_token)
            .one(&self.db)
            .await?
            .ok_or_else(|| DbErr::Custom("Refresh token not found.".to_owned()))?
            .into_active_model();

        oauth2_refresh_token.revoked_at = Set(Some(Local::now().naive_local()));
        oauth2_refresh_token.update(&self.db).await
    }

    pub async fn revoke_refresh_token_by_token(
        &self,
        access_token: String,
    ) -> Result<oauth2_refresh_tokens::Model, DbErr> {
        let mut oauth2_refresh_token = oauth2_refresh_tokens::Entity::find()
            .filter(oauth2_refresh_tokens::Column::AccessToken.eq(access_token))
            .one(&self.db)
            .await?
            .ok_or_else(|| DbErr::Custom("Refresh token not found.".to_owned()))?
            .into_active_model();

        oauth2_refresh_token.revoked_at = Set(Some(Local::now().naive_local()));
        oauth2_refresh_token.update(&self.db).await
    }

    pub async fn revoke_token(&self, access_token: String) -> Result<oauth2_tokens::Model, DbErr> {
        let mut oauth2_token = oauth2_tokens::Entity::find_by_id(access_token)
            .one(&self.db)
            .await?
            .ok_or_else(|| DbErr::Custom("Token not found.".to_owned()))?
            .into_active_model();

        oauth2_token.revoked_at = Set(Some(Local::now().naive_local()));
        oauth2_token.update(&self.db).await
    }
}
