use crate::repository::db_repository;
use async_redis_session::RedisSessionStore;

#[derive(Clone)]
pub struct AppState {
    //session: SessionToken,
    pub store: RedisSessionStore,
    pub repo: db_repository::Repository,
}
