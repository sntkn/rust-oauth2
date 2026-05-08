use crate::repository::db_repository;

#[derive(Clone)]
pub struct AppState {
    pub repo: db_repository::Repository,
}
