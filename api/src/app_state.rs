use crate::repository;

#[derive(Clone)]
pub struct AppState {
    pub repo: repository::Repository,
}
