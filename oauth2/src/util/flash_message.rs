use crate::util::session_manager;
use async_redis_session::RedisSessionStore;
use async_session::Session;
use session_manager::{marshal_to_session, remove_session, unmarshal_from_session};

pub struct FlashMessage<'a> {
    store: &'a RedisSessionStore,
    session: &'a Session,
    messages: Vec<String>,
}

impl<'a> FlashMessage<'a> {
    pub async fn new(store: &'a RedisSessionStore, session: &'a Session) -> FlashMessage<'a> {
        FlashMessage {
            store,
            session,
            messages: Vec::new(),
        }
    }

    pub fn push(&mut self, message: String) {
        self.messages.push(message);
    }

    pub async fn store(&mut self) {
        marshal_to_session(
            self.store,
            self.session,
            "flash_message".to_string(),
            &self.messages,
        )
        .await;
    }

    pub async fn pull(&mut self) -> Vec<String> {
        let val: Vec<String> =
            unmarshal_from_session(self.session, "flash_message".to_string()).await;
        remove_session(self.store, self.session, "flash_message".to_string()).await;
        val
    }
}
