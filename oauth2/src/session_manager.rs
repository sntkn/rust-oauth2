use async_redis_session::RedisSessionStore;
use async_session::Session;
use async_session::SessionStore;
use axum::http::HeaderMap;
use axum_extra::extract::cookie::{Cookie as EntityCookie, CookieJar};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{self, Value};

pub async fn manage_session(
    store: &RedisSessionStore,
    headers: &HeaderMap,
) -> (Session, CookieJar) {
    let session = Session::new();
    let jar = CookieJar::from_headers(headers);
    let cookie = {
        let cookie_value = store.store_session(session).await.unwrap().unwrap();
        let cookie_entity = EntityCookie::new("session_id", cookie_value);
        let cookie = jar.get("session_id").unwrap_or(&cookie_entity);
        cookie.clone()
    };
    let jar = jar.add(cookie.clone());
    let session = store
        .load_session(cookie.value().to_string())
        .await
        .unwrap()
        .unwrap();

    (session, jar)
}

pub async fn unmarshal_from_session<T: DeserializeOwned + Serialize + Default>(
    session: &Session,
    key: String,
) -> T {
    let sess_val =
        session
            .get::<String>(&key)
            .unwrap_or_else(|| match serde_json::to_value(&T::default()) {
                Ok(val) => match val {
                    Value::Array(_) => "[]".to_string(),
                    _ => "{}".to_string(),
                },
                Err(_) => "{}".to_string(),
            });
    serde_json::from_str(&sess_val).unwrap()
}

pub async fn marshal_to_session<T: Serialize>(
    store: &RedisSessionStore,
    session: &Session,
    key: String,
    val: &T,
) {
    let v = serde_json::to_string(&val).unwrap();
    let mut session_clone = session.clone();

    session_clone.insert(&key.to_string(), v).unwrap();

    store.store_session(session_clone).await.unwrap();
}

pub async fn remove_session(store: &RedisSessionStore, session: &Session, key: String) {
    let mut session_clone = session.clone();

    session_clone.remove(&key.to_string());

    store.store_session(session_clone).await.unwrap();
}
