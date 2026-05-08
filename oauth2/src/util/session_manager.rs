use serde::{de::DeserializeOwned, Serialize};
use serde_json::{self, Value};
use tower_sessions::Session;

pub async fn unmarshal_from_session<T: DeserializeOwned + Serialize + Default>(
    session: &Session,
    key: &str,
) -> T {
    let sess_val = session
        .get::<String>(key)
        .await
        .unwrap()
        .unwrap_or_else(|| match serde_json::to_value(&T::default()) {
            Ok(val) => match val {
                Value::Array(_) => "[]".to_string(),
                _ => "{}".to_string(),
            },
            Err(_) => "{}".to_string(),
        });
    serde_json::from_str(&sess_val).unwrap()
}

pub async fn marshal_to_session<T: Serialize>(session: &Session, key: &str, val: &T) {
    let v = serde_json::to_string(&val).unwrap();
    session.insert(key, v).await.unwrap();
}

pub async fn remove_session(session: &Session, key: &str) {
    let _: Option<String> = session.remove(key).await.unwrap();
}
