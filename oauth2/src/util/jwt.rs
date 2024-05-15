use jsonwebtoken::{
    decode, encode, errors::Error, Algorithm, DecodingKey, EncodingKey, Header, TokenData,
    Validation,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TokenClaims {
    pub sub: String, // access_token
    pub jti: Uuid,   // user_id
    pub exp: i64,
    pub iat: i64,
}

pub fn generate_token<T: Serialize>(claims: &T, secret: &[u8]) -> Result<String, Error> {
    let encoding_key = EncodingKey::from_secret(secret);
    encode(&Header::default(), claims, &encoding_key)
}

pub fn decode_token(
    token: &str,
    decoding_key: &DecodingKey,
) -> Result<TokenData<TokenClaims>, Error> {
    decode::<TokenClaims>(token, decoding_key, &Validation::new(Algorithm::HS256))
}
