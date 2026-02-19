use thiserror::Error;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("url parse error: {0}")]
    Url(#[from] url::ParseError),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("jwt error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
    #[error("invalid token: {0}")]
    InvalidToken(String),
    #[error("internal error: {0}")]
    Internal(String),
    #[error("invalid state")]
    InvalidState,
    #[error("crypto failure")]
    Crypto,
}
