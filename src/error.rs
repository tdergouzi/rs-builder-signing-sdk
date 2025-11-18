use thiserror::Error;

#[derive(Error, Debug)]
pub enum BuilderError {
    #[error("Invalid remote URL: {0}")]
    InvalidRemoteUrl(String),

    #[error("Invalid auth token")]
    InvalidAuthToken,

    #[error("Invalid local builder credentials: {0}")]
    InvalidLocalCredentials(String),

    #[error("Invalid builder credentials configured")]
    InvalidBuilderCreds,

    #[error("Base64 decode error: {0}")]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error("Remote signer error: {0}")]
    RemoteSignerError(String),

    #[error("HTTP request error: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, BuilderError>;

