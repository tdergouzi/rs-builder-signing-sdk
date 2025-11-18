use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Builder type indicating the signing method
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuilderType {
    Unavailable,
    Local,
    Remote,
}

/// API key credentials for local signing
#[derive(Debug, Clone)]
pub struct BuilderApiKeyCreds {
    pub key: String,
    pub secret: String,
    pub passphrase: String,
}

/// Configuration for remote builder/signer
#[derive(Debug, Clone)]
pub struct RemoteBuilderConfig {
    pub url: String,
    pub token: Option<String>,
}

/// Payload sent to remote signer
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoteSignerPayload {
    pub method: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<u64>,
}

/// Builder header payload returned after signing
pub type BuilderHeaderPayload = HashMap<String, String>;

