use std::collections::HashMap;

use crate::error::Result;
use crate::signing::build_hmac_signature;
use crate::types::{BuilderApiKeyCreds, BuilderHeaderPayload};

/// Builder signer for creating authenticated headers locally
#[derive(Debug, Clone)]
pub struct BuilderSigner {
    creds: BuilderApiKeyCreds,
}

impl BuilderSigner {
    /// Create a new signer with API credentials
    pub fn new(creds: BuilderApiKeyCreds) -> Self {
        Self { creds }
    }

    /// Create builder header payload for API authentication
    pub fn create_builder_header_payload(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timestamp: Option<u64>,
    ) -> Result<BuilderHeaderPayload> {
        let ts = timestamp.unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        });

        let builder_sig = build_hmac_signature(&self.creds.secret, ts, method, path, body)?;

        let mut headers = HashMap::new();
        headers.insert("POLY_BUILDER_API_KEY".to_string(), self.creds.key.clone());
        headers.insert(
            "POLY_BUILDER_PASSPHRASE".to_string(),
            self.creds.passphrase.clone(),
        );
        headers.insert("POLY_BUILDER_SIGNATURE".to_string(), builder_sig);
        headers.insert("POLY_BUILDER_TIMESTAMP".to_string(), ts.to_string());

        Ok(headers)
    }

    /// Get reference to credentials
    pub fn creds(&self) -> &BuilderApiKeyCreds {
        &self.creds
    }
}
