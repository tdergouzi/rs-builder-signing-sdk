use std::collections::HashMap;

use crate::error::Result;
use crate::signing::build_hmac_signature;
use crate::types::{BuilderApiKeyCreds, BuilderHeaderPayload};

/// Builder signer for creating authenticated headers locally
///
/// # Example
/// ```
/// use builder_signing_sdk::{BuilderSigner, BuilderApiKeyCreds};
///
/// let creds = BuilderApiKeyCreds {
///     key: "my-api-key".to_string(),
///     secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
///     passphrase: "my-passphrase".to_string(),
/// };
///
/// let signer = BuilderSigner::new(creds);
/// let headers = signer.create_builder_header_payload(
///     "POST",
///     "/order",
///     Some(r#"{"marketId":"0x123"}"#),
///     None,
/// ).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct BuilderSigner {
    creds: BuilderApiKeyCreds,
}

impl BuilderSigner {
    /// Create a new BuilderSigner with the given credentials
    pub fn new(creds: BuilderApiKeyCreds) -> Self {
        Self { creds }
    }

    /// Create builder header payload for API authentication
    ///
    /// # Arguments
    /// * `method` - HTTP method (e.g., "GET", "POST")
    /// * `path` - API endpoint path (e.g., "/order")
    /// * `body` - Optional request body as string
    /// * `timestamp` - Optional Unix timestamp (defaults to current time)
    ///
    /// # Returns
    /// HashMap with builder authentication headers:
    /// - POLY_BUILDER_API_KEY
    /// - POLY_BUILDER_PASSPHRASE
    /// - POLY_BUILDER_SIGNATURE
    /// - POLY_BUILDER_TIMESTAMP
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

    /// Get a reference to the credentials
    pub fn creds(&self) -> &BuilderApiKeyCreds {
        &self.creds
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_builder_header_payload() {
        let creds = BuilderApiKeyCreds {
            key: "test-key".to_string(),
            secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            passphrase: "test-passphrase".to_string(),
        };

        let signer = BuilderSigner::new(creds);
        let headers = signer
            .create_builder_header_payload("POST", "/order", Some(r#"{"test":"data"}"#), Some(1234567890))
            .unwrap();

        assert_eq!(headers.get("POLY_BUILDER_API_KEY").unwrap(), "test-key");
        assert_eq!(
            headers.get("POLY_BUILDER_PASSPHRASE").unwrap(),
            "test-passphrase"
        );
        assert_eq!(headers.get("POLY_BUILDER_TIMESTAMP").unwrap(), "1234567890");
        assert!(headers.contains_key("POLY_BUILDER_SIGNATURE"));
    }
}

