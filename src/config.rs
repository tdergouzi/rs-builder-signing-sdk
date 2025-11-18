use crate::error::{BuilderError, Result};
use crate::http_helpers;
use crate::signer::BuilderSigner;
use crate::types::{
    BuilderApiKeyCreds, BuilderHeaderPayload, BuilderType, RemoteBuilderConfig,
    RemoteSignerPayload,
};

/// Configuration for builder signing
///
/// Supports two modes:
/// - Local: Signs requests locally using API credentials
/// - Remote: Delegates signing to a remote service
///
/// # Example
/// ```
/// use builder_signing_sdk::{BuilderConfig, BuilderApiKeyCreds};
///
/// // Local signing
/// let config = BuilderConfig::new(
///     None,
///     Some(BuilderApiKeyCreds {
///         key: "my-key".to_string(),
///         secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
///         passphrase: "my-passphrase".to_string(),
///     }),
/// ).unwrap();
/// ```
#[derive(Debug, Clone)]
pub struct BuilderConfig {
    remote_builder_config: Option<RemoteBuilderConfig>,
    local_builder_creds: Option<BuilderApiKeyCreds>,
    signer: Option<BuilderSigner>,
}

impl BuilderConfig {
    /// Create a new BuilderConfig
    ///
    /// # Arguments
    /// * `remote_builder_config` - Optional remote signer configuration
    /// * `local_builder_creds` - Optional local API credentials
    ///
    /// # Returns
    /// Result with BuilderConfig or error if validation fails
    ///
    /// # Notes
    /// - If both local and remote configs are provided, local takes precedence
    /// - At least one configuration method must be valid
    pub fn new(
        remote_builder_config: Option<RemoteBuilderConfig>,
        local_builder_creds: Option<BuilderApiKeyCreds>,
    ) -> Result<Self> {
        let mut config = BuilderConfig {
            remote_builder_config: None,
            local_builder_creds: None,
            signer: None,
        };

        // Validate and set remote config if provided
        if let Some(remote_config) = remote_builder_config {
            if !Self::has_valid_remote_url(&remote_config.url) {
                return Err(BuilderError::InvalidRemoteUrl(remote_config.url));
            }

            if let Some(ref token) = remote_config.token {
                if token.is_empty() {
                    return Err(BuilderError::InvalidAuthToken);
                }
            }

            config.remote_builder_config = Some(remote_config);
        }

        // Validate and set local creds if provided
        if let Some(local_creds) = local_builder_creds {
            if !Self::has_valid_local_creds(&local_creds) {
                return Err(BuilderError::InvalidLocalCredentials(
                    "key, secret, and passphrase must be non-empty".to_string(),
                ));
            }

            config.signer = Some(BuilderSigner::new(local_creds.clone()));
            config.local_builder_creds = Some(local_creds);
        }

        // Ensure at least one valid configuration
        if !config.is_valid() {
            return Err(BuilderError::InvalidBuilderCreds);
        }

        Ok(config)
    }

    /// Generate builder headers using the configured signing method
    ///
    /// # Arguments
    /// * `method` - HTTP method (e.g., "GET", "POST")
    /// * `path` - API endpoint path (e.g., "/order")
    /// * `body` - Optional request body as string
    /// * `timestamp` - Optional Unix timestamp (defaults to current time)
    ///
    /// # Returns
    /// HashMap with builder authentication headers
    pub async fn generate_builder_headers(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
        timestamp: Option<u64>,
    ) -> Result<BuilderHeaderPayload> {
        self.ensure_valid()?;

        let builder_type = self.get_builder_type();

        match builder_type {
            BuilderType::Local => {
                if let Some(ref signer) = self.signer {
                    return signer.create_builder_header_payload(method, path, body, timestamp);
                }
            }
            BuilderType::Remote => {
                if let Some(ref remote_config) = self.remote_builder_config {
                    let payload = RemoteSignerPayload {
                        method: method.to_string(),
                        path: path.to_string(),
                        body: body.map(|s| s.to_string()),
                        timestamp,
                    };

                    return http_helpers::post(
                        &remote_config.url,
                        payload,
                        remote_config.token.as_deref(),
                    )
                    .await;
                }
            }
            BuilderType::Unavailable => {
                return Err(BuilderError::InvalidBuilderCreds);
            }
        }

        Err(BuilderError::InvalidBuilderCreds)
    }

    /// Check if the configuration is valid
    pub fn is_valid(&self) -> bool {
        self.get_builder_type() != BuilderType::Unavailable
    }

    /// Get the builder type (Local, Remote, or Unavailable)
    pub fn get_builder_type(&self) -> BuilderType {
        // If both present, prefer local
        if self.local_builder_creds.is_some() {
            return BuilderType::Local;
        }

        if self.remote_builder_config.is_some() {
            return BuilderType::Remote;
        }

        BuilderType::Unavailable
    }

    /// Validate local credentials
    fn has_valid_local_creds(creds: &BuilderApiKeyCreds) -> bool {
        !creds.key.trim().is_empty()
            && !creds.secret.trim().is_empty()
            && !creds.passphrase.trim().is_empty()
    }

    /// Validate remote URL
    fn has_valid_remote_url(remote_url: &str) -> bool {
        let url = remote_url.trim();
        !url.is_empty() && (url.starts_with("http://") || url.starts_with("https://"))
    }

    /// Ensure configuration is valid, otherwise return error
    fn ensure_valid(&self) -> Result<()> {
        if self.get_builder_type() == BuilderType::Unavailable {
            return Err(BuilderError::InvalidBuilderCreds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_local_config() {
        let creds = BuilderApiKeyCreds {
            key: "test-key".to_string(),
            secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            passphrase: "test-passphrase".to_string(),
        };

        let config = BuilderConfig::new(None, Some(creds));
        assert!(config.is_ok());

        let config = config.unwrap();
        assert!(config.is_valid());
        assert_eq!(config.get_builder_type(), BuilderType::Local);
    }

    #[test]
    fn test_valid_remote_config() {
        let remote = RemoteBuilderConfig {
            url: "https://example.com/sign".to_string(),
            token: Some("token123".to_string()),
        };

        let config = BuilderConfig::new(Some(remote), None);
        assert!(config.is_ok());

        let config = config.unwrap();
        assert!(config.is_valid());
        assert_eq!(config.get_builder_type(), BuilderType::Remote);
    }

    #[test]
    fn test_invalid_local_creds() {
        let creds = BuilderApiKeyCreds {
            key: "".to_string(),
            secret: "secret".to_string(),
            passphrase: "pass".to_string(),
        };

        let config = BuilderConfig::new(None, Some(creds));
        assert!(config.is_err());
    }

    #[test]
    fn test_invalid_remote_url() {
        let remote = RemoteBuilderConfig {
            url: "not-a-url".to_string(),
            token: None,
        };

        let config = BuilderConfig::new(Some(remote), None);
        assert!(config.is_err());
    }

    #[test]
    fn test_local_preference_when_both_provided() {
        let creds = BuilderApiKeyCreds {
            key: "test-key".to_string(),
            secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            passphrase: "test-passphrase".to_string(),
        };

        let remote = RemoteBuilderConfig {
            url: "https://example.com/sign".to_string(),
            token: None,
        };

        let config = BuilderConfig::new(Some(remote), Some(creds)).unwrap();
        assert_eq!(config.get_builder_type(), BuilderType::Local);
    }

    #[tokio::test]
    async fn test_generate_headers_local() {
        let creds = BuilderApiKeyCreds {
            key: "test-key".to_string(),
            secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            passphrase: "test-passphrase".to_string(),
        };

        let config = BuilderConfig::new(None, Some(creds)).unwrap();
        let headers = config
            .generate_builder_headers("POST", "/order", Some(r#"{"test":"data"}"#), Some(1234567890))
            .await;

        assert!(headers.is_ok());
        let headers = headers.unwrap();
        assert_eq!(headers.get("POLY_BUILDER_API_KEY").unwrap(), "test-key");
    }
}

