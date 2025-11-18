use crate::error::{BuilderError, Result};
use crate::http_helpers;
use crate::signer::BuilderSigner;
use crate::types::{
    BuilderApiKeyCreds, BuilderHeaderPayload, BuilderType, RemoteBuilderConfig,
    RemoteSignerPayload,
};

/// Configuration for builder signing (local or remote)
#[derive(Debug, Clone)]
pub struct BuilderConfig {
    remote_builder_config: Option<RemoteBuilderConfig>,
    local_builder_creds: Option<BuilderApiKeyCreds>,
    signer: Option<BuilderSigner>,
}

impl BuilderConfig {
    /// Create a new BuilderConfig
    /// 
    /// Note: Local takes precedence if both configs provided
    pub fn new(
        remote_builder_config: Option<RemoteBuilderConfig>,
        local_builder_creds: Option<BuilderApiKeyCreds>,
    ) -> Result<Self> {
        let mut config = BuilderConfig {
            remote_builder_config: None,
            local_builder_creds: None,
            signer: None,
        };

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

        if let Some(local_creds) = local_builder_creds {
            if !Self::has_valid_local_creds(&local_creds) {
                return Err(BuilderError::InvalidLocalCredentials(
                    "key, secret, and passphrase must be non-empty".to_string(),
                ));
            }

            config.signer = Some(BuilderSigner::new(local_creds.clone()));
            config.local_builder_creds = Some(local_creds);
        }

        if !config.is_valid() {
            return Err(BuilderError::InvalidBuilderCreds);
        }

        Ok(config)
    }

    /// Generate builder authentication headers
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

    /// Check if configuration is valid
    pub fn is_valid(&self) -> bool {
        self.get_builder_type() != BuilderType::Unavailable
    }

    /// Get builder type: Local, Remote, or Unavailable
    pub fn get_builder_type(&self) -> BuilderType {
        if self.local_builder_creds.is_some() {
            return BuilderType::Local;
        }

        if self.remote_builder_config.is_some() {
            return BuilderType::Remote;
        }

        BuilderType::Unavailable
    }

    fn has_valid_local_creds(creds: &BuilderApiKeyCreds) -> bool {
        !creds.key.trim().is_empty()
            && !creds.secret.trim().is_empty()
            && !creds.passphrase.trim().is_empty()
    }

    fn has_valid_remote_url(remote_url: &str) -> bool {
        let url = remote_url.trim();
        !url.is_empty() && (url.starts_with("http://") || url.starts_with("https://"))
    }

    fn ensure_valid(&self) -> Result<()> {
        if self.get_builder_type() == BuilderType::Unavailable {
            return Err(BuilderError::InvalidBuilderCreds);
        }
        Ok(())
    }
}
