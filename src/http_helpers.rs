use crate::error::{BuilderError, Result};
use crate::types::{BuilderHeaderPayload, RemoteSignerPayload};

/// Send POST request to remote signer and return authentication headers
pub async fn post(
    endpoint: &str,
    payload: RemoteSignerPayload,
    token: Option<&str>,
) -> Result<BuilderHeaderPayload> {
    let client = reqwest::Client::new();
    let mut request = client.post(endpoint).json(&payload);

    if let Some(token_str) = token {
        request = request.bearer_auth(token_str);
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        return Err(BuilderError::RemoteSignerError(format!(
            "Remote signer returned status: {}",
            response.status()
        )));
    }

    let headers: BuilderHeaderPayload = response.json().await?;
    Ok(headers)
}
