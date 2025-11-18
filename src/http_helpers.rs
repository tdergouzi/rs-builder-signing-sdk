use crate::error::{BuilderError, Result};
use crate::types::{BuilderHeaderPayload, RemoteSignerPayload};

/// Send POST request to remote signer
///
/// # Arguments
/// * `endpoint` - Remote signer URL
/// * `payload` - Request payload with method, path, body, timestamp
/// * `token` - Optional bearer token for authentication
///
/// # Returns
/// BuilderHeaderPayload with authentication headers from remote signer
pub async fn post(
    endpoint: &str,
    payload: RemoteSignerPayload,
    token: Option<&str>,
) -> Result<BuilderHeaderPayload> {
    let client = reqwest::Client::new();
    let mut request = client.post(endpoint).json(&payload);

    // Add Authorization header if token is provided
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_post_request_structure() {
        let payload = RemoteSignerPayload {
            method: "POST".to_string(),
            path: "/order".to_string(),
            body: Some(r#"{"test":"data"}"#.to_string()),
            timestamp: Some(1234567890),
        };

        // This test just verifies the function signature and types compile
        // Actual HTTP testing would require a mock server
        let _ = payload;
    }
}

