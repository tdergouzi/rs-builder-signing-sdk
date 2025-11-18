use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::Result;

type HmacSha256 = Hmac<Sha256>;

/// Builds an HMAC signature for builder API authentication
///
/// # Arguments
/// * `secret` - Base64-encoded secret key
/// * `timestamp` - Unix timestamp in seconds
/// * `method` - HTTP method (e.g., "GET", "POST")
/// * `request_path` - API endpoint path (e.g., "/order")
/// * `body` - Optional request body as string
///
/// # Returns
/// URL-safe base64-encoded HMAC-SHA256 signature
///
/// # Example
/// ```
/// use builder_signing_sdk::signing::build_hmac_signature;
///
/// let signature = build_hmac_signature(
///     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
///     1234567890,
///     "POST",
///     "/order",
///     Some(r#"{"marketId":"0x123"}"#),
/// ).unwrap();
/// ```
pub fn build_hmac_signature(
    secret: &str,
    timestamp: u64,
    method: &str,
    request_path: &str,
    body: Option<&str>,
) -> Result<String> {
    // Build message: timestamp + method + requestPath + body
    let mut message = format!("{}{}{}", timestamp, method, request_path);
    if let Some(body_str) = body {
        message.push_str(body_str);
    }

    // Decode base64 secret
    let base64_secret = general_purpose::STANDARD.decode(secret)?;

    // Create HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(&base64_secret)
        .map_err(|e| crate::error::BuilderError::RemoteSignerError(e.to_string()))?;
    
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let signature_bytes = result.into_bytes();

    // Encode to base64
    let sig = general_purpose::STANDARD.encode(signature_bytes);

    // Convert to URL-safe base64 (keep '=' padding)
    // Convert '+' to '-'
    // Convert '/' to '_'
    let sig_url_safe = sig.replace('+', "-").replace('/', "_");

    Ok(sig_url_safe)
}
