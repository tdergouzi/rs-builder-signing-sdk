use base64::{engine::general_purpose, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::Result;

type HmacSha256 = Hmac<Sha256>;

/// Build HMAC-SHA256 signature for builder API authentication
pub fn build_hmac_signature(
    secret: &str,
    timestamp: u64,
    method: &str,
    request_path: &str,
    body: Option<&str>,
) -> Result<String> {
    // Build message: timestamp + method + path + body
    let mut message = format!("{}{}{}", timestamp, method, request_path);
    if let Some(body_str) = body {
        message.push_str(body_str);
    }

    let base64_secret = general_purpose::STANDARD.decode(secret)?;

    let mut mac = HmacSha256::new_from_slice(&base64_secret)
        .map_err(|e| crate::error::BuilderError::RemoteSignerError(e.to_string()))?;
    
    mac.update(message.as_bytes());
    let result = mac.finalize();
    let signature_bytes = result.into_bytes();

    let sig = general_purpose::STANDARD.encode(signature_bytes);

    // Convert to URL-safe base64
    let sig_url_safe = sig.replace('+', "-").replace('/', "_");

    Ok(sig_url_safe)
}
