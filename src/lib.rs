//! # Builder Signing SDK
//!
//! A Rust SDK for creating authenticated builder headers for Polymarket Builder API.
//!
//! ## Features
//!
//! - HMAC-SHA256 signature generation
//! - Local signing with API credentials
//! - Remote signing via HTTP service
//! - URL-safe base64 encoding
//!
//! ## Quick Start
//!
//! ### Local Signing
//!
//! ```rust
//! use builder_signing_sdk::{BuilderConfig, BuilderApiKeyCreds};
//!
//! #[tokio::main]
//! async fn main() {
//!     let creds = BuilderApiKeyCreds {
//!         key: "your-api-key".to_string(),
//!         secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
//!         passphrase: "your-passphrase".to_string(),
//!     };
//!
//!     let config = BuilderConfig::new(None, Some(creds)).unwrap();
//!     
//!     let headers = config.generate_builder_headers(
//!         "POST",
//!         "/order",
//!         Some(r#"{"marketId":"0x123"}"#),
//!         None,
//!     ).await.unwrap();
//!
//!     println!("Headers: {:?}", headers);
//! }
//! ```
//!
//! ### Remote Signing
//!
//! ```rust
//! use builder_signing_sdk::{BuilderConfig, RemoteBuilderConfig};
//!
//! #[tokio::main]
//! async fn main() {
//!     let remote_config = RemoteBuilderConfig {
//!         url: "https://your-signer-service.com/sign".to_string(),
//!         token: Some("your-auth-token".to_string()),
//!     };
//!
//!     let config = BuilderConfig::new(Some(remote_config), None).unwrap();
//!     
//!     let headers = config.generate_builder_headers(
//!         "POST",
//!         "/order",
//!         Some(r#"{"marketId":"0x123"}"#),
//!         None,
//!     ).await.unwrap();
//!
//!     println!("Headers: {:?}", headers);
//! }
//! ```

pub mod config;
pub mod error;
pub mod http_helpers;
pub mod signer;
pub mod signing;
pub mod types;

// Re-export main types for convenience
pub use config::BuilderConfig;
pub use error::{BuilderError, Result};
pub use signer::BuilderSigner;
pub use signing::build_hmac_signature;
pub use types::{
    BuilderApiKeyCreds, BuilderHeaderPayload, BuilderType, RemoteBuilderConfig,
    RemoteSignerPayload,
};
