# rs-builder-signing-sdk

🦀 Rust implementation of Polymarket Builder API authentication with HMAC-SHA256 signatures.

A complete Rust port of the TypeScript `@polymarket/builder-signing-sdk` package for creating authenticated headers for Polymarket Builder API requests.

## Features

- 🔐 HMAC-SHA256 signature generation with URL-safe base64 encoding
- 🏠 Local signing with API credentials
- 🌐 Remote signing via HTTP service
- ✅ Full compatibility with TypeScript SDK

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
builder-signing-sdk = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

## Quick Start

### Local Signing

```rust
use builder_signing_sdk::{BuilderConfig, BuilderApiKeyCreds};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create credentials
    let creds = BuilderApiKeyCreds {
        key: "019894b9-cb40-79c4-b2bd-6aecb6f8c6c5".to_string(),
        secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        passphrase: "1816e5ed89518467ffa78c65a2d6a62d240f6fd6d159cba7b2c4dc510800f75a".to_string(),
    };

    // Create config with local credentials
    let config = BuilderConfig::new(None, Some(creds))?;

    // Generate headers
    let headers = config.generate_builder_headers(
        "POST",
        "/order",
        Some(r#"{"marketId": "0x123"}"#),
        None, // Uses current timestamp
    ).await?;

    println!("Headers: {:?}", headers);
    // Headers will contain:
    // - POLY_BUILDER_API_KEY
    // - POLY_BUILDER_PASSPHRASE
    // - POLY_BUILDER_SIGNATURE
    // - POLY_BUILDER_TIMESTAMP

    Ok(())
}
```

### Remote Signing

```rust
use builder_signing_sdk::{BuilderConfig, RemoteBuilderConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create remote signer configuration
    let remote_config = RemoteBuilderConfig {
        url: "https://your-signer-service.com/sign".to_string(),
        token: Some("your-auth-token".to_string()), // Optional
    };

    // Create config with remote signer
    let config = BuilderConfig::new(Some(remote_config), None)?;

    // Generate headers (calls remote signer)
    let headers = config.generate_builder_headers(
        "POST",
        "/order",
        Some(r#"{"marketId": "0x123"}"#),
        None,
    ).await?;

    println!("Headers: {:?}", headers);

    Ok(())
}
```

## Usage

```bash
# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Run specific test
cargo test test_build_hmac_signature

# Check code quality
cargo clippy

# Format code
cargo fmt
```

## Security Considerations

- 🔒 **API Keys**: Never hardcode API keys or secrets. Use environment variables or secure key management systems
- 🔐 **HMAC Signatures**: All requests are signed using HMAC-SHA256 to ensure authenticity and prevent tampering
- ✅ **Timestamp Validation**: Signatures include timestamps to prevent replay attacks
- 🛡️ **TLS/HTTPS**: Always use HTTPS for remote signing services to protect credentials in transit
- 🔑 **Credential Storage**: Store base64-encoded secrets securely and rotate them regularly

## Compatibility

This SDK is a Rust port of the TypeScript [@polymarket/builder-signing-sdk](https://github.com/polymarket/builder-signing-sdk) and maintains identical HMAC signature generation and API behavior.

## Notice

⚠️ **AI-Generated Code**: This library was generated with AI assistance. While it has been tested and verified against the TypeScript implementation, users should:
- Review the code thoroughly before using in production
- Conduct their own security audits
- Test extensively with their specific use cases
- Verify signature compatibility with their infrastructure
- Use at their own risk

## License

MIT

## Acknowledgments

- Original TypeScript implementation: [Polymarket builder-signing-sdk](https://github.com/polymarket/builder-signing-sdk)

---

**Made with 🦀 by the Polymarket community**

