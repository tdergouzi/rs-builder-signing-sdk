use rs_builder_signing_sdk::{BuilderApiKeyCreds, BuilderConfig, BuilderType, RemoteBuilderConfig};
use mockito;

#[test]
fn test_is_valid() {
    let creds = BuilderApiKeyCreds {
        key: "019894b9-cb40-79c4-b2bd-6aecb6f8c6c5".to_string(),
        secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        passphrase: "1816e5ed89518467ffa78c65a2d6a62d240f6fd6d159cba7b2c4dc510800f75a".to_string(),
    };

    // Valid with local creds
    let builder_config = BuilderConfig::new(None, Some(creds)).expect("Failed to create config");
    assert!(builder_config.is_valid());

    // Invalid with no config
    let result = BuilderConfig::new(None, None);
    assert!(result.is_err());
}

#[test]
fn test_get_builder_type() {
    let creds = BuilderApiKeyCreds {
        key: "019894b9-cb40-79c4-b2bd-6aecb6f8c6c5".to_string(),
        secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        passphrase: "1816e5ed89518467ffa78c65a2d6a62d240f6fd6d159cba7b2c4dc510800f75a".to_string(),
    };

    // Local type
    let builder_config = BuilderConfig::new(None, Some(creds.clone())).unwrap();
    assert_eq!(builder_config.get_builder_type(), BuilderType::Local);

    // Remote type
    let remote_config = RemoteBuilderConfig {
        url: "http://localhost:3000/sign".to_string(),
        token: None,
    };
    let builder_config = BuilderConfig::new(Some(remote_config), None).unwrap();
    assert_eq!(builder_config.get_builder_type(), BuilderType::Remote);

    // If both present, local is preferred
    let remote_config = RemoteBuilderConfig {
        url: "http://localhost:3000/sign".to_string(),
        token: None,
    };
    let builder_config = BuilderConfig::new(Some(remote_config), Some(creds)).unwrap();
    assert_eq!(builder_config.get_builder_type(), BuilderType::Local);
}

#[tokio::test]
async fn test_generate_builder_headers() {
    let creds = BuilderApiKeyCreds {
        key: "019894b9-cb40-79c4-b2bd-6aecb6f8c6c5".to_string(),
        secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        passphrase: "1816e5ed89518467ffa78c65a2d6a62d240f6fd6d159cba7b2c4dc510800f75a".to_string(),
    };

    let builder_config = BuilderConfig::new(None, Some(creds)).unwrap();

    let request_path = "/order";
    let request_body = r#"{"deferExec":false,"order":{"salt":718139292476,"maker":"0x6e0c80c90ea6c15917308F820Eac91Ce2724B5b5","signer":"0x6e0c80c90ea6c15917308F820Eac91Ce2724B5b5","taker":"0x0000000000000000000000000000000000000000","tokenId":"15871154585880608648532107628464183779895785213830018178010423617714102767076","makerAmount":"5000000","takerAmount":"10000000","side":"BUY","expiration":"0","nonce":"0","feeRateBps":"1000","signatureType":0,"signature":"0x64a2b097cf14f9a24403748b4060bedf8f33f3dbe2a38e5f85bc2a5f2b841af633a2afcc9c4d57e60e4ff1d58df2756b2ca469f984ecfd46cb0c8baba8a0d6411b"},"owner":"5d1c266a-ed39-b9bd-c1f5-f24ae3e14a7b","orderType":"GTC"}"#;
    let request_method = "POST";
    let timestamp = 1758744060;

    let headers = builder_config
        .generate_builder_headers(request_method, request_path, Some(request_body), Some(timestamp))
        .await
        .expect("Failed to generate builder headers");

    assert!(!headers.is_empty());
    assert_eq!(
        headers.get("POLY_BUILDER_API_KEY").unwrap(),
        "019894b9-cb40-79c4-b2bd-6aecb6f8c6c5"
    );
    assert_eq!(
        headers.get("POLY_BUILDER_PASSPHRASE").unwrap(),
        "1816e5ed89518467ffa78c65a2d6a62d240f6fd6d159cba7b2c4dc510800f75a"
    );
    assert_eq!(headers.get("POLY_BUILDER_TIMESTAMP").unwrap(), "1758744060");
    assert_eq!(
        headers.get("POLY_BUILDER_SIGNATURE").unwrap(),
        "8xh8d0qZHhBcLLYbsKNeiOW3Z0W2N5yNEq1kCVMe5QE="
    );
}

#[tokio::test]
async fn test_generate_builder_headers_remote() {
    // Create mock server
    let mut server = mockito::Server::new_async().await;
    let mock_response = serde_json::json!({
        "POLY_BUILDER_API_KEY": "test-api-key",
        "POLY_BUILDER_TIMESTAMP": "1758744060",
        "POLY_BUILDER_PASSPHRASE": "test-passphrase",
        "POLY_BUILDER_SIGNATURE": "test-signature"
    });

    // Set up mock endpoint
    let _m = server
        .mock("POST", "/sign")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(mock_response.to_string())
        .create_async()
        .await;

    // Create config with remote signer URL
    let remote_config = RemoteBuilderConfig {
        url: format!("{}/sign", server.url()),
        token: None,
    };

    let builder_config = BuilderConfig::new(Some(remote_config), None).unwrap();
    assert_eq!(builder_config.get_builder_type(), BuilderType::Remote);

    let request_path = "/order";
    let request_body = r#"{"deferExec":false,"order":{"salt":718139292476,"maker":"0x6e0c80c90ea6c15917308F820Eac91Ce2724B5b5","signer":"0x6e0c80c90ea6c15917308F820Eac91Ce2724B5b5","taker":"0x0000000000000000000000000000000000000000","tokenId":"15871154585880608648532107628464183779895785213830018178010423617714102767076","makerAmount":"5000000","takerAmount":"10000000","side":"BUY","expiration":"0","nonce":"0","feeRateBps":"1000","signatureType":0,"signature":"0x64a2b097cf14f9a24403748b4060bedf8f33f3dbe2a38e5f85bc2a5f2b841af633a2afcc9c4d57e60e4ff1d58df2756b2ca469f984ecfd46cb0c8baba8a0d6411b"},"owner":"5d1c266a-ed39-b9bd-c1f5-f24ae3e14a7b","orderType":"GTC"}"#;
    let request_method = "POST";
    let timestamp = 1758744060;

    let headers = builder_config
        .generate_builder_headers(request_method, request_path, Some(request_body), Some(timestamp))
        .await
        .expect("Failed to generate builder headers");

    // Verify the response
    assert!(!headers.is_empty());
    assert_eq!(headers.get("POLY_BUILDER_API_KEY").unwrap(), "test-api-key");
    assert_eq!(
        headers.get("POLY_BUILDER_TIMESTAMP").unwrap(),
        "1758744060"
    );
    assert_eq!(
        headers.get("POLY_BUILDER_PASSPHRASE").unwrap(),
        "test-passphrase"
    );
    assert_eq!(
        headers.get("POLY_BUILDER_SIGNATURE").unwrap(),
        "test-signature"
    );
}