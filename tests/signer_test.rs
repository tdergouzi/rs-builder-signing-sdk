use rs_builder_signing_sdk::{BuilderApiKeyCreds, BuilderSigner};

#[test]
fn test_create_builder_header_payload() {
    let creds = BuilderApiKeyCreds {
        key: "019894b9-cb40-79c4-b2bd-6aecb6f8c6c5".to_string(),
        secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        passphrase: "1816e5ed89518467ffa78c65a2d6a62d240f6fd6d159cba7b2c4dc510800f75a".to_string(),
    };

    let signer = BuilderSigner::new(creds);
    let request_path = "/order";
    let request_body = r#"{"deferExec":false,"order":{"salt":718139292476,"maker":"0x6e0c80c90ea6c15917308F820Eac91Ce2724B5b5","signer":"0x6e0c80c90ea6c15917308F820Eac91Ce2724B5b5","taker":"0x0000000000000000000000000000000000000000","tokenId":"15871154585880608648532107628464183779895785213830018178010423617714102767076","makerAmount":"5000000","takerAmount":"10000000","side":"BUY","expiration":"0","nonce":"0","feeRateBps":"1000","signatureType":0,"signature":"0x64a2b097cf14f9a24403748b4060bedf8f33f3dbe2a38e5f85bc2a5f2b841af633a2afcc9c4d57e60e4ff1d58df2756b2ca469f984ecfd46cb0c8baba8a0d6411b"},"owner":"5d1c266a-ed39-b9bd-c1f5-f24ae3e14a7b","orderType":"GTC"}"#;
    let request_method = "POST";
    let timestamp = 1758744060;

    let payload = signer
        .create_builder_header_payload(request_method, request_path, Some(request_body), Some(timestamp))
        .expect("Failed to create builder header payload");

    assert!(!payload.is_empty());
    assert_eq!(
        payload.get("POLY_BUILDER_API_KEY").unwrap(),
        "019894b9-cb40-79c4-b2bd-6aecb6f8c6c5"
    );
    assert_eq!(
        payload.get("POLY_BUILDER_PASSPHRASE").unwrap(),
        "1816e5ed89518467ffa78c65a2d6a62d240f6fd6d159cba7b2c4dc510800f75a"
    );
    assert_eq!(payload.get("POLY_BUILDER_TIMESTAMP").unwrap(), "1758744060");
    assert_eq!(
        payload.get("POLY_BUILDER_SIGNATURE").unwrap(),
        "8xh8d0qZHhBcLLYbsKNeiOW3Z0W2N5yNEq1kCVMe5QE="
    );
}

#[test]
fn test_builder_header_contains_all_required_fields() {
    let creds = BuilderApiKeyCreds {
        key: "test-key".to_string(),
        secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        passphrase: "test-passphrase".to_string(),
    };

    let signer = BuilderSigner::new(creds);
    let payload = signer
        .create_builder_header_payload("GET", "/test", None, Some(1234567890))
        .expect("Failed to create builder header payload");

    // Verify all required headers are present
    assert!(payload.contains_key("POLY_BUILDER_API_KEY"));
    assert!(payload.contains_key("POLY_BUILDER_PASSPHRASE"));
    assert!(payload.contains_key("POLY_BUILDER_SIGNATURE"));
    assert!(payload.contains_key("POLY_BUILDER_TIMESTAMP"));
}

#[test]
fn test_builder_header_default_timestamp() {
    let creds = BuilderApiKeyCreds {
        key: "test-key".to_string(),
        secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
        passphrase: "test-passphrase".to_string(),
    };

    let signer = BuilderSigner::new(creds);
    let payload = signer
        .create_builder_header_payload("GET", "/test", None, None)
        .expect("Failed to create builder header payload");

    // Verify timestamp is generated
    let timestamp_str = payload.get("POLY_BUILDER_TIMESTAMP").unwrap();
    let timestamp: u64 = timestamp_str.parse().expect("Invalid timestamp");
    assert!(timestamp > 0);
}

