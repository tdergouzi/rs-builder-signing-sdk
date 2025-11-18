use builder_signing_sdk::signing::build_hmac_signature;

#[test]
fn test_build_hmac_signature() {
    let signature = build_hmac_signature(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        1000000,
        "test-sign",
        "/orders",
        Some(r#"{"hash": "0x123"}"#),
    )
    .expect("Failed to build HMAC signature");

    assert!(!signature.is_empty());
    assert_eq!(signature, "ZwAdJKvoYRlEKDkNMwd5BuwNNtg93kNaR_oU2HrfVvc=");
}

#[test]
fn test_build_hmac_signature_no_body() {
    let signature = build_hmac_signature(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        1000000,
        "GET",
        "/markets",
        None,
    )
    .expect("Failed to build HMAC signature");

    assert!(!signature.is_empty());
    // Verify URL-safe encoding (no '+' or '/')
    assert!(!signature.contains('+'));
    assert!(!signature.contains('/'));
}

#[test]
fn test_url_safe_base64_encoding() {
    // Test that the signature uses URL-safe base64 encoding
    let signature = build_hmac_signature(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        1234567890,
        "POST",
        "/test",
        Some("test body"),
    )
    .expect("Failed to build HMAC signature");

    // Verify no '+' or '/' characters (URL-safe requirement)
    assert!(!signature.contains('+'));
    assert!(!signature.contains('/'));
}

#[test]
fn test_invalid_base64_secret() {
    let result = build_hmac_signature(
        "not-valid-base64!!!",
        1000000,
        "GET",
        "/test",
        None,
    );

    assert!(result.is_err());
}

