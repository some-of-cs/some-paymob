use some_paymob::core::error::PaymobError;

pub(crate) fn assert_redacted(rendered: &str, forbidden_secrets: &[&str]) {
    assert!(rendered.contains("[REDACTED]"));
    for secret in forbidden_secrets {
        assert!(
            !rendered.contains(secret),
            "secret `{secret}` leaked in `{rendered}`"
        );
    }
}

fn assert_non_api_error_meta(err: &PaymobError, expected_retryable: bool) {
    assert_eq!(err.is_retryable(), expected_retryable);
    assert_eq!(err.status_code(), None);
}

#[test]
fn tc_1_3_1_paymob_error_redacts_secrets_and_pii_in_display_and_debug() {
    let cases = [
        (
            PaymobError::AuthenticationError(
                "sk_live_abc123 egy_sk_secret999 Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig"
                    .to_string(),
            ),
            vec!["sk_live_abc123", "egy_sk_secret999", "eyJhbGciOiJIUzI1NiJ9"],
        ),
        (
            PaymobError::ValidationError {
                field: "payload",
                reason: "phone_number=+201012345678 pan=4111-1111-1111-1111 cvv=123 token=tok_xyz"
                    .to_string(),
            },
            vec!["+201012345678", "4111-1111-1111-1111", "123", "tok_xyz"],
        ),
        (
            PaymobError::WebhookError(
                "user@example.com card 4111 1111 1111 1111 mobile +20 101 234 5678".to_string(),
            ),
            vec!["user@example.com", "4111 1111 1111 1111", "+20 101 234 5678"],
        ),
    ];

    for (err, secrets) in cases {
        assert_redacted(&err.to_string(), &secrets);
        assert_redacted(&format!("{err:?}"), &secrets);
    }

    assert_non_api_error_meta(
        &PaymobError::EnvironmentMismatch("Test key with Live ID".to_string()),
        false,
    );
    assert_non_api_error_meta(
        &PaymobError::TransportError("connection reset".to_string()),
        true,
    );
}
