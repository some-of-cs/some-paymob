//! Protocol A: Transaction Processed `POST` 20-key HMAC-SHA512 webhook verifier.
//!
//! Implements fail-closed, constant-time verification for Paymob's server-to-server
//! `TRANSACTION` processed callbacks (`POST` JSON body + `?hmac=<hex>` query parameter).
//!
//! # Canonical 20-Key Concatenation Order
//!
//! The following 20 fields are extracted from `body.obj` in strict lexicographical order
//! and concatenated without separators (`error_occured` spelled with one `'r'`, booleans
//! serialized as lowercase `"true"` / `"false"`):
//!
//! 1. `amount_cents`
//! 2. `created_at`
//! 3. `currency`
//! 4. `error_occured`
//! 5. `has_parent_transaction`
//! 6. `obj.id`
//! 7. `integration_id`
//! 8. `is_3d_secure`
//! 9. `is_auth`
//! 10. `is_capture`
//! 11. `is_refunded`
//! 12. `is_standalone_payment`
//! 13. `is_voided`
//! 14. `obj.order.id`
//! 15. `owner`
//! 16. `pending`
//! 17. `source_data.pan`
//! 18. `source_data.sub_type`
//! 19. `source_data.type`
//! 20. `success`

use super::canonical_tx::CanonicalTransactionConcatenator;
use super::tx_models::{TransactionProcessedEvent, TransactionWebhookObj};
use super::verifier::{PaymobWebhookEngine, WebhookError, WebhookResult};

/// Builds the canonical 20-key concatenation string for a Protocol A
/// [`TransactionWebhookObj`] payload.
///
/// Extracts the 20 lexicographically sorted fields from `obj` (preserving
/// Paymob's single-`r` `error_occured` key and nested `obj.order.id`) using
/// [`CanonicalTransactionConcatenator`], formatting booleans as lowercase
/// `"true"` or `"false"` without intermediate heap allocations.
///
/// # Examples
///
/// ```rust
/// use some_paymob::webhooks::protocol_a_post::build_protocol_a_canonical_string;
/// use some_paymob::webhooks::tx_models::TransactionProcessedEvent;
///
/// let raw_json = r#"{
///   "type": "TRANSACTION",
///   "obj": {
///     "id": 192036465,
///     "pending": false,
///     "amount_cents": 100000,
///     "success": true,
///     "is_auth": false,
///     "is_capture": false,
///     "is_standalone_payment": true,
///     "is_voided": false,
///     "is_refunded": false,
///     "is_3d_secure": true,
///     "is_captured": false,
///     "integration_id": 4097558,
///     "has_parent_transaction": false,
///     "order": { "id": 217503754 },
///     "created_at": "2024-06-13T11:33:44.592345",
///     "currency": "EGP",
///     "source_data": { "pan": "2346", "type": "card", "sub_type": "MasterCard" },
///     "error_occured": false,
///     "owner": 302852
///   }
/// }"#;
///
/// let event: TransactionProcessedEvent = serde_json::from_str(raw_json).unwrap();
/// let canonical = build_protocol_a_canonical_string(&event.obj);
/// assert_eq!(
///     canonical,
///     "1000002024-06-13T11:33:44.592345EGPfalsefalse1920364654097558truefalsefalsefalsetruefalse217503754302852false2346MasterCardcardtrue"
/// );
/// ```
#[must_use]
pub fn build_protocol_a_canonical_string(obj: &TransactionWebhookObj) -> String {
    let mut concat = CanonicalTransactionConcatenator::new();
    concat.push_u64(obj.amount_cents);
    concat.push_str(&obj.created_at);
    concat.push_str(&obj.currency);
    concat.push_bool(obj.error_occured);
    concat.push_bool(obj.has_parent_transaction);
    concat.push_u64(obj.id);
    concat.push_u64(obj.integration_id);
    concat.push_bool(obj.is_3d_secure);
    concat.push_bool(obj.is_auth);
    concat.push_bool(obj.is_capture);
    concat.push_bool(obj.is_refunded);
    concat.push_bool(obj.is_standalone_payment);
    concat.push_bool(obj.is_voided);
    concat.push_u64(obj.order.id);
    concat.push_u64(obj.owner);
    concat.push_bool(obj.pending);
    concat.push_str(&obj.source_data.pan);
    concat.push_str(&obj.source_data.sub_type);
    concat.push_str(&obj.source_data.source_type);
    concat.push_bool(obj.success);
    concat.finish()
}

impl PaymobWebhookEngine {
    /// Verifies a Protocol A Transaction Processed `POST` webhook callback in constant time.
    ///
    /// Parses `raw_body` as a [`TransactionProcessedEvent`] (mapping JSON syntax or schema
    /// failures to [`WebhookError::InvalidJsonPayload`] with redacted string literals),
    /// enforces `event_type == "TRANSACTION"`, concatenates the 20 lexicographical
    /// fields from `body.obj` via [`CanonicalTransactionConcatenator`], and verifies the
    /// resulting string against `query_hmac` using `HMAC-SHA512` and
    /// [`subtle::ConstantTimeEq`].
    ///
    /// # Errors
    ///
    /// - [`WebhookError::MissingQueryHmac`] if `query_hmac` is empty or whitespace-only.
    /// - [`WebhookError::InvalidJsonPayload`] if `raw_body` is not valid JSON, lacks required
    ///   transaction fields, or has an `event_type` other than `"TRANSACTION"`.
    /// - [`WebhookError::MalformedSignatureHex`] if `query_hmac` is not valid hexadecimal.
    /// - [`WebhookError::InvalidSecretKeyLength`] if the configured HMAC secret cannot initialize
    ///   `Hmac<Sha512>`.
    /// - [`WebhookError::SignatureMismatch`] if the constant-time digest comparison fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    ///
    /// let engine = PaymobWebhookEngine::new("3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE")?;
    /// let raw_body = r#"{
    ///   "type": "TRANSACTION",
    ///   "obj": {
    ///     "id": 192036465,
    ///     "pending": false,
    ///     "amount_cents": 100000,
    ///     "success": true,
    ///     "is_auth": false,
    ///     "is_capture": false,
    ///     "is_standalone_payment": true,
    ///     "is_voided": false,
    ///     "is_refunded": false,
    ///     "is_3d_secure": true,
    ///     "is_captured": false,
    ///     "integration_id": 4097558,
    ///     "has_parent_transaction": false,
    ///     "order": { "id": 217503754 },
    ///     "created_at": "2024-06-13T11:33:44.592345",
    ///     "currency": "EGP",
    ///     "source_data": { "pan": "2346", "type": "card", "sub_type": "MasterCard" },
    ///     "error_occured": false,
    ///     "owner": 302852
    ///   }
    /// }"#;
    /// let query_hmac = "28f19ec85986d4534f77201b00bf750948334753847f437b538cc699f3de447cd0d62a5f521c7b20069bd255f48e8d891f0033167ad35b434d532b61e85a3da7";
    ///
    /// let event = engine.verify_transaction_post(raw_body, query_hmac).unwrap();
    /// assert_eq!(event.obj.id, 192036465);
    /// assert_eq!(event.obj.order.id, 217503754);
    /// assert!(event.obj.success);
    /// # Ok::<(), WebhookError>(())
    /// ```
    pub fn verify_transaction_post(
        &self,
        raw_body: &str,
        query_hmac: &str,
    ) -> WebhookResult<TransactionProcessedEvent> {
        let hmac = super::verifier::require_non_empty_query_hmac(Some(query_hmac))?;
        let event: TransactionProcessedEvent = super::verifier::parse_webhook_json_str(raw_body)?;
        if event.event_type != "TRANSACTION" {
            return Err(WebhookError::InvalidJsonPayload(
                "expected webhook type 'TRANSACTION'".into(),
            ));
        }
        let canonical = build_protocol_a_canonical_string(&event.obj);
        self.verify_concatenated_str(&canonical, hmac)?;
        Ok(event)
    }

    /// Verifies a Protocol A Transaction Processed `POST` webhook from raw request bytes.
    ///
    /// Validates that `raw_body` is valid UTF-8 before delegating to
    /// [`Self::verify_transaction_post`].
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::InvalidJsonPayload`] if `raw_body` is not valid UTF-8, or any
    /// error returned by [`Self::verify_transaction_post`].
    pub fn verify_transaction_post_bytes(
        &self,
        raw_body: &[u8],
        query_hmac: &str,
    ) -> WebhookResult<TransactionProcessedEvent> {
        let raw_str = super::verifier::decode_webhook_utf8(raw_body)?;
        self.verify_transaction_post(raw_str, query_hmac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official Paymob Transaction Processed POST payload for Transaction `192036465`.
    const OFFICIAL_TEST_VECTOR_192036465_JSON: &str = r#"{
        "type": "TRANSACTION",
        "obj": {
            "id": 192036465,
            "pending": false,
            "amount_cents": 100000,
            "success": true,
            "is_auth": false,
            "is_capture": false,
            "is_standalone_payment": true,
            "is_voided": false,
            "is_refunded": false,
            "is_3d_secure": true,
            "integration_id": 4097558,
            "profile_id": 164295,
            "has_parent_transaction": false,
            "order": {
                "id": 217503754,
                "created_at": "2024-06-13T11:32:09.628623",
                "delivery_needed": false,
                "amount_cents": 100000,
                "currency": "EGP"
            },
            "created_at": "2024-06-13T11:33:44.592345",
            "transaction_processed_callback_responses": [],
            "currency": "EGP",
            "source_data": {
                "pan": "2346",
                "type": "card",
                "tenure": null,
                "sub_type": "MasterCard"
            },
            "api_source": "IFRAME",
            "is_void": false,
            "is_refund": false,
            "error_occured": false,
            "is_live": false,
            "refunded_amount_cents": null,
            "is_captured": false,
            "captured_amount": null,
            "owner": 302852
        },
        "issuer_bank": null,
        "transaction_processed_callback_responses": ""
    }"#;

    /// Expected 20-key canonical concatenated string for Official Test Vector `192036465`.
    const OFFICIAL_TEST_VECTOR_192036465_CONCAT: &str = "1000002024-06-13T11:33:44.592345EGPfalsefalse1920364654097558truefalsefalsefalsetruefalse217503754302852false2346MasterCardcardtrue";

    /// Official Paymob documented HMAC-SHA512 digest for Test Vector `192036465`.
    const OFFICIAL_TEST_VECTOR_192036465_HMAC: &str = "fa8ac0b7f3852e60c50e7fdd4ea5ef0bda96030c19dea1d55df8c76d6c08ab1877774662cbb04981dc84839ad4da560bcc8cb53b8973548657f7e8f8d2e79930";

    /// Known SDK test secret and its deterministic HMAC-SHA512 over Test Vector `192036465`.
    const SAMPLE_HMAC_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";
    const SAMPLE_TEST_VECTOR_192036465_HMAC: &str = "28f19ec85986d4534f77201b00bf750948334753847f437b538cc699f3de447cd0d62a5f521c7b20069bd255f48e8d891f0033167ad35b434d532b61e85a3da7";

    const SINGLE_FIELD_TAMPER_PAIRS: [(&str, &str); 20] = [
        ("\"amount_cents\": 100000", "\"amount_cents\": 100001"),
        (
            "\"created_at\": \"2024-06-13T11:33:44.592345\"",
            "\"created_at\": \"2024-06-13T11:33:44.592346\"",
        ),
        ("\"currency\": \"EGP\"", "\"currency\": \"USD\""),
        ("\"error_occured\": false", "\"error_occured\": true"),
        (
            "\"has_parent_transaction\": false",
            "\"has_parent_transaction\": true",
        ),
        ("\"id\": 192036465", "\"id\": 192036466"),
        ("\"integration_id\": 4097558", "\"integration_id\": 4097559"),
        ("\"is_3d_secure\": true", "\"is_3d_secure\": false"),
        ("\"is_auth\": false", "\"is_auth\": true"),
        ("\"is_capture\": false", "\"is_capture\": true"),
        ("\"is_refunded\": false", "\"is_refunded\": true"),
        (
            "\"is_standalone_payment\": true",
            "\"is_standalone_payment\": false",
        ),
        ("\"is_voided\": false", "\"is_voided\": true"),
        ("\"id\": 217503754", "\"id\": 217503755"),
        ("\"owner\": 302852", "\"owner\": 302853"),
        ("\"pending\": false", "\"pending\": true"),
        ("\"pan\": \"2346\"", "\"pan\": \"9999\""),
        ("\"sub_type\": \"MasterCard\"", "\"sub_type\": \"Visa\""),
        ("\"type\": \"card\"", "\"type\": \"wallet\""),
        ("\"success\": true", "\"success\": false"),
    ];

    #[test]
    fn test_official_vector_192036465_canonical_concatenation() {
        let event: TransactionProcessedEvent =
            serde_json::from_str(OFFICIAL_TEST_VECTOR_192036465_JSON)
                .expect("official test vector JSON must deserialize");
        let canonical = build_protocol_a_canonical_string(&event.obj);
        assert_eq!(canonical, OFFICIAL_TEST_VECTOR_192036465_CONCAT);
    }

    #[test]
    fn test_verify_transaction_post_official_vector_192036465_valid() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let event = engine
            .verify_transaction_post(
                OFFICIAL_TEST_VECTOR_192036465_JSON,
                SAMPLE_TEST_VECTOR_192036465_HMAC,
            )
            .expect("valid HMAC over official test vector 192036465 must succeed");
        assert_eq!(event.obj.id, 192036465);
        assert_eq!(event.obj.order.id, 217503754);
        assert_eq!(event.obj.amount_cents, 100_000);
        assert_eq!(event.obj.currency, "EGP");
        assert!(event.obj.success && !event.obj.error_occured);
    }

    #[test]
    fn test_verify_transaction_post_accepts_uppercase_and_whitespace_hmac() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let upper_padded = format!(
            "  {} \n",
            SAMPLE_TEST_VECTOR_192036465_HMAC.to_ascii_uppercase()
        );
        let event = engine
            .verify_transaction_post(OFFICIAL_TEST_VECTOR_192036465_JSON, &upper_padded)
            .expect("uppercase padded HMAC must verify");
        assert_eq!(event.transaction_id(), 192036465);
    }

    #[test]
    fn test_verify_transaction_post_rejects_mismatched_official_hmac_fail_closed() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let err = engine
            .verify_transaction_post(
                OFFICIAL_TEST_VECTOR_192036465_JSON,
                OFFICIAL_TEST_VECTOR_192036465_HMAC,
            )
            .expect_err("digest from a different secret must fail closed");
        assert_eq!(err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn test_verify_transaction_post_rejects_all_20_single_field_tamperings() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        for (from, to) in SINGLE_FIELD_TAMPER_PAIRS {
            let tampered = OFFICIAL_TEST_VECTOR_192036465_JSON.replace(from, to);
            let err = engine
                .verify_transaction_post(&tampered, SAMPLE_TEST_VECTOR_192036465_HMAC)
                .expect_err("single field tamper must fail");
            assert_eq!(err, WebhookError::SignatureMismatch);
        }
    }

    #[test]
    fn test_verify_transaction_post_rejects_wrong_event_type() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let wrong_type = OFFICIAL_TEST_VECTOR_192036465_JSON.replacen(
            "\"type\": \"TRANSACTION\"",
            "\"type\": \"TOKEN\"",
            1,
        );
        let err = engine
            .verify_transaction_post(&wrong_type, SAMPLE_TEST_VECTOR_192036465_HMAC)
            .expect_err("wrong event_type must fail");
        assert!(matches!(err, WebhookError::InvalidJsonPayload(_)));
    }

    #[test]
    fn test_verify_transaction_post_bytes_valid_and_invalid_utf8() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let ok_evt = engine
            .verify_transaction_post_bytes(
                OFFICIAL_TEST_VECTOR_192036465_JSON.as_bytes(),
                SAMPLE_TEST_VECTOR_192036465_HMAC,
            )
            .expect("valid bytes must verify");
        assert_eq!(ok_evt.transaction_id(), 192036465);

        let err = engine
            .verify_transaction_post_bytes(&[0xff, 0xfe, 0x00], SAMPLE_TEST_VECTOR_192036465_HMAC)
            .expect_err("invalid UTF-8 must fail");
        assert!(matches!(err, WebhookError::InvalidJsonPayload(_)));
    }

    #[test]
    fn test_verify_transaction_post_rejects_malformed_hex_and_missing_hmac() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let err_non_hex = engine
            .verify_transaction_post(OFFICIAL_TEST_VECTOR_192036465_JSON, "zzzz-not-hex!")
            .expect_err("non-hex signature must return MalformedSignatureHex");
        assert_eq!(err_non_hex, WebhookError::MalformedSignatureHex);

        let err_missing = engine
            .verify_transaction_post(OFFICIAL_TEST_VECTOR_192036465_JSON, "   ")
            .expect_err("whitespace-only query_hmac must return MissingQueryHmac");
        assert_eq!(err_missing, WebhookError::MissingQueryHmac);
    }

    #[test]
    fn test_verify_transaction_post_rejects_invalid_json() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let err_syntax = engine
            .verify_transaction_post("{not valid json", SAMPLE_TEST_VECTOR_192036465_HMAC)
            .expect_err("malformed JSON must return InvalidJsonPayload");
        assert!(matches!(err_syntax, WebhookError::InvalidJsonPayload(_)));

        let err_missing_fields = engine
            .verify_transaction_post(
                r#"{"type":"TRANSACTION"}"#,
                SAMPLE_TEST_VECTOR_192036465_HMAC,
            )
            .expect_err("incomplete JSON missing obj must return InvalidJsonPayload");
        assert!(matches!(
            err_missing_fields,
            WebhookError::InvalidJsonPayload(_)
        ));
    }
}
