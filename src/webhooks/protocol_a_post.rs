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
use super::verifier::{PaymobWebhookEngine, WebhookError};

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
    /// failures to [`WebhookError::InvalidJsonPayload`]), concatenates the 20 lexicographical
    /// fields from `body.obj` via [`CanonicalTransactionConcatenator`], and verifies the
    /// resulting string against `query_hmac` using `HMAC-SHA512` and
    /// [`subtle::ConstantTimeEq`](subtle::ConstantTimeEq).
    ///
    /// # Errors
    ///
    /// - [`WebhookError::MissingQueryHmac`] if `query_hmac` is empty or whitespace-only.
    /// - [`WebhookError::InvalidJsonPayload`] if `raw_body` is not valid JSON or lacks required
    ///   transaction fields.
    /// - [`WebhookError::MalformedSignatureHex`] if `query_hmac` is not valid hexadecimal.
    /// - [`WebhookError::InvalidSecretKeyLength`] if the configured HMAC secret cannot initialize
    ///   `Hmac<Sha512>`.
    /// - [`WebhookError::SignatureMismatch`] if the constant-time digest comparison fails.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::webhooks::verifier::PaymobWebhookEngine;
    ///
    /// let engine = PaymobWebhookEngine::new("3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE");
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
    /// ```
    pub fn verify_transaction_post(
        &self,
        raw_body: &str,
        query_hmac: &str,
    ) -> Result<TransactionProcessedEvent, WebhookError> {
        if query_hmac.trim().is_empty() {
            return Err(WebhookError::MissingQueryHmac);
        }
        let event: TransactionProcessedEvent =
            serde_json::from_str(raw_body).map_err(|_| WebhookError::InvalidJsonPayload)?;
        let canonical = build_protocol_a_canonical_string(&event.obj);
        self.verify_concatenated_str(&canonical, query_hmac)?;
        Ok(event)
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
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET);
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
        assert!(event.obj.success);
        assert!(!event.obj.error_occured);
    }

    #[test]
    fn test_verify_transaction_post_rejects_mismatched_official_hmac_fail_closed() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET);
        let err = engine
            .verify_transaction_post(
                OFFICIAL_TEST_VECTOR_192036465_JSON,
                OFFICIAL_TEST_VECTOR_192036465_HMAC,
            )
            .expect_err("digest from a different secret must fail closed");
        assert_eq!(err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn test_verify_transaction_post_rejects_tampered_amount_cents() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET);
        let tampered_json = OFFICIAL_TEST_VECTOR_192036465_JSON
            .replacen(""amount_cents": 100000", ""amount_cents": 100", 1);
        let err = engine
            .verify_transaction_post(&tampered_json, SAMPLE_TEST_VECTOR_192036465_HMAC)
            .expect_err("tampered amount_cents must be rejected in constant time");
        assert_eq!(err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn test_verify_transaction_post_rejects_malformed_hex() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET);
        let err_non_hex = engine
            .verify_transaction_post(OFFICIAL_TEST_VECTOR_192036465_JSON, "zzzz-not-hex!")
            .expect_err("non-hex signature must return MalformedSignatureHex");
        assert_eq!(err_non_hex, WebhookError::MalformedSignatureHex);

        let err_odd_len = engine
            .verify_transaction_post(OFFICIAL_TEST_VECTOR_192036465_JSON, "abc")
            .expect_err("odd-length hex signature must return MalformedSignatureHex");
        assert_eq!(err_odd_len, WebhookError::MalformedSignatureHex);
    }

    #[test]
    fn test_verify_transaction_post_rejects_missing_query_hmac() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET);
        let err = engine
            .verify_transaction_post(OFFICIAL_TEST_VECTOR_192036465_JSON, "   ")
            .expect_err("whitespace-only query_hmac must return MissingQueryHmac");
        assert_eq!(err, WebhookError::MissingQueryHmac);
    }

    #[test]
    fn test_verify_transaction_post_rejects_invalid_json() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET);
        let err_syntax = engine
            .verify_transaction_post("{not valid json", SAMPLE_TEST_VECTOR_192036465_HMAC)
            .expect_err("malformed JSON must return InvalidJsonPayload");
        assert_eq!(err_syntax, WebhookError::InvalidJsonPayload);

        let err_missing_fields = engine
            .verify_transaction_post("{"type":"TRANSACTION"}", SAMPLE_TEST_VECTOR_192036465_HMAC)
            .expect_err("incomplete JSON missing obj must return InvalidJsonPayload");
        assert_eq!(err_missing_fields, WebhookError::InvalidJsonPayload);
    }
}
