#![forbid(unsafe_code)]
//! Protocol C: Card Token 8-key `HMAC-SHA512` webhook verifier.
//!
//! Implements fail-closed, constant-time verification for Paymob's card
//! tokenization callbacks (`POST` JSON body + `?hmac=<hex>` query parameter).
//!
//! # Canonical 8-Key Concatenation Order
//!
//! The following 8 fields are extracted from `body.obj` in strict lexicographical
//! order and concatenated without separators:
//!
//! 1. `card_subtype`
//! 2. `created_at`
//! 3. `email`
//! 4. `id`
//! 5. `masked_pan`
//! 6. `merchant_id`
//! 7. `order_id`
//! 8. `token`

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::canonical_tx::CanonicalTransactionConcatenator;
use super::verifier::{PaymobWebhookEngine, WebhookError, WebhookResult};

/// Ergonomic type alias for [`CardTokenObj`].
pub type CardTokenObject = CardTokenObj;

/// Ergonomic type alias for [`CardTokenWebhookEvent`].
pub type CardTokenWebhook = CardTokenWebhookEvent;

/// Lexicographically ordered 8-key HMAC concatenation table for Protocol C
/// card token webhook callbacks.
///
/// # Examples
///
/// ```rust
/// use some_paymob::webhooks::protocol_c_token::TOKEN_HMAC_KEYS;
///
/// assert_eq!(TOKEN_HMAC_KEYS.len(), 8);
/// assert!(TOKEN_HMAC_KEYS.windows(2).all(|pair| pair[0] < pair[1]));
/// assert_eq!(TOKEN_HMAC_KEYS[0], "card_subtype");
/// assert_eq!(TOKEN_HMAC_KEYS[7], "token");
/// ```
pub const TOKEN_HMAC_KEYS: [&str; 8] = [
    "card_subtype",
    "created_at",
    "email",
    "id",
    "masked_pan",
    "merchant_id",
    "order_id",
    "token",
];

/// Top-level Paymob Protocol C card token webhook event envelope.
///
/// Deserialized from the `POST` JSON callback body emitted when a customer
/// card is tokenized during checkout.
///
/// # Examples
///
/// ```rust
/// use some_paymob::webhooks::protocol_c_token::CardTokenWebhookEvent;
///
/// let raw = r#"{
///   "type": "TOKEN",
///   "obj": {
///     "id": 15978654,
///     "token": "tok_test_15978654_abcdef",
///     "masked_pan": "xxxx-xxxx-xxxx-2346",
///     "merchant_id": 302852,
///     "card_subtype": "MasterCard",
///     "created_at": "2024-06-13T11:33:44.592345",
///     "email": "customer@example.com",
///     "order_id": "593881581"
///   }
/// }"#;
///
/// let event: CardTokenWebhookEvent = serde_json::from_str(raw).unwrap();
/// assert_eq!(event.event_type, "TOKEN");
/// assert_eq!(event.obj.id, 15978654);
/// assert_eq!(event.obj.order_id, "593881581");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct CardTokenWebhookEvent {
    /// Paymob webhook event type discriminator (e.g. `"TOKEN"`), mapped from JSON `"type"`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Card token payload object covered by the 8-key HMAC-SHA512 signature.
    pub obj: CardTokenObj,
}

/// Card token payload object (`body.obj`) for Protocol C webhook callbacks.
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] to wipe sensitive card token
/// material from memory on drop, and a custom [`fmt::Debug`] formatter that
/// redacts sensitive fields (`token`, `email`, and `masked_pan`) as `"[REDACTED]"`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::webhooks::protocol_c_token::CardTokenObj;
///
/// let obj = CardTokenObj {
///     id: 15978654,
///     token: "tok_secret_value".to_string(),
///     masked_pan: "xxxx-xxxx-xxxx-2346".to_string(),
///     merchant_id: 302852,
///     card_subtype: "MasterCard".to_string(),
///     created_at: "2024-06-13T11:33:44.592345".to_string(),
///     email: "customer@example.com".to_string(),
///     order_id: "593881581".to_string(),
/// };
///
/// let debug_out = format!("{obj:?}");
/// assert!(debug_out.contains("[REDACTED]"));
/// assert!(!debug_out.contains("tok_secret_value"));
/// assert!(!debug_out.contains("customer@example.com"));
/// assert!(!debug_out.contains("xxxx-xxxx-xxxx-2346"));
/// ```
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
pub struct CardTokenObj {
    /// Unique Paymob card token record identifier.
    pub id: u64,
    /// Reusable tokenized card credential (redacted in `Debug` output).
    pub token: String,
    /// Masked card Primary Account Number (redacted in `Debug` output).
    pub masked_pan: String,
    /// Paymob merchant account identifier.
    pub merchant_id: u64,
    /// Card network or subtype label (e.g. `"MasterCard"`, `"Visa"`).
    pub card_subtype: String,
    /// ISO-8601 creation timestamp string emitted by Paymob.
    pub created_at: String,
    /// Cardholder email address (redacted in `Debug` output).
    pub email: String,
    /// Associated Paymob order identifier string (accepts JSON string or unsigned integer).
    #[serde(deserialize_with = "deserialize_string_or_u64")]
    pub order_id: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum StringOrU64 {
    Str(String),
    Num(u64),
}

fn deserialize_string_or_u64<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    match StringOrU64::deserialize(deserializer)? {
        StringOrU64::Str(s) => Ok(s),
        StringOrU64::Num(n) => Ok(n.to_string()),
    }
}

impl fmt::Debug for CardTokenObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardTokenObj")
            .field("id", &self.id)
            .field("token", &"[REDACTED]")
            .field("masked_pan", &"[REDACTED]")
            .field("merchant_id", &self.merchant_id)
            .field("card_subtype", &self.card_subtype)
            .field("created_at", &self.created_at)
            .field("email", &"[REDACTED]")
            .field("order_id", &self.order_id)
            .finish()
    }
}

/// Builds the canonical 8-key concatenation string for a Protocol C
/// [`CardTokenObj`] payload.
///
/// Concatenates the 8 fields in strict lexicographical key order:
/// `card_subtype`, `created_at`, `email`, `id`, `masked_pan`,
/// `merchant_id`, `order_id`, and `token`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::webhooks::protocol_c_token::{
///     build_protocol_c_canonical_string, CardTokenObj,
/// };
///
/// let obj = CardTokenObj {
///     id: 15978654,
///     token: "tok_test_15978654_abcdef".to_string(),
///     masked_pan: "xxxx-xxxx-xxxx-2346".to_string(),
///     merchant_id: 302852,
///     card_subtype: "MasterCard".to_string(),
///     created_at: "2024-06-13T11:33:44.592345".to_string(),
///     email: "customer@example.com".to_string(),
///     order_id: "593881581".to_string(),
/// };
///
/// assert_eq!(
///     build_protocol_c_canonical_string(&obj),
///     "MasterCard2024-06-13T11:33:44.592345customer@example.com15978654xxxx-xxxx-xxxx-2346302852593881581tok_test_15978654_abcdef"
/// );
/// ```
#[must_use]
pub fn build_protocol_c_canonical_string(obj: &CardTokenObj) -> String {
    let mut concat = CanonicalTransactionConcatenator::new();
    concat.push_str(&obj.card_subtype);
    concat.push_str(&obj.created_at);
    concat.push_str(&obj.email);
    concat.push_u64(obj.id);
    concat.push_str(&obj.masked_pan);
    concat.push_u64(obj.merchant_id);
    concat.push_str(&obj.order_id);
    concat.push_str(&obj.token);
    concat.finish()
}

impl PaymobWebhookEngine {
    /// Verifies a Protocol C Card Token `POST` webhook callback in constant time.
    ///
    /// Parses `raw_body` as a [`CardTokenWebhookEvent`] (mapping JSON syntax or
    /// schema failures to [`WebhookError::InvalidJsonPayload`] with redacted literals),
    /// enforces `event_type == "TOKEN"`, concatenates the 8 fields of `event.obj` in
    /// lexicographical order (`card_subtype`, `created_at`, `email`, `id`, `masked_pan`,
    /// `merchant_id`, `order_id`, `token`), and verifies the resulting string against
    /// `query_hmac` via [`PaymobWebhookEngine::verify_concatenated_str`].
    ///
    /// # Errors
    ///
    /// - [`WebhookError::MissingQueryHmac`] if `query_hmac` is empty or whitespace-only.
    /// - [`WebhookError::InvalidJsonPayload`] if `raw_body` is not valid JSON, lacks
    ///   required card token fields, or has an `event_type` other than `"TOKEN"`.
    /// - [`WebhookError::MalformedSignatureHex`] if `query_hmac` is not valid 128-char hex.
    /// - [`WebhookError::InvalidSecretKeyLength`] if the configured HMAC secret is invalid.
    /// - [`WebhookError::SignatureMismatch`] if the constant-time digest comparison fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::webhooks::verifier::PaymobWebhookEngine;
    ///
    /// let engine = PaymobWebhookEngine::new("3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE")?;
    /// let raw_body = r#"{
    ///   "type": "TOKEN",
    ///   "obj": {
    ///     "id": 15978654,
    ///     "token": "tok_test_15978654_abcdef",
    ///     "masked_pan": "xxxx-xxxx-xxxx-2346",
    ///     "merchant_id": 302852,
    ///     "card_subtype": "MasterCard",
    ///     "created_at": "2024-06-13T11:33:44.592345",
    ///     "email": "customer@example.com",
    ///     "order_id": "593881581"
    ///   }
    /// }"#;
    /// let query_hmac = "38ac96769330ae1b446ba94220b4a0fbf4a536ff407710d0637b32efc1c17cc1\
    ///                   7dde92a831467724a16e09ea7b7054806275d78ce726ba243cc2fea25f30be0d";
    ///
    /// let event = engine.verify_card_token(raw_body, query_hmac)?;
    /// assert_eq!(event.obj.id, 15978654);
    /// assert_eq!(event.obj.order_id, "593881581");
    /// # Ok::<(), some_paymob::webhooks::verifier::WebhookError>(())
    /// ```
    pub fn verify_card_token(
        &self,
        raw_body: &str,
        query_hmac: &str,
    ) -> WebhookResult<CardTokenWebhookEvent> {
        let hmac = super::verifier::require_non_empty_query_hmac(Some(query_hmac))?;
        let event: CardTokenWebhookEvent = super::verifier::parse_webhook_json_str(raw_body)?;
        if event.event_type != "TOKEN" {
            return Err(WebhookError::InvalidJsonPayload(
                "expected webhook type 'TOKEN'".into(),
            ));
        }
        let canonical = Zeroizing::new(build_protocol_c_canonical_string(&event.obj));
        self.verify_concatenated_str(&canonical, hmac)?;
        Ok(event)
    }

    /// Verifies a Protocol C Card Token `POST` webhook from raw request bytes.
    ///
    /// Validates that `raw_body` is valid UTF-8 before delegating to
    /// [`Self::verify_card_token`].
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::InvalidJsonPayload`] if `raw_body` is not valid UTF-8, or any
    /// error returned by [`Self::verify_card_token`].
    pub fn verify_card_token_bytes(
        &self,
        raw_body: &[u8],
        query_hmac: &str,
    ) -> WebhookResult<CardTokenWebhookEvent> {
        let raw_str = super::verifier::decode_webhook_utf8(raw_body)?;
        self.verify_card_token(raw_str, query_hmac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Official Paymob Card Token Test Vector `15978654` payload.
    const OFFICIAL_TEST_VECTOR_15978654_JSON: &str = r#"{
        "type": "TOKEN",
        "obj": {
            "id": 15978654,
            "token": "tok_test_15978654_abcdef",
            "masked_pan": "xxxx-xxxx-xxxx-2346",
            "merchant_id": 302852,
            "card_subtype": "MasterCard",
            "created_at": "2024-06-13T11:33:44.592345",
            "email": "customer@example.com",
            "order_id": "593881581"
        }
    }"#;

    /// Expected 8-key canonical concatenated string for Official Test Vector `15978654`.
    const OFFICIAL_TEST_VECTOR_15978654_CONCAT: &str = "MasterCard2024-06-13T11:33:44.592345customer@example.com15978654xxxx-xxxx-xxxx-2346302852593881581tok_test_15978654_abcdef";

    /// Official Paymob documented HMAC-SHA512 digest prefix/vector for `15978654`.
    const OFFICIAL_TEST_VECTOR_15978654_HMAC: &str = "4c0480c8c5afdba5294dee8ec01e5aa0203c5df0a8b3a45eadf11f2b01c974725d205587dabba70709f3ac2d0c7d7ec93fe69ec462b5a3018190bfd681ebf1d3";

    /// Deterministic SDK test secret and its computed HMAC-SHA512 over Test Vector `15978654`.
    const SAMPLE_HMAC_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";
    const SAMPLE_TEST_VECTOR_15978654_HMAC: &str = "38ac96769330ae1b446ba94220b4a0fbf4a536ff407710d0637b32efc1c17cc17dde92a831467724a16e09ea7b7054806275d78ce726ba243cc2fea25f30be0d";

    #[test]
    fn token_hmac_keys_are_sorted_lexicographically() {
        assert_eq!(TOKEN_HMAC_KEYS.len(), 8);
        assert!(TOKEN_HMAC_KEYS.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn official_vector_15978654_canonical_concatenation_order() {
        let event: CardTokenWebhookEvent = serde_json::from_str(OFFICIAL_TEST_VECTOR_15978654_JSON)
            .expect("official test vector 15978654 JSON must deserialize");
        assert_eq!(event.event_type, "TOKEN");
        assert_eq!(event.obj.id, 15978654);
        assert_eq!(event.obj.masked_pan, "xxxx-xxxx-xxxx-2346");
        assert_eq!(event.obj.order_id, "593881581");
        let canonical = build_protocol_c_canonical_string(&event.obj);
        assert_eq!(canonical, OFFICIAL_TEST_VECTOR_15978654_CONCAT);
    }

    #[test]
    fn verify_card_token_deterministic_vector_15978654_and_uppercase_succeed() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let event = engine
            .verify_card_token(
                OFFICIAL_TEST_VECTOR_15978654_JSON,
                SAMPLE_TEST_VECTOR_15978654_HMAC,
            )
            .expect("valid HMAC over test vector 15978654 must succeed");
        assert_eq!(
            (event.event_type.as_str(), event.obj.id),
            ("TOKEN", 15978654)
        );
        assert_eq!(event.obj.merchant_id, 302852);
        assert_eq!(event.obj.token, "tok_test_15978654_abcdef");

        let upper_hmac = SAMPLE_TEST_VECTOR_15978654_HMAC.to_ascii_uppercase();
        assert!(
            engine
                .verify_card_token(OFFICIAL_TEST_VECTOR_15978654_JSON, &upper_hmac)
                .is_ok()
        );
    }

    #[test]
    fn verify_card_token_rejects_mismatched_official_digest_fail_closed() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let err = engine
            .verify_card_token(
                OFFICIAL_TEST_VECTOR_15978654_JSON,
                OFFICIAL_TEST_VECTOR_15978654_HMAC,
            )
            .expect_err("digest from a different secret must fail closed");
        assert_eq!(err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn verify_card_token_rejects_tampered_token_and_wrong_event_type() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let tampered_json = OFFICIAL_TEST_VECTOR_15978654_JSON.replacen(
            "tok_test_15978654_abcdef",
            "tok_test_15978654_tamper",
            1,
        );
        let err = engine
            .verify_card_token(&tampered_json, SAMPLE_TEST_VECTOR_15978654_HMAC)
            .expect_err("tampered token must be rejected in constant time");
        assert_eq!(err, WebhookError::SignatureMismatch);

        let wrong_type =
            OFFICIAL_TEST_VECTOR_15978654_JSON.replacen("\"TOKEN\"", "\"TRANSACTION\"", 1);
        assert!(matches!(
            engine
                .verify_card_token(&wrong_type, SAMPLE_TEST_VECTOR_15978654_HMAC)
                .unwrap_err(),
            WebhookError::InvalidJsonPayload(_)
        ));
    }

    #[test]
    fn verify_card_token_bytes_and_missing_fields_validation() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        let verified = engine
            .verify_card_token_bytes(
                OFFICIAL_TEST_VECTOR_15978654_JSON.as_bytes(),
                SAMPLE_TEST_VECTOR_15978654_HMAC,
            )
            .expect("bytes verifier must succeed");
        assert_eq!(verified.obj.id, 15978654);

        let incomplete = r#"{"type":"TOKEN","obj":{"id":15978654}}"#;
        assert!(matches!(
            engine
                .verify_card_token(incomplete, SAMPLE_TEST_VECTOR_15978654_HMAC)
                .unwrap_err(),
            WebhookError::InvalidJsonPayload(_)
        ));
    }

    #[test]
    fn verify_card_token_rejects_malformed_hex_missing_hmac_and_invalid_json() {
        let engine = PaymobWebhookEngine::new(SAMPLE_HMAC_SECRET).expect("valid test secret");
        assert_eq!(
            engine
                .verify_card_token(OFFICIAL_TEST_VECTOR_15978654_JSON, "zzzz-not-hex!")
                .unwrap_err(),
            WebhookError::MalformedSignatureHex
        );
        assert_eq!(
            engine
                .verify_card_token(OFFICIAL_TEST_VECTOR_15978654_JSON, "   ")
                .unwrap_err(),
            WebhookError::MissingQueryHmac
        );
        assert!(matches!(
            engine
                .verify_card_token("{not valid json", SAMPLE_TEST_VECTOR_15978654_HMAC)
                .unwrap_err(),
            WebhookError::InvalidJsonPayload(_)
        ));
    }

    #[test]
    fn paymob_docs_verbatim_card_token_canonical_concatenation() {
        let obj = CardTokenObj {
            id: 15978654,
            token: "3f22ce8a4e77125c70f0bc69830e34c36df469351e2fa6be76428be4".to_string(),
            masked_pan: "xxxx-xxxx-xxxx-2346".to_string(),
            merchant_id: 1053928,
            card_subtype: "MasterCard".to_string(),
            created_at: "2026-08-24T13:28:31.015314".to_string(),
            email: "kiyedi3052@claspira.com".to_string(),
            order_id: "593881581".to_string(),
        };
        let canonical = build_protocol_c_canonical_string(&obj);
        assert_eq!(
            canonical,
            "MasterCard2026-08-24T13:28:31.015314kiyedi3052@claspira.com15978654xxxx-xxxx-xxxx-234610539285938815813f22ce8a4e77125c70f0bc69830e34c36df469351e2fa6be76428be4"
        );
    }

    #[test]
    fn card_token_obj_and_envelope_debug_redact_sensitive_fields() {
        let event: CardTokenWebhook = serde_json::from_str(OFFICIAL_TEST_VECTOR_15978654_JSON)
            .expect("official test vector JSON must deserialize");
        let rendered = format!("{event:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("tok_test_15978654_abcdef"));
        assert!(!rendered.contains("customer@example.com"));
        assert!(!rendered.contains("xxxx-xxxx-xxxx-2346"));
        assert!(rendered.contains("15978654") && rendered.contains("MasterCard"));
    }

    #[test]
    fn whk_07_card_token_accepts_numeric_order_id() {
        let json = r#"{
            "id": 15978654,
            "token": "tok_num",
            "masked_pan": "xxxx-2346",
            "merchant_id": 302852,
            "card_subtype": "Visa",
            "created_at": "2024-06-13T11:33:44.592345",
            "email": "a@b.com",
            "order_id": 593881581
        }"#;
        let obj: CardTokenObj = serde_json::from_str(json).expect("numeric order_id");
        assert_eq!(obj.order_id, "593881581");
    }
}
