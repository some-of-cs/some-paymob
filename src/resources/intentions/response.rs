#![forbid(unsafe_code)]
//! Deserialized response models for Paymob v1 Payment Intentions.
//!
//! Ensures `client_secret` (`egy_csk_*`), payment keys, and saved `card_tokens`
//! are wrapped in [`SecretString`] and redacted as `[REDACTED]` in [`fmt::Debug`].

use std::fmt;

use secrecy::SecretString;
use serde::Deserialize;

use crate::core::credentials::EnvironmentMode;
use crate::core::types::MinorUnitAmount;

const REDACTED: &str = "[REDACTED]";

/// Single payment key entry returned inside [`IntentionResponse::payment_keys`].
///
/// Redacts the sensitive `key` token in [`fmt::Debug`].
#[derive(Clone, Deserialize)]
pub struct IntentionPaymentKey {
    /// Numeric Paymob integration ID associated with this payment key.
    pub integration: u64,
    /// Single-use payment key token (redacted in `Debug` output).
    pub key: SecretString,
    /// Gateway channel type (for example `"VPC"` or `"MIGS"`).
    #[serde(default)]
    pub gateway_type: Option<String>,
    /// Legacy iframe identifier, if configured on the integration.
    #[serde(default)]
    pub iframe_id: Option<String>,
    /// Paymob order identifier linked to this payment key.
    #[serde(default)]
    pub order_id: Option<u64>,
    /// Redirection URL configured for this payment key.
    #[serde(default)]
    pub redirection_url: Option<String>,
}

impl fmt::Debug for IntentionPaymentKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentionPaymentKey")
            .field("integration", &self.integration)
            .field("key", &REDACTED)
            .field("gateway_type", &self.gateway_type)
            .field("iframe_id", &self.iframe_id)
            .field("order_id", &self.order_id)
            .field("redirection_url", &self.redirection_url)
            .finish()
    }
}

/// Payment integration metadata returned in [`IntentionResponse::payment_methods`].
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct ConfiguredPaymentMethod {
    /// Numeric integration ID on Paymob.
    pub integration_id: u64,
    /// Optional merchant-configured alias.
    #[serde(default)]
    pub alias: Option<String>,
    /// Display name of the payment method.
    #[serde(default)]
    pub name: Option<String>,
    /// Payment method type (mapped from `"type"` in JSON).
    #[serde(default, rename = "type")]
    pub method_type: Option<String>,
    /// Whether this integration is configured for Live (`true`) or Test (`false`) mode.
    #[serde(default)]
    pub live: Option<bool>,
    /// Whether CVC is required with MOTO transactions.
    #[serde(default)]
    pub use_cvc_with_moto: Option<bool>,
}

/// Echoed intention details returned inside [`IntentionResponse::intention_detail`].
#[derive(Clone, PartialEq, Eq, Deserialize)]
pub struct IntentionDetail {
    /// Total amount in integer minor units.
    pub amount: MinorUnitAmount,
    /// ISO currency code.
    pub currency: String,
    /// Echoed line items.
    #[serde(default)]
    pub items: Vec<serde_json::Value>,
    /// Echoed billing data (redacted in `Debug`).
    #[serde(default)]
    pub billing_data: Option<serde_json::Value>,
}

impl fmt::Debug for IntentionDetail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentionDetail")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("items_count", &self.items.len())
            .field(
                "billing_data",
                &self.billing_data.as_ref().map(|_| REDACTED),
            )
            .finish()
    }
}

/// Response returned by `POST /v1/intention/` and `PUT /v1/intention/`.
///
/// Wraps `client_secret` (`egy_csk_*`) and `card_tokens` in [`SecretString`]
/// and redacts all sensitive fields in [`fmt::Debug`].
///
/// # Examples
///
/// ```rust
/// use secrecy::ExposeSecret;
/// use some_paymob::resources::intentions::response::IntentionResponse;
///
/// let raw = r#"{
///     "id": "pi_test_123456",
///     "intention_order_id": 987654,
///     "client_secret": "egy_csk_test_secret_abc",
///     "payment_keys": [],
///     "payment_methods": [],
///     "confirmed": false,
///     "status": "intended"
/// }"#;
///
/// let resp: IntentionResponse = serde_json::from_str(raw).unwrap();
/// assert_eq!(resp.id, "pi_test_123456");
/// assert_eq!(resp.client_secret.expose_secret(), "egy_csk_test_secret_abc");
/// assert!(format!("{resp:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, Deserialize)]
pub struct IntentionResponse {
    /// Paymob Payment Intention identifier (for example `pi_*`).
    pub id: String,
    /// Paymob internal order ID created for this intention.
    pub intention_order_id: u64,
    /// Single-use Unified Checkout client secret (`egy_csk_*`), redacted in `Debug`.
    pub client_secret: SecretString,
    /// Generated payment keys for each configured integration.
    #[serde(default)]
    pub payment_keys: Vec<IntentionPaymentKey>,
    /// Echoed intention amount, currency, items, and billing summary.
    #[serde(default)]
    pub intention_detail: Option<IntentionDetail>,
    /// Resolved integration metadata returned by Paymob.
    #[serde(default)]
    pub payment_methods: Vec<ConfiguredPaymentMethod>,
    /// Optional merchant `special_reference`.
    #[serde(default)]
    pub special_reference: Option<String>,
    /// Optional merchant `extras` payload.
    #[serde(default)]
    pub extras: Option<serde_json::Value>,
    /// Whether the intention has been confirmed/paid.
    #[serde(default)]
    pub confirmed: bool,
    /// Current intention lifecycle status (for example `"intended"`).
    #[serde(default)]
    pub status: String,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created: Option<String>,
    /// Optional saved card summary returned by Paymob (redacted in `Debug`).
    #[serde(default)]
    pub card_detail: Option<serde_json::Value>,
    /// Optional saved card tokens associated with the intention (redacted in `Debug`).
    #[serde(default)]
    pub card_tokens: Vec<SecretString>,
    /// Paymob object type discriminator (for example `"intention"`).
    #[serde(default)]
    pub object: Option<String>,
}

impl IntentionResponse {
    /// Returns `true` if any returned [`ConfiguredPaymentMethod`] has a `live`
    /// flag that conflicts with `expected_mode`.
    #[must_use]
    pub fn has_mode_mismatch(&self, expected_mode: EnvironmentMode) -> bool {
        let expected_live = expected_mode.is_live();
        self.payment_methods
            .iter()
            .any(|pm| pm.live.is_some_and(|is_live| is_live != expected_live))
    }
}

impl fmt::Debug for IntentionResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentionResponse")
            .field("id", &self.id)
            .field("intention_order_id", &self.intention_order_id)
            .field("client_secret", &REDACTED)
            .field("payment_keys", &self.payment_keys)
            .field("intention_detail", &self.intention_detail)
            .field("payment_methods", &self.payment_methods)
            .field("special_reference", &self.special_reference)
            .field("extras", &self.extras)
            .field("confirmed", &self.confirmed)
            .field("status", &self.status)
            .field("created", &self.created)
            .field("card_detail", &self.card_detail.as_ref().map(|_| REDACTED))
            .field("card_tokens_count", &self.card_tokens.len())
            .field("object", &self.object)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn sample_response_json() -> &'static str {
        r#"{
            "id": "pi_test_9911",
            "intention_order_id": 445566,
            "client_secret": "egy_csk_test_super_secret_token",
            "payment_keys": [
                {
                    "integration": 4097558,
                    "key": "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5",
                    "gateway_type": "VPC",
                    "order_id": 445566,
                    "redirection_url": "https://example.com/return"
                }
            ],
            "intention_detail": {
                "amount": 100000,
                "currency": "EGP",
                "items": [],
                "billing_data": {"phone_number": "+201116491564"}
            },
            "payment_methods": [
                {
                    "integration_id": 4097558,
                    "alias": "card",
                    "name": "Online Card",
                    "type": "card",
                    "live": false,
                    "use_cvc_with_moto": false
                }
            ],
            "special_reference": "order-9911",
            "extras": {"tenant": "some-cs"},
            "confirmed": false,
            "status": "intended",
            "created": "2026-11-16T18:00:00Z",
            "card_detail": {"pan": "411111xxxxxx1111"},
            "card_tokens": ["tok_saved_9911"],
            "object": "intention"
        }"#
    }

    #[test]
    fn tc_2_1_3_deserializes_full_intention_response_and_checks_mode() {
        let resp: IntentionResponse =
            serde_json::from_str(sample_response_json()).expect("deserialize");

        assert_eq!(resp.id, "pi_test_9911");
        assert_eq!(resp.intention_order_id, 445_566);
        assert_eq!(
            resp.client_secret.expose_secret(),
            "egy_csk_test_super_secret_token"
        );
        assert_eq!(resp.payment_keys.len(), 1);
        assert_eq!(resp.payment_methods[0].integration_id, 4_097_558);
        assert_eq!(resp.object.as_deref(), Some("intention"));
        assert!(!resp.has_mode_mismatch(EnvironmentMode::Test));
        assert!(resp.has_mode_mismatch(EnvironmentMode::Live));
    }

    #[test]
    fn tc_2_1_5_debug_redacts_client_secret_keys_and_card_tokens() {
        let resp: IntentionResponse =
            serde_json::from_str(sample_response_json()).expect("deserialize");
        let dbg = format!("{resp:?}");

        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("egy_csk_test_super_secret_token"));
        assert!(!dbg.contains("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5"));
        assert!(!dbg.contains("tok_saved_9911"));
        assert!(!dbg.contains("+201116491564"));
        assert!(!dbg.contains("411111xxxxxx1111"));
    }
}
