#![forbid(unsafe_code)]
//! Deserialized response models for Paymob v1 Payment Intentions.
//!
//! Ensures `client_secret` (`egy_csk_*`), payment keys, and saved `card_tokens`
//! are wrapped in [`SecretString`], validated during deserialization, and
//! redacted as `[REDACTED]` in [`fmt::Debug`].

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};

use crate::core::credentials::EnvironmentMode;
use crate::core::error::PaymobError;
use crate::core::types::{MinorUnitAmount, validate_prefixed_id};

const REDACTED: &str = "[REDACTED]";

/// Single payment key entry returned inside [`IntentionResponse::payment_keys`].
///
/// Redacts the sensitive `key` token in [`fmt::Debug`].
#[derive(Clone)]
pub struct IntentionPaymentKey {
    /// Numeric Paymob integration ID associated with this payment key.
    pub integration: u64,
    /// Single-use payment key token (redacted in `Debug` output).
    pub key: SecretString,
    /// Gateway channel type (for example `"VPC"` or `"MIGS"`).
    pub gateway_type: Option<String>,
    /// Legacy iframe identifier, if configured on the integration.
    pub iframe_id: Option<String>,
    /// Paymob order identifier linked to this payment key.
    pub order_id: Option<u64>,
    /// Redirection URL configured for this payment key.
    pub redirection_url: Option<String>,
}

#[derive(Deserialize)]
struct RawIntentionPaymentKey {
    integration: u64,
    key: SecretString,
    #[serde(default)]
    gateway_type: Option<String>,
    #[serde(default)]
    iframe_id: Option<String>,
    #[serde(default)]
    order_id: Option<u64>,
    #[serde(default)]
    redirection_url: Option<String>,
}

impl<'de> Deserialize<'de> for IntentionPaymentKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawIntentionPaymentKey::deserialize(deserializer)?;
        validate_payment_key(raw).map_err(D::Error::custom)
    }
}

fn validate_payment_key(raw: RawIntentionPaymentKey) -> Result<IntentionPaymentKey, PaymobError> {
    let key_str = raw.key.expose_secret().trim();
    if key_str.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "payment_keys.key",
            reason: "payment key token must not be empty".to_owned(),
        });
    }
    Ok(IntentionPaymentKey {
        integration: raw.integration,
        key: SecretString::from(key_str.to_owned()),
        gateway_type: raw.gateway_type,
        iframe_id: raw.iframe_id,
        order_id: raw.order_id,
        redirection_url: raw.redirection_url,
    })
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
#[derive(Clone)]
pub struct IntentionResponse {
    /// Paymob Payment Intention identifier (for example `pi_*`).
    pub id: String,
    /// Paymob internal order ID created for this intention.
    pub intention_order_id: u64,
    /// Single-use Unified Checkout client secret (`egy_csk_*`), redacted in `Debug`.
    pub client_secret: SecretString,
    /// Generated payment keys for each configured integration.
    pub payment_keys: Vec<IntentionPaymentKey>,
    /// Echoed intention amount, currency, items, and billing summary.
    pub intention_detail: Option<IntentionDetail>,
    /// Resolved integration metadata returned by Paymob.
    pub payment_methods: Vec<ConfiguredPaymentMethod>,
    /// Optional merchant `special_reference`.
    pub special_reference: Option<String>,
    /// Optional merchant `extras` payload.
    pub extras: Option<serde_json::Value>,
    /// Whether the intention has been confirmed/paid.
    pub confirmed: bool,
    /// Current intention lifecycle status (for example `"intended"`).
    pub status: String,
    /// ISO-8601 creation timestamp.
    pub created: Option<String>,
    /// Optional saved card summary returned by Paymob (redacted in `Debug`).
    pub card_detail: Option<serde_json::Value>,
    /// Optional saved card tokens associated with the intention (redacted in `Debug`).
    pub card_tokens: Vec<SecretString>,
    /// Paymob object type discriminator (for example `"intention"`).
    pub object: Option<String>,
}

#[derive(Deserialize)]
struct RawIntentionResponse {
    id: String,
    intention_order_id: u64,
    client_secret: SecretString,
    #[serde(default)]
    payment_keys: Vec<IntentionPaymentKey>,
    #[serde(default)]
    intention_detail: Option<IntentionDetail>,
    #[serde(default)]
    payment_methods: Vec<ConfiguredPaymentMethod>,
    #[serde(default)]
    special_reference: Option<String>,
    #[serde(default)]
    extras: Option<serde_json::Value>,
    #[serde(default)]
    confirmed: bool,
    #[serde(default)]
    status: String,
    #[serde(default)]
    created: Option<String>,
    #[serde(default)]
    card_detail: Option<serde_json::Value>,
    #[serde(default)]
    card_tokens: Vec<SecretString>,
    #[serde(default)]
    object: Option<String>,
}

impl<'de> Deserialize<'de> for IntentionResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawIntentionResponse::deserialize(deserializer)?;
        from_raw_intention_response(raw).map_err(D::Error::custom)
    }
}

fn from_raw_intention_response(
    raw: RawIntentionResponse,
) -> Result<IntentionResponse, PaymobError> {
    let id = validate_intention_id(&raw.id)?;
    let client_secret = validate_response_client_secret(raw.client_secret)?;
    Ok(IntentionResponse {
        id,
        intention_order_id: raw.intention_order_id,
        client_secret,
        payment_keys: raw.payment_keys,
        intention_detail: raw.intention_detail,
        payment_methods: raw.payment_methods,
        special_reference: raw.special_reference,
        extras: raw.extras,
        confirmed: raw.confirmed,
        status: raw.status,
        created: raw.created,
        card_detail: raw.card_detail,
        card_tokens: raw.card_tokens,
        object: raw.object,
    })
}

fn validate_intention_id(raw_id: &str) -> Result<String, PaymobError> {
    let trimmed = raw_id.trim();
    if trimmed.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "id",
            reason: "intention id must not be empty".to_owned(),
        });
    }
    if trimmed.starts_with("pi_") {
        validate_prefixed_id(trimmed, "pi_", "id")?;
    }
    Ok(trimmed.to_owned())
}

fn validate_response_client_secret(secret: SecretString) -> Result<SecretString, PaymobError> {
    let trimmed = secret.expose_secret().trim();
    if trimmed.is_empty() || trimmed.chars().any(|ch| ch.is_ascii_control()) {
        return Err(PaymobError::ValidationError {
            field: "client_secret",
            reason: "client_secret must be non-empty and contain no control characters".to_owned(),
        });
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.starts_with("sk_") || lower.contains("_sk_") {
        return Err(PaymobError::ValidationError {
            field: "client_secret",
            reason: "server secret key (`sk_*`) must not appear in client_secret".to_owned(),
        });
    }
    validate_csk_suffix(&lower)?;
    Ok(SecretString::from(trimmed.to_owned()))
}

fn validate_csk_suffix(lower: &str) -> Result<(), PaymobError> {
    let suffix = if let Some((_, rest)) = lower.split_once("_csk_") {
        Some(rest)
    } else {
        lower.strip_prefix("csk_")
    };
    if suffix.is_some_and(str::is_empty) {
        return Err(PaymobError::ValidationError {
            field: "client_secret",
            reason: "client_secret with `csk_` prefix must have a non-empty suffix".to_owned(),
        });
    }
    Ok(())
}

fn infer_client_secret_mode(secret: &SecretString) -> Option<EnvironmentMode> {
    let lower = secret.expose_secret().trim().to_ascii_lowercase();
    if lower.starts_with("csk_test_") || lower.contains("_csk_test_") {
        Some(EnvironmentMode::Test)
    } else if lower.starts_with("csk_live_") || lower.contains("_csk_live_") {
        Some(EnvironmentMode::Live)
    } else {
        None
    }
}

impl IntentionResponse {
    /// Returns `true` if any returned [`ConfiguredPaymentMethod`] has a `live`
    /// flag or `client_secret` prefix mode that conflicts with `expected_mode`.
    #[must_use]
    pub fn has_mode_mismatch(&self, expected_mode: EnvironmentMode) -> bool {
        if infer_client_secret_mode(&self.client_secret)
            .is_some_and(|secret_mode| secret_mode != expected_mode)
        {
            return true;
        }
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
            .field("extras", &self.extras.as_ref().map(|_| REDACTED))
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

    #[test]
    fn tc_2_1_cycle2_response_deserialization_bounds_and_csk_mode_mismatch() {
        let empty_id = serde_json::from_str::<IntentionResponse>(
            r#"{"id":"   ","intention_order_id":1,"client_secret":"egy_csk_test_123"}"#,
        );
        assert!(empty_id.is_err());

        let bare_pi = serde_json::from_str::<IntentionResponse>(
            r#"{"id":"pi_","intention_order_id":1,"client_secret":"egy_csk_test_123"}"#,
        );
        assert!(bare_pi.is_err());

        let empty_secret = serde_json::from_str::<IntentionResponse>(
            r#"{"id":"pi_123","intention_order_id":1,"client_secret":"   "}"#,
        );
        assert!(empty_secret.is_err());

        let sk_in_secret = serde_json::from_str::<IntentionResponse>(
            r#"{"id":"pi_123","intention_order_id":1,"client_secret":"egy_sk_test_123"}"#,
        );
        assert!(sk_in_secret.is_err());

        let bare_csk = serde_json::from_str::<IntentionResponse>(
            r#"{"id":"pi_123","intention_order_id":1,"client_secret":"egy_csk_"}"#,
        );
        assert!(bare_csk.is_err());

        let empty_payment_key =
            serde_json::from_str::<IntentionPaymentKey>(r#"{"integration":4097558,"key":"   "}"#);
        assert!(empty_payment_key.is_err());

        let live_secret_resp = serde_json::from_str::<IntentionResponse>(
            r#"{"id":"pi_123","intention_order_id":1,"client_secret":"egy_csk_live_abc"}"#,
        )
        .expect("valid live secret response");
        assert!(live_secret_resp.has_mode_mismatch(EnvironmentMode::Test));
        assert!(!live_secret_resp.has_mode_mismatch(EnvironmentMode::Live));
    }

    #[test]
    fn res1_03_intention_response_debug_redacts_extras() {
        let payload = serde_json::json!({
            "id": "pi_test_redaction_extras",
            "intention_order_id": 123456,
            "client_secret": "egy_csk_test_secret_123",
            "extras": { "customer_secret_note": "top-secret-pii-value" },
            "status": "intended"
        });
        let resp: IntentionResponse =
            serde_json::from_value(payload).expect("valid IntentionResponse");
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("top-secret-pii-value"));
    }
}
