#![forbid(unsafe_code)]
//! Transaction webhook payload models for Paymob Protocol A (`TRANSACTION` events).
//!
//! These types model the JSON envelope delivered to Paymob transaction processed
//! webhook endpoints while enforcing:
//! - Integer minor-unit monetary fields (`u64` cents, zero `f32`/`f64` floats).
//! - Custom `Debug` implementations that redact sensitive card PANs and
//!   `payment_key_claims` payloads as `"[REDACTED]"`.
//!
//! # Examples
//!
//! ```rust
//! use some_paymob::webhooks::tx_models::{
//!     TransactionOrderRef, TransactionProcessedEvent, TransactionSourceData,
//!     TransactionWebhookObj,
//! };
//!
//! let json = r#"{
//!     "type": "TRANSACTION",
//!     "obj": {
//!         "id": 123456,
//!         "pending": false,
//!         "amount_cents": 10000,
//!         "success": true,
//!         "is_auth": false,
//!         "is_capture": false,
//!         "is_standalone_payment": true,
//!         "is_voided": false,
//!         "is_refunded": false,
//!         "is_3d_secure": true,
//!         "is_captured": false,
//!         "refunded_amount_cents": 0,
//!         "captured_amount": 0,
//!         "integration_id": 42,
//!         "has_parent_transaction": false,
//!         "order": { "id": 998877 },
//!         "created_at": "2026-11-16T12:00:00.000000",
//!         "currency": "EGP",
//!         "source_data": {
//!             "pan": "9876",
//!             "sub_type": "MasterCard",
//!             "type": "card"
//!         },
//!         "error_occured": false,
//!         "owner": 777,
//!         "payment_key_claims": { "email": "buyer@example.com" }
//!     }
//! }"#;
//!
//! let event: TransactionProcessedEvent = serde_json::from_str(json).expect("valid payload");
//! assert_eq!(event.event_type, "TRANSACTION");
//! assert_eq!(event.amount_cents(), 10000);
//! assert!(event.is_approved());
//! assert_eq!(event.obj.order, TransactionOrderRef { id: 998877 });
//!
//! let debug_output = format!("{event:?}");
//! assert!(debug_output.contains("[REDACTED]"));
//! assert!(!debug_output.contains("9876"));
//! assert!(!debug_output.contains("buyer@example.com"));
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Ergonomic type alias for [`TransactionProcessedEvent`].
pub type TransactionWebhook = TransactionProcessedEvent;

/// Ergonomic type alias for [`TransactionWebhookObj`].
pub type TransactionObject = TransactionWebhookObj;

fn default_transaction_event_type() -> String {
    "TRANSACTION".to_string()
}

/// Top-level Paymob `TRANSACTION` webhook event envelope (Protocol A).
///
/// Wraps the event discriminator (`"type"`) and the nested [`TransactionWebhookObj`]
/// containing the 20 HMAC-signed transaction fields and auxiliary metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionProcessedEvent {
    /// Webhook event discriminator (defaults to `"TRANSACTION"` when omitted), mapped from JSON `"type"`.
    #[serde(rename = "type", default = "default_transaction_event_type")]
    pub event_type: String,
    /// Nested Paymob transaction object payload.
    pub obj: TransactionWebhookObj,
}

impl TransactionProcessedEvent {
    /// Returns the unique Paymob transaction identifier (`obj.id`).
    #[must_use]
    pub const fn transaction_id(&self) -> u64 {
        self.obj.transaction_id()
    }

    /// Returns the associated Paymob order identifier (`obj.order.id`).
    #[must_use]
    pub const fn order_id(&self) -> u64 {
        self.obj.order_id()
    }

    /// Returns the transaction amount in integer minor units (`obj.amount_cents`).
    #[must_use]
    pub const fn amount_cents(&self) -> u64 {
        self.obj.amount_cents()
    }

    /// Returns the transaction amount as a strongly-typed [`MinorUnitAmount`](crate::core::types::MinorUnitAmount).
    #[must_use]
    pub const fn amount(&self) -> crate::core::types::MinorUnitAmount {
        self.obj.amount()
    }

    /// Returns the net settled amount as a strongly-typed [`MinorUnitAmount`](crate::core::types::MinorUnitAmount).
    #[must_use]
    pub fn net_settled_amount(&self) -> crate::core::types::MinorUnitAmount {
        self.obj.net_settled_amount()
    }

    /// Returns the ISO-4217 currency code slice (`obj.currency`).
    #[must_use]
    pub fn currency(&self) -> &str {
        self.obj.currency()
    }

    /// Parses the transaction currency into a strongly-typed [`Currency`](crate::core::types::Currency).
    #[must_use]
    pub fn parsed_currency(&self) -> crate::core::types::Currency {
        self.obj.parsed_currency()
    }

    /// Returns `true` if the transaction succeeded, is not pending, and has no error flag.
    #[must_use]
    pub const fn is_approved(&self) -> bool {
        self.obj.is_approved()
    }

    /// Returns `true` if the transaction is not pending and either failed or recorded an error.
    #[must_use]
    pub const fn is_declined_or_failed(&self) -> bool {
        self.obj.is_declined_or_failed()
    }

    /// Returns `true` if the transaction is currently pending settlement.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.obj.is_pending()
    }

    /// Returns `true` if the transaction has been voided.
    #[must_use]
    pub const fn is_voided(&self) -> bool {
        self.obj.is_voided()
    }

    /// Returns `true` if the transaction has been refunded.
    #[must_use]
    pub const fn is_refunded(&self) -> bool {
        self.obj.is_refunded()
    }

    /// Returns `true` if the transaction has been captured or is a capture operation.
    #[must_use]
    pub const fn is_captured(&self) -> bool {
        self.obj.is_captured()
    }

    /// Returns `true` if the transaction is an uncaptured authorization hold.
    #[must_use]
    pub const fn is_auth_only(&self) -> bool {
        self.obj.is_auth_only()
    }

    /// Returns `true` if 3-D Secure authentication was performed.
    #[must_use]
    pub const fn is_3ds_authenticated(&self) -> bool {
        self.obj.is_3ds_authenticated()
    }

    /// Computes the net settled amount in integer minor units after accounting for
    /// voids, uncaptured auth holds, partial captures, and refunds.
    #[must_use]
    pub fn net_settled_cents(&self) -> u64 {
        self.obj.net_settled_cents()
    }

    /// Builds the 20-key canonical HMAC concatenation string for this transaction.
    #[must_use]
    pub fn canonical_hmac_string(&self) -> String {
        self.obj.canonical_hmac_string()
    }
}

/// Minimal order reference embedded inside [`TransactionWebhookObj`].
///
/// Used to extract `order.id` for Paymob's 20-key canonical HMAC concatenation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOrderRef {
    /// Unique Paymob order identifier.
    pub id: u64,
}

/// Payment instrument metadata associated with a Paymob transaction webhook.
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] to wipe sensitive instrument strings
/// on drop, and a custom [`fmt::Debug`] that redacts [`Self::pan`] as `"[REDACTED]"`
/// to prevent masked or partial card numbers from leaking into logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
fn deserialize_null_as_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

pub struct TransactionSourceData {
    /// Card PAN suffix or masked instrument identifier (redacted in `Debug` output).
    #[serde(default, deserialize_with = "deserialize_null_as_empty_string")]
    pub pan: String,
    /// Payment instrument sub-type (for example, `"MasterCard"` or `"Visa"`).
    #[serde(default, deserialize_with = "deserialize_null_as_empty_string")]
    pub sub_type: String,
    /// Payment instrument type (for example, `"card"` or `"wallet"`), mapped from JSON `"type"`.
    #[serde(rename = "type")]
    pub source_type: String,
}

impl fmt::Debug for TransactionSourceData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionSourceData")
            .field("pan", &"[REDACTED]")
            .field("sub_type", &self.sub_type)
            .field("source_type", &self.source_type)
            .finish()
    }
}

/// Paymob transaction object delivered inside [`TransactionProcessedEvent`].
///
/// Contains all 20 fields required for Protocol A/B HMAC-SHA512 verification
/// alongside refund/capture accounting fields (in integer minor units) and
/// optional `payment_key_claims`.
///
/// Implements a custom [`fmt::Debug`] that redacts [`Self::payment_key_claims`]
/// as `Some("[REDACTED]")` when present.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionWebhookObj {
    /// Transaction amount in integer minor units (for example, piastres or cents).
    pub amount_cents: u64,
    /// ISO-8601 creation timestamp string as emitted by Paymob.
    pub created_at: String,
    /// Three-letter ISO-4217 currency code (for example, `"EGP"`).
    pub currency: String,
    /// Whether an error occurred during transaction processing (Paymob spelling: `error_occured`).
    pub error_occured: bool,
    /// Whether this transaction references a parent transaction (for example, a capture or refund).
    pub has_parent_transaction: bool,
    /// Unique Paymob transaction identifier.
    pub id: u64,
    /// Paymob payment integration identifier.
    pub integration_id: u64,
    /// Whether 3-D Secure authentication was performed.
    pub is_3d_secure: bool,
    /// Whether this transaction is an authorization hold.
    pub is_auth: bool,
    /// Whether this transaction is a capture operation.
    pub is_capture: bool,
    /// Whether this transaction has been captured.
    #[serde(default)]
    pub is_captured: bool,
    /// Whether this transaction has been refunded.
    pub is_refunded: bool,
    /// Whether this transaction is a standalone payment.
    pub is_standalone_payment: bool,
    /// Whether this transaction has been voided.
    pub is_voided: bool,
    /// Order reference containing the Paymob order ID.
    pub order: TransactionOrderRef,
    /// Paymob merchant owner identifier.
    pub owner: u64,
    /// Optional payment key claims JSON object (redacted in `Debug` output when present).
    #[serde(default)]
    pub payment_key_claims: Option<serde_json::Value>,
    /// Whether the transaction is currently pending settlement.
    pub pending: bool,
    /// Total refunded amount in integer minor units, if provided by Paymob.
    #[serde(default)]
    pub refunded_amount_cents: Option<u64>,
    /// Total captured amount in integer minor units, if provided by Paymob.
    #[serde(default)]
    pub captured_amount: Option<u64>,
    /// Payment source metadata (card/wallet type, sub-type, and redacted PAN).
    pub source_data: TransactionSourceData,
    /// Whether the transaction succeeded.
    pub success: bool,
}

impl TransactionWebhookObj {
    /// Returns the unique Paymob transaction identifier (`id`).
    #[must_use]
    pub const fn transaction_id(&self) -> u64 {
        self.id
    }

    /// Returns the associated Paymob order identifier (`order.id`).
    #[must_use]
    pub const fn order_id(&self) -> u64 {
        self.order.id
    }

    /// Returns the transaction amount in integer minor units (`amount_cents`).
    #[must_use]
    pub const fn amount_cents(&self) -> u64 {
        self.amount_cents
    }

    /// Returns the transaction amount as a strongly-typed [`MinorUnitAmount`](crate::core::types::MinorUnitAmount).
    #[must_use]
    pub const fn amount(&self) -> crate::core::types::MinorUnitAmount {
        crate::core::types::MinorUnitAmount::new(self.amount_cents)
    }

    /// Returns the net settled amount as a strongly-typed [`MinorUnitAmount`](crate::core::types::MinorUnitAmount).
    #[must_use]
    pub fn net_settled_amount(&self) -> crate::core::types::MinorUnitAmount {
        crate::core::types::MinorUnitAmount::new(self.net_settled_cents())
    }

    /// Returns the three-letter ISO-4217 currency code slice (`currency`).
    #[must_use]
    pub fn currency(&self) -> &str {
        &self.currency
    }

    /// Parses [`Self::currency`] into a strongly-typed [`Currency`](crate::core::types::Currency).
    #[must_use]
    pub fn parsed_currency(&self) -> crate::core::types::Currency {
        crate::core::types::Currency::from_code(&self.currency)
    }

    /// Returns `true` if the transaction succeeded, is not pending, and has no error flag.
    #[must_use]
    pub const fn is_approved(&self) -> bool {
        if self.pending || self.error_occured {
            return false;
        }
        self.success
    }

    /// Returns `true` if the transaction is not pending and either failed or recorded an error.
    #[must_use]
    pub const fn is_declined_or_failed(&self) -> bool {
        if self.pending {
            return false;
        }
        !self.success || self.error_occured
    }

    /// Returns `true` if the transaction is currently pending settlement.
    #[must_use]
    pub const fn is_pending(&self) -> bool {
        self.pending
    }

    /// Returns `true` if the transaction has been voided.
    #[must_use]
    pub const fn is_voided(&self) -> bool {
        self.is_voided
    }

    /// Returns `true` if the transaction has been refunded.
    #[must_use]
    pub const fn is_refunded(&self) -> bool {
        self.is_refunded
    }

    /// Returns `true` if the transaction has been captured or is a capture operation.
    #[must_use]
    pub const fn is_captured(&self) -> bool {
        self.is_captured || self.is_capture
    }

    /// Returns `true` if the transaction is an uncaptured authorization hold.
    #[must_use]
    pub const fn is_auth_only(&self) -> bool {
        if self.is_captured() {
            return false;
        }
        self.is_auth
    }

    /// Returns `true` if 3-D Secure authentication was performed.
    #[must_use]
    pub const fn is_3ds_authenticated(&self) -> bool {
        self.is_3d_secure
    }

    /// Computes the net settled amount in integer minor units after accounting for
    /// voids, uncaptured auth holds, partial captures, and refunds.
    #[must_use]
    pub fn net_settled_cents(&self) -> u64 {
        if !self.is_approved() || self.is_voided {
            return 0;
        }
        if self.is_auth_only() {
            return 0;
        }
        let gross = self
            .captured_amount
            .filter(|&c| c > 0)
            .unwrap_or(self.amount_cents);
        let refunded = self.refunded_amount_cents.unwrap_or(0);
        gross.saturating_sub(refunded)
    }

    /// Builds the 20-key canonical HMAC concatenation string for this transaction.
    #[must_use]
    pub fn canonical_hmac_string(&self) -> String {
        super::protocol_a_post::build_protocol_a_canonical_string(self)
    }
}

impl fmt::Debug for TransactionWebhookObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let claims_redacted: Option<&str> = self.payment_key_claims.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("TransactionWebhookObj")
            .field("amount_cents", &self.amount_cents)
            .field("created_at", &self.created_at)
            .field("currency", &self.currency)
            .field("error_occured", &self.error_occured)
            .field("has_parent_transaction", &self.has_parent_transaction)
            .field("id", &self.id)
            .field("integration_id", &self.integration_id)
            .field("is_3d_secure", &self.is_3d_secure)
            .field("is_auth", &self.is_auth)
            .field("is_capture", &self.is_capture)
            .field("is_captured", &self.is_captured)
            .field("is_refunded", &self.is_refunded)
            .field("is_standalone_payment", &self.is_standalone_payment)
            .field("is_voided", &self.is_voided)
            .field("order", &self.order)
            .field("owner", &self.owner)
            .field("payment_key_claims", &claims_redacted)
            .field("pending", &self.pending)
            .field("refunded_amount_cents", &self.refunded_amount_cents)
            .field("captured_amount", &self.captured_amount)
            .field("source_data", &self.source_data)
            .field("success", &self.success)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_transaction_obj() -> TransactionWebhookObj {
        TransactionWebhookObj {
            amount_cents: 15000,
            created_at: "2026-11-16T12:34:56.000000".to_owned(),
            currency: "EGP".to_owned(),
            error_occured: false,
            has_parent_transaction: false,
            id: 400_500_600,
            integration_id: 12345,
            is_3d_secure: true,
            is_auth: false,
            is_capture: false,
            is_captured: false,
            is_refunded: false,
            is_standalone_payment: true,
            is_voided: false,
            order: TransactionOrderRef { id: 900_800_700 },
            owner: 42,
            payment_key_claims: Some(serde_json::json!({
                "user_id": 99,
                "billing_data": {
                    "email": "secret-customer@example.com",
                    "phone_number": "+201000000000"
                }
            })),
            pending: false,
            refunded_amount_cents: Some(0),
            captured_amount: Some(0),
            source_data: TransactionSourceData {
                pan: "4111-xxxx-1111".to_owned(),
                sub_type: "Visa".to_owned(),
                source_type: "card".to_owned(),
            },
            success: true,
        }
    }

    fn assert_pan_redacted(rendered: &str, raw_pan: &str) {
        assert!(rendered.contains("pan: \"[REDACTED]\""));
        assert!(!rendered.contains(raw_pan));
    }

    fn assert_source_metadata(rendered: &str, sub_type: &str, source_type: &str) {
        assert!(rendered.contains(sub_type));
        assert!(rendered.contains(source_type));
    }

    fn assert_claims_redacted(rendered: &str) {
        assert!(rendered.contains("payment_key_claims: Some(\"[REDACTED]\")"));
        assert!(!rendered.contains("secret-customer@example.com"));
        assert!(!rendered.contains("+201000000000"));
    }

    fn assert_serialized_envelope_fields(value: &serde_json::Value) {
        assert_eq!(value["type"], "TRANSACTION");
        assert_eq!(value["obj"]["source_data"]["type"], "card");
        assert_eq!(value["obj"]["amount_cents"], 15000);
        assert_eq!(value["obj"]["order"]["id"], 900_800_700);
    }

    fn assert_wallet_event_identity(event: &TransactionProcessedEvent) {
        assert_eq!(event.event_type, "TRANSACTION");
        assert_eq!(event.transaction_id(), 101);
        assert_eq!(event.order_id(), 303);
        assert_eq!(event.obj.payment_key_claims, None);
        assert_eq!(event.obj.source_data.source_type, "wallet");
    }

    fn assert_optional_amounts_absent(event: &TransactionProcessedEvent) {
        assert_eq!(event.obj.refunded_amount_cents, None);
        assert_eq!(event.obj.captured_amount, None);
    }

    #[test]
    fn source_data_debug_redacts_pan() {
        let source = TransactionSourceData {
            pan: "4111-xxxx-1111".to_owned(),
            sub_type: "Visa".to_owned(),
            source_type: "card".to_owned(),
        };
        let rendered = format!("{source:?}");
        assert_pan_redacted(&rendered, "4111-xxxx-1111");
        assert_source_metadata(&rendered, "sub_type: \"Visa\"", "source_type: \"card\"");
    }

    #[test]
    fn webhook_obj_debug_redacts_payment_key_claims_when_present() {
        let obj = sample_transaction_obj();
        let rendered = format!("{obj:?}");
        assert_claims_redacted(&rendered);
        assert_pan_redacted(&rendered, "4111-xxxx-1111");
    }

    #[test]
    fn webhook_obj_debug_shows_none_when_claims_absent() {
        let mut obj = sample_transaction_obj();
        obj.payment_key_claims = None;
        let rendered = format!("{obj:?}");
        assert!(rendered.contains("payment_key_claims: None"));
        assert_pan_redacted(&rendered, "4111-xxxx-1111");
    }

    #[test]
    fn transaction_processed_event_serde_roundtrip() {
        let event = TransactionProcessedEvent {
            event_type: "TRANSACTION".to_owned(),
            obj: sample_transaction_obj(),
        };
        let serialized = serde_json::to_string(&event).expect("serialize event");
        let value: serde_json::Value = serde_json::from_str(&serialized).expect("parse json");
        assert_serialized_envelope_fields(&value);

        let roundtripped: TransactionWebhook =
            serde_json::from_str(&serialized).expect("deserialize event");
        assert_eq!(roundtripped, event);
    }

    #[test]
    fn transaction_processed_event_deserializes_without_optional_claims() {
        let mut event = TransactionProcessedEvent {
            event_type: "TRANSACTION".to_owned(),
            obj: sample_transaction_obj(),
        };
        event.obj.id = 101;
        event.obj.order.id = 303;
        event.obj.payment_key_claims = None;
        event.obj.source_data.source_type = "wallet".to_owned();
        let raw = serde_json::to_string(&event).expect("serialize");
        let parsed: TransactionProcessedEvent = serde_json::from_str(&raw).expect("deserialize");
        assert_wallet_event_identity(&parsed);
    }

    #[test]
    fn transaction_processed_event_handles_null_and_omitted_optional_amounts() {
        let mut event = TransactionProcessedEvent {
            event_type: "TRANSACTION".to_owned(),
            obj: sample_transaction_obj(),
        };
        event.obj.refunded_amount_cents = None;
        event.obj.captured_amount = None;
        let mut val = serde_json::to_value(&event).expect("to value");
        let null_parsed: TransactionProcessedEvent =
            serde_json::from_value(val.clone()).expect("null amounts");
        assert_optional_amounts_absent(&null_parsed);

        val["obj"]
            .as_object_mut()
            .unwrap()
            .remove("refunded_amount_cents");
        val["obj"]
            .as_object_mut()
            .unwrap()
            .remove("captured_amount");
        let omitted_parsed: TransactionProcessedEvent =
            serde_json::from_value(val).expect("omitted amounts");
        assert_optional_amounts_absent(&omitted_parsed);
    }

    #[test]
    fn rejects_negative_and_floating_point_amounts() {
        let event = TransactionProcessedEvent {
            event_type: "TRANSACTION".to_owned(),
            obj: sample_transaction_obj(),
        };
        let mut neg_val = serde_json::to_value(&event).expect("to value");
        neg_val["obj"]["amount_cents"] = serde_json::json!(-500);
        assert!(serde_json::from_value::<TransactionProcessedEvent>(neg_val).is_err());

        let mut float_val = serde_json::to_value(&event).expect("to value");
        float_val["obj"]["amount_cents"] = serde_json::json!(150.75);
        assert!(serde_json::from_value::<TransactionProcessedEvent>(float_val).is_err());
    }

    #[test]
    fn handles_zero_and_u64_max_boundaries_and_rejects_null_nested_fields() {
        let mut obj = sample_transaction_obj();
        obj.amount_cents = 0;
        obj.id = u64::MAX;
        let raw = serde_json::to_string(&obj).expect("serialize");
        let parsed: TransactionObject = serde_json::from_str(&raw).expect("deserialize");
        assert_eq!(
            (parsed.amount_cents(), parsed.transaction_id()),
            (0, u64::MAX)
        );

        let mut bad_val = serde_json::to_value(&obj).expect("to value");
        bad_val["order"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<TransactionObject>(bad_val).is_err());
    }

    #[test]
    fn ergonomic_lifecycle_getters_and_net_settled_cents() {
        let mut event = TransactionProcessedEvent {
            event_type: "TRANSACTION".to_owned(),
            obj: sample_transaction_obj(),
        };
        assert_eq!(
            (event.currency(), event.net_settled_cents()),
            ("EGP", 15000)
        );
        assert!(event.is_approved() && event.is_3ds_authenticated());
        assert!(!event.is_pending());

        event.obj.refunded_amount_cents = Some(5000);
        assert_eq!(event.net_settled_cents(), 10000);

        event.obj.is_auth = true;
        assert!(event.is_auth_only());
        assert_eq!(event.net_settled_cents(), 0);
        assert!(!event.canonical_hmac_string().is_empty());
    }

    #[test]
    fn lifecycle_getters_cover_captured_voided_refunded_and_declined() {
        let mut event = TransactionProcessedEvent {
            event_type: "TRANSACTION".to_owned(),
            obj: sample_transaction_obj(),
        };
        event.obj.is_auth = true;
        event.obj.is_captured = true;
        event.obj.captured_amount = Some(12000);
        event.obj.refunded_amount_cents = Some(2000);
        assert!(event.is_captured() && !event.is_auth_only());
        assert_eq!(event.net_settled_cents(), 10000);

        event.obj.is_voided = true;
        event.obj.is_refunded = true;
        event.obj.success = false;
        assert!(event.is_voided() && event.is_refunded());
        assert!(event.is_declined_or_failed());
        assert_eq!(event.net_settled_cents(), 0);
    }

    #[test]
    fn whk_07_source_data_accepts_null_pan_and_sub_type() {
        let json = r#"{"pan":null,"sub_type":null,"type":"wallet"}"#;
        let parsed: TransactionSourceData = serde_json::from_str(json).expect("nulls accepted");
        assert_eq!(parsed.pan, "");
        assert_eq!(parsed.sub_type, "");
        assert_eq!(parsed.source_type, "wallet");
    }
}
