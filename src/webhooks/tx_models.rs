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
//! assert_eq!(event.obj.amount_cents, 10000);
//! assert_eq!(event.obj.order, TransactionOrderRef { id: 998877 });
//!
//! let debug_output = format!("{event:?}");
//! assert!(debug_output.contains("[REDACTED]"));
//! assert!(!debug_output.contains("9876"));
//! assert!(!debug_output.contains("buyer@example.com"));
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

/// Top-level Paymob `TRANSACTION` webhook event envelope (Protocol A).
///
/// Wraps the event discriminator (`"type"`) and the nested [`TransactionWebhookObj`]
/// containing the 20 HMAC-signed transaction fields and auxiliary metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionProcessedEvent {
    /// Webhook event discriminator (typically `"TRANSACTION"`), mapped from JSON `"type"`.
    #[serde(rename = "type")]
    pub event_type: String,
    /// Nested Paymob transaction object payload.
    pub obj: TransactionWebhookObj,
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
/// Implements a custom [`fmt::Debug`] that redacts [`Self::pan`] as `"[REDACTED]"`
/// to prevent masked or partial card numbers from leaking into logs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionSourceData {
    /// Card PAN suffix or masked instrument identifier (redacted in `Debug` output).
    pub pan: String,
    /// Payment instrument sub-type (for example, `"MasterCard"` or `"Visa"`).
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
    }

    fn assert_serialized_order_amount(value: &serde_json::Value) {
        assert_eq!(value["obj"]["amount_cents"], 15000);
        assert_eq!(value["obj"]["order"]["id"], 900_800_700);
    }

    fn assert_wallet_event_identity(event: &TransactionProcessedEvent) {
        assert_eq!(event.event_type, "TRANSACTION");
        assert_eq!(event.obj.id, 101);
        assert_eq!(event.obj.order, TransactionOrderRef { id: 303 });
    }

    fn assert_wallet_event_source(event: &TransactionProcessedEvent) {
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
        assert_serialized_order_amount(&value);

        let roundtripped: TransactionProcessedEvent =
            serde_json::from_str(&serialized).expect("deserialize event");
        assert_eq!(roundtripped, event);
    }

    #[test]
    fn transaction_processed_event_deserializes_without_optional_claims() {
        let payload = r#"{
            "type": "TRANSACTION",
            "obj": {
                "amount_cents": 5000,
                "created_at": "2026-11-16T10:00:00.000000",
                "currency": "EGP",
                "error_occured": false,
                "has_parent_transaction": false,
                "id": 101,
                "integration_id": 202,
                "is_3d_secure": false,
                "is_auth": false,
                "is_capture": false,
                "is_captured": false,
                "is_refunded": false,
                "is_standalone_payment": true,
                "is_voided": false,
                "order": { "id": 303 },
                "owner": 404,
                "pending": false,
                "refunded_amount_cents": 0,
                "captured_amount": 0,
                "source_data": {
                    "pan": "9999",
                    "sub_type": "Wallet",
                    "type": "wallet"
                },
                "success": true
            }
        }"#;

        let event: TransactionProcessedEvent =
            serde_json::from_str(payload).expect("deserialize without payment_key_claims");
        assert_wallet_event_identity(&event);
        assert_wallet_event_source(&event);
    }

    #[test]
    fn transaction_processed_event_handles_null_and_omitted_optional_amounts() {
        let null_payload = r#"{
            "type": "TRANSACTION",
            "obj": {
                "amount_cents": 5000,
                "created_at": "2026-11-16T10:00:00.000000",
                "currency": "EGP",
                "error_occured": false,
                "has_parent_transaction": false,
                "id": 101,
                "integration_id": 202,
                "is_3d_secure": false,
                "is_auth": false,
                "is_capture": false,
                "is_captured": false,
                "is_refunded": false,
                "is_standalone_payment": true,
                "is_voided": false,
                "order": { "id": 303 },
                "owner": 404,
                "pending": false,
                "refunded_amount_cents": null,
                "captured_amount": null,
                "source_data": {
                    "pan": "9999",
                    "sub_type": "Wallet",
                    "type": "wallet"
                },
                "success": true
            }
        }"#;

        let null_event: TransactionProcessedEvent =
            serde_json::from_str(null_payload).expect("deserialize with null amounts");
        assert_optional_amounts_absent(&null_event);

        let omitted_payload = r#"{
            "type": "TRANSACTION",
            "obj": {
                "amount_cents": 5000,
                "created_at": "2026-11-16T10:00:00.000000",
                "currency": "EGP",
                "error_occured": false,
                "has_parent_transaction": false,
                "id": 101,
                "integration_id": 202,
                "is_3d_secure": false,
                "is_auth": false,
                "is_capture": false,
                "is_captured": false,
                "is_refunded": false,
                "is_standalone_payment": true,
                "is_voided": false,
                "order": { "id": 303 },
                "owner": 404,
                "pending": false,
                "source_data": {
                    "pan": "9999",
                    "sub_type": "Wallet",
                    "type": "wallet"
                },
                "success": true
            }
        }"#;

        let omitted_event: TransactionProcessedEvent =
            serde_json::from_str(omitted_payload).expect("deserialize with omitted amounts");
        assert_optional_amounts_absent(&omitted_event);
    }
}
