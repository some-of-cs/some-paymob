#![forbid(unsafe_code)]
//! Transaction and child transaction response models for Paymob payment management (`US-3.1.0`).
//!
//! Covers Paymob's `Transaction` response payload returned by `refund`, `void`, and `capture`
//! endpoints, enforcing integer minor-unit monetary fields (`u64`, zero floats) and `[REDACTED]`
//! [`fmt::Debug`] output for sensitive card PAN fields.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::types::{deserialize_opt_u64_flexible, deserialize_u64_flexible};

/// Payment or child lifecycle transaction returned by Paymob's Manage Payment APIs.
///
/// Represents parent payment transactions as well as child `refund`, `void`, and `capture`
/// transactions returned by `/api/acceptance/void_refund/refund`,
/// `/api/acceptance/void_refund/void`, and `/api/acceptance/capture`.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::manage::models::Transaction;
///
/// let json = r#"{
///     "id": 192036466,
///     "pending": false,
///     "amount_cents": 25000,
///     "success": true,
///     "is_auth": false,
///     "is_capture": false,
///     "is_void": false,
///     "is_refund": true,
///     "is_voided": false,
///     "is_refunded": false,
///     "is_captured": false,
///     "parent_transaction": 192036465,
///     "refunded_amount_cents": 0,
///     "captured_amount": 0,
///     "integration_id": 12345,
///     "currency": "EGP",
///     "created_at": "2026-11-16T12:00:00Z"
/// }"#;
///
/// let tx: Transaction = serde_json::from_str(json).expect("valid transaction JSON");
/// assert_eq!(tx.id, 192036466);
/// assert!(tx.is_refund);
/// assert_eq!(tx.parent_transaction, Some(192036465));
/// assert_eq!(tx.amount_cents, 25_000);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique Paymob transaction identifier.
    #[serde(deserialize_with = "deserialize_u64_flexible")]
    pub id: u64,
    /// Whether the transaction is still pending settlement or 3DS completion.
    #[serde(default)]
    pub pending: bool,
    /// Transaction amount in minor currency units (e.g., piasters or halalas).
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub amount_cents: u64,
    /// Whether the transaction succeeded on the gateway.
    #[serde(default)]
    pub success: bool,
    /// Whether this transaction is an authorization hold.
    #[serde(default)]
    pub is_auth: bool,
    /// Whether this transaction is a capture child transaction.
    #[serde(default)]
    pub is_capture: bool,
    /// Whether this transaction is a void child transaction.
    #[serde(default)]
    pub is_void: bool,
    /// Whether this transaction is a refund child transaction.
    #[serde(default)]
    pub is_refund: bool,
    /// Whether the transaction has been voided.
    #[serde(default)]
    pub is_voided: bool,
    /// Whether the transaction has been refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// Whether the authorized transaction has been captured.
    #[serde(default)]
    pub is_captured: bool,
    /// Identifier of the parent transaction when this is a child refund, void, or capture.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub parent_transaction: Option<u64>,
    /// Cumulative refunded amount in minor currency units.
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub refunded_amount_cents: u64,
    /// Cumulative captured amount in minor currency units.
    #[serde(default, deserialize_with = "deserialize_u64_flexible")]
    pub captured_amount: u64,
    /// Paymob integration identifier used for this transaction.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub integration_id: Option<u64>,
    /// ISO 4217 currency code (for example, `"EGP"` or `"SAR"`).
    #[serde(default)]
    pub currency: Option<String>,
    /// Payment instrument metadata associated with the transaction.
    #[serde(default)]
    pub source_data: Option<TransactionSourceData>,
    /// Associated order reference (either a numeric ID or an expanded order object).
    #[serde(default)]
    pub order: Option<TransactionOrder>,
    /// ISO 8601 creation timestamp returned by Paymob.
    #[serde(default)]
    pub created_at: Option<String>,
}

impl Transaction {
    /// Returns the numeric order ID if [`Transaction::order`] is present.
    #[must_use]
    pub const fn order_id(&self) -> Option<u64> {
        match &self.order {
            Some(order) => Some(order.id()),
            None => None,
        }
    }

    /// Returns the remaining refundable amount in minor currency units using saturating subtraction.
    #[must_use]
    pub const fn remaining_refundable_cents(&self) -> u64 {
        self.amount_cents.saturating_sub(self.refunded_amount_cents)
    }
}

/// Payment instrument metadata nested inside [`Transaction::source_data`].
///
/// Redacts [`TransactionSourceData::pan`] in [`fmt::Debug`] output (`"[REDACTED]"`) to
/// prevent accidental PAN leakage into logs or error traces.
///
/// # Memory Hygiene & Field Moves (`ZeroizeOnDrop`)
///
/// Implements [`ZeroizeOnDrop`] (`Drop`) to scrub PAN metadata on drop; borrow or clone
/// fields rather than moving fields out of an owned value (`E0509`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Default, Zeroize, ZeroizeOnDrop)]
pub struct TransactionSourceData {
    /// Payment instrument type (for example, `"card"` or `"wallet"`).
    #[serde(rename = "type", default)]
    pub source_type: Option<String>,
    /// Masked or raw PAN/account identifier (always redacted in `Debug` output).
    #[serde(default)]
    pub pan: Option<String>,
    /// Card scheme or sub-type (for example, `"MasterCard"` or `"Visa"`).
    #[serde(default)]
    pub sub_type: Option<String>,
}

impl fmt::Debug for TransactionSourceData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let pan_display = self.pan.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("TransactionSourceData")
            .field("source_type", &self.source_type)
            .field("pan", &pan_display)
            .field("sub_type", &self.sub_type)
            .finish()
    }
}

/// Order reference attached to a [`Transaction`].
///
/// Paymob endpoints may return `"order"` either as a bare numeric ID (`12345`) or as an
/// expanded JSON object (`{"id": 12345, ...}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransactionOrder {
    /// Numeric order identifier.
    Id(u64),
    /// Expanded order summary object.
    Details(TransactionOrderDetails),
}

impl TransactionOrder {
    /// Returns the numeric order identifier regardless of representation.
    #[must_use]
    pub const fn id(&self) -> u64 {
        match self {
            Self::Id(id) => *id,
            Self::Details(details) => details.id,
        }
    }
}

/// Expanded order summary nested inside [`TransactionOrder::Details`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionOrderDetails {
    /// Unique Paymob order identifier.
    #[serde(deserialize_with = "deserialize_u64_flexible")]
    pub id: u64,
    /// Order total amount in minor currency units.
    #[serde(default, deserialize_with = "deserialize_opt_u64_flexible")]
    pub amount_cents: Option<u64>,
    /// ISO 4217 currency code for the order.
    #[serde(default)]
    pub currency: Option<String>,
    /// Merchant-supplied order identifier, if configured.
    #[serde(default)]
    pub merchant_order_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_full_refund_child_transaction() {
        let payload = r#"{
            "id": 192036466,
            "pending": false,
            "amount_cents": 25000,
            "success": true,
            "is_auth": false,
            "is_capture": false,
            "is_void": false,
            "is_refund": true,
            "is_voided": false,
            "is_refunded": false,
            "is_captured": false,
            "parent_transaction": 192036465,
            "refunded_amount_cents": 0,
            "captured_amount": 0,
            "integration_id": 445566,
            "currency": "EGP",
            "source_data": {
                "type": "card",
                "pan": "2346",
                "sub_type": "MasterCard"
            },
            "order": {
                "id": 998877,
                "amount_cents": 100000,
                "currency": "EGP",
                "merchant_order_id": "ORD-42"
            },
            "created_at": "2026-11-16T12:00:00.000000Z"
        }"#;
        let tx: Transaction = serde_json::from_str(payload).expect("valid transaction JSON");
        assert_eq!(tx.id, 192_036_466);
        assert!(!tx.pending);
        assert_eq!(tx.amount_cents, 25_000);
        assert!(tx.success);
        assert!(tx.is_refund);
        assert_eq!(tx.parent_transaction, Some(192_036_465));
        assert_eq!(tx.integration_id, Some(445_566));
        assert_eq!(tx.currency.as_deref(), Some("EGP"));
        assert_eq!(tx.order_id(), Some(998_877));
        assert_eq!(tx.remaining_refundable_cents(), 25_000);
    }

    #[test]
    fn deserializes_string_encoded_fields_and_numeric_order() {
        let payload = r#"{
            "id": "574588",
            "amount_cents": "1000",
            "success": true,
            "is_capture": true,
            "parent_transaction": "574500",
            "refunded_amount_cents": "200",
            "captured_amount": "1000",
            "order": 771122
        }"#;
        let tx: Transaction = serde_json::from_str(payload).expect("valid flexible JSON");
        assert_eq!(tx.id, 574_588);
        assert_eq!(tx.amount_cents, 1_000);
        assert!(tx.is_capture);
        assert_eq!(tx.parent_transaction, Some(574_500));
        assert_eq!(tx.refunded_amount_cents, 200);
        assert_eq!(tx.captured_amount, 1_000);
        assert_eq!(tx.order_id(), Some(771_122));
        assert_eq!(tx.remaining_refundable_cents(), 800);
    }

    #[test]
    fn handles_boundary_and_empty_optional_fields() {
        let payload = r#"{
            "id": 1,
            "parent_transaction": "",
            "amount_cents": 0,
            "refunded_amount_cents": 50
        }"#;
        let tx: Transaction = serde_json::from_str(payload).expect("valid boundary JSON");
        assert_eq!(tx.id, 1);
        assert_eq!(tx.parent_transaction, None);
        assert_eq!(tx.order_id(), None);
        assert_eq!(tx.remaining_refundable_cents(), 0);
    }

    #[test]
    fn rejects_malformed_numeric_or_missing_id() {
        let bad_amount = r#"{"id": 10, "amount_cents": "not-a-number"}"#;
        assert!(serde_json::from_str::<Transaction>(bad_amount).is_err());
        let missing_id = r#"{"amount_cents": 100}"#;
        assert!(serde_json::from_str::<Transaction>(missing_id).is_err());
    }

    #[test]
    fn redacts_pan_in_debug_output() {
        let source = TransactionSourceData {
            source_type: Some(String::from("card")),
            pan: Some(String::from("4111111111112346")),
            sub_type: Some(String::from("Visa")),
        };
        let rendered = format!("{source:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("4111111111112346"));
        assert!(!rendered.contains("2346"));
    }
}
