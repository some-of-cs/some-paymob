#![forbid(unsafe_code)]
//! Deterministic 9-step Paymob boolean-flag status synthesizer and parent-child transaction
//! correlation (`US-9.1.0` AC-4, TC-9.1.5, TM-3).
//!
//! Paymob transaction payloads do not expose a single canonical status enum; instead they
//! carry overlapping boolean flags (`pending`, `success`, `error_occured`, `is_voided`,
//! `is_refunded`, `is_auth`, `is_captured`) and minor-unit counters (`amount_cents`,
//! `refunded_amount_cents`, `captured_amount`).
//!
//! This module provides:
//! - [`synthesize_paymob_status`]: collapses [`PaymobTransactionFlags`] into a single
//!   [`SynthesizedPaymentStatus`] using a deterministic 9-step precedence order.
//! - [`extract_parent_correlation`]: separates child action callbacks (`is_void`, `is_refund`,
//!   `is_capture`) from parent state updates (`is_voided`, `is_refunded`, `is_captured`) so
//!   child callbacks never overwrite the canonical parent payment identifier.
//!
//! # Example
//!
//! ```rust
//! use some_paymob::alignment::status_synthesizer::{
//!     ChildTransactionKind, PaymobTransactionFlags, SynthesizedPaymentStatus,
//!     extract_parent_correlation, synthesize_paymob_status,
//! };
//!
//! let flags = PaymobTransactionFlags {
//!     id: 202,
//!     success: true,
//!     amount_cents: 10_000,
//!     is_refund: true,
//!     parent_transaction: Some(100),
//!     ..Default::default()
//! };
//!
//! assert_eq!(synthesize_paymob_status(&flags), SynthesizedPaymentStatus::Paid);
//!
//! let correlation = extract_parent_correlation(&flags);
//! assert_eq!(correlation.canonical_payment_id, 100);
//! assert_eq!(correlation.child_transaction_id, Some(202));
//! assert_eq!(correlation.child_kind, Some(ChildTransactionKind::Refund));
//! ```

use serde::{Deserialize, Serialize};

/// Subset of Paymob transaction fields required for deterministic status synthesis and
/// parent-child transaction correlation.
///
/// Note that Paymob's API spells `error_occured` with a single `r`; this struct preserves
/// that exact wire field name so raw Paymob JSON payloads deserialize without custom aliases.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PaymobTransactionFlags {
    /// Paymob numeric transaction identifier.
    #[serde(default)]
    pub id: u64,
    /// Whether the transaction is still pending completion.
    #[serde(default)]
    pub pending: bool,
    /// Whether Paymob marked the transaction as successful.
    #[serde(default)]
    pub success: bool,
    /// Whether an error occurred during processing (Paymob's exact single-`r` spelling).
    #[serde(default)]
    pub error_occured: bool,
    /// Parent-state flag indicating the transaction has been voided.
    #[serde(default)]
    pub is_voided: bool,
    /// Parent-state flag indicating the transaction has been fully refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// Total transaction amount in minor units (cents/piastres/halalas).
    #[serde(default)]
    pub amount_cents: u64,
    /// Cumulative refunded amount in minor units.
    #[serde(default)]
    pub refunded_amount_cents: u64,
    /// Whether the transaction was created as an authorization (`auth`) transaction.
    #[serde(default)]
    pub is_auth: bool,
    /// Parent-state flag indicating the authorization has been captured.
    #[serde(default)]
    pub is_captured: bool,
    /// Cumulative captured amount in minor units.
    #[serde(default)]
    pub captured_amount: u64,
    /// Child-action flag indicating this transaction is a void action on a parent transaction.
    #[serde(default)]
    pub is_void: bool,
    /// Child-action flag indicating this transaction is a refund action on a parent transaction.
    #[serde(default)]
    pub is_refund: bool,
    /// Child-action flag indicating this transaction is a capture action on a parent transaction.
    #[serde(default)]
    pub is_capture: bool,
    /// Optional numeric ID of the parent transaction when this payload is a child action.
    #[serde(default)]
    pub parent_transaction: Option<u64>,
}

/// Canonical payment lifecycle status synthesized from [`PaymobTransactionFlags`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SynthesizedPaymentStatus {
    /// Step 1: Transaction is still pending (`pending == true`).
    Processing,
    /// Step 2: Transaction did not succeed or reported an error (`!success || error_occured`).
    Failed,
    /// Step 3: Transaction was voided (`is_voided`).
    Voided,
    /// Step 4: Transaction was fully refunded by flag or refunded amount.
    Refunded,
    /// Step 5: Transaction has a non-zero partial refund (`refunded_amount_cents > 0`).
    PartiallyRefunded,
    /// Step 6: Authorization succeeded with zero captured funds.
    Authorized,
    /// Step 7: Authorization has been partially captured (`0 < captured_amount < amount_cents`).
    PartiallyCaptured,
    /// Step 8: Transaction has been captured (`is_captured`).
    Captured,
    /// Step 9: Successful non-voided, non-refunded, non-auth-hold transaction.
    Paid,
}

/// Kind of child follow-up action linked to a parent Paymob transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ChildTransactionKind {
    /// Child void transaction (`is_void == true`).
    Void,
    /// Child refund transaction (`is_refund == true`).
    Refund,
    /// Child capture transaction (`is_capture == true`).
    Capture,
}

/// Correlation result mapping a Paymob transaction payload to its canonical parent payment ID.
///
/// For child action callbacks (`is_void`, `is_refund`, or `is_capture` with a
/// `parent_transaction` ID), [`canonical_payment_id`](Self::canonical_payment_id) points to
/// the parent transaction while [`child_transaction_id`](Self::child_transaction_id) records
/// the child callback's own ID. For root/parent transactions,
/// [`canonical_payment_id`](Self::canonical_payment_id) equals the transaction's own `id` and
/// both child fields are `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ParentTransactionCorrelation {
    /// Authoritative payment ID that must be used as the primary correlation key.
    pub canonical_payment_id: u64,
    /// Transaction ID of the child action when this payload is a correlated child callback.
    pub child_transaction_id: Option<u64>,
    /// Classification of the child action when this payload is a correlated child callback.
    pub child_kind: Option<ChildTransactionKind>,
}

/// Synthesizes a deterministic [`SynthesizedPaymentStatus`] from [`PaymobTransactionFlags`].
///
/// Evaluation follows an exact 9-step precedence chain:
/// 1. `pending == true` -> [`SynthesizedPaymentStatus::Processing`]
/// 2. `!success || error_occured` -> [`SynthesizedPaymentStatus::Failed`]
/// 3. `is_voided` -> [`SynthesizedPaymentStatus::Voided`]
/// 4. `is_refunded || (amount_cents > 0 && refunded_amount_cents >= amount_cents)` ->
///    [`SynthesizedPaymentStatus::Refunded`]
/// 5. `refunded_amount_cents > 0` -> [`SynthesizedPaymentStatus::PartiallyRefunded`]
/// 6. `is_auth && !is_captured && captured_amount == 0` ->
///    [`SynthesizedPaymentStatus::Authorized`]
/// 7. `is_auth && captured_amount > 0 && captured_amount < amount_cents` ->
///    [`SynthesizedPaymentStatus::PartiallyCaptured`]
/// 8. `is_captured` -> [`SynthesizedPaymentStatus::Captured`]
/// 9. Otherwise -> [`SynthesizedPaymentStatus::Paid`]
///
/// # Example
///
/// ```rust
/// use some_paymob::alignment::status_synthesizer::{
///     PaymobTransactionFlags, SynthesizedPaymentStatus, synthesize_paymob_status,
/// };
///
/// let flags = PaymobTransactionFlags {
///     success: true,
///     amount_cents: 5_000,
///     refunded_amount_cents: 1_500,
///     ..Default::default()
/// };
///
/// assert_eq!(
///     synthesize_paymob_status(&flags),
///     SynthesizedPaymentStatus::PartiallyRefunded
/// );
/// ```
#[must_use]
pub fn synthesize_paymob_status(flags: &PaymobTransactionFlags) -> SynthesizedPaymentStatus {
    synthesize_terminal_or_pending(flags)
        .or_else(|| synthesize_refund_state(flags))
        .unwrap_or_else(|| synthesize_capture_state(flags))
}

/// Extracts parent-vs-child transaction correlation from [`PaymobTransactionFlags`] (TM-3).
///
/// Distinguishes child action flags (`is_void`, `is_refund`, `is_capture`) from parent-state
/// flags (`is_voided`, `is_refunded`, `is_captured`). When a transaction is a child action and
/// carries `parent_transaction: Some(parent_id)`, the returned [`ParentTransactionCorrelation`]
/// preserves `parent_id` as `canonical_payment_id` so child callbacks never overwrite the
/// root payment record.
///
/// # Example
///
/// ```rust
/// use some_paymob::alignment::status_synthesizer::{
///     ChildTransactionKind, PaymobTransactionFlags, extract_parent_correlation,
/// };
///
/// let child_capture = PaymobTransactionFlags {
///     id: 901,
///     is_capture: true,
///     parent_transaction: Some(500),
///     ..Default::default()
/// };
///
/// let corr = extract_parent_correlation(&child_capture);
/// assert_eq!(corr.canonical_payment_id, 500);
/// assert_eq!(corr.child_transaction_id, Some(901));
/// assert_eq!(corr.child_kind, Some(ChildTransactionKind::Capture));
/// ```
#[must_use]
pub fn extract_parent_correlation(flags: &PaymobTransactionFlags) -> ParentTransactionCorrelation {
    let child_kind = classify_child_kind(flags);
    if let (Some(parent_id), Some(kind)) = (flags.parent_transaction, child_kind) {
        return ParentTransactionCorrelation {
            canonical_payment_id: parent_id,
            child_transaction_id: Some(flags.id),
            child_kind: Some(kind),
        };
    }

    ParentTransactionCorrelation {
        canonical_payment_id: flags.id,
        child_transaction_id: None,
        child_kind: None,
    }
}

fn synthesize_terminal_or_pending(
    flags: &PaymobTransactionFlags,
) -> Option<SynthesizedPaymentStatus> {
    if flags.pending {
        return Some(SynthesizedPaymentStatus::Processing);
    }
    if !flags.success || flags.error_occured {
        return Some(SynthesizedPaymentStatus::Failed);
    }
    if flags.is_voided {
        return Some(SynthesizedPaymentStatus::Voided);
    }
    None
}

fn synthesize_refund_state(flags: &PaymobTransactionFlags) -> Option<SynthesizedPaymentStatus> {
    let fully_refunded_by_amount =
        flags.amount_cents > 0 && flags.refunded_amount_cents >= flags.amount_cents;
    if flags.is_refunded || fully_refunded_by_amount {
        return Some(SynthesizedPaymentStatus::Refunded);
    }
    if flags.refunded_amount_cents > 0 {
        return Some(SynthesizedPaymentStatus::PartiallyRefunded);
    }
    None
}

fn is_uncollected_auth(flags: &PaymobTransactionFlags) -> bool {
    flags.is_auth && !flags.is_captured && flags.captured_amount == 0
}

fn is_partial_capture(flags: &PaymobTransactionFlags) -> bool {
    flags.is_auth && flags.captured_amount > 0 && flags.captured_amount < flags.amount_cents
}

fn synthesize_capture_state(flags: &PaymobTransactionFlags) -> SynthesizedPaymentStatus {
    if is_uncollected_auth(flags) {
        return SynthesizedPaymentStatus::Authorized;
    }
    if is_partial_capture(flags) {
        return SynthesizedPaymentStatus::PartiallyCaptured;
    }
    if flags.is_captured {
        return SynthesizedPaymentStatus::Captured;
    }
    SynthesizedPaymentStatus::Paid
}

fn classify_child_kind(flags: &PaymobTransactionFlags) -> Option<ChildTransactionKind> {
    if flags.is_void {
        return Some(ChildTransactionKind::Void);
    }
    if flags.is_refund {
        return Some(ChildTransactionKind::Refund);
    }
    if flags.is_capture {
        return Some(ChildTransactionKind::Capture);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_success_flags() -> PaymobTransactionFlags {
        PaymobTransactionFlags {
            id: 1_000,
            success: true,
            amount_cents: 10_000,
            ..Default::default()
        }
    }

    #[test]
    fn step_1_pending_yields_processing() {
        let flags = PaymobTransactionFlags {
            pending: true,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::Processing
        );
    }

    #[test]
    fn step_2_not_success_or_error_occured_yields_failed() {
        let not_success = PaymobTransactionFlags {
            success: false,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&not_success),
            SynthesizedPaymentStatus::Failed
        );

        let error_flag = PaymobTransactionFlags {
            error_occured: true,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&error_flag),
            SynthesizedPaymentStatus::Failed
        );
    }

    #[test]
    fn step_3_is_voided_yields_voided() {
        let flags = PaymobTransactionFlags {
            is_voided: true,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::Voided
        );
    }

    #[test]
    fn step_4_is_refunded_or_full_refund_amount_yields_refunded() {
        let by_flag = PaymobTransactionFlags {
            is_refunded: true,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&by_flag),
            SynthesizedPaymentStatus::Refunded
        );

        let by_exact_amount = PaymobTransactionFlags {
            refunded_amount_cents: 10_000,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&by_exact_amount),
            SynthesizedPaymentStatus::Refunded
        );

        let by_excess_amount = PaymobTransactionFlags {
            refunded_amount_cents: 12_000,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&by_excess_amount),
            SynthesizedPaymentStatus::Refunded
        );

        let zero_amount_not_refunded = PaymobTransactionFlags {
            amount_cents: 0,
            refunded_amount_cents: 0,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&zero_amount_not_refunded),
            SynthesizedPaymentStatus::Paid
        );
    }

    #[test]
    fn step_5_partial_refund_amount_yields_partially_refunded() {
        let flags = PaymobTransactionFlags {
            refunded_amount_cents: 2_500,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::PartiallyRefunded
        );
    }

    #[test]
    fn step_6_uncollected_auth_yields_authorized() {
        let flags = PaymobTransactionFlags {
            is_auth: true,
            is_captured: false,
            captured_amount: 0,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::Authorized
        );
    }

    #[test]
    fn step_7_partial_capture_yields_partially_captured() {
        let flags = PaymobTransactionFlags {
            is_auth: true,
            is_captured: false,
            captured_amount: 4_000,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::PartiallyCaptured
        );
    }

    #[test]
    fn step_8_is_captured_yields_captured() {
        let full_auth_capture = PaymobTransactionFlags {
            is_auth: true,
            is_captured: true,
            captured_amount: 10_000,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&full_auth_capture),
            SynthesizedPaymentStatus::Captured
        );

        let direct_captured = PaymobTransactionFlags {
            is_captured: true,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&direct_captured),
            SynthesizedPaymentStatus::Captured
        );
    }

    #[test]
    fn step_9_default_success_yields_paid() {
        let flags = base_success_flags();
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::Paid
        );
    }

    #[test]
    fn precedence_pending_beats_error_occured_and_terminal_flags() {
        let flags = PaymobTransactionFlags {
            pending: true,
            success: false,
            error_occured: true,
            is_voided: true,
            is_refunded: true,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::Processing
        );
    }

    #[test]
    fn precedence_failed_beats_voided_and_refunded() {
        let flags = PaymobTransactionFlags {
            error_occured: true,
            is_voided: true,
            is_refunded: true,
            refunded_amount_cents: 10_000,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::Failed
        );
    }

    #[test]
    fn precedence_voided_beats_refunded_and_captured() {
        let flags = PaymobTransactionFlags {
            is_voided: true,
            is_refunded: true,
            refunded_amount_cents: 5_000,
            is_captured: true,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::Voided
        );
    }

    #[test]
    fn precedence_refund_beats_auth_and_capture_states() {
        let partial_refund_over_auth = PaymobTransactionFlags {
            refunded_amount_cents: 500,
            is_auth: true,
            is_captured: true,
            captured_amount: 5_000,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&partial_refund_over_auth),
            SynthesizedPaymentStatus::PartiallyRefunded
        );
    }

    #[test]
    fn precedence_partially_captured_beats_is_captured_flag() {
        let flags = PaymobTransactionFlags {
            is_auth: true,
            is_captured: true,
            captured_amount: 6_000,
            ..base_success_flags()
        };
        assert_eq!(
            synthesize_paymob_status(&flags),
            SynthesizedPaymentStatus::PartiallyCaptured
        );
    }

    #[test]
    fn serde_deserializes_single_r_error_occured_and_defaults() {
        let payload = serde_json::json!({
            "id": 774_411,
            "pending": false,
            "success": true,
            "error_occured": true,
            "is_voided": false,
            "is_refunded": false,
            "amount_cents": 15_000,
            "refunded_amount_cents": 0,
            "is_auth": false,
            "is_captured": false,
            "captured_amount": 0,
            "is_void": false,
            "is_refund": false,
            "is_capture": false,
            "parent_transaction": null
        });
        let parsed: PaymobTransactionFlags =
            serde_json::from_value(payload).expect("valid Paymob transaction JSON");
        assert_eq!(parsed.id, 774_411);
        assert!(parsed.error_occured);
        assert_eq!(
            synthesize_paymob_status(&parsed),
            SynthesizedPaymentStatus::Failed
        );

        let minimal_payload = serde_json::json!({"id": 42, "success": true});
        let minimal: PaymobTransactionFlags = serde_json::from_value(minimal_payload)
            .expect("minimal JSON should default missing fields");
        assert!(!minimal.error_occured);
        assert_eq!(minimal.parent_transaction, None);
        assert_eq!(
            synthesize_paymob_status(&minimal),
            SynthesizedPaymentStatus::Paid
        );
    }

    #[test]
    fn correlation_root_and_parent_state_flags_stay_root() {
        let root = PaymobTransactionFlags {
            id: 55_001,
            is_voided: true,
            is_refunded: true,
            is_captured: true,
            parent_transaction: None,
            ..base_success_flags()
        };
        let corr = extract_parent_correlation(&root);
        assert_eq!(
            corr,
            ParentTransactionCorrelation {
                canonical_payment_id: 55_001,
                child_transaction_id: None,
                child_kind: None,
            }
        );

        let parent_state_with_stray_parent = PaymobTransactionFlags {
            id: 55_002,
            is_refunded: true,
            parent_transaction: Some(99_999),
            ..base_success_flags()
        };
        assert_eq!(
            extract_parent_correlation(&parent_state_with_stray_parent),
            ParentTransactionCorrelation {
                canonical_payment_id: 55_002,
                child_transaction_id: None,
                child_kind: None,
            }
        );
    }

    #[test]
    fn correlation_child_void_refund_capture_preserves_parent_id() {
        let child_void = PaymobTransactionFlags {
            id: 60_001,
            is_void: true,
            parent_transaction: Some(50_000),
            ..base_success_flags()
        };
        assert_eq!(
            extract_parent_correlation(&child_void),
            ParentTransactionCorrelation {
                canonical_payment_id: 50_000,
                child_transaction_id: Some(60_001),
                child_kind: Some(ChildTransactionKind::Void),
            }
        );

        let child_refund = PaymobTransactionFlags {
            id: 60_002,
            is_refund: true,
            parent_transaction: Some(50_000),
            ..base_success_flags()
        };
        assert_eq!(
            extract_parent_correlation(&child_refund),
            ParentTransactionCorrelation {
                canonical_payment_id: 50_000,
                child_transaction_id: Some(60_002),
                child_kind: Some(ChildTransactionKind::Refund),
            }
        );

        let child_capture = PaymobTransactionFlags {
            id: 60_003,
            is_capture: true,
            parent_transaction: Some(50_000),
            ..base_success_flags()
        };
        assert_eq!(
            extract_parent_correlation(&child_capture),
            ParentTransactionCorrelation {
                canonical_payment_id: 50_000,
                child_transaction_id: Some(60_003),
                child_kind: Some(ChildTransactionKind::Capture),
            }
        );
    }

    #[test]
    fn correlation_child_flag_without_parent_id_falls_back_to_self() {
        let orphan_child = PaymobTransactionFlags {
            id: 70_001,
            is_refund: true,
            parent_transaction: None,
            ..base_success_flags()
        };
        assert_eq!(
            extract_parent_correlation(&orphan_child),
            ParentTransactionCorrelation {
                canonical_payment_id: 70_001,
                child_transaction_id: None,
                child_kind: None,
            }
        );
    }
}
