#![forbid(unsafe_code)]
//! Protocol E Paymob Payouts disbursement and topup webhook callbacks.
//!
//! This module models Paymob Payouts webhook payloads for outbound
//! disbursements ([`DisbursementCallback`]) and account top-up approvals
//! ([`TopupCallback`]), and extends [`crate::webhooks::verifier::PaymobWebhookEngine`]
//! with fail-closed constant-time `HMAC-SHA512` verification using the
//! configured payouts secret.
//!
//! # Examples
//!
//! ```rust
//! use some_paymob::webhooks::protocol_e_payouts::{
//!     DisbursementCallback, DisbursementIssuer, TopupCallback, TopupStatus,
//! };
//!
//! let disbursement_json = r#"{
//!     "transaction_id": "disb_9001",
//!     "issuer": "bank_wallet",
//!     "amount_cents": 25000,
//!     "currency": "EGP",
//!     "status": "success",
//!     "recipient_identifier": "+201001234567"
//! }"#;
//!
//! let disbursement: DisbursementCallback =
//!     serde_json::from_str(disbursement_json).expect("valid disbursement JSON");
//! assert_eq!(disbursement.issuer, DisbursementIssuer::BankWallet);
//! assert_eq!(disbursement.amount_cents, 25_000);
//!
//! let debug_rendered = format!("{disbursement:?}");
//! assert!(debug_rendered.contains("[REDACTED]"));
//! assert!(!debug_rendered.contains("+201001234567"));
//!
//! let topup_json = r#"{
//!     "topup_id": "topup_42",
//!     "amount_cents": 100000,
//!     "currency": "EGP",
//!     "status": "Approved"
//! }"#;
//!
//! let topup: TopupCallback = serde_json::from_str(topup_json).expect("valid topup JSON");
//! assert_eq!(topup.status, TopupStatus::Approved);
//! ```

use std::fmt;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Supported Paymob Payouts disbursement rail issuers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisbursementIssuer {
    /// Disbursement to a bank card (`"bank_card"`).
    BankCard,
    /// Disbursement to a mobile or bank wallet (`"bank_wallet"`).
    BankWallet,
    /// Instant bank account transfer (`"instant_bank"`).
    InstantBank,
}

/// Paymob Protocol E disbursement webhook callback payload.
///
/// Monetary amounts are represented strictly in integer minor units (`u64`).
/// Implements a custom [`fmt::Debug`] that redacts
/// [`Self::recipient_identifier`] as `"[REDACTED]"` when present.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisbursementCallback {
    /// Unique Paymob disbursement transaction identifier.
    pub transaction_id: String,
    /// Payout rail issuer used for the disbursement.
    pub issuer: DisbursementIssuer,
    /// Disbursed amount in integer minor currency units.
    pub amount_cents: u64,
    /// Three-letter ISO-4217 currency code (for example, `"EGP"`).
    pub currency: String,
    /// Disbursement settlement status string reported by Paymob.
    pub status: String,
    /// Optional recipient phone, wallet, or bank account identifier (redacted in `Debug`).
    #[serde(default)]
    pub recipient_identifier: Option<String>,
}

impl DisbursementCallback {
    /// Returns the disbursed amount as a strongly-typed [`MinorUnitAmount`](crate::core::types::MinorUnitAmount).
    #[must_use]
    pub const fn amount(&self) -> crate::core::types::MinorUnitAmount {
        crate::core::types::MinorUnitAmount::new(self.amount_cents)
    }

    /// Parses [`Self::currency`] into a strongly-typed [`Currency`](crate::core::types::Currency).
    #[must_use]
    pub fn parsed_currency(&self) -> crate::core::types::Currency {
        crate::core::types::Currency::from_code(&self.currency)
    }
}

impl fmt::Debug for DisbursementCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_recipient: Option<&str> =
            self.recipient_identifier.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("DisbursementCallback")
            .field("transaction_id", &self.transaction_id)
            .field("issuer", &self.issuer)
            .field("amount_cents", &self.amount_cents)
            .field("currency", &self.currency)
            .field("status", &self.status)
            .field("recipient_identifier", &redacted_recipient)
            .finish()
    }
}

/// Review outcome for a Paymob Payouts account top-up callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopupStatus {
    /// Top-up request was approved and credited.
    #[serde(alias = "approved")]
    Approved,
    /// Top-up request was rejected.
    #[serde(alias = "rejected")]
    Rejected,
}

/// Paymob Protocol E account top-up webhook callback payload.
///
/// Monetary amounts are represented strictly in integer minor units (`u64`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopupCallback {
    /// Unique Paymob top-up identifier.
    pub topup_id: String,
    /// Top-up amount in integer minor currency units.
    pub amount_cents: u64,
    /// Three-letter ISO-4217 currency code (for example, `"EGP"`).
    pub currency: String,
    /// Approval or rejection status of the top-up.
    pub status: TopupStatus,
}

impl TopupCallback {
    /// Returns the top-up amount as a strongly-typed [`MinorUnitAmount`](crate::core::types::MinorUnitAmount).
    #[must_use]
    pub const fn amount(&self) -> crate::core::types::MinorUnitAmount {
        crate::core::types::MinorUnitAmount::new(self.amount_cents)
    }

    /// Parses [`Self::currency`] into a strongly-typed [`Currency`](crate::core::types::Currency).
    #[must_use]
    pub fn parsed_currency(&self) -> crate::core::types::Currency {
        crate::core::types::Currency::from_code(&self.currency)
    }
}

/// Verifies an optional `HMAC-SHA512` signature against `raw_body` when a
/// payouts secret is configured, failing closed on any configuration mismatch.
fn verify_optional_payouts_hmac(
    payouts_secret: Option<&SecretString>,
    raw_body: &str,
    signature_hex: Option<&str>,
) -> super::verifier::WebhookResult<()> {
    match (payouts_secret, signature_hex) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(super::verifier::WebhookError::SignatureMismatch),
        (Some(_), None) => Err(super::verifier::WebhookError::MissingQueryHmac),
        (Some(secret), Some(sig_hex)) => {
            let trimmed = sig_hex.trim();
            if trimmed.is_empty() {
                return Err(super::verifier::WebhookError::MissingQueryHmac);
            }
            super::verifier::PaymobWebhookEngine::verify_concatenated_with_secret(
                secret, raw_body, trimmed,
            )
        }
    }
}

impl super::verifier::PaymobWebhookEngine {
    /// Verifies (when configured) and deserializes a Protocol E disbursement
    /// webhook callback (`DisbursementCallback`).
    ///
    /// Fails closed if `signature_hex` is supplied without a configured
    /// `payouts_secret()`, if `payouts_secret()` is configured while
    /// `signature_hex` is `None` or blank, or if `transaction_id` is empty.
    ///
    /// # Errors
    ///
    /// Returns [`super::verifier::WebhookError`] if HMAC verification fails,
    /// the signature configuration is inconsistent, `raw_body` is invalid JSON,
    /// or `transaction_id` is empty.
    pub fn verify_payout_disbursement(
        &self,
        raw_body: &str,
        signature_hex: Option<&str>,
    ) -> super::verifier::WebhookResult<DisbursementCallback> {
        verify_optional_payouts_hmac(self.payouts_secret(), raw_body, signature_hex)?;
        let cb: DisbursementCallback = super::verifier::parse_webhook_json_str(raw_body)?;
        if cb.transaction_id.trim().is_empty() {
            return Err(super::verifier::WebhookError::MissingRequiredField(
                "transaction_id".into(),
            ));
        }
        Ok(cb)
    }

    /// Verifies (when configured) and deserializes a Protocol E disbursement
    /// webhook callback from raw request bytes.
    ///
    /// # Errors
    ///
    /// Returns [`super::verifier::WebhookError::InvalidJsonPayload`] if `raw_body` is not
    /// valid UTF-8, or any error returned by [`Self::verify_payout_disbursement`].
    pub fn verify_payout_disbursement_bytes(
        &self,
        raw_body: &[u8],
        signature_hex: Option<&str>,
    ) -> super::verifier::WebhookResult<DisbursementCallback> {
        let raw_str = super::verifier::decode_webhook_utf8(raw_body)?;
        self.verify_payout_disbursement(raw_str, signature_hex)
    }

    /// Verifies (when configured) and deserializes a Protocol E top-up
    /// webhook callback (`TopupCallback`).
    ///
    /// Fails closed if `signature_hex` is supplied without a configured
    /// `payouts_secret()`, if `payouts_secret()` is configured while
    /// `signature_hex` is `None` or blank, or if `topup_id` is empty.
    ///
    /// # Errors
    ///
    /// Returns [`super::verifier::WebhookError`] if HMAC verification fails,
    /// the signature configuration is inconsistent, `raw_body` is invalid JSON,
    /// or `topup_id` is empty.
    pub fn verify_payout_topup(
        &self,
        raw_body: &str,
        signature_hex: Option<&str>,
    ) -> super::verifier::WebhookResult<TopupCallback> {
        verify_optional_payouts_hmac(self.payouts_secret(), raw_body, signature_hex)?;
        let cb: TopupCallback = super::verifier::parse_webhook_json_str(raw_body)?;
        if cb.topup_id.trim().is_empty() {
            return Err(super::verifier::WebhookError::MissingRequiredField(
                "topup_id".into(),
            ));
        }
        Ok(cb)
    }

    /// Verifies (when configured) and deserializes a Protocol E top-up
    /// webhook callback from raw request bytes.
    ///
    /// # Errors
    ///
    /// Returns [`super::verifier::WebhookError::InvalidJsonPayload`] if `raw_body` is not
    /// valid UTF-8, or any error returned by [`Self::verify_payout_topup`].
    pub fn verify_payout_topup_bytes(
        &self,
        raw_body: &[u8],
        signature_hex: Option<&str>,
    ) -> super::verifier::WebhookResult<TopupCallback> {
        let raw_str = super::verifier::decode_webhook_utf8(raw_body)?;
        self.verify_payout_topup(raw_str, signature_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    fn compute_test_hmac_hex(secret: &str, payload: &str) -> String {
        let mut mac =
            Hmac::<Sha512>::new_from_slice(secret.as_bytes()).expect("valid HMAC key length");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn disbursement_issuer_roundtrip_all_variants() {
        let cases = [
            (DisbursementIssuer::BankCard, "\"bank_card\""),
            (DisbursementIssuer::BankWallet, "\"bank_wallet\""),
            (DisbursementIssuer::InstantBank, "\"instant_bank\""),
        ];

        for (variant, wire) in cases {
            let serialized = serde_json::to_string(&variant).expect("serialize issuer");
            assert_eq!(serialized, wire);
            let parsed: DisbursementIssuer =
                serde_json::from_str(wire).expect("deserialize issuer");
            assert_eq!(parsed, variant);
        }
    }

    #[test]
    fn disbursement_callback_debug_redacts_recipient_identifier() {
        let cb = DisbursementCallback {
            transaction_id: "tx_100".to_owned(),
            issuer: DisbursementIssuer::InstantBank,
            amount_cents: 50_000,
            currency: "EGP".to_owned(),
            status: "success".to_owned(),
            recipient_identifier: Some("EG380019000500000000263180002".to_owned()),
        };

        let rendered = format!("{cb:?}");
        assert!(rendered.contains("Some(\"[REDACTED]\")"));
        assert!(!rendered.contains("EG380019000500000000263180002"));
        assert!(rendered.contains("tx_100") && rendered.contains("InstantBank"));
    }

    #[test]
    fn disbursement_callback_debug_handles_none_recipient() {
        let payload = r#"{
            "transaction_id": "tx_101",
            "issuer": "bank_card",
            "amount_cents": 1200,
            "currency": "EGP",
            "status": "pending"
        }"#;

        let cb: DisbursementCallback = serde_json::from_str(payload).expect("valid payload");
        assert_eq!(cb.recipient_identifier, None);
        let rendered = format!("{cb:?}");
        assert!(rendered.contains("recipient_identifier: None"));
    }

    #[test]
    fn topup_callback_roundtrip_approved_and_rejected() {
        let approved_json = r#"{
            "topup_id": "top_1",
            "amount_cents": 500000,
            "currency": "EGP",
            "status": "Approved"
        }"#;
        let approved: TopupCallback =
            serde_json::from_str(approved_json).expect("valid approved topup");
        assert_eq!(
            (approved.status, approved.amount_cents),
            (TopupStatus::Approved, 500_000)
        );

        let rejected_json = r#"{
            "topup_id": "top_2",
            "amount_cents": 0,
            "currency": "SAR",
            "status": "rejected"
        }"#;
        let rejected: TopupCallback =
            serde_json::from_str(rejected_json).expect("valid rejected topup");
        assert_eq!(
            (rejected.status, rejected.amount_cents),
            (TopupStatus::Rejected, 0)
        );
    }

    #[test]
    fn optional_payouts_hmac_handles_unconfigured_and_missing_states() {
        assert_eq!(verify_optional_payouts_hmac(None, "{}", None), Ok(()));
        assert_eq!(
            verify_optional_payouts_hmac(None, "{}", Some("")),
            Err(WebhookError::SignatureMismatch)
        );
        assert_eq!(
            verify_optional_payouts_hmac(None, "{}", Some("deadbeef")),
            Err(WebhookError::SignatureMismatch)
        );

        let secret = SecretString::from("payouts_secret_123".to_owned());
        assert_eq!(
            verify_optional_payouts_hmac(Some(&secret), "{}", None),
            Err(WebhookError::MissingQueryHmac)
        );
        assert_eq!(
            verify_optional_payouts_hmac(Some(&secret), "{}", Some("   ")),
            Err(WebhookError::MissingQueryHmac)
        );
    }

    #[test]
    fn optional_payouts_hmac_verifies_valid_and_rejects_tampered_or_malformed() {
        let secret_str = "payouts_secret_123";
        let secret = SecretString::from(secret_str.to_owned());
        let body =
            r#"{"topup_id":"top_9","amount_cents":1000,"currency":"EGP","status":"Approved"}"#;
        let valid_sig = compute_test_hmac_hex(secret_str, body);

        assert_eq!(
            verify_optional_payouts_hmac(Some(&secret), body, Some(&valid_sig)),
            Ok(())
        );

        let tampered_body =
            r#"{"topup_id":"top_9","amount_cents":9999,"currency":"EGP","status":"Approved"}"#;
        assert_eq!(
            verify_optional_payouts_hmac(Some(&secret), tampered_body, Some(&valid_sig)),
            Err(WebhookError::SignatureMismatch)
        );
        assert_eq!(
            verify_optional_payouts_hmac(Some(&secret), body, Some("not-valid-hex!")),
            Err(WebhookError::MalformedSignatureHex)
        );
    }

    #[test]
    fn verify_payout_methods_reject_empty_ids_and_unknown_enums() {
        let engine = PaymobWebhookEngine::new("accept_secret").expect("engine");
        let empty_tx = "{\"transaction_id\":\"  \",\"issuer\":\"bank_wallet\",\
            \"amount_cents\":100,\"currency\":\"EGP\",\"status\":\"ok\"}";
        let empty_topup = "{\"topup_id\":\"\",\"amount_cents\":100,\
            \"currency\":\"EGP\",\"status\":\"Approved\"}";
        let bad_issuer = "{\"transaction_id\":\"tx_1\",\"issuer\":\"crypto\",\
            \"amount_cents\":100,\"currency\":\"EGP\",\"status\":\"ok\"}";
        let bad_status = "{\"topup_id\":\"top_1\",\"amount_cents\":100,\
            \"currency\":\"EGP\",\"status\":\"Pending\"}";

        assert_eq!(
            engine.verify_payout_disbursement(empty_tx, None),
            Err(WebhookError::MissingRequiredField("transaction_id".into()))
        );
        assert_eq!(
            engine.verify_payout_topup(empty_topup, None),
            Err(WebhookError::MissingRequiredField("topup_id".into()))
        );
        assert!(matches!(
            engine.verify_payout_disbursement_bytes(bad_issuer.as_bytes(), None),
            Err(WebhookError::InvalidJsonPayload(_))
        ));
        assert!(matches!(
            engine.verify_payout_topup_bytes(bad_status.as_bytes(), None),
            Err(WebhookError::InvalidJsonPayload(_))
        ));
    }
}
