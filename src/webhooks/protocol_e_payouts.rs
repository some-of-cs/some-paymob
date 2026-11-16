//! Protocol E Paymob Payouts disbursement and topup webhook callbacks.
//!
//! This module models Paymob Payouts webhook payloads for outbound
//! disbursements ([`DisbursementCallback`]) and account top-up approvals
//! ([`TopupCallback`]), and extends [`super::verifier::PaymobWebhookEngine`]
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

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use std::fmt;
use subtle::ConstantTimeEq;

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

/// Verifies an optional `HMAC-SHA512` signature against `raw_body` when a
/// payouts secret is configured, failing closed on any configuration mismatch.
fn verify_optional_payouts_hmac(
    payouts_secret: Option<&SecretString>,
    raw_body: &str,
    signature_hex: Option<&str>,
) -> Result<(), super::verifier::WebhookError> {
    match (payouts_secret, signature_hex) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(super::verifier::WebhookError::SignatureMismatch),
        (Some(_), None) => Err(super::verifier::WebhookError::MissingQueryHmac),
        (Some(secret), Some(sig_hex)) => verify_hmac_sha512(
            secret.expose_secret().as_bytes(),
            raw_body.as_bytes(),
            sig_hex,
        ),
    }
}

/// Computes `HMAC-SHA512(key, payload)` and compares against `signature_hex`
/// in constant time using [`subtle::ConstantTimeEq`].
fn verify_hmac_sha512(
    key: &[u8],
    payload: &[u8],
    signature_hex: &str,
) -> Result<(), super::verifier::WebhookError> {
    let provided = hex::decode(signature_hex)
        .map_err(|_| super::verifier::WebhookError::MalformedSignatureHex)?;
    let mut mac = Hmac::<Sha512>::new_from_slice(key)
        .map_err(|_| super::verifier::WebhookError::InvalidSecretKeyLength)?;
    mac.update(payload);
    let expected = mac.finalize().into_bytes();

    if bool::from(expected.as_slice().ct_eq(provided.as_slice())) {
        Ok(())
    } else {
        Err(super::verifier::WebhookError::SignatureMismatch)
    }
}

impl super::verifier::PaymobWebhookEngine {
    /// Verifies (when configured) and deserializes a Protocol E disbursement
    /// webhook callback (`DisbursementCallback`).
    ///
    /// Fails closed if `signature_hex` is supplied without a configured
    /// `payouts_secret()`, or if `payouts_secret()` is configured while
    /// `signature_hex` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`super::verifier::WebhookError`] if HMAC verification fails,
    /// the signature configuration is inconsistent, or `raw_body` is invalid JSON.
    pub fn verify_payout_disbursement(
        &self,
        raw_body: &str,
        signature_hex: Option<&str>,
    ) -> Result<DisbursementCallback, super::verifier::WebhookError> {
        verify_optional_payouts_hmac(self.payouts_secret(), raw_body, signature_hex)?;
        serde_json::from_str(raw_body)
            .map_err(|_| super::verifier::WebhookError::InvalidJsonPayload)
    }

    /// Verifies (when configured) and deserializes a Protocol E top-up
    /// webhook callback (`TopupCallback`).
    ///
    /// Fails closed if `signature_hex` is supplied without a configured
    /// `payouts_secret()`, or if `payouts_secret()` is configured while
    /// `signature_hex` is `None`.
    ///
    /// # Errors
    ///
    /// Returns [`super::verifier::WebhookError`] if HMAC verification fails,
    /// the signature configuration is inconsistent, or `raw_body` is invalid JSON.
    pub fn verify_payout_topup(
        &self,
        raw_body: &str,
        signature_hex: Option<&str>,
    ) -> Result<TopupCallback, super::verifier::WebhookError> {
        verify_optional_payouts_hmac(self.payouts_secret(), raw_body, signature_hex)?;
        serde_json::from_str(raw_body)
            .map_err(|_| super::verifier::WebhookError::InvalidJsonPayload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::verifier::WebhookError;

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
        assert!(rendered.contains("tx_100"));
        assert!(rendered.contains("InstantBank"));
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
        assert_eq!(approved.status, TopupStatus::Approved);
        assert_eq!(approved.amount_cents, 500_000);

        let rejected_json = r#"{
            "topup_id": "top_2",
            "amount_cents": 0,
            "currency": "SAR",
            "status": "rejected"
        }"#;
        let rejected: TopupCallback =
            serde_json::from_str(rejected_json).expect("valid rejected topup");
        assert_eq!(rejected.status, TopupStatus::Rejected);
        assert_eq!(rejected.amount_cents, 0);
    }

    #[test]
    fn optional_payouts_hmac_accepts_unconfigured_without_signature() {
        assert_eq!(verify_optional_payouts_hmac(None, "{}", None), Ok(()));
    }

    #[test]
    fn optional_payouts_hmac_fails_closed_when_signature_without_secret() {
        let err = verify_optional_payouts_hmac(None, "{}", Some("deadbeef"))
            .expect_err("must fail closed");
        assert_eq!(err, WebhookError::SignatureMismatch);
    }

    #[test]
    fn optional_payouts_hmac_fails_closed_when_secret_without_signature() {
        let secret = SecretString::from("payouts_secret_123".to_owned());
        let err =
            verify_optional_payouts_hmac(Some(&secret), "{}", None).expect_err("must fail closed");
        assert_eq!(err, WebhookError::MissingQueryHmac);
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
}
