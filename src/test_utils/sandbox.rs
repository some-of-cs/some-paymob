#![forbid(unsafe_code)]
//! Sandbox constraint guards and Paymob Webhook Testing Tool payload generators (`US-8.2.0` Unit 3).
//!
//! Surfaces Paymob Sandbox limitations documented in
//! `docs/Paymob Rust SDK Architecture Research.md` (lines 507–519):
//! - **30-day credential expiration**: Sandbox test credentials expire 30 days after issuance.
//! - **Kiosk & BNPL live-only**: Kiosk (`Aman`/`Masary`) and BNPL (`ValU`/`Sympl`/`Souhoola`/`Shahry`)
//!   flows are unsupported in Paymob Sandbox mode.
//! - **Webhook Testing Tool compatibility**: Generates HMAC-SHA512 signed payloads matching
//!   Paymob's Webhook Testing Tool canonical ordering by reusing the crate's Protocol A and
//!   Protocol D canonical builders.

use std::fmt;

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use sha2::Sha512;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::core::credentials::resolve_secret_or_env;
use crate::core::types::MinorUnitAmount;
use crate::webhooks::{
    PaymobWebhookEngine, SubscriptionTriggerType, TransactionProcessedEvent, WebhookError,
    WebhookResult, build_protocol_a_canonical_string, canonical_subscription_message,
};

type HmacSha512 = Hmac<Sha512>;

const TX_CREATED_AT: &str = "2026-11-17T10:00:00.000000";
const TX_INTEGRATION_ID: u64 = 4_097_558;
const TX_OWNER: u64 = 302_852;
const TX_PAN: &str = "2346";
const TX_SUB_TYPE: &str = "MasterCard";
const TX_SOURCE_TYPE: &str = "card";

/// Maximum lifetime (in days) of Paymob Sandbox test credentials before expiry.
pub const SANDBOX_CREDENTIAL_MAX_AGE_DAYS: u64 = 30;

/// Age threshold (in days) at which [`SandboxGuard`] emits an expiring-soon warning.
pub const SANDBOX_CREDENTIAL_WARN_AGE_DAYS: u64 = 25;

/// Payment channel evaluated by [`SandboxGuard`] for Paymob Sandbox compatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SandboxPaymentChannel {
    /// Standard 3DS card payment (supported in sandbox).
    Card,
    /// Mobile wallet payment (supported in sandbox with test wallets).
    MobileWallet,
    /// Kiosk payment (`Aman` / `Masary`) — live-only, unsupported in sandbox.
    Kiosk,
    /// Buy-Now-Pay-Later (`ValU`, `Sympl`, `Souhoola`, `Shahry`) — live-only, unsupported in sandbox.
    Bnpl,
    /// Payouts disbursement channel.
    Payouts,
}

/// Non-fatal sandbox diagnostic warning surfaced by [`SandboxGuard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxWarning {
    /// Sandbox test credentials are approaching the 30-day expiration limit.
    CredentialExpiringSoon {
        /// Age of the sandbox credentials in days.
        age_days: u64,
        /// Remaining days before the 30-day expiration cutoff.
        days_remaining: u64,
    },
}

/// Blocking sandbox constraint error surfaced by [`SandboxGuard`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SandboxConstraintError {
    /// Sandbox credentials have reached or exceeded the 30-day expiration limit.
    #[error(
        "Paymob sandbox test credentials expired ({age_days} days old; max {SANDBOX_CREDENTIAL_MAX_AGE_DAYS} days) — regenerate keys in Paymob Dashboard"
    )]
    CredentialExpired {
        /// Age of the sandbox credentials in days.
        age_days: u64,
    },
    /// Attempted to run a live-only payment channel (Kiosk or BNPL) in sandbox mode.
    #[error("Paymob channel `{channel}` is live-only and unsupported in Sandbox mode")]
    UnsupportedSandboxChannel {
        /// Human-readable channel name (`"Kiosk"` or `"BNPL"`).
        channel: &'static str,
    },
}

/// Input parameters for [`SandboxGuard::check_constraints`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxCheckRequest {
    /// `true` when operating against Paymob Sandbox / Test mode.
    pub is_sandbox: bool,
    /// Age of the test credentials in days since creation.
    pub credential_age_days: u64,
    /// Payment channel being exercised.
    pub channel: SandboxPaymentChannel,
}

/// Input parameters for [`generate_signed_transaction_post`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedTransactionRequest<'a> {
    /// Paymob transaction ID (must be non-zero).
    pub transaction_id: u64,
    /// Paymob order ID (must be non-zero).
    pub order_id: u64,
    /// Payment amount in minor units (must be positive).
    pub amount: MinorUnitAmount,
    /// Three-letter ISO currency code (e.g., `"EGP"` or `"SAR"`).
    pub currency: &'a str,
    /// Whether the simulated transaction succeeded.
    pub success: bool,
}

/// Input parameters for [`generate_signed_subscription_post`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedSubscriptionRequest<'a> {
    /// Paymob request correlation identifier.
    pub paymob_request_id: &'a str,
    /// Paymob subscription ID (must be non-zero).
    pub subscription_id: u64,
    /// Subscription lifecycle trigger type (e.g., `"suspended"` or `"resumed"`).
    pub trigger_type: &'a str,
    /// Subscription billing amount in minor units (must be positive).
    pub amount: MinorUnitAmount,
}

/// Structured diagnostic outcome returned by [`SandboxGuard::check_constraints`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SandboxReport {
    /// Non-blocking warnings (for example, credentials expiring within 5 days).
    pub warnings: Vec<SandboxWarning>,
    /// Blocking constraint errors (for example, 30-day expiry or Kiosk/BNPL in sandbox).
    pub errors: Vec<SandboxConstraintError>,
}

impl SandboxReport {
    /// Returns `true` when zero blocking [`SandboxConstraintError`]s were detected.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Diagnostic validator for Paymob Sandbox constraints and Webhook Testing Tool payloads.
///
/// # Examples
///
/// ```rust
/// use some_paymob::test_utils::sandbox::{
///     SandboxCheckRequest, SandboxGuard, SandboxPaymentChannel,
/// };
///
/// let ok_req = SandboxCheckRequest {
///     is_sandbox: true,
///     credential_age_days: 10,
///     channel: SandboxPaymentChannel::Card,
/// };
/// assert!(SandboxGuard::check_constraints(&ok_req).is_ok());
///
/// let kiosk_req = SandboxCheckRequest {
///     is_sandbox: true,
///     credential_age_days: 10,
///     channel: SandboxPaymentChannel::Kiosk,
/// };
/// assert!(!SandboxGuard::check_constraints(&kiosk_req).is_ok());
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct SandboxGuard;

impl SandboxGuard {
    /// Validates sandbox credential age and channel compatibility.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::test_utils::sandbox::{
    ///     SandboxCheckRequest, SandboxGuard, SandboxPaymentChannel,
    /// };
    ///
    /// let expired = SandboxCheckRequest {
    ///     is_sandbox: true,
    ///     credential_age_days: 30,
    ///     channel: SandboxPaymentChannel::Card,
    /// };
    /// let report = SandboxGuard::check_constraints(&expired);
    /// assert!(!report.is_ok());
    /// ```
    #[must_use]
    pub fn check_constraints(request: &SandboxCheckRequest) -> SandboxReport {
        let mut report = SandboxReport::default();
        if !request.is_sandbox {
            return report;
        }
        Self::evaluate_credential_age(request.credential_age_days, &mut report);
        Self::evaluate_channel(request.channel, &mut report);
        report
    }

    fn evaluate_credential_age(age_days: u64, report: &mut SandboxReport) {
        if age_days >= SANDBOX_CREDENTIAL_MAX_AGE_DAYS {
            report
                .errors
                .push(SandboxConstraintError::CredentialExpired { age_days });
            return;
        }
        if age_days >= SANDBOX_CREDENTIAL_WARN_AGE_DAYS {
            report
                .warnings
                .push(SandboxWarning::CredentialExpiringSoon {
                    age_days,
                    days_remaining: SANDBOX_CREDENTIAL_MAX_AGE_DAYS - age_days,
                });
        }
    }

    fn evaluate_channel(channel: SandboxPaymentChannel, report: &mut SandboxReport) {
        match channel {
            SandboxPaymentChannel::Kiosk => {
                report
                    .errors
                    .push(SandboxConstraintError::UnsupportedSandboxChannel { channel: "Kiosk" });
            }
            SandboxPaymentChannel::Bnpl => {
                report
                    .errors
                    .push(SandboxConstraintError::UnsupportedSandboxChannel { channel: "BNPL" });
            }
            SandboxPaymentChannel::Card
            | SandboxPaymentChannel::MobileWallet
            | SandboxPaymentChannel::Payouts => {}
        }
    }
}

/// Signed payload bundle compatible with Paymob's Webhook Testing Tool.
///
/// Redacts raw JSON body and HMAC digest in [`fmt::Debug`] and zeroizes
/// both string buffers on drop.
#[derive(Clone, PartialEq, Eq, ZeroizeOnDrop)]
pub struct SignedWebhookToolPayload {
    /// Serialized JSON webhook body.
    pub json_body: String,
    /// 128-character lowercase hex HMAC-SHA512 signature.
    pub hmac_hex: String,
}

impl fmt::Debug for SignedWebhookToolPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignedWebhookToolPayload")
            .field("json_body", &"[REDACTED]")
            .field("hmac_hex", &"[REDACTED]")
            .finish()
    }
}

/// Computes a lowercase hex HMAC-SHA512 signature over `canonical_message`.
///
/// Supports `$ENV_VARNAME` / `.env` references via [`resolve_secret_or_env`] and
/// zeroizes intermediate digest bytes after hex encoding.
///
/// # Errors
///
/// Returns [`WebhookError::InvalidSecretKeyLength`] if `hmac_secret` is empty or whitespace.
///
/// # Examples
///
/// ```rust
/// use secrecy::SecretString;
/// use some_paymob::test_utils::sandbox::sign_hmac_sha512;
///
/// let secret = SecretString::from("test_hmac_secret");
/// let sig = sign_hmac_sha512(&secret, "100020003000").expect("valid secret");
/// assert_eq!(sig.len(), 128);
/// ```
pub fn sign_hmac_sha512(
    hmac_secret: &SecretString,
    canonical_message: &str,
) -> WebhookResult<String> {
    let resolved = resolve_secret_or_env("hmac_secret", hmac_secret.expose_secret())
        .map_err(|_| WebhookError::InvalidSecretKeyLength)?;
    let trimmed = resolved.expose_secret().trim();
    if trimmed.is_empty() {
        return Err(WebhookError::InvalidSecretKeyLength);
    }
    let mut mac = HmacSha512::new_from_slice(trimmed.as_bytes())
        .map_err(|_| WebhookError::InvalidSecretKeyLength)?;
    mac.update(canonical_message.as_bytes());
    let mut digest = mac.finalize().into_bytes();
    let encoded = hex::encode(digest.as_slice());
    digest.as_mut_slice().zeroize();
    Ok(encoded)
}

fn build_transaction_post_body(request: &SignedTransactionRequest<'_>) -> String {
    let amount_cents = request.amount.as_u64();
    let currency = request.currency.trim();
    json!({
        "type": "TRANSACTION",
        "obj": {
            "id": request.transaction_id,
            "pending": false,
            "amount_cents": amount_cents,
            "success": request.success,
            "is_auth": false,
            "is_capture": false,
            "is_standalone_payment": true,
            "is_voided": false,
            "is_refunded": false,
            "is_3d_secure": true,
            "integration_id": TX_INTEGRATION_ID,
            "profile_id": 164_295,
            "has_parent_transaction": false,
            "order": {
                "id": request.order_id,
                "created_at": TX_CREATED_AT,
                "delivery_needed": false,
                "amount_cents": amount_cents,
                "currency": currency
            },
            "created_at": TX_CREATED_AT,
            "transaction_processed_callback_responses": [],
            "currency": currency,
            "source_data": {
                "pan": TX_PAN,
                "type": TX_SOURCE_TYPE,
                "tenure": null,
                "sub_type": TX_SUB_TYPE
            },
            "api_source": "IFRAME",
            "is_void": false,
            "is_refund": false,
            "error_occured": false,
            "is_live": false,
            "refunded_amount_cents": null,
            "is_captured": false,
            "captured_amount": null,
            "owner": TX_OWNER
        },
        "issuer_bank": null,
        "transaction_processed_callback_responses": ""
    })
    .to_string()
}

/// Generates a signed Protocol A (`TRANSACTION` `POST`) payload for Paymob's Webhook Testing Tool.
///
/// Reuses [`build_protocol_a_canonical_string`] so the 20-key canonical concatenation order
/// is shared directly with [`PaymobWebhookEngine`].
///
/// # Errors
///
/// Returns [`WebhookError`] if `hmac_secret` is empty or `request.transaction_id` is zero.
///
/// # Examples
///
/// ```rust
/// use secrecy::SecretString;
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::test_utils::sandbox::{
///     SignedTransactionRequest, generate_signed_transaction_post,
/// };
/// use some_paymob::webhooks::PaymobWebhookEngine;
///
/// let secret = SecretString::from("my_sandbox_hmac_secret");
/// let signed = generate_signed_transaction_post(
///     &secret,
///     &SignedTransactionRequest {
///         transaction_id: 990011,
///         order_id: 880022,
///         amount: MinorUnitAmount::new(25_000),
///         currency: "EGP",
///         success: true,
///     },
/// )
/// .expect("signed payload");
///
/// let engine = PaymobWebhookEngine::new("my_sandbox_hmac_secret").unwrap();
/// let event = engine
///     .verify_transaction_post(&signed.json_body, &signed.hmac_hex)
///     .expect("verifies cleanly");
/// assert_eq!(event.obj.id, 990011);
/// ```
pub fn generate_signed_transaction_post(
    hmac_secret: &SecretString,
    request: &SignedTransactionRequest<'_>,
) -> WebhookResult<SignedWebhookToolPayload> {
    if request.transaction_id == 0 {
        return Err(WebhookError::MissingRequiredField(
            "transaction_id".to_owned(),
        ));
    }
    let json_body = build_transaction_post_body(request);
    let parsed: TransactionProcessedEvent = serde_json::from_str(&json_body)?;
    let canonical = build_protocol_a_canonical_string(&parsed.obj);
    let hmac_hex = sign_hmac_sha512(hmac_secret, &canonical)?;

    // Ensure generated payload always satisfies PaymobWebhookEngine roundtrip contract.
    PaymobWebhookEngine::verify_concatenated_with_secret(hmac_secret, &canonical, &hmac_hex)?;

    Ok(SignedWebhookToolPayload {
        json_body,
        hmac_hex,
    })
}

/// Generates a signed Protocol D (`Subscription`) JSON body for Paymob's Webhook Testing Tool.
///
/// Reuses [`canonical_subscription_message`] so the `<trigger_type>for<id>` signature
/// format is shared directly with [`PaymobWebhookEngine`].
///
/// # Errors
///
/// Returns [`WebhookError`] if `hmac_secret` is empty or `request.subscription_id` is zero.
///
/// # Examples
///
/// ```rust
/// use secrecy::SecretString;
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::test_utils::sandbox::{
///     SignedSubscriptionRequest, generate_signed_subscription_post,
/// };
/// use some_paymob::webhooks::PaymobWebhookEngine;
///
/// let secret = SecretString::from("my_sandbox_hmac_secret");
/// let signed = generate_signed_subscription_post(
///     &secret,
///     &SignedSubscriptionRequest {
///         paymob_request_id: "req-sub-1",
///         subscription_id: 1264,
///         trigger_type: "suspended",
///         amount: MinorUnitAmount::new(330),
///     },
/// )
/// .expect("signed subscription payload");
///
/// let engine = PaymobWebhookEngine::new("my_sandbox_hmac_secret").unwrap();
/// let event = engine.verify_subscription(&signed.json_body).expect("verifies cleanly");
/// assert_eq!(event.subscription_data.id, 1264);
/// ```
pub fn generate_signed_subscription_post(
    hmac_secret: &SecretString,
    request: &SignedSubscriptionRequest<'_>,
) -> WebhookResult<SignedWebhookToolPayload> {
    if request.subscription_id == 0 {
        return Err(WebhookError::MissingRequiredField(
            "subscription_id".to_owned(),
        ));
    }
    let trigger = SubscriptionTriggerType::from_wire(request.trigger_type.trim());
    let canonical = canonical_subscription_message(&trigger, request.subscription_id);
    let hmac_hex = sign_hmac_sha512(hmac_secret, &canonical)?;
    let json_body = json!({
        "paymob_request_id": request.paymob_request_id.trim(),
        "subscription_data": {
            "id": request.subscription_id,
            "amount_cents": request.amount.as_u64(),
            "state": trigger.as_wire()
        },
        "trigger_type": trigger.as_wire(),
        "hmac": hmac_hex
    })
    .to_string();

    Ok(SignedWebhookToolPayload {
        json_body,
        hmac_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_tx_req(tx_id: u64, currency: &str) -> SignedTransactionRequest<'_> {
        SignedTransactionRequest {
            transaction_id: tx_id,
            order_id: 888,
            amount: MinorUnitAmount::new(15_000),
            currency,
            success: true,
        }
    }

    #[test]
    fn tc_8_2_3_sandbox_guard_credential_age_boundaries() {
        let fresh = SandboxGuard::check_constraints(&SandboxCheckRequest {
            is_sandbox: true,
            credential_age_days: 24,
            channel: SandboxPaymentChannel::Card,
        });
        assert!(fresh.is_ok() && fresh.warnings.is_empty());

        let warning = SandboxGuard::check_constraints(&SandboxCheckRequest {
            is_sandbox: true,
            credential_age_days: 25,
            channel: SandboxPaymentChannel::MobileWallet,
        });
        assert!(warning.is_ok());
        assert_eq!(
            warning.warnings,
            vec![SandboxWarning::CredentialExpiringSoon {
                age_days: 25,
                days_remaining: 5,
            }]
        );

        let expired = SandboxGuard::check_constraints(&SandboxCheckRequest {
            is_sandbox: true,
            credential_age_days: 30,
            channel: SandboxPaymentChannel::Card,
        });
        assert!(!expired.is_ok());
        assert_eq!(
            expired.errors,
            vec![SandboxConstraintError::CredentialExpired { age_days: 30 }]
        );
    }

    #[test]
    fn tc_8_2_3_sandbox_guard_flags_kiosk_and_bnpl_only_in_sandbox() {
        for ch in [SandboxPaymentChannel::Kiosk, SandboxPaymentChannel::Bnpl] {
            let sandbox_res = SandboxGuard::check_constraints(&SandboxCheckRequest {
                is_sandbox: true,
                credential_age_days: 5,
                channel: ch,
            });
            assert!(!sandbox_res.is_ok());

            let live_res = SandboxGuard::check_constraints(&SandboxCheckRequest {
                is_sandbox: false,
                credential_age_days: 90,
                channel: ch,
            });
            assert!(live_res.is_ok() && live_res.warnings.is_empty());
        }
    }

    #[test]
    fn tc_8_2_3_signed_webhook_tool_payloads_verify_roundtrip() {
        let secret = SecretString::from("tool_secret_123");
        let tx = generate_signed_transaction_post(&secret, &sample_tx_req(777, "SAR")).expect("tx");
        let engine = PaymobWebhookEngine::new("tool_secret_123").unwrap();
        let parsed_tx = engine
            .verify_transaction_post(&tx.json_body, &tx.hmac_hex)
            .expect("tx verifies");
        assert_eq!(parsed_tx.obj.amount_cents, 15_000);

        let sub = generate_signed_subscription_post(
            &secret,
            &SignedSubscriptionRequest {
                paymob_request_id: "req-1",
                subscription_id: 1264,
                trigger_type: "resumed",
                amount: MinorUnitAmount::new(330),
            },
        )
        .expect("signed sub");
        let parsed_sub = engine
            .verify_subscription(&sub.json_body)
            .expect("sub verifies");
        assert_eq!(parsed_sub.subscription_data.id, 1264);
    }

    #[test]
    fn tc_8_2_3_signed_webhook_tool_rejects_invalid_inputs() {
        let empty = SecretString::from("   ");
        assert_eq!(
            sign_hmac_sha512(&empty, "msg"),
            Err(WebhookError::InvalidSecretKeyLength)
        );

        let secret = SecretString::from("tool_secret_123");
        assert!(generate_signed_transaction_post(&secret, &sample_tx_req(0, "EGP")).is_err());
    }

    #[test]
    fn tc_8_2_4_signed_payload_debug_redacts_body_and_hmac() {
        let secret = SecretString::from("tool_secret_123");
        let tx = generate_signed_transaction_post(&secret, &sample_tx_req(777, "EGP")).expect("tx");
        let rendered = format!("{tx:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&tx.hmac_hex));
        assert!(!rendered.contains("15000"));
    }
}
