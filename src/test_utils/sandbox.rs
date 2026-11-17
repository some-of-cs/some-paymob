#![forbid(unsafe_code)]
//! Sandbox constraint guards and Paymob Webhook Testing Tool payload generators (`US-8.2.0` Unit 3).
//!
//! Surfaces Paymob Sandbox limitations documented in
//! `docs/Paymob Rust SDK Architecture Research.md` (lines 507–519):
//! - **30-day credential expiration**: Sandbox test credentials expire 30 days after issuance.
//! - **Kiosk & BNPL live-only**: Kiosk (`Aman`/`Masary`) and BNPL (`ValU`/`Sympl`/`Souhoola`/`Shahry`)
//!   flows are unsupported in Paymob Sandbox mode.
//! - **Webhook Testing Tool compatibility**: Generates HMAC-SHA512 signed payloads matching
//!   Paymob's Webhook Testing Tool canonical ordering.

use std::fmt;

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use serde_json::json;
use sha2::Sha512;

use crate::core::types::MinorUnitAmount;
use crate::webhooks::verifier::{PaymobWebhookEngine, WebhookError, WebhookResult};

type HmacSha512 = Hmac<Sha512>;

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
/// Redacts raw JSON body and HMAC digest in [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq)]
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
    let trimmed = hmac_secret.expose_secret().trim();
    if trimmed.is_empty() {
        return Err(WebhookError::InvalidSecretKeyLength);
    }
    let mut mac = HmacSha512::new_from_slice(trimmed.as_bytes())
        .map_err(|_| WebhookError::InvalidSecretKeyLength)?;
    mac.update(canonical_message.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Generates a signed Protocol A (`TRANSACTION` `POST`) payload for Paymob's Webhook Testing Tool.
///
/// # Errors
///
/// Returns [`WebhookError::InvalidSecretKeyLength`] if `hmac_secret` is empty.
///
/// # Examples
///
/// ```rust
/// use secrecy::SecretString;
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::test_utils::sandbox::generate_signed_transaction_post;
/// use some_paymob::webhooks::PaymobWebhookEngine;
///
/// let secret = SecretString::from("my_sandbox_hmac_secret");
/// let signed = generate_signed_transaction_post(
///     &secret,
///     990011,
///     880022,
///     MinorUnitAmount::new(25_000),
///     "EGP",
///     true,
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
    transaction_id: u64,
    order_id: u64,
    amount: MinorUnitAmount,
    currency: &str,
    success: bool,
) -> WebhookResult<SignedWebhookToolPayload> {
    let created_at = "2026-11-17T10:00:00.000000";
    let integration_id = 4097558_u64;
    let owner = 302852_u64;
    let pan = "2346";
    let sub_type = "MasterCard";
    let source_type = "card";
    let amount_cents = amount.as_u64();

    let canonical = format!(
        "{amount_cents}{created_at}{currency}falsefalse{transaction_id}{integration_id}\
         truefalsefalsefalsetruefalse{order_id}{owner}false{pan}{sub_type}{source_type}{success}"
    );
    let hmac_hex = sign_hmac_sha512(hmac_secret, &canonical)?;
    let json_body = json!({
        "type": "TRANSACTION",
        "obj": {
            "id": transaction_id,
            "pending": false,
            "amount_cents": amount_cents,
            "success": success,
            "is_auth": false,
            "is_capture": false,
            "is_standalone_payment": true,
            "is_voided": false,
            "is_refunded": false,
            "is_3d_secure": true,
            "integration_id": integration_id,
            "profile_id": 164295,
            "has_parent_transaction": false,
            "order": {
                "id": order_id,
                "created_at": created_at,
                "delivery_needed": false,
                "amount_cents": amount_cents,
                "currency": currency
            },
            "created_at": created_at,
            "transaction_processed_callback_responses": [],
            "currency": currency,
            "source_data": {
                "pan": pan,
                "type": source_type,
                "tenure": null,
                "sub_type": sub_type
            },
            "api_source": "IFRAME",
            "is_void": false,
            "is_refund": false,
            "error_occured": false,
            "is_live": false,
            "refunded_amount_cents": null,
            "is_captured": false,
            "captured_amount": null,
            "owner": owner
        },
        "issuer_bank": null,
        "transaction_processed_callback_responses": ""
    })
    .to_string();

    // Ensure generated payload always satisfies PaymobWebhookEngine roundtrip contract.
    let _ =
        PaymobWebhookEngine::verify_concatenated_with_secret(hmac_secret, &canonical, &hmac_hex)?;

    Ok(SignedWebhookToolPayload {
        json_body,
        hmac_hex,
    })
}

/// Generates a signed Protocol D (`Subscription`) JSON body for Paymob's Webhook Testing Tool.
///
/// # Errors
///
/// Returns [`WebhookError::InvalidSecretKeyLength`] if `hmac_secret` is empty.
///
/// # Examples
///
/// ```rust
/// use secrecy::SecretString;
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::test_utils::sandbox::generate_signed_subscription_post;
/// use some_paymob::webhooks::PaymobWebhookEngine;
///
/// let secret = SecretString::from("my_sandbox_hmac_secret");
/// let signed = generate_signed_subscription_post(
///     &secret,
///     "req-sub-1",
///     1264,
///     "suspended",
///     MinorUnitAmount::new(330),
/// )
/// .expect("signed subscription payload");
///
/// let engine = PaymobWebhookEngine::new("my_sandbox_hmac_secret").unwrap();
/// let event = engine.verify_subscription(&signed.json_body).expect("verifies cleanly");
/// assert_eq!(event.subscription_data.id, 1264);
/// ```
pub fn generate_signed_subscription_post(
    hmac_secret: &SecretString,
    paymob_request_id: &str,
    subscription_id: u64,
    trigger_type: &str,
    amount: MinorUnitAmount,
) -> WebhookResult<SignedWebhookToolPayload> {
    let canonical = format!("{trigger_type}for{subscription_id}");
    let hmac_hex = sign_hmac_sha512(hmac_secret, &canonical)?;
    let json_body = json!({
        "paymob_request_id": paymob_request_id,
        "subscription_data": {
            "id": subscription_id,
            "amount_cents": amount.as_u64(),
            "state": trigger_type
        },
        "trigger_type": trigger_type,
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
    fn tc_8_2_3_signed_webhook_tool_payloads_verify_and_reject_empty_secret() {
        let empty = SecretString::from("   ");
        assert_eq!(
            sign_hmac_sha512(&empty, "msg"),
            Err(WebhookError::InvalidSecretKeyLength)
        );

        let secret = SecretString::from("tool_secret_123");
        let tx = generate_signed_transaction_post(
            &secret,
            777,
            888,
            MinorUnitAmount::new(15_000),
            "SAR",
            true,
        )
        .expect("signed tx");
        let engine = PaymobWebhookEngine::new("tool_secret_123").unwrap();
        let parsed_tx = engine
            .verify_transaction_post(&tx.json_body, &tx.hmac_hex)
            .expect("tx verifies");
        assert_eq!(parsed_tx.obj.amount_cents, 15_000);

        let sub = generate_signed_subscription_post(
            &secret,
            "req-1",
            1264,
            "resumed",
            MinorUnitAmount::new(330),
        )
        .expect("signed sub");
        let parsed_sub = engine
            .verify_subscription(&sub.json_body)
            .expect("sub verifies");
        assert_eq!(parsed_sub.subscription_data.id, 1264);
    }

    #[test]
    fn tc_8_2_4_signed_payload_debug_redacts_body_and_hmac() {
        let secret = SecretString::from("tool_secret_123");
        let tx = generate_signed_transaction_post(
            &secret,
            777,
            888,
            MinorUnitAmount::new(15_000),
            "EGP",
            true,
        )
        .expect("signed tx");
        let rendered = format!("{tx:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains(&tx.hmac_hex));
        assert!(!rendered.contains("15000"));
    }
}
