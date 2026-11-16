//! Core webhook error types and constant-time HMAC-SHA512 verification engine.
//!
//! Owned by Unit 7.1.1 (`feat/us-7.1.0/unit-1-webhook-error-and-core`).

use std::fmt;

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha512;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

type HmacSha512 = Hmac<Sha512>;

const SHA512_DIGEST_LEN: usize = 64;

/// Convenient result alias for Paymob webhook verification and parsing operations.
pub type WebhookResult<T> = Result<T, WebhookError>;

/// Errors returned during Paymob webhook signature verification and payload parsing.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum WebhookError {
    /// The provided HMAC signature is not valid hexadecimal or does not decode to 64 bytes.
    #[error("malformed webhook signature hex: expected 128 hex characters (64 bytes)")]
    MalformedSignatureHex,

    /// The configured HMAC secret key is empty or has an invalid length.
    #[error("invalid HMAC secret key length: secret must not be empty")]
    InvalidSecretKeyLength,

    /// The computed HMAC-SHA512 digest did not match the provided signature.
    #[error("webhook HMAC-SHA512 signature mismatch")]
    SignatureMismatch,

    /// The `hmac` query parameter was missing from a GET redirect or POST callback.
    #[error("missing `hmac` query parameter in webhook request")]
    MissingQueryHmac,

    /// The `hmac` field was missing from a JSON webhook body.
    #[error("missing `hmac` field in webhook JSON body")]
    MissingBodyHmac,

    /// A required field was missing from the webhook payload or query parameters.
    #[error("missing required webhook field: {0}")]
    MissingRequiredField(String),

    /// The webhook payload could not be parsed as valid JSON.
    #[error("invalid webhook JSON payload: {0}")]
    InvalidJsonPayload(String),

    /// Webhook event was already processed according to the idempotency store.
    #[error(
        "duplicate webhook delivery rejected: key={idempotency_key}, correlation_id={correlation_id}"
    )]
    DuplicateWebhookDelivery {
        /// Protocol-specific primary idempotency key.
        idempotency_key: String,
        /// Protocol-specific secondary correlation identifier.
        correlation_id: String,
    },
}

impl WebhookError {
    /// Returns `true` if the error represents a missing, malformed, or mismatched HMAC signature.
    #[must_use]
    pub const fn is_signature_error(&self) -> bool {
        matches!(
            self,
            Self::MalformedSignatureHex
                | Self::SignatureMismatch
                | Self::MissingQueryHmac
                | Self::MissingBodyHmac
        )
    }

    /// Returns `true` if the error represents a malformed JSON body or missing required field.
    #[must_use]
    pub const fn is_malformed_payload(&self) -> bool {
        matches!(
            self,
            Self::MissingRequiredField(_) | Self::InvalidJsonPayload(_)
        )
    }

    /// Returns `true` if the error is caused by an invalid local HMAC secret key configuration.
    #[must_use]
    pub const fn is_configuration_error(&self) -> bool {
        matches!(self, Self::InvalidSecretKeyLength)
    }

    /// Returns `true` if the webhook delivery was rejected as a replay or duplicate.
    #[must_use]
    pub const fn is_replay_or_duplicate(&self) -> bool {
        matches!(self, Self::DuplicateWebhookDelivery { .. })
    }

    /// Returns the recommended HTTP status code for the webhook endpoint response.
    ///
    /// - `401 Unauthorized` for signature errors (`MalformedSignatureHex`, `SignatureMismatch`,
    ///   `MissingQueryHmac`, `MissingBodyHmac`).
    /// - `400 Bad Request` for malformed payloads (`MissingRequiredField`, `InvalidJsonPayload`).
    /// - `409 Conflict` for duplicate deliveries (`DuplicateWebhookDelivery`).
    /// - `500 Internal Server Error` for local configuration errors (`InvalidSecretKeyLength`).
    #[must_use]
    pub const fn suggested_http_status_code(&self) -> u16 {
        if self.is_signature_error() {
            401
        } else if self.is_malformed_payload() {
            400
        } else if self.is_replay_or_duplicate() {
            409
        } else {
            500
        }
    }

    /// Returns `true` if the webhook sender should retry delivery (only on configuration errors).
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        self.is_configuration_error()
    }

    /// Converts a [`serde_json::Error`] into [`WebhookError::InvalidJsonPayload`] while
    /// redacting any quoted string literals as `"[REDACTED]"` to prevent PAN/token leakage.
    #[must_use]
    pub fn from_serde_error(err: &serde_json::Error) -> Self {
        Self::InvalidJsonPayload(redact_quoted_literals(&err.to_string()))
    }
}

impl From<serde_json::Error> for WebhookError {
    fn from(err: serde_json::Error) -> Self {
        Self::from_serde_error(&err)
    }
}

fn redact_quoted_literals(input: &str) -> String {
    if !input.contains('"') {
        return input.to_owned();
    }
    let mut out = String::with_capacity(input.len());
    for (idx, part) in input.split('"').enumerate() {
        let piece = if idx % 2 == 0 { part } else { "\"[REDACTED]\"" };
        out.push_str(piece);
    }
    out
}

/// Constant-time HMAC-SHA512 webhook verification engine for Paymob callbacks.
///
/// Holds the primary Accept HMAC secret and an optional Payouts HMAC secret,
/// redacting both in [`fmt::Debug`] output.
///
/// # Examples
///
/// ```rust
/// use some_paymob::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
///
/// let engine = PaymobWebhookEngine::new("test_hmac_secret")?;
/// let sig = "b0c960da53f0c16e9d7478563f3fd8063633f9fd9b009025f568aba9252542ac\
///            637c171bdee453b160d89b957f4ef93cd30814ddb147f4c1a1497443d150c68d";
/// assert_eq!(engine.verify_concatenated_str("100020003000", sig), Ok(()));
/// # Ok::<(), WebhookError>(())
/// ```
#[derive(Clone)]
pub struct PaymobWebhookEngine {
    hmac_secret: SecretString,
    payouts_hmac_secret: Option<SecretString>,
}

impl fmt::Debug for PaymobWebhookEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobWebhookEngine")
            .field("hmac_secret", &"[REDACTED]")
            .field(
                "payouts_hmac_secret",
                &self.payouts_hmac_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl PaymobWebhookEngine {
    /// Creates a new [`PaymobWebhookEngine`] with the primary Accept HMAC secret.
    ///
    /// Rejects empty or whitespace-only secrets with [`WebhookError::InvalidSecretKeyLength`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    ///
    /// assert_eq!(
    ///     PaymobWebhookEngine::new("").unwrap_err(),
    ///     WebhookError::InvalidSecretKeyLength
    /// );
    /// let engine = PaymobWebhookEngine::new("my_secret")?;
    /// assert!(engine.payouts_secret().is_none());
    /// # Ok::<(), WebhookError>(())
    /// ```
    pub fn new(hmac_secret: impl Into<SecretString>) -> WebhookResult<Self> {
        let secret = normalize_secret_string(hmac_secret.into())?;
        Ok(Self {
            hmac_secret: secret,
            payouts_hmac_secret: None,
        })
    }

    /// Constructs a [`PaymobWebhookEngine`] directly from a validated [`HmacSecret`](crate::core::credentials::HmacSecret).
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::core::credentials::HmacSecret;
    /// use some_paymob::webhooks::verifier::PaymobWebhookEngine;
    ///
    /// let secret = HmacSecret::new("my_secret").unwrap();
    /// let engine = PaymobWebhookEngine::from_hmac_secret(&secret);
    /// assert!(engine.payouts_secret().is_none());
    /// ```
    #[must_use]
    pub fn from_hmac_secret(secret: &crate::core::credentials::HmacSecret) -> Self {
        Self {
            hmac_secret: secret.as_secret_string().clone(),
            payouts_hmac_secret: None,
        }
    }

    /// Configures an optional Payouts HMAC secret for Protocol E callbacks.
    ///
    /// Rejects empty or whitespace-only secrets with [`WebhookError::InvalidSecretKeyLength`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    ///
    /// let engine = PaymobWebhookEngine::new("accept_secret")?
    ///     .with_payouts_secret("payout_secret")?;
    /// assert!(engine.payouts_secret().is_some());
    /// # Ok::<(), WebhookError>(())
    /// ```
    pub fn with_payouts_secret(mut self, secret: impl Into<SecretString>) -> WebhookResult<Self> {
        let secret = normalize_secret_string(secret.into())?;
        self.payouts_hmac_secret = Some(secret);
        Ok(self)
    }

    /// Configures an optional Payouts [`HmacSecret`](crate::core::credentials::HmacSecret) for Protocol E callbacks.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::core::credentials::HmacSecret;
    /// use some_paymob::webhooks::verifier::PaymobWebhookEngine;
    ///
    /// let primary = HmacSecret::new("accept_secret").unwrap();
    /// let payouts = HmacSecret::new("payout_secret").unwrap();
    /// let engine = PaymobWebhookEngine::from_hmac_secret(&primary)
    ///     .with_payouts_hmac_secret(&payouts);
    /// assert!(engine.payouts_secret().is_some());
    /// ```
    #[must_use]
    pub fn with_payouts_hmac_secret(
        mut self,
        secret: &crate::core::credentials::HmacSecret,
    ) -> Self {
        self.payouts_hmac_secret = Some(secret.as_secret_string().clone());
        self
    }

    /// Returns a reference to the configured Payouts HMAC secret, if present.
    #[must_use]
    pub fn payouts_secret(&self) -> Option<&SecretString> {
        self.payouts_hmac_secret.as_ref()
    }

    /// Verifies a pre-concatenated Paymob webhook string against a hex-encoded
    /// HMAC-SHA512 signature using the engine's primary HMAC secret.
    ///
    /// Comparison is performed in constant time via [`ConstantTimeEq`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    ///
    /// let engine = PaymobWebhookEngine::new("test_hmac_secret")?;
    /// let sig = "b0c960da53f0c16e9d7478563f3fd8063633f9fd9b009025f568aba9252542ac\
    ///            637c171bdee453b160d89b957f4ef93cd30814ddb147f4c1a1497443d150c68d";
    /// assert_eq!(engine.verify_concatenated_str("100020003000", sig), Ok(()));
    /// assert_eq!(
    ///     engine.verify_concatenated_str("tampered", sig),
    ///     Err(WebhookError::SignatureMismatch)
    /// );
    /// # Ok::<(), WebhookError>(())
    /// ```
    pub fn verify_concatenated_str(
        &self,
        concatenated: &str,
        signature_hex: &str,
    ) -> WebhookResult<()> {
        Self::verify_concatenated_with_secret(&self.hmac_secret, concatenated, signature_hex)
    }

    /// Verifies a pre-concatenated Paymob webhook string against a hex-encoded
    /// HMAC-SHA512 signature using an explicit [`SecretString`].
    ///
    /// Rejects empty or whitespace-only secrets with [`WebhookError::InvalidSecretKeyLength`],
    /// non-hex or non-64-byte signatures with [`WebhookError::MalformedSignatureHex`],
    /// and mismatched digests with [`WebhookError::SignatureMismatch`].
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secrecy::SecretString;
    /// use some_paymob::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    ///
    /// let secret = SecretString::from("payout_secret_key");
    /// let sig = "6fc165775a3b285e6058f68cadeafbec94978a28d6a29c3fd17b118fb527219c\
    ///            be11bf5d64dd38e2b04ad2bd15bcbd13fa24901b50abe7fc51ac54520812485a";
    /// assert_eq!(
    ///     PaymobWebhookEngine::verify_concatenated_with_secret(&secret, "payout_payload_123", sig),
    ///     Ok(())
    /// );
    /// # Ok::<(), WebhookError>(())
    /// ```
    pub fn verify_concatenated_with_secret(
        secret: &SecretString,
        concatenated: &str,
        signature_hex: &str,
    ) -> WebhookResult<()> {
        let trimmed_secret = validate_secret_non_empty(secret)?;
        let mut decoded = decode_sha512_hex(signature_hex)?;
        let mut mac = HmacSha512::new_from_slice(trimmed_secret.as_bytes())
            .map_err(|_| WebhookError::InvalidSecretKeyLength)?;
        mac.update(concatenated.as_bytes());
        let mut expected = mac.finalize().into_bytes();
        let matched = bool::from(expected.as_slice().ct_eq(&decoded));
        expected.as_mut_slice().zeroize();
        decoded.zeroize();
        if matched {
            Ok(())
        } else {
            Err(WebhookError::SignatureMismatch)
        }
    }
}

fn normalize_secret_string(secret: SecretString) -> WebhookResult<SecretString> {
    let trimmed = validate_secret_non_empty(&secret)?;
    Ok(SecretString::from(trimmed.to_owned()))
}

fn validate_secret_non_empty(secret: &SecretString) -> WebhookResult<&str> {
    let trimmed = secret.expose_secret().trim();
    if trimmed.is_empty() {
        return Err(WebhookError::InvalidSecretKeyLength);
    }
    Ok(trimmed)
}

fn decode_sha512_hex(signature_hex: &str) -> WebhookResult<[u8; SHA512_DIGEST_LEN]> {
    let trimmed = signature_hex.trim();
    if trimmed.len() != SHA512_DIGEST_LEN * 2 {
        return Err(WebhookError::MalformedSignatureHex);
    }
    let mut decoded = [0u8; SHA512_DIGEST_LEN];
    hex::decode_to_slice(trimmed, &mut decoded).map_err(|_| WebhookError::MalformedSignatureHex)?;
    Ok(decoded)
}

pub(crate) fn require_non_empty_query_hmac(query_hmac: Option<&str>) -> WebhookResult<&str> {
    query_hmac
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or(WebhookError::MissingQueryHmac)
}

pub(crate) fn parse_webhook_json_str<T: serde::de::DeserializeOwned>(
    raw_body: &str,
) -> WebhookResult<T> {
    serde_json::from_str(raw_body).map_err(|err| WebhookError::from_serde_error(&err))
}

#[allow(dead_code)]
pub(crate) fn parse_webhook_json_slice<T: serde::de::DeserializeOwned>(
    raw_bytes: &[u8],
) -> WebhookResult<T> {
    let raw_str = decode_webhook_utf8(raw_bytes)?;
    parse_webhook_json_str(raw_str)
}

pub(crate) fn decode_webhook_utf8(raw_bytes: &[u8]) -> WebhookResult<&str> {
    std::str::from_utf8(raw_bytes)
        .map_err(|_| WebhookError::InvalidJsonPayload("webhook body is not valid UTF-8".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const VEC_1_SECRET: &str = "test_hmac_secret";
    const VEC_1_PAYLOAD: &str = "100020003000";
    const VEC_1_SIG: &str = "b0c960da53f0c16e9d7478563f3fd8063633f9fd9b009025f568aba9252542ac637c171bdee453b160d89b957f4ef93cd30814ddb147f4c1a1497443d150c68d";

    const VEC_2_SECRET: &str = "payout_secret_key";
    const VEC_2_PAYLOAD: &str = "payout_payload_123";
    const VEC_2_SIG: &str = "6fc165775a3b285e6058f68cadeafbec94978a28d6a29c3fd17b118fb527219cbe11bf5d64dd38e2b04ad2bd15bcbd13fa24901b50abe7fc51ac54520812485a";

    const EMPTY_PAYLOAD_SIG: &str = "c22f4d78d2482f5f97a72f2f8f4bcf95bfa075e2510833f9e17baae34c7e13824335a4d32d27c1c87aafd630e9bf1fcf37ab24465f76ee49f0ef22a7b8a41996";

    #[test]
    fn new_rejects_empty_and_whitespace_secret() {
        assert_eq!(
            PaymobWebhookEngine::new("").unwrap_err(),
            WebhookError::InvalidSecretKeyLength
        );
        assert_eq!(
            PaymobWebhookEngine::new("   \t\n ").unwrap_err(),
            WebhookError::InvalidSecretKeyLength
        );
    }

    #[test]
    fn with_payouts_secret_handles_valid_and_empty_secrets() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid primary secret");
        assert!(engine.payouts_secret().is_none());
        assert_eq!(
            engine.clone().with_payouts_secret("  \t ").unwrap_err(),
            WebhookError::InvalidSecretKeyLength
        );
        let configured = engine
            .with_payouts_secret(VEC_2_SECRET)
            .expect("valid payouts secret");
        assert_eq!(
            configured.payouts_secret().map(ExposeSecret::expose_secret),
            Some(VEC_2_SECRET)
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let engine = PaymobWebhookEngine::new("super_secret_primary")
            .expect("valid primary secret")
            .with_payouts_secret("super_secret_payouts")
            .expect("valid payouts secret");
        let rendered = format!("{engine:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("super_secret_primary"));
        assert!(!rendered.contains("super_secret_payouts"));
    }

    #[test]
    fn verify_concatenated_str_positive_lowercase_uppercase_and_padded() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, VEC_1_SIG),
            Ok(())
        );
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &VEC_1_SIG.to_ascii_uppercase()),
            Ok(())
        );
        let padded = format!("  \t{VEC_1_SIG}\n ");
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &padded),
            Ok(())
        );
    }

    #[test]
    fn verify_concatenated_str_boundary_empty_and_multibyte_utf8() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        assert_eq!(
            engine.verify_concatenated_str("", EMPTY_PAYLOAD_SIG),
            Ok(())
        );

        let rocket_payload = "🚀".repeat(32);
        let mut mac = HmacSha512::new_from_slice(VEC_1_SECRET.as_bytes()).expect("valid key");
        mac.update(rocket_payload.as_bytes());
        let rocket_sig = hex::encode(mac.finalize().into_bytes());
        assert_eq!(
            engine.verify_concatenated_str(&rocket_payload, &rocket_sig),
            Ok(())
        );
    }

    #[test]
    fn verify_concatenated_with_secret_positive_and_empty_secret() {
        let secret = SecretString::from(VEC_2_SECRET);
        assert_eq!(
            PaymobWebhookEngine::verify_concatenated_with_secret(&secret, VEC_2_PAYLOAD, VEC_2_SIG),
            Ok(())
        );
        let empty = SecretString::from("   ");
        assert_eq!(
            PaymobWebhookEngine::verify_concatenated_with_secret(&empty, VEC_2_PAYLOAD, VEC_2_SIG),
            Err(WebhookError::InvalidSecretKeyLength)
        );
    }

    #[test]
    fn verify_rejects_malformed_and_boundary_length_hex() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        let non_hex = "z".repeat(128);
        let len_127 = "a".repeat(127);
        let len_129 = "a".repeat(129);
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &non_hex),
            Err(WebhookError::MalformedSignatureHex)
        );
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &len_127),
            Err(WebhookError::MalformedSignatureHex)
        );
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &len_129),
            Err(WebhookError::MalformedSignatureHex)
        );
    }

    #[test]
    fn verify_rejects_single_bit_flips_at_digest_boundaries() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        let base_bytes = hex::decode(VEC_1_SIG).expect("valid hex");
        for idx in [0_usize, 31, 63] {
            let mut flipped = base_bytes.clone();
            flipped[idx] ^= 0x01;
            let flipped_hex = hex::encode(flipped);
            assert_eq!(
                engine.verify_concatenated_str(VEC_1_PAYLOAD, &flipped_hex),
                Err(WebhookError::SignatureMismatch)
            );
        }
    }

    #[test]
    fn webhook_error_classification_and_http_status_codes() {
        let sig = WebhookError::SignatureMismatch;
        let bad = WebhookError::MissingRequiredField("id".into());
        let dup = WebhookError::DuplicateWebhookDelivery {
            idempotency_key: "1".into(),
            correlation_id: "2".into(),
        };
        let cfg = WebhookError::InvalidSecretKeyLength;

        assert_eq!(
            (sig.is_signature_error(), sig.suggested_http_status_code()),
            (true, 401)
        );
        assert_eq!(
            (bad.is_malformed_payload(), bad.suggested_http_status_code()),
            (true, 400)
        );
        assert_eq!(
            (
                dup.is_replay_or_duplicate(),
                dup.suggested_http_status_code()
            ),
            (true, 409)
        );
        assert_eq!(
            (
                cfg.is_configuration_error(),
                cfg.suggested_http_status_code()
            ),
            (true, 500)
        );
        assert!(cfg.is_retryable() && !sig.is_retryable());
    }

    #[test]
    fn from_serde_error_redacts_sensitive_quoted_literals() {
        let bad_json = r#""4111-2222-3333-4444""#;
        let serde_err = serde_json::from_str::<u64>(bad_json).unwrap_err();
        let webhook_err = WebhookError::from(serde_err);
        let msg = webhook_err.to_string();
        assert!(msg.contains("[REDACTED]"));
        assert!(!msg.contains("4111-2222-3333-4444"));
    }
}
