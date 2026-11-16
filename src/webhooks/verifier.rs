//! Core webhook error types and constant-time HMAC-SHA512 verification engine.
//!
//! Owned by Unit 7.1.1 (`feat/us-7.1.0/unit-1-webhook-error-and-core`).

use std::fmt;

use hmac::{Hmac, Mac};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha512;
use subtle::ConstantTimeEq;

type HmacSha512 = Hmac<Sha512>;

const SHA512_DIGEST_LEN: usize = 64;

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

    /// The `hmac` query parameter was missing from a GET redirect callback.
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
    /// Rejects empty secrets with [`WebhookError::InvalidSecretKeyLength`].
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
    pub fn new(hmac_secret: impl Into<SecretString>) -> Result<Self, WebhookError> {
        let secret = hmac_secret.into();
        if secret.expose_secret().is_empty() {
            return Err(WebhookError::InvalidSecretKeyLength);
        }
        Ok(Self {
            hmac_secret: secret,
            payouts_hmac_secret: None,
        })
    }

    /// Configures an optional Payouts HMAC secret for Protocol E callbacks.
    ///
    /// Rejects empty secrets with [`WebhookError::InvalidSecretKeyLength`].
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
    pub fn with_payouts_secret(
        mut self,
        secret: impl Into<SecretString>,
    ) -> Result<Self, WebhookError> {
        let secret = secret.into();
        if secret.expose_secret().is_empty() {
            return Err(WebhookError::InvalidSecretKeyLength);
        }
        self.payouts_hmac_secret = Some(secret);
        Ok(self)
    }

    /// Returns a reference to the configured Payouts HMAC secret, if present.
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
    ) -> Result<(), WebhookError> {
        Self::verify_concatenated_with_secret(&self.hmac_secret, concatenated, signature_hex)
    }

    /// Verifies a pre-concatenated Paymob webhook string against a hex-encoded
    /// HMAC-SHA512 signature using an explicit [`SecretString`].
    ///
    /// Rejects empty secrets with [`WebhookError::InvalidSecretKeyLength`],
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
    ) -> Result<(), WebhookError> {
        if secret.expose_secret().is_empty() {
            return Err(WebhookError::InvalidSecretKeyLength);
        }
        let decoded = decode_sha512_hex(signature_hex)?;
        let mut mac = HmacSha512::new_from_slice(secret.expose_secret().as_bytes())
            .map_err(|_| WebhookError::InvalidSecretKeyLength)?;
        mac.update(concatenated.as_bytes());
        let expected = mac.finalize().into_bytes();
        if bool::from(expected.as_slice().ct_eq(&decoded)) {
            Ok(())
        } else {
            Err(WebhookError::SignatureMismatch)
        }
    }
}

fn decode_sha512_hex(signature_hex: &str) -> Result<[u8; SHA512_DIGEST_LEN], WebhookError> {
    let decoded = hex::decode(signature_hex).map_err(|_| WebhookError::MalformedSignatureHex)?;
    decoded
        .try_into()
        .map_err(|_| WebhookError::MalformedSignatureHex)
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
    fn new_rejects_empty_secret() {
        assert_eq!(
            PaymobWebhookEngine::new("").unwrap_err(),
            WebhookError::InvalidSecretKeyLength
        );
    }

    #[test]
    fn with_payouts_secret_handles_valid_and_empty_secrets() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid primary secret");
        assert!(engine.payouts_secret().is_none());

        let err = engine
            .clone()
            .with_payouts_secret("")
            .expect_err("empty payouts secret must fail");
        assert_eq!(err, WebhookError::InvalidSecretKeyLength);

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
    fn verify_concatenated_str_positive_lowercase_and_uppercase() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, VEC_1_SIG),
            Ok(())
        );
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &VEC_1_SIG.to_ascii_uppercase()),
            Ok(())
        );
    }

    #[test]
    fn verify_concatenated_str_boundary_empty_payload() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        assert_eq!(engine.verify_concatenated_str("", EMPTY_PAYLOAD_SIG), Ok(()));
    }

    #[test]
    fn verify_concatenated_with_secret_positive_and_empty_secret() {
        let secret = SecretString::from(VEC_2_SECRET);
        assert_eq!(
            PaymobWebhookEngine::verify_concatenated_with_secret(&secret, VEC_2_PAYLOAD, VEC_2_SIG),
            Ok(())
        );

        let empty = SecretString::from("");
        assert_eq!(
            PaymobWebhookEngine::verify_concatenated_with_secret(&empty, VEC_2_PAYLOAD, VEC_2_SIG),
            Err(WebhookError::InvalidSecretKeyLength)
        );
    }

    #[test]
    fn verify_rejects_malformed_hex() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        let non_hex = "z".repeat(128);
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &non_hex),
            Err(WebhookError::MalformedSignatureHex)
        );
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, "abc"),
            Err(WebhookError::MalformedSignatureHex)
        );
    }

    #[test]
    fn verify_rejects_wrong_length_hex() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        let too_short = "aa".repeat(63);
        let too_long = "aa".repeat(65);
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &too_short),
            Err(WebhookError::MalformedSignatureHex)
        );
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &too_long),
            Err(WebhookError::MalformedSignatureHex)
        );
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, ""),
            Err(WebhookError::MalformedSignatureHex)
        );
    }

    #[test]
    fn verify_rejects_tampered_payload_and_wrong_signature() {
        let engine = PaymobWebhookEngine::new(VEC_1_SECRET).expect("valid secret");
        assert_eq!(
            engine.verify_concatenated_str("100020003001", VEC_1_SIG),
            Err(WebhookError::SignatureMismatch)
        );

        let mut altered = VEC_1_SIG.to_string();
        altered.pop();
        altered.push('0');
        assert_eq!(
            engine.verify_concatenated_str(VEC_1_PAYLOAD, &altered),
            Err(WebhookError::SignatureMismatch)
        );
    }

    #[test]
    fn error_variants_display_cleanly() {
        let missing = WebhookError::MissingRequiredField("obj.id".to_string());
        let invalid = WebhookError::InvalidJsonPayload("eof".to_string());
        assert!(missing.to_string().contains("obj.id"));
        assert!(invalid.to_string().contains("eof"));
        assert!(!WebhookError::MissingQueryHmac.to_string().is_empty());
        assert!(!WebhookError::MissingBodyHmac.to_string().is_empty());
    }
}
