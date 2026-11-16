#![forbid(unsafe_code)]
//! Polymorphic payment source types for headless Paymob payments (`US-4.1.0`, Unit 1).
//!
//! Defines [`PaymentSource`](self::PaymentSource) for Paymob's `POST /api/acceptance/payments/pay`
//! endpoint, supporting saved card tokens (`TOKEN`), mobile wallets (`WALLET`),
//! and offline kiosk aggregators (`AGGREGATOR`) with automatic `[REDACTED]`
//! [`Debug`](std::fmt::Debug) formatting and builder-time validation.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};

use crate::core::error::PaymobError;

/// Canonical identifier required by Paymob's Kiosk aggregator payment source.
const KIOSK_AGGREGATOR_IDENTIFIER: &str = "AGGREGATOR";

/// Redacted placeholder emitted for all secrets and PII in [`fmt::Debug`].
const REDACTED: &str = "[REDACTED]";

/// Polymorphic payment source for headless Paymob payment execution.
///
/// Serializes with an internal `"subtype"` tag (`"TOKEN"`, `"WALLET"`, or
/// `"AGGREGATOR"`) matching Paymob's `POST /api/acceptance/payments/pay` schema.
///
/// All secret credentials (`identifier` token, optional `cvn`) and customer
/// phone numbers (`MobileWallet::identifier`) emit `"[REDACTED]"` in
/// [`fmt::Debug`] output.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::saved_cards::sources::PaymentSource;
///
/// let token = PaymentSource::saved_token("tok_3f22ce8a")?;
/// assert_eq!(token.subtype(), "TOKEN");
/// assert!(!format!("{token:?}").contains("tok_3f22ce8a"));
///
/// let wallet = PaymentSource::mobile_wallet("01012345678")?;
/// assert_eq!(wallet.subtype(), "WALLET");
/// assert!(!format!("{wallet:?}").contains("01012345678"));
///
/// let kiosk = PaymentSource::kiosk_aggregator();
/// assert_eq!(kiosk.subtype(), "AGGREGATOR");
/// # Ok::<(), some_paymob::PaymobError>(())
/// ```
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "subtype")]
pub enum PaymentSource {
    /// Off-session or CIT/MIT tokenized card payment source (`subtype: "TOKEN"`).
    #[serde(rename = "TOKEN")]
    SavedToken {
        /// Tokenized card identifier issued by Paymob (`SecretString`, redacted in `Debug`).
        #[serde(serialize_with = "serialize_secret")]
        identifier: SecretString,
        /// Optional 3- or 4-digit card verification number (`SecretString`, redacted in `Debug`).
        #[serde(
            default,
            skip_serializing_if = "Option::is_none",
            serialize_with = "serialize_opt_secret"
        )]
        cvn: Option<SecretString>,
    },
    /// Direct mobile wallet payment source such as Vodafone Cash (`subtype: "WALLET"`).
    #[serde(rename = "WALLET")]
    MobileWallet {
        /// Customer wallet phone number / MSISDN (redacted in `Debug`).
        identifier: String,
    },
    /// Offline kiosk cash payment aggregator source (`subtype: "AGGREGATOR"`).
    #[serde(rename = "AGGREGATOR")]
    KioskAggregator {
        /// Aggregator identifier (always `"AGGREGATOR"`).
        identifier: String,
    },
}

impl PaymentSource {
    /// Creates a validated [`PaymentSource::SavedToken`] without a CVN.
    ///
    /// Returns [`PaymobError::ValidationError`] if `identifier` is empty or whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::resources::saved_cards::sources::PaymentSource;
    ///
    /// let source = PaymentSource::saved_token("tok_live_abc123")?;
    /// assert_eq!(source.subtype(), "TOKEN");
    /// # Ok::<(), some_paymob::PaymobError>(())
    /// ```
    pub fn saved_token(identifier: impl Into<SecretString>) -> Result<Self, PaymobError> {
        let secret = identifier.into();
        validate_token(secret.expose_secret())?;
        Ok(Self::SavedToken {
            identifier: secret,
            cvn: None,
        })
    }

    /// Creates a validated [`PaymentSource::SavedToken`] with an explicit CVN.
    ///
    /// Returns [`PaymobError::ValidationError`] if `identifier` is empty or if `cvn`
    /// is not 3 or 4 ASCII digits.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::resources::saved_cards::sources::PaymentSource;
    ///
    /// let source = PaymentSource::saved_token_with_cvn("tok_live_abc123", "123")?;
    /// assert_eq!(source.subtype(), "TOKEN");
    /// # Ok::<(), some_paymob::PaymobError>(())
    /// ```
    pub fn saved_token_with_cvn(
        identifier: impl Into<SecretString>,
        cvn: impl Into<SecretString>,
    ) -> Result<Self, PaymobError> {
        let token_secret = identifier.into();
        let cvn_secret = cvn.into();
        validate_token(token_secret.expose_secret())?;
        validate_cvn(cvn_secret.expose_secret())?;
        Ok(Self::SavedToken {
            identifier: token_secret,
            cvn: Some(cvn_secret),
        })
    }

    /// Creates a validated [`PaymentSource::MobileWallet`] for a wallet MSISDN.
    ///
    /// Accepts 7 to 15 ASCII digits, with an optional leading `'+'`.
    /// Returns [`PaymobError::ValidationError`] on empty or malformed numbers.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::resources::saved_cards::sources::PaymentSource;
    ///
    /// let source = PaymentSource::mobile_wallet("01012345678")?;
    /// assert_eq!(source.subtype(), "WALLET");
    /// # Ok::<(), some_paymob::PaymobError>(())
    /// ```
    pub fn mobile_wallet(identifier: impl Into<String>) -> Result<Self, PaymobError> {
        let phone = identifier.into();
        validate_wallet_identifier(&phone)?;
        Ok(Self::MobileWallet { identifier: phone })
    }

    /// Creates a [`PaymentSource::KioskAggregator`] with `"AGGREGATOR"` identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::resources::saved_cards::sources::PaymentSource;
    ///
    /// let source = PaymentSource::kiosk_aggregator();
    /// assert_eq!(source.subtype(), "AGGREGATOR");
    /// ```
    #[must_use]
    pub fn kiosk_aggregator() -> Self {
        Self::KioskAggregator {
            identifier: KIOSK_AGGREGATOR_IDENTIFIER.to_owned(),
        }
    }

    /// Returns the Paymob wire `"subtype"` discriminant (`"TOKEN"`, `"WALLET"`, or `"AGGREGATOR"`).
    #[must_use]
    pub const fn subtype(&self) -> &'static str {
        match self {
            Self::SavedToken { .. } => "TOKEN",
            Self::MobileWallet { .. } => "WALLET",
            Self::KioskAggregator { .. } => KIOSK_AGGREGATOR_IDENTIFIER,
        }
    }

    /// Validates the payment source invariants for the current variant.
    ///
    /// Useful when a caller constructs a [`PaymentSource`] directly via struct
    /// literals or deserialization and wants to verify invariants before dispatch.
    pub fn validate(&self) -> Result<(), PaymobError> {
        match self {
            Self::SavedToken { identifier, cvn } => {
                validate_token(identifier.expose_secret())?;
                if let Some(code) = cvn {
                    validate_cvn(code.expose_secret())?;
                }
                Ok(())
            }
            Self::MobileWallet { identifier } => validate_wallet_identifier(identifier),
            Self::KioskAggregator { identifier } => validate_kiosk_identifier(identifier),
        }
    }
}

impl fmt::Debug for PaymentSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SavedToken { cvn, .. } => {
                let cvn_display: Option<&str> = cvn.as_ref().map(|_| REDACTED);
                f.debug_struct("SavedToken")
                    .field("subtype", &"TOKEN")
                    .field("identifier", &REDACTED)
                    .field("cvn", &cvn_display)
                    .finish()
            }
            Self::MobileWallet { .. } => f
                .debug_struct("MobileWallet")
                .field("subtype", &"WALLET")
                .field("identifier", &REDACTED)
                .finish(),
            Self::KioskAggregator { identifier } => f
                .debug_struct("KioskAggregator")
                .field("subtype", &KIOSK_AGGREGATOR_IDENTIFIER)
                .field("identifier", identifier)
                .finish(),
        }
    }
}

fn validate_token(token: &str) -> Result<(), PaymobError> {
    if token.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field: "identifier",
            reason: "saved card token identifier must not be empty".to_owned(),
        });
    }
    Ok(())
}

fn validate_cvn(cvn: &str) -> Result<(), PaymobError> {
    let valid_len = cvn.len() == 3 || cvn.len() == 4;
    if !valid_len || !cvn.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaymobError::ValidationError {
            field: "cvn",
            reason: "CVN must be 3 or 4 ASCII digits".to_owned(),
        });
    }
    Ok(())
}

fn validate_wallet_identifier(identifier: &str) -> Result<(), PaymobError> {
    let digits = identifier.strip_prefix('+').unwrap_or(identifier);
    let valid_len = (7..=15).contains(&digits.len());
    if !valid_len || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaymobError::ValidationError {
            field: "identifier",
            reason: "mobile wallet identifier must be 7 to 15 ASCII digits (optional leading '+')"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_kiosk_identifier(identifier: &str) -> Result<(), PaymobError> {
    if identifier != KIOSK_AGGREGATOR_IDENTIFIER {
        return Err(PaymobError::ValidationError {
            field: "identifier",
            reason: "kiosk aggregator identifier must be \"AGGREGATOR\"".to_owned(),
        });
    }
    Ok(())
}

fn serialize_secret<S: Serializer>(
    secret: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose_secret())
}

fn serialize_opt_secret<S: Serializer>(
    secret: &Option<SecretString>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match secret {
        Some(value) => serializer.serialize_str(value.expose_secret()),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tc_4_1_1_saved_token_serializes_and_redacts_debug() {
        let source = PaymentSource::saved_token("3f22ce8a-token-secret").expect("valid token");
        assert_eq!(source.subtype(), "TOKEN");
        assert!(source.validate().is_ok());

        let json_val = serde_json::to_value(&source).expect("serialize saved token");
        assert_eq!(
            json_val,
            json!({
                "subtype": "TOKEN",
                "identifier": "3f22ce8a-token-secret"
            })
        );

        let dbg = format!("{source:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("3f22ce8a-token-secret"));
    }

    #[test]
    fn tc_4_1_1_saved_token_with_cvn_serializes_and_redacts_debug() {
        let source =
            PaymentSource::saved_token_with_cvn("tok_secret_99", "0429").expect("valid token+cvn");
        let json_val = serde_json::to_value(&source).expect("serialize saved token with cvn");
        assert_eq!(
            json_val,
            json!({
                "subtype": "TOKEN",
                "identifier": "tok_secret_99",
                "cvn": "0429"
            })
        );

        let dbg = format!("{source:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("tok_secret_99"));
        assert!(!dbg.contains("0429"));
    }

    #[test]
    fn tc_4_1_1_mobile_wallet_serializes_and_redacts_debug() {
        let source = PaymentSource::mobile_wallet("01012345678").expect("valid wallet");
        assert_eq!(source.subtype(), "WALLET");
        assert!(source.validate().is_ok());

        let json_val = serde_json::to_value(&source).expect("serialize wallet");
        assert_eq!(
            json_val,
            json!({
                "subtype": "WALLET",
                "identifier": "01012345678"
            })
        );

        let dbg = format!("{source:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("01012345678"));

        let intl = PaymentSource::mobile_wallet("+201012345678").expect("valid intl wallet");
        assert!(intl.validate().is_ok());
    }

    #[test]
    fn tc_4_1_1_kiosk_aggregator_serializes_and_validates() {
        let source = PaymentSource::kiosk_aggregator();
        assert_eq!(source.subtype(), "AGGREGATOR");
        assert!(source.validate().is_ok());

        let json_val = serde_json::to_value(&source).expect("serialize kiosk");
        assert_eq!(
            json_val,
            json!({
                "subtype": "AGGREGATOR",
                "identifier": "AGGREGATOR"
            })
        );

        let dbg = format!("{source:?}");
        assert!(dbg.contains("AGGREGATOR"));
    }

    #[test]
    fn tc_4_1_1_rejects_empty_and_malformed_inputs() {
        assert!(matches!(
            PaymentSource::saved_token("   "),
            Err(PaymobError::ValidationError {
                field: "identifier",
                ..
            })
        ));
        assert!(matches!(
            PaymentSource::saved_token_with_cvn("tok_1", "12"),
            Err(PaymobError::ValidationError { field: "cvn", .. })
        ));
        assert!(matches!(
            PaymentSource::saved_token_with_cvn("tok_1", "12345"),
            Err(PaymobError::ValidationError { field: "cvn", .. })
        ));
        assert!(matches!(
            PaymentSource::saved_token_with_cvn("tok_1", "12a"),
            Err(PaymobError::ValidationError { field: "cvn", .. })
        ));
        assert!(matches!(
            PaymentSource::mobile_wallet("123"),
            Err(PaymobError::ValidationError {
                field: "identifier",
                ..
            })
        ));
        assert!(matches!(
            PaymentSource::mobile_wallet("0101234abcd"),
            Err(PaymobError::ValidationError {
                field: "identifier",
                ..
            })
        ));

        let bad_kiosk = PaymentSource::KioskAggregator {
            identifier: "INVALID".to_owned(),
        };
        assert!(matches!(
            bad_kiosk.validate(),
            Err(PaymobError::ValidationError {
                field: "identifier",
                ..
            })
        ));
    }

    #[test]
    fn tc_4_1_1_roundtrip_deserialize_and_validate() {
        let raw = r#"{"subtype":"WALLET","identifier":"01099887766"}"#;
        let parsed: PaymentSource = serde_json::from_str(raw).expect("deserialize wallet");
        assert_eq!(parsed.subtype(), "WALLET");
        assert!(parsed.validate().is_ok());
    }
}
