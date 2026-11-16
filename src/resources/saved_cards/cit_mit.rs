#![forbid(unsafe_code)]
//! CIT saved-card token configuration, MIT charge parameters, and MOTO CVC guard (`US-4.1.0`).
//!
//! Implements Unit 4.1.2 (`TC-4.1.2`):
//! - [`CitCardTokenConfig`] for wiring saved card tokens into Intention `card_tokens`.
//! - [`MitChargeParams`] for off-session Merchant-Initiated Transaction (MIT) / MOTO charges.
//! - [`validate_use_cvc_with_moto`] for enforcing PCI-DSS CVN presence/minimization rules.
//!
//! All secret-bearing fields (`payment_token`, `saved_token`, `cvn`, `card_tokens`) wrap
//! [`secrecy::SecretString`] and emit `"[REDACTED]"` in [`fmt::Debug`] output.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use crate::core::error::PaymobError;

const REDACTED: &str = "[REDACTED]";

/// Configuration wiring Customer-Initiated Transaction (CIT) saved card tokens
/// into `CreateIntentionParams::card_tokens`.
///
/// Wraps each saved card token in [`SecretString`] and redacts all token values
/// in [`fmt::Debug`] output.
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::resources::saved_cards::cit_mit::CitCardTokenConfig;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = CitCardTokenConfig::from_single(SecretString::from("3f22ce8a_saved_tok"))?;
/// assert_eq!(config.len(), 1);
/// assert!(!config.is_empty());
/// assert_eq!(config.to_wire_tokens(), vec!["3f22ce8a_saved_tok".to_owned()]);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct CitCardTokenConfig {
    card_tokens: Vec<SecretString>,
}

impl CitCardTokenConfig {
    /// Creates a new [`CitCardTokenConfig`] from a non-empty list of saved card tokens.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on `"card_tokens"` if `card_tokens` is empty
    /// or if any token is empty or contains whitespace/control characters.
    pub fn new(card_tokens: Vec<SecretString>) -> Result<Self, PaymobError> {
        if card_tokens.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "card_tokens",
                reason: "card_tokens must contain at least one saved card token".to_owned(),
            });
        }
        for token in &card_tokens {
            validate_token(token.expose_secret(), "card_tokens")?;
        }
        Ok(Self { card_tokens })
    }

    /// Creates a [`CitCardTokenConfig`] containing a single validated saved card token.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on `"card_tokens"` if `token` is empty
    /// or contains whitespace/control characters.
    pub fn from_single(token: SecretString) -> Result<Self, PaymobError> {
        Self::new(vec![token])
    }

    /// Appends another validated saved card token to this configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on `"card_tokens"` if `token` is empty
    /// or contains whitespace/control characters.
    pub fn add_token(&mut self, token: SecretString) -> Result<(), PaymobError> {
        validate_token(token.expose_secret(), "card_tokens")?;
        self.card_tokens.push(token);
        Ok(())
    }

    /// Returns a slice of the configured saved card tokens.
    #[must_use]
    pub fn card_tokens(&self) -> &[SecretString] {
        &self.card_tokens
    }

    /// Returns the number of configured saved card tokens.
    #[must_use]
    pub fn len(&self) -> usize {
        self.card_tokens.len()
    }

    /// Returns `true` if no saved card tokens are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.card_tokens.is_empty()
    }

    /// Exports the saved card tokens as plain strings for wiring into
    /// `CreateIntentionParams::card_tokens` at serialization time.
    #[must_use]
    pub fn to_wire_tokens(&self) -> Vec<String> {
        self.card_tokens
            .iter()
            .map(|t| t.expose_secret().to_owned())
            .collect()
    }
}

impl fmt::Debug for CitCardTokenConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CitCardTokenConfig")
            .field("card_tokens_count", &self.card_tokens.len())
            .field("card_tokens", &REDACTED)
            .finish()
    }
}

impl Serialize for CitCardTokenConfig {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut state = serializer.serialize_struct("CitCardTokenConfig", 1)?;
        let wire_tokens = self.to_wire_tokens();
        state.serialize_field("card_tokens", &wire_tokens)?;
        state.end()
    }
}

/// Parameters for executing an off-session Merchant-Initiated Transaction (MIT)
/// or MOTO saved-card charge via `POST /api/acceptance/payments/pay`.
///
/// All secret-bearing fields (`payment_token`, `saved_token`, and optional `cvn`)
/// are stored in [`SecretString`] and redacted to `"[REDACTED]"` in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::resources::saved_cards::cit_mit::MitChargeParams;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mit = MitChargeParams::new(
///     SecretString::from("pay_tok_abc123"),
///     SecretString::from("saved_tok_xyz789"),
/// )?;
/// assert!(!mit.is_use_cvc_with_moto());
/// assert!(mit.cvn().is_none());
///
/// let moto = MitChargeParams::with_moto_cvc(
///     SecretString::from("pay_tok_abc123"),
///     SecretString::from("saved_tok_xyz789"),
///     SecretString::from("412"),
/// )?;
/// assert!(moto.is_use_cvc_with_moto());
/// assert!(moto.cvn().is_some());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct MitChargeParams {
    payment_token: SecretString,
    saved_token: SecretString,
    cvn: Option<SecretString>,
    use_cvc_with_moto: bool,
}

impl MitChargeParams {
    /// Creates standard off-session MIT charge parameters without CVC (`use_cvc_with_moto = false`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `payment_token` or `saved_token`
    /// is empty or contains whitespace/control characters.
    pub fn new(
        payment_token: SecretString,
        saved_token: SecretString,
    ) -> Result<Self, PaymobError> {
        validate_token(payment_token.expose_secret(), "payment_token")?;
        validate_token(saved_token.expose_secret(), "saved_token")?;
        Ok(Self {
            payment_token,
            saved_token,
            cvn: None,
            use_cvc_with_moto: false,
        })
    }

    /// Creates MOTO saved-card charge parameters with CVC enabled (`use_cvc_with_moto = true`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `payment_token` or `saved_token`
    /// is invalid, or if `cvn` fails [`validate_use_cvc_with_moto`] (must be 3 or 4 ASCII digits).
    pub fn with_moto_cvc(
        payment_token: SecretString,
        saved_token: SecretString,
        cvn: SecretString,
    ) -> Result<Self, PaymobError> {
        validate_token(payment_token.expose_secret(), "payment_token")?;
        validate_token(saved_token.expose_secret(), "saved_token")?;
        validate_use_cvc_with_moto(true, Some(&cvn))?;
        Ok(Self {
            payment_token,
            saved_token,
            cvn: Some(cvn),
            use_cvc_with_moto: true,
        })
    }

    /// Validates all fields and the `use_cvc_with_moto` invariant on this instance.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any token or CVN rule is violated.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_token(self.payment_token.expose_secret(), "payment_token")?;
        validate_token(self.saved_token.expose_secret(), "saved_token")?;
        validate_use_cvc_with_moto(self.use_cvc_with_moto, self.cvn.as_ref())
    }

    /// Returns the Intention `payment_token` credential.
    #[must_use]
    pub fn payment_token(&self) -> &SecretString {
        &self.payment_token
    }

    /// Returns the tokenized saved-card identifier.
    #[must_use]
    pub fn saved_token(&self) -> &SecretString {
        &self.saved_token
    }

    /// Returns the optional MOTO card verification number (`cvn`).
    #[must_use]
    pub fn cvn(&self) -> Option<&SecretString> {
        self.cvn.as_ref()
    }

    /// Returns `true` if `use_cvc_with_moto` is enabled for this charge.
    #[must_use]
    pub const fn is_use_cvc_with_moto(&self) -> bool {
        self.use_cvc_with_moto
    }
}

impl fmt::Debug for MitChargeParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitChargeParams")
            .field("payment_token", &REDACTED)
            .field("saved_token", &REDACTED)
            .field("cvn", &self.cvn.as_ref().map(|_| REDACTED))
            .field("use_cvc_with_moto", &self.use_cvc_with_moto)
            .finish()
    }
}

impl Serialize for MitChargeParams {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = if self.cvn.is_some() { 4 } else { 3 };
        let mut state = serializer.serialize_struct("MitChargeParams", field_count)?;
        state.serialize_field("payment_token", self.payment_token.expose_secret())?;
        state.serialize_field("saved_token", self.saved_token.expose_secret())?;
        if let Some(cvn) = &self.cvn {
            state.serialize_field("cvn", cvn.expose_secret())?;
        }
        state.serialize_field("use_cvc_with_moto", &self.use_cvc_with_moto)?;
        state.end()
    }
}

/// Validation guard enforcing consistency between `use_cvc_with_moto` and `cvn`.
///
/// Rules:
/// - When `use_cvc_with_moto` is `true`, `cvn` must be `Some` and contain 3 or 4 ASCII digits.
/// - When `use_cvc_with_moto` is `false`, `cvn` must be `None` (PCI-DSS CVN minimization).
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] on `"cvn"` if the combination or CVN format is invalid.
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::resources::saved_cards::cit_mit::validate_use_cvc_with_moto;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// validate_use_cvc_with_moto(false, None)?;
/// let cvn = SecretString::from("123");
/// validate_use_cvc_with_moto(true, Some(&cvn))?;
/// assert!(validate_use_cvc_with_moto(true, None).is_err());
/// assert!(validate_use_cvc_with_moto(false, Some(&cvn)).is_err());
/// # Ok(())
/// # }
/// ```
pub fn validate_use_cvc_with_moto(
    use_cvc_with_moto: bool,
    cvn: Option<&SecretString>,
) -> Result<(), PaymobError> {
    match (use_cvc_with_moto, cvn) {
        (true, Some(code)) => validate_cvn_digits(code.expose_secret()),
        (true, None) => Err(PaymobError::ValidationError {
            field: "cvn",
            reason: "cvn is required when use_cvc_with_moto is true".to_owned(),
        }),
        (false, Some(_)) => Err(PaymobError::ValidationError {
            field: "cvn",
            reason: "cvn must not be provided when use_cvc_with_moto is false".to_owned(),
        }),
        (false, None) => Ok(()),
    }
}

fn validate_token(value: &str, field: &'static str) -> Result<(), PaymobError> {
    if value.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: "token must not be empty".to_owned(),
        });
    }
    if value.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(PaymobError::ValidationError {
            field,
            reason: "token must not contain whitespace or control characters".to_owned(),
        });
    }
    Ok(())
}

fn validate_cvn_digits(cvn: &str) -> Result<(), PaymobError> {
    let len = cvn.len();
    if !(3..=4).contains(&len) || !cvn.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaymobError::ValidationError {
            field: "cvn",
            reason: "cvn must be 3 or 4 ASCII digits".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_4_1_2_cit_card_token_config_valid_and_wire_export() {
        let mut cfg = CitCardTokenConfig::from_single(SecretString::from("tok_alpha"))
            .expect("single token should be valid");
        cfg.add_token(SecretString::from("tok_beta"))
            .expect("second token should be valid");
        assert_eq!(cfg.len(), 2);
        assert!(!cfg.is_empty());
        assert_eq!(cfg.card_tokens().len(), 2);
        assert_eq!(
            cfg.to_wire_tokens(),
            vec!["tok_alpha".to_owned(), "tok_beta".to_owned()]
        );

        let value = serde_json::to_value(&cfg).expect("serialize CitCardTokenConfig");
        assert_eq!(
            value,
            serde_json::json!({ "card_tokens": ["tok_alpha", "tok_beta"] })
        );
    }

    #[test]
    fn tc_4_1_2_cit_card_token_config_rejects_empty_and_malformed_tokens() {
        assert!(matches!(
            CitCardTokenConfig::new(vec![]),
            Err(PaymobError::ValidationError {
                field: "card_tokens",
                ..
            })
        ));
        let with_newline = format!("tok{}newline", char::from(10));
        let with_nul = format!("tok{}nul", char::from(0));
        for bad in [
            "",
            "   ",
            "tok with space",
            with_newline.as_str(),
            with_nul.as_str(),
        ] {
            let res = CitCardTokenConfig::from_single(SecretString::from(bad));
            assert!(
                matches!(
                    res,
                    Err(PaymobError::ValidationError {
                        field: "card_tokens",
                        ..
                    })
                ),
                "expected ValidationError for {bad:?}"
            );
        }
    }

    #[test]
    fn tc_4_1_2_mit_charge_params_standard_and_moto_cvc() {
        let mit = MitChargeParams::new(
            SecretString::from("pay_tok_123"),
            SecretString::from("saved_tok_456"),
        )
        .expect("standard MIT params should be valid");
        assert!(!mit.is_use_cvc_with_moto());
        assert!(mit.cvn().is_none());
        assert_eq!(mit.payment_token().expose_secret(), "pay_tok_123");
        assert_eq!(mit.saved_token().expose_secret(), "saved_tok_456");
        mit.validate().expect("validate standard MIT params");

        let moto_3 = MitChargeParams::with_moto_cvc(
            SecretString::from("pay_tok_123"),
            SecretString::from("saved_tok_456"),
            SecretString::from("123"),
        )
        .expect("3-digit MOTO CVN should be valid");
        assert!(moto_3.is_use_cvc_with_moto());
        assert_eq!(moto_3.cvn().expect("cvn present").expose_secret(), "123");
        moto_3.validate().expect("validate MOTO 3-digit params");

        let moto_4 = MitChargeParams::with_moto_cvc(
            SecretString::from("pay_tok_123"),
            SecretString::from("saved_tok_456"),
            SecretString::from("1234"),
        )
        .expect("4-digit MOTO CVN should be valid");
        assert_eq!(moto_4.cvn().expect("cvn present").expose_secret(), "1234");
    }

    #[test]
    fn tc_4_1_2_mit_charge_params_rejects_invalid_tokens() {
        assert!(matches!(
            MitChargeParams::new(SecretString::from(""), SecretString::from("saved_tok_456"),),
            Err(PaymobError::ValidationError {
                field: "payment_token",
                ..
            })
        ));
        assert!(matches!(
            MitChargeParams::new(
                SecretString::from("pay_tok_123"),
                SecretString::from("saved tok"),
            ),
            Err(PaymobError::ValidationError {
                field: "saved_token",
                ..
            })
        ));
    }

    #[test]
    fn tc_4_1_2_use_cvc_with_moto_guard_matrix() {
        let valid_3 = SecretString::from("789");
        let valid_4 = SecretString::from("7890");
        assert!(validate_use_cvc_with_moto(false, None).is_ok());
        assert!(validate_use_cvc_with_moto(true, Some(&valid_3)).is_ok());
        assert!(validate_use_cvc_with_moto(true, Some(&valid_4)).is_ok());

        assert!(matches!(
            validate_use_cvc_with_moto(true, None),
            Err(PaymobError::ValidationError { field: "cvn", .. })
        ));
        assert!(matches!(
            validate_use_cvc_with_moto(false, Some(&valid_3)),
            Err(PaymobError::ValidationError { field: "cvn", .. })
        ));

        for bad_cvn in ["", "12", "12345", "12a", " 12"] {
            let secret = SecretString::from(bad_cvn);
            assert!(
                matches!(
                    validate_use_cvc_with_moto(true, Some(&secret)),
                    Err(PaymobError::ValidationError { field: "cvn", .. })
                ),
                "expected ValidationError for cvn {bad_cvn:?}"
            );
        }
    }

    #[test]
    fn tc_4_1_2_debug_output_redacts_all_secrets() {
        let cfg = CitCardTokenConfig::from_single(SecretString::from("super_secret_card_tok"))
            .expect("valid config");
        let cfg_dbg = format!("{cfg:?}");
        assert!(cfg_dbg.contains("[REDACTED]"));
        assert!(!cfg_dbg.contains("super_secret_card_tok"));

        let moto = MitChargeParams::with_moto_cvc(
            SecretString::from("secret_pay_tok_999"),
            SecretString::from("secret_saved_tok_888"),
            SecretString::from("987"),
        )
        .expect("valid MOTO params");
        let moto_dbg = format!("{moto:?}");
        assert!(moto_dbg.contains("[REDACTED]"));
        assert!(!moto_dbg.contains("secret_pay_tok_999"));
        assert!(!moto_dbg.contains("secret_saved_tok_888"));
        assert!(!moto_dbg.contains("987"));
    }
}
