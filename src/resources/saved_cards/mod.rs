#![forbid(unsafe_code)]
//! Saved-card tokenization (CIT/MIT) and headless payment execution (`US-4.1.0`).
//!
//! Pre-scaffolded module index for `feat/module-4-saved-cards-subscriptions`.

/// Unit 4.1.2: CIT token config, MIT charge params, and `use_cvc_with_moto` validation guard.
pub mod cit_mit;
/// Unit 4.1.3: [`SavedCardsService`] executing `POST /api/acceptance/payments/pay`.
pub mod service;
/// Unit 4.1.1: Polymorphic `PaymentSource` enum with `[REDACTED]` formatting.
pub mod sources;

pub use cit_mit::{CitCardTokenConfig, MitChargeParams, validate_use_cvc_with_moto};
pub use service::{
    ACCEPT_PAY_PATH, HeadlessPayResponse, HeadlessTransaction, KioskPayParams, MitPayParams,
    RawPayParams, SavedCardsService, WalletPayParams,
};
pub use sources::PaymentSource;

use secrecy::{ExposeSecret, SecretString};
use serde_json::{Map, Value};
use zeroize::Zeroize;

use crate::core::error::PaymobError;

pub(crate) fn validate_token_str(field: &'static str, value: &str) -> Result<(), PaymobError> {
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

pub(crate) fn validate_runtime_token(
    field: &'static str,
    token: SecretString,
) -> Result<SecretString, PaymobError> {
    validate_token_str(field, token.expose_secret())?;
    Ok(token)
}

pub(crate) fn validate_cvn_str(cvn: &str) -> Result<(), PaymobError> {
    let len = cvn.len();
    if !(3..=4).contains(&len) || !cvn.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaymobError::ValidationError {
            field: "cvn",
            reason: "cvn must be 3 or 4 ASCII digits".to_owned(),
        });
    }
    Ok(())
}

pub(crate) fn validate_cvn_secret(cvn: SecretString) -> Result<SecretString, PaymobError> {
    validate_cvn_str(cvn.expose_secret())?;
    Ok(cvn)
}

pub(crate) fn validate_wallet_msisdn(field: &'static str, value: &str) -> Result<(), PaymobError> {
    let digits = value.strip_prefix('+').unwrap_or(value);
    if !(7..=15).contains(&digits.len()) || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must be 7 to 15 ASCII digits with optional leading '+'"),
        });
    }
    Ok(())
}

pub(crate) fn zeroize_json_value(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => {
            items.iter_mut().for_each(zeroize_json_value);
            items.clear();
        }
        Value::Object(map) => zeroize_json_map(map),
        Value::Bool(flag) => flag.zeroize(),
        Value::Number(num) => {
            *num = serde_json::Number::from(0_u8);
            *value = Value::Null;
        }
        _ => {}
    }
}

fn zeroize_json_map(map: &mut Map<String, Value>) {
    let entries = std::mem::take(map);
    for (mut key, mut val) in entries {
        key.zeroize();
        zeroize_json_value(&mut val);
    }
}
