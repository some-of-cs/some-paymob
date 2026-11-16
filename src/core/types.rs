#![forbid(unsafe_code)]
//! Zero-float minor-unit money types, currency lookup primitives, and prefixed ID validators.
//!
//! Implements US-1.3.0 Unit 3 (`TC-1.3.3`):
//! - [`MinorUnitAmount`] for exact integer minor-unit arithmetic (piasters, halalas, fils, paisas).
//! - [`Currency`] backed by [`KNOWN_CURRENCIES`] for case-insensitive ISO-4217 lookup.
//! - [`validate_prefixed_id`] for non-empty, whitespace-free, prefix-enforced identifier checks.

use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;

/// Monetary amount represented strictly as integer minor units (piasters, halalas, fils, paisas).
///
/// All monetary calculations across `some-paymob` use integer minor units with zero
/// floating-point arithmetic to prevent rounding drift and 100x scaling bugs.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::MinorUnitAmount;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let amount = MinorUnitAmount::from_major_checked(1000, 2)?;
/// assert_eq!(amount.as_u64(), 100_000);
///
/// let fee = MinorUnitAmount::new(250);
/// assert_eq!(amount.checked_add(fee)?, MinorUnitAmount(100_250));
/// assert_eq!(amount.checked_sub(fee)?, MinorUnitAmount(99_750));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MinorUnitAmount(
    /// Raw minor-unit integer value.
    pub u64,
);

impl MinorUnitAmount {
    /// Creates a [`MinorUnitAmount`] directly from an integer minor-unit count.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::core::types::MinorUnitAmount;
    ///
    /// let cents = MinorUnitAmount::new(15_000);
    /// assert_eq!(cents.as_u64(), 15_000);
    /// ```
    #[must_use]
    pub const fn new(amount: u64) -> Self {
        Self(amount)
    }

    /// Returns the underlying integer minor-unit count.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts a major-unit integer amount into minor units using checked power-of-ten scaling.
    ///
    /// Returns [`PaymobError::ValidationError`] if `decimals` overflows a `u64` power of ten
    /// or if `major * 10^decimals` overflows `u64`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::core::types::MinorUnitAmount;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// assert_eq!(MinorUnitAmount::from_major_checked(1000, 2)?, MinorUnitAmount(100_000));
    /// assert_eq!(MinorUnitAmount::from_major_checked(50, 3)?, MinorUnitAmount(50_000));
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_major_checked(major: u64, decimals: u8) -> Result<Self, PaymobError> {
        let Some(scale) = 10_u64.checked_pow(u32::from(decimals)) else {
            return Err(PaymobError::ValidationError {
                field: "decimals",
                reason: format!("decimal precision {decimals} overflows u64 scale"),
            });
        };
        let Some(minor) = major.checked_mul(scale) else {
            return Err(PaymobError::ValidationError {
                field: "amount",
                reason: format!("major amount {major} with {decimals} decimals overflows u64"),
            });
        };
        Ok(Self(minor))
    }

    /// Adds two [`MinorUnitAmount`] values, returning [`PaymobError::ValidationError`] on overflow.
    pub fn checked_add(self, rhs: Self) -> Result<Self, PaymobError> {
        self.0
            .checked_add(rhs.0)
            .map(Self)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "amount",
                reason: format!("addition overflow: {} + {}", self.0, rhs.0),
            })
    }

    /// Subtracts `rhs` from `self`, returning [`PaymobError::ValidationError`] on underflow.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, PaymobError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "amount",
                reason: format!("subtraction underflow: {} - {}", self.0, rhs.0),
            })
    }
}

impl fmt::Display for MinorUnitAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u64> for MinorUnitAmount {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<MinorUnitAmount> for u64 {
    fn from(value: MinorUnitAmount) -> Self {
        value.0
    }
}

/// Static lookup table mapping canonical ISO-4217 currency codes to [`Currency`] variants.
pub const KNOWN_CURRENCIES: &[(&str, Currency)] = &[
    ("EGP", Currency::EGP),
    ("SAR", Currency::SAR),
    ("AED", Currency::AED),
    ("OMR", Currency::OMR),
    ("PKR", Currency::PKR),
    ("USD", Currency::USD),
    ("EUR", Currency::EUR),
];

/// Supported ISO-4217 currencies across Paymob MENA & Pakistan regions, plus an extensible fallback.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::Currency;
///
/// let egp = Currency::from_code("egp");
/// assert_eq!(egp, Currency::EGP);
/// assert_eq!(egp.as_str(), "EGP");
///
/// let other = Currency::from_code("kwd");
/// assert_eq!(other, Currency::Unknown("KWD".to_owned()));
/// assert_eq!(other.as_str(), "KWD");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Currency {
    /// Egyptian Pound (EGP, 2 minor-unit decimals: piasters).
    EGP,
    /// Saudi Riyal (SAR, 2 minor-unit decimals: halalas).
    SAR,
    /// UAE Dirham (AED, 2 minor-unit decimals: fils).
    AED,
    /// Omani Rial (OMR, 3 minor-unit decimals: baisa).
    OMR,
    /// Pakistani Rupee (PKR, 2 minor-unit decimals: paisas).
    PKR,
    /// United States Dollar (USD, 2 minor-unit decimals: cents).
    USD,
    /// Euro (EUR, 2 minor-unit decimals: cents).
    EUR,
    /// Any other ISO-4217 currency code not explicitly enumerated.
    Unknown(String),
}

impl Currency {
    /// Parses a currency code case-insensitively using [`KNOWN_CURRENCIES`].
    ///
    /// Trims surrounding whitespace and normalizes unrecognized codes to uppercase
    /// inside [`Currency::Unknown`].
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        let trimmed = code.trim();
        KNOWN_CURRENCIES
            .iter()
            .find(|(iso, _)| trimmed.eq_ignore_ascii_case(iso))
            .map_or_else(
                || Self::Unknown(trimmed.to_ascii_uppercase()),
                |(_, currency)| currency.clone(),
            )
    }

    /// Returns the canonical uppercase ISO-4217 code slice for this [`Currency`].
    #[must_use]
    pub fn as_str(&self) -> &str {
        if let Self::Unknown(code) = self {
            return code.as_str();
        }
        KNOWN_CURRENCIES
            .iter()
            .find(|(_, currency)| currency == self)
            .map_or("UNKNOWN", |(iso, _)| *iso)
    }

    /// Returns the standard minor-unit decimal precision for this currency (`3` for `OMR`, `2` otherwise).
    #[must_use]
    pub fn minor_unit_decimals(&self) -> u8 {
        if matches!(self, Self::OMR) {
            3
        } else {
            2
        }
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Currency {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_code(s))
    }
}

/// Validates that an identifier `value` is non-empty, contains no whitespace,
/// starts with `prefix`, and has a non-empty suffix after `prefix`.
///
/// Returns [`PaymobError::ValidationError`] tagged with `field` if any check fails.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::validate_prefixed_id;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// validate_prefixed_id("pi_123456", "pi_", "payment_intention_id")?;
/// assert!(validate_prefixed_id("", "pi_", "payment_intention_id").is_err());
/// assert!(validate_prefixed_id("pi_", "pi_", "payment_intention_id").is_err());
/// # Ok(())
/// # }
/// ```
pub fn validate_prefixed_id(
    value: &str,
    prefix: &str,
    field: &'static str,
) -> Result<(), PaymobError> {
    if value.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: "identifier must not be empty".to_owned(),
        });
    }
    if value.chars().any(char::is_whitespace) {
        return Err(PaymobError::ValidationError {
            field,
            reason: "identifier must not contain whitespace".to_owned(),
        });
    }
    if !value.starts_with(prefix) || value.len() <= prefix.len() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("identifier must start with `{prefix}` and include a non-empty suffix"),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_1_3_3_minor_unit_amount_from_major_checked_and_math() {
        let egp = MinorUnitAmount::from_major_checked(1000, 2).expect("1000 EGP fits in u64");
        assert_eq!(egp, MinorUnitAmount(100_000));
        assert_eq!(egp.as_u64(), 100_000);

        let omr = MinorUnitAmount::from_major_checked(25, 3).expect("25 OMR fits in u64");
        assert_eq!(omr, MinorUnitAmount(25_000));

        let zero_dec = MinorUnitAmount::from_major_checked(42, 0).expect("0 decimals");
        assert_eq!(zero_dec, MinorUnitAmount(42));

        let sum = egp
            .checked_add(MinorUnitAmount::new(500))
            .expect("addition succeeds");
        assert_eq!(sum, MinorUnitAmount(100_500));

        let diff = egp
            .checked_sub(MinorUnitAmount::new(500))
            .expect("subtraction succeeds");
        assert_eq!(diff, MinorUnitAmount(99_500));

        let zero = egp.checked_sub(egp).expect("exact subtraction yields zero");
        assert_eq!(zero, MinorUnitAmount(0));
    }

    #[test]
    fn tc_1_3_3_minor_unit_amount_overflow_and_underflow_return_validation_error() {
        let scale_overflow = MinorUnitAmount::from_major_checked(1, 20);
        assert!(matches!(
            scale_overflow,
            Err(PaymobError::ValidationError {
                field: "decimals",
                ..
            })
        ));

        let mul_overflow = MinorUnitAmount::from_major_checked(u64::MAX, 2);
        assert!(matches!(
            mul_overflow,
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));

        let add_overflow = MinorUnitAmount(u64::MAX).checked_add(MinorUnitAmount(1));
        assert!(matches!(
            add_overflow,
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));

        let sub_underflow = MinorUnitAmount(10).checked_sub(MinorUnitAmount(11));
        assert!(matches!(
            sub_underflow,
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));
    }

    #[test]
    fn tc_1_3_3_minor_unit_amount_serde_transparent_and_conversions() {
        let amount = MinorUnitAmount::from(123_456_u64);
        let json = serde_json::to_string(&amount).expect("serialize");
        assert_eq!(json, "123456");

        let parsed: MinorUnitAmount = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, amount);
        assert_eq!(u64::from(parsed), 123_456);
        assert_eq!(parsed.to_string(), "123456");
    }

    #[test]
    fn tc_1_3_3_currency_case_insensitive_lookup_and_as_str() {
        let cases = [
            ("egp", Currency::EGP, "EGP", 2_u8),
            ("SAR", Currency::SAR, "SAR", 2_u8),
            (" aed ", Currency::AED, "AED", 2_u8),
            ("Omr", Currency::OMR, "OMR", 3_u8),
            ("pKr", Currency::PKR, "PKR", 2_u8),
            ("usd", Currency::USD, "USD", 2_u8),
            ("Eur", Currency::EUR, "EUR", 2_u8),
        ];

        for (raw, expected, canonical, decimals) in cases {
            let parsed = Currency::from_code(raw);
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), canonical);
            assert_eq!(parsed.to_string(), canonical);
            assert_eq!(parsed.minor_unit_decimals(), decimals);
            assert_eq!(raw.parse::<Currency>().expect("infallible"), expected);
        }

        let unknown = Currency::from_code("kwd");
        assert_eq!(unknown, Currency::Unknown("KWD".to_owned()));
        assert_eq!(unknown.as_str(), "KWD");
        assert_eq!(unknown.minor_unit_decimals(), 2);
        assert_eq!(KNOWN_CURRENCIES.len(), 7);
    }

    #[test]
    fn tc_1_3_3_validate_prefixed_id_positive_and_negative_cases() {
        assert!(validate_prefixed_id("pi_abc123", "pi_", "intention_id").is_ok());
        assert!(validate_prefixed_id("pk_test_xyz", "pk_", "public_key").is_ok());
        assert!(validate_prefixed_id("opaque_id", "", "raw_id").is_ok());

        for bad in ["", "   ", "\t\n"] {
            assert!(matches!(
                validate_prefixed_id(bad, "pi_", "intention_id"),
                Err(PaymobError::ValidationError {
                    field: "intention_id",
                    ..
                })
            ));
        }

        for ws in [" pi_123", "pi_123 ", "pi_12 3", "pi_\n123"] {
            assert!(matches!(
                validate_prefixed_id(ws, "pi_", "intention_id"),
                Err(PaymobError::ValidationError {
                    field: "intention_id",
                    ..
                })
            ));
        }

        for wrong_or_empty_suffix in ["pk_123", "pi_", "123"] {
            assert!(matches!(
                validate_prefixed_id(wrong_or_empty_suffix, "pi_", "intention_id"),
                Err(PaymobError::ValidationError {
                    field: "intention_id",
                    ..
                })
            ));
        }
    }
}
