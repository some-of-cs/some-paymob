#![forbid(unsafe_code)]
//! Zero-float minor-unit money types, currency lookup primitives, and prefixed ID validators.
//!
//! Implements US-1.3.0 Unit 3 (`TC-1.3.3`):
//! - [`MinorUnitAmount`] for exact integer minor-unit arithmetic (piasters, halalas, fils, paisas).
//! - [`Currency`] backed by [`KNOWN_CURRENCIES`] for case-insensitive ISO-4217 lookup and plain-string serde.
//! - [`validate_prefixed_id`] for non-empty, safe, prefix-enforced identifier checks.

use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

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
    /// Zero minor-unit amount constant (`0`).
    pub const ZERO: Self = Self(0);

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

    /// Returns `true` if the amount equals zero (`0`).
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Converts a major-unit integer amount into minor units using checked power-of-ten scaling.
    ///
    /// # Errors
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
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `self + rhs` overflows `u64`.
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
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `rhs > self`.
    pub fn checked_sub(self, rhs: Self) -> Result<Self, PaymobError> {
        self.0
            .checked_sub(rhs.0)
            .map(Self)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "amount",
                reason: format!("subtraction underflow: {} - {}", self.0, rhs.0),
            })
    }

    /// Multiplies `self` by an integer `factor`, returning [`PaymobError::ValidationError`] on overflow.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `self * factor` overflows `u64`.
    pub fn checked_mul(self, factor: u64) -> Result<Self, PaymobError> {
        self.0
            .checked_mul(factor)
            .map(Self)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "amount",
                reason: format!("multiplication overflow: {} * {factor}", self.0),
            })
    }

    /// Divides `self` by `divisor` using integer floor division.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `divisor == 0`.
    pub fn checked_div(self, divisor: u64) -> Result<Self, PaymobError> {
        self.0
            .checked_div(divisor)
            .map(Self)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "divisor",
                reason: "division by zero".to_owned(),
            })
    }

    /// Saturating addition of two [`MinorUnitAmount`] values.
    #[must_use]
    pub const fn saturating_add(self, rhs: Self) -> Self {
        Self(self.0.saturating_add(rhs.0))
    }

    /// Saturating subtraction of `rhs` from `self`, clamping at [`MinorUnitAmount::ZERO`].
    #[must_use]
    pub const fn saturating_sub(self, rhs: Self) -> Self {
        Self(self.0.saturating_sub(rhs.0))
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
/// Serializes and deserializes as a plain uppercase ISO-4217 code string (e.g. `"EGP"`, `"KWD"`).
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
/// assert_eq!(other.minor_unit_decimals(), 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

    /// Returns `true` if the currency is one of the explicitly enumerated [`KNOWN_CURRENCIES`].
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }

    /// Returns the standard minor-unit decimal precision for this currency
    /// (`3` for `KWD`, `BHD`, `OMR`, `JOD`, `TND`, `LYD`, `IQD`; `2` otherwise).
    #[must_use]
    pub fn minor_unit_decimals(&self) -> u8 {
        match self.as_str() {
            "KWD" | "BHD" | "OMR" | "JOD" | "TND" | "LYD" | "IQD" => 3,
            _ => 2,
        }
    }
}

impl Serialize for Currency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Currency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::from_code(&raw))
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

fn has_unsafe_id_chars(value: &str) -> bool {
    value.chars().any(|ch| {
        ch.is_whitespace()
            || ch.is_ascii_control()
            || matches!(ch, '/' | '?' | '#' | '%' | '\\')
    }) || value.contains("..")
}

/// Validates that an identifier `value` is non-empty, contains no whitespace,
/// ASCII control characters, or URL-reserved/traversal characters (`/`, `?`, `#`, `%`, `\`, `..`),
/// starts with `prefix`, and has a non-empty suffix after `prefix`.
///
/// # Errors
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
    if has_unsafe_id_chars(value) {
        return Err(PaymobError::ValidationError {
            field,
            reason: "identifier contains forbidden whitespace, control, or URL-reserved characters"
                .to_owned(),
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
        assert_eq!(
            (
                egp,
                egp.as_u64(),
                MinorUnitAmount::from_major_checked(25, 3).expect("25 OMR"),
                MinorUnitAmount::from_major_checked(42, 0).expect("0 decimals"),
            ),
            (
                MinorUnitAmount(100_000),
                100_000,
                MinorUnitAmount(25_000),
                MinorUnitAmount(42),
            )
        );
        assert_eq!(
            (
                egp.checked_add(MinorUnitAmount::new(500)).expect("add"),
                egp.checked_sub(MinorUnitAmount::new(500)).expect("sub"),
                egp.checked_sub(egp).expect("zero"),
            ),
            (
                MinorUnitAmount(100_500),
                MinorUnitAmount(99_500),
                MinorUnitAmount::ZERO,
            )
        );
    }

    #[test]
    fn tc_1_3_3_minor_unit_amount_zero_mul_div_and_saturating() {
        assert_eq!(
            (MinorUnitAmount::ZERO.is_zero(), MinorUnitAmount::new(1).is_zero()),
            (true, false)
        );
        assert_eq!(
            (
                MinorUnitAmount::new(250).checked_mul(4).expect("mul"),
                MinorUnitAmount::new(250).checked_div(4).expect("div"),
                MinorUnitAmount(u64::MAX).saturating_add(MinorUnitAmount(1)),
                MinorUnitAmount(5).saturating_sub(MinorUnitAmount(10)),
            ),
            (
                MinorUnitAmount(1000),
                MinorUnitAmount(62),
                MinorUnitAmount(u64::MAX),
                MinorUnitAmount::ZERO,
            )
        );
    }

    #[test]
    fn tc_1_3_3_minor_unit_amount_overflow_underflow_and_div_zero() {
        let err_cases = [
            (MinorUnitAmount::from_major_checked(1, 20), "decimals"),
            (MinorUnitAmount::from_major_checked(u64::MAX, 2), "amount"),
            (MinorUnitAmount(u64::MAX).checked_add(MinorUnitAmount(1)), "amount"),
            (MinorUnitAmount(10).checked_sub(MinorUnitAmount(11)), "amount"),
            (MinorUnitAmount(u64::MAX).checked_mul(2), "amount"),
            (MinorUnitAmount(100).checked_div(0), "divisor"),
        ];
        for (res, expected_field) in err_cases {
            assert!(matches!(
                res,
                Err(PaymobError::ValidationError { field, .. }) if field == expected_field
            ));
        }
    }

    #[test]
    fn tc_1_3_3_minor_unit_amount_serde_transparent_and_conversions() {
        let amount = MinorUnitAmount::from(123_456_u64);
        let json = serde_json::to_string(&amount).expect("serialize");
        let parsed: MinorUnitAmount = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            (json.as_str(), parsed, u64::from(parsed), parsed.to_string().as_str()),
            ("123456", amount, 123_456, "123456")
        );
    }

    #[test]
    fn tc_1_3_3_currency_case_insensitive_lookup_and_three_decimal_codes() {
        let cases = [
            ("egp", Currency::EGP, "EGP", 2_u8, true),
            ("SAR", Currency::SAR, "SAR", 2_u8, true),
            (" aed ", Currency::AED, "AED", 2_u8, true),
            ("Omr", Currency::OMR, "OMR", 3_u8, true),
            ("pKr", Currency::PKR, "PKR", 2_u8, true),
            ("usd", Currency::USD, "USD", 2_u8, true),
            ("Eur", Currency::EUR, "EUR", 2_u8, true),
            ("kwd", Currency::Unknown("KWD".to_owned()), "KWD", 3_u8, false),
            ("bhd", Currency::Unknown("BHD".to_owned()), "BHD", 3_u8, false),
            ("jod", Currency::Unknown("JOD".to_owned()), "JOD", 3_u8, false),
            ("tnd", Currency::Unknown("TND".to_owned()), "TND", 3_u8, false),
            ("lyd", Currency::Unknown("LYD".to_owned()), "LYD", 3_u8, false),
            ("iqd", Currency::Unknown("IQD".to_owned()), "IQD", 3_u8, false),
        ];

        for (raw, expected, canonical, decimals, known) in cases {
            let parsed = Currency::from_code(raw);
            assert_eq!(
                (
                    &parsed,
                    parsed.as_str(),
                    parsed.minor_unit_decimals(),
                    parsed.is_known(),
                    raw.parse::<Currency>().expect("infallible"),
                ),
                (&expected, canonical, decimals, known, expected.clone())
            );
        }
        assert_eq!(KNOWN_CURRENCIES.len(), 7);
    }

    #[test]
    fn tc_1_3_3_currency_plain_iso_serde_and_empty_code() {
        let kwd_json = serde_json::to_string(&Currency::from_code("kwd")).expect("serialize");
        let kwd_parsed: Currency = serde_json::from_str(&kwd_json).expect("deserialize");
        assert_eq!(
            (kwd_json.as_str(), kwd_parsed),
            ("\"KWD\"", Currency::Unknown("KWD".to_owned()))
        );

        let empty = Currency::from_code("   ");
        assert_eq!(
            (empty.as_str(), empty.is_known(), empty.minor_unit_decimals()),
            ("", false, 2)
        );
    }

    #[test]
    fn tc_1_3_3_validate_prefixed_id_positive_and_negative_cases() {
        for (id, prefix, field) in [
            ("pi_abc123", "pi_", "intention_id"),
            ("pk_test_xyz", "pk_", "public_key"),
            ("opaque_id", "", "raw_id"),
        ] {
            assert!(validate_prefixed_id(id, prefix, field).is_ok());
        }

        let invalid = [
            "",
            "   ",
            "\t\n",
            " pi_123",
            "pi_123 ",
            "pi_12 3",
            "pi_\n123",
            "pi_\x00123",
            "pi_\x1b123",
            "pi_123/../../admin",
            "pi_123?foo=bar",
            "pi_123#frag",
            "pi_123%2f",
            "pi_123\\bar",
            "pi_..123",
            "pk_123",
            "pi_",
            "123",
        ];
        for bad in invalid {
            assert!(matches!(
                validate_prefixed_id(bad, "pi_", "intention_id"),
                Err(PaymobError::ValidationError {
                    field: "intention_id",
                    ..
                })
            ));
        }
    }
}
