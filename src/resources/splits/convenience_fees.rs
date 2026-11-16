#![forbid(unsafe_code)]
//! Convenience fee configuration and checked integer fee calculator (`US-3.3.0/unit-3`).
//!
//! Provides [`FeeCalculationMode`], [`CardFeeRule`], [`CardFeeContext`], and
//! [`ConvenienceFeeConfig`] with zero floating-point arithmetic, basis-point
//! scaling (`10_000 bps = 100%`), and `max_fee_cents` clamping.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;

/// Basis-points denominator (`10_000 bps = 100.00%`).
pub const BASIS_POINTS_DENOMINATOR: u64 = 10_000;

const REDACTED_MARKER: &str = "[REDACTED]";

/// Fee calculation formula applied to a transaction amount in integer minor units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FeeCalculationMode {
    /// Percentage fee expressed in integer basis points (`10_000 bps = 100%`).
    PercentageBps(u32),
    /// Flat fixed fee expressed in integer minor units.
    FixedCents(u64),
    /// Combined percentage (basis points) plus a flat minor-unit fee.
    Combination {
        /// Percentage component in integer basis points (`10_000 bps = 100%`).
        bps: u32,
        /// Flat minor-unit fee added to the percentage component.
        fixed_cents: u64,
    },
}

/// Card-level matching rule determining how convenience fees apply to a card.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CardFeeRule {
    /// Apply the same fee configuration uniformly to all cards.
    Uniform,
    /// Apply separate fee modes for debit versus credit cards.
    DebitVsCredit {
        /// Fee mode applied to debit cards.
        debit_mode: FeeCalculationMode,
        /// Fee mode applied to credit cards.
        credit_mode: FeeCalculationMode,
    },
    /// Apply the fee when a card BIN prefix falls within `[start_bin, end_bin]` (inclusive).
    BinRange {
        /// Inclusive lower BIN prefix bound (6 to 8 ASCII digits).
        start_bin: String,
        /// Inclusive upper BIN prefix bound (6 to 8 ASCII digits).
        end_bin: String,
    },
    /// Apply separate fee modes for domestic versus international cards.
    DomesticVsInternational {
        /// Fee mode applied to domestic cards.
        domestic_mode: FeeCalculationMode,
        /// Fee mode applied to international cards.
        international_mode: FeeCalculationMode,
    },
}

/// Card classification context used when evaluating [`CardFeeRule`].
///
/// Any `bin_prefix` is redacted as `"[REDACTED]"` in [`fmt::Debug`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CardFeeContext<'a> {
    /// `true` for credit cards, `false` for debit cards.
    pub is_credit: bool,
    /// `true` for internationally issued cards, `false` for domestic cards.
    pub is_international: bool,
    /// Optional 6-to-8 digit card BIN prefix (redacted in `Debug` output).
    pub bin_prefix: Option<&'a str>,
}

impl fmt::Debug for CardFeeContext<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardFeeContext")
            .field("is_credit", &self.is_credit)
            .field("is_international", &self.is_international)
            .field(
                "bin_prefix",
                if self.bin_prefix.is_some() {
                    &REDACTED_MARKER
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

impl<'a> CardFeeContext<'a> {
    /// Creates a new [`CardFeeContext`].
    #[must_use]
    pub const fn new(is_credit: bool, is_international: bool) -> Self {
        Self {
            is_credit,
            is_international,
            bin_prefix: None,
        }
    }

    /// Attaches a 6-to-8 digit BIN prefix for [`CardFeeRule::BinRange`] evaluation.
    #[must_use]
    pub const fn with_bin_prefix(mut self, bin_prefix: &'a str) -> Self {
        self.bin_prefix = Some(bin_prefix);
        self
    }
}

/// Merchant convenience fee configuration and checked integer fee calculator.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::splits::convenience_fees::{
///     ConvenienceFeeConfig, FeeCalculationMode,
/// };
///
/// # fn example() -> Result<(), some_paymob::PaymobError> {
/// let cfg = ConvenienceFeeConfig::new(FeeCalculationMode::Combination {
///     bps: 250,
///     fixed_cents: 300,
/// })
/// .with_max_fee_cents(5_000);
///
/// // 2.5% of 300_000 = 7_500 + 300 = 7_800, capped at 5_000
/// assert_eq!(cfg.compute_fee_cents(300_000)?, 5_000);
/// # Ok(())
/// # }
/// # example().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConvenienceFeeConfig {
    /// Primary fee calculation mode.
    pub mode: FeeCalculationMode,
    /// Optional maximum convenience fee cap in integer minor units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_cents: Option<u64>,
    /// Whether the convenience fee is refundable on full/partial refunds.
    pub is_refundable: bool,
    /// Card-level rule controlling fee applicability or rate selection.
    pub card_rule: CardFeeRule,
}

impl ConvenienceFeeConfig {
    /// Creates a new [`ConvenienceFeeConfig`] with [`CardFeeRule::Uniform`] and `is_refundable = false`.
    #[must_use]
    pub const fn new(mode: FeeCalculationMode) -> Self {
        Self {
            mode,
            max_fee_cents: None,
            is_refundable: false,
            card_rule: CardFeeRule::Uniform,
        }
    }

    /// Sets the optional maximum convenience fee cap in integer minor units.
    #[must_use]
    pub const fn with_max_fee_cents(mut self, max_fee_cents: u64) -> Self {
        self.max_fee_cents = Some(max_fee_cents);
        self
    }

    /// Sets whether the convenience fee is refundable.
    #[must_use]
    pub const fn with_refundable(mut self, is_refundable: bool) -> Self {
        self.is_refundable = is_refundable;
        self
    }

    /// Sets the [`CardFeeRule`] for card-specific fee calculation.
    #[must_use]
    pub fn with_card_rule(mut self, card_rule: CardFeeRule) -> Self {
        self.card_rule = card_rule;
        self
    }

    /// Validates the fee configuration, basis-point bounds, and BIN range bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any percentage exceeds `10_000` bps,
    /// `max_fee_cents` is `Some(0)`, or a [`CardFeeRule::BinRange`] has invalid bounds.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_mode(self.mode)?;
        if self.max_fee_cents == Some(0) {
            return Err(validation_err(
                "max_fee_cents",
                "max_fee_cents must be greater than zero when specified",
            ));
        }
        validate_card_rule(&self.card_rule)
    }

    /// Computes the convenience fee in integer minor units using checked arithmetic,
    /// clamping to `max_fee_cents` when configured.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if configuration validation fails or
    /// integer arithmetic overflows `u64`.
    pub fn compute_fee_cents(&self, amount_cents: u64) -> Result<u64, PaymobError> {
        self.validate()?;
        compute_mode_fee(self.mode, amount_cents, self.max_fee_cents)
    }

    /// Computes the convenience fee for a specific [`CardFeeContext`].
    ///
    /// For [`CardFeeRule::BinRange`], returns `0` when the context BIN prefix is absent
    /// or outside `[start_bin, end_bin]`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if configuration validation fails or
    /// integer arithmetic overflows `u64`.
    pub fn compute_fee_for_card_cents(
        &self,
        amount_cents: u64,
        ctx: &CardFeeContext<'_>,
    ) -> Result<u64, PaymobError> {
        self.validate()?;
        let effective_mode = match &self.card_rule {
            CardFeeRule::Uniform => self.mode,
            CardFeeRule::DebitVsCredit {
                debit_mode,
                credit_mode,
            } => select_mode(ctx.is_credit, *credit_mode, *debit_mode),
            CardFeeRule::DomesticVsInternational {
                domestic_mode,
                international_mode,
            } => select_mode(ctx.is_international, *international_mode, *domestic_mode),
            CardFeeRule::BinRange { start_bin, end_bin } => {
                if !bin_in_range(ctx.bin_prefix, start_bin, end_bin) {
                    return Ok(0);
                }
                self.mode
            }
        };
        compute_mode_fee(effective_mode, amount_cents, self.max_fee_cents)
    }

    /// Computes `amount_cents + compute_fee_cents(amount_cents)` using checked addition.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if fee computation or addition overflows.
    pub fn total_with_fee_cents(&self, amount_cents: u64) -> Result<u64, PaymobError> {
        let fee = self.compute_fee_cents(amount_cents)?;
        amount_cents
            .checked_add(fee)
            .ok_or_else(|| validation_err("amount_cents", "total with convenience fee overflow"))
    }
}

const fn select_mode(
    condition: bool,
    when_true: FeeCalculationMode,
    when_false: FeeCalculationMode,
) -> FeeCalculationMode {
    if condition {
        when_true
    } else {
        when_false
    }
}

fn bin_in_range(bin_prefix: Option<&str>, start_bin: &str, end_bin: &str) -> bool {
    match bin_prefix {
        Some(bin) => is_valid_bin(bin) && bin >= start_bin && bin <= end_bin,
        None => false,
    }
}

fn compute_mode_fee(
    mode: FeeCalculationMode,
    amount_cents: u64,
    max_fee_cents: Option<u64>,
) -> Result<u64, PaymobError> {
    let raw_fee = match mode {
        FeeCalculationMode::PercentageBps(bps) => checked_bps_fee(amount_cents, bps)?,
        FeeCalculationMode::FixedCents(fixed) => fixed,
        FeeCalculationMode::Combination { bps, fixed_cents } => checked_bps_fee(amount_cents, bps)?
            .checked_add(fixed_cents)
            .ok_or_else(|| validation_err("fee_cents", "combined convenience fee overflow"))?,
    };
    Ok(match max_fee_cents {
        Some(cap) => raw_fee.min(cap),
        None => raw_fee,
    })
}

fn checked_bps_fee(amount_cents: u64, bps: u32) -> Result<u64, PaymobError> {
    let scaled = u128::from(amount_cents)
        .checked_mul(u128::from(bps))
        .ok_or_else(|| validation_err("amount_cents", "convenience fee multiplication overflow"))?;
    let fee = scaled / u128::from(BASIS_POINTS_DENOMINATOR);
    u64::try_from(fee)
        .map_err(|_| validation_err("fee_cents", "convenience fee exceeds u64 range"))
}

fn validate_mode(mode: FeeCalculationMode) -> Result<(), PaymobError> {
    let bps = match mode {
        FeeCalculationMode::PercentageBps(b) | FeeCalculationMode::Combination { bps: b, .. } => b,
        FeeCalculationMode::FixedCents(_) => return Ok(()),
    };
    if u64::from(bps) > BASIS_POINTS_DENOMINATOR {
        return Err(validation_err(
            "bps",
            "basis points must not exceed 10_000 (100%)",
        ));
    }
    Ok(())
}

fn validate_card_rule(rule: &CardFeeRule) -> Result<(), PaymobError> {
    match rule {
        CardFeeRule::Uniform => Ok(()),
        CardFeeRule::DebitVsCredit {
            debit_mode,
            credit_mode,
        } => {
            validate_mode(*debit_mode)?;
            validate_mode(*credit_mode)
        }
        CardFeeRule::DomesticVsInternational {
            domestic_mode,
            international_mode,
        } => {
            validate_mode(*domestic_mode)?;
            validate_mode(*international_mode)
        }
        CardFeeRule::BinRange { start_bin, end_bin } => validate_bin_range(start_bin, end_bin),
    }
}

fn validate_bin_range(start_bin: &str, end_bin: &str) -> Result<(), PaymobError> {
    if !is_valid_bin(start_bin) || !is_valid_bin(end_bin) || start_bin > end_bin {
        return Err(validation_err(
            "bin_range",
            "BIN range bounds must be 6-8 ASCII digits with start_bin <= end_bin",
        ));
    }
    Ok(())
}

fn is_valid_bin(bin: &str) -> bool {
    (6..=8).contains(&bin.len()) && bin.bytes().all(|b| b.is_ascii_digit())
}

fn validation_err(field: &'static str, reason: impl Into<String>) -> PaymobError {
    PaymobError::ValidationError {
        field,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_3_3_3_combination_fee_with_max_cap() {
        let cfg = ConvenienceFeeConfig::new(FeeCalculationMode::Combination {
            bps: 250,
            fixed_cents: 300,
        })
        .with_max_fee_cents(5_000)
        .with_refundable(true);

        assert_eq!(cfg.compute_fee_cents(300_000).expect("fee"), 5_000);
        assert_eq!(cfg.total_with_fee_cents(300_000).expect("total"), 305_000);
        assert_eq!(cfg.compute_fee_cents(100_000).expect("uncapped"), 2_800);
        assert!(cfg.is_refundable);
    }

    #[test]
    fn tc_3_3_3_percentage_and_fixed_modes() {
        let pct = ConvenienceFeeConfig::new(FeeCalculationMode::PercentageBps(175));
        assert_eq!(pct.compute_fee_cents(200_000).expect("pct"), 3_500);

        let fixed = ConvenienceFeeConfig::new(FeeCalculationMode::FixedCents(450));
        assert_eq!(fixed.compute_fee_cents(10_000).expect("fixed"), 450);
    }

    #[test]
    fn tc_3_3_3_card_fee_rules_evaluation() {
        let debit_credit = ConvenienceFeeConfig::new(FeeCalculationMode::FixedCents(0))
            .with_card_rule(CardFeeRule::DebitVsCredit {
                debit_mode: FeeCalculationMode::PercentageBps(100),
                credit_mode: FeeCalculationMode::PercentageBps(250),
            });
        assert_eq!(
            debit_credit
                .compute_fee_for_card_cents(100_000, &CardFeeContext::new(false, false))
                .expect("debit"),
            1_000
        );
        assert_eq!(
            debit_credit
                .compute_fee_for_card_cents(100_000, &CardFeeContext::new(true, false))
                .expect("credit"),
            2_500
        );

        let bin_cfg = ConvenienceFeeConfig::new(FeeCalculationMode::FixedCents(500))
            .with_card_rule(CardFeeRule::BinRange {
                start_bin: "400000".to_owned(),
                end_bin: "499999".to_owned(),
            });
        assert_eq!(
            bin_cfg
                .compute_fee_for_card_cents(
                    50_000,
                    &CardFeeContext::new(true, false).with_bin_prefix("411111")
                )
                .expect("in bin range"),
            500
        );
        assert_eq!(
            bin_cfg
                .compute_fee_for_card_cents(
                    50_000,
                    &CardFeeContext::new(true, false).with_bin_prefix("510000")
                )
                .expect("out of bin range"),
            0
        );
    }

    #[test]
    fn tc_3_3_3_validation_rejects_invalid_bps_cap_and_bin_range() {
        let bad_bps = ConvenienceFeeConfig::new(FeeCalculationMode::PercentageBps(10_001));
        assert!(matches!(
            bad_bps.compute_fee_cents(10_000),
            Err(PaymobError::ValidationError { field: "bps", .. })
        ));

        let zero_cap =
            ConvenienceFeeConfig::new(FeeCalculationMode::FixedCents(100)).with_max_fee_cents(0);
        assert!(matches!(
            zero_cap.validate(),
            Err(PaymobError::ValidationError {
                field: "max_fee_cents",
                ..
            })
        ));

        let bad_bin = ConvenienceFeeConfig::new(FeeCalculationMode::FixedCents(100))
            .with_card_rule(CardFeeRule::BinRange {
                start_bin: "500000".to_owned(),
                end_bin: "400000".to_owned(),
            });
        assert!(matches!(
            bad_bin.validate(),
            Err(PaymobError::ValidationError {
                field: "bin_range",
                ..
            })
        ));
    }

    #[test]
    fn tc_3_3_4_card_fee_context_redacts_bin_prefix() {
        let ctx = CardFeeContext::new(true, true).with_bin_prefix("411111");
        let dbg = format!("{ctx:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("411111"));
    }
}
