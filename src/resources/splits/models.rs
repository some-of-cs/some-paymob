#![forbid(unsafe_code)]
//! Marketplace split recipient rules and multi-card split checkout models (`US-3.3.0/unit-2`).
//!
//! Provides [`SplitRecipientRule`], [`SplitDescription`], [`SplitCardPortion`],
//! and [`SplitPaymentConfig`] enforcing Paymob's maximum 3-card split checkout
//! limit (`1 <= cards.len() <= 3`) and integer-only minor-unit / basis-point math.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use crate::core::error::PaymobError;

/// Maximum number of customer cards permitted in a single Paymob Split Payment checkout.
pub const MAX_SPLIT_CARDS: usize = 3;

/// Maximum total basis points (`10_000 bps = 100.00%`).
pub const MAX_BASIS_POINTS: u32 = 10_000;

const REDACTED_MARKER: &str = "[REDACTED]";

/// Single marketplace recipient settlement rule inside [`SplitDescription`].
///
/// Each rule specifies **either** a fixed integer minor-unit share (`amount_cents`)
/// **or** a percentage share in basis points (`percentage_bps`, `10_000 = 100%`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRecipientRule {
    /// Target Paymob sub-merchant or recipient account identifier.
    pub recipient_id: String,
    /// Fixed settlement amount in integer minor units (mutually exclusive with `percentage_bps`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<u64>,
    /// Settlement percentage in integer basis points (`1..=10_000`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percentage_bps: Option<u32>,
    /// Optional human-readable settlement description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl SplitRecipientRule {
    /// Creates a fixed minor-unit settlement rule for `recipient_id`.
    #[must_use]
    pub fn fixed(recipient_id: impl Into<String>, amount_cents: u64) -> Self {
        Self {
            recipient_id: recipient_id.into(),
            amount_cents: Some(amount_cents),
            percentage_bps: None,
            description: None,
        }
    }

    /// Creates a basis-points percentage settlement rule for `recipient_id`.
    #[must_use]
    pub fn percentage_bps(recipient_id: impl Into<String>, percentage_bps: u32) -> Self {
        Self {
            recipient_id: recipient_id.into(),
            amount_cents: None,
            percentage_bps: Some(percentage_bps),
            description: None,
        }
    }

    /// Attaches an optional settlement description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Validates that `recipient_id` is non-empty and exactly one split mode is set.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `recipient_id` is empty,
    /// both/neither of `amount_cents` and `percentage_bps` are set, `amount_cents == 0`,
    /// or `percentage_bps` is outside `1..=10_000`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.recipient_id.trim().is_empty() {
            return Err(validation_err(
                "recipient_id",
                "recipient_id must not be empty",
            ));
        }
        match (self.amount_cents, self.percentage_bps) {
            (Some(amt), None) if amt > 0 => Ok(()),
            (Some(_), None) => Err(validation_err(
                "amount_cents",
                "fixed split amount_cents must be greater than zero",
            )),
            (None, Some(bps)) if (1..=MAX_BASIS_POINTS).contains(&bps) => Ok(()),
            (None, Some(_)) => Err(validation_err(
                "percentage_bps",
                "percentage_bps must be between 1 and 10_000",
            )),
            _ => Err(validation_err(
                "split_rule",
                "specify exactly one of amount_cents or percentage_bps",
            )),
        }
    }
}

/// Multi-recipient marketplace settlement configuration (`Split Amount`).
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::splits::models::{SplitDescription, SplitRecipientRule};
///
/// # fn example() -> Result<(), some_paymob::PaymobError> {
/// let split = SplitDescription::new(vec![
///     SplitRecipientRule::percentage_bps("seller_1", 8_500),
///     SplitRecipientRule::percentage_bps("platform", 1_500),
/// ])?;
/// assert_eq!(split.total_percentage_bps()?, 10_000);
/// # Ok(())
/// # }
/// # example().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitDescription {
    /// Ordered list of marketplace recipient settlement rules.
    pub recipients: Vec<SplitRecipientRule>,
}

impl SplitDescription {
    /// Constructs and validates a [`SplitDescription`] from `recipients`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `recipients` is empty,
    /// mixes fixed and percentage rules, fails individual rule validation, or
    /// exceeds `10_000` total basis points.
    pub fn new(recipients: Vec<SplitRecipientRule>) -> Result<Self, PaymobError> {
        let desc = Self { recipients };
        desc.validate()?;
        Ok(desc)
    }

    /// Validates all recipient rules and aggregate bounds.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on empty recipients, mixed modes,
    /// invalid rules, or total percentage exceeding `10_000` bps.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.recipients.is_empty() {
            return Err(validation_err(
                "recipients",
                "at least one split recipient rule is required",
            ));
        }
        let expect_fixed = self.recipients[0].amount_cents.is_some();
        for rule in &self.recipients {
            rule.validate()?;
            if rule.amount_cents.is_some() != expect_fixed {
                return Err(validation_err(
                    "recipients",
                    "cannot mix fixed amount_cents and percentage_bps rules",
                ));
            }
        }
        if !expect_fixed && self.total_percentage_bps()? > MAX_BASIS_POINTS {
            return Err(validation_err(
                "percentage_bps",
                "total percentage_bps across recipients cannot exceed 10_000",
            ));
        }
        Ok(())
    }

    /// Returns the checked sum of fixed `amount_cents` across all recipients.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on integer overflow.
    pub fn total_fixed_cents(&self) -> Result<u64, PaymobError> {
        let mut total: u64 = 0;
        for rule in &self.recipients {
            if let Some(amt) = rule.amount_cents {
                total = total
                    .checked_add(amt)
                    .ok_or_else(|| validation_err("amount_cents", "fixed split sum overflow"))?;
            }
        }
        Ok(total)
    }

    /// Returns the checked sum of `percentage_bps` across all recipients.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on integer overflow.
    pub fn total_percentage_bps(&self) -> Result<u32, PaymobError> {
        let mut total: u32 = 0;
        for rule in &self.recipients {
            if let Some(bps) = rule.percentage_bps {
                total = total
                    .checked_add(bps)
                    .ok_or_else(|| validation_err("percentage_bps", "percentage sum overflow"))?;
            }
        }
        Ok(total)
    }
}

/// Single customer card portion in a multi-card [`SplitPaymentConfig`].
///
/// Any attached `card_token` is redacted as `"[REDACTED]"` in [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitCardPortion {
    /// Portion charged to this card in integer minor units.
    pub amount_cents: u64,
    /// Optional Paymob integration ID for this card leg.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration_id: Option<u64>,
    /// Optional saved card token (redacted in `Debug` output).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card_token: Option<String>,
}

impl fmt::Debug for SplitCardPortion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SplitCardPortion")
            .field("amount_cents", &self.amount_cents)
            .field("integration_id", &self.integration_id)
            .field(
                "card_token",
                if self.card_token.is_some() {
                    &REDACTED_MARKER
                } else {
                    &"None"
                },
            )
            .finish()
    }
}

impl SplitCardPortion {
    /// Creates a new [`SplitCardPortion`] with `amount_cents`.
    #[must_use]
    pub const fn new(amount_cents: u64) -> Self {
        Self {
            amount_cents,
            integration_id: None,
            card_token: None,
        }
    }

    /// Sets the Paymob integration ID for this card leg.
    #[must_use]
    pub const fn with_integration_id(mut self, integration_id: u64) -> Self {
        self.integration_id = Some(integration_id);
        self
    }

    /// Sets the saved card token for this card leg.
    #[must_use]
    pub fn with_card_token(mut self, card_token: impl Into<String>) -> Self {
        self.card_token = Some(card_token.into());
        self
    }

    /// Validates that `amount_cents > 0` and any provided `card_token` is non-empty.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount_cents == 0` or `card_token` is blank.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.amount_cents == 0 {
            return Err(validation_err(
                "amount_cents",
                "card portion amount_cents must be greater than zero",
            ));
        }
        if self
            .card_token
            .as_deref()
            .is_some_and(|token| token.trim().is_empty())
        {
            return Err(validation_err(
                "card_token",
                "card_token must not be empty when provided",
            ));
        }
        Ok(())
    }
}

/// Multi-card customer checkout configuration enforcing `1 <= cards.len() <= 3`.
///
/// Paymob's Split Payment feature allows a customer to split a single checkout
/// across at most [`MAX_SPLIT_CARDS`] (3) cards.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::splits::models::{SplitCardPortion, SplitPaymentConfig};
///
/// # fn example() -> Result<(), some_paymob::PaymobError> {
/// let cfg = SplitPaymentConfig::new(vec![
///     SplitCardPortion::new(60_000),
///     SplitCardPortion::new(40_000),
/// ])?;
/// assert_eq!(cfg.total_amount_cents()?, 100_000);
/// # Ok(())
/// # }
/// # example().unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SplitPaymentConfig {
    /// Card portions (between 1 and 3 entries inclusive).
    pub cards: Vec<SplitCardPortion>,
}

impl<'de> Deserialize<'de> for SplitPaymentConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawSplitPaymentConfig {
            cards: Vec<SplitCardPortion>,
        }

        let raw = RawSplitPaymentConfig::deserialize(deserializer)?;
        Self::new(raw.cards).map_err(serde::de::Error::custom)
    }
}

impl SplitPaymentConfig {
    /// Creates and validates a [`SplitPaymentConfig`] enforcing `1 <= cards.len() <= 3`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] (`field: "cards"`) if `cards`
    /// is empty or contains more than 3 entries, or if any portion has `amount_cents == 0`
    /// or an empty `card_token`.
    pub fn new(cards: Vec<SplitCardPortion>) -> Result<Self, PaymobError> {
        let cfg = Self { cards };
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validates that `1 <= cards.len() <= 3` and every [`SplitCardPortion`] is valid.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `cards` is empty, exceeds [`MAX_SPLIT_CARDS`],
    /// or contains an invalid portion.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.cards.is_empty() || self.cards.len() > MAX_SPLIT_CARDS {
            return Err(validation_err(
                "cards",
                format!("split payment requires between 1 and {MAX_SPLIT_CARDS} cards"),
            ));
        }
        for card in &self.cards {
            card.validate()?;
        }
        Ok(())
    }

    /// Returns the checked sum of `amount_cents` across all card portions.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] on integer overflow.
    pub fn total_amount_cents(&self) -> Result<u64, PaymobError> {
        let mut total: u64 = 0;
        for card in &self.cards {
            total = total
                .checked_add(card.amount_cents)
                .ok_or_else(|| validation_err("amount_cents", "split payment total overflow"))?;
        }
        Ok(total)
    }

    /// Validates all card invariants (`self.validate()?`) and verifies that the sum of card
    /// portions equals `expected_total_cents`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if card invariants fail, totals do not match,
    /// or integer addition overflows.
    pub fn validate_total(&self, expected_total_cents: u64) -> Result<(), PaymobError> {
        self.validate()?;
        let total = self.total_amount_cents()?;
        if total != expected_total_cents {
            return Err(validation_err(
                "amount_cents",
                format!(
                    "split payment total {total} does not match expected {expected_total_cents}"
                ),
            ));
        }
        Ok(())
    }
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
    fn tc_3_3_2_split_payment_enforces_one_to_three_cards() {
        assert!(matches!(
            SplitPaymentConfig::new(vec![]),
            Err(PaymobError::ValidationError { field: "cards", .. })
        ));

        let three = SplitPaymentConfig::new(vec![
            SplitCardPortion::new(10_000),
            SplitCardPortion::new(20_000),
            SplitCardPortion::new(30_000),
        ])
        .expect("3 cards should be allowed");
        assert!(three.validate_total(60_000).is_ok());

        let four = vec![
            SplitCardPortion::new(10_000),
            SplitCardPortion::new(10_000),
            SplitCardPortion::new(10_000),
            SplitCardPortion::new(10_000),
        ];
        assert!(matches!(
            SplitPaymentConfig::new(four),
            Err(PaymobError::ValidationError { field: "cards", .. })
        ));
    }

    #[test]
    fn tc_3_3_2_split_payment_rejects_zero_portion_and_mismatch_total() {
        let zero = SplitPaymentConfig::new(vec![SplitCardPortion::new(0)]);
        assert!(matches!(
            zero,
            Err(PaymobError::ValidationError {
                field: "amount_cents",
                ..
            })
        ));

        let cfg = SplitPaymentConfig::new(vec![SplitCardPortion::new(50_000)]).expect("valid");
        assert!(matches!(
            cfg.validate_total(60_000),
            Err(PaymobError::ValidationError {
                field: "amount_cents",
                ..
            })
        ));
    }

    #[test]
    fn tc_3_3_2_split_description_percentage_and_fixed_validation() {
        let pct = SplitDescription::new(vec![
            SplitRecipientRule::percentage_bps("seller_a", 7_000).with_description("Seller A"),
            SplitRecipientRule::percentage_bps("platform", 3_000),
        ])
        .expect("valid percentage split");
        assert_eq!(pct.total_percentage_bps().expect("sum"), 10_000);

        let fixed = SplitDescription::new(vec![
            SplitRecipientRule::fixed("seller_a", 80_000),
            SplitRecipientRule::fixed("platform", 20_000),
        ])
        .expect("valid fixed split");
        assert_eq!(fixed.total_fixed_cents().expect("sum"), 100_000);

        let over_100 = SplitDescription::new(vec![
            SplitRecipientRule::percentage_bps("seller_a", 6_000),
            SplitRecipientRule::percentage_bps("platform", 5_000),
        ]);
        assert!(matches!(
            over_100,
            Err(PaymobError::ValidationError {
                field: "percentage_bps",
                ..
            })
        ));

        let mixed = SplitDescription::new(vec![
            SplitRecipientRule::fixed("seller_a", 50_000),
            SplitRecipientRule::percentage_bps("platform", 1_000),
        ]);
        assert!(matches!(
            mixed,
            Err(PaymobError::ValidationError {
                field: "recipients",
                ..
            })
        ));
    }

    #[test]
    fn tc_3_3_4_split_card_portion_redacts_card_token() {
        let portion = SplitCardPortion::new(25_000)
            .with_integration_id(4097558)
            .with_card_token("tok_secret_visa_4242");
        let dbg = format!("{portion:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("tok_secret_visa_4242"));
    }

    #[test]
    fn tc_3_3_2_split_payment_deserialization_and_validate_total_enforce_invariants() {
        let empty_json = r#"{"cards":[]}"#;
        assert!(serde_json::from_str::<SplitPaymentConfig>(empty_json).is_err());

        let four_json = r#"{"cards":[{"amount_cents":1},{"amount_cents":1},{"amount_cents":1},{"amount_cents":1}]}"#;
        assert!(serde_json::from_str::<SplitPaymentConfig>(four_json).is_err());

        let zero_amt_json = r#"{"cards":[{"amount_cents":0}]}"#;
        assert!(serde_json::from_str::<SplitPaymentConfig>(zero_amt_json).is_err());

        let blank_tok_json = r#"{"cards":[{"amount_cents":100,"card_token":"   "}]}"#;
        assert!(serde_json::from_str::<SplitPaymentConfig>(blank_tok_json).is_err());

        let valid_json = r#"{"cards":[{"amount_cents":6000,"card_token":"t1"},{"amount_cents":4000,"card_token":"t2"}]}"#;
        let mut cfg: SplitPaymentConfig =
            serde_json::from_str(valid_json).expect("valid split payment config");
        assert!(cfg.validate_total(10_000).is_ok());

        cfg.cards[0].card_token = Some("   ".to_owned());
        assert!(matches!(
            cfg.validate_total(10_000),
            Err(PaymobError::ValidationError {
                field: "card_token",
                ..
            })
        ));

        cfg.cards[0].card_token = Some("tok_1".to_owned());
        cfg.cards.push(SplitCardPortion::new(1_000));
        cfg.cards.push(SplitCardPortion::new(1_000));
        assert!(matches!(
            cfg.validate_total(12_000),
            Err(PaymobError::ValidationError { field: "cards", .. })
        ));
    }
}
