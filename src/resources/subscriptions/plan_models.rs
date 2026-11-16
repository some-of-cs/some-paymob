#![forbid(unsafe_code)]
//! Subscription plan frequency, plan type, and plan record models (`US-4.2.0` Unit 1).
//!
//! Implements `TC-4.2.1`:
//! - [`PlanFrequency`] restricting plan intervals to Paymob's exact 7 allowed values
//!   (`7 | 15 | 30 | 60 | 90 | 180 | 360` days) mapped via [`KNOWN_PLAN_FREQUENCIES`].
//! - [`PlanType`] (`Rent`) for Paymob subscription plan classifications.
//! - [`SubscriptionPlan`] response record using [`MinorUnitAmount`] (zero floats).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::error::PaymobError;
use crate::core::types::MinorUnitAmount;

/// Static lookup table mapping Paymob's exact allowed billing intervals (in days)
/// to [`PlanFrequency`] variants (`CC <= 3`).
pub const KNOWN_PLAN_FREQUENCIES: &[(u16, PlanFrequency)] = &[
    (7, PlanFrequency::Days7),
    (15, PlanFrequency::Days15),
    (30, PlanFrequency::Days30),
    (60, PlanFrequency::Days60),
    (90, PlanFrequency::Days90),
    (180, PlanFrequency::Days180),
    (360, PlanFrequency::Days360),
];

/// Billing interval for a Paymob subscription plan, restricted to Paymob's exact
/// 7 allowed frequencies (`7`, `15`, `30`, `60`, `90`, `180`, `360` days).
///
/// Paymob rejects any other integer frequency with HTTP 400
/// `{"frequency": ["\"5\" is not a valid choice."]}`. Serializes and deserializes
/// directly as an unsigned integer day count (`u16`).
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::plan_models::PlanFrequency;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let monthly = PlanFrequency::try_from(30)?;
/// assert_eq!(monthly, PlanFrequency::Days30);
/// assert_eq!(monthly.as_days(), 30);
///
/// // Invalid frequencies are rejected before any network call:
/// assert!(PlanFrequency::try_from(5).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum PlanFrequency {
    /// Weekly billing interval (7 days).
    Days7 = 7,
    /// Bi-weekly billing interval (15 days).
    Days15 = 15,
    /// Monthly billing interval (30 days).
    Days30 = 30,
    /// Bi-monthly billing interval (60 days).
    Days60 = 60,
    /// Quarterly billing interval (90 days).
    Days90 = 90,
    /// Semi-annual billing interval (180 days).
    Days180 = 180,
    /// Annual billing interval (360 days).
    Days360 = 360,
}

impl PlanFrequency {
    /// Resolves a day count into a [`PlanFrequency`] via [`KNOWN_PLAN_FREQUENCIES`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] tagged with `field: "frequency"` if
    /// `days` is not one of `7`, `15`, `30`, `60`, `90`, `180`, or `360`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use some_paymob::resources::subscriptions::plan_models::PlanFrequency;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// assert_eq!(PlanFrequency::from_days(90)?, PlanFrequency::Days90);
    /// assert!(PlanFrequency::from_days(14).is_err());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_days(days: u16) -> Result<Self, PaymobError> {
        KNOWN_PLAN_FREQUENCIES
            .iter()
            .find(|(d, _)| *d == days)
            .map(|(_, freq)| *freq)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "frequency",
                reason: format!(
                    "unsupported plan frequency `{days}`; expected one of 7, 15, 30, 60, 90, 180, 360"
                ),
            })
    }

    /// Returns the integer number of days for this [`PlanFrequency`].
    #[must_use]
    pub const fn as_days(self) -> u16 {
        self as u16
    }
}

impl TryFrom<u16> for PlanFrequency {
    type Error = PaymobError;

    fn try_from(days: u16) -> Result<Self, Self::Error> {
        Self::from_days(days)
    }
}

impl From<PlanFrequency> for u16 {
    fn from(value: PlanFrequency) -> Self {
        value.as_days()
    }
}

impl fmt::Display for PlanFrequency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_days())
    }
}

impl Serialize for PlanFrequency {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u16(self.as_days())
    }
}

impl<'de> Deserialize<'de> for PlanFrequency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let days = u16::deserialize(deserializer)?;
        Self::from_days(days).map_err(serde::de::Error::custom)
    }
}

/// Classification of a Paymob subscription plan.
///
/// Serializes as `"rent"` and accepts `"rent"`, `"Rent"`, or `"RENT"` on
/// deserialization or [`FromStr`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::plan_models::PlanType;
///
/// let plan_type = PlanType::Rent;
/// assert_eq!(plan_type.as_str(), "rent");
/// assert_eq!(plan_type.to_string(), "rent");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum PlanType {
    /// Recurring rent / standard subscription plan (`"rent"`).
    #[default]
    #[serde(rename = "rent", alias = "Rent", alias = "RENT")]
    Rent,
}

impl PlanType {
    /// Returns the canonical wire string representation of this [`PlanType`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rent => "rent",
        }
    }
}

impl fmt::Display for PlanType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PlanType {
    type Err = PaymobError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.eq_ignore_ascii_case("rent") {
            return Ok(Self::Rent);
        }
        Err(PaymobError::ValidationError {
            field: "plan_type",
            reason: format!("unsupported plan_type `{trimmed}`; expected `rent`"),
        })
    }
}

/// Subscription plan record returned by Paymob's `/api/acceptance/subscription-plans`
/// endpoints.
///
/// All monetary fields (`amount_cents`, `fee`) strictly use [`MinorUnitAmount`]
/// integer minor units with zero floating-point types.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::resources::subscriptions::plan_models::{
///     PlanFrequency, PlanType, SubscriptionPlan,
/// };
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let json = r#"{
///     "id": 1024,
///     "name": "Pro Monthly",
///     "frequency": 30,
///     "integration": 4111111,
///     "amount_cents": 25000,
///     "fee": 500,
///     "use_transaction_amount": false,
///     "is_active": true,
///     "plan_type": "rent"
/// }"#;
///
/// let plan: SubscriptionPlan = serde_json::from_str(json)?;
/// assert_eq!(plan.id, 1024);
/// assert_eq!(plan.frequency, PlanFrequency::Days30);
/// assert_eq!(plan.amount_cents, Some(MinorUnitAmount::new(25_000)));
/// assert_eq!(plan.fee, Some(MinorUnitAmount::new(500)));
/// assert_eq!(plan.plan_type, Some(PlanType::Rent));
/// assert!(!plan.is_suspended());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionPlan {
    /// Unique Paymob subscription plan identifier.
    pub id: u64,
    /// Human-readable subscription plan name.
    pub name: String,
    /// Billing interval restricted to Paymob's 7 allowed frequencies.
    pub frequency: PlanFrequency,
    /// MIGS MOTO integration ID associated with this plan.
    pub integration: u64,
    /// Fixed plan charge in integer minor units (zero floats), if configured.
    #[serde(default)]
    pub amount_cents: Option<MinorUnitAmount>,
    /// Optional plan fee in integer minor units (zero floats).
    #[serde(default)]
    pub fee: Option<MinorUnitAmount>,
    /// Whether each recurring charge uses the initial transaction amount.
    #[serde(default)]
    pub use_transaction_amount: bool,
    /// Whether the subscription plan is currently active (`false` when suspended).
    #[serde(default)]
    pub is_active: bool,
    /// Optional plan classification (such as [`PlanType::Rent`]).
    #[serde(default)]
    pub plan_type: Option<PlanType>,
    /// Optional webhook URL notified on plan or subscription lifecycle events.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Optional number of days before renewal to send a reminder notification.
    #[serde(default)]
    pub reminder_days: Option<u16>,
    /// Optional number of days to retry failed recurring charges.
    #[serde(default)]
    pub retrial_days: Option<u16>,
    /// Optional maximum number of deductions before the subscription completes.
    #[serde(default)]
    pub number_of_deductions: Option<u32>,
    /// Optional ISO-8601 creation timestamp returned by Paymob.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Optional ISO-8601 last-updated timestamp returned by Paymob.
    #[serde(default)]
    pub updated_at: Option<String>,
}

impl SubscriptionPlan {
    /// Returns `true` when the subscription plan is suspended (`!is_active`).
    #[must_use]
    pub const fn is_suspended(&self) -> bool {
        !self.is_active
    }

    /// Returns the configured `amount_cents`, or [`MinorUnitAmount::ZERO`] if unset.
    #[must_use]
    pub const fn effective_amount(&self) -> MinorUnitAmount {
        match self.amount_cents {
            Some(amount) => amount,
            None => MinorUnitAmount::ZERO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_4_2_1_plan_frequency_known_table_and_try_from() {
        assert_eq!(KNOWN_PLAN_FREQUENCIES.len(), 7);
        let expected = [
            (7_u16, PlanFrequency::Days7),
            (15, PlanFrequency::Days15),
            (30, PlanFrequency::Days30),
            (60, PlanFrequency::Days60),
            (90, PlanFrequency::Days90),
            (180, PlanFrequency::Days180),
            (360, PlanFrequency::Days360),
        ];
        for (days, variant) in expected {
            let parsed = PlanFrequency::try_from(days).expect("valid frequency");
            assert_eq!(
                (
                    parsed,
                    PlanFrequency::from_days(days).expect("from_days"),
                    parsed.as_days(),
                    u16::from(parsed),
                    parsed.to_string(),
                ),
                (variant, variant, days, days, days.to_string())
            );
        }
    }

    #[test]
    fn tc_4_2_1_plan_frequency_rejects_invalid_values() {
        for bad_days in [0_u16, 1, 5, 14, 29, 31, 45, 365, u16::MAX] {
            let res = PlanFrequency::try_from(bad_days);
            assert!(matches!(
                res,
                Err(PaymobError::ValidationError {
                    field: "frequency",
                    ..
                })
            ));
        }
    }

    #[test]
    fn tc_4_2_1_plan_frequency_serde_integer_roundtrip_and_rejection() {
        let json = serde_json::to_string(&PlanFrequency::Days30).expect("serialize");
        assert_eq!(json, "30");

        let parsed: PlanFrequency = serde_json::from_str("180").expect("deserialize 180");
        assert_eq!(parsed, PlanFrequency::Days180);

        let bad_json: Result<PlanFrequency, _> = serde_json::from_str("5");
        assert!(bad_json.is_err());
    }

    #[test]
    fn tc_4_2_1_plan_type_rent_serde_and_from_str() {
        let rent = PlanType::default();
        assert_eq!(
            (rent, rent.as_str(), rent.to_string().as_str()),
            (PlanType::Rent, "rent", "rent")
        );

        let json = serde_json::to_string(&rent).expect("serialize");
        assert_eq!(json, "\"rent\"");

        for alias in ["\"rent\"", "\"Rent\"", "\"RENT\""] {
            let parsed: PlanType = serde_json::from_str(alias).expect("deserialize alias");
            assert_eq!(parsed, PlanType::Rent);
        }

        for raw in ["rent", "Rent", " RENT "] {
            assert_eq!(raw.parse::<PlanType>().expect("parse"), PlanType::Rent);
        }
        assert!(matches!(
            "lease".parse::<PlanType>(),
            Err(PaymobError::ValidationError {
                field: "plan_type",
                ..
            })
        ));
    }

    #[test]
    fn tc_4_2_1_subscription_plan_deserialization_and_minor_units() {
        let payload = r#"{
            "id": 42,
            "name": "Enterprise Quarterly",
            "frequency": 90,
            "integration": 4111111,
            "amount_cents": 150000,
            "fee": 750,
            "use_transaction_amount": false,
            "is_active": true,
            "plan_type": "Rent",
            "webhook_url": "https://example.com/webhooks/paymob",
            "reminder_days": 3,
            "retrial_days": 2,
            "number_of_deductions": 12,
            "created_at": "2026-11-16T10:00:00Z",
            "updated_at": "2026-11-16T10:05:00Z"
        }"#;

        let plan: SubscriptionPlan = serde_json::from_str(payload).expect("deserialize plan");
        assert_eq!(
            (
                plan.id,
                plan.name.as_str(),
                plan.frequency,
                plan.integration,
                plan.amount_cents,
                plan.fee,
                plan.effective_amount(),
            ),
            (
                42,
                "Enterprise Quarterly",
                PlanFrequency::Days90,
                4_111_111,
                Some(MinorUnitAmount::new(150_000)),
                Some(MinorUnitAmount::new(750)),
                MinorUnitAmount::new(150_000),
            )
        );
        assert_eq!(
            (
                plan.use_transaction_amount,
                plan.is_active,
                plan.is_suspended(),
                plan.plan_type,
                plan.reminder_days,
                plan.retrial_days,
                plan.number_of_deductions,
            ),
            (
                false,
                true,
                false,
                Some(PlanType::Rent),
                Some(3),
                Some(2),
                Some(12)
            )
        );
    }

    #[test]
    fn tc_4_2_1_subscription_plan_minimal_payload_and_invalid_frequency() {
        let minimal = r#"{
            "id": 99,
            "name": "Dynamic Usage",
            "frequency": 7,
            "integration": 4222222,
            "amount_cents": null,
            "use_transaction_amount": true,
            "is_active": false
        }"#;

        let plan: SubscriptionPlan = serde_json::from_str(minimal).expect("deserialize minimal");
        assert_eq!(
            (
                plan.amount_cents,
                plan.effective_amount(),
                plan.use_transaction_amount,
                plan.is_suspended(),
                plan.plan_type,
            ),
            (None, MinorUnitAmount::ZERO, true, true, None)
        );

        let invalid_freq = r#"{
            "id": 100,
            "name": "Bad Plan",
            "frequency": 5,
            "integration": 4222222
        }"#;
        let err = serde_json::from_str::<SubscriptionPlan>(invalid_freq);
        assert!(err.is_err());
    }
}
