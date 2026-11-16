#![forbid(unsafe_code)]
//! Subscription record, lifecycle state, list filter, and card vault models.
//!
//! Implements `US-4.3.0` Unit 1 (`TC-4.3.1`):
//! - [`Subscription`] record with integer minor-unit [`MinorUnitAmount`] pricing and lifecycle timestamps.
//! - [`SubscriptionState`] backed by [`KNOWN_SUBSCRIPTION_STATES`] static lookup table (`CC <= 3`).
//! - [`SubscriptionListFilter`] query builder for listing subscriptions.
//! - [`SubscriptionCard`] vault model with [`SecretString`] token and `[REDACTED]` `Debug` formatting.

use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

use secrecy::SecretString;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

use crate::core::types::MinorUnitAmount;

/// Static lookup table mapping canonical lowercase Paymob subscription states
/// to [`SubscriptionState`] variants.
pub const KNOWN_SUBSCRIPTION_STATES: &[(&str, SubscriptionState)] = &[
    ("active", SubscriptionState::Active),
    ("suspended", SubscriptionState::Suspended),
    ("canceled", SubscriptionState::Canceled),
    ("cancelled", SubscriptionState::Canceled),
    ("inactive", SubscriptionState::Inactive),
];

/// Lifecycle state of a Paymob subscription.
///
/// Serializes and deserializes as a lowercase state string (e.g. `"active"`, `"suspended"`),
/// falling back to [`SubscriptionState::Unknown`] for unrecognized values.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::models::SubscriptionState;
///
/// let active = SubscriptionState::from_state("ACTIVE");
/// assert_eq!(active, SubscriptionState::Active);
/// assert_eq!(active.as_str(), "active");
/// assert!(active.is_known());
///
/// let custom = SubscriptionState::from_state("paused_by_bank");
/// assert!(!custom.is_known());
/// assert_eq!(custom.as_str(), "paused_by_bank");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionState {
    /// Subscription is active and billing on schedule.
    Active,
    /// Subscription is temporarily suspended.
    Suspended,
    /// Subscription has been permanently canceled.
    Canceled,
    /// Subscription is inactive or awaiting initial activation.
    Inactive,
    /// Unrecognized subscription state returned by the Paymob API.
    Unknown(String),
}

impl SubscriptionState {
    /// Parses a subscription state string case-insensitively using [`KNOWN_SUBSCRIPTION_STATES`].
    ///
    /// Trims surrounding whitespace and normalizes unrecognized states to lowercase
    /// inside [`SubscriptionState::Unknown`].
    #[must_use]
    pub fn from_state(raw: &str) -> Self {
        let trimmed = raw.trim();
        KNOWN_SUBSCRIPTION_STATES
            .iter()
            .find(|(code, _)| trimmed.eq_ignore_ascii_case(code))
            .map_or_else(
                || Self::Unknown(trimmed.to_ascii_lowercase()),
                |(_, state)| state.clone(),
            )
    }

    /// Returns the canonical lowercase string slice for this [`SubscriptionState`].
    #[must_use]
    pub fn as_str(&self) -> &str {
        if let Self::Unknown(raw) = self {
            return raw.as_str();
        }
        KNOWN_SUBSCRIPTION_STATES
            .iter()
            .find(|(_, state)| state == self)
            .map_or("unknown", |(code, _)| *code)
    }

    /// Returns `true` if the state is one of the explicitly enumerated [`KNOWN_SUBSCRIPTION_STATES`].
    #[must_use]
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl Serialize for SubscriptionState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SubscriptionState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(Self::from_state(&raw))
    }
}

impl fmt::Display for SubscriptionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubscriptionState {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::from_state(s))
    }
}

/// Paymob subscription record returned by subscription lifecycle endpoints.
///
/// All monetary amounts use integer minor units via [`MinorUnitAmount`] with zero
/// floating-point arithmetic.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::resources::subscriptions::models::{Subscription, SubscriptionState};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let json = r#"{
///     "id": 1264,
///     "plan_id": 88,
///     "state": "active",
///     "initial_transaction": 998877,
///     "amount_cents": 50000,
///     "starts_at": "2026-11-01T00:00:00Z",
///     "next_billing": "2026-12-01T00:00:00Z",
///     "reminder_date": null,
///     "ends_at": null,
///     "resumed_at": null,
///     "suspended_at": null,
///     "reactivated_at": null,
///     "created_at": "2026-11-01T00:00:00Z"
/// }"#;
///
/// let sub: Subscription = serde_json::from_str(json)?;
/// assert_eq!(sub.id, 1264);
/// assert_eq!(sub.state, SubscriptionState::Active);
/// assert_eq!(sub.amount_cents, MinorUnitAmount::new(50_000));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subscription {
    /// Unique Paymob subscription identifier.
    pub id: u64,
    /// Identifier of the associated subscription plan.
    pub plan_id: u64,
    /// Current lifecycle state of the subscription.
    pub state: SubscriptionState,
    /// Identifier of the initial 3DS enrollment transaction, if present.
    #[serde(default)]
    pub initial_transaction: Option<u64>,
    /// Recurring charge amount in integer minor units (e.g. piasters, halalas).
    pub amount_cents: MinorUnitAmount,
    /// ISO-8601 timestamp when the subscription starts.
    #[serde(default)]
    pub starts_at: Option<String>,
    /// ISO-8601 timestamp of the next scheduled billing attempt.
    #[serde(default)]
    pub next_billing: Option<String>,
    /// ISO-8601 timestamp of the upcoming billing reminder.
    #[serde(default)]
    pub reminder_date: Option<String>,
    /// ISO-8601 timestamp when the subscription ends or was canceled.
    #[serde(default)]
    pub ends_at: Option<String>,
    /// ISO-8601 timestamp when the subscription was last resumed.
    #[serde(default)]
    pub resumed_at: Option<String>,
    /// ISO-8601 timestamp when the subscription was last suspended.
    #[serde(default)]
    pub suspended_at: Option<String>,
    /// ISO-8601 timestamp when the subscription was reactivated.
    #[serde(default)]
    pub reactivated_at: Option<String>,
    /// ISO-8601 timestamp when the subscription record was created.
    #[serde(default)]
    pub created_at: String,
}

/// Optional query-string filters for listing Paymob subscriptions.
///
/// Fields set to `None` are omitted during serialization.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::models::{
///     SubscriptionListFilter, SubscriptionState,
/// };
///
/// let filter = SubscriptionListFilter::new()
///     .plan_id(88)
///     .state(SubscriptionState::Active);
///
/// assert!(!filter.is_empty());
/// assert_eq!(filter.plan_id, Some(88));
/// assert_eq!(filter.state, Some(SubscriptionState::Active));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionListFilter {
    /// Filter by associated transaction identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<u64>,
    /// Filter by subscription plan identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<u64>,
    /// Filter by subscription lifecycle state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<SubscriptionState>,
}

impl SubscriptionListFilter {
    /// Creates an empty [`SubscriptionListFilter`] with all filter fields unset.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the `transaction` filter parameter.
    #[must_use]
    pub const fn transaction(mut self, transaction: u64) -> Self {
        self.transaction = Some(transaction);
        self
    }

    /// Sets the `plan_id` filter parameter.
    #[must_use]
    pub const fn plan_id(mut self, plan_id: u64) -> Self {
        self.plan_id = Some(plan_id);
        self
    }

    /// Sets the `state` filter parameter.
    #[must_use]
    pub fn state(mut self, state: SubscriptionState) -> Self {
        self.state = Some(state);
        self
    }

    /// Returns `true` if no filter criteria are set.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.transaction.is_none() && self.plan_id.is_none() && self.state.is_none()
    }
}

/// Saved card vault entry attached to a Paymob subscription.
///
/// The card `token` is wrapped in [`SecretString`] (`ZeroizeOnDrop`) and its
/// [`fmt::Debug`] implementation always renders `token` as `"[REDACTED]"`.
///
/// # Examples
///
/// ```rust
/// use secrecy::ExposeSecret;
/// use some_paymob::resources::subscriptions::models::SubscriptionCard;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let json = r#"{
///     "id": 374,
///     "card_data": {"card_subtype": "MasterCard"},
///     "token": "tok_live_secret_abc123",
///     "created_at": "2026-11-01T00:00:00Z",
///     "is_primary": true,
///     "masked_pan": "xxxx-xxxx-xxxx-2346",
///     "failed_attempts": 0
/// }"#;
///
/// let card: SubscriptionCard = serde_json::from_str(json)?;
/// assert_eq!(card.id, 374);
/// assert!(card.is_primary);
/// assert_eq!(card.token.expose_secret(), "tok_live_secret_abc123");
///
/// let debug_out = format!("{card:?}");
/// assert!(debug_out.contains("[REDACTED]"));
/// assert!(!debug_out.contains("tok_live_secret_abc123"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Deserialize)]
pub struct SubscriptionCard {
    /// Unique card vault entry identifier.
    pub id: u64,
    /// Optional card metadata payload returned by Paymob.
    #[serde(default)]
    pub card_data: Option<Value>,
    /// Secret card token used for recurring MIT charges (redacted in `Debug`).
    pub token: SecretString,
    /// ISO-8601 timestamp when the card was attached to the subscription.
    #[serde(default)]
    pub created_at: String,
    /// Whether this card is the primary billing card for the subscription.
    #[serde(default)]
    pub is_primary: bool,
    /// Masked Primary Account Number (e.g. `"xxxx-xxxx-xxxx-2346"`).
    #[serde(default)]
    pub masked_pan: String,
    /// Number of consecutive failed recurring charge attempts on this card.
    #[serde(default)]
    pub failed_attempts: u32,
}

impl fmt::Debug for SubscriptionCard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionCard")
            .field("id", &self.id)
            .field("card_data", &self.card_data)
            .field("token", &"[REDACTED]")
            .field("created_at", &self.created_at)
            .field("is_primary", &self.is_primary)
            .field("masked_pan", &self.masked_pan)
            .field("failed_attempts", &self.failed_attempts)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn tc_4_3_1_subscription_state_lookup_and_serde() {
        let cases = [
            ("active", SubscriptionState::Active, "active", true),
            ("ACTIVE", SubscriptionState::Active, "active", true),
            (" suspended ", SubscriptionState::Suspended, "suspended", true),
            ("canceled", SubscriptionState::Canceled, "canceled", true),
            ("cancelled", SubscriptionState::Canceled, "canceled", true),
            ("INACTIVE", SubscriptionState::Inactive, "inactive", true),
            (
                "PAUSED_CUSTOM",
                SubscriptionState::Unknown("paused_custom".to_owned()),
                "paused_custom",
                false,
            ),
            (
                "   ",
                SubscriptionState::Unknown(String::new()),
                "",
                false,
            ),
        ];

        for (raw, expected, canonical, known) in cases {
            let parsed = SubscriptionState::from_state(raw);
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), canonical);
            assert_eq!(parsed.is_known(), known);
            assert_eq!(parsed.to_string(), canonical);
            assert_eq!(raw.parse::<SubscriptionState>().expect("infallible"), expected);
        }

        let serialized = serde_json::to_string(&SubscriptionState::Suspended).expect("serialize");
        let deserialized: SubscriptionState =
            serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(serialized, "\"suspended\"");
        assert_eq!(deserialized, SubscriptionState::Suspended);
        assert_eq!(KNOWN_SUBSCRIPTION_STATES.len(), 5);
    }

    #[test]
    fn tc_4_3_1_subscription_record_deserialization_and_boundary_fields() {
        let full_json = r#"{
            "id": 1264,
            "plan_id": 88,
            "state": "active",
            "initial_transaction": 998877,
            "amount_cents": 50000,
            "starts_at": "2026-11-01T00:00:00Z",
            "next_billing": "2026-12-01T00:00:00Z",
            "reminder_date": "2026-11-28T00:00:00Z",
            "ends_at": "2027-11-01T00:00:00Z",
            "resumed_at": "2026-11-10T00:00:00Z",
            "suspended_at": "2026-11-05T00:00:00Z",
            "reactivated_at": "2026-11-12T00:00:00Z",
            "created_at": "2026-11-01T00:00:00Z"
        }"#;

        let sub: Subscription = serde_json::from_str(full_json).expect("valid full subscription");
        assert_eq!(sub.id, 1264);
        assert_eq!(sub.plan_id, 88);
        assert_eq!(sub.state, SubscriptionState::Active);
        assert_eq!(sub.initial_transaction, Some(998_877));
        assert_eq!(sub.amount_cents, MinorUnitAmount::new(50_000));
        assert_eq!(sub.starts_at.as_deref(), Some("2026-11-01T00:00:00Z"));
        assert_eq!(sub.next_billing.as_deref(), Some("2026-12-01T00:00:00Z"));
        assert_eq!(sub.reminder_date.as_deref(), Some("2026-11-28T00:00:00Z"));
        assert_eq!(sub.ends_at.as_deref(), Some("2027-11-01T00:00:00Z"));
        assert_eq!(sub.resumed_at.as_deref(), Some("2026-11-10T00:00:00Z"));
        assert_eq!(sub.suspended_at.as_deref(), Some("2026-11-05T00:00:00Z"));
        assert_eq!(sub.reactivated_at.as_deref(), Some("2026-11-12T00:00:00Z"));
        assert_eq!(sub.created_at, "2026-11-01T00:00:00Z");

        let roundtrip: Subscription =
            serde_json::from_str(&serde_json::to_string(&sub).expect("serialize"))
                .expect("roundtrip");
        assert_eq!(roundtrip, sub);

        let minimal_json = r#"{
            "id": 1265,
            "plan_id": 1,
            "state": "inactive",
            "amount_cents": 0
        }"#;
        let minimal: Subscription =
            serde_json::from_str(minimal_json).expect("minimal boundary subscription");
        assert_eq!(minimal.amount_cents, MinorUnitAmount::ZERO);
        assert_eq!(minimal.initial_transaction, None);
        assert_eq!(minimal.next_billing, None);
        assert_eq!(minimal.created_at, "");
    }

    #[test]
    fn tc_4_3_1_subscription_list_filter_builder_and_serialization() {
        let empty = SubscriptionListFilter::new();
        assert!(empty.is_empty());
        assert_eq!(serde_json::to_string(&empty).expect("serialize"), "{}");

        let filter = SubscriptionListFilter::new()
            .transaction(998_877)
            .plan_id(88)
            .state(SubscriptionState::Suspended);
        assert!(!filter.is_empty());
        assert_eq!(filter.transaction, Some(998_877));
        assert_eq!(filter.plan_id, Some(88));
        assert_eq!(filter.state, Some(SubscriptionState::Suspended));

        let json_val = serde_json::to_value(&filter).expect("to_value");
        assert_eq!(json_val["transaction"], 998_877);
        assert_eq!(json_val["plan_id"], 88);
        assert_eq!(json_val["state"], "suspended");
    }

    #[test]
    fn tc_4_3_1_subscription_card_redacted_debug_and_malformed_inputs() {
        let card_json = r#"{
            "id": 374,
            "card_data": {"card_subtype": "MasterCard", "issuer": "CIB"},
            "token": "tok_secret_987654321",
            "created_at": "2026-11-01T12:00:00Z",
            "is_primary": true,
            "masked_pan": "xxxx-xxxx-xxxx-2346",
            "failed_attempts": 2
        }"#;

        let card: SubscriptionCard = serde_json::from_str(card_json).expect("valid card");
        assert_eq!(card.id, 374);
        assert!(card.card_data.is_some());
        assert_eq!(card.token.expose_secret(), "tok_secret_987654321");
        assert_eq!(card.created_at, "2026-11-01T12:00:00Z");
        assert!(card.is_primary);
        assert_eq!(card.masked_pan, "xxxx-xxxx-xxxx-2346");
        assert_eq!(card.failed_attempts, 2);

        let debug_str = format!("{card:?}");
        assert!(debug_str.contains("SubscriptionCard"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("tok_secret_987654321"));

        let missing_token_json = r#"{"id": 375, "is_primary": false}"#;
        assert!(serde_json::from_str::<SubscriptionCard>(missing_token_json).is_err());

        let float_amount_json = r#"{
            "id": 1266,
            "plan_id": 88,
            "state": "active",
            "amount_cents": 12.50
        }"#;
        assert!(serde_json::from_str::<Subscription>(float_amount_json).is_err());
    }
}
