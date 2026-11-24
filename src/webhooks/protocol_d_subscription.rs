#![forbid(unsafe_code)]
//! Protocol D — Subscription Lifecycle 12-trigger webhook models and verifier.
//!
//! Paymob subscription callbacks are delivered as HTTP `POST` JSON payloads with
//! the `HMAC-SHA512` signature embedded in the request body (`hmac` field) rather
//! than as a query parameter.
//!
//! The canonical digest input is formatted strictly as:
//! `"{trigger_type}for{subscription_data.id}"` (for example, `"suspendedfor1264"`).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Static lookup table mapping all 12 official Paymob subscription trigger
/// wire strings to [`SubscriptionTriggerType`] variants.
///
/// Using a static slice keeps [`SubscriptionTriggerType::from_wire`] and
/// [`SubscriptionTriggerType::as_wire`] at cyclomatic complexity `CC <= 3`
/// without a 12-arm `match` statement.
///
/// Note that `"add_secondry_card"` intentionally preserves Paymob's exact
/// wire spelling.
pub const KNOWN_SUBSCRIPTION_TRIGGERS: &[(&str, SubscriptionTriggerType)] = &[
    ("Subscription Created", SubscriptionTriggerType::Created),
    ("suspended", SubscriptionTriggerType::Suspended),
    ("canceled", SubscriptionTriggerType::Canceled),
    ("resumed", SubscriptionTriggerType::Resumed),
    ("updated", SubscriptionTriggerType::Updated),
    (
        "add_secondry_card",
        SubscriptionTriggerType::SecondaryCardAdded,
    ),
    (
        "change_primary_card",
        SubscriptionTriggerType::PrimaryCardChanged,
    ),
    ("delete_card", SubscriptionTriggerType::SecondaryCardDeleted),
    (
        "register_webhook",
        SubscriptionTriggerType::WebhookRegistered,
    ),
    (
        "Successful Transaction",
        SubscriptionTriggerType::SuccessfulTransaction,
    ),
    (
        "Failed Transaction",
        SubscriptionTriggerType::FailedTransaction,
    ),
    (
        "Failed Overdue Transaction",
        SubscriptionTriggerType::FailedOverdueTransaction,
    ),
];

/// Subscription lifecycle trigger type delivered in Protocol D webhooks.
///
/// Covers all 12 documented Paymob subscription trigger strings plus a
/// forward-compatible [`SubscriptionTriggerType::Unknown`] variant.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::protocol_d_subscription::SubscriptionTriggerType;
///
/// let trigger = SubscriptionTriggerType::from_wire("suspended");
/// assert_eq!(trigger, SubscriptionTriggerType::Suspended);
/// assert!(trigger.is_known());
/// assert_eq!(trigger.as_wire(), "suspended");
///
/// let misspelled = SubscriptionTriggerType::from_wire("add_secondry_card");
/// assert_eq!(misspelled, SubscriptionTriggerType::SecondaryCardAdded);
/// assert_eq!(misspelled.as_wire(), "add_secondry_card");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SubscriptionTriggerType {
    /// `"Subscription Created"` — emitted when a new subscription is created.
    Created,
    /// `"suspended"` — emitted when a subscription is suspended.
    Suspended,
    /// `"canceled"` — emitted when a subscription is canceled.
    Canceled,
    /// `"resumed"` — emitted when a suspended subscription is resumed.
    Resumed,
    /// `"updated"` — emitted when subscription details are updated.
    Updated,
    /// `"add_secondry_card"` — emitted when a secondary card is attached.
    SecondaryCardAdded,
    /// `"change_primary_card"` — emitted when the primary card is changed.
    PrimaryCardChanged,
    /// `"delete_card"` — emitted when a secondary card is removed.
    SecondaryCardDeleted,
    /// `"register_webhook"` — emitted when a subscription webhook is registered.
    WebhookRegistered,
    /// `"Successful Transaction"` — emitted on a successful recurring billing cycle.
    SuccessfulTransaction,
    /// `"Failed Transaction"` — emitted when a recurring deduction attempt fails.
    FailedTransaction,
    /// `"Failed Overdue Transaction"` — emitted when a retrial deduction fails.
    FailedOverdueTransaction,
    /// Forward-compatible fallback preserving unrecognized wire trigger strings.
    Unknown(String),
}

impl SubscriptionTriggerType {
    /// Parses a Paymob wire `trigger_type` string into a [`SubscriptionTriggerType`].
    ///
    /// Lookup is performed against [`KNOWN_SUBSCRIPTION_TRIGGERS`] (`CC <= 3`).
    /// Unrecognized strings are preserved verbatim in [`SubscriptionTriggerType::Unknown`].
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::webhooks::protocol_d_subscription::SubscriptionTriggerType;
    ///
    /// assert_eq!(
    ///     SubscriptionTriggerType::from_wire("Subscription Created"),
    ///     SubscriptionTriggerType::Created,
    /// );
    /// assert_eq!(
    ///     SubscriptionTriggerType::from_wire("future_event"),
    ///     SubscriptionTriggerType::Unknown("future_event".to_owned()),
    /// );
    /// ```
    #[must_use]
    pub fn from_wire(wire: &str) -> Self {
        if let Some((_, variant)) = KNOWN_SUBSCRIPTION_TRIGGERS
            .iter()
            .find(|(key, _)| *key == wire)
        {
            return variant.clone();
        }
        Self::Unknown(wire.to_owned())
    }

    /// Returns the exact Paymob wire string representation of this trigger type.
    ///
    /// Lookup is performed against [`KNOWN_SUBSCRIPTION_TRIGGERS`] (`CC <= 3`).
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::webhooks::protocol_d_subscription::SubscriptionTriggerType;
    ///
    /// assert_eq!(
    ///     SubscriptionTriggerType::FailedOverdueTransaction.as_wire(),
    ///     "Failed Overdue Transaction",
    /// );
    /// ```
    #[must_use]
    pub fn as_wire(&self) -> &str {
        if let Self::Unknown(raw) = self {
            return raw.as_str();
        }
        KNOWN_SUBSCRIPTION_TRIGGERS
            .iter()
            .find(|(_, variant)| variant == self)
            .map_or("", |(wire, _)| *wire)
    }

    /// Returns `true` if this trigger matches one of Paymob's 12 documented triggers.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

impl fmt::Display for SubscriptionTriggerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

impl Serialize for SubscriptionTriggerType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for SubscriptionTriggerType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = String::deserialize(deserializer)?;
        Ok(Self::from_wire(&wire))
    }
}

/// Customer contact metadata nested inside [`SubscriptionData::client_info`].
///
/// Implements a custom [`fmt::Debug`] that redacts PII fields (`email`,
/// `full_name`, `phone_number`) as `"[REDACTED]"`.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionClientInfo {
    /// Customer email address.
    #[serde(default)]
    pub email: Option<String>,
    /// Customer full name.
    #[serde(default)]
    pub full_name: Option<String>,
    /// Customer phone number.
    #[serde(default)]
    pub phone_number: Option<String>,
}

impl fmt::Debug for SubscriptionClientInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionClientInfo")
            .field("email", &self.email.as_ref().map(|_| "[REDACTED]"))
            .field("full_name", &self.full_name.as_ref().map(|_| "[REDACTED]"))
            .field(
                "phone_number",
                &self.phone_number.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Subscription object carried inside [`SubscriptionWebhookEvent::subscription_data`].
///
/// Only `id` is required for Protocol D HMAC verification (`"{trigger_type}for{id}"`);
/// all other Paymob metadata fields default gracefully when omitted.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::protocol_d_subscription::SubscriptionData;
///
/// let data = SubscriptionData {
///     id: 1264,
///     state: Some("suspended".to_owned()),
///     amount_cents: Some(330),
///     ..Default::default()
/// };
/// assert_eq!(data.id, 1264);
/// ```
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionData {
    /// Unique Paymob subscription identifier used in `"{trigger_type}for{id}"`.
    pub id: u64,
    /// Associated subscription plan identifier, if present.
    #[serde(default)]
    pub plan_id: Option<u64>,
    /// Human-readable subscription or plan name.
    #[serde(default)]
    pub name: Option<String>,
    /// Current lifecycle state string (e.g., `"active"`, `"suspended"`).
    #[serde(default)]
    pub state: Option<String>,
    /// Billing amount in integer minor units (e.g., piasters/halalas/cents).
    #[serde(default)]
    pub amount_cents: Option<u64>,
    /// Billing frequency in days.
    #[serde(default)]
    pub frequency: Option<u64>,
    /// Paymob integration identifier.
    #[serde(default)]
    pub integration: Option<u64>,
    /// Initial transaction identifier, if recorded.
    #[serde(default)]
    pub initial_transaction: Option<u64>,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// ISO-8601 last-update timestamp.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// Subscription start date (`YYYY-MM-DD`).
    #[serde(default)]
    pub starts_at: Option<String>,
    /// Next scheduled billing date (`YYYY-MM-DD`).
    #[serde(default)]
    pub next_billing: Option<String>,
    /// Subscription end date (`YYYY-MM-DD`), if set.
    #[serde(default)]
    pub ends_at: Option<String>,
    /// Timestamp or date when the subscription was resumed, if any.
    #[serde(default)]
    pub resumed_at: Option<String>,
    /// Timestamp or date when the subscription was suspended, if any.
    #[serde(default)]
    pub suspended_at: Option<String>,
    /// Number of reminder days before billing, if configured.
    #[serde(default)]
    pub reminder_days: Option<u64>,
    /// Number of retrial days for overdue payments, if configured.
    #[serde(default)]
    pub retrial_days: Option<u64>,
    /// Scheduled reminder date, if any.
    #[serde(default)]
    pub reminder_date: Option<String>,
    /// Registered webhook URL for this subscription.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Customer contact details (redacted in `Debug`).
    #[serde(default)]
    pub client_info: Option<SubscriptionClientInfo>,
    /// Forward-compatible catch-all for additional Paymob subscription fields.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

impl SubscriptionData {
    /// Returns the optional billing amount as a strongly-typed [`MinorUnitAmount`](crate::core::types::MinorUnitAmount).
    #[must_use]
    pub const fn amount(&self) -> Option<crate::core::types::MinorUnitAmount> {
        match self.amount_cents {
            Some(cents) => Some(crate::core::types::MinorUnitAmount::new(cents)),
            None => None,
        }
    }
}

impl fmt::Debug for SubscriptionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_webhook_url = self.webhook_url.as_ref().map(|_| "[REDACTED]");
        let redacted_extra = format_args!("<{} extra fields redacted>", self.extra.len());
        f.debug_struct("SubscriptionData")
            .field("id", &self.id)
            .field("plan_id", &self.plan_id)
            .field("name", &self.name)
            .field("state", &self.state)
            .field("amount_cents", &self.amount_cents)
            .field("frequency", &self.frequency)
            .field("integration", &self.integration)
            .field("initial_transaction", &self.initial_transaction)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("starts_at", &self.starts_at)
            .field("next_billing", &self.next_billing)
            .field("ends_at", &self.ends_at)
            .field("resumed_at", &self.resumed_at)
            .field("suspended_at", &self.suspended_at)
            .field("reminder_days", &self.reminder_days)
            .field("retrial_days", &self.retrial_days)
            .field("reminder_date", &self.reminder_date)
            .field("webhook_url", &redacted_webhook_url)
            .field("client_info", &self.client_info)
            .field("extra", &redacted_extra)
            .finish()
    }
}

/// Verified Protocol D Subscription Lifecycle webhook payload.
///
/// Implements a custom [`fmt::Debug`] that redacts [`SubscriptionWebhookEvent::hmac`]
/// as `"[REDACTED]"` so signatures are never leaked into logs or panic traces.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::protocol_d_subscription::{
///     SubscriptionData, SubscriptionTriggerType, SubscriptionWebhookEvent,
/// };
///
/// let event = SubscriptionWebhookEvent {
///     trigger_type: SubscriptionTriggerType::Suspended,
///     subscription_data: SubscriptionData {
///         id: 1264,
///         ..Default::default()
///     },
///     paymob_request_id: "df9e4ecf-12e0-4925-b258-65423f32bc98".to_owned(),
///     hmac: Some("secret_digest".to_owned()),
/// };
///
/// assert_eq!(event.canonical_message(), "suspendedfor1264");
/// let debug_out = format!("{event:?}");
/// assert!(debug_out.contains("[REDACTED]"));
/// assert!(!debug_out.contains("secret_digest"));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionWebhookEvent {
    /// Subscription lifecycle trigger type.
    pub trigger_type: SubscriptionTriggerType,
    /// Subscription metadata payload containing `id`.
    pub subscription_data: SubscriptionData,
    /// Unique Paymob request identifier suitable for webhook deduplication.
    pub paymob_request_id: String,
    /// Hex-encoded `HMAC-SHA512` digest embedded in the JSON request body.
    #[serde(default)]
    pub hmac: Option<String>,
}

impl SubscriptionWebhookEvent {
    /// Builds the canonical Protocol D HMAC input string:
    /// `"{trigger_type}for{subscription_data.id}"`.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::webhooks::protocol_d_subscription::{
    ///     SubscriptionData, SubscriptionTriggerType, SubscriptionWebhookEvent,
    /// };
    ///
    /// let event = SubscriptionWebhookEvent {
    ///     trigger_type: SubscriptionTriggerType::Created,
    ///     subscription_data: SubscriptionData {
    ///         id: 99,
    ///         ..Default::default()
    ///     },
    ///     paymob_request_id: "req-1".to_owned(),
    ///     hmac: None,
    /// };
    /// assert_eq!(event.canonical_message(), "Subscription Createdfor99");
    /// ```
    #[must_use]
    pub fn canonical_message(&self) -> String {
        canonical_subscription_message(&self.trigger_type, self.subscription_data.id)
    }
}

impl fmt::Debug for SubscriptionWebhookEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_hmac = self.hmac.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("SubscriptionWebhookEvent")
            .field("trigger_type", &self.trigger_type)
            .field("subscription_data", &self.subscription_data)
            .field("paymob_request_id", &self.paymob_request_id)
            .field("hmac", &redacted_hmac)
            .finish()
    }
}

/// Formats the canonical Protocol D HMAC input string
/// `"{trigger_type}for{subscription_id}"`.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::protocol_d_subscription::{
///     canonical_subscription_message, SubscriptionTriggerType,
/// };
///
/// assert_eq!(
///     canonical_subscription_message(&SubscriptionTriggerType::Suspended, 1264),
///     "suspendedfor1264",
/// );
/// ```
#[must_use]
pub fn canonical_subscription_message(
    trigger_type: &SubscriptionTriggerType,
    subscription_id: u64,
) -> String {
    format!("{}for{}", trigger_type.as_wire(), subscription_id)
}

impl super::verifier::PaymobWebhookEngine {
    /// Verifies a Protocol D Subscription Lifecycle webhook payload in constant time.
    ///
    /// Parses `raw_body` into [`SubscriptionWebhookEvent`], requires a non-empty
    /// `paymob_request_id` (returning [`super::verifier::WebhookError::MissingRequiredField`]
    /// if blank) and a non-empty `hmac` field in the JSON body (returning
    /// [`super::verifier::WebhookError::MissingBodyHmac`] if absent or blank),
    /// constructs `"{trigger_type}for{subscription_data.id}"`, and verifies the
    /// `HMAC-SHA512` signature via [`Self::verify_concatenated_str`].
    ///
    /// # Security Note
    ///
    /// Paymob's Protocol D HMAC authenticates **only** `(trigger_type, subscription_data.id)`.
    /// Other JSON body fields (including `paymob_request_id` and `subscription_data.state`) are
    /// not covered by the HMAC; callers **must** re-query the Paymob Subscription API for
    /// authoritative subscription state before mutating billing records.
    ///
    /// # Errors
    ///
    /// - [`super::verifier::WebhookError::InvalidJsonPayload`] if `raw_body` is not valid JSON
    ///   matching [`SubscriptionWebhookEvent`].
    /// - [`super::verifier::WebhookError::MissingRequiredField`] if `paymob_request_id` is empty.
    /// - [`super::verifier::WebhookError::MissingBodyHmac`] if `body.hmac` is `None` or empty.
    /// - [`super::verifier::WebhookError::MalformedSignatureHex`] if `body.hmac` is not valid
    ///   128-character hex.
    /// - [`super::verifier::WebhookError::SignatureMismatch`] if the computed digest does not
    ///   match `body.hmac` in constant time.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use some_paymob::webhooks::verifier::PaymobWebhookEngine;
    ///
    /// # fn example() -> Result<(), some_paymob::webhooks::verifier::WebhookError> {
    /// let engine = PaymobWebhookEngine::new("your_hmac_secret")?;
    /// let raw_body = r#"{
    ///     "paymob_request_id": "df9e4ecf-12e0-4925-b258-65423f32bc98",
    ///     "subscription_data": { "id": 1264 },
    ///     "trigger_type": "suspended",
    ///     "hmac": "dd5b3018888d9f98574cd180793db10d969b522e08c62baf2ea33357d1546b567b7fd79760e90046e90eaacf30024ede5539cbd0748bd9e6c005faf5117e0e7b"
    /// }"#;
    /// let event = engine.verify_subscription(raw_body)?;
    /// assert_eq!(event.subscription_data.id, 1264);
    /// # Ok(())
    /// # }
    /// ```
    pub fn verify_subscription(
        &self,
        raw_body: &str,
    ) -> super::verifier::WebhookResult<SubscriptionWebhookEvent> {
        let event: SubscriptionWebhookEvent = super::verifier::parse_webhook_json_str(raw_body)?;
        if event.paymob_request_id.trim().is_empty() {
            return Err(super::verifier::WebhookError::MissingRequiredField(
                "paymob_request_id".into(),
            ));
        }
        let hmac_hex = event
            .hmac
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .ok_or(super::verifier::WebhookError::MissingBodyHmac)?;
        let canonical = event.canonical_message();
        self.verify_concatenated_str(&canonical, hmac_hex)?;
        Ok(event)
    }

    /// Verifies a Protocol D Subscription Lifecycle webhook from raw request bytes.
    ///
    /// Validates that `raw_body` is valid UTF-8 before delegating to
    /// [`Self::verify_subscription`].
    ///
    /// # Errors
    ///
    /// Returns [`super::verifier::WebhookError::InvalidJsonPayload`] if `raw_body` is not
    /// valid UTF-8, or any error returned by [`Self::verify_subscription`].
    pub fn verify_subscription_bytes(
        &self,
        raw_body: &[u8],
    ) -> super::verifier::WebhookResult<SubscriptionWebhookEvent> {
        let raw_str = super::verifier::decode_webhook_utf8(raw_body)?;
        self.verify_subscription(raw_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    use hmac::{Hmac, Mac};
    use sha2::Sha512;

    const OFFICIAL_SAMPLE_HMAC: &str = "dd5b3018888d9f98574cd180793db10d969b522e08c62baf2ea33357d1546b567b7fd79760e90046e90eaacf30024ede5539cbd0748bd9e6c005faf5117e0e7b";

    const OFFICIAL_SAMPLE_JSON: &str = r#"{
        "paymob_request_id": "df9e4ecf-12e0-4925-b258-65423f32bc98",
        "subscription_data": {
            "id": 1264,
            "client_info": {
                "email": "test@test.com",
                "full_name": "mo ay",
                "phone_number": "01010101010"
            },
            "frequency": 365,
            "created_at": "2024-12-03T22:11:02.280164",
            "updated_at": "2024-12-03T22:11:02.280179",
            "name": "Testplan 3",
            "reminder_days": null,
            "retrial_days": null,
            "plan_id": 1186,
            "state": "suspended",
            "amount_cents": 330,
            "starts_at": "2024-12-20",
            "next_billing": "2024-12-20",
            "reminder_date": null,
            "ends_at": null,
            "resumed_at": null,
            "suspended_at": "2024-12-03",
            "webhook_url": "https://webhook.site/a16ba9d5-4f4a-47dc-8005-e6ec2d197f26",
            "integration": 4565330,
            "initial_transaction": 241322967
        },
        "trigger_type": "suspended",
        "hmac": "dd5b3018888d9f98574cd180793db10d969b522e08c62baf2ea33357d1546b567b7fd79760e90046e90eaacf30024ede5539cbd0748bd9e6c005faf5117e0e7b"
    }"#;

    fn sign_hmac_sha512(secret: &str, msg: &str) -> String {
        let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes()).expect("valid key");
        mac.update(msg.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn test_all_12_trigger_types_roundtrip() {
        assert_eq!(KNOWN_SUBSCRIPTION_TRIGGERS.len(), 12);
        for (wire, expected_variant) in KNOWN_SUBSCRIPTION_TRIGGERS {
            let parsed = SubscriptionTriggerType::from_wire(wire);
            assert_eq!((&parsed, parsed.is_known()), (expected_variant, true));
            assert_eq!(
                (parsed.as_wire(), parsed.to_string().as_str()),
                (*wire, *wire)
            );

            let serialized = serde_json::to_string(&parsed).expect("serialize trigger");
            assert_eq!(serialized, format!("\"{wire}\""));
            let deserialized: SubscriptionTriggerType =
                serde_json::from_str(&serialized).expect("deserialize trigger");
            assert_eq!(&deserialized, expected_variant);
        }
    }

    #[test]
    fn test_unknown_trigger_type_preserved_and_verified() {
        let secret = "paymob_test_hmac_secret";
        let engine = PaymobWebhookEngine::new(secret).expect("valid test secret");
        let trigger = SubscriptionTriggerType::from_wire("custom_future_trigger");
        assert!(!trigger.is_known());
        assert_eq!(trigger.as_wire(), "custom_future_trigger");

        let sig = sign_hmac_sha512(secret, "custom_future_triggerfor1264");
        let body = format!(
            "{{\"paymob_request_id\":\"req-9\",\"subscription_data\":{{\"id\":1264}},\
             \"trigger_type\":\"custom_future_trigger\",\"hmac\":\"{sig}\"}}"
        );
        let verified = engine
            .verify_subscription(&body)
            .expect("unknown trigger must verify");
        assert_eq!(verified.trigger_type, trigger);
    }

    #[test]
    fn test_official_test_vector_suspendedfor1264_fields() {
        let event: SubscriptionWebhookEvent =
            serde_json::from_str(OFFICIAL_SAMPLE_JSON).expect("parse official sample");

        assert_eq!(event.trigger_type, SubscriptionTriggerType::Suspended);
        assert_eq!(event.subscription_data.id, 1264);
        assert_eq!(event.subscription_data.plan_id, Some(1186));
        assert_eq!(event.subscription_data.amount_cents, Some(330));
        assert_eq!(
            event.paymob_request_id,
            "df9e4ecf-12e0-4925-b258-65423f32bc98"
        );
        assert_eq!(event.canonical_message(), "suspendedfor1264");
    }

    #[test]
    fn test_official_test_vector_debug_redaction_and_none_client_info() {
        let event: SubscriptionWebhookEvent =
            serde_json::from_str(OFFICIAL_SAMPLE_JSON).expect("parse official sample");
        let debug_str = format!("{event:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains(OFFICIAL_SAMPLE_HMAC));
        assert!(!debug_str.contains("test@test.com") && !debug_str.contains("mo ay"));
        assert!(!debug_str.contains("01010101010"));

        let empty_info = SubscriptionClientInfo::default();
        assert!(format!("{empty_info:?}").contains("email: None"));
    }

    #[test]
    fn test_verify_subscription_all_12_triggers_and_bytes() {
        let secret = "paymob_test_hmac_secret";
        let engine = PaymobWebhookEngine::new(secret).expect("valid test secret");

        for (wire, expected_variant) in KNOWN_SUBSCRIPTION_TRIGGERS {
            let canonical = format!("{wire}for1264");
            let sig = sign_hmac_sha512(secret, &canonical);
            let body = format!(
                "{{\"paymob_request_id\":\"req-1264\",\"subscription_data\":{{\"id\":1264}},\
                 \"trigger_type\":\"{wire}\",\"hmac\":\"{sig}\"}}"
            );
            let verified = engine
                .verify_subscription_bytes(body.as_bytes())
                .expect("valid signature must verify");
            assert_eq!(&verified.trigger_type, expected_variant);
            assert_eq!(verified.canonical_message(), canonical);
        }
    }

    #[test]
    fn test_verify_subscription_rejects_missing_or_blank_hmac_and_request_id() {
        let engine =
            PaymobWebhookEngine::new("paymob_test_hmac_secret").expect("valid test secret");
        let missing_hmac = "{\"paymob_request_id\":\"req-1\",\
            \"subscription_data\":{\"id\":1264},\"trigger_type\":\"suspended\"}";
        let blank_hmac = "{\"paymob_request_id\":\"req-1\",\
            \"subscription_data\":{\"id\":1264},\"trigger_type\":\"suspended\",\"hmac\":\"   \"}";
        let blank_req_id = "{\"paymob_request_id\":\"  \",\
            \"subscription_data\":{\"id\":1264},\"trigger_type\":\"suspended\",\"hmac\":\"dd5b\"}";

        assert_eq!(
            engine.verify_subscription(missing_hmac),
            Err(WebhookError::MissingBodyHmac)
        );
        assert_eq!(
            engine.verify_subscription(blank_hmac),
            Err(WebhookError::MissingBodyHmac)
        );
        assert_eq!(
            engine.verify_subscription(blank_req_id),
            Err(WebhookError::MissingRequiredField(
                "paymob_request_id".into()
            ))
        );
    }

    #[test]
    fn test_verify_subscription_rejects_tampered_fields_and_invalid_inputs() {
        let secret = "paymob_test_hmac_secret";
        let engine = PaymobWebhookEngine::new(secret).expect("valid test secret");
        let sig = sign_hmac_sha512(secret, "suspendedfor1264");
        let tampered_id = format!(
            "{{\"paymob_request_id\":\"req-1\",\"subscription_data\":{{\"id\":9999}},\
             \"trigger_type\":\"suspended\",\"hmac\":\"{sig}\"}}"
        );
        let bad_hex = "{\"paymob_request_id\":\"req-1\",\"subscription_data\":{\"id\":1264},\
            \"trigger_type\":\"suspended\",\"hmac\":\"not-valid-hex\"}";

        assert_eq!(
            engine.verify_subscription(OFFICIAL_SAMPLE_JSON),
            Err(WebhookError::SignatureMismatch)
        );
        assert_eq!(
            engine.verify_subscription(&tampered_id),
            Err(WebhookError::SignatureMismatch)
        );
        assert_eq!(
            engine.verify_subscription(bad_hex),
            Err(WebhookError::MalformedSignatureHex)
        );
        assert!(matches!(
            engine.verify_subscription_bytes(&[0xff, 0xfe]),
            Err(WebhookError::InvalidJsonPayload(_))
        ));
    }
}
