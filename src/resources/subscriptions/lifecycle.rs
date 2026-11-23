#![forbid(unsafe_code)]
//! Unit 4.3.2 — [`SubscriptionsService`] lifecycle operations (`US-4.3.0`).
//!
//! Provides Paymob subscription enrollment via Intention 3DS (`POST /v1/intention/`
//! under Regime 1 `Token <secret_key>`) and Regime 2 (`Bearer <auth_token>`)
//! lifecycle operations (`retrieve`, `list`, `update`, `suspend`, `resume`,
//! `cancel`) alongside `.plans()` and `.cards()` sub-service accessors.

use std::fmt;

use reqwest::Method;
use reqwest::header::AUTHORIZATION;
use secrecy::SecretString;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub use super::models::{
    KNOWN_SUBSCRIPTION_STATES, Subscription, SubscriptionListFilter, SubscriptionState,
};
use super::{decode_subscription_response, validate_positive_id};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::core::pagination::PaginatedResponse;
use crate::core::types::{Currency, MinorUnitAmount};

const SUBSCRIPTIONS_BASE_PATH: &str = "/api/acceptance/subscriptions";
const INTENTION_CREATE_PATH: &str = "/v1/intention/";

/// Request payload for enrolling a subscription via Intention 3DS (`POST /v1/intention/`).
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::{Currency, MinorUnitAmount};
/// use some_paymob::resources::subscriptions::lifecycle::CreateSubscriptionParams;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let params = CreateSubscriptionParams::new(
///     88,
///     MinorUnitAmount::new(50_000),
///     Currency::from_code("EGP"),
///     vec![42001],
/// )
/// .with_special_reference("sub_ref_1001");
/// params.validate()?;
/// assert_eq!(params.subscription_plan_id, 88);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CreateSubscriptionParams {
    /// Subscription plan identifier to enroll the customer into.
    pub subscription_plan_id: u64,
    /// Initial 3DS charge amount in integer minor units.
    pub amount: MinorUnitAmount,
    /// ISO-4217 currency code for the enrollment charge.
    pub currency: Currency,
    /// One or more Paymob 3DS card integration IDs.
    pub payment_methods: Vec<u64>,
    /// Optional customer billing metadata required by Paymob Intention API.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub billing_data: Option<Value>,
    /// Optional merchant-defined idempotency or order reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub special_reference: Option<String>,
    /// Optional webhook callback URL for transaction notifications.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification_url: Option<String>,
    /// Optional 3DS browser redirect URL after checkout completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redirection_url: Option<String>,
    /// Optional extra JSON metadata forwarded with the intention.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<Value>,
}

impl fmt::Debug for CreateSubscriptionParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateSubscriptionParams")
            .field("subscription_plan_id", &self.subscription_plan_id)
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("payment_methods", &self.payment_methods)
            .field(
                "billing_data",
                &self.billing_data.as_ref().map(|_| "[REDACTED]"),
            )
            .field("special_reference", &self.special_reference)
            .field("notification_url", &self.notification_url)
            .field("redirection_url", &self.redirection_url)
            .field("extras", &self.extras.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl CreateSubscriptionParams {
    /// Constructs a new [`CreateSubscriptionParams`] for Intention 3DS enrollment.
    #[must_use]
    pub fn new(
        subscription_plan_id: u64,
        amount: MinorUnitAmount,
        currency: Currency,
        payment_methods: Vec<u64>,
    ) -> Self {
        Self {
            subscription_plan_id,
            amount,
            currency,
            payment_methods,
            billing_data: None,
            special_reference: None,
            notification_url: None,
            redirection_url: None,
            extras: None,
        }
    }

    /// Attaches customer `billing_data` JSON to the enrollment intention.
    #[must_use]
    pub fn with_billing_data(mut self, billing_data: Value) -> Self {
        self.billing_data = Some(billing_data);
        self
    }

    /// Sets `special_reference` on the enrollment intention.
    #[must_use]
    pub fn with_special_reference(mut self, reference: impl Into<String>) -> Self {
        self.special_reference = Some(reference.into());
        self
    }

    /// Sets `notification_url` for asynchronous intention callbacks.
    #[must_use]
    pub fn with_notification_url(mut self, url: impl Into<String>) -> Self {
        self.notification_url = Some(url.into());
        self
    }

    /// Sets `redirection_url` for post-3DS browser redirection.
    #[must_use]
    pub fn with_redirection_url(mut self, url: impl Into<String>) -> Self {
        self.redirection_url = Some(url.into());
        self
    }

    /// Attaches `extras` metadata JSON to the enrollment intention.
    #[must_use]
    pub fn with_extras(mut self, extras: Value) -> Self {
        self.extras = Some(extras);
        self
    }

    /// Validates all required enrollment fields and optional callback URLs.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `subscription_plan_id == 0`,
    /// `amount` is zero, `payment_methods` is empty, `currency` is empty, or an
    /// optional URL is malformed.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_positive_id("subscription_plan_id", self.subscription_plan_id)?;
        if self.amount.is_zero() {
            return Err(PaymobError::ValidationError {
                field: "amount",
                reason: "enrollment amount must be greater than zero".to_owned(),
            });
        }
        if self.currency.as_str().trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "currency",
                reason: "currency must not be empty".to_owned(),
            });
        }
        if self.payment_methods.is_empty() || !self.payment_methods.iter().all(|&id| id > 0) {
            return Err(PaymobError::ValidationError {
                field: "payment_methods",
                reason: "payment_methods must contain only non-zero integration IDs".to_owned(),
            });
        }
        validate_optional_http_url("notification_url", self.notification_url.as_deref())?;
        validate_optional_http_url("redirection_url", self.redirection_url.as_deref())?;
        Ok(())
    }
}

/// Response returned by `POST /v1/intention/` during subscription 3DS enrollment.
///
/// The `client_secret` field is wrapped in [`SecretString`] and rendered as
/// `"[REDACTED]"` in [`fmt::Debug`] output.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::lifecycle::SubscriptionEnrollmentResponse;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let json = r#"{
///     "id": "pi_test_123",
///     "client_secret": "egy_csk_test_secret_abc",
///     "intention_order_id": 556677,
///     "status": "intended"
/// }"#;
/// let resp: SubscriptionEnrollmentResponse = serde_json::from_str(json)?;
/// let dbg = format!("{resp:?}");
/// assert!(dbg.contains("[REDACTED]"));
/// assert!(!dbg.contains("egy_csk_test_secret_abc"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Deserialize)]
pub struct SubscriptionEnrollmentResponse {
    /// Paymob Payment Intention identifier (e.g., `pi_test_...`).
    pub id: String,
    /// Sensitive client secret passed to Unified Checkout (redacted in `Debug`).
    pub client_secret: SecretString,
    /// Associated Paymob order identifier, if created.
    #[serde(default)]
    pub intention_order_id: Option<u64>,
    /// Current intention status returned by Paymob.
    #[serde(default)]
    pub status: Option<String>,
    /// Linked subscription plan identifier, if echoed by Paymob.
    #[serde(default)]
    pub subscription_plan_id: Option<u64>,
    /// Raw payment keys returned by the Intention API.
    #[serde(default)]
    pub payment_keys: Vec<Value>,
}

impl Drop for SubscriptionEnrollmentResponse {
    fn drop(&mut self) {
        for key in &mut self.payment_keys {
            zeroize_json_value(key);
        }
        self.payment_keys.clear();
    }
}

impl ZeroizeOnDrop for SubscriptionEnrollmentResponse {}

fn zeroize_json_value(value: &mut Value) {
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

impl fmt::Debug for SubscriptionEnrollmentResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionEnrollmentResponse")
            .field("id", &self.id)
            .field("client_secret", &"[REDACTED]")
            .field("intention_order_id", &self.intention_order_id)
            .field("status", &self.status)
            .field("subscription_plan_id", &self.subscription_plan_id)
            .field("payment_keys_count", &self.payment_keys.len())
            .finish()
    }
}

/// Request payload for updating a subscription (`PUT /api/acceptance/subscriptions/{id}`).
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::resources::subscriptions::lifecycle::UpdateSubscriptionParams;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let params = UpdateSubscriptionParams::new()
///     .with_amount_cents(MinorUnitAmount::new(75_000))
///     .with_reminder_days(3);
/// params.validate()?;
/// assert!(!params.is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UpdateSubscriptionParams {
    /// Updated recurring charge amount in integer minor units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<MinorUnitAmount>,
    /// Updated subscription plan identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_id: Option<u64>,
    /// Updated ISO-8601 start timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<String>,
    /// Updated ISO-8601 end timestamp.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<String>,
    /// Updated number of days before billing to send a reminder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reminder_days: Option<u32>,
    /// Updated number of retry days after a failed deduction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrial_days: Option<u32>,
    /// Updated subscription webhook URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Updated active flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
}

impl UpdateSubscriptionParams {
    /// Creates an empty [`UpdateSubscriptionParams`] builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `amount_cents` using integer minor units.
    #[must_use]
    pub const fn with_amount_cents(mut self, amount: MinorUnitAmount) -> Self {
        self.amount_cents = Some(amount);
        self
    }

    /// Sets `plan_id` to migrate or update the subscription plan.
    #[must_use]
    pub const fn with_plan_id(mut self, plan_id: u64) -> Self {
        self.plan_id = Some(plan_id);
        self
    }

    /// Sets `starts_at` ISO-8601 timestamp.
    #[must_use]
    pub fn with_starts_at(mut self, starts_at: impl Into<String>) -> Self {
        self.starts_at = Some(starts_at.into());
        self
    }

    /// Sets `ends_at` ISO-8601 timestamp.
    #[must_use]
    pub fn with_ends_at(mut self, ends_at: impl Into<String>) -> Self {
        self.ends_at = Some(ends_at.into());
        self
    }

    /// Sets `reminder_days`.
    #[must_use]
    pub const fn with_reminder_days(mut self, days: u32) -> Self {
        self.reminder_days = Some(days);
        self
    }

    /// Sets `retrial_days`.
    #[must_use]
    pub const fn with_retrial_days(mut self, days: u32) -> Self {
        self.retrial_days = Some(days);
        self
    }

    /// Sets `webhook_url`.
    #[must_use]
    pub fn with_webhook_url(mut self, url: impl Into<String>) -> Self {
        self.webhook_url = Some(url.into());
        self
    }

    /// Sets `is_active`.
    #[must_use]
    pub const fn with_is_active(mut self, active: bool) -> Self {
        self.is_active = Some(active);
        self
    }

    /// Returns `true` when no update fields have been populated.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        [
            self.amount_cents.is_none(),
            self.plan_id.is_none(),
            self.starts_at.is_none(),
            self.ends_at.is_none(),
            self.reminder_days.is_none(),
            self.retrial_days.is_none(),
            self.webhook_url.is_none(),
            self.is_active.is_none(),
        ]
        .into_iter()
        .all(std::convert::identity)
    }

    /// Validates that at least one field is set and all provided values are valid.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if no fields are set, `plan_id == 0`,
    /// `amount_cents == 0`, or `webhook_url` is not a valid `http(s)://` URL.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "params",
                reason: "at least one subscription update field must be set".to_owned(),
            });
        }
        if let Some(plan_id) = self.plan_id {
            validate_positive_id("plan_id", plan_id)?;
        }
        if let Some(amount) = self.amount_cents
            && amount.is_zero()
        {
            return Err(PaymobError::ValidationError {
                field: "amount_cents",
                reason: "updated amount_cents must be greater than zero".to_owned(),
            });
        }
        validate_optional_http_url("webhook_url", self.webhook_url.as_deref())
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SubscriptionListEnvelope {
    Paginated(PaginatedResponse<Subscription>),
    Array(Vec<Subscription>),
}

impl SubscriptionListEnvelope {
    fn into_paginated(self) -> PaginatedResponse<Subscription> {
        match self {
            Self::Paginated(page) => page,
            Self::Array(results) => PaginatedResponse {
                count: results.len() as u64,
                next: None,
                previous: None,
                results,
            },
        }
    }
}

/// Accessor type alias for subscription plans (`paymob.subscriptions().plans()`).
pub type SubscriptionPlansAccessor = super::plans_service::SubscriptionPlansService;

/// Accessor type alias for subscription card vault operations (`paymob.subscriptions().cards()`).
pub type SubscriptionCardsAccessor = super::cards::SubscriptionCardsService;

/// Service handle for subscription plans, lifecycle, card vault, and history (`US-4.3.0`).
///
/// Accessed via `paymob.subscriptions()`. Lifecycle operations execute under
/// Regime 2 (`Authorization: Bearer <auth_token>`), while [`Self::create`]
/// enrolls subscriptions via Intention 3DS (`POST /v1/intention/`) under
/// Regime 1 (`Authorization: Token <secret_key>`).
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::ApiKey;
/// use some_paymob::core::region::PaymobRegion;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .api_key(ApiKey::new("egy_api_key_example")?)
///     .build()?;
/// let client = PaymobClient::new(config)?;
/// let sub = client.subscriptions().retrieve(1264).await?;
/// println!("subscription {} state: {}", sub.id, sub.state);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SubscriptionsService {
    client: PaymobClient,
}

impl SubscriptionsService {
    /// Creates a new [`SubscriptionsService`] bound to `client`.
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        Self { client }
    }

    #[cfg(test)]
    fn with_test_http(client: PaymobClient) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub fn client(&self) -> &PaymobClient {
        &self.client
    }

    /// Returns a [`SubscriptionPlansService`](super::plans_service::SubscriptionPlansService) bound to this client.
    #[must_use]
    pub fn plans(&self) -> SubscriptionPlansAccessor {
        SubscriptionPlansAccessor::new(self.client.clone())
    }

    /// Enrolls a customer into a subscription via Intention 3DS (`POST /v1/intention/`).
    ///
    /// Executes under Regime 1 (`Authorization: Token <secret_key>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `params` is invalid or `secret_key`
    /// is missing from [`ClientConfig`](crate::core::config::ClientConfig), or
    /// [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::core::types::{Currency, MinorUnitAmount};
    /// use some_paymob::resources::subscriptions::lifecycle::CreateSubscriptionParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let params = CreateSubscriptionParams::new(
    ///     88,
    ///     MinorUnitAmount::new(50_000),
    ///     Currency::from_code("EGP"),
    ///     vec![42001],
    /// );
    /// let enrolled = client.subscriptions().create(&params).await?;
    /// println!("intention id: {}", enrolled.id);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn create(
        &self,
        params: &CreateSubscriptionParams,
    ) -> Result<SubscriptionEnrollmentResponse, PaymobError> {
        params.validate()?;
        if self.client.config().secret_key().is_none() {
            return Err(PaymobError::ValidationError {
                field: "secret_key",
                reason: "Paymob secret_key is required for Intention 3DS enrollment".to_owned(),
            });
        }
        let auth_header = self
            .client
            .regime1_token_header("Paymob secret_key is required for Intention 3DS enrollment")?;
        let url = self.client.accept_url(INTENTION_CREATE_PATH)?;
        let request = HttpRequest::new(Method::POST, url.as_str())?
            .with_header(AUTHORIZATION, auth_header)
            .with_json(params)?;
        let response = self.client.execute_request(&request).await?;
        decode_subscription_response(response)
    }

    /// Retrieves details for subscription `sub_id` (`GET /api/acceptance/subscriptions/{id}`).
    ///
    /// Executes under Regime 2 (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing,
    /// [`PaymobError::AuthenticationError`] on invalid credentials, or
    /// [`PaymobError::ApiError`] (e.g. `404 {"detail": "not found."}`) on gateway failure.
    pub async fn retrieve(&self, sub_id: u64) -> Result<Subscription, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}");
        self.execute_bearer_json::<(), Subscription>(Method::GET, &path, None)
            .await
    }

    /// Lists subscriptions matching `filters` (`GET /api/acceptance/subscriptions`).
    ///
    /// Executes under Regime 2 (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `filters.page` is `Some(0)` or
    /// `api_key` is missing, or [`PaymobError::ApiError`] / [`PaymobError::TransportError`]
    /// on gateway failure.
    pub async fn list(
        &self,
        filters: &SubscriptionListFilter,
    ) -> Result<PaginatedResponse<Subscription>, PaymobError> {
        filters.validate()?;
        let query = filters.to_query_string();
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}{query}");
        let envelope: SubscriptionListEnvelope = self
            .execute_bearer_json::<(), SubscriptionListEnvelope>(Method::GET, &path, None)
            .await?;
        Ok(envelope.into_paginated())
    }

    /// Updates subscription `sub_id` (`PUT /api/acceptance/subscriptions/{id}`).
    ///
    /// Executes under Regime 2 (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0`, `params` is empty/invalid,
    /// or `api_key` is missing, or gateway/transport errors.
    pub async fn update(
        &self,
        sub_id: u64,
        params: &UpdateSubscriptionParams,
    ) -> Result<Subscription, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        params.validate()?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}");
        self.execute_bearer_json(Method::PUT, &path, Some(params))
            .await
    }

    /// Suspends active subscription `sub_id` (`POST /api/acceptance/subscriptions/{id}/suspend`).
    ///
    /// Executes under Regime 2 (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing,
    /// or [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    pub async fn suspend(&self, sub_id: u64) -> Result<Subscription, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}/suspend");
        self.execute_bearer_json::<(), Subscription>(Method::POST, &path, None)
            .await
    }

    /// Resumes suspended subscription `sub_id` (`POST /api/acceptance/subscriptions/{id}/resume`).
    ///
    /// Executes under Regime 2 (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing,
    /// or [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    pub async fn resume(&self, sub_id: u64) -> Result<Subscription, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}/resume");
        self.execute_bearer_json::<(), Subscription>(Method::POST, &path, None)
            .await
    }

    /// Cancels subscription `sub_id` (`POST /api/acceptance/subscriptions/{id}/cancel`).
    ///
    /// Executes under Regime 2 (`Authorization: Bearer <auth_token>`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing,
    /// or [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    pub async fn cancel(&self, sub_id: u64) -> Result<Subscription, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("{SUBSCRIPTIONS_BASE_PATH}/{sub_id}/cancel");
        self.execute_bearer_json::<(), Subscription>(Method::POST, &path, None)
            .await
    }

    async fn execute_bearer_json<Req, Resp>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Req>,
    ) -> Result<Resp, PaymobError>
    where
        Req: Serialize + ?Sized,
        Resp: DeserializeOwned,
    {
        super::execute_subscription_bearer_json(&self.client, method, path, body).await
    }
}

fn validate_optional_http_url(field: &'static str, raw: Option<&str>) -> Result<(), PaymobError> {
    let Some(raw_url) = raw else {
        return Ok(());
    };
    super::validate_webhook_url(field, raw_url).map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::{ApiKey, SecretKey};
    use crate::core::region::PaymobRegion;

    const TEST_API_KEY: &str = "test-paymob-api-key-value";
    const TEST_SECRET_KEY: &str = "egy_sk_test_secretvalue";
    const TEST_JWT: &str = "eyJ.test.jwt.token";

    fn mock_client(base_uri: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_uri.to_owned(),
            checkout_base_url: format!("{base_uri}/unifiedcheckout/"),
            payouts_base_url: base_uri.to_owned(),
            payouts_staging_base_url: base_uri.to_owned(),
        };
        let config = ClientConfig::builder()
            .region(region)
            .secret_key(SecretKey::new(TEST_SECRET_KEY).expect("valid secret key"))
            .api_key(ApiKey::new(TEST_API_KEY).expect("valid api key"))
            .build()
            .expect("valid mock client config");
        PaymobClient::new(config).expect("client should build")
    }

    async fn mount_auth_mock(server: &MockServer, token: &str) {
        let token_owned = token.to_owned();
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .and(body_json(json!({ "api_key": TEST_API_KEY })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({ "token": token_owned })))
            .mount(server)
            .await;
    }

    fn sample_subscription_json(state: &str) -> Value {
        json!({
            "id": 1264,
            "plan_id": 88,
            "state": state,
            "initial_transaction": 998877,
            "amount_cents": 50000,
            "starts_at": "2026-11-01T00:00:00Z",
            "next_billing": "2026-12-01T00:00:00Z",
            "reminder_date": null,
            "ends_at": null,
            "resumed_at": null,
            "suspended_at": null,
            "reactivated_at": null,
            "created_at": "2026-11-01T00:00:00Z"
        })
    }

    #[tokio::test]
    async fn tc_4_3_2_create_subscription_via_intention_3ds_enrollment() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/intention/"))
            .and(header("authorization", &format!("Token {TEST_SECRET_KEY}")))
            .and(body_json(json!({
                "subscription_plan_id": 88,
                "amount": 50000,
                "currency": "EGP",
                "payment_methods": [42001],
                "special_reference": "sub_enroll_001"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "id": "pi_test_sub_001",
                "client_secret": "egy_csk_test_secret_999",
                "intention_order_id": 778899,
                "status": "intended",
                "subscription_plan_id": 88
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionsService::with_test_http(mock_client(&server.uri()));
        let params = CreateSubscriptionParams::new(
            88,
            MinorUnitAmount::new(50_000),
            Currency::from_code("EGP"),
            vec![42001],
        )
        .with_special_reference("sub_enroll_001");
        let resp = service
            .create(&params)
            .await
            .expect("enrollment should succeed");

        assert_eq!(resp.id, "pi_test_sub_001");
        assert_eq!(resp.subscription_plan_id, Some(88));
        let dbg = format!("{resp:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("egy_csk_test_secret_999"));
    }

    #[tokio::test]
    async fn tc_4_3_2_create_validation_rejects_invalid_inputs() {
        let server = MockServer::start().await;
        let service = SubscriptionsService::with_test_http(mock_client(&server.uri()));

        let zero_plan = CreateSubscriptionParams::new(
            0,
            MinorUnitAmount::new(50_000),
            Currency::from_code("EGP"),
            vec![42001],
        );
        assert!(matches!(
            service.create(&zero_plan).await,
            Err(PaymobError::ValidationError {
                field: "subscription_plan_id",
                ..
            })
        ));

        let zero_amt = CreateSubscriptionParams::new(
            88,
            MinorUnitAmount::ZERO,
            Currency::from_code("EGP"),
            vec![42001],
        );
        assert!(matches!(
            service.create(&zero_amt).await,
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));

        let no_methods = CreateSubscriptionParams::new(
            88,
            MinorUnitAmount::new(1000),
            Currency::from_code("EGP"),
            vec![],
        );
        assert!(matches!(
            service.create(&no_methods).await,
            Err(PaymobError::ValidationError {
                field: "payment_methods",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn tc_4_3_2_retrieve_subscription_and_404_mapping() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264"))
            .and(header("authorization", &format!("Bearer {TEST_JWT}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(sample_subscription_json("active")),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/9999"))
            .respond_with(
                ResponseTemplate::new(404).set_body_json(json!({ "detail": "not found." })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionsService::with_test_http(mock_client(&server.uri()));
        let sub = service
            .retrieve(1264)
            .await
            .expect("retrieve should succeed");
        assert_eq!(sub.id, 1264);
        assert_eq!(sub.state, SubscriptionState::Active);

        let err = service
            .retrieve(9999)
            .await
            .expect_err("404 should map to ApiError");
        assert!(matches!(err, PaymobError::ApiError { status: 404, .. }));
    }

    #[tokio::test]
    async fn tc_4_3_2_list_subscriptions_with_filters() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions"))
            .and(query_param("plan_id", "88"))
            .and(query_param("state", "active"))
            .and(query_param("page", "2"))
            .and(header("authorization", &format!("Bearer {TEST_JWT}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count": 1,
                "next": null,
                "previous": null,
                "results": [sample_subscription_json("active")]
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionsService::with_test_http(mock_client(&server.uri()));
        let filters = SubscriptionListFilter::new()
            .plan_id(88)
            .state(SubscriptionState::Active)
            .page(2);
        let page = service.list(&filters).await.expect("list should succeed");
        assert_eq!(page.count, 1);
        assert_eq!(page.results.len(), 1);
        assert_eq!(page.results[0].id, 1264);
    }

    #[tokio::test]
    async fn tc_4_3_2_update_subscription_and_reject_empty_params() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        Mock::given(method("PUT"))
            .and(path("/api/acceptance/subscriptions/1264"))
            .and(header("authorization", &format!("Bearer {TEST_JWT}")))
            .and(body_json(
                json!({ "amount_cents": 75000, "reminder_days": 3 }),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 1264,
                "plan_id": 88,
                "state": "active",
                "amount_cents": 75000,
                "created_at": "2026-11-01T00:00:00Z"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionsService::with_test_http(mock_client(&server.uri()));
        let empty = UpdateSubscriptionParams::new();
        assert!(matches!(
            service.update(1264, &empty).await,
            Err(PaymobError::ValidationError {
                field: "params",
                ..
            })
        ));

        let params = UpdateSubscriptionParams::new()
            .with_amount_cents(MinorUnitAmount::new(75_000))
            .with_reminder_days(3);
        let updated = service
            .update(1264, &params)
            .await
            .expect("update should succeed");
        assert_eq!(updated.amount_cents, MinorUnitAmount::new(75_000));
    }

    #[tokio::test]
    async fn tc_4_3_2_suspend_resume_cancel_transitions() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, TEST_JWT).await;
        for (action, state) in [
            ("suspend", "suspended"),
            ("resume", "active"),
            ("cancel", "canceled"),
        ] {
            let expected_path = format!("/api/acceptance/subscriptions/1264/{action}");
            Mock::given(method("POST"))
                .and(path(expected_path))
                .and(header("authorization", &format!("Bearer {TEST_JWT}")))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(sample_subscription_json(state)),
                )
                .expect(1)
                .mount(&server)
                .await;
        }

        let service = SubscriptionsService::with_test_http(mock_client(&server.uri()));
        assert_eq!(
            service.suspend(1264).await.expect("suspend").state,
            SubscriptionState::Suspended
        );
        assert_eq!(
            service.resume(1264).await.expect("resume").state,
            SubscriptionState::Active
        );
        assert_eq!(
            service.cancel(1264).await.expect("cancel").state,
            SubscriptionState::Canceled
        );
    }

    #[tokio::test]
    async fn tc_4_3_2_401_evicts_stale_token_and_retries() {
        let server = MockServer::start().await;
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let auth_counter = Arc::clone(&auth_calls);
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(move |_req: &Request| {
                let n = auth_counter.fetch_add(1, Ordering::SeqCst);
                let tok = if n == 0 { "stale-jwt" } else { "fresh-jwt" };
                ResponseTemplate::new(201).set_body_json(json!({ "token": tok }))
            })
            .expect(2)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscriptions/1264/suspend"))
            .and(header("authorization", "Bearer stale-jwt"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "detail": "Incorrect credentials"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscriptions/1264/suspend"))
            .and(header("authorization", "Bearer fresh-jwt"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(sample_subscription_json("suspended")),
            )
            .expect(1)
            .mount(&server)
            .await;

        let service = SubscriptionsService::with_test_http(mock_client(&server.uri()));
        let sub = service
            .suspend(1264)
            .await
            .expect("retry with fresh token should succeed");
        assert_eq!(sub.state, SubscriptionState::Suspended);
        assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn tc_4_3_2_plans_and_cards_accessors_and_zero_id_guard() {
        let client = mock_client("https://accept.paymob.com");
        let service = SubscriptionsService::new(client.clone());
        assert!(service.plans().client().ptr_eq(&client));
        assert!(service.cards().client().ptr_eq(&client));
        assert!(matches!(
            validate_positive_id("sub_id", 0),
            Err(PaymobError::ValidationError {
                field: "sub_id",
                ..
            })
        ));
    }
}
