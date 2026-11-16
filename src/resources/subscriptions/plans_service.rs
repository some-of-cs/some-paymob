#![forbid(unsafe_code)]
//! Subscription plans CRUD and lifecycle service (`US-4.2.0`, Unit 3).
//!
//! Provides `SubscriptionPlansService` for creating, updating, listing,
//! suspending, and resuming Paymob subscription plans over
//! `/api/acceptance/subscription-plans` under Regime 2
//! (`Authorization: Bearer <auth_token>`).

use reqwest::Method;
use reqwest::header::AUTHORIZATION;
use secrecy::SecretString;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::core::auth::{
    AcceptJwtProvider, CachedToken, format_bearer_header, is_incorrect_credentials_401,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest, HttpResponse};
use crate::core::pagination::PaginatedResponse;

const SUBSCRIPTION_PLANS_PATH: &str = "/api/acceptance/subscription-plans";
const MAX_PLAN_NAME_LEN: usize = 200;

/// Allowed Paymob subscription billing frequencies in days.
///
/// Paymob rejects any frequency outside `{7, 15, 30, 60, 90, 180, 360}` with
/// HTTP 400 (`"\"5\" is not a valid choice."`).
///
/// # Examples
///
/// ```
/// use some_paymob::resources::subscriptions::plans_service::PlanFrequency;
///
/// assert_eq!(PlanFrequency::try_from(30).unwrap(), PlanFrequency::Days30);
/// assert!(PlanFrequency::try_from(5).is_err());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "u16", try_from = "u16")]
#[repr(u16)]
pub enum PlanFrequency {
    /// Weekly billing every 7 days.
    Days7 = 7,
    /// Bi-weekly billing every 15 days.
    Days15 = 15,
    /// Monthly billing every 30 days.
    Days30 = 30,
    /// Bi-monthly billing every 60 days.
    Days60 = 60,
    /// Quarterly billing every 90 days.
    Days90 = 90,
    /// Semi-annual billing every 180 days.
    Days180 = 180,
    /// Annual billing every 360 days.
    Days360 = 360,
}

const ALLOWED_FREQUENCIES: &[(u16, PlanFrequency)] = &[
    (7, PlanFrequency::Days7),
    (15, PlanFrequency::Days15),
    (30, PlanFrequency::Days30),
    (60, PlanFrequency::Days60),
    (90, PlanFrequency::Days90),
    (180, PlanFrequency::Days180),
    (360, PlanFrequency::Days360),
];

impl From<PlanFrequency> for u16 {
    fn from(value: PlanFrequency) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for PlanFrequency {
    type Error = PaymobError;

    fn try_from(days: u16) -> Result<Self, Self::Error> {
        ALLOWED_FREQUENCIES
            .iter()
            .find(|(code, _)| *code == days)
            .map(|(_, variant)| *variant)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "frequency",
                reason: format!(
                    "unsupported plan frequency '{days}'; expected one of 7, 15, 30, 60, 90, 180, or 360 days"
                ),
            })
    }
}

/// Paymob subscription plan classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PlanType {
    /// Recurring rent/subscription plan (`"rent"`).
    Rent,
}

/// Subscription plan record returned by Paymob's `/api/acceptance/subscription-plans` API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionPlan {
    /// Unique Paymob subscription plan identifier.
    pub id: u64,
    /// Merchant-facing subscription plan name.
    pub name: String,
    /// Billing interval in days (`7 | 15 | 30 | 60 | 90 | 180 | 360`).
    pub frequency: PlanFrequency,
    /// Optional MIGS MOTO integration identifier bound to this plan.
    #[serde(default)]
    pub integration: Option<u64>,
    /// Optional recurring charge amount in integer minor units (e.g., piastres/halalas).
    #[serde(default)]
    pub amount_cents: Option<u64>,
    /// Optional platform fee in integer minor units.
    #[serde(default)]
    pub fee: Option<u64>,
    /// Whether the plan is currently active (`true`) or suspended (`false`).
    #[serde(default)]
    pub is_active: bool,
    /// Optional webhook callback URL for plan lifecycle notifications.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Optional number of days before renewal to send a reminder.
    #[serde(default)]
    pub reminder_days: Option<u16>,
    /// Optional number of days to retry failed recurring charges.
    #[serde(default)]
    pub retrial_days: Option<u16>,
    /// Optional plan type classification.
    #[serde(default)]
    pub plan_type: Option<PlanType>,
    /// Optional maximum number of deductions before automatic completion.
    #[serde(default)]
    pub number_of_deductions: Option<u32>,
    /// Whether each renewal uses the initial transaction amount.
    #[serde(default)]
    pub use_transaction_amount: Option<bool>,
    /// Optional ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Optional ISO-8601 last-update timestamp.
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// Request payload for `POST /api/acceptance/subscription-plans`.
///
/// Enforces `1 <= name.chars().count() <= 200`, a validated [`PlanFrequency`],
/// and a non-zero MIGS MOTO `integration` ID before network dispatch.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::subscriptions::plans_service::{
///     CreateSubscriptionPlanParams, PlanFrequency,
/// };
///
/// let params = CreateSubscriptionPlanParams::new("Pro Monthly", PlanFrequency::Days30, 4_111_111)
///     .with_amount_cents(15_000)
///     .with_is_active(true);
/// assert!(params.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateSubscriptionPlanParams {
    /// Billing interval in days (`7 | 15 | 30 | 60 | 90 | 180 | 360`).
    pub frequency: PlanFrequency,
    /// Human-readable plan name (`1..=200` UTF-8 characters).
    pub name: String,
    /// MIGS MOTO integration ID configured for recurring billing.
    pub integration: u64,
    /// Optional webhook notification URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Optional reminder lead time in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reminder_days: Option<u16>,
    /// Optional retrial window in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrial_days: Option<u16>,
    /// Optional plan type (`"rent"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_type: Option<PlanType>,
    /// Optional maximum deduction count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_deductions: Option<u32>,
    /// Optional recurring amount in integer minor units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<u64>,
    /// Optional flag to reuse the initial transaction amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_transaction_amount: Option<bool>,
    /// Optional initial active state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    /// Optional fee in integer minor units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
}

impl CreateSubscriptionPlanParams {
    /// Creates a new [`CreateSubscriptionPlanParams`] with required fields.
    #[must_use]
    pub fn new(name: impl Into<String>, frequency: PlanFrequency, integration: u64) -> Self {
        Self {
            frequency,
            name: name.into(),
            integration,
            webhook_url: None,
            reminder_days: None,
            retrial_days: None,
            plan_type: None,
            number_of_deductions: None,
            amount_cents: None,
            use_transaction_amount: None,
            is_active: None,
            fee: None,
        }
    }

    /// Sets `webhook_url` on the plan creation payload.
    #[must_use]
    pub fn with_webhook_url(mut self, webhook_url: impl Into<String>) -> Self {
        self.webhook_url = Some(webhook_url.into());
        self
    }

    /// Sets `reminder_days` on the plan creation payload.
    #[must_use]
    pub const fn with_reminder_days(mut self, reminder_days: u16) -> Self {
        self.reminder_days = Some(reminder_days);
        self
    }

    /// Sets `retrial_days` on the plan creation payload.
    #[must_use]
    pub const fn with_retrial_days(mut self, retrial_days: u16) -> Self {
        self.retrial_days = Some(retrial_days);
        self
    }

    /// Sets `plan_type` on the plan creation payload.
    #[must_use]
    pub const fn with_plan_type(mut self, plan_type: PlanType) -> Self {
        self.plan_type = Some(plan_type);
        self
    }

    /// Sets `number_of_deductions` on the plan creation payload.
    #[must_use]
    pub const fn with_number_of_deductions(mut self, number_of_deductions: u32) -> Self {
        self.number_of_deductions = Some(number_of_deductions);
        self
    }

    /// Sets `amount_cents` (integer minor units) on the plan creation payload.
    #[must_use]
    pub const fn with_amount_cents(mut self, amount_cents: u64) -> Self {
        self.amount_cents = Some(amount_cents);
        self
    }

    /// Sets `use_transaction_amount` on the plan creation payload.
    #[must_use]
    pub const fn with_use_transaction_amount(mut self, use_transaction_amount: bool) -> Self {
        self.use_transaction_amount = Some(use_transaction_amount);
        self
    }

    /// Sets `is_active` on the plan creation payload.
    #[must_use]
    pub const fn with_is_active(mut self, is_active: bool) -> Self {
        self.is_active = Some(is_active);
        self
    }

    /// Sets `fee` (integer minor units) on the plan creation payload.
    #[must_use]
    pub const fn with_fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Validates all domain invariants before dispatching the HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `name` is empty/whitespace or
    /// exceeds 200 UTF-8 characters, or if `integration` is `0`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_plan_name(&self.name)?;
        validate_integration_id(self.integration)
    }
}

/// Request payload for `PUT /api/acceptance/subscription-plans/{id}`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UpdateSubscriptionPlanParams {
    /// Updated billing frequency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<PlanFrequency>,
    /// Updated plan name (`1..=200` UTF-8 characters when provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Updated MIGS MOTO integration ID (`> 0` when provided).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration: Option<u64>,
    /// Updated webhook URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Updated reminder lead time in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reminder_days: Option<u16>,
    /// Updated retrial window in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrial_days: Option<u16>,
    /// Updated plan type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_type: Option<PlanType>,
    /// Updated maximum deduction count.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_deductions: Option<u32>,
    /// Updated recurring amount in integer minor units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<u64>,
    /// Updated flag to reuse initial transaction amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_transaction_amount: Option<bool>,
    /// Updated active status.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    /// Updated fee in integer minor units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
}

impl UpdateSubscriptionPlanParams {
    /// Creates an empty [`UpdateSubscriptionPlanParams`] builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets an updated `name`.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets an updated `frequency`.
    #[must_use]
    pub const fn with_frequency(mut self, frequency: PlanFrequency) -> Self {
        self.frequency = Some(frequency);
        self
    }

    /// Sets an updated `integration` ID.
    #[must_use]
    pub const fn with_integration(mut self, integration: u64) -> Self {
        self.integration = Some(integration);
        self
    }

    /// Sets an updated `amount_cents` in integer minor units.
    #[must_use]
    pub const fn with_amount_cents(mut self, amount_cents: u64) -> Self {
        self.amount_cents = Some(amount_cents);
        self
    }

    /// Sets an updated `is_active` flag.
    #[must_use]
    pub const fn with_is_active(mut self, is_active: bool) -> Self {
        self.is_active = Some(is_active);
        self
    }

    /// Validates all populated fields before network dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if a provided `name` is empty or
    /// exceeds 200 UTF-8 characters, or if a provided `integration` is `0`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if let Some(name) = &self.name {
            validate_plan_name(name)?;
        }
        if let Some(integration) = self.integration {
            validate_integration_id(integration)?;
        }
        Ok(())
    }
}

/// Service handle for Paymob subscription plan CRUD and lifecycle operations.
///
/// Routes all calls to `/api/acceptance/subscription-plans` under Regime 2
/// (`Authorization: Bearer <auth_token>`), using the shared [`PaymobClient`]
/// single-flight JWT cache and automatic one-shot retry on expired-token `401`
/// responses.
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::ApiKey;
/// use some_paymob::core::region::PaymobRegion;
/// use some_paymob::resources::subscriptions::plans_service::{
///     CreateSubscriptionPlanParams, PlanFrequency, SubscriptionPlansService,
/// };
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .api_key(ApiKey::new("egy_api_key_example")?)
///     .build()?;
/// let client = PaymobClient::new(config)?;
/// let service = SubscriptionPlansService::new(client);
///
/// let params = CreateSubscriptionPlanParams::new("Pro Monthly", PlanFrequency::Days30, 4_111_111)
///     .with_amount_cents(15_000);
/// let _plan = service.create(&params).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SubscriptionPlansService {
    client: PaymobClient,
    http: HttpClient,
}

impl SubscriptionPlansService {
    /// Creates a new [`SubscriptionPlansService`] bound to `client`.
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        let http = client.http().clone();
        Self { client, http }
    }

    /// Creates a [`SubscriptionPlansService`] with an explicit [`HttpClient`] for tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn with_http_client(client: PaymobClient, http: HttpClient) -> Self {
        Self { client, http }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub fn client(&self) -> &PaymobClient {
        &self.client
    }

    /// Creates a new subscription plan via `POST /api/acceptance/subscription-plans`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `params` fails client-side
    /// validation, [`PaymobError::AuthenticationError`] if Regime 2 JWT
    /// acquisition fails, or [`PaymobError::ApiError`] / [`PaymobError::TransportError`]
    /// on gateway failure.
    pub async fn create(
        &self,
        params: &CreateSubscriptionPlanParams,
    ) -> Result<SubscriptionPlan, PaymobError> {
        params.validate()?;
        let body = serde_json::to_value(params).map_err(|err| PaymobError::ValidationError {
            field: "params",
            reason: format!("failed to serialize create plan params: {err}"),
        })?;
        self.send_authorized(Method::POST, SUBSCRIPTION_PLANS_PATH, Some(&body))
            .await
    }

    /// Updates an existing subscription plan via `PUT /api/acceptance/subscription-plans/{id}`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `plan_id == 0` or `params`
    /// contains invalid fields, [`PaymobError::AuthenticationError`] on Regime 2
    /// auth failure, or gateway/transport errors.
    pub async fn update(
        &self,
        plan_id: u64,
        params: &UpdateSubscriptionPlanParams,
    ) -> Result<SubscriptionPlan, PaymobError> {
        validate_plan_id(plan_id)?;
        params.validate()?;
        let body = serde_json::to_value(params).map_err(|err| PaymobError::ValidationError {
            field: "params",
            reason: format!("failed to serialize update plan params: {err}"),
        })?;
        let path = format!("{SUBSCRIPTION_PLANS_PATH}/{plan_id}");
        self.send_authorized(Method::PUT, &path, Some(&body)).await
    }

    /// Lists subscription plans via `GET /api/acceptance/subscription-plans` (or `?page=N`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `page` is `Some(0)`,
    /// [`PaymobError::AuthenticationError`] on Regime 2 auth failure, or
    /// gateway/transport errors.
    pub async fn list(
        &self,
        page: Option<u32>,
    ) -> Result<PaginatedResponse<SubscriptionPlan>, PaymobError> {
        validate_page(page)?;
        let path = list_path(page);
        self.send_authorized(Method::GET, &path, None).await
    }

    /// Suspends an active subscription plan via `POST /api/acceptance/subscription-plans/{id}/suspend`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `plan_id == 0`,
    /// [`PaymobError::AuthenticationError`] on Regime 2 auth failure, or
    /// gateway/transport errors.
    pub async fn suspend(&self, plan_id: u64) -> Result<SubscriptionPlan, PaymobError> {
        validate_plan_id(plan_id)?;
        let path = format!("{SUBSCRIPTION_PLANS_PATH}/{plan_id}/suspend");
        self.send_authorized(Method::POST, &path, None).await
    }

    /// Resumes a suspended subscription plan via `POST /api/acceptance/subscription-plans/{id}/resume`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `plan_id == 0`,
    /// [`PaymobError::AuthenticationError`] on Regime 2 auth failure, or
    /// gateway/transport errors.
    pub async fn resume(&self, plan_id: u64) -> Result<SubscriptionPlan, PaymobError> {
        validate_plan_id(plan_id)?;
        let path = format!("{SUBSCRIPTION_PLANS_PATH}/{plan_id}/resume");
        self.send_authorized(Method::POST, &path, None).await
    }

    async fn send_authorized<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<T, PaymobError> {
        let url = self.client.accept_url(path)?;
        let token = self.acquire_bearer_token().await?;
        let response = self.execute_once(&method, &url, body, &token).await?;

        if is_incorrect_credentials_401(response.status, &response.body) {
            self.client
                .auth()
                .accept_cache()
                .evict_if_matches(&token)
                .await;
            let refreshed = self.acquire_bearer_token().await?;
            let retry_resp = self.execute_once(&method, &url, body, &refreshed).await?;
            return parse_json_response(&retry_resp);
        }

        parse_json_response(&response)
    }

    async fn execute_once(
        &self,
        method: &Method,
        url: &Url,
        body: Option<&Value>,
        token: &SecretString,
    ) -> Result<HttpResponse, PaymobError> {
        let header_value = format_bearer_header(token)
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        let mut request = HttpRequest::new(method.clone(), url.as_str())
            .map_err(|err| PaymobError::TransportError(err.to_string()))?
            .with_header(AUTHORIZATION, header_value);

        if let Some(payload) = body {
            request = request
                .with_json(payload)
                .map_err(|err| PaymobError::TransportError(err.to_string()))?;
        }

        self.http
            .execute(&request)
            .await
            .map_err(|err| PaymobError::TransportError(err.to_string()))
    }

    async fn acquire_bearer_token(&self) -> Result<SecretString, PaymobError> {
        if let Some(cached) = self.client.auth().accept_cache().peek() {
            return Ok(cached.access_token);
        }

        let api_key = self.client.config().api_key().ok_or_else(|| {
            PaymobError::AuthenticationError(
                "missing Paymob API key for Regime 2 Bearer authentication".to_owned(),
            )
        })?;
        let provider = AcceptJwtProvider::new(
            &self.client.endpoints().accept_base_url,
            SecretString::from(api_key.expose_secret().to_owned()),
        )
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;

        let cached = self
            .client
            .auth()
            .accept_cache()
            .get_or_refresh(|| async {
                let jwt = provider
                    .token()
                    .await
                    .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
                Ok(CachedToken::with_default_ttl(jwt, None))
            })
            .await?;
        Ok(cached.access_token)
    }
}

fn validate_plan_id(plan_id: u64) -> Result<(), PaymobError> {
    if plan_id == 0 {
        return Err(PaymobError::ValidationError {
            field: "plan_id",
            reason: "subscription plan id must be greater than zero".to_owned(),
        });
    }
    Ok(())
}

fn validate_integration_id(integration: u64) -> Result<(), PaymobError> {
    if integration == 0 {
        return Err(PaymobError::ValidationError {
            field: "integration",
            reason: "MIGS MOTO integration id must be greater than zero".to_owned(),
        });
    }
    Ok(())
}

fn validate_plan_name(name: &str) -> Result<(), PaymobError> {
    let trimmed = name.trim();
    if trimmed.is_empty() || name.chars().count() > MAX_PLAN_NAME_LEN {
        return Err(PaymobError::ValidationError {
            field: "name",
            reason: format!("plan name must be between 1 and {MAX_PLAN_NAME_LEN} UTF-8 characters"),
        });
    }
    Ok(())
}

fn validate_page(page: Option<u32>) -> Result<(), PaymobError> {
    if matches!(page, Some(0)) {
        return Err(PaymobError::ValidationError {
            field: "page",
            reason: "page number must be greater than zero".to_owned(),
        });
    }
    Ok(())
}

fn list_path(page: Option<u32>) -> String {
    match page {
        Some(n) => format!("{SUBSCRIPTION_PLANS_PATH}?page={n}"),
        None => SUBSCRIPTION_PLANS_PATH.to_owned(),
    }
}

fn parse_json_response<T: DeserializeOwned>(response: &HttpResponse) -> Result<T, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(response));
    }
    response
        .json::<T>()
        .map_err(|err| PaymobError::TransportError(format!("invalid JSON response: {err}")))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::http::HttpClientConfig;
    use crate::core::region::PaymobRegion;

    fn mock_client(base_url: &str, with_api_key: bool) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: base_url.to_owned(),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let mut builder = ClientConfig::builder().region(region);
        if with_api_key {
            builder = builder.api_key(ApiKey::new("test_api_key_secret").expect("valid api key"));
        }
        PaymobClient::new(builder.build().expect("valid config")).expect("valid client")
    }

    fn mock_service(base_url: &str, with_api_key: bool) -> SubscriptionPlansService {
        let client = mock_client(base_url, with_api_key);
        let http = HttpClient::new(HttpClientConfig::default().with_allow_insecure_http(true))
            .expect("valid test http client");
        SubscriptionPlansService::with_http_client(client, http)
    }

    async fn mount_auth_token(server: &MockServer, token: &str) {
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": token })))
            .mount(server)
            .await;
    }

    fn sample_plan_json(id: u64, name: &str, is_active: bool) -> Value {
        json!({
            "id": id,
            "name": name,
            "frequency": 30,
            "integration": 4111111,
            "amount_cents": 15000,
            "fee": 500,
            "is_active": is_active,
            "plan_type": "rent"
        })
    }

    #[tokio::test]
    async fn tc_4_2_3_create_plan_posts_with_bearer_and_returns_plan() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt_create_123").await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscription-plans"))
            .and(header("authorization", "Bearer jwt_create_123"))
            .and(body_json(json!({
                "frequency": 30,
                "name": "Pro Monthly",
                "integration": 4111111,
                "amount_cents": 15000,
                "is_active": true,
                "plan_type": "rent"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_plan_json(
                101,
                "Pro Monthly",
                true,
            )))
            .mount(&server)
            .await;

        let service = mock_service(&server.uri(), true);
        let params =
            CreateSubscriptionPlanParams::new("Pro Monthly", PlanFrequency::Days30, 4_111_111)
                .with_amount_cents(15_000)
                .with_is_active(true)
                .with_plan_type(PlanType::Rent);

        let plan = service
            .create(&params)
            .await
            .expect("create should succeed");
        assert_eq!(plan.id, 101);
        assert_eq!(plan.name, "Pro Monthly");
        assert_eq!(plan.frequency, PlanFrequency::Days30);
        assert_eq!(plan.amount_cents, Some(15_000));
        assert!(plan.is_active);
    }

    #[tokio::test]
    async fn tc_4_2_3_update_plan_puts_to_plan_id_endpoint() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt_update_123").await;
        Mock::given(method("PUT"))
            .and(path("/api/acceptance/subscription-plans/42"))
            .and(header("authorization", "Bearer jwt_update_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_plan_json(
                    42,
                    "Pro Annual",
                    true,
                )),
            )
            .mount(&server)
            .await;

        let service = mock_service(&server.uri(), true);
        let params = UpdateSubscriptionPlanParams::new()
            .with_name("Pro Annual")
            .with_frequency(PlanFrequency::Days360)
            .with_amount_cents(120_000);

        let plan = service
            .update(42, &params)
            .await
            .expect("update should succeed");
        assert_eq!(plan.id, 42);
        assert_eq!(plan.name, "Pro Annual");
    }

    #[tokio::test]
    async fn tc_4_2_3_list_plans_with_and_without_page_query() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt_list_123").await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscription-plans"))
            .and(header("authorization", "Bearer jwt_list_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count": 2,
                "next": "https://accept.paymob.com/api/acceptance/subscription-plans?page=2",
                "previous": null,
                "results": [sample_plan_json(1, "Starter", true)]
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscription-plans"))
            .and(query_param("page", "2"))
            .and(header("authorization", "Bearer jwt_list_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count": 2,
                "next": null,
                "previous": "https://accept.paymob.com/api/acceptance/subscription-plans?page=1",
                "results": [sample_plan_json(2, "Enterprise", true)]
            })))
            .mount(&server)
            .await;

        let service = mock_service(&server.uri(), true);
        let page2 = service
            .list(Some(2))
            .await
            .expect("list page 2 should succeed");
        assert_eq!(page2.count, 2);
        assert_eq!(page2.results.len(), 1);
        assert_eq!(page2.results[0].id, 2);
    }

    #[tokio::test]
    async fn tc_4_2_3_suspend_and_resume_plan_lifecycle() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt_lifecycle_123").await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscription-plans/42/suspend"))
            .and(header("authorization", "Bearer jwt_lifecycle_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_plan_json(
                    42,
                    "Pro Monthly",
                    false,
                )),
            )
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscription-plans/42/resume"))
            .and(header("authorization", "Bearer jwt_lifecycle_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_plan_json(
                    42,
                    "Pro Monthly",
                    true,
                )),
            )
            .mount(&server)
            .await;

        let service = mock_service(&server.uri(), true);
        let suspended = service.suspend(42).await.expect("suspend should succeed");
        assert!(!suspended.is_active);

        let resumed = service.resume(42).await.expect("resume should succeed");
        assert!(resumed.is_active);
    }

    #[tokio::test]
    async fn tc_4_2_3_validation_rejects_invalid_inputs_before_network() {
        let server = MockServer::start().await;
        let service = mock_service(&server.uri(), false);

        assert!(PlanFrequency::try_from(5).is_err());

        let empty_name = CreateSubscriptionPlanParams::new("  ", PlanFrequency::Days30, 4_111_111);
        assert!(service.create(&empty_name).await.is_err());

        let long_name =
            CreateSubscriptionPlanParams::new("a".repeat(201), PlanFrequency::Days30, 4_111_111);
        assert!(service.create(&long_name).await.is_err());

        let zero_integration = CreateSubscriptionPlanParams::new("Valid", PlanFrequency::Days7, 0);
        assert!(service.create(&zero_integration).await.is_err());

        assert!(
            service
                .update(0, &UpdateSubscriptionPlanParams::new())
                .await
                .is_err()
        );
        assert!(service.list(Some(0)).await.is_err());
        assert!(service.suspend(0).await.is_err());
        assert!(service.resume(0).await.is_err());

        let valid_params =
            CreateSubscriptionPlanParams::new("Valid", PlanFrequency::Days30, 4_111_111);
        let missing_auth = service.create(&valid_params).await;
        assert!(matches!(
            missing_auth,
            Err(PaymobError::AuthenticationError(_))
        ));

        assert!(
            server
                .received_requests()
                .await
                .unwrap_or_default()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn tc_4_2_3_401_incorrect_credentials_evicts_cache_and_retries_once() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "fresh_jwt_token").await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscription-plans/42/suspend"))
            .and(header("authorization", "Bearer stale_jwt_token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({ "detail": "incorrect credentials" })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscription-plans/42/suspend"))
            .and(header("authorization", "Bearer fresh_jwt_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_plan_json(
                42,
                "Pro Monthly",
                false,
            )))
            .expect(1)
            .mount(&server)
            .await;

        let service = mock_service(&server.uri(), true);
        service
            .client()
            .auth()
            .accept_cache()
            .store(CachedToken::with_default_ttl("stale_jwt_token", None));

        let suspended = service
            .suspend(42)
            .await
            .expect("retry after 401 should succeed");
        assert!(!suspended.is_active);
    }
}
