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
use serde_json::Value;
use url::Url;

use super::plan_models::SubscriptionPlan;
use super::plan_params::{CreateSubscriptionPlanParams, UpdateSubscriptionPlanParams};
use crate::core::auth::{
    AcceptJwtProvider, CachedToken, format_bearer_header, is_incorrect_credentials_401,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest, HttpResponse};
use crate::core::pagination::PaginatedResponse;

const SUBSCRIPTION_PLANS_PATH: &str = "/api/acceptance/subscription-plans";

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
/// use some_paymob::resources::subscriptions::plan_models::PlanFrequency;
/// use some_paymob::resources::subscriptions::plan_params::CreateSubscriptionPlanParams;
/// use some_paymob::resources::subscriptions::plans_service::SubscriptionPlansService;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .api_key(ApiKey::new("egy_api_key_example")?)
///     .build()?;
/// let client = PaymobClient::new(config)?;
/// let service = SubscriptionPlansService::new(client);
///
/// let params = CreateSubscriptionPlanParams::builder()
///     .name("Pro Monthly")
///     .frequency(PlanFrequency::Days30)
///     .integration(4_111_111)
///     .amount_cents(15_000)
///     .build()?;
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
            return Ok(cached.access_token.clone());
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
                Ok::<CachedToken, PaymobError>(CachedToken::with_default_ttl(jwt, None))
            })
            .await?;
        Ok(cached.access_token.clone())
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

    use super::super::plan_models::{PlanFrequency, PlanType};
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::http::HttpClientConfig;
    use crate::core::region::PaymobRegion;
    use crate::core::types::MinorUnitAmount;

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
        let params = CreateSubscriptionPlanParams::builder()
            .name("Pro Monthly")
            .frequency(PlanFrequency::Days30)
            .integration(4_111_111)
            .amount_cents(15_000)
            .is_active(true)
            .plan_type(PlanType::Rent.as_str())
            .build()
            .expect("valid create params");

        let plan = service
            .create(&params)
            .await
            .expect("create should succeed");
        assert_eq!(plan.id, 101);
        assert_eq!(plan.name, "Pro Monthly");
        assert_eq!(plan.frequency, PlanFrequency::Days30);
        assert_eq!(plan.amount_cents, Some(MinorUnitAmount::new(15_000)));
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
            )))
            .mount(&server)
            .await;

        let service = mock_service(&server.uri(), true);
        let params = UpdateSubscriptionPlanParams::builder()
            .name("Pro Annual")
            .frequency(PlanFrequency::Days360)
            .amount_cents(120_000)
            .build()
            .expect("valid update params");

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
            .and(query_param("page", "2"))
            .and(header("authorization", "Bearer jwt_list_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count": 2,
                "next": null,
                "previous": "https://accept.paymob.com/api/acceptance/subscription-plans?page=1",
                "results": [sample_plan_json(2, "Enterprise", true)]
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscription-plans"))
            .and(header("authorization", "Bearer jwt_list_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "count": 2,
                "next": "https://accept.paymob.com/api/acceptance/subscription-plans?page=2",
                "previous": null,
                "results": [sample_plan_json(1, "Starter", true)]
            })))
            .expect(1)
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

        let page1 = service
            .list(None)
            .await
            .expect("list default page should succeed");
        assert_eq!(page1.results.len(), 1);
        assert_eq!(page1.results[0].id, 1);
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
            )))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscription-plans/42/resume"))
            .and(header("authorization", "Bearer jwt_lifecycle_123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_plan_json(
                42,
                "Pro Monthly",
                true,
            )))
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

        assert!(
            CreateSubscriptionPlanParams::builder()
                .name("  ")
                .frequency(PlanFrequency::Days30)
                .integration(4_111_111)
                .build()
                .is_err()
        );

        assert!(
            CreateSubscriptionPlanParams::builder()
                .name("a".repeat(201))
                .frequency(PlanFrequency::Days30)
                .integration(4_111_111)
                .build()
                .is_err()
        );

        assert!(
            CreateSubscriptionPlanParams::builder()
                .name("Valid")
                .frequency(PlanFrequency::Days7)
                .integration(0)
                .build()
                .is_err()
        );

        let valid_update = UpdateSubscriptionPlanParams::builder()
            .name("Valid")
            .build()
            .expect("valid update");
        assert!(service.update(0, &valid_update).await.is_err());
        assert!(service.list(Some(0)).await.is_err());
        assert!(service.suspend(0).await.is_err());
        assert!(service.resume(0).await.is_err());

        let valid_params = CreateSubscriptionPlanParams::builder()
            .name("Valid")
            .frequency(PlanFrequency::Days30)
            .integration(4_111_111)
            .build()
            .expect("valid params");
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
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({ "detail": "incorrect credentials" })),
            )
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

    #[test]
    fn tc_4_2_4_debug_redacts_api_key_and_never_leaks_secret() {
        let service = mock_service("https://accept.paymob.com", true);
        let debug_output = format!("{service:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("test_api_key_secret"));
    }
}
