#![forbid(unsafe_code)]
//! Service client for Paymob v1 Payment Intention Create & Update (`POST` & `PUT /v1/intention/`).
//!
//! Uses Regime 1 `Authorization: Token <secret_key>` authentication and enforces
//! pre-flight and post-response Test/Live [`EnvironmentMode`] parity guards.

use std::collections::HashMap;

use reqwest::Method;
use reqwest::header::HeaderMap;
use secrecy::SecretString;

use crate::core::auth::strategy::{AuthStrategy, EndpointAuthSpec};
use crate::core::client::PaymobClient;
use crate::core::credentials::EnvironmentMode;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest};

use super::params::{CreateIntentionParams, PaymentMethodInput, UpdateIntentionParams};
use super::response::IntentionResponse;

const INTENTION_PATH: &str = "/v1/intention/";

/// Service handle for Paymob v1 Payment Intentions (`POST` & `PUT /v1/intention/`).
///
/// Obtain via [`PaymobClient::intentions`].
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::SecretKey;
/// use some_paymob::core::region::PaymobRegion;
/// use some_paymob::core::types::Currency;
/// use some_paymob::resources::intentions::billing::BillingData;
/// use some_paymob::resources::intentions::params::{
///     CreateIntentionParams, PaymentMethodInput,
/// };
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .secret_key(SecretKey::new("egy_sk_test_example")?)
///     .build()?;
/// let paymob = PaymobClient::new(config)?;
///
/// let params = CreateIntentionParams::builder()
///     .amount(100_000_u64)
///     .currency(Currency::EGP)
///     .payment_methods(vec![PaymentMethodInput::IntegrationId(4_097_558)])
///     .billing_data(BillingData::builder().phone_number("+201116491564").build()?)
///     .build()?;
///
/// let _intention = paymob.intentions().create(params).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct IntentionsService<'a> {
    client: &'a PaymobClient,
    known_integration_modes: HashMap<u64, EnvironmentMode>,
    #[cfg(test)]
    mock_base_url: Option<String>,
    #[cfg(test)]
    mock_http: Option<HttpClient>,
}

impl PaymobClient {
    /// Returns the v1 Payment Intentions service handle (`POST` & `PUT /v1/intention/`).
    #[must_use]
    pub fn intentions(&self) -> IntentionsService<'_> {
        IntentionsService::new(self)
    }
}

impl<'a> IntentionsService<'a> {
    /// Creates a new [`IntentionsService`] bound to `client`.
    #[must_use]
    pub fn new(client: &'a PaymobClient) -> Self {
        Self {
            client,
            known_integration_modes: HashMap::new(),
            #[cfg(test)]
            mock_base_url: None,
            #[cfg(test)]
            mock_http: None,
        }
    }

    /// Registers a known [`EnvironmentMode`] (`Test` or `Live`) for an integration ID
    /// so pre-flight parity validation can reject mismatches before network I/O.
    #[must_use]
    pub fn with_integration_mode(mut self, integration_id: u64, mode: EnvironmentMode) -> Self {
        self.known_integration_modes.insert(integration_id, mode);
        self
    }

    /// Creates a new Paymob v1 Payment Intention (`POST /v1/intention/`).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::AuthenticationError`] if `secret_key` is missing from [`PaymobClient`].
    /// - [`PaymobError::EnvironmentMismatch`] if any known integration ID or returned
    ///   integration conflicts with the configured `Test`/`Live` secret key mode.
    /// - [`PaymobError::ValidationError`], [`PaymobError::RateLimited`],
    ///   [`PaymobError::ApiError`], or [`PaymobError::TransportError`] on gateway failure.
    pub async fn create(
        &self,
        params: CreateIntentionParams,
    ) -> Result<IntentionResponse, PaymobError> {
        let mode = self.preflight_check(params.payment_methods())?;
        self.dispatch_intention(Method::POST, &params, mode).await
    }

    /// Updates an existing Paymob v1 Payment Intention (`PUT /v1/intention/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::AuthenticationError`], [`PaymobError::EnvironmentMismatch`],
    /// or normalized gateway/transport errors.
    pub async fn update(
        &self,
        params: UpdateIntentionParams,
    ) -> Result<IntentionResponse, PaymobError> {
        let methods = params.payment_methods().unwrap_or(&[]);
        let mode = self.preflight_check(methods)?;
        self.dispatch_intention(Method::PUT, &params, mode).await
    }

    fn preflight_check(
        &self,
        methods: &[PaymentMethodInput],
    ) -> Result<EnvironmentMode, PaymobError> {
        let secret_key = self.client.config().secret_key().ok_or_else(|| {
            PaymobError::AuthenticationError(
                "SecretKey is required for Regime 1 /v1/intention/ endpoints".to_owned(),
            )
        })?;
        let key_mode = secret_key.mode();
        self.check_integration_parity(methods, key_mode)?;
        Ok(key_mode)
    }

    fn check_integration_parity(
        &self,
        methods: &[PaymentMethodInput],
        key_mode: EnvironmentMode,
    ) -> Result<(), PaymobError> {
        for method in methods {
            let Some(id) = method.as_integration_id() else {
                continue;
            };
            if let Some(&known_mode) = self.known_integration_modes.get(&id) {
                if known_mode != key_mode {
                    return Err(env_mismatch_error(id, key_mode, known_mode));
                }
            }
        }
        Ok(())
    }

    async fn dispatch_intention<T: serde::Serialize>(
        &self,
        method: Method,
        payload: &T,
        key_mode: EnvironmentMode,
    ) -> Result<IntentionResponse, PaymobError> {
        let url = self.resolve_intention_url()?;
        let headers = self.build_auth_headers(&method)?;
        let mut req = HttpRequest::new(method, &url)
            .map_err(PaymobError::from)?
            .with_json(payload)
            .map_err(PaymobError::from)?;
        for (name, value) in &headers {
            req = req.with_header(name.clone(), value.clone());
        }

        let response = self.http_client().execute(&req).await.map_err(PaymobError::from)?;
        if !response.status.is_success() {
            return Err(PaymobError::from_http_response(&response));
        }
        let parsed: IntentionResponse = response.json().map_err(PaymobError::from)?;
        verify_response_parity(&parsed, key_mode)?;
        Ok(parsed)
    }

    fn build_auth_headers(&self, method: &Method) -> Result<HeaderMap, PaymobError> {
        let secret_key = self.client.config().secret_key().ok_or_else(|| {
            PaymobError::AuthenticationError("missing SecretKey".to_owned())
        })?;
        let spec = EndpointAuthSpec::new(INTENTION_PATH, method.clone(), AuthStrategy::SecretKeyToken)
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        let mut headers = HeaderMap::new();
        let token = SecretString::from(secret_key.expose_secret().to_owned());
        spec.apply_secret_key(&mut headers, &token)
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        Ok(headers)
    }

    fn resolve_intention_url(&self) -> Result<String, PaymobError> {
        #[cfg(test)]
        if let Some(ref base) = self.mock_base_url {
            return Ok(format!("{}{}", base.trim_end_matches('/'), INTENTION_PATH));
        }
        Ok(self.client.accept_url(INTENTION_PATH)?.to_string())
    }

    fn http_client(&self) -> &HttpClient {
        #[cfg(test)]
        if let Some(ref mock) = self.mock_http {
            return mock;
        }
        self.client.http()
    }
}

fn verify_response_parity(
    response: &IntentionResponse,
    key_mode: EnvironmentMode,
) -> Result<(), PaymobError> {
    if response.has_mode_mismatch(key_mode) {
        return Err(PaymobError::EnvironmentMismatch(format!(
            "Paymob returned a payment_methods integration whose live/test mode conflicts with \
             configured {key_mode} SecretKey; verify integration IDs in the Merchant Dashboard \
             Payment Integrations tab"
        )));
    }
    Ok(())
}

fn env_mismatch_error(
    integration_id: u64,
    key_mode: EnvironmentMode,
    integration_mode: EnvironmentMode,
) -> PaymobError {
    PaymobError::EnvironmentMismatch(format!(
        "Integration ID {integration_id} is configured for {integration_mode} mode, which \
         conflicts with your {key_mode} SecretKey; verify integration IDs in the Merchant \
         Dashboard Payment Integrations tab"
    ))
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::core::config::ClientConfig;
    use crate::core::credentials::SecretKey;
    use crate::core::http::{HttpClientConfig, RetryPolicy};
    use crate::core::region::PaymobRegion;
    use crate::core::types::Currency;

    use super::super::billing::BillingData;
    use super::*;

    fn test_client(secret: &str) -> PaymobClient {
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new(secret).expect("valid key"))
            .build()
            .expect("valid config");
        PaymobClient::new(cfg).expect("client")
    }

    fn mock_service<'a>(client: &'a PaymobClient, server: &MockServer) -> IntentionsService<'a> {
        let http_cfg = HttpClientConfig {
            allow_insecure_http: true,
            retry: RetryPolicy {
                max_retries: 0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut svc = client.intentions();
        svc.mock_base_url = Some(server.uri());
        svc.mock_http = Some(HttpClient::new(http_cfg).expect("mock http"));
        svc
    }

    fn sample_create_params() -> CreateIntentionParams {
        let billing = BillingData::builder()
            .phone_number("+201116491564")
            .build()
            .expect("billing");
        CreateIntentionParams::builder()
            .amount(100_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![
                PaymentMethodInput::IntegrationId(4_097_558),
                PaymentMethodInput::MethodName("card".to_owned()),
            ])
            .billing_data(billing)
            .build()
            .expect("params")
    }

    fn sample_response_body(live: bool) -> serde_json::Value {
        serde_json::json!({
            "id": "pi_test_001",
            "intention_order_id": 123456,
            "client_secret": "egy_csk_test_wiremock_secret",
            "payment_keys": [],
            "payment_methods": [
                {
                    "integration_id": 4_097_558,
                    "alias": "card",
                    "live": live
                }
            ],
            "confirmed": false,
            "status": "intended"
        })
    }

    #[tokio::test]
    async fn tc_2_1_4_create_intention_happy_path_sends_token_auth() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/intention/"))
            .and(header("authorization", "Token egy_sk_test_abc123"))
            .respond_with(ResponseTemplate::new(201).set_body_json(sample_response_body(false)))
            .mount(&server)
            .await;

        let client = test_client("egy_sk_test_abc123");
        let resp = mock_service(&client, &server)
            .create(sample_create_params())
            .await
            .expect("create intention");

        assert_eq!(resp.id, "pi_test_001");
        assert_eq!(resp.intention_order_id, 123_456);
    }

    #[tokio::test]
    async fn tc_2_1_4_update_intention_sends_put_with_token_auth() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/v1/intention/"))
            .and(header("authorization", "Token egy_sk_test_abc123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sample_response_body(false)))
            .mount(&server)
            .await;

        let client = test_client("egy_sk_test_abc123");
        let update = UpdateIntentionParams::builder()
            .amount(120_000_u64)
            .build()
            .expect("update params");

        let resp = mock_service(&client, &server)
            .update(update)
            .await
            .expect("update intention");
        assert_eq!(resp.id, "pi_test_001");
    }

    #[tokio::test]
    async fn tc_2_1_4_preflight_and_response_parity_rejects_mode_mismatch() {
        let server = MockServer::start().await;
        let client = test_client("egy_sk_test_abc123");

        let err = mock_service(&client, &server)
            .with_integration_mode(4_097_558, EnvironmentMode::Live)
            .create(sample_create_params())
            .await
            .expect_err("preflight mismatch");
        assert!(matches!(err, PaymobError::EnvironmentMismatch(_)));
        assert!(err.to_string().contains("Payment Integrations"));

        Mock::given(method("POST"))
            .and(path("/v1/intention/"))
            .respond_with(ResponseTemplate::new(201).set_body_json(sample_response_body(true)))
            .mount(&server)
            .await;

        let post_err = mock_service(&client, &server)
            .create(sample_create_params())
            .await
            .expect_err("response parity mismatch");
        assert!(matches!(post_err, PaymobError::EnvironmentMismatch(_)));
    }

    #[tokio::test]
    async fn tc_2_1_4_maps_400_and_401_gateway_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/intention/"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_string(r#"{"billing_data":{"phone_number":["This field is required."]}}"#),
            )
            .mount(&server)
            .await;

        let client = test_client("egy_sk_test_abc123");
        let err = mock_service(&client, &server)
            .create(sample_create_params())
            .await
            .expect_err("400 validation error");
        assert!(err.is_validation_error());
    }
}
