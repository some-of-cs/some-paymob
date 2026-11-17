#![forbid(unsafe_code)]
//! Partner sub-merchant registration and onboarding flow schema discovery (`US-6.2.0`).
//!
//! Implements [`PartnerFlowService::register_merchant`] (`POST /api/onboarding/register`)
//! and [`PartnerFlowService::get_schema`] (`GET /api/onboarding/flow/schema`)
//! under Regime 4 [`PartnerApiKey`](crate::core::auth::strategy::AuthStrategy::PartnerApiKey)
//! authentication.

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::onboarding::flow_models::{
    OnboardingFlowSchema, OnboardingSchemaQuery, RegisterMerchantParams, RegisteredMerchantResponse,
};
use crate::resources::onboarding::{
    PartnerFlowService, apply_header_map, decode_onboarding_json, execute_onboarding_request,
    resolve_partner_api_key_headers,
};

const REGISTER_MERCHANT_PATH: &str = "/api/onboarding/register";
const ONBOARDING_SCHEMA_PATH: &str = "/api/onboarding/flow/schema";

impl PartnerFlowService {
    /// Registers a new sub-merchant under the partner account (`POST /api/onboarding/register`).
    ///
    /// Authenticates with Regime 4 `PartnerApiKey` (`x-api-key` header) configured via
    /// [`PartnerCredentials`](crate::core::credentials::PartnerCredentials).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `params` contains empty or invalid fields.
    /// - [`PaymobError::AuthenticationError`] if `partner_credentials` is missing.
    /// - [`PaymobError::ApiError`], [`PaymobError::RateLimited`], or [`PaymobError::TransportError`]
    ///   if the Paymob API rejects or fails to process the request.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::PartnerCredentials;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::onboarding::flow_models::RegisterMerchantParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .partner_credentials(PartnerCredentials::new("partner_api_key_123")?)
    ///     .build()?;
    /// let paymob = PaymobClient::new(config)?;
    ///
    /// let params = RegisterMerchantParams::new(
    ///     "KeyPartner",
    ///     "merchant@example.com",
    ///     "+201000000000",
    ///     "Amira",
    ///     "Hassan",
    /// )?;
    /// let registered = paymob.onboarding().flow().register_merchant(&params).await?;
    /// println!("assigned paymob_mid={}", registered.paymob_mid);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register_merchant(
        &self,
        params: &RegisterMerchantParams,
    ) -> Result<RegisteredMerchantResponse, PaymobError> {
        params.validate()?;
        let headers = resolve_partner_api_key_headers(
            self.client(),
            "partner_credentials must be configured for Regime 4 onboarding endpoints",
        )?;
        let url = self.client().accept_url(REGISTER_MERCHANT_PATH)?;
        let req = HttpRequest::post(url.as_str())?.with_json(params)?;
        let request = apply_header_map(req, &headers);
        let response = execute_onboarding_request(self.client(), &request).await?;
        decode_onboarding_json(&response)
    }

    /// Fetches the dynamic onboarding KYC flow schema (`GET /api/onboarding/flow/schema`).
    ///
    /// Serializes [`OnboardingSchemaQuery`] as `?partner=...&resubmission=...&paymob_mid=...`
    /// and authenticates under Regime 4 `PartnerApiKey`.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `query` is invalid.
    /// - [`PaymobError::AuthenticationError`] if `partner_credentials` is missing.
    /// - [`PaymobError::ApiError`], [`PaymobError::RateLimited`], or [`PaymobError::TransportError`]
    ///   if the Paymob API rejects or fails to process the request.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::PartnerCredentials;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::onboarding::flow_models::OnboardingSchemaQuery;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .partner_credentials(PartnerCredentials::new("partner_api_key_123")?)
    ///     .build()?;
    /// let paymob = PaymobClient::new(config)?;
    ///
    /// let query = OnboardingSchemaQuery::new("KeyPartner")?
    ///     .with_resubmission(true)
    ///     .with_paymob_mid(123);
    /// let schema = paymob.onboarding().flow().get_schema(&query).await?;
    /// println!("steps={}", schema.steps.len());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_schema(
        &self,
        query: &OnboardingSchemaQuery,
    ) -> Result<OnboardingFlowSchema, PaymobError> {
        let query_str = query.to_query_string()?;
        let headers = resolve_partner_api_key_headers(
            self.client(),
            "partner_credentials must be configured for Regime 4 onboarding endpoints",
        )?;
        let path = format!("{ONBOARDING_SCHEMA_PATH}?{query_str}");
        let url = self.client().accept_url(&path)?;
        let request = apply_header_map(HttpRequest::get(url.as_str())?, &headers);
        let response = execute_onboarding_request(self.client(), &request).await?;
        decode_onboarding_json(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::PartnerCredentials;
    use crate::core::region::PaymobRegion;

    fn mock_region(base_url: &str) -> PaymobRegion {
        PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        }
    }

    fn partner_client(base_url: &str) -> PaymobClient {
        let config = ClientConfig::builder()
            .region(mock_region(base_url))
            .partner_credentials(
                PartnerCredentials::new("partner_key_secret_622").expect("valid partner creds"),
            )
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    #[tokio::test]
    async fn tc_6_2_2_register_merchant_dispatches_post_with_partner_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/onboarding/register"))
            .and(header("x-api-key", "partner_key_secret_622"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "paymob_mid": 987654,
                "partner": "KeyPartner",
                "status": "pending_kyc"
            })))
            .mount(&server)
            .await;

        let client = partner_client(&server.uri());
        let params = RegisterMerchantParams::new(
            "KeyPartner",
            "merchant@example.com",
            "+201116491564",
            "Amira",
            "Hassan",
        )
        .expect("valid params");

        let resp = client
            .onboarding()
            .flow()
            .register_merchant(&params)
            .await
            .expect("register_merchant succeeds");
        assert_eq!(resp.paymob_mid, 987_654);
        assert_eq!(resp.status.as_deref(), Some("pending_kyc"));
    }

    #[tokio::test]
    async fn tc_6_2_2_get_schema_dispatches_exact_query_params_with_partner_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/onboarding/flow/schema"))
            .and(query_param("partner", "KeyPartner"))
            .and(query_param("resubmission", "true"))
            .and(query_param("paymob_mid", "123"))
            .and(header("x-api-key", "partner_key_secret_622"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "partner": "KeyPartner",
                "resubmission": true,
                "steps": [
                    {
                        "step_id": "business_profile",
                        "order": 1,
                        "fields": [
                            { "name": "commercial_register", "type": "file", "required": true }
                        ]
                    }
                ]
            })))
            .mount(&server)
            .await;

        let client = partner_client(&server.uri());
        let query = OnboardingSchemaQuery::new("KeyPartner")
            .expect("valid query")
            .with_resubmission(true)
            .with_paymob_mid(123);

        let schema = client
            .onboarding()
            .flow()
            .get_schema(&query)
            .await
            .expect("get_schema succeeds");
        assert_eq!(schema.partner.as_deref(), Some("KeyPartner"));
        assert_eq!(schema.resubmission, Some(true));
        assert_eq!(schema.steps.len(), 1);
    }

    #[tokio::test]
    async fn tc_6_2_2_missing_partner_credentials_returns_authentication_error() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("valid client");
        let query = OnboardingSchemaQuery::new("KeyPartner").expect("valid query");

        let err = client
            .onboarding()
            .flow()
            .get_schema(&query)
            .await
            .expect_err("missing partner_credentials must fail");
        assert!(matches!(err, PaymobError::AuthenticationError(_)));
    }

    #[tokio::test]
    async fn tc_6_2_2_maps_http_error_status_to_paymob_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/onboarding/flow/schema"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Invalid partner API key"))
            .mount(&server)
            .await;

        let client = partner_client(&server.uri());
        let query = OnboardingSchemaQuery::new("KeyPartner").expect("valid query");
        let err = client
            .onboarding()
            .flow()
            .get_schema(&query)
            .await
            .expect_err("401 must map to PaymobError");
        assert!(matches!(err, PaymobError::AuthenticationError(_)));
    }
}
