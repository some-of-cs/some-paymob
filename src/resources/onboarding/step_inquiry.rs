#![forbid(unsafe_code)]
//! Partner onboarding KYC step submission and sub-merchant status inquiry (`US-6.2.0`).
//!
//! Implements [`PartnerFlowService::submit_step`] (`POST /api/onboarding/flow/step`)
//! and [`PartnerFlowService::merchant_inquiry`] (`GET /api/onboarding/merchant/{mid}`)
//! under Regime 4 [`PartnerApiKey`](crate::core::auth::strategy::AuthStrategy::PartnerApiKey)
//! authentication.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::core::error::PaymobError;
use crate::core::http::HttpRequest;
use crate::resources::onboarding::flow_models::{
    PartnerMerchantInquiryResponse, SubmitOnboardingStepParams,
};
use crate::resources::onboarding::{
    PartnerFlowService, apply_header_map, decode_onboarding_json, execute_onboarding_request,
    resolve_partner_api_key_headers, validate_non_zero_id,
};

const SUBMIT_STEP_PATH: &str = "/api/onboarding/flow/step";

/// Response returned after submitting an onboarding KYC step.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::onboarding::step_inquiry::SubmitOnboardingStepResponse;
///
/// let json = r#"{"paymob_mid": 987654, "step_id": "business_profile", "status": "completed", "completed": true}"#;
/// let resp: SubmitOnboardingStepResponse = serde_json::from_str(json)?;
/// assert_eq!(resp.paymob_mid, Some(987_654));
/// assert_eq!(resp.completed, Some(true));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitOnboardingStepResponse {
    /// Sub-merchant Paymob MID, if echoed by the API.
    #[serde(default, alias = "id", alias = "merchant_id")]
    pub paymob_mid: Option<u64>,
    /// Submitted step identifier.
    #[serde(default)]
    pub step_id: Option<String>,
    /// Step or onboarding status reported by Paymob.
    #[serde(default)]
    pub status: Option<String>,
    /// Whether the step is marked complete.
    #[serde(default)]
    pub completed: Option<bool>,
    /// Additional response fields returned by Paymob.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PartnerFlowService {
    /// Submits a completed onboarding KYC step (`POST /api/onboarding/flow/step`).
    ///
    /// Authenticates under Regime 4 `PartnerApiKey` (`x-api-key` header).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `params.paymob_mid()` is `0` or `step_id` is empty.
    /// - [`PaymobError::AuthenticationError`] if `partner_credentials` is missing.
    /// - [`PaymobError::ApiError`], [`PaymobError::RateLimited`], or [`PaymobError::TransportError`]
    ///   if the Paymob API rejects or fails to process the request.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use serde_json::{Map, Value};
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::PartnerCredentials;
    /// use some_paymob::core::region::PaymobRegion;
    /// use some_paymob::resources::onboarding::flow_models::SubmitOnboardingStepParams;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .partner_credentials(PartnerCredentials::new("partner_api_key_123")?)
    ///     .build()?;
    /// let paymob = PaymobClient::new(config)?;
    ///
    /// let mut data = Map::new();
    /// data.insert("commercial_register".into(), Value::String("CR-998877".into()));
    /// let params = SubmitOnboardingStepParams::new(987_654, "business_profile", data)?;
    ///
    /// let res = paymob.onboarding().flow().submit_step(&params).await?;
    /// println!("step status={:?}", res.status);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn submit_step(
        &self,
        params: &SubmitOnboardingStepParams,
    ) -> Result<SubmitOnboardingStepResponse, PaymobError> {
        params.validate()?;
        let headers = resolve_partner_api_key_headers(
            self.client(),
            "partner_credentials must be configured for Regime 4 onboarding endpoints",
        )?;
        let url = self.client().accept_url(SUBMIT_STEP_PATH)?;
        let req = HttpRequest::post(url.as_str())?.with_json(params)?;
        let request = apply_header_map(req, &headers);
        let response = execute_onboarding_request(self.client(), &request).await?;
        decode_onboarding_json(&response)
    }

    /// Queries a sub-merchant's onboarding approval status and provisioned live integration IDs
    /// (`GET /api/onboarding/merchant/{mid}`).
    ///
    /// Authenticates under Regime 4 `PartnerApiKey` (`x-api-key` header).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `mid == 0`.
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
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .partner_credentials(PartnerCredentials::new("partner_api_key_123")?)
    ///     .build()?;
    /// let paymob = PaymobClient::new(config)?;
    ///
    /// let inquiry = paymob.onboarding().flow().merchant_inquiry(987_654).await?;
    /// if inquiry.is_approved() && inquiry.has_live_integrations() {
    ///     println!("live integrations: {:?}", inquiry.live_integration_ids);
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn merchant_inquiry(
        &self,
        mid: u64,
    ) -> Result<PartnerMerchantInquiryResponse, PaymobError> {
        validate_non_zero_id("mid", mid, "mid must be a non-zero merchant ID")?;
        let headers = resolve_partner_api_key_headers(
            self.client(),
            "partner_credentials must be configured for Regime 4 onboarding endpoints",
        )?;
        let path = format!("/api/onboarding/merchant/{mid}");
        let url = self.client().accept_url(&path)?;
        let request = apply_header_map(HttpRequest::get(url.as_str())?, &headers);
        let response = execute_onboarding_request(self.client(), &request).await?;
        decode_onboarding_json(&response)
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
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
                PartnerCredentials::new("partner_key_secret_623").expect("valid partner creds"),
            )
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    #[tokio::test]
    async fn tc_6_2_3_submit_step_dispatches_post_with_partner_api_key() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/onboarding/flow/step"))
            .and(header("x-api-key", "partner_key_secret_623"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "paymob_mid": 987654,
                "step_id": "business_profile",
                "status": "completed",
                "completed": true
            })))
            .mount(&server)
            .await;

        let client = partner_client(&server.uri());
        let mut data = Map::new();
        data.insert(
            "commercial_register".into(),
            Value::String("CR-998877".into()),
        );
        let params = SubmitOnboardingStepParams::new(987_654, "business_profile", data)
            .expect("valid params");

        let resp = client
            .onboarding()
            .flow()
            .submit_step(&params)
            .await
            .expect("submit_step succeeds");
        assert_eq!(resp.paymob_mid, Some(987_654));
        assert_eq!(resp.completed, Some(true));
    }

    #[tokio::test]
    async fn tc_6_2_3_merchant_inquiry_returns_approval_and_live_integrations() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/onboarding/merchant/987654"))
            .and(header("x-api-key", "partner_key_secret_623"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "paymob_mid": 987654,
                "status": "approved",
                "is_live": true,
                "live_integration_ids": [4097558, 4097559],
                "test_integration_ids": [100200],
                "pending_steps": []
            })))
            .mount(&server)
            .await;

        let client = partner_client(&server.uri());
        let inquiry = client
            .onboarding()
            .flow()
            .merchant_inquiry(987_654)
            .await
            .expect("merchant_inquiry succeeds");
        assert_eq!(inquiry.paymob_mid, 987_654);
        assert!(inquiry.is_approved());
        assert!(inquiry.has_live_integrations());
        assert_eq!(inquiry.live_integration_ids, vec![4_097_558, 4_097_559]);
    }

    #[tokio::test]
    async fn tc_6_2_3_merchant_inquiry_rejects_zero_mid() {
        let client = partner_client("http://127.0.0.1:1");
        let err = client
            .onboarding()
            .flow()
            .merchant_inquiry(0)
            .await
            .expect_err("mid=0 must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError { field: "mid", .. }
        ));
    }

    #[tokio::test]
    async fn tc_6_2_3_missing_partner_credentials_returns_authentication_error() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("valid client");

        let err = client
            .onboarding()
            .flow()
            .merchant_inquiry(987_654)
            .await
            .expect_err("missing partner_credentials must fail");
        assert!(matches!(err, PaymobError::AuthenticationError(_)));
    }
}
