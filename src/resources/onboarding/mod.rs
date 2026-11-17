#![forbid(unsafe_code)]
//! Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping (`Module 6`).
//!
//! Provides [`OnboardingService`] (`paymob.onboarding()`) with:
//! - [`PartnerAuthService`] (`paymob.onboarding().auth()`): Partner login, API key provisioning, and HMAC secret retrieval (`US-6.1.0`).
//! - [`PartnerFlowService`] (`paymob.onboarding().flow()`): Sub-merchant registration, onboarding flow schema, step submission, and merchant inquiry (`US-6.2.0`).

pub mod auth_models;
pub mod flow_models;
pub mod hmac_secret;
pub mod login_apikey;
pub mod schema_register;
pub mod scoped_client;
pub mod step_inquiry;

use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;

use crate::core::auth::partner::PartnerAuthContext;
use crate::core::auth::strategy::AuthStrategy;
use crate::core::client::PaymobClient;
use crate::core::credentials::PartnerCredentials;
use crate::core::error::PaymobError;
use crate::core::http::{HttpRequest, HttpResponse};
pub(crate) use crate::core::types::{
    deserialize_non_empty_secret, deserialize_non_zero_u64,
    validate_non_zero_u64 as validate_non_zero_id,
};

pub use auth_models::{
    CreatePartnerApiKeyParams, PartnerApiKeyResponse, PartnerAuthTokenResponse, PartnerHmacBody,
    PartnerHmacEnvelope, PartnerLoginCredentials,
};
pub use flow_models::{
    OnboardingFlowSchema, OnboardingSchemaField, OnboardingSchemaQuery, OnboardingSchemaStep,
    PartnerMerchantInquiryResponse, RegisterMerchantParams, RegisteredMerchantResponse,
    SubmitOnboardingStepParams,
};
pub use scoped_client::MerchantScopedClient;
#[cfg(feature = "inquiries")]
pub use scoped_client::ScopedInquiries;
#[cfg(feature = "intentions")]
pub use scoped_client::ScopedIntentions;
#[cfg(feature = "manage")]
pub use scoped_client::ScopedManage;
pub use step_inquiry::SubmitOnboardingStepResponse;

/// Top-level Partner Merchant Onboarding service handle (`paymob.onboarding()`).
#[derive(Debug, Clone)]
pub struct OnboardingService {
    client: PaymobClient,
}

impl OnboardingService {
    /// Creates a new [`OnboardingService`] bound to `client`.
    #[must_use]
    pub const fn new(client: PaymobClient) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &PaymobClient {
        &self.client
    }

    /// Returns the Partner Authentication service (`US-6.1.0`).
    #[must_use]
    pub fn auth(&self) -> PartnerAuthService {
        PartnerAuthService::new(self.client.clone())
    }

    /// Returns the Partner Merchant Onboarding Flow service (`US-6.2.0`).
    #[must_use]
    pub fn flow(&self) -> PartnerFlowService {
        PartnerFlowService::new(self.client.clone())
    }
}

/// Service handle for Partner Authentication, API Key provisioning, and HMAC secret retrieval (`US-6.1.0`).
#[derive(Debug, Clone)]
pub struct PartnerAuthService {
    client: PaymobClient,
}

impl PartnerAuthService {
    /// Creates a new [`PartnerAuthService`] bound to `client`.
    #[must_use]
    pub const fn new(client: PaymobClient) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &PaymobClient {
        &self.client
    }
}

/// Service handle for Sub-Merchant Registration, Onboarding Flow Schema, Step Submission, and Inquiry (`US-6.2.0`).
#[derive(Debug, Clone)]
pub struct PartnerFlowService {
    client: PaymobClient,
}

impl PartnerFlowService {
    /// Creates a new [`PartnerFlowService`] bound to `client`.
    #[must_use]
    pub const fn new(client: PaymobClient) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &PaymobClient {
        &self.client
    }
}

impl PaymobClient {
    /// Returns the Partner Merchant Onboarding service (`Module 6`).
    #[must_use]
    pub fn onboarding(&self) -> OnboardingService {
        OnboardingService::new(self.clone())
    }
}

pub(crate) async fn execute_onboarding_request(
    client: &PaymobClient,
    request: &HttpRequest,
) -> Result<HttpResponse, PaymobError> {
    client.execute_request(request).await
}

pub(crate) fn decode_onboarding_json<T: DeserializeOwned>(
    response: &HttpResponse,
) -> Result<T, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(response));
    }
    response.json::<T>().map_err(PaymobError::from)
}

pub(crate) fn apply_header_map(mut request: HttpRequest, headers: &HeaderMap) -> HttpRequest {
    for (name, value) in headers {
        request = request.with_header(name.clone(), value.clone());
    }
    request
}

pub(crate) fn resolve_partner_bearer_headers(
    client: &PaymobClient,
    missing_reason: &'static str,
) -> Result<HeaderMap, PaymobError> {
    let _strategy = AuthStrategy::PartnerBearer;
    let bearer = client
        .config()
        .partner_credentials()
        .and_then(PartnerCredentials::bearer_token)
        .ok_or_else(|| PaymobError::AuthenticationError(String::from(missing_reason)))?;

    let ctx = PartnerAuthContext::bearer(bearer)
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    let mut headers = HeaderMap::new();
    ctx.apply_headers(&mut headers)
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    Ok(headers)
}

pub(crate) fn resolve_partner_api_key_headers(
    client: &PaymobClient,
    missing_reason: &'static str,
) -> Result<HeaderMap, PaymobError> {
    let _strategy = AuthStrategy::PartnerApiKey;
    let api_key = client
        .config()
        .partner_credentials()
        .map(PartnerCredentials::api_key)
        .ok_or_else(|| PaymobError::AuthenticationError(String::from(missing_reason)))?;

    let ctx = PartnerAuthContext::api_key_header(api_key)
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    let mut headers = HeaderMap::new();
    ctx.apply_headers(&mut headers)
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    Ok(headers)
}

pub(crate) fn validate_non_empty_trimmed(
    field: &'static str,
    value: &str,
    reason: &'static str,
) -> Result<(), PaymobError> {
    if value.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: String::from(reason),
        });
    }
    Ok(())
}

pub(crate) fn validate_no_control_chars(
    field: &'static str,
    value: &str,
) -> Result<(), PaymobError> {
    if value.chars().any(char::is_control) {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not contain control characters"),
        });
    }
    Ok(())
}
