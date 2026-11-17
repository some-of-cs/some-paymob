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

use crate::core::client::PaymobClient;

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
