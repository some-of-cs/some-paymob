#![forbid(unsafe_code)]
//! Paymob Send Payouts & Disbursement service (`US-5.1.0` & `US-5.2.0`).
//!
//! Covers Regime 3 OAuth 2.0 (`auth()`), Instant & Bulk Cashin (`cashin()`),
//! Transaction/Reference/Budget/Topup Inquiries (`inquiries()`), and Topup
//! Requests (`topups()`).

pub mod auth;
pub mod bank_cashin;
pub mod budget;
pub mod bulk;
pub mod inquiries;
pub mod models;
pub mod topups;
pub mod wallet_cashin;

pub use auth::*;
pub use bank_cashin::*;
pub use budget::*;
pub use bulk::*;
pub use inquiries::*;
pub use models::*;
pub use topups::*;
pub use wallet_cashin::*;

use reqwest::header::HeaderValue;
use secrecy::ExposeSecret;

use crate::core::auth::payouts_oauth::{PayoutsCredentials, PayoutsOAuthProvider};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{
    HttpClient, HttpClientConfig, HttpError, HttpRequest, HttpResponse, RetryPolicy,
};

/// Top-level Paymob Send Payouts service handle (`paymob.payouts()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsService<'a> {
    /// Creates a new [`PayoutsService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }

    /// Returns the Payouts OAuth 2.0 token service (`POST /api/secure/o/token/`).
    #[must_use]
    pub const fn auth(&self) -> auth::PayoutsAuthService<'a> {
        auth::PayoutsAuthService::new(self.client)
    }

    /// Returns the Instant & Bulk Cashin disbursement service.
    #[must_use]
    pub const fn cashin(&self) -> PayoutsCashinService<'a> {
        PayoutsCashinService::new(self.client)
    }

    /// Returns the Payouts transaction, reference, budget, and topup inquiry service.
    #[must_use]
    pub const fn inquiries(&self) -> PayoutsInquiriesService<'a> {
        PayoutsInquiriesService::new(self.client)
    }

    /// Returns the Payouts topup request service (Bank Transfer & Accept Balance).
    #[must_use]
    pub const fn topups(&self) -> topups::PayoutsTopupsService<'a> {
        topups::PayoutsTopupsService::new(self.client)
    }
}

/// Instant & Bulk Cashin disbursement service (`paymob.payouts().cashin()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsCashinService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsCashinService<'a> {
    /// Creates a new [`PayoutsCashinService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }
}

/// Payouts inquiry service (`paymob.payouts().inquiries()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsInquiriesService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsInquiriesService<'a> {
    /// Creates a new [`PayoutsInquiriesService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }
}

/// Resolves a Regime 3 `Authorization: Bearer <access_token>` header using the
/// client's Payouts cache or configured [`PayoutsCredentials`].
pub(crate) async fn resolve_payouts_bearer_header(
    client: &PaymobClient,
) -> Result<HeaderValue, PaymobError> {
    if let Some(cached) = client.auth().payouts_cache().peek() {
        return build_bearer_header(cached.access_token.expose_secret());
    }
    let core_creds = client.config().payouts_credentials().ok_or_else(|| {
        PaymobError::AuthenticationError(String::from(
            "payouts_credentials are required for Paymob Send Payouts endpoints",
        ))
    })?;
    let base_url = client.payouts_url("/")?;
    let provider = PayoutsOAuthProvider::with_client_and_cache(
        base_url.as_str(),
        PayoutsCredentials::from(core_creds),
        reqwest::Client::new(),
        client.auth().payouts_cache_arc(),
    )
    .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    let token = provider
        .access_token()
        .await
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    build_bearer_header(token.expose_secret())
}

fn build_bearer_header(token: &str) -> Result<HeaderValue, PaymobError> {
    let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
    header.set_sensitive(true);
    Ok(header)
}

pub(crate) async fn execute_payouts_request(
    client: &PaymobClient,
    request: &HttpRequest,
) -> Result<HttpResponse, PaymobError> {
    let is_loopback_http = request.url().scheme() == "http"
        && matches!(
            request.url().host_str(),
            Some("127.0.0.1" | "localhost" | "[::1]")
        );
    if !is_loopback_http {
        return client.http().execute(request).await.map_err(map_http_error);
    }
    let cfg = client.config();
    let local_http = HttpClient::new(HttpClientConfig {
        connect_timeout: cfg.timeout(),
        request_timeout: cfg.timeout(),
        max_response_bytes: client.http().config().max_response_bytes,
        retry: RetryPolicy {
            max_retries: cfg.max_retries(),
            ..RetryPolicy::default()
        },
        allow_insecure_http: true,
    })
    .map_err(map_http_error)?;
    local_http.execute(request).await.map_err(map_http_error)
}

pub(crate) fn map_http_error(err: HttpError) -> PaymobError {
    PaymobError::from(err)
}

pub(crate) fn parse_payouts_response<T: serde::de::DeserializeOwned>(
    response: &HttpResponse,
) -> Result<T, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(response));
    }
    response.json::<T>().map_err(map_http_error)
}
