#![forbid(unsafe_code)]
//! Payment lifecycle management service (`refund`, `void`, `capture`) for `US-3.1.0`.

pub mod models;
pub mod refund;
pub mod void_capture;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};
use secrecy::{ExposeSecret, SecretString};

use crate::core::auth::accept_jwt::AcceptJwtProvider;
use crate::core::auth::strategy::inject_secret_key_token;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{
    HttpClient, HttpClientConfig, HttpError, HttpRequest, HttpResponse, RetryPolicy,
};

/// Service handle for Paymob payment lifecycle management operations.
#[derive(Debug, Clone, Copy)]
pub struct ManageService<'a> {
    client: &'a PaymobClient,
}

impl<'a> ManageService<'a> {
    /// Creates a new [`ManageService`] bound to `client`.
    #[must_use]
    pub(crate) const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }

    pub(crate) async fn resolve_auth_header(
        &self,
        missing_secret_reason: &'static str,
    ) -> Result<HeaderValue, PaymobError> {
        if self.client().config().use_legacy_v2_bearer_for_capture() {
            return self.resolve_legacy_v2_bearer_header().await;
        }
        self.resolve_regime1_token_header(missing_secret_reason)
    }

    fn resolve_regime1_token_header(
        &self,
        missing_secret_reason: &'static str,
    ) -> Result<HeaderValue, PaymobError> {
        let secret_key =
            self.client().config().secret_key().ok_or_else(|| {
                PaymobError::AuthenticationError(String::from(missing_secret_reason))
            })?;
        let mut headers = HeaderMap::new();
        let secret = SecretString::from(secret_key.expose_secret().to_owned());
        inject_secret_key_token(&mut headers, &secret)
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        headers.remove(AUTHORIZATION).ok_or_else(|| {
            PaymobError::AuthenticationError(String::from(
                "failed to construct Regime 1 Authorization header",
            ))
        })
    }

    async fn resolve_legacy_v2_bearer_header(&self) -> Result<HeaderValue, PaymobError> {
        let api_key = self.client().config().api_key().ok_or_else(|| {
            PaymobError::AuthenticationError(String::from(
                "api_key is required when use_legacy_v2_bearer_for_capture is enabled",
            ))
        })?;
        let base_url = self.client().accept_url("/")?;
        let provider = AcceptJwtProvider::with_cache(
            base_url.as_str(),
            SecretString::from(api_key.expose_secret().to_owned()),
            self.client().auth().accept_cache_arc(),
        )
        .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;

        let jwt = provider
            .token()
            .await
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        let mut header_val = HeaderValue::from_str(&format!("Bearer {}", jwt.expose_secret()))
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        header_val.set_sensitive(true);
        Ok(header_val)
    }
}

impl PaymobClient {
    /// Returns the payment lifecycle management service (`refund`, `void`, `capture`).
    #[must_use]
    pub const fn manage(&self) -> ManageService<'_> {
        ManageService::new(self)
    }
}

pub(crate) async fn execute_manage_request(
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
