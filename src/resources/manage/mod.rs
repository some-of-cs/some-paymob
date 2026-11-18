#![forbid(unsafe_code)]
//! Payment lifecycle management service (`refund`, `void`, `capture`) for `US-3.1.0`.

pub mod models;
pub mod refund;
pub mod void_capture;

pub use models::Transaction;
pub use refund::RefundParams;
pub use void_capture::{CaptureParams, VoidParams};

use reqwest::header::HeaderValue;

use crate::core::auth::accept_jwt::format_bearer_header;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpError, HttpRequest, HttpResponse};

/// Service handle for Paymob payment lifecycle management operations.
#[derive(Debug, Clone, Copy)]
pub struct ManageService<'a> {
    client: &'a PaymobClient,
    use_legacy_v2_bearer: bool,
}

impl<'a> ManageService<'a> {
    /// Creates a new [`ManageService`] bound to `client`.
    #[must_use]
    pub(crate) const fn new(client: &'a PaymobClient) -> Self {
        Self {
            client,
            use_legacy_v2_bearer: false,
        }
    }

    /// Configures this [`ManageService`] handle to authenticate `void` and `capture`
    /// requests using Legacy Accept v2 Regime 2 (`Authorization: Bearer <auth_token>`).
    #[must_use]
    pub const fn with_legacy_v2_bearer(mut self) -> Self {
        self.use_legacy_v2_bearer = true;
        self
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
        if self.use_legacy_v2_bearer || self.client().config().use_legacy_v2_bearer_for_capture() {
            return self.resolve_legacy_v2_bearer_header().await;
        }
        self.client().regime1_token_header(missing_secret_reason)
    }

    async fn resolve_legacy_v2_bearer_header(&self) -> Result<HeaderValue, PaymobError> {
        let jwt = self
            .client()
            .acquire_accept_jwt(|| {
                PaymobError::AuthenticationError(String::from(
                    "api_key is required when use_legacy_v2_bearer_for_capture is enabled",
                ))
            })
            .await?;
        format_bearer_header(&jwt).map_err(|err| PaymobError::AuthenticationError(err.to_string()))
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
    client.execute_request(request).await
}

pub(crate) fn map_http_error(err: HttpError) -> PaymobError {
    PaymobError::from(err)
}
