#![forbid(unsafe_code)]
//! Payment lifecycle management service (`refund`, `void`, `capture`) for `US-3.1.0`.

pub mod models;
pub mod refund;
pub mod void_capture;

pub use models::Transaction;
pub use refund::RefundParams;
pub use void_capture::{CaptureParams, VoidParams};

use reqwest::Method;
use reqwest::header::AUTHORIZATION;
use serde::Serialize;

use crate::core::client::{PaymobClient, build_bearer_json_request};
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

    fn uses_legacy_v2_bearer(&self) -> bool {
        self.use_legacy_v2_bearer || self.client().config().use_legacy_v2_bearer_for_capture()
    }

    pub(crate) async fn execute_post_json<T: Serialize>(
        &self,
        path: &str,
        payload: &T,
        missing_secret_reason: &'static str,
    ) -> Result<HttpResponse, PaymobError> {
        let url = self.client().accept_url(path)?;
        if self.uses_legacy_v2_bearer() {
            return self
                .client()
                .execute_regime2_with_retry(
                    || {
                        PaymobError::AuthenticationError(String::from(
                            "api_key is required when use_legacy_v2_bearer_for_capture is enabled",
                        ))
                    },
                    |token| build_bearer_json_request(Method::POST, url.as_str(), token, Some(payload)),
                )
                .await;
        }
        let auth_header = self.client().regime1_token_header(missing_secret_reason)?;
        let request = HttpRequest::post(url.as_str())
            .map_err(map_http_error)?
            .with_header(AUTHORIZATION, auth_header)
            .with_json(payload)
            .map_err(|err| PaymobError::ValidationError {
                field: "params",
                reason: err.to_string(),
            })?;
        execute_manage_request(self.client(), &request).await
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
