#![forbid(unsafe_code)]
//! Transaction, order, and saved card token inquiry service (`US-3.2.0`).

pub mod by_id;
pub mod by_order;
pub mod card_tokens;
pub mod order_inquiry;

use secrecy::SecretString;
use url::Url;

use crate::core::auth::accept_jwt::{AcceptJwtError, AcceptJwtProvider};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpClientConfig, HttpRequest, HttpResponse, RetryPolicy};

/// Service handle for Paymob transaction, order, and saved card token inquiries.
#[derive(Debug, Clone, Copy)]
pub struct InquiriesService<'a> {
    client: &'a PaymobClient,
}

impl<'a> InquiriesService<'a> {
    /// Creates a new [`InquiriesService`] bound to `client`.
    #[must_use]
    pub(crate) const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }
}

impl PaymobClient {
    /// Returns the transaction, order, and saved card token inquiry service.
    #[must_use]
    pub const fn inquiries(&self) -> InquiriesService<'_> {
        InquiriesService::new(self)
    }
}

pub(crate) async fn acquire_accept_jwt(
    service: &InquiriesService<'_>,
) -> Result<SecretString, PaymobError> {
    let api_key =
        service
            .client()
            .config()
            .api_key()
            .ok_or_else(|| PaymobError::ValidationError {
                field: "api_key",
                reason: "api_key must be configured for Regime 2 inquiry endpoints".to_owned(),
            })?;
    let provider = AcceptJwtProvider::with_cache(
        service.client().endpoints().accept_base_url.as_str(),
        SecretString::from(api_key.expose_secret().to_owned()),
        service.client().auth().accept_cache_arc(),
    )
    .map_err(map_accept_jwt_error)?;
    provider.token().await.map_err(map_accept_jwt_error)
}

pub(crate) async fn execute_accept_request(
    service: &InquiriesService<'_>,
    url: &Url,
    request: &HttpRequest,
) -> Result<HttpResponse, PaymobError> {
    if url.scheme() == "https" {
        return service
            .client()
            .http()
            .execute(request)
            .await
            .map_err(PaymobError::from);
    }

    let cfg = service.client().config();
    let local_http = HttpClient::new(HttpClientConfig {
        connect_timeout: cfg.timeout(),
        request_timeout: cfg.timeout(),
        max_response_bytes: service.client().http().config().max_response_bytes,
        retry: RetryPolicy {
            max_retries: cfg.max_retries(),
            ..RetryPolicy::default()
        },
        allow_insecure_http: true,
    })
    .map_err(PaymobError::from)?;
    local_http.execute(request).await.map_err(PaymobError::from)
}

pub(crate) fn map_accept_jwt_error(err: AcceptJwtError) -> PaymobError {
    match err {
        AcceptJwtError::EmptyApiKey => PaymobError::ValidationError {
            field: "api_key",
            reason: err.to_string(),
        },
        AcceptJwtError::InvalidBaseUrl(_) | AcceptJwtError::InvalidJsonBody => {
            PaymobError::ValidationError {
                field: "accept_base_url",
                reason: err.to_string(),
            }
        }
        AcceptJwtError::InvalidCredentials | AcceptJwtError::InvalidHeaderValue => {
            PaymobError::AuthenticationError(err.to_string())
        }
        AcceptJwtError::UnexpectedStatus { status, detail } => {
            PaymobError::from_response(status, &detail, None)
        }
        AcceptJwtError::MissingTokenField | AcceptJwtError::Transport(_) => {
            PaymobError::TransportError(err.to_string())
        }
    }
}
