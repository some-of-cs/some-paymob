#![forbid(unsafe_code)]
//! Transaction, order, and saved card token inquiry service (`US-3.2.0`).

pub mod by_id;
pub mod by_order;
pub mod card_tokens;
pub mod order_inquiry;

pub use by_id::{Transaction, TransactionOrder, TransactionOrderDetails, TransactionSourceData};
pub use by_order::TransactionInquiryParams;
pub use card_tokens::{CardTokenEnvelope, CardTokenObject};
pub use order_inquiry::{OrderInquiryResponse, OrderShippingData, OrderTransactionAttempt};

use reqwest::Method;
use secrecy::SecretString;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::core::auth::accept_jwt::inject_body_auth_token;
use crate::core::client::{PaymobClient, build_bearer_json_request};
use crate::core::error::PaymobError;
use crate::core::http::{HttpRequest, HttpResponse};

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

fn missing_inquiry_api_key() -> PaymobError {
    PaymobError::ValidationError {
        field: "api_key",
        reason: "api_key must be configured for Regime 2 inquiry endpoints".to_owned(),
    }
}

pub(crate) async fn execute_inquiry_bearer_get<T: DeserializeOwned>(
    service: &InquiriesService<'_>,
    path: &str,
) -> Result<T, PaymobError> {
    let url = service.client().accept_url(path)?;
    let response = service
        .client()
        .execute_regime2_with_retry(missing_inquiry_api_key, |token| {
            build_bearer_json_request::<()>(Method::GET, url.as_str(), token, None)
        })
        .await?;
    decode_inquiry_response(&response)
}

pub(crate) async fn execute_inquiry_body_post<T: DeserializeOwned>(
    service: &InquiriesService<'_>,
    path: &str,
    base_body: &Value,
) -> Result<T, PaymobError> {
    let url = service.client().accept_url(path)?;
    let response = service
        .client()
        .execute_regime2_with_retry(missing_inquiry_api_key, |token| {
            build_body_auth_post_request(url.as_str(), base_body, token)
        })
        .await?;
    decode_inquiry_response(&response)
}

fn build_body_auth_post_request(
    url: &str,
    base_body: &Value,
    token: &SecretString,
) -> Result<HttpRequest, PaymobError> {
    let mut body = base_body.clone();
    inject_body_auth_token(&mut body, token).map_err(PaymobError::from)?;
    HttpRequest::post(url)
        .map_err(PaymobError::from)?
        .with_json(&body)
        .map_err(PaymobError::from)
}

fn decode_inquiry_response<T: DeserializeOwned>(response: &HttpResponse) -> Result<T, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(response));
    }
    response.json::<T>().map_err(PaymobError::from)
}
