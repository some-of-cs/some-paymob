#![forbid(unsafe_code)]
//! Full order record and payment-attempt inquiry (`GET /api/ecommerce/orders/{order_id}`).
//!
//! Implements Unit 4 (`TC-3.2.4`) of `US-3.2.0` under Regime 2
//! (`Authorization: Bearer <auth_token>`).

use std::fmt;

use reqwest::header::AUTHORIZATION;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::core::auth::accept_jwt::{AcceptJwtError, AcceptJwtProvider, format_bearer_header};
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpClientConfig, HttpRequest, HttpResponse, RetryPolicy};
use crate::resources::inquiries::InquiriesService;

/// Summary of an individual payment attempt nested inside [`OrderInquiryResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderTransactionAttempt {
    /// Paymob transaction identifier.
    pub id: u64,
    /// Whether the attempt is still pending.
    #[serde(default)]
    pub pending: bool,
    /// Attempt amount in integer minor units.
    pub amount_cents: u64,
    /// Whether the attempt succeeded.
    #[serde(default)]
    pub success: bool,
    /// Whether the attempt was an authorization.
    #[serde(default)]
    pub is_auth: bool,
    /// Whether the attempt was a capture.
    #[serde(default)]
    pub is_capture: bool,
    /// Whether the attempt was voided.
    #[serde(default)]
    pub is_voided: bool,
    /// Whether the attempt was refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: String,
    /// ISO-4217 currency code.
    #[serde(default)]
    pub currency: String,
    /// Whether an error occurred during this attempt.
    #[serde(default)]
    pub error_occured: bool,
}

/// Customer shipping metadata attached to an [`OrderInquiryResponse`].
///
/// PII fields (`email`, `phone_number`, `first_name`, `last_name`) are redacted
/// in `Debug` output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderShippingData {
    /// Customer first name.
    #[serde(default)]
    pub first_name: Option<String>,
    /// Customer last name.
    #[serde(default)]
    pub last_name: Option<String>,
    /// Customer email address.
    #[serde(default)]
    pub email: Option<String>,
    /// Customer phone number.
    #[serde(default)]
    pub phone_number: Option<String>,
    /// City name.
    #[serde(default)]
    pub city: Option<String>,
    /// ISO country code or name.
    #[serde(default)]
    pub country: Option<String>,
}

impl fmt::Debug for OrderShippingData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OrderShippingData")
            .field("first_name", &self.first_name.as_ref().map(|_| "[REDACTED]"))
            .field("last_name", &self.last_name.as_ref().map(|_| "[REDACTED]"))
            .field("email", &self.email.as_ref().map(|_| "[REDACTED]"))
            .field(
                "phone_number",
                &self.phone_number.as_ref().map(|_| "[REDACTED]"),
            )
            .field("city", &self.city)
            .field("country", &self.country)
            .finish()
    }
}

/// Full order record returned by `GET /api/ecommerce/orders/{order_id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderInquiryResponse {
    /// Paymob order identifier.
    pub id: u64,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: String,
    /// Whether physical delivery is required.
    #[serde(default)]
    pub delivery_needed: bool,
    /// Order total in integer minor units.
    pub amount_cents: u64,
    /// Total paid amount in integer minor units.
    #[serde(default)]
    pub paid_amount_cents: u64,
    /// ISO-4217 currency code.
    #[serde(default)]
    pub currency: String,
    /// Optional merchant-supplied order reference.
    #[serde(default)]
    pub merchant_order_id: Option<String>,
    /// Current payment status (for example, `"PAID"`, `"UNPAID"`).
    #[serde(default)]
    pub payment_status: Option<String>,
    /// Whether payment attempts are locked on this order.
    #[serde(default)]
    pub is_payment_locked: bool,
    /// Whether this order is a return order.
    #[serde(default)]
    pub is_return: bool,
    /// Whether this order is a cancel order.
    #[serde(default)]
    pub is_cancel: bool,
    /// Whether this order has been returned.
    #[serde(default)]
    pub is_returned: bool,
    /// Whether this order has been canceled.
    #[serde(default)]
    pub is_canceled: bool,
    /// Nested payment attempt transactions for this order.
    #[serde(default)]
    pub transactions: Vec<OrderTransactionAttempt>,
    /// Optional shipping/customer metadata (PII redacted in `Debug`).
    #[serde(default)]
    pub shipping_data: Option<OrderShippingData>,
}

impl<'a> InquiriesService<'a> {
    /// Retrieves the full Paymob order record and nested payment attempts via
    /// `GET /api/ecommerce/orders/{order_id}`.
    ///
    /// Authenticates using Regime 2 `Authorization: Bearer <auth_token>`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `order_id` is `0` or `api_key`
    /// is missing, [`PaymobError::AuthenticationError`] on rejected credentials,
    /// or [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on failure.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("example_api_key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let order = client.inquiries().order(212_245_716).await?;
    /// assert_eq!(order.id, 212_245_716);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn order(&self, order_id: u64) -> Result<OrderInquiryResponse, PaymobError> {
        if order_id == 0 {
            return Err(PaymobError::ValidationError {
                field: "order_id",
                reason: "order_id must be greater than zero".to_owned(),
            });
        }

        let token = acquire_accept_jwt(self).await?;
        let url = self
            .client()
            .accept_url(&format!("/api/ecommerce/orders/{order_id}"))?;
        let bearer = format_bearer_header(&token).map_err(map_accept_jwt_error)?;
        let request = HttpRequest::get(url.as_str())
            .map_err(PaymobError::from)?
            .with_header(AUTHORIZATION, bearer);

        let response = execute_accept_request(self, &url, &request).await?;
        if !response.status.is_success() {
            return Err(PaymobError::from_http_response(&response));
        }

        response
            .json::<OrderInquiryResponse>()
            .map_err(PaymobError::from)
    }
}

async fn acquire_accept_jwt(service: &InquiriesService<'_>) -> Result<SecretString, PaymobError> {
    let api_key = service.client().config().api_key().ok_or_else(|| {
        PaymobError::ValidationError {
            field: "api_key",
            reason: "api_key must be configured for Regime 2 inquiry endpoints".to_owned(),
        }
    })?;
    let provider = AcceptJwtProvider::new(
        service.client().endpoints().accept_base_url.as_str(),
        SecretString::from(api_key.expose_secret().to_owned()),
    )
    .map_err(map_accept_jwt_error)?;
    provider.token().await.map_err(map_accept_jwt_error)
}

async fn execute_accept_request(
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

fn map_accept_jwt_error(err: AcceptJwtError) -> PaymobError {
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

#[cfg(test)]
mod tests {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::client::PaymobClient;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::region::PaymobRegion;

    fn mock_client(base_url: &str) -> PaymobClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
        };
        let cfg = ClientConfig::builder()
            .region(region)
            .api_key(ApiKey::new("test_api_key_123").expect("valid api key"))
            .max_retries(0)
            .build()
            .expect("valid config");
        PaymobClient::new(cfg).expect("valid client")
    }

    #[tokio::test]
    async fn tc_3_2_4_order_inquiry_returns_attempts_and_redacts_pii() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(
                ResponseTemplate::new(201).set_body_json(serde_json::json!({"token": "jwt_ord"})),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/api/ecommerce/orders/212245716"))
            .and(header("Authorization", "Bearer jwt_ord"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 212245716,
                "created_at": "2026-11-16T09:55:00Z",
                "delivery_needed": false,
                "amount_cents": 25000,
                "paid_amount_cents": 25000,
                "currency": "EGP",
                "merchant_order_id": "order_estatestack_2026_001",
                "payment_status": "PAID",
                "is_payment_locked": true,
                "transactions": [
                    {
                        "id": 192036460,
                        "pending": false,
                        "amount_cents": 25000,
                        "success": false,
                        "created_at": "2026-11-16T09:56:00Z",
                        "currency": "EGP",
                        "error_occured": true
                    },
                    {
                        "id": 192036465,
                        "pending": false,
                        "amount_cents": 25000,
                        "success": true,
                        "created_at": "2026-11-16T10:00:00Z",
                        "currency": "EGP",
                        "error_occured": false
                    }
                ],
                "shipping_data": {
                    "first_name": "Maher",
                    "last_name": "Alaa",
                    "email": "maher@example.com",
                    "phone_number": "+201000000000",
                    "city": "Mansoura",
                    "country": "EG"
                }
            })))
            .mount(&server)
            .await;

        let client = mock_client(&server.uri());
        let order = client
            .inquiries()
            .order(212_245_716)
            .await
            .expect("order inquiry should succeed");

        assert_eq!(order.id, 212_245_716);
        assert_eq!(order.paid_amount_cents, 25_000);
        assert_eq!(order.transactions.len(), 2);
        assert!(!order.transactions[0].success);
        assert!(order.transactions[1].success);

        let dbg = format!("{order:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("maher@example.com"));
        assert!(!dbg.contains("+201000000000"));
    }

    #[tokio::test]
    async fn tc_3_2_4_rejects_zero_order_id() {
        let client = mock_client("http://127.0.0.1:9999");
        let err = client
            .inquiries()
            .order(0)
            .await
            .expect_err("zero order_id must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "order_id",
                ..
            }
        ));
    }
}
