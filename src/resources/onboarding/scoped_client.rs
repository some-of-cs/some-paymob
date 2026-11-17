#![forbid(unsafe_code)]
//! Multi-tenant sub-merchant client scoping (`US-6.2.0`).
//!
//! Provides [`PaymobClient::with_merchant`] and [`MerchantScopedClient`], an
//! immutable tenant-isolated view binding a Partner API Key (`Regime 4`) and a
//! validated non-zero `merchant_id` across scoped `.intentions()`,
//! `.inquiries()`, and `.manage()` operations.

use std::fmt;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use url::Url;

use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpClientConfig, HttpRequest, HttpResponse, RetryPolicy};

const PARTNER_API_KEY_HEADER: &str = "x-api-key";
const MERCHANT_ID_HEADER: &str = "x-paymob-merchant-id";

/// Immutable, thread-safe view of [`PaymobClient`] scoped to a single sub-merchant.
///
/// Created via [`PaymobClient::with_merchant`]. Cloning is `O(1)` via the
/// underlying `Arc`-backed [`PaymobClient`], and scoping never mutates the
/// parent client's configuration or tenant state.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::PartnerCredentials;
/// use some_paymob::core::region::PaymobRegion;
///
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .partner_credentials(PartnerCredentials::new("partner_api_key_123")?)
///     .build()?;
/// let paymob = PaymobClient::new(config)?;
///
/// let scoped = paymob.with_merchant(987_654)?;
/// assert_eq!(scoped.merchant_id(), 987_654);
/// assert!(format!("{scoped:?}").contains("[REDACTED]"));
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Clone)]
pub struct MerchantScopedClient {
    inner: PaymobClient,
    merchant_id: u64,
}

impl fmt::Debug for MerchantScopedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MerchantScopedClient")
            .field("merchant_id", &self.merchant_id)
            .field("inner", &self.inner)
            .finish()
    }
}

impl PaymobClient {
    /// Returns an immutable [`MerchantScopedClient`] bound to `merchant_id` and
    /// the configured Regime 4 [`PartnerCredentials`](crate::core::credentials::PartnerCredentials).
    ///
    /// # Errors
    ///
    /// Returns:
    /// - [`PaymobError::ValidationError`] if `merchant_id == 0`.
    /// - [`PaymobError::AuthenticationError`] if `partner_credentials` is not configured.
    pub fn with_merchant(&self, merchant_id: u64) -> Result<MerchantScopedClient, PaymobError> {
        if merchant_id == 0 {
            return Err(PaymobError::ValidationError {
                field: "merchant_id",
                reason: "merchant_id must be a non-zero merchant ID".to_owned(),
            });
        }
        if self.config().partner_credentials().is_none() {
            return Err(PaymobError::AuthenticationError(String::from(
                "partner_credentials must be configured for with_merchant scoping",
            )));
        }
        Ok(MerchantScopedClient {
            inner: self.clone(),
            merchant_id,
        })
    }
}

impl MerchantScopedClient {
    /// Returns the bound sub-merchant ID.
    #[must_use]
    pub const fn merchant_id(&self) -> u64 {
        self.merchant_id
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &PaymobClient {
        &self.inner
    }

    /// Builds the Regime 4 Partner API Key and tenant-scoping HTTP headers.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::AuthenticationError`] if `partner_credentials` is
    /// missing or contains invalid header bytes.
    pub fn scope_headers(&self) -> Result<HeaderMap, PaymobError> {
        let creds = self.inner.config().partner_credentials().ok_or_else(|| {
            PaymobError::AuthenticationError(String::from(
                "partner_credentials must be configured for with_merchant scoping",
            ))
        })?;
        let mut api_key_val = HeaderValue::from_str(creds.api_key())
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        api_key_val.set_sensitive(true);
        let mid_val = HeaderValue::from_str(&self.merchant_id.to_string())
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;

        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static(PARTNER_API_KEY_HEADER), api_key_val);
        headers.insert(HeaderName::from_static(MERCHANT_ID_HEADER), mid_val);
        Ok(headers)
    }

    /// Returns a scoped Payment Intentions service handle (`feature = "intentions"`).
    #[cfg(feature = "intentions")]
    #[must_use]
    pub const fn intentions(&self) -> ScopedIntentions<'_> {
        ScopedIntentions { scoped: self }
    }

    /// Returns a scoped Transaction & Order Inquiries service handle (`feature = "inquiries"`).
    #[cfg(feature = "inquiries")]
    #[must_use]
    pub const fn inquiries(&self) -> ScopedInquiries<'_> {
        ScopedInquiries { scoped: self }
    }

    /// Returns a scoped Payment Lifecycle Management handle (`feature = "manage"`).
    #[cfg(feature = "manage")]
    #[must_use]
    pub const fn manage(&self) -> ScopedManage<'_> {
        ScopedManage { scoped: self }
    }
}

/// Scoped Payment Intentions operations bound to a [`MerchantScopedClient`].
#[cfg(feature = "intentions")]
#[derive(Debug, Clone, Copy)]
pub struct ScopedIntentions<'a> {
    scoped: &'a MerchantScopedClient,
}

#[cfg(feature = "intentions")]
impl<'a> ScopedIntentions<'a> {
    /// Returns the bound sub-merchant ID.
    #[must_use]
    pub const fn merchant_id(&self) -> u64 {
        self.scoped.merchant_id()
    }

    /// Creates a v1 Payment Intention on behalf of the scoped sub-merchant (`POST /v1/intention/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::AuthenticationError`], [`PaymobError::ValidationError`],
    /// [`PaymobError::ApiError`], or [`PaymobError::TransportError`] on failure.
    pub async fn create(
        &self,
        params: &crate::resources::intentions::CreateIntentionParams,
    ) -> Result<crate::resources::intentions::IntentionResponse, PaymobError> {
        let headers = self.scoped.scope_headers()?;
        let url = self.scoped.client().accept_url("/v1/intention/")?;
        let mut request = HttpRequest::post(url.as_str())?.with_json(params)?;
        for (name, val) in &headers {
            request = request.with_header(name.clone(), val.clone());
        }
        let response = execute_scoped_request(self.scoped.client(), &request).await?;
        decode_json_response(&response)
    }
}

/// Scoped Transaction & Order Inquiries operations bound to a [`MerchantScopedClient`].
#[cfg(feature = "inquiries")]
#[derive(Debug, Clone, Copy)]
pub struct ScopedInquiries<'a> {
    scoped: &'a MerchantScopedClient,
}

#[cfg(feature = "inquiries")]
impl<'a> ScopedInquiries<'a> {
    /// Returns the bound sub-merchant ID.
    #[must_use]
    pub const fn merchant_id(&self) -> u64 {
        self.scoped.merchant_id()
    }

    /// Returns the underlying [`InquiriesService`](crate::resources::inquiries::InquiriesService).
    #[must_use]
    pub const fn service(&self) -> crate::resources::inquiries::InquiriesService<'a> {
        self.scoped.client().inquiries()
    }

    /// Queries a transaction by ID on behalf of the scoped sub-merchant
    /// (`GET /api/acceptance/transactions/{transaction_id}`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id == 0`, or
    /// [`PaymobError::AuthenticationError`] / [`PaymobError::ApiError`] / [`PaymobError::TransportError`].
    pub async fn transaction_by_id(
        &self,
        transaction_id: u64,
    ) -> Result<serde_json::Value, PaymobError> {
        if transaction_id == 0 {
            return Err(PaymobError::ValidationError {
                field: "transaction_id",
                reason: "transaction_id must be non-zero".to_owned(),
            });
        }
        let headers = self.scoped.scope_headers()?;
        let path = format!("/api/acceptance/transactions/{transaction_id}");
        let url = self.scoped.client().accept_url(&path)?;
        let mut request = HttpRequest::get(url.as_str())?;
        for (name, val) in &headers {
            request = request.with_header(name.clone(), val.clone());
        }
        let response = execute_scoped_request(self.scoped.client(), &request).await?;
        decode_json_response(&response)
    }
}

/// Scoped Payment Lifecycle Management operations bound to a [`MerchantScopedClient`].
#[cfg(feature = "manage")]
#[derive(Debug, Clone, Copy)]
pub struct ScopedManage<'a> {
    scoped: &'a MerchantScopedClient,
}

#[cfg(feature = "manage")]
impl<'a> ScopedManage<'a> {
    /// Returns the bound sub-merchant ID.
    #[must_use]
    pub const fn merchant_id(&self) -> u64 {
        self.scoped.merchant_id()
    }

    /// Returns the underlying [`ManageService`](crate::resources::manage::ManageService).
    #[must_use]
    pub const fn service(&self) -> crate::resources::manage::ManageService<'a> {
        self.scoped.client().manage()
    }

    /// Voids a transaction on behalf of the scoped sub-merchant
    /// (`POST /api/acceptance/void_refund/void`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id == 0`, or
    /// [`PaymobError::AuthenticationError`] / [`PaymobError::ApiError`] / [`PaymobError::TransportError`].
    pub async fn void_transaction(
        &self,
        transaction_id: u64,
    ) -> Result<serde_json::Value, PaymobError> {
        if transaction_id == 0 {
            return Err(PaymobError::ValidationError {
                field: "transaction_id",
                reason: "transaction_id must be non-zero".to_owned(),
            });
        }
        let headers = self.scoped.scope_headers()?;
        let url = self
            .scoped
            .client()
            .accept_url("/api/acceptance/void_refund/void")?;
        let payload = serde_json::json!({ "transaction_id": transaction_id });
        let mut request = HttpRequest::post(url.as_str())?.with_json(&payload)?;
        for (name, val) in &headers {
            request = request.with_header(name.clone(), val.clone());
        }
        let response = execute_scoped_request(self.scoped.client(), &request).await?;
        decode_json_response(&response)
    }
}

#[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
fn is_loopback_http(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))
}

#[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
async fn execute_scoped_request(
    client: &PaymobClient,
    request: &HttpRequest,
) -> Result<HttpResponse, PaymobError> {
    if !is_loopback_http(request.url()) {
        return client
            .http()
            .execute(request)
            .await
            .map_err(PaymobError::from);
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
    .map_err(PaymobError::from)?;
    local_http.execute(request).await.map_err(PaymobError::from)
}

#[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
fn decode_json_response<T: serde::de::DeserializeOwned>(
    response: &HttpResponse,
) -> Result<T, PaymobError> {
    if !response.status.is_success() {
        let body = response.text().unwrap_or_default();
        return Err(PaymobError::from_response(
            response.status.as_u16(),
            body,
            None,
        ));
    }
    response.json::<T>().map_err(PaymobError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::PartnerCredentials;
    use crate::core::region::PaymobRegion;

    #[test]
    fn tc_6_2_4_with_merchant_validates_mid_and_credentials() {
        let no_creds_cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("valid config");
        let no_creds = PaymobClient::new(no_creds_cfg).expect("valid client");
        assert!(matches!(
            no_creds.with_merchant(987_654),
            Err(PaymobError::AuthenticationError(_))
        ));

        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .partner_credentials(
                PartnerCredentials::new("partner_key_secret_624").expect("valid partner"),
            )
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");

        assert!(matches!(
            client.with_merchant(0),
            Err(PaymobError::ValidationError {
                field: "merchant_id",
                ..
            })
        ));

        let m1 = client.with_merchant(111_222).expect("valid scoped m1");
        let m2 = client.with_merchant(333_444).expect("valid scoped m2");
        assert_eq!(m1.merchant_id(), 111_222);
        assert_eq!(m2.merchant_id(), 333_444);
        assert!(m1.client().ptr_eq(&client));
        assert!(format!("{m1:?}").contains("[REDACTED]"));
        assert!(!format!("{m1:?}").contains("partner_key_secret_624"));
    }

    #[cfg(feature = "intentions")]
    #[tokio::test]
    async fn tc_6_2_4_scoped_intentions_dispatches_partner_key_and_merchant_id() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::core::types::Currency;
        use crate::resources::intentions::{
            BillingData, CreateIntentionParams, PaymentMethodInput,
        };

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/intention/"))
            .and(header("x-api-key", "partner_key_secret_624"))
            .and(header("x-paymob-merchant-id", "987654"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": "pi_scoped_123",
                "client_secret": "egy_csk_test_scoped",
                "status": "intended"
            })))
            .mount(&server)
            .await;

        let region = PaymobRegion::Custom {
            accept_base_url: server.uri(),
            checkout_base_url: format!("{}/unifiedcheckout/", server.uri()),
            payouts_base_url: server.uri(),
            payouts_staging_base_url: server.uri(),
        };
        let cfg = ClientConfig::builder()
            .region(region)
            .partner_credentials(
                PartnerCredentials::new("partner_key_secret_624").expect("valid partner"),
            )
            .max_retries(0)
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");

        let params = CreateIntentionParams::builder()
            .amount(10_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![PaymentMethodInput::IntegrationId(4_097_558)])
            .billing_data(
                BillingData::builder()
                    .phone_number("+201116491564")
                    .build()
                    .expect("valid billing"),
            )
            .build()
            .expect("valid intention params");

        let scoped = client.with_merchant(987_654).expect("valid scoped client");
        let resp = scoped
            .intentions()
            .create(&params)
            .await
            .expect("scoped intention create succeeds");
        assert_eq!(resp.id, "pi_scoped_123");
    }

    #[cfg(feature = "inquiries")]
    #[tokio::test]
    async fn tc_6_2_4_scoped_inquiries_dispatches_partner_key_and_merchant_id() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/42"))
            .and(header("x-api-key", "partner_key_secret_624"))
            .and(header("x-paymob-merchant-id", "987654"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "success": true
            })))
            .mount(&server)
            .await;

        let region = PaymobRegion::Custom {
            accept_base_url: server.uri(),
            checkout_base_url: format!("{}/unifiedcheckout/", server.uri()),
            payouts_base_url: server.uri(),
            payouts_staging_base_url: server.uri(),
        };
        let cfg = ClientConfig::builder()
            .region(region)
            .partner_credentials(
                PartnerCredentials::new("partner_key_secret_624").expect("valid partner"),
            )
            .max_retries(0)
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");

        let scoped = client.with_merchant(987_654).expect("valid scoped client");
        let tx = scoped
            .inquiries()
            .transaction_by_id(42)
            .await
            .expect("scoped transaction_by_id succeeds");
        assert_eq!(tx["id"], 42);
    }

    #[cfg(feature = "manage")]
    #[tokio::test]
    async fn tc_6_2_4_scoped_manage_dispatches_partner_key_and_merchant_id() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/void"))
            .and(header("x-api-key", "partner_key_secret_624"))
            .and(header("x-paymob-merchant-id", "987654"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "is_voided": true
            })))
            .mount(&server)
            .await;

        let region = PaymobRegion::Custom {
            accept_base_url: server.uri(),
            checkout_base_url: format!("{}/unifiedcheckout/", server.uri()),
            payouts_base_url: server.uri(),
            payouts_staging_base_url: server.uri(),
        };
        let cfg = ClientConfig::builder()
            .region(region)
            .partner_credentials(
                PartnerCredentials::new("partner_key_secret_624").expect("valid partner"),
            )
            .max_retries(0)
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");

        let scoped = client.with_merchant(987_654).expect("valid scoped client");
        let res = scoped
            .manage()
            .void_transaction(42)
            .await
            .expect("scoped void_transaction succeeds");
        assert_eq!(res["is_voided"], true);
    }
}
