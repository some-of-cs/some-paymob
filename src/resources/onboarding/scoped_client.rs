#![forbid(unsafe_code)]
//! Multi-tenant sub-merchant client scoping (`US-6.2.0`).
//!
//! Provides [`PaymobClient::with_merchant`] and [`MerchantScopedClient`], an
//! immutable tenant-isolated view binding a Partner API Key (`Regime 4`) and a
//! validated non-zero `merchant_id` across scoped `.intentions()`,
//! `.inquiries()`, and `.manage()` operations.

use std::fmt;

use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

use crate::core::auth::partner::DEFAULT_MERCHANT_ID_HEADER;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
#[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
use crate::core::http::{HttpRequest, HttpResponse};
#[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
use crate::resources::onboarding::{
    apply_header_map, decode_onboarding_json, execute_onboarding_request,
};
use crate::resources::onboarding::{resolve_partner_api_key_headers, validate_non_zero_id};

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
        validate_non_zero_id(
            "merchant_id",
            merchant_id,
            "merchant_id must be a non-zero merchant ID",
        )?;
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
    /// Injects `x-api-key` along with both `x-paymob-merchant-id` and
    /// `x-merchant-id` ([`DEFAULT_MERCHANT_ID_HEADER`]).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::AuthenticationError`] if `partner_credentials` is
    /// missing or contains invalid header bytes.
    pub fn scope_headers(&self) -> Result<HeaderMap, PaymobError> {
        let mut headers = resolve_partner_api_key_headers(
            &self.inner,
            "partner_credentials must be configured for with_merchant scoping",
        )?;
        let mid_val = HeaderValue::from_str(&self.merchant_id.to_string())
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        let default_mid_header = HeaderName::from_bytes(DEFAULT_MERCHANT_ID_HEADER.as_bytes())
            .map_err(|err| PaymobError::AuthenticationError(err.to_string()))?;
        headers.insert(HeaderName::from_static(MERCHANT_ID_HEADER), mid_val.clone());
        headers.insert(default_mid_header, mid_val);
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

    #[cfg(feature = "inquiries")]
    async fn send_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, PaymobError> {
        let headers = self.scope_headers()?;
        let url = self.inner.accept_url(path)?;
        let request = apply_header_map(HttpRequest::get(url.as_str())?, &headers);
        let response = execute_onboarding_request(&self.inner, &request).await?;
        decode_onboarding_json(&response)
    }

    #[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
    async fn send_raw_post<B: serde::Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<HttpResponse, PaymobError> {
        let headers = self.scope_headers()?;
        let url = self.inner.accept_url(path)?;
        let req = HttpRequest::post(url.as_str())?.with_json(body)?;
        let request = apply_header_map(req, &headers);
        execute_onboarding_request(&self.inner, &request).await
    }

    #[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
    async fn send_post<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, PaymobError> {
        let response = self.send_raw_post(path, body).await?;
        decode_onboarding_json(&response)
    }

    #[cfg(feature = "intentions")]
    async fn send_put<B: serde::Serialize, T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, PaymobError> {
        let headers = self.scope_headers()?;
        let url = self.inner.accept_url(path)?;
        let req = HttpRequest::put(url.as_str())?.with_json(body)?;
        let request = apply_header_map(req, &headers);
        let response = execute_onboarding_request(&self.inner, &request).await?;
        decode_onboarding_json(&response)
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
        self.scoped.send_post("/v1/intention/", params).await
    }

    /// Updates a v1 Payment Intention on behalf of the scoped sub-merchant (`PUT /v1/intention/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::AuthenticationError`], [`PaymobError::ValidationError`],
    /// [`PaymobError::ApiError`], or [`PaymobError::TransportError`] on failure.
    pub async fn update(
        &self,
        params: &crate::resources::intentions::UpdateIntentionParams,
    ) -> Result<crate::resources::intentions::IntentionResponse, PaymobError> {
        self.scoped.send_put("/v1/intention/", params).await
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

    /// Queries a transaction by ID on behalf of the scoped sub-merchant as raw JSON
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
        validate_non_zero_id(
            "transaction_id",
            transaction_id,
            "transaction_id must be non-zero",
        )?;
        let path = format!("/api/acceptance/transactions/{transaction_id}");
        self.scoped.send_get(&path).await
    }

    /// Queries a strongly-typed [`Transaction`](crate::resources::inquiries::by_id::Transaction)
    /// by ID on behalf of the scoped sub-merchant (`GET /api/acceptance/transactions/{transaction_id}`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `transaction_id == 0`, or
    /// [`PaymobError::AuthenticationError`] / [`PaymobError::ApiError`] / [`PaymobError::TransportError`].
    pub async fn transaction(
        &self,
        transaction_id: u64,
    ) -> Result<crate::resources::inquiries::by_id::Transaction, PaymobError> {
        validate_non_zero_id(
            "transaction_id",
            transaction_id,
            "transaction_id must be non-zero",
        )?;
        let path = format!("/api/acceptance/transactions/{transaction_id}");
        self.scoped.send_get(&path).await
    }

    /// Queries a strongly-typed [`InquiredTransaction`](crate::resources::inquiries::by_order::InquiredTransaction)
    /// by order ID or merchant reference on behalf of the scoped sub-merchant
    /// (`POST /api/ecommerce/orders/transaction_inquiry`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `params` is invalid, or
    /// [`PaymobError::AuthenticationError`] / [`PaymobError::ApiError`] / [`PaymobError::TransportError`].
    pub async fn by_order(
        &self,
        params: &crate::resources::inquiries::by_order::TransactionInquiryParams,
    ) -> Result<crate::resources::inquiries::by_order::InquiredTransaction, PaymobError> {
        params.validate()?;
        self.scoped
            .send_post("/api/ecommerce/orders/transaction_inquiry", params)
            .await
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

    /// Voids a transaction on behalf of the scoped sub-merchant as raw JSON
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
        validate_non_zero_id(
            "transaction_id",
            transaction_id,
            "transaction_id must be non-zero",
        )?;
        let payload = serde_json::json!({ "transaction_id": transaction_id });
        self.scoped
            .send_post("/api/acceptance/void_refund/void", &payload)
            .await
    }

    /// Voids an unsettled transaction on behalf of the scoped sub-merchant
    /// (`POST /api/acceptance/void_refund/void`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `params.transaction_id == 0`, or
    /// [`PaymobError::AuthenticationError`] / [`PaymobError::ApiError`] / [`PaymobError::TransportError`].
    pub async fn void(
        &self,
        params: &crate::resources::manage::void_capture::VoidParams,
    ) -> Result<crate::resources::manage::models::Transaction, PaymobError> {
        params.validate()?;
        self.scoped
            .send_post("/api/acceptance/void_refund/void", params)
            .await
    }

    /// Captures an authorized transaction on behalf of the scoped sub-merchant
    /// (`POST /api/acceptance/capture`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `params` has zero ID or amount, or
    /// [`PaymobError::AuthenticationError`] / [`PaymobError::ApiError`] / [`PaymobError::TransportError`].
    pub async fn capture(
        &self,
        params: &crate::resources::manage::void_capture::CaptureParams,
    ) -> Result<crate::resources::manage::models::Transaction, PaymobError> {
        params.validate()?;
        self.scoped
            .send_post("/api/acceptance/capture", params)
            .await
    }

    /// Refunds a settled transaction on behalf of the scoped sub-merchant
    /// (`POST /api/acceptance/void_refund/refund`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `params` has zero ID or amount,
    /// [`PaymobError::RefundExceedsPermissibleAmount`] on over-refund HTTP 400, or
    /// [`PaymobError::AuthenticationError`] / [`PaymobError::ApiError`] / [`PaymobError::TransportError`].
    pub async fn refund(
        &self,
        params: &crate::resources::manage::refund::RefundParams,
    ) -> Result<crate::resources::manage::models::Transaction, PaymobError> {
        params.validate()?;
        let response = self
            .scoped
            .send_raw_post("/api/acceptance/void_refund/refund", params)
            .await?;
        if !response.status.is_success() {
            return Err(crate::resources::manage::refund::parse_refund_error(
                &response,
            ));
        }
        decode_onboarding_json(&response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::PartnerCredentials;
    use crate::core::region::PaymobRegion;

    #[cfg(any(feature = "intentions", feature = "inquiries", feature = "manage"))]
    fn scoped_mock_client(base_url: &str) -> MerchantScopedClient {
        let region = PaymobRegion::Custom {
            accept_base_url: base_url.to_owned(),
            checkout_base_url: format!("{base_url}/unifiedcheckout/"),
            payouts_base_url: base_url.to_owned(),
            payouts_staging_base_url: base_url.to_owned(),
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
        client.with_merchant(987_654).expect("valid scoped client")
    }

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

        let headers = m1.scope_headers().expect("valid scope headers");
        assert_eq!(headers.get("x-paymob-merchant-id").unwrap(), "111222");
        assert_eq!(headers.get("x-merchant-id").unwrap(), "111222");
    }

    #[cfg(feature = "intentions")]
    #[tokio::test]
    async fn tc_6_2_4_scoped_intentions_dispatches_partner_key_and_merchant_id() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::core::types::Currency;
        use crate::resources::intentions::{
            BillingData, CreateIntentionParams, PaymentMethodInput, UpdateIntentionParams,
        };

        let server = MockServer::start().await;
        for (verb, status_code, status_str) in [
            ("POST", 201_u16, "intended"),
            ("PUT", 200_u16, "updated"),
        ] {
            Mock::given(method(verb))
                .and(path("/v1/intention/"))
                .and(header("x-api-key", "partner_key_secret_624"))
                .and(header("x-paymob-merchant-id", "987654"))
                .and(header("x-merchant-id", "987654"))
                .respond_with(ResponseTemplate::new(status_code).set_body_json(
                    serde_json::json!({
                        "id": "pi_scoped_123",
                        "intention_order_id": 987654,
                        "client_secret": "egy_csk_test_scoped",
                        "status": status_str
                    }),
                ))
                .mount(&server)
                .await;
        }

        let scoped = scoped_mock_client(&server.uri());
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

        let resp = scoped.intentions().create(&params).await.unwrap();
        assert_eq!(resp.id, "pi_scoped_123");

        let update_params = UpdateIntentionParams::builder()
            .amount(15_000_u64)
            .build()
            .expect("valid update params");
        let updated = scoped.intentions().update(&update_params).await.unwrap();
        assert_eq!(updated.status.as_deref(), Some("updated"));
    }

    #[cfg(feature = "inquiries")]
    #[tokio::test]
    async fn tc_6_2_4_scoped_inquiries_dispatches_partner_key_and_merchant_id() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::resources::inquiries::by_order::TransactionInquiryParams;

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/transactions/42"))
            .and(header("x-api-key", "partner_key_secret_624"))
            .and(header("x-paymob-merchant-id", "987654"))
            .and(header("x-merchant-id", "987654"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "amount_cents": 10000,
                "success": true
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/ecommerce/orders/transaction_inquiry"))
            .and(header("x-api-key", "partner_key_secret_624"))
            .and(header("x-paymob-merchant-id", "987654"))
            .and(header("x-merchant-id", "987654"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "amount_cents": 10000,
                "success": true,
                "currency": "EGP"
            })))
            .mount(&server)
            .await;

        let scoped = scoped_mock_client(&server.uri());
        let tx = scoped.inquiries().transaction_by_id(42).await.unwrap();
        assert_eq!(tx["id"], 42);

        let typed_tx = scoped.inquiries().transaction(42).await.unwrap();
        assert_eq!(typed_tx.amount_cents, 10_000);

        let order_tx = scoped
            .inquiries()
            .by_order(&TransactionInquiryParams::by_order_id(212_245_716))
            .await
            .unwrap();
        assert_eq!(order_tx.currency, "EGP");
    }

    #[cfg(feature = "manage")]
    #[tokio::test]
    async fn tc_6_2_4_scoped_manage_dispatches_partner_key_and_merchant_id() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::resources::manage::refund::RefundParams;
        use crate::resources::manage::void_capture::{CaptureParams, VoidParams};

        let server = MockServer::start().await;
        for (endpoint, body) in [
            (
                "/api/acceptance/void_refund/void",
                serde_json::json!({
                    "id": 42, "amount_cents": 10000, "is_voided": true, "is_void": true
                }),
            ),
            (
                "/api/acceptance/capture",
                serde_json::json!({"id": 43, "amount_cents": 5000, "is_capture": true}),
            ),
            (
                "/api/acceptance/void_refund/refund",
                serde_json::json!({"id": 44, "amount_cents": 2500, "is_refund": true}),
            ),
        ] {
            Mock::given(method("POST"))
                .and(path(endpoint))
                .and(header("x-api-key", "partner_key_secret_624"))
                .and(header("x-paymob-merchant-id", "987654"))
                .and(header("x-merchant-id", "987654"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&server)
                .await;
        }

        let scoped = scoped_mock_client(&server.uri());
        let res = scoped.manage().void_transaction(42).await.unwrap();
        assert_eq!(res["is_voided"], true);

        let voided = scoped.manage().void(&VoidParams::new(42)).await.unwrap();
        assert!(voided.is_void);

        let captured = scoped
            .manage()
            .capture(&CaptureParams::new(42, 5_000))
            .await
            .unwrap();
        assert!(captured.is_capture);

        let refunded = scoped
            .manage()
            .refund(&RefundParams::new(42, 2_500))
            .await
            .unwrap();
        assert!(refunded.is_refund);
    }
}
