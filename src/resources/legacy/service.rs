#![forbid(unsafe_code)]
//! [`LegacyV2Service`] 3-step checkout facade (`US-2.3.0` Unit 3).
//!
//! Orchestrates the classic Paymob Accept v2 flow:
//! 1. Acquire / reuse 60-minute JWT via Regime 2 (`POST /api/auth/tokens`)
//! 2. Register order (`POST /api/ecommerce/orders`)
//! 3. Exchange order + billing data for a payment key (`POST /api/acceptance/payment_keys`)
//! 4. Build a percent-encoded iframe URL (`https://accept.paymob.com/api/acceptance/iframes/{iframe_id}?payment_token=...`)
//!
//! Includes transparent single-flight 401 JWT eviction + retry and exposes
//! [`PaymobClient::legacy_v2`] (and alias [`PaymobClient::legacy`]).

use std::fmt;
use std::future::Future;

use secrecy::{ExposeSecret, SecretString};
use url::Url;
use zeroize::Zeroizing;

use crate::core::auth::accept_jwt::{ACCEPT_AUTH_TOKENS_PATH, AcceptJwtError, AcceptJwtProvider};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::HttpClient;
use crate::core::types::Currency;
use crate::resources::legacy::orders::{
    CreateLegacyOrderParams, LEGACY_ORDERS_PATH, LegacyOrder, LegacyOrderItem, create_legacy_order,
};
use crate::resources::legacy::payment_keys::{
    CreatePaymentKeyParams, DEFAULT_PAYMENT_KEY_EXPIRATION_SECS, LEGACY_PAYMENT_KEYS_PATH,
    LegacyBillingData, PaymentKeyResponse, create_legacy_payment_key,
};

/// Composite request parameters for [`LegacyV2Service::create_checkout`].
///
/// # Examples
///
/// ```
/// use some_paymob::core::types::Currency;
/// use some_paymob::resources::legacy::payment_keys::LegacyBillingData;
/// use some_paymob::resources::legacy::service::LegacyCheckoutParams;
///
/// let billing = LegacyBillingData::new("Ada", "Lovelace", "ada@example.com", "+201000000000");
/// let params = LegacyCheckoutParams::new(50_000, Currency::EGP, 4_097_558, 812_345, billing)
///     .merchant_order_id("ord-2026-42")
///     .lock_order_when_paid(true);
/// assert!(params.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyCheckoutParams {
    /// Order amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: Currency,
    /// Paymob payment integration ID.
    pub integration_id: u64,
    /// Paymob checkout iframe ID.
    pub iframe_id: u64,
    /// Customer billing metadata (PII-redacted in `Debug`).
    pub billing_data: LegacyBillingData,
    /// Whether physical delivery is required.
    pub delivery_needed: bool,
    /// Optional merchant-assigned order reference.
    pub merchant_order_id: Option<String>,
    /// Optional line items for the order.
    pub items: Vec<LegacyOrderItem>,
    /// Payment key expiration in seconds (default `3600`).
    pub expiration: u32,
    /// Whether to lock the order once paid.
    pub lock_order_when_paid: bool,
}

impl LegacyCheckoutParams {
    /// Creates a new [`LegacyCheckoutParams`] with sensible defaults.
    #[must_use]
    pub fn new(
        amount_cents: u64,
        currency: Currency,
        integration_id: u64,
        iframe_id: u64,
        billing_data: LegacyBillingData,
    ) -> Self {
        Self {
            amount_cents,
            currency,
            integration_id,
            iframe_id,
            billing_data,
            delivery_needed: false,
            merchant_order_id: None,
            items: Vec::new(),
            expiration: DEFAULT_PAYMENT_KEY_EXPIRATION_SECS,
            lock_order_when_paid: false,
        }
    }

    /// Sets whether physical delivery is needed.
    #[must_use]
    pub const fn delivery_needed(mut self, delivery_needed: bool) -> Self {
        self.delivery_needed = delivery_needed;
        self
    }

    /// Sets the optional merchant order reference ID.
    #[must_use]
    pub fn merchant_order_id(mut self, merchant_order_id: impl Into<String>) -> Self {
        self.merchant_order_id = Some(merchant_order_id.into());
        self
    }

    /// Sets the order line items.
    #[must_use]
    pub fn items(mut self, items: Vec<LegacyOrderItem>) -> Self {
        self.items = items;
        self
    }

    /// Sets the payment key expiration in seconds.
    #[must_use]
    pub const fn expiration(mut self, expiration: u32) -> Self {
        self.expiration = expiration;
        self
    }

    /// Sets whether to lock the order once paid.
    #[must_use]
    pub const fn lock_order_when_paid(mut self, lock: bool) -> Self {
        self.lock_order_when_paid = lock;
        self
    }

    /// Validates all checkout parameters before executing any network calls.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `iframe_id == 0`,
    /// `integration_id == 0`, `amount_cents == 0`, or billing/order fields are invalid.
    pub fn validate(&self) -> Result<(), PaymobError> {
        self.validate_identifiers()?;
        self.to_order_params().validate()?;
        self.billing_data.validate()
    }

    fn validate_identifiers(&self) -> Result<(), PaymobError> {
        require_nonzero("iframe_id", self.iframe_id)?;
        require_nonzero("integration_id", self.integration_id)?;
        require_nonzero("expiration", u64::from(self.expiration))
    }

    fn to_order_params(&self) -> CreateLegacyOrderParams {
        let mut order = CreateLegacyOrderParams::new(self.amount_cents, self.currency.clone())
            .delivery_needed(self.delivery_needed)
            .items(self.items.clone());
        if let Some(ref merchant_order_id) = self.merchant_order_id {
            order = order.merchant_order_id(merchant_order_id.clone());
        }
        order
    }

    fn to_payment_key_params(&self, order_id: u64) -> CreatePaymentKeyParams {
        CreatePaymentKeyParams::new(
            order_id,
            self.amount_cents,
            self.currency.clone(),
            self.integration_id,
            self.billing_data.clone(),
        )
        .expiration(self.expiration)
        .lock_order_when_paid(self.lock_order_when_paid)
    }
}

/// Result of a complete 3-step Legacy Accept v2 checkout orchestration.
#[derive(Debug, Clone)]
pub struct LegacyCheckoutSession {
    /// Registered Paymob order.
    pub order: LegacyOrder,
    /// Generated short-lived payment key (`token` redacted in `Debug`).
    pub payment_key: PaymentKeyResponse,
    /// Ready-to-render iframe URL with percent-encoded `payment_token`.
    pub iframe_url: Url,
}

/// Facade for Paymob's Legacy Accept v2 3-step checkout flow.
///
/// Cheaply cloneable (`Arc`-backed via [`PaymobClient`] and [`AcceptJwtProvider`])
/// and safe to share across async tasks (`Send + Sync`).
#[derive(Clone)]
pub struct LegacyV2Service {
    client: PaymobClient,
    base_url: String,
    http: HttpClient,
    jwt_provider: AcceptJwtProvider,
}

impl fmt::Debug for LegacyV2Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyV2Service")
            .field("base_url", &self.base_url)
            .field("client", &self.client)
            .field("jwt_provider", &"[REDACTED]")
            .finish()
    }
}

impl LegacyV2Service {
    /// Constructs a [`LegacyV2Service`] bound to `client`'s regional Accept endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `api_key` is missing from
    /// [`ClientConfig`](crate::core::config::ClientConfig), or if endpoint resolution fails.
    pub fn new(client: PaymobClient) -> Result<Self, PaymobError> {
        let probe = client.accept_url(ACCEPT_AUTH_TOKENS_PATH)?;
        let base_url = probe
            .as_str()
            .trim_end_matches(ACCEPT_AUTH_TOKENS_PATH)
            .to_owned();
        Self::with_base_url(client, base_url)
    }

    /// Constructs a [`LegacyV2Service`] targeting an explicit `base_url`
    /// (useful for `wiremock` integration tests or custom proxies).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `api_key` is missing or `base_url` is invalid.
    pub fn with_base_url(
        client: PaymobClient,
        base_url: impl Into<String>,
    ) -> Result<Self, PaymobError> {
        let api_key = extract_trimmed_api_key(&client)?;
        let base_url = base_url.into().trim_end_matches('/').to_owned();
        let jwt_provider = AcceptJwtProvider::new(&base_url, api_key).map_err(map_jwt_err)?;
        let http = build_http_for_base_url(&client, &base_url)?;
        Ok(Self {
            client,
            base_url,
            http,
            jwt_provider,
        })
    }

    /// Acquires or reuses a cached 60-minute Accept JWT (`POST /api/auth/tokens`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::AuthenticationError`] if credentials are rejected, or
    /// [`PaymobError::TransportError`] on network failure.
    pub async fn generate_auth_token(&self) -> Result<SecretString, PaymobError> {
        self.jwt_provider.token().await.map_err(map_jwt_err)
    }

    /// Registers a legacy order (`POST /api/ecommerce/orders`) with automatic
    /// single-flight 401 JWT recovery.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if validation, authentication, or order creation fails.
    pub async fn create_order(
        &self,
        params: &CreateLegacyOrderParams,
    ) -> Result<LegacyOrder, PaymobError> {
        self.execute_with_jwt_retry(LEGACY_ORDERS_PATH, |url, token| async move {
            create_legacy_order(&self.http, url, &token, params).await
        })
        .await
    }

    /// Generates a short-lived payment key (`POST /api/acceptance/payment_keys`)
    /// with automatic single-flight 401 JWT recovery.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if validation, authentication, or key generation fails.
    pub async fn create_payment_key(
        &self,
        params: &CreatePaymentKeyParams,
    ) -> Result<PaymentKeyResponse, PaymobError> {
        self.execute_with_jwt_retry(LEGACY_PAYMENT_KEYS_PATH, |url, token| async move {
            create_legacy_payment_key(&self.http, url, &token, params).await
        })
        .await
    }

    /// Builds a percent-encoded Paymob Accept v2 iframe URL for `iframe_id` and `payment_token`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `iframe_id == 0`, `payment_token`
    /// is blank, contains ASCII control characters, is a server secret key (`sk_*`),
    /// or URL construction fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use secrecy::SecretString;
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::ApiKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("egy_api_key_example")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let legacy = client.legacy_v2()?;
    /// let url = legacy.iframe_url(812_345, &SecretString::from("tok+1/2="))?;
    /// assert_eq!(
    ///     url.as_str(),
    ///     "https://accept.paymob.com/api/acceptance/iframes/812345?payment_token=tok%2B1%2F2%3D"
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn iframe_url(
        &self,
        iframe_id: u64,
        payment_token: &SecretString,
    ) -> Result<Url, PaymobError> {
        require_nonzero("iframe_id", iframe_id)?;
        let resolved_token = if payment_token.expose_secret().trim().starts_with('$') {
            crate::core::credentials::resolve_secret_or_env(
                "payment_token",
                payment_token.expose_secret(),
            )?
        } else {
            payment_token.clone()
        };
        validate_payment_token(&resolved_token)?;
        let mut url = self.endpoint_url(&format!("/api/acceptance/iframes/{iframe_id}"))?;
        url.query_pairs_mut()
            .append_pair("payment_token", resolved_token.expose_secret());
        Ok(url)
    }

    /// Executes the complete 3-step Legacy Accept v2 checkout sequence:
    /// `auth_token` -> `create_order` -> `create_payment_key` -> `iframe_url`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if validation, authentication, order creation,
    /// payment key generation, or iframe URL construction fails.
    pub async fn create_checkout(
        &self,
        params: &LegacyCheckoutParams,
    ) -> Result<LegacyCheckoutSession, PaymobError> {
        params.validate()?;
        let order = self.create_order(&params.to_order_params()).await?;
        let pk_params = params.to_payment_key_params(order.id);
        let payment_key = self.create_payment_key(&pk_params).await?;
        let iframe_url = self.iframe_url(params.iframe_id, &payment_key.token)?;
        Ok(LegacyCheckoutSession {
            order,
            payment_key,
            iframe_url,
        })
    }

    async fn execute_with_jwt_retry<T, F, Fut>(
        &self,
        path: &str,
        mut op: F,
    ) -> Result<T, PaymobError>
    where
        F: FnMut(Url, SecretString) -> Fut,
        Fut: Future<Output = Result<T, PaymobError>>,
    {
        let url = self.endpoint_url(path)?;
        let token = self.generate_auth_token().await?;
        match op(url.clone(), token.clone()).await {
            Ok(output) => Ok(output),
            Err(err) => self.retry_on_auth_error(err, &token, url, op).await,
        }
    }

    async fn retry_on_auth_error<T, F, Fut>(
        &self,
        err: PaymobError,
        stale_token: &SecretString,
        url: Url,
        mut op: F,
    ) -> Result<T, PaymobError>
    where
        F: FnMut(Url, SecretString) -> Fut,
        Fut: Future<Output = Result<T, PaymobError>>,
    {
        if !err.is_auth_error() {
            return Err(err);
        }
        self.jwt_provider
            .cache()
            .evict_if_matches(stale_token)
            .await;
        let fresh = self.generate_auth_token().await?;
        op(url, fresh).await
    }

    fn endpoint_url(&self, path: &str) -> Result<Url, PaymobError> {
        let raw = format!("{}{}", self.base_url, path);
        Url::parse(&raw).map_err(|err| PaymobError::ValidationError {
            field: "url",
            reason: err.to_string(),
        })
    }
}

impl PaymobClient {
    /// Returns a [`LegacyV2Service`] facade for Paymob's Legacy Accept v2 3-step checkout flow.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `api_key` was not configured on
    /// [`ClientConfig`](crate::core::config::ClientConfig).
    pub fn legacy_v2(&self) -> Result<LegacyV2Service, PaymobError> {
        LegacyV2Service::new(self.clone())
    }

    /// Alias for [`Self::legacy_v2`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `api_key` was not configured on
    /// [`ClientConfig`](crate::core::config::ClientConfig).
    pub fn legacy(&self) -> Result<LegacyV2Service, PaymobError> {
        self.legacy_v2()
    }
}

fn require_nonzero(field: &'static str, value: u64) -> Result<(), PaymobError> {
    if value == 0 {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must be greater than zero"),
        });
    }
    Ok(())
}

fn extract_trimmed_api_key(client: &PaymobClient) -> Result<SecretString, PaymobError> {
    let api_key = client
        .config()
        .api_key()
        .ok_or_else(|| PaymobError::ValidationError {
            field: "api_key",
            reason: "api_key is required for Legacy Accept v2 checkout".to_owned(),
        })?;
    let trimmed = Zeroizing::new(api_key.expose_secret().trim().to_owned());
    Ok(SecretString::from(trimmed.as_str().to_owned()))
}

fn validate_payment_token(payment_token: &SecretString) -> Result<(), PaymobError> {
    let raw = payment_token.expose_secret();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "payment_token",
            reason: "payment_token must not be empty".to_owned(),
        });
    }
    if raw.bytes().any(|b| b.is_ascii_control()) {
        return Err(PaymobError::ValidationError {
            field: "payment_token",
            reason: "payment_token must not contain ASCII control characters".to_owned(),
        });
    }
    if is_secret_key_token(trimmed) {
        return Err(PaymobError::ValidationError {
            field: "payment_token",
            reason: "server secret key (sk_*) must not be passed as payment_token".to_owned(),
        });
    }
    Ok(())
}

fn is_secret_key_token(trimmed: &str) -> bool {
    let lower = Zeroizing::new(trimmed.to_ascii_lowercase());
    if lower.starts_with("sk_") {
        return true;
    }
    lower.contains("_sk_")
}

fn build_http_for_base_url(
    client: &PaymobClient,
    base_url: &str,
) -> Result<HttpClient, PaymobError> {
    if !base_url.starts_with("http://") {
        return Ok(client.http().clone());
    }
    let cfg = client
        .http()
        .config()
        .clone()
        .with_allow_insecure_http(true);
    HttpClient::new(cfg).map_err(|err| PaymobError::TransportError(err.to_string()))
}

fn map_jwt_err(err: AcceptJwtError) -> PaymobError {
    match err {
        AcceptJwtError::EmptyApiKey | AcceptJwtError::InvalidCredentials => {
            PaymobError::AuthenticationError(err.to_string())
        }
        AcceptJwtError::InvalidBaseUrl(_) | AcceptJwtError::InvalidJsonBody => {
            PaymobError::ValidationError {
                field: "auth_token",
                reason: err.to_string(),
            }
        }
        AcceptJwtError::UnexpectedStatus { status, detail } => PaymobError::ApiError {
            status,
            message: detail,
            code: None,
        },
        _ => PaymobError::TransportError(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::region::PaymobRegion;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn test_client() -> PaymobClient {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .api_key(ApiKey::new("test_api_key_value").expect("api key"))
            .build()
            .expect("config");
        PaymobClient::new(config).expect("client")
    }

    fn sample_billing() -> LegacyBillingData {
        LegacyBillingData::new("Maher", "Mansour", "maher@example.com", "+201001234567")
    }

    struct RefreshingOrderResponder {
        calls: Arc<AtomicUsize>,
    }

    impl Respond for RefreshingOrderResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let count = self.calls.fetch_add(1, Ordering::SeqCst);
            let body: serde_json::Value =
                serde_json::from_slice(&request.body).unwrap_or(serde_json::Value::Null);
            if count == 0 && body["auth_token"] == "stale-jwt" {
                return ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"detail": "incorrect credentials"}));
            }
            if body["auth_token"] == "fresh-jwt" {
                return ResponseTemplate::new(201).set_body_json(serde_json::json!({
                    "id": 777_001,
                    "amount_cents": 50_000,
                    "currency": "EGP",
                    "merchant_order_id": "ord-retry"
                }));
            }
            ResponseTemplate::new(400)
        }
    }

    #[test]
    fn tc_2_3_3_legacy_v2_requires_api_key_and_encodes_iframe_url() {
        let no_key_cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("config");
        let no_key_client = PaymobClient::new(no_key_cfg).expect("client");
        assert!(matches!(
            no_key_client.legacy_v2(),
            Err(PaymobError::ValidationError {
                field: "api_key",
                ..
            })
        ));

        let client = test_client();
        let service = client.legacy_v2().expect("legacy_v2");
        let url = service
            .iframe_url(812_345, &SecretString::from("abc+def/ghi="))
            .expect("iframe url");
        assert_eq!(
            url.as_str(),
            "https://accept.paymob.com/api/acceptance/iframes/812345?payment_token=abc%2Bdef%2Fghi%3D"
        );
    }

    #[test]
    fn tc_2_3_3_iframe_url_rejects_zero_id_and_blank_token() {
        let service = test_client().legacy_v2().expect("legacy_v2");
        assert!(matches!(
            service.iframe_url(0, &SecretString::from("tok")),
            Err(PaymobError::ValidationError {
                field: "iframe_id",
                ..
            })
        ));
        assert!(matches!(
            service.iframe_url(812_345, &SecretString::from("   ")),
            Err(PaymobError::ValidationError {
                field: "payment_token",
                ..
            })
        ));
    }

    #[test]
    fn tc_2_3_cycle2_iframe_url_rejects_control_chars_and_secret_keys() {
        let service = test_client().legacy_v2().expect("legacy_v2");
        for invalid in [
            "tok\r\ninjected",
            "tok\0null",
            "sk_test_123456",
            "sk_live_abcdef",
            "egy_sk_test_123456",
            "ksa_sk_live_999",
        ] {
            let res = service.iframe_url(812_345, &SecretString::from(invalid));
            assert!(matches!(
                res,
                Err(PaymobError::ValidationError {
                    field: "payment_token",
                    ..
                })
            ));
        }
    }

    #[test]
    fn tc_2_3_cycle2_deserialization_guards_reject_zero_order_id_and_control_token() {
        let bad_order = serde_json::json!({
            "id": 0,
            "amount_cents": 50_000,
            "currency": "EGP"
        });
        assert!(serde_json::from_value::<LegacyOrder>(bad_order).is_err());

        let bad_key = serde_json::json!({ "token": "pay_tok\r\ninjected" });
        assert!(serde_json::from_value::<PaymentKeyResponse>(bad_key).is_err());
    }

    #[tokio::test]
    async fn tc_2_3_3_create_checkout_3_step_orchestration_wiremock() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path(ACCEPT_AUTH_TOKENS_PATH))
            .and(body_partial_json(
                serde_json::json!({"api_key": "test_api_key_value"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "jwt-step-1"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(LEGACY_ORDERS_PATH))
            .and(body_partial_json(serde_json::json!({
                "auth_token": "jwt-step-1",
                "amount_cents": 50_000,
                "currency": "EGP"
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "id": 998_877,
                "amount_cents": 50_000,
                "currency": "EGP",
                "merchant_order_id": "ord-1"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(LEGACY_PAYMENT_KEYS_PATH))
            .and(body_partial_json(serde_json::json!({
                "auth_token": "jwt-step-1",
                "order_id": 998_877,
                "integration_id": 4_097_558
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "pay+key/tok="
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = LegacyV2Service::with_base_url(test_client(), server.uri()).expect("service");
        let params =
            LegacyCheckoutParams::new(50_000, Currency::EGP, 4_097_558, 812_345, sample_billing())
                .merchant_order_id("ord-1");

        let session = service.create_checkout(&params).await.expect("checkout");
        assert_eq!(session.order.id, 998_877);
        assert_eq!(session.payment_key.expose_token(), "pay+key/tok=");
        assert_eq!(
            session.iframe_url.as_str(),
            format!(
                "{}/api/acceptance/iframes/812345?payment_token=pay%2Bkey%2Ftok%3D",
                server.uri()
            )
        );
        assert!(format!("{session:?}").contains("[REDACTED]"));
        assert!(!format!("{session:?}").contains("pay+key/tok="));
    }

    #[tokio::test]
    async fn tc_2_3_3_transparent_401_jwt_recovery_mid_flow() {
        let server = MockServer::start().await;
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let auth_counter = Arc::clone(&auth_calls);

        Mock::given(method("POST"))
            .and(path(ACCEPT_AUTH_TOKENS_PATH))
            .respond_with(move |_req: &Request| {
                let idx = auth_counter.fetch_add(1, Ordering::SeqCst);
                let tok = if idx == 0 { "stale-jwt" } else { "fresh-jwt" };
                ResponseTemplate::new(201).set_body_json(serde_json::json!({ "token": tok }))
            })
            .expect(2)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path(LEGACY_ORDERS_PATH))
            .respond_with(RefreshingOrderResponder {
                calls: Arc::new(AtomicUsize::new(0)),
            })
            .expect(2)
            .mount(&server)
            .await;

        let service = LegacyV2Service::with_base_url(test_client(), server.uri()).expect("service");
        let order_params =
            CreateLegacyOrderParams::new(50_000, Currency::EGP).merchant_order_id("ord-retry");
        let order = service
            .create_order(&order_params)
            .await
            .expect("recovered after 401 refresh");

        assert_eq!(order.id, 777_001);
        assert_eq!(auth_calls.load(Ordering::SeqCst), 2);
    }
}
