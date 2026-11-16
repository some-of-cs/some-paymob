#![forbid(unsafe_code)]
//! Unit 4.1.3 — [`SavedCardsService`] executing `POST /api/acceptance/payments/pay`.
//!
//! Implements Regime 2 (`Authorization: Bearer <auth_token>`) headless payment
//! execution across saved-card MIT/MOTO tokens, Mobile Wallets, Kiosk
//! aggregators, and raw `source` payloads, returning [`HeadlessPayResponse`].

use std::fmt;

use reqwest::StatusCode;
use reqwest::header::AUTHORIZATION;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::ZeroizeOnDrop;

use crate::core::auth::accept_jwt::{
    ACCEPT_AUTH_TOKENS_PATH, format_bearer_header, is_incorrect_credentials_401,
};
use crate::core::auth::cache::CachedToken;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest, HttpResponse};

/// Relative endpoint path for Paymob Accept headless payment execution.
pub const ACCEPT_PAY_PATH: &str = "/api/acceptance/payments/pay";

const REDACTED: &str = "[REDACTED]";

/// Parameters for an off-session MIT/MOTO saved-card payment (`subtype: "TOKEN"`).
///
/// All secret fields (`payment_token`, `saved_token`, and optional `cvn`) are
/// wrapped in [`SecretString`] with [`ZeroizeOnDrop`] and redacted in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::resources::saved_cards::service::MitPayParams;
///
/// let params = MitPayParams::new("pay_tok_123", "card_tok_abc")
///     .expect("valid params")
///     .with_cvn("123")
///     .expect("valid cvn");
/// assert!(format!("{params:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct MitPayParams {
    payment_token: SecretString,
    saved_token: SecretString,
    cvn: Option<SecretString>,
}

impl MitPayParams {
    /// Creates validated [`MitPayParams`] for a saved-card MIT/MOTO charge.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `payment_token` or `saved_token`
    /// is empty or whitespace-only.
    pub fn new(
        payment_token: impl Into<SecretString>,
        saved_token: impl Into<SecretString>,
    ) -> Result<Self, PaymobError> {
        let payment_token = validate_non_empty_secret("payment_token", payment_token.into())?;
        let saved_token = validate_non_empty_secret("saved_token", saved_token.into())?;
        Ok(Self {
            payment_token,
            saved_token,
            cvn: None,
        })
    }

    /// Attaches an optional MOTO security code (`cvn`) to the token payment.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `cvn` is empty or whitespace-only.
    pub fn with_cvn(mut self, cvn: impl Into<SecretString>) -> Result<Self, PaymobError> {
        self.cvn = Some(validate_non_empty_secret("cvn", cvn.into())?);
        Ok(self)
    }

    /// Returns a reference to the redacted payment token.
    #[must_use]
    pub fn payment_token(&self) -> &SecretString {
        &self.payment_token
    }

    /// Returns a reference to the redacted saved-card token.
    #[must_use]
    pub fn saved_token(&self) -> &SecretString {
        &self.saved_token
    }

    /// Returns a reference to the optional redacted CVN.
    #[must_use]
    pub fn cvn(&self) -> Option<&SecretString> {
        self.cvn.as_ref()
    }
}

impl fmt::Debug for MitPayParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MitPayParams")
            .field("payment_token", &REDACTED)
            .field("saved_token", &REDACTED)
            .field("cvn", &self.cvn.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Parameters for a direct Mobile Wallet payment (`subtype: "WALLET"`).
///
/// Both `payment_token` and `wallet_phone` (PII) are redacted in [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::resources::saved_cards::service::WalletPayParams;
///
/// let params = WalletPayParams::new("pay_tok_123", "01012345678").expect("valid params");
/// let debug_out = format!("{params:?}");
/// assert!(debug_out.contains("[REDACTED]"));
/// assert!(!debug_out.contains("01012345678"));
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct WalletPayParams {
    payment_token: SecretString,
    wallet_phone: String,
}

impl WalletPayParams {
    /// Creates validated [`WalletPayParams`] for a Mobile Wallet charge.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `payment_token` or `wallet_phone`
    /// is empty or whitespace-only.
    pub fn new(
        payment_token: impl Into<SecretString>,
        wallet_phone: impl Into<String>,
    ) -> Result<Self, PaymobError> {
        let payment_token = validate_non_empty_secret("payment_token", payment_token.into())?;
        let wallet_phone = validate_non_empty_string("wallet_phone", wallet_phone.into())?;
        Ok(Self {
            payment_token,
            wallet_phone,
        })
    }

    /// Returns a reference to the redacted payment token.
    #[must_use]
    pub fn payment_token(&self) -> &SecretString {
        &self.payment_token
    }

    /// Returns the customer wallet phone number (`msisdn`).
    #[must_use]
    pub fn wallet_phone(&self) -> &str {
        &self.wallet_phone
    }
}

impl fmt::Debug for WalletPayParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletPayParams")
            .field("payment_token", &REDACTED)
            .field("wallet_phone", &REDACTED)
            .finish()
    }
}

/// Parameters for a Kiosk aggregator bill-reference payment (`subtype: "AGGREGATOR"`).
///
/// # Examples
///
/// ```
/// use some_paymob::resources::saved_cards::service::KioskPayParams;
///
/// let params = KioskPayParams::new("pay_tok_123").expect("valid params");
/// assert!(format!("{params:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct KioskPayParams {
    payment_token: SecretString,
}

impl KioskPayParams {
    /// Creates validated [`KioskPayParams`] for a Kiosk aggregator payment.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `payment_token` is empty or whitespace-only.
    pub fn new(payment_token: impl Into<SecretString>) -> Result<Self, PaymobError> {
        let payment_token = validate_non_empty_secret("payment_token", payment_token.into())?;
        Ok(Self { payment_token })
    }

    /// Returns a reference to the redacted payment token.
    #[must_use]
    pub fn payment_token(&self) -> &SecretString {
        &self.payment_token
    }
}

impl fmt::Debug for KioskPayParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KioskPayParams")
            .field("payment_token", &REDACTED)
            .finish()
    }
}

/// Parameters for a raw polymorphic `POST /api/acceptance/payments/pay` request.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use some_paymob::resources::saved_cards::service::RawPayParams;
///
/// let params = RawPayParams::new(
///     "pay_tok_123",
///     json!({ "identifier": "01012345678", "subtype": "WALLET" }),
/// )
/// .expect("valid raw params");
/// assert!(format!("{params:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone)]
pub struct RawPayParams {
    payment_token: SecretString,
    source: Value,
}

impl RawPayParams {
    /// Creates validated [`RawPayParams`] from a `payment_token` and JSON `source` object.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `payment_token` is empty or `source`
    /// is not a JSON object containing non-empty `"identifier"` and `"subtype"` strings.
    pub fn new(payment_token: impl Into<SecretString>, source: Value) -> Result<Self, PaymobError> {
        let payment_token = validate_non_empty_secret("payment_token", payment_token.into())?;
        validate_raw_source(&source)?;
        Ok(Self {
            payment_token,
            source,
        })
    }

    /// Returns a reference to the redacted payment token.
    #[must_use]
    pub fn payment_token(&self) -> &SecretString {
        &self.payment_token
    }

    /// Returns a reference to the raw `source` JSON payload.
    #[must_use]
    pub fn source(&self) -> &Value {
        &self.source
    }
}

impl fmt::Debug for RawPayParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawPayParams")
            .field("payment_token", &REDACTED)
            .field("source", &REDACTED)
            .finish()
    }
}

/// Normalized transaction payload returned by `POST /api/acceptance/payments/pay`.
///
/// Monetary amounts use integer minor units (`u64`) with zero floating-point types.
/// Raw gateway `data` and `source_data` blobs are redacted in [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct HeadlessTransaction {
    /// Paymob transaction identifier.
    #[serde(default)]
    pub id: u64,
    /// Whether the transaction is still pending asynchronous completion.
    #[serde(default)]
    pub pending: bool,
    /// Transaction amount in integer minor units (e.g., piasters/halalas).
    #[serde(default)]
    pub amount_cents: u64,
    /// Whether the transaction succeeded.
    #[serde(default)]
    pub success: bool,
    /// Whether this was an authorization-only transaction.
    #[serde(default)]
    pub is_auth: bool,
    /// Whether this transaction is a capture.
    #[serde(default)]
    pub is_capture: bool,
    /// Whether this transaction was voided.
    #[serde(default)]
    pub is_voided: bool,
    /// Whether this transaction was refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// Whether 3D Secure was triggered.
    #[serde(default)]
    pub is_3d_secure: bool,
    /// Paymob integration identifier used for the transaction, if present.
    #[serde(default)]
    pub integration_id: Option<u64>,
    /// Three-letter ISO currency code.
    #[serde(default)]
    pub currency: String,
    /// ISO-8601 creation timestamp, if returned by the gateway.
    #[serde(default)]
    pub created_at: Option<String>,
    /// Gateway-specific nested `data` object (e.g., `bill_reference`, `redirect_url`).
    #[serde(default)]
    pub data: Option<Value>,
    /// Gateway-specific nested `source_data` object.
    #[serde(default)]
    pub source_data: Option<Value>,
}

impl fmt::Debug for HeadlessTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeadlessTransaction")
            .field("id", &self.id)
            .field("pending", &self.pending)
            .field("amount_cents", &self.amount_cents)
            .field("success", &self.success)
            .field("is_3d_secure", &self.is_3d_secure)
            .field("integration_id", &self.integration_id)
            .field("currency", &self.currency)
            .field("data", &self.data.as_ref().map(|_| REDACTED))
            .field("source_data", &self.source_data.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Response returned by [`SavedCardsService`] headless payment methods.
///
/// Extracts the core [`HeadlessTransaction`], optional Mobile Wallet / 3DS
/// `redirect_url`, and optional Kiosk `kiosk_bill_reference`.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use some_paymob::resources::saved_cards::service::HeadlessPayResponse;
///
/// let raw = json!({
///     "id": 98765,
///     "pending": true,
///     "amount_cents": 15000,
///     "success": false,
///     "currency": "EGP",
///     "data": { "bill_reference": 44556677 }
/// });
/// let parsed = HeadlessPayResponse::from_raw_value(raw).expect("valid response");
/// assert_eq!(parsed.transaction.id, 98765);
/// assert_eq!(parsed.kiosk_bill_reference.as_deref(), Some("44556677"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessPayResponse {
    /// Parsed transaction details from the gateway response.
    pub transaction: HeadlessTransaction,
    /// Optional redirect URL for Mobile Wallet or 3DS challenges.
    pub redirect_url: Option<String>,
    /// Optional offline Kiosk bill reference number (e.g., Fawry/Aman).
    pub kiosk_bill_reference: Option<String>,
}

impl HeadlessPayResponse {
    /// Parses a [`HeadlessPayResponse`] from a raw JSON [`Value`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `raw` is not a JSON object or
    /// cannot be deserialized into [`HeadlessTransaction`].
    pub fn from_raw_value(raw: Value) -> Result<Self, PaymobError> {
        if !raw.is_object() {
            return Err(PaymobError::ValidationError {
                field: "response",
                reason: "expected JSON object from /api/acceptance/payments/pay".to_owned(),
            });
        }
        let redirect_url = extract_redirect_url(&raw);
        let kiosk_bill_reference = extract_kiosk_bill_reference(&raw);
        let transaction: HeadlessTransaction =
            serde_json::from_value(raw).map_err(|err| PaymobError::ValidationError {
                field: "response",
                reason: format!("invalid headless pay transaction payload: {err}"),
            })?;
        Ok(Self {
            transaction,
            redirect_url,
            kiosk_bill_reference,
        })
    }
}

/// Service handle for saved-card tokenization and headless payments (`US-4.1.0`).
///
/// Executes `POST /api/acceptance/payments/pay` under Regime 2
/// (`Authorization: Bearer <auth_token>`) with single-flight JWT caching and
/// one-shot retry on HTTP `401 {"detail": "incorrect credentials"}`.
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::region::PaymobRegion;
/// use some_paymob::resources::saved_cards::service::KioskPayParams;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .try_api_key("your-accept-api-key")?
///     .build()?;
/// let client = PaymobClient::new(config)?;
/// let params = KioskPayParams::new("payment_token_from_step_3")?;
/// let response = client.saved_cards().pay_with_kiosk(&params).await?;
/// let _bill_ref = response.kiosk_bill_reference;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct SavedCardsService {
    client: PaymobClient,
    http: HttpClient,
}

impl SavedCardsService {
    /// Creates a new [`SavedCardsService`] bound to `client`.
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        let http = client.http().clone();
        Self { client, http }
    }

    #[cfg(test)]
    pub(crate) fn with_http_client(client: PaymobClient, http: HttpClient) -> Self {
        Self { client, http }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub fn client(&self) -> &PaymobClient {
        &self.client
    }

    /// Executes an off-session MIT/MOTO saved-card charge (`subtype: "TOKEN"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if Regime 2 JWT acquisition fails, the HTTP
    /// transport fails, or the gateway returns a non-2xx error response.
    pub async fn pay_with_token_mit(
        &self,
        params: &MitPayParams,
    ) -> Result<HeadlessPayResponse, PaymobError> {
        let payload = build_mit_payload(params);
        self.execute_pay(&payload).await
    }

    /// Initiates a direct Mobile Wallet charge (`subtype: "WALLET"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if Regime 2 JWT acquisition fails, the HTTP
    /// transport fails, or the gateway returns a non-2xx error response.
    pub async fn pay_with_wallet(
        &self,
        params: &WalletPayParams,
    ) -> Result<HeadlessPayResponse, PaymobError> {
        let payload = build_wallet_payload(params);
        self.execute_pay(&payload).await
    }

    /// Generates an offline Kiosk aggregator bill reference (`subtype: "AGGREGATOR"`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if Regime 2 JWT acquisition fails, the HTTP
    /// transport fails, or the gateway returns a non-2xx error response.
    pub async fn pay_with_kiosk(
        &self,
        params: &KioskPayParams,
    ) -> Result<HeadlessPayResponse, PaymobError> {
        let payload = build_kiosk_payload(params);
        self.execute_pay(&payload).await
    }

    /// Executes a raw polymorphic `POST /api/acceptance/payments/pay` request.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if Regime 2 JWT acquisition fails, the HTTP
    /// transport fails, or the gateway returns a non-2xx error response.
    pub async fn pay_raw(&self, params: &RawPayParams) -> Result<HeadlessPayResponse, PaymobError> {
        let payload = build_raw_payload(params);
        self.execute_pay(&payload).await
    }

    async fn execute_pay(&self, payload: &Value) -> Result<HeadlessPayResponse, PaymobError> {
        let pay_url = self.client.accept_url(ACCEPT_PAY_PATH)?;
        let token = self.acquire_accept_jwt().await?;
        let response = self
            .send_pay_request(pay_url.as_str(), &token, payload)
            .await?;
        if is_incorrect_credentials_401(response.status, &response.body) {
            self.client
                .auth()
                .accept_cache()
                .evict_if_matches(&token)
                .await;
            let fresh_token = self.acquire_accept_jwt().await?;
            let retry_resp = self
                .send_pay_request(pay_url.as_str(), &fresh_token, payload)
                .await?;
            return parse_pay_response(&retry_resp);
        }
        parse_pay_response(&response)
    }

    async fn send_pay_request(
        &self,
        url: &str,
        token: &SecretString,
        payload: &Value,
    ) -> Result<HttpResponse, PaymobError> {
        let header = format_bearer_header(token)?;
        let req = HttpRequest::post(url)?
            .with_header(AUTHORIZATION, header)
            .with_json(payload)?;
        Ok(self.http.execute(&req).await?)
    }

    async fn acquire_accept_jwt(&self) -> Result<SecretString, PaymobError> {
        let api_key = self.client.config().api_key().ok_or_else(|| {
            PaymobError::AuthenticationError(
                "missing Paymob Accept API key for Regime 2 Bearer authentication".to_owned(),
            )
        })?;
        let auth_url = self.client.accept_url(ACCEPT_AUTH_TOKENS_PATH)?;
        let cache = self.client.auth().accept_cache();
        let cached = cache
            .get_or_refresh(|| async {
                let jwt = self
                    .fetch_fresh_jwt(auth_url.as_str(), api_key.expose_secret())
                    .await?;
                Ok::<CachedToken, PaymobError>(CachedToken::with_default_ttl(jwt, None))
            })
            .await?;
        Ok(cached.access_token.clone())
    }

    async fn fetch_fresh_jwt(
        &self,
        auth_url: &str,
        api_key: &str,
    ) -> Result<SecretString, PaymobError> {
        let body = json!({ "api_key": api_key });
        let req = HttpRequest::post(auth_url)?.with_json(&body)?;
        let resp = self.http.execute(&req).await?;
        parse_auth_token_response(&resp)
    }
}

#[derive(Deserialize)]
struct AuthTokenBody {
    token: SecretString,
}

fn parse_auth_token_response(resp: &HttpResponse) -> Result<SecretString, PaymobError> {
    if resp.status == StatusCode::UNAUTHORIZED {
        return Err(PaymobError::AuthenticationError(
            "Paymob Accept rejected API key (HTTP 401)".to_owned(),
        ));
    }
    if !resp.status.is_success() {
        return Err(PaymobError::from_http_response(resp));
    }
    let parsed: AuthTokenBody = resp.json()?;
    if parsed.token.expose_secret().trim().is_empty() {
        return Err(PaymobError::AuthenticationError(
            "Paymob Accept auth response missing non-empty `token` field".to_owned(),
        ));
    }
    Ok(parsed.token)
}

fn parse_pay_response(resp: &HttpResponse) -> Result<HeadlessPayResponse, PaymobError> {
    if !resp.status.is_success() {
        return Err(PaymobError::from_http_response(resp));
    }
    let raw: Value = resp.json()?;
    HeadlessPayResponse::from_raw_value(raw)
}

fn build_mit_payload(params: &MitPayParams) -> Value {
    let mut source = Map::new();
    source.insert(
        "identifier".to_owned(),
        Value::String(params.saved_token.expose_secret().to_owned()),
    );
    source.insert("subtype".to_owned(), Value::String("TOKEN".to_owned()));
    if let Some(cvn) = &params.cvn {
        source.insert(
            "cvn".to_owned(),
            Value::String(cvn.expose_secret().to_owned()),
        );
    }
    json!({
        "source": Value::Object(source),
        "payment_token": params.payment_token.expose_secret(),
    })
}

fn build_wallet_payload(params: &WalletPayParams) -> Value {
    json!({
        "source": {
            "identifier": params.wallet_phone,
            "subtype": "WALLET",
        },
        "payment_token": params.payment_token.expose_secret(),
    })
}

fn build_kiosk_payload(params: &KioskPayParams) -> Value {
    json!({
        "source": {
            "identifier": "AGGREGATOR",
            "subtype": "AGGREGATOR",
        },
        "payment_token": params.payment_token.expose_secret(),
    })
}

fn build_raw_payload(params: &RawPayParams) -> Value {
    json!({
        "source": params.source,
        "payment_token": params.payment_token.expose_secret(),
    })
}

fn validate_non_empty_secret(
    field: &'static str,
    secret: SecretString,
) -> Result<SecretString, PaymobError> {
    if secret.expose_secret().trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    Ok(secret)
}

fn validate_non_empty_string(field: &'static str, value: String) -> Result<String, PaymobError> {
    if value.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    Ok(value)
}

fn validate_raw_source(source: &Value) -> Result<(), PaymobError> {
    let Some(obj) = source.as_object() else {
        return Err(PaymobError::ValidationError {
            field: "source",
            reason: "source must be a JSON object".to_owned(),
        });
    };
    let has_identifier = non_empty_str_field(obj.get("identifier")).is_some();
    let has_subtype = non_empty_str_field(obj.get("subtype")).is_some();
    if !has_identifier || !has_subtype {
        return Err(PaymobError::ValidationError {
            field: "source",
            reason: "source must contain non-empty string `identifier` and `subtype` fields"
                .to_owned(),
        });
    }
    Ok(())
}

fn non_empty_str_field(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn value_to_non_empty_string(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            (!trimmed.is_empty()).then(|| trimmed.to_owned())
        }
        Some(Value::Number(num)) => Some(num.to_string()),
        _ => None,
    }
}

fn extract_redirect_url(raw: &Value) -> Option<String> {
    non_empty_str_field(raw.get("redirect_url"))
        .or_else(|| non_empty_str_field(raw.get("data").and_then(|d| d.get("redirect_url"))))
}

fn extract_kiosk_bill_reference(raw: &Value) -> Option<String> {
    value_to_non_empty_string(raw.get("kiosk_bill_reference"))
        .or_else(|| value_to_non_empty_string(raw.get("bill_reference")))
        .or_else(|| {
            value_to_non_empty_string(raw.get("data").and_then(|d| d.get("bill_reference")))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::http::HttpClientConfig;
    use crate::core::region::PaymobRegion;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_service(server: &MockServer, with_api_key: bool) -> SavedCardsService {
        let mut builder = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: server.uri(),
                checkout_base_url: server.uri(),
                payouts_base_url: server.uri(),
                payouts_staging_base_url: server.uri(),
            })
            .max_retries(0);
        if with_api_key {
            builder = builder
                .try_api_key("test-accept-api-key")
                .expect("valid api key");
        }
        let config = builder.build().expect("valid config");
        let client = PaymobClient::new(config).expect("valid client");
        let http = HttpClient::new(HttpClientConfig::default().with_allow_insecure_http(true))
            .expect("valid test http client");
        SavedCardsService::with_http_client(client, http)
    }

    async fn mount_auth_mock(server: &MockServer, jwt: &str, times: u64) {
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .and(body_json(json!({ "api_key": "test-accept-api-key" })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": jwt })))
            .expect(times)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn tc_4_1_3_pay_with_token_mit_sends_bearer_and_returns_transaction() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, "jwt-mit-1", 1).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .and(header("authorization", "Bearer jwt-mit-1"))
            .and(body_json(json!({
                "source": {
                    "identifier": "saved_tok_999",
                    "subtype": "TOKEN",
                    "cvn": "456"
                },
                "payment_token": "pay_tok_111"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 1001,
                "pending": false,
                "amount_cents": 25000,
                "success": true,
                "currency": "EGP"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = test_service(&server, true);
        let params = MitPayParams::new("pay_tok_111", "saved_tok_999")
            .expect("valid params")
            .with_cvn("456")
            .expect("valid cvn");
        let resp = service
            .pay_with_token_mit(&params)
            .await
            .expect("MIT pay succeeds");

        assert_eq!(resp.transaction.id, 1001);
        assert_eq!(resp.transaction.amount_cents, 25000);
        assert!(resp.transaction.success);
        assert!(!resp.transaction.pending);
        assert!(resp.redirect_url.is_none());
        assert!(resp.kiosk_bill_reference.is_none());
    }

    #[tokio::test]
    async fn tc_4_1_3_pay_with_wallet_extracts_transaction_and_redirect_url() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, "jwt-wallet-1", 1).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .and(header("authorization", "Bearer jwt-wallet-1"))
            .and(body_json(json!({
                "source": {
                    "identifier": "01012345678",
                    "subtype": "WALLET"
                },
                "payment_token": "pay_tok_wallet"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 2002,
                "pending": true,
                "amount_cents": 15000,
                "success": false,
                "currency": "EGP",
                "redirect_url": "https://accept.paymob.com/wallet/redirect/abc"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = test_service(&server, true);
        let params = WalletPayParams::new("pay_tok_wallet", "01012345678").expect("valid params");
        let resp = service
            .pay_with_wallet(&params)
            .await
            .expect("wallet pay succeeds");

        assert_eq!(resp.transaction.id, 2002);
        assert!(resp.transaction.pending);
        assert_eq!(
            resp.redirect_url.as_deref(),
            Some("https://accept.paymob.com/wallet/redirect/abc")
        );
        assert!(resp.kiosk_bill_reference.is_none());
    }

    #[tokio::test]
    async fn tc_4_1_3_pay_with_kiosk_extracts_bill_reference_from_data() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, "jwt-kiosk-1", 1).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .and(header("authorization", "Bearer jwt-kiosk-1"))
            .and(body_json(json!({
                "source": {
                    "identifier": "AGGREGATOR",
                    "subtype": "AGGREGATOR"
                },
                "payment_token": "pay_tok_kiosk"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 3003,
                "pending": true,
                "amount_cents": 50000,
                "success": false,
                "currency": "EGP",
                "data": {
                    "bill_reference": 77889900
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = test_service(&server, true);
        let params = KioskPayParams::new("pay_tok_kiosk").expect("valid params");
        let resp = service
            .pay_with_kiosk(&params)
            .await
            .expect("kiosk pay succeeds");

        assert_eq!(resp.transaction.id, 3003);
        assert_eq!(resp.kiosk_bill_reference.as_deref(), Some("77889900"));
        assert!(resp.redirect_url.is_none());
    }

    #[tokio::test]
    async fn tc_4_1_3_pay_raw_dispatches_custom_source_object() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, "jwt-raw-1", 1).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .and(header("authorization", "Bearer jwt-raw-1"))
            .and(body_json(json!({
                "source": {
                    "identifier": "tok_raw_1",
                    "subtype": "TOKEN"
                },
                "payment_token": "pay_tok_raw"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 4004,
                "pending": false,
                "amount_cents": 1000,
                "success": true,
                "currency": "SAR"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = test_service(&server, true);
        let params = RawPayParams::new(
            "pay_tok_raw",
            json!({ "identifier": "tok_raw_1", "subtype": "TOKEN" }),
        )
        .expect("valid raw params");
        let resp = service.pay_raw(&params).await.expect("raw pay succeeds");

        assert_eq!(resp.transaction.id, 4004);
        assert_eq!(resp.transaction.currency, "SAR");
    }

    #[tokio::test]
    async fn tc_4_1_3_reuses_cached_jwt_across_multiple_pay_calls() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, "jwt-cached", 1).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .and(header("authorization", "Bearer jwt-cached"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 5005,
                "pending": false,
                "amount_cents": 500,
                "success": true,
                "currency": "EGP"
            })))
            .expect(2)
            .mount(&server)
            .await;

        let service = test_service(&server, true);
        let params = KioskPayParams::new("pay_tok_cache").expect("valid params");
        service.pay_with_kiosk(&params).await.expect("first call");
        service.pay_with_kiosk(&params).await.expect("second call");
    }

    #[tokio::test]
    async fn tc_4_1_3_evicts_and_retries_once_on_401_incorrect_credentials() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": "jwt-stale" })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/auth/tokens"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": "jwt-fresh" })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .and(header("authorization", "Bearer jwt-stale"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(json!({ "detail": "incorrect credentials" })),
            )
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .and(header("authorization", "Bearer jwt-fresh"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 6006,
                "pending": false,
                "amount_cents": 2000,
                "success": true,
                "currency": "EGP"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let service = test_service(&server, true);
        let params = KioskPayParams::new("pay_tok_retry").expect("valid params");
        let resp = service
            .pay_with_kiosk(&params)
            .await
            .expect("retry succeeds after 401 eviction");
        assert_eq!(resp.transaction.id, 6006);
    }

    #[tokio::test]
    async fn tc_4_1_3_returns_auth_error_when_api_key_missing() {
        let server = MockServer::start().await;
        let service = test_service(&server, false);
        let params = KioskPayParams::new("pay_tok_no_key").expect("valid params");
        let err = service
            .pay_with_kiosk(&params)
            .await
            .expect_err("missing api_key must fail");
        assert!(err.is_auth_error());
    }

    #[tokio::test]
    async fn tc_4_1_3_maps_gateway_400_validation_error() {
        let server = MockServer::start().await;
        mount_auth_mock(&server, "jwt-400", 1).await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/payments/pay"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(json!({ "source": ["Invalid token identifier."] })),
            )
            .expect(1)
            .mount(&server)
            .await;

        let service = test_service(&server, true);
        let params = KioskPayParams::new("pay_tok_400").expect("valid params");
        let err = service
            .pay_with_kiosk(&params)
            .await
            .expect_err("400 should map to validation error");
        assert!(err.is_validation_error());
    }

    #[test]
    fn tc_4_1_3_rejects_empty_and_malformed_inputs() {
        assert!(MitPayParams::new("   ", "tok_1").is_err());
        assert!(MitPayParams::new("pay_1", "").is_err());
        assert!(
            MitPayParams::new("pay_1", "tok_1")
                .expect("valid")
                .with_cvn("  ")
                .is_err()
        );
        assert!(WalletPayParams::new("", "01012345678").is_err());
        assert!(WalletPayParams::new("pay_1", "   ").is_err());
        assert!(KioskPayParams::new("").is_err());
        assert!(RawPayParams::new("pay_1", json!("not-an-object")).is_err());
        assert!(RawPayParams::new("pay_1", json!({ "identifier": "x" })).is_err());
        assert!(HeadlessPayResponse::from_raw_value(json!([1, 2, 3])).is_err());
    }

    #[test]
    fn tc_4_1_3_debug_redacts_all_secrets_and_pii() {
        let mit = MitPayParams::new("secret_pay_tok", "secret_card_tok")
            .expect("valid")
            .with_cvn("999")
            .expect("valid");
        let wallet = WalletPayParams::new("secret_pay_tok", "01099887766").expect("valid");
        let kiosk = KioskPayParams::new("secret_pay_tok").expect("valid");
        let raw = RawPayParams::new(
            "secret_pay_tok",
            json!({ "identifier": "secret_card_tok", "subtype": "TOKEN" }),
        )
        .expect("valid");
        let resp = HeadlessPayResponse::from_raw_value(json!({
            "id": 77,
            "pending": false,
            "amount_cents": 100,
            "success": true,
            "currency": "EGP",
            "data": { "bill_reference": "12345" },
            "source_data": { "pan": "4111" }
        }))
        .expect("valid");

        for dbg in [
            format!("{mit:?}"),
            format!("{wallet:?}"),
            format!("{kiosk:?}"),
            format!("{raw:?}"),
            format!("{resp:?}"),
        ] {
            assert!(dbg.contains(REDACTED));
            assert!(!dbg.contains("secret_pay_tok"));
            assert!(!dbg.contains("secret_card_tok"));
            assert!(!dbg.contains("999"));
            assert!(!dbg.contains("01099887766"));
            assert!(!dbg.contains("4111"));
        }
    }
}
