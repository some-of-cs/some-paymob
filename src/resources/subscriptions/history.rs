#![forbid(unsafe_code)]
//! Subscription webhook registration and transaction history (`US-4.3.0` Unit 4).
//!
//! Provides Regime 2 (`Authorization: Bearer <auth_token>`) operations for:
//! - [`SubscriptionsService::register_webhook`] (`POST /api/acceptance/subscriptions/{id}/webhook`)
//! - [`SubscriptionsService::last_transaction`] (`GET /api/acceptance/subscriptions/{id}/last-transaction`)
//! - [`SubscriptionsService::list_transactions`] (`GET /api/acceptance/subscriptions/{id}/transactions`)
//!
//! All monetary fields use integer minor units (`u64`), all functions adhere to
//! cyclomatic complexity `CC <= 6` and nesting depth `<= 2`, and no secrets or
//! raw card data are exposed in `Debug` or error outputs.

use std::collections::BTreeMap;
use std::fmt;

use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    SubscriptionsService, execute_subscription_bearer_json, validate_positive_id,
    validate_webhook_url,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;

const SUBSCRIPTION_API_SOURCE: &str = "SUBSCRIPTION";

/// Request payload for registering a subscription lifecycle webhook URL.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::subscriptions::history::RegisterWebhookParams;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let params = RegisterWebhookParams::new("https://merchant.example.com/webhooks/paymob")?;
/// assert_eq!(params.webhook_url(), "https://merchant.example.com/webhooks/paymob");
/// assert!(RegisterWebhookParams::new("http://insecure.example.com/hook").is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegisterWebhookParams {
    webhook_url: String,
}

impl RegisterWebhookParams {
    /// Validates and constructs a [`RegisterWebhookParams`] payload.
    ///
    /// Requires a non-empty `https://` URL (or loopback `http://127.0.0.1` / `localhost`
    /// for local testing) with no ASCII control characters or whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] (`field: "url"`) if `url` is empty,
    /// malformed, contains control characters/whitespace, or uses a non-HTTPS scheme
    /// outside loopback hosts.
    pub fn new(url: impl Into<String>) -> Result<Self, PaymobError> {
        let validated = validate_webhook_url("url", &url.into())?;
        Ok(Self {
            webhook_url: validated,
        })
    }

    /// Returns the validated webhook callback URL slice.
    #[must_use]
    pub fn webhook_url(&self) -> &str {
        &self.webhook_url
    }
}

/// Response returned by `POST /api/acceptance/subscriptions/{id}/webhook`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SubscriptionWebhookRegistration {
    /// Optional subscription identifier echoed by the gateway.
    #[serde(default)]
    pub id: Option<u64>,
    /// Registered webhook URL echoed by the gateway, if present.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Optional status detail message returned by Paymob.
    #[serde(default)]
    pub detail: Option<String>,
    /// Optional confirmation message returned by Paymob.
    #[serde(default)]
    pub message: Option<String>,
    /// Additional gateway-supplied metadata fields.
    #[serde(default, flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Full Paymob subscription transaction record returned by
/// `GET /api/acceptance/subscriptions/{id}/last-transaction` and
/// `GET /api/acceptance/subscriptions/{id}/transactions`.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::subscriptions::history::SubscriptionTransaction;
///
/// # fn main() -> Result<(), serde_json::Error> {
/// let json = r#"{
///     "id": 998877,
///     "pending": false,
///     "amount_cents": 50000,
///     "success": true,
///     "is_refunded": false,
///     "is_voided": false,
///     "currency": "EGP",
///     "api_source": "SUBSCRIPTION"
/// }"#;
/// let tx: SubscriptionTransaction = serde_json::from_str(json)?;
/// assert_eq!(tx.id, 998877);
/// assert!(tx.is_subscription_source());
/// assert!(tx.is_refundable());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SubscriptionTransaction {
    /// Unique Paymob transaction identifier.
    pub id: u64,
    /// Whether the transaction is still pending settlement.
    #[serde(default)]
    pub pending: bool,
    /// Transaction amount in minor units (piasters, halalas, fils, paisas).
    #[serde(default)]
    pub amount_cents: u64,
    /// Whether the transaction succeeded.
    #[serde(default)]
    pub success: bool,
    /// Whether this transaction is an authorization hold.
    #[serde(default)]
    pub is_auth: bool,
    /// Whether this transaction is a capture operation.
    #[serde(default)]
    pub is_capture: bool,
    /// Whether this transaction is a standalone payment.
    #[serde(default)]
    pub is_standalone_payment: bool,
    /// Whether this transaction has been voided.
    #[serde(default)]
    pub is_voided: bool,
    /// Whether this transaction has been refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// Whether 3D Secure authentication was used.
    #[serde(default)]
    pub is_3d_secure: bool,
    /// Integration ID used to process the transaction.
    #[serde(default)]
    pub integration_id: Option<u64>,
    /// Whether this transaction has a parent transaction.
    #[serde(default)]
    pub has_parent_transaction: bool,
    /// ISO-8601 creation timestamp.
    #[serde(default)]
    pub created_at: Option<String>,
    /// ISO-8601 payment completion timestamp.
    #[serde(default)]
    pub paid_at: Option<String>,
    /// ISO-8601 last update timestamp.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// ISO-4217 currency code (for example, `"EGP"`).
    #[serde(default)]
    pub currency: Option<String>,
    /// API source identifier (typically `"SUBSCRIPTION"` for recurring deductions).
    #[serde(default)]
    pub api_source: Option<String>,
    /// Legacy void flag.
    #[serde(default)]
    pub is_void: bool,
    /// Legacy refund flag.
    #[serde(default)]
    pub is_refund: bool,
    /// Whether this transaction is a cashout.
    #[serde(default)]
    pub is_cashout: bool,
    /// Whether this transaction is hidden in merchant reports.
    #[serde(default)]
    pub is_hidden: bool,
    /// Whether an upstream error occurred (preserves Paymob's `error_occured` spelling).
    #[serde(default)]
    pub error_occured: bool,
    /// Whether the transaction ran in live mode.
    #[serde(default)]
    pub is_live: bool,
    /// Optional external endpoint reference.
    #[serde(default)]
    pub other_endpoint_reference: Option<String>,
    /// Total refunded amount in minor units.
    #[serde(default)]
    pub refunded_amount_cents: Option<u64>,
    /// Optional payment source identifier.
    #[serde(default)]
    pub source_id: Option<u64>,
    /// Whether the transaction has been captured.
    #[serde(default)]
    pub is_captured: bool,
    /// Captured amount in minor units.
    #[serde(default)]
    pub captured_amount: Option<u64>,
    /// Merchant owner identifier.
    #[serde(default)]
    pub owner: Option<u64>,
    /// Associated order payload or identifier.
    #[serde(default)]
    pub order: Option<Value>,
    /// Payment instrument metadata (`type`, `sub_type`, `pan`).
    #[serde(default)]
    pub source_data: Option<Value>,
    /// Acquirer/gateway response metadata.
    #[serde(default)]
    pub data: Option<Value>,
    /// Optional parent transaction reference.
    #[serde(default)]
    pub parent_transaction: Option<Value>,
}

impl SubscriptionTransaction {
    /// Returns `true` when `api_source` equals `"SUBSCRIPTION"`.
    #[must_use]
    pub fn is_subscription_source(&self) -> bool {
        self.api_source.as_deref() == Some(SUBSCRIPTION_API_SOURCE)
    }

    /// Returns `true` when the transaction succeeded, is not pending, is not voided,
    /// and has not been fully refunded.
    #[must_use]
    pub const fn is_refundable(&self) -> bool {
        self.success && !self.pending && !self.is_refunded && !self.is_voided
    }
}

impl fmt::Debug for SubscriptionTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubscriptionTransaction")
            .field("id", &self.id)
            .field("pending", &self.pending)
            .field("amount_cents", &self.amount_cents)
            .field("success", &self.success)
            .field("is_refunded", &self.is_refunded)
            .field("is_voided", &self.is_voided)
            .field("currency", &self.currency)
            .field("api_source", &self.api_source)
            .field(
                "source_data",
                &self.source_data.as_ref().map(|_| "[REDACTED]"),
            )
            .field("data", &self.data.as_ref().map(|_| "[REDACTED]"))
            .finish_non_exhaustive()
    }
}

/// Wire envelope supporting both bare arrays and paginated/wrapped transaction lists.
#[derive(Deserialize)]
#[serde(untagged)]
enum TransactionListEnvelope {
    Array(Vec<SubscriptionTransaction>),
    Results {
        results: Vec<SubscriptionTransaction>,
    },
    Transactions {
        transactions: Vec<SubscriptionTransaction>,
    },
}

impl TransactionListEnvelope {
    fn into_vec(self) -> Vec<SubscriptionTransaction> {
        match self {
            Self::Array(items) => items,
            Self::Results { results } => results,
            Self::Transactions { transactions } => transactions,
        }
    }
}

/// Sub-service for subscription webhook registration and transaction history (`US-4.3.0` Unit 4).
///
/// Obtained via [`SubscriptionsService::history`] or [`SubscriptionHistoryService::new`].
#[derive(Debug, Clone)]
pub struct SubscriptionHistoryService {
    client: PaymobClient,
}

impl SubscriptionHistoryService {
    /// Creates a new [`SubscriptionHistoryService`] bound to `client`.
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub fn client(&self) -> &PaymobClient {
        &self.client
    }

    /// Registers or updates the lifecycle webhook URL for subscription `sub_id`
    /// (`POST /api/acceptance/subscriptions/{id}/webhook`) under Regime 2 `Bearer <auth_token>`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0`, `url` is invalid, or
    /// `api_key` is missing from [`ClientConfig`](crate::core::config::ClientConfig);
    /// [`PaymobError::AuthenticationError`] on rejected credentials; or
    /// [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
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
    ///     .api_key(ApiKey::new("test-api-key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let reg = client
    ///     .subscriptions()
    ///     .history()
    ///     .register_webhook(1264, "https://merchant.example.com/webhooks/paymob")
    ///     .await?;
    /// let _ = reg.webhook_url;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register_webhook(
        &self,
        sub_id: u64,
        url: &str,
    ) -> Result<SubscriptionWebhookRegistration, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let payload = RegisterWebhookParams::new(url)?;
        let path = format!("/api/acceptance/subscriptions/{sub_id}/webhook");
        execute_subscription_bearer_json(&self.client, Method::POST, &path, Some(&payload)).await
    }

    /// Fetches the latest deduction transaction for subscription `sub_id`
    /// (`GET /api/acceptance/subscriptions/{id}/last-transaction`) under Regime 2 `Bearer <auth_token>`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing;
    /// [`PaymobError::AuthenticationError`] on rejected credentials; or
    /// [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    pub async fn last_transaction(
        &self,
        sub_id: u64,
    ) -> Result<SubscriptionTransaction, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("/api/acceptance/subscriptions/{sub_id}/last-transaction");
        execute_subscription_bearer_json::<(), SubscriptionTransaction>(
            &self.client,
            Method::GET,
            &path,
            None,
        )
        .await
    }

    /// Lists all deduction transactions for subscription `sub_id`
    /// (`GET /api/acceptance/subscriptions/{id}/transactions`) under Regime 2 `Bearer <auth_token>`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `sub_id == 0` or `api_key` is missing;
    /// [`PaymobError::AuthenticationError`] on rejected credentials; or
    /// [`PaymobError::ApiError`] / [`PaymobError::TransportError`] on gateway failure.
    pub async fn list_transactions(
        &self,
        sub_id: u64,
    ) -> Result<Vec<SubscriptionTransaction>, PaymobError> {
        validate_positive_id("sub_id", sub_id)?;
        let path = format!("/api/acceptance/subscriptions/{sub_id}/transactions");
        let envelope: TransactionListEnvelope = execute_subscription_bearer_json::<
            (),
            TransactionListEnvelope,
        >(&self.client, Method::GET, &path, None)
        .await?;
        Ok(envelope.into_vec())
    }
}

impl SubscriptionsService {
    /// Returns a [`SubscriptionHistoryService`] handle bound to this client.
    #[must_use]
    pub fn history(&self) -> SubscriptionHistoryService {
        SubscriptionHistoryService::new(self.client().clone())
    }

    /// Registers or updates the lifecycle webhook URL for subscription `sub_id`
    /// (`POST /api/acceptance/subscriptions/{id}/webhook`) under Regime 2 `Bearer <auth_token>`.
    ///
    /// # Errors
    ///
    /// Propagates validation, authentication, API, and transport errors from
    /// [`SubscriptionHistoryService::register_webhook`].
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
    ///     .api_key(ApiKey::new("test-api-key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let _reg = client
    ///     .subscriptions()
    ///     .register_webhook(1264, "https://merchant.example.com/webhooks/paymob")
    ///     .await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn register_webhook(
        &self,
        sub_id: u64,
        url: &str,
    ) -> Result<SubscriptionWebhookRegistration, PaymobError> {
        self.history().register_webhook(sub_id, url).await
    }

    /// Fetches the latest deduction transaction for subscription `sub_id`
    /// (`GET /api/acceptance/subscriptions/{id}/last-transaction`) under Regime 2 `Bearer <auth_token>`.
    ///
    /// # Errors
    ///
    /// Propagates validation, authentication, API, and transport errors from
    /// [`SubscriptionHistoryService::last_transaction`].
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
    ///     .api_key(ApiKey::new("test-api-key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let tx = client.subscriptions().last_transaction(1264).await?;
    /// assert!(tx.is_subscription_source());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn last_transaction(
        &self,
        sub_id: u64,
    ) -> Result<SubscriptionTransaction, PaymobError> {
        self.history().last_transaction(sub_id).await
    }

    /// Lists all deduction transactions for subscription `sub_id`
    /// (`GET /api/acceptance/subscriptions/{id}/transactions`) under Regime 2 `Bearer <auth_token>`.
    ///
    /// # Errors
    ///
    /// Propagates validation, authentication, API, and transport errors from
    /// [`SubscriptionHistoryService::list_transactions`].
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
    ///     .api_key(ApiKey::new("test-api-key")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let txs = client.subscriptions().list_transactions(1264).await?;
    /// assert!(!txs.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn list_transactions(
        &self,
        sub_id: u64,
    ) -> Result<Vec<SubscriptionTransaction>, PaymobError> {
        self.history().list_transactions(sub_id).await
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::auth::{ACCEPT_AUTH_TOKENS_PATH, CachedToken};
    use crate::core::config::ClientConfig;
    use crate::core::credentials::ApiKey;
    use crate::core::region::PaymobRegion;

    fn build_mock_client(server: &MockServer) -> PaymobClient {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: server.uri(),
                checkout_base_url: format!("{}/unifiedcheckout/", server.uri()),
                payouts_base_url: server.uri(),
                payouts_staging_base_url: server.uri(),
            })
            .api_key(ApiKey::new("test-api-key-unit4").expect("valid api key"))
            .build()
            .expect("valid client config");
        PaymobClient::new(config).expect("valid client")
    }

    async fn mount_auth_token(server: &MockServer, token: &str) {
        Mock::given(method("POST"))
            .and(path(ACCEPT_AUTH_TOKENS_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": token })))
            .expect(1)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn tc_4_3_4_register_webhook_sends_bearer_token_and_webhook_url() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt-unit4-reg").await;
        Mock::given(method("POST"))
            .and(path("/api/acceptance/subscriptions/1264/webhook"))
            .and(header("authorization", "Bearer jwt-unit4-reg"))
            .and(body_json(json!({
                "webhook_url": "https://merchant.example.com/webhooks/paymob"
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 1264,
                "webhook_url": "https://merchant.example.com/webhooks/paymob",
                "detail": "Webhook registered"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_mock_client(&server);
        let reg = client
            .subscriptions()
            .register_webhook(1264, "https://merchant.example.com/webhooks/paymob")
            .await
            .expect("register_webhook succeeds");

        assert_eq!(reg.id, Some(1264));
        assert_eq!(
            reg.webhook_url.as_deref(),
            Some("https://merchant.example.com/webhooks/paymob")
        );
        assert_eq!(reg.detail.as_deref(), Some("Webhook registered"));
    }

    #[tokio::test]
    async fn tc_4_3_4_last_transaction_returns_subscription_transaction() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt-unit4-last").await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
            .and(header("authorization", "Bearer jwt-unit4-last"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 998877,
                "pending": false,
                "amount_cents": 50000,
                "success": true,
                "is_auth": false,
                "is_capture": false,
                "is_standalone_payment": false,
                "is_voided": false,
                "is_refunded": false,
                "is_3d_secure": false,
                "integration_id": 445566,
                "has_parent_transaction": false,
                "created_at": "2026-11-16T10:00:00Z",
                "currency": "EGP",
                "api_source": "SUBSCRIPTION",
                "error_occured": false,
                "is_live": false
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_mock_client(&server);
        let tx = client
            .subscriptions()
            .last_transaction(1264)
            .await
            .expect("last_transaction succeeds");

        assert_eq!(tx.id, 998_877);
        assert_eq!(tx.amount_cents, 50_000);
        assert!(tx.success);
        assert!(!tx.is_refunded);
        assert_eq!(tx.currency.as_deref(), Some("EGP"));
        assert_eq!(tx.api_source.as_deref(), Some("SUBSCRIPTION"));
        assert!(tx.is_subscription_source());
        assert!(tx.is_refundable());
    }

    #[tokio::test]
    async fn tc_4_3_4_list_transactions_supports_array_and_paginated_envelope() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt-unit4-list").await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/transactions"))
            .and(header("authorization", "Bearer jwt-unit4-list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "id": 998876,
                    "amount_cents": 50000,
                    "success": true,
                    "is_refunded": true,
                    "api_source": "SUBSCRIPTION"
                },
                {
                    "id": 998877,
                    "amount_cents": 50000,
                    "success": true,
                    "is_refunded": false,
                    "api_source": "SUBSCRIPTION"
                }
            ])))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_mock_client(&server);
        let txs = client
            .subscriptions()
            .list_transactions(1264)
            .await
            .expect("list_transactions array succeeds");

        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].id, 998_876);
        assert!(!txs[0].is_refundable());
        assert_eq!(txs[1].id, 998_877);
        assert!(txs[1].is_refundable());

        let server_wrapped = MockServer::start().await;
        mount_auth_token(&server_wrapped, "jwt-unit4-wrapped").await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [
                    {
                        "id": 777,
                        "amount_cents": 25000,
                        "success": true,
                        "is_refunded": false,
                        "api_source": "SUBSCRIPTION"
                    }
                ]
            })))
            .expect(1)
            .mount(&server_wrapped)
            .await;

        let wrapped_client = build_mock_client(&server_wrapped);
        let wrapped = wrapped_client
            .subscriptions()
            .list_transactions(1264)
            .await
            .expect("list_transactions wrapped succeeds");
        assert_eq!(wrapped.len(), 1);
        assert_eq!(wrapped[0].id, 777);
    }

    #[tokio::test]
    async fn tc_4_3_4_retries_once_on_401_incorrect_credentials() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "fresh-jwt-token").await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
            .and(header("authorization", "Bearer stale-jwt-token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(json!({
                "detail": "incorrect credentials"
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
            .and(header("authorization", "Bearer fresh-jwt-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 555,
                "amount_cents": 10000,
                "success": true,
                "api_source": "SUBSCRIPTION"
            })))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_mock_client(&server);
        client
            .auth()
            .accept_cache()
            .store(CachedToken::with_default_ttl("stale-jwt-token", None));

        let tx = client
            .subscriptions()
            .last_transaction(1264)
            .await
            .expect("401 retry succeeds");
        assert_eq!(tx.id, 555);
    }

    #[tokio::test]
    async fn tc_4_3_4_rejects_invalid_sub_id_and_insecure_webhook_url() {
        let server = MockServer::start().await;
        let client = build_mock_client(&server);

        let err_zero = client
            .subscriptions()
            .last_transaction(0)
            .await
            .expect_err("sub_id=0 must fail");
        assert!(matches!(
            err_zero,
            PaymobError::ValidationError {
                field: "sub_id",
                ..
            }
        ));

        let err_http = client
            .subscriptions()
            .register_webhook(1264, "http://merchant.example.com/hook")
            .await
            .expect_err("non-loopback http must fail");
        assert!(matches!(
            err_http,
            PaymobError::ValidationError { field: "url", .. }
        ));

        let err_empty = client
            .subscriptions()
            .register_webhook(1264, "   ")
            .await
            .expect_err("empty url must fail");
        assert!(matches!(
            err_empty,
            PaymobError::ValidationError { field: "url", .. }
        ));

        let no_key_config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("valid config without api_key");
        let no_key_client = PaymobClient::new(no_key_config).expect("valid client");
        let err_key = no_key_client
            .subscriptions()
            .list_transactions(1264)
            .await
            .expect_err("missing api_key must fail");
        assert!(matches!(err_key, PaymobError::AuthenticationError(_)));
    }

    #[tokio::test]
    async fn tc_4_3_4_maps_404_and_malformed_json_errors() {
        let server = MockServer::start().await;
        mount_auth_token(&server, "jwt-unit4-err").await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/9999/last-transaction"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({
                "detail": "not found."
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/transactions"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{not-json"))
            .expect(1)
            .mount(&server)
            .await;

        let client = build_mock_client(&server);
        let err_404 = client
            .subscriptions()
            .last_transaction(9999)
            .await
            .expect_err("404 must fail");
        assert!(matches!(err_404, PaymobError::ApiError { status: 404, .. }));

        let err_json = client
            .subscriptions()
            .list_transactions(1264)
            .await
            .expect_err("malformed json must fail");
        assert!(matches!(err_json, PaymobError::TransportError(_)));
    }
}
