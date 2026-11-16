#![forbid(unsafe_code)]
//! Unit 4.3.5 — Composite `refund_last_transaction` helper (`US-4.3.0`).
//!
//! Fetches the latest deduction transaction for a subscription via Regime 2
//! (`GET /api/acceptance/subscriptions/{id}/last-transaction`), enforces the
//! fail-closed deduction refund guard (`tx.success && !tx.pending && !tx.is_refunded`),
//! and dispatches a full or partial refund via Regime 1
//! (`POST /api/acceptance/void_refund/refund`).

use reqwest::header::{AUTHORIZATION, HeaderMap};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::core::auth::{
    AcceptJwtProvider, CachedToken, format_bearer_header, inject_secret_key_token,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest};

/// Snapshot of a subscription's latest deduction transaction returned by
/// `GET /api/acceptance/subscriptions/{id}/last-transaction`.
///
/// All monetary values are represented in integer minor units (`u64`), never
/// floating-point types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionLastTransaction {
    /// Paymob transaction identifier.
    pub id: u64,
    /// Whether the deduction transaction succeeded.
    pub success: bool,
    /// Whether the deduction transaction is still pending settlement.
    #[serde(default)]
    pub pending: bool,
    /// Whether the deduction transaction has already been refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// Charged transaction amount in integer minor units (for example, piasters/halalas).
    pub amount_cents: u64,
    /// Originating Paymob API source (for example, `"SUBSCRIPTION"`).
    #[serde(default)]
    pub api_source: Option<String>,
    /// Three-letter ISO 4217 currency code, if present.
    #[serde(default)]
    pub currency: Option<String>,
    /// ISO-8601 creation timestamp, if present.
    #[serde(default)]
    pub created_at: Option<String>,
}

/// Request payload dispatched to `POST /api/acceptance/void_refund/refund`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionRefundRequest {
    /// Target Paymob transaction identifier to refund.
    pub transaction_id: u64,
    /// Refund amount in integer minor units (`u64`).
    pub amount_cents: u64,
}

/// Refund outcome returned by `POST /api/acceptance/void_refund/refund`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionRefundResponse {
    /// Newly created refund transaction identifier.
    pub id: u64,
    /// Whether the refund operation succeeded.
    pub success: bool,
    /// Whether the refund is still pending.
    #[serde(default)]
    pub pending: bool,
    /// Whether the transaction is marked as refunded.
    #[serde(default)]
    pub is_refunded: bool,
    /// Refunded amount in integer minor units (`u64`).
    pub amount_cents: u64,
    /// Original parent deduction transaction identifier, if returned.
    #[serde(default)]
    pub parent_transaction: Option<u64>,
}

/// Validates a subscription's latest deduction transaction and builds a
/// [`SubscriptionRefundRequest`] for a full (`None`) or partial (`Some(amount)`) refund.
///
/// Enforces the fail-closed deduction refund guard:
/// - `tx.id > 0`
/// - `tx.success == true`
/// - `tx.pending == false`
/// - `tx.is_refunded == false`
/// - `0 < resolved_amount <= tx.amount_cents`
///
/// # Errors
///
/// - Returns [`PaymobError::ValidationError`] if `tx.id == 0`, `!tx.success`,
///   `tx.pending`, `tx.is_refunded`, or `resolved_amount == 0`.
/// - Returns [`PaymobError::RefundExceedsPermissibleAmount`] if `amount_cents`
///   exceeds `tx.amount_cents`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::refund::{
///     SubscriptionLastTransaction, prepare_refund_payload,
/// };
///
/// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let tx = SubscriptionLastTransaction {
///     id: 998_877,
///     success: true,
///     pending: false,
///     is_refunded: false,
///     amount_cents: 50_000,
///     api_source: Some(String::from("SUBSCRIPTION")),
///     currency: Some(String::from("EGP")),
///     created_at: None,
/// };
///
/// let partial = prepare_refund_payload(&tx, Some(20_000))?;
/// assert_eq!(partial.transaction_id, 998_877);
/// assert_eq!(partial.amount_cents, 20_000);
///
/// let full = prepare_refund_payload(&tx, None)?;
/// assert_eq!(full.amount_cents, 50_000);
/// # Ok(())
/// # }
/// # example().unwrap();
/// ```
pub fn prepare_refund_payload(
    tx: &SubscriptionLastTransaction,
    amount_cents: Option<u64>,
) -> Result<SubscriptionRefundRequest, PaymobError> {
    validate_refundable_transaction(tx)?;
    let resolved_amount = resolve_refund_amount(tx.amount_cents, amount_cents)?;
    Ok(SubscriptionRefundRequest {
        transaction_id: tx.id,
        amount_cents: resolved_amount,
    })
}

fn validate_refundable_transaction(tx: &SubscriptionLastTransaction) -> Result<(), PaymobError> {
    if tx.id == 0 {
        return Err(PaymobError::ValidationError {
            field: "transaction_id",
            reason: String::from("latest subscription transaction ID must be greater than zero"),
        });
    }
    if !tx.success || tx.pending {
        return Err(PaymobError::ValidationError {
            field: "last_transaction",
            reason: String::from(
                "cannot refund a subscription transaction that is pending or unsuccessful",
            ),
        });
    }
    if tx.is_refunded {
        return Err(PaymobError::ValidationError {
            field: "is_refunded",
            reason: String::from("latest subscription transaction has already been refunded"),
        });
    }
    Ok(())
}

fn resolve_refund_amount(
    max_refundable_cents: u64,
    requested_cents: Option<u64>,
) -> Result<u64, PaymobError> {
    let amount = requested_cents.unwrap_or(max_refundable_cents);
    if amount == 0 {
        return Err(PaymobError::ValidationError {
            field: "amount_cents",
            reason: String::from("refund amount must be greater than zero minor units"),
        });
    }
    if amount > max_refundable_cents {
        return Err(PaymobError::RefundExceedsPermissibleAmount {
            message: format!(
                "requested refund amount {amount} exceeds transaction amount {max_refundable_cents}"
            ),
        });
    }
    Ok(amount)
}

impl super::SubscriptionsService {
    /// Fetches the latest deduction transaction for `sub_id`, verifies it is
    /// eligible for refund (`success && !pending && !is_refunded`), and issues a
    /// full (`None`) or partial (`Some(amount_cents)`) refund.
    ///
    /// Executes a two-step cross-regime flow:
    /// 1. Regime 2 (`Authorization: Bearer <auth_token>`):
    ///    `GET /api/acceptance/subscriptions/{sub_id}/last-transaction`
    /// 2. Regime 1 (`Authorization: Token <secret_key>`):
    ///    `POST /api/acceptance/void_refund/refund`
    ///
    /// # Errors
    ///
    /// - Returns [`PaymobError::ValidationError`] if `sub_id == 0`, the latest
    ///   transaction is unsuccessful/pending/already refunded, or `amount_cents == Some(0)`.
    /// - Returns [`PaymobError::RefundExceedsPermissibleAmount`] if `amount_cents`
    ///   exceeds the latest transaction's `amount_cents`.
    /// - Returns [`PaymobError::AuthenticationError`] if `api_key` (for Regime 2
    ///   when no cached JWT exists) or `secret_key` (for Regime 1) is missing.
    /// - Returns [`PaymobError::ApiError`] or [`PaymobError::TransportError`] on
    ///   gateway or network failure.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::{ApiKey, SecretKey};
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .api_key(ApiKey::new("egy_api_key_example")?)
    ///     .secret_key(SecretKey::new("egy_sk_test_example")?)
    ///     .build()?;
    /// let paymob = PaymobClient::new(config)?;
    ///
    /// let refund = paymob
    ///     .subscriptions()
    ///     .refund_last_transaction(1264, Some(20_000))
    ///     .await?;
    /// assert!(refund.success);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refund_last_transaction(
        &self,
        sub_id: u64,
        amount_cents: Option<u64>,
    ) -> Result<SubscriptionRefundResponse, PaymobError> {
        execute_refund_last_transaction(self.client().http(), self.client(), sub_id, amount_cents)
            .await
    }
}

async fn execute_refund_last_transaction(
    http: &HttpClient,
    client: &PaymobClient,
    sub_id: u64,
    amount_cents: Option<u64>,
) -> Result<SubscriptionRefundResponse, PaymobError> {
    if sub_id == 0 {
        return Err(PaymobError::ValidationError {
            field: "sub_id",
            reason: String::from("subscription ID must be greater than zero"),
        });
    }
    let last_tx = fetch_last_transaction(http, client, sub_id).await?;
    let payload = prepare_refund_payload(&last_tx, amount_cents)?;
    dispatch_refund(http, client, &payload).await
}

async fn resolve_accept_jwt(client: &PaymobClient) -> Result<SecretString, PaymobError> {
    if let Some(cached) = client.auth().accept_cache().get_if_fresh() {
        return Ok(cached.access_token.clone());
    }
    let api_key = client.config().api_key().ok_or_else(|| {
        PaymobError::AuthenticationError(String::from(
            "api_key is required for Regime 2 subscription endpoints",
        ))
    })?;
    let provider = AcceptJwtProvider::new(
        client.endpoints().accept_base_url.as_str(),
        SecretString::from(api_key.expose_secret()),
    )?;
    let cached = client
        .auth()
        .accept_cache()
        .get_or_refresh(|| async {
            let token = provider.token().await?;
            Ok::<_, PaymobError>(CachedToken::with_default_ttl(token, None))
        })
        .await?;
    Ok(cached.access_token.clone())
}

async fn fetch_last_transaction(
    http: &HttpClient,
    client: &PaymobClient,
    sub_id: u64,
) -> Result<SubscriptionLastTransaction, PaymobError> {
    let jwt = resolve_accept_jwt(client).await?;
    let response = send_last_transaction_get(http, client, sub_id, &jwt).await?;
    if response.status.as_u16() == 401 {
        client.auth().accept_cache().evict_if_matches(&jwt).await;
        let fresh_jwt = resolve_accept_jwt(client).await?;
        let retry_resp = send_last_transaction_get(http, client, sub_id, &fresh_jwt).await?;
        return parse_json_or_error(retry_resp);
    }
    parse_json_or_error(response)
}

async fn send_last_transaction_get(
    http: &HttpClient,
    client: &PaymobClient,
    sub_id: u64,
    jwt: &SecretString,
) -> Result<crate::core::http::HttpResponse, PaymobError> {
    let url = client.accept_url(&format!(
        "/api/acceptance/subscriptions/{sub_id}/last-transaction"
    ))?;
    let bearer = format_bearer_header(jwt)?;
    let request = HttpRequest::get(url.as_str())
        .map_err(|err| PaymobError::TransportError(err.to_string()))?
        .with_header(AUTHORIZATION, bearer);
    http.execute(&request)
        .await
        .map_err(|err| PaymobError::TransportError(err.to_string()))
}

async fn dispatch_refund(
    http: &HttpClient,
    client: &PaymobClient,
    payload: &SubscriptionRefundRequest,
) -> Result<SubscriptionRefundResponse, PaymobError> {
    let secret_key = client.config().secret_key().ok_or_else(|| {
        PaymobError::AuthenticationError(String::from(
            "secret_key is required for Regime 1 refund endpoint",
        ))
    })?;
    let url = client.accept_url("/api/acceptance/void_refund/refund")?;
    let mut headers = HeaderMap::new();
    inject_secret_key_token(
        &mut headers,
        &SecretString::from(secret_key.expose_secret()),
    )?;
    let auth_header = headers.get(AUTHORIZATION).cloned().ok_or_else(|| {
        PaymobError::AuthenticationError(String::from(
            "failed to construct Regime 1 authorization header",
        ))
    })?;
    let request = HttpRequest::post(url.as_str())
        .map_err(|err| PaymobError::TransportError(err.to_string()))?
        .with_header(AUTHORIZATION, auth_header)
        .with_json(payload)
        .map_err(|err| PaymobError::TransportError(err.to_string()))?;
    let response = http
        .execute(&request)
        .await
        .map_err(|err| PaymobError::TransportError(err.to_string()))?;
    parse_json_or_error(response)
}

fn parse_json_or_error<T: serde::de::DeserializeOwned>(
    response: crate::core::http::HttpResponse,
) -> Result<T, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(&response));
    }
    response
        .json::<T>()
        .map_err(|err| PaymobError::TransportError(err.to_string()))
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::{ApiKey, SecretKey};
    use crate::core::http::HttpClientConfig;
    use crate::core::region::PaymobRegion;

    fn mock_client(base_uri: &str) -> PaymobClient {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Custom {
                accept_base_url: base_uri.to_owned(),
                checkout_base_url: format!("{base_uri}/unifiedcheckout/"),
                payouts_base_url: format!("{base_uri}/payouts/"),
                payouts_staging_base_url: format!("{base_uri}/staging-payouts/"),
            })
            .api_key(ApiKey::new("egy_api_key_test_123").expect("valid api key"))
            .secret_key(SecretKey::new("egy_sk_test_626supersecret").expect("valid secret key"))
            .build()
            .expect("valid test config");
        PaymobClient::new(config).expect("valid PaymobClient")
    }

    fn mock_http() -> HttpClient {
        HttpClient::new(HttpClientConfig::default().with_allow_insecure_http(true))
            .expect("valid test HttpClient")
    }

    #[tokio::test]
    async fn tc_4_3_5_refund_last_transaction_partial_succeeds_end_to_end() {
        let server = MockServer::start().await;
        let client = mock_client(&server.uri());
        client
            .auth()
            .accept_cache()
            .store(CachedToken::with_default_ttl("jwt-sub-token", None));
        let http = mock_http();

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
            .and(header("authorization", "Bearer jwt-sub-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 998_877,
                "success": true,
                "pending": false,
                "is_refunded": false,
                "amount_cents": 50_000,
                "api_source": "SUBSCRIPTION",
                "currency": "EGP"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .and(header("authorization", "Token egy_sk_test_626supersecret"))
            .and(body_json(json!({
                "transaction_id": 998_877,
                "amount_cents": 20_000
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 999_001,
                "success": true,
                "pending": false,
                "is_refunded": true,
                "amount_cents": 20_000,
                "parent_transaction": 998_877
            })))
            .expect(1)
            .mount(&server)
            .await;

        let res = execute_refund_last_transaction(&http, &client, 1264, Some(20_000))
            .await
            .expect("partial refund should succeed");
        assert!(res.success);
        assert_eq!(res.id, 999_001);
        assert_eq!(res.amount_cents, 20_000);
        assert_eq!(res.parent_transaction, Some(998_877));
    }

    #[tokio::test]
    async fn tc_4_3_5_refund_last_transaction_full_amount_when_none() {
        let server = MockServer::start().await;
        let client = mock_client(&server.uri());
        client
            .auth()
            .accept_cache()
            .store(CachedToken::with_default_ttl("jwt-sub-full", None));
        let http = mock_http();

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 998_877,
                "success": true,
                "pending": false,
                "is_refunded": false,
                "amount_cents": 50_000,
                "api_source": "SUBSCRIPTION"
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .and(body_json(json!({
                "transaction_id": 998_877,
                "amount_cents": 50_000
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 999_002,
                "success": true,
                "pending": false,
                "is_refunded": true,
                "amount_cents": 50_000
            })))
            .expect(1)
            .mount(&server)
            .await;

        let res = execute_refund_last_transaction(&http, &client, 1264, None)
            .await
            .expect("full refund should succeed");
        assert_eq!(res.amount_cents, 50_000);
    }

    #[tokio::test]
    async fn tc_4_3_5_rejects_already_refunded_or_failed_transactions_before_dispatch() {
        let server = MockServer::start().await;
        let client = mock_client(&server.uri());
        client
            .auth()
            .accept_cache()
            .store(CachedToken::with_default_ttl("jwt-guard", None));
        let http = mock_http();

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 998_877,
                "success": true,
                "pending": false,
                "is_refunded": true,
                "amount_cents": 50_000
            })))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/acceptance/void_refund/refund"))
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        let err = execute_refund_last_transaction(&http, &client, 1264, None)
            .await
            .expect_err("already refunded transaction must be rejected");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "is_refunded",
                ..
            }
        ));
    }

    #[tokio::test]
    async fn tc_4_3_5_rejects_excessive_and_zero_amounts_and_zero_sub_id() {
        let server = MockServer::start().await;
        let client = mock_client(&server.uri());
        client
            .auth()
            .accept_cache()
            .store(CachedToken::with_default_ttl("jwt-bounds", None));
        let http = mock_http();

        let zero_sub = execute_refund_last_transaction(&http, &client, 0, None)
            .await
            .expect_err("sub_id == 0 must fail");
        assert!(matches!(
            zero_sub,
            PaymobError::ValidationError {
                field: "sub_id",
                ..
            }
        ));

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/1264/last-transaction"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": 998_877,
                "success": true,
                "pending": false,
                "is_refunded": false,
                "amount_cents": 50_000
            })))
            .expect(2)
            .mount(&server)
            .await;

        let zero_amt = execute_refund_last_transaction(&http, &client, 1264, Some(0))
            .await
            .expect_err("zero amount must fail");
        assert!(matches!(
            zero_amt,
            PaymobError::ValidationError {
                field: "amount_cents",
                ..
            }
        ));

        let excess_amt = execute_refund_last_transaction(&http, &client, 1264, Some(60_000))
            .await
            .expect_err("excessive amount must fail");
        assert!(matches!(
            excess_amt,
            PaymobError::RefundExceedsPermissibleAmount { .. }
        ));
    }

    #[tokio::test]
    async fn tc_4_3_5_maps_gateway_404_error() {
        let server = MockServer::start().await;
        let client = mock_client(&server.uri());
        client
            .auth()
            .accept_cache()
            .store(CachedToken::with_default_ttl("jwt-404", None));
        let http = mock_http();

        Mock::given(method("GET"))
            .and(path("/api/acceptance/subscriptions/9999/last-transaction"))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({"detail": "Not found."})))
            .expect(1)
            .mount(&server)
            .await;

        let err = execute_refund_last_transaction(&http, &client, 9999, None)
            .await
            .expect_err("404 must map to PaymobError::ApiError");
        assert!(matches!(err, PaymobError::ApiError { status: 404, .. }));
    }

    #[test]
    fn tc_4_3_5_prepare_refund_payload_rejects_unsuccessful_and_pending() {
        let failed = SubscriptionLastTransaction {
            id: 101,
            success: false,
            pending: false,
            is_refunded: false,
            amount_cents: 10_000,
            api_source: None,
            currency: None,
            created_at: None,
        };
        assert!(matches!(
            prepare_refund_payload(&failed, None),
            Err(PaymobError::ValidationError {
                field: "last_transaction",
                ..
            })
        ));

        let pending = SubscriptionLastTransaction {
            id: 102,
            success: true,
            pending: true,
            is_refunded: false,
            amount_cents: 10_000,
            api_source: None,
            currency: None,
            created_at: None,
        };
        assert!(matches!(
            prepare_refund_payload(&pending, None),
            Err(PaymobError::ValidationError {
                field: "last_transaction",
                ..
            })
        ));
    }
}
