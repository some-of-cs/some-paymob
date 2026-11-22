#![forbid(unsafe_code)]
//! US-9.1.0 Unit 4: Numeric `transaction_id` fallback resolution and full-refund
//! remaining amount lookup (`amount_cents - refunded_amount_cents`).
//!
//! This module provides two alignment primitives for the `some-payment` orchestrator:
//!
//! 1. [`resolve_transaction_id`](crate::alignment::tx_correlation::resolve_transaction_id)
//!    resolves a positive numeric Paymob `transaction_id` with zero HTTP calls when one is
//!    already present on
//!    [`TransactionLookupRef`](crate::alignment::tx_correlation::TransactionLookupRef),
//!    and otherwise falls back to `POST /api/ecommerce/orders/transaction_inquiry`.
//! 2. [`resolve_full_refund_amount`](crate::alignment::tx_correlation::resolve_full_refund_amount)
//!    queries `GET /api/acceptance/transactions/{id}` and computes the remaining refundable
//!    minor units using checked integer subtraction
//!    ([`compute_remaining_refund_cents`](crate::alignment::tx_correlation::compute_remaining_refund_cents))
//!    to satisfy the TM-2 integer underflow guard.
//!
//! # Examples
//!
//! ```
//! use some_paymob::alignment::tx_correlation::{
//!     TransactionLookupRef, compute_remaining_refund_cents,
//! };
//!
//! let lookup = TransactionLookupRef::from_payment_id("987654");
//! assert_eq!(lookup.direct_transaction_id(), Some(987_654));
//! assert_eq!(compute_remaining_refund_cents(25_000, 7_500), Ok(17_500));
//! ```

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const TRANSACTION_INQUIRY_PATH: &str = "/api/ecommerce/orders/transaction_inquiry";
const TRANSACTION_DETAILS_PREFIX: &str = "/api/acceptance/transactions/";
const TRANSACTION_DETAILS_ENDPOINT: &str = "/api/acceptance/transactions/{transaction_id}";

/// Errors returned by transaction correlation and full-refund amount lookup.
///
/// All variants avoid capturing secret tokens or raw gateway response bodies so
/// `Debug` and `Display` output never leaks credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxCorrelationError {
    /// The configured Paymob base URL is empty or whitespace-only.
    #[error("Paymob base URL must not be empty")]
    InvalidBaseUrl,
    /// The supplied authentication token is empty or whitespace-only.
    #[error("Paymob authentication token must not be empty")]
    EmptyAuthToken,
    /// Neither a numeric transaction ID nor an inquiry reference was provided.
    #[error("transaction lookup requires a transaction_id, order_id, or merchant_order_id")]
    MissingLookupReference,
    /// A transaction identifier was zero or otherwise invalid.
    #[error("transaction_id must be a positive integer, got {0}")]
    InvalidTransactionId(u64),
    /// The Paymob API returned a non-success HTTP status code.
    #[error("Paymob {endpoint} returned HTTP status {status}")]
    HttpStatus {
        /// HTTP status code returned by Paymob.
        status: u16,
        /// Logical Paymob endpoint path.
        endpoint: &'static str,
    },
    /// Network or HTTP client transport failure.
    #[error("HTTP transport error calling Paymob {endpoint}: {detail}")]
    Transport {
        /// Logical Paymob endpoint path.
        endpoint: &'static str,
        /// Sanitized transport error description without URL credentials.
        detail: String,
    },
    /// Failed to deserialize the Paymob JSON response payload.
    #[error("failed to decode Paymob {endpoint} response: {detail}")]
    Decode {
        /// Logical Paymob endpoint path.
        endpoint: &'static str,
        /// Sanitized deserialization error description.
        detail: String,
    },
    /// Checked integer subtraction detected `refunded_amount_cents > amount_cents` (TM-2).
    #[error(
        "refunded_amount_cents ({refunded_amount_cents}) exceeds amount_cents ({amount_cents})"
    )]
    ArithmeticUnderflow {
        /// Original transaction amount in minor units.
        amount_cents: u64,
        /// Previously refunded amount in minor units.
        refunded_amount_cents: u64,
    },
    /// Transaction has zero remaining refundable balance (`amount_cents == refunded_amount_cents`).
    #[error("no remaining refundable balance ({amount_cents} - {refunded_amount_cents} = 0)")]
    NothingRemainingToRefund {
        /// Original transaction amount in minor units.
        amount_cents: u64,
        /// Previously refunded amount in minor units.
        refunded_amount_cents: u64,
    },
}

/// Identifiers used to resolve a Paymob numeric `transaction_id`.
///
/// Resolution checks [`Self::transaction_id`] and [`Self::payment_id`] locally first.
/// Only when neither yields a positive `u64` does [`resolve_transaction_id`] fall back
/// to Paymob `transaction_inquiry` using [`Self::order_id`], [`Self::merchant_order_id`],
/// or [`Self::special_reference`].
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::tx_correlation::TransactionLookupRef;
///
/// let direct = TransactionLookupRef::from_transaction_id(12_345);
/// assert_eq!(direct.direct_transaction_id(), Some(12_345));
///
/// let order = TransactionLookupRef::from_order_id("ord-9001");
/// assert_eq!(order.direct_transaction_id(), None);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionLookupRef {
    /// Already-known positive Paymob numeric transaction identifier.
    pub transaction_id: Option<u64>,
    /// Unified payment identifier string, which may parse as a positive `u64`.
    pub payment_id: Option<String>,
    /// Paymob order identifier used for `transaction_inquiry` fallback.
    pub order_id: Option<String>,
    /// Merchant-assigned order identifier (`merchant_order_id`) for `transaction_inquiry`.
    pub merchant_order_id: Option<String>,
    /// Unified checkout `special_reference`, used as a fallback `merchant_order_id`.
    pub special_reference: Option<String>,
}

impl TransactionLookupRef {
    /// Creates a lookup reference with a direct numeric `transaction_id`.
    #[must_use]
    pub fn from_transaction_id(transaction_id: u64) -> Self {
        Self {
            transaction_id: Some(transaction_id),
            ..Self::default()
        }
    }

    /// Creates a lookup reference from a unified `payment_id` string.
    #[must_use]
    pub fn from_payment_id(payment_id: impl Into<String>) -> Self {
        Self {
            payment_id: Some(payment_id.into()),
            ..Self::default()
        }
    }

    /// Creates a lookup reference from a Paymob `order_id`.
    #[must_use]
    pub fn from_order_id(order_id: impl Into<String>) -> Self {
        Self {
            order_id: Some(order_id.into()),
            ..Self::default()
        }
    }

    /// Creates a lookup reference from a `merchant_order_id`.
    #[must_use]
    pub fn from_merchant_order_id(merchant_order_id: impl Into<String>) -> Self {
        Self {
            merchant_order_id: Some(merchant_order_id.into()),
            ..Self::default()
        }
    }

    /// Creates a lookup reference from a unified checkout `special_reference`.
    #[must_use]
    pub fn from_special_reference(special_reference: impl Into<String>) -> Self {
        Self {
            special_reference: Some(special_reference.into()),
            ..Self::default()
        }
    }

    /// Returns a positive numeric `transaction_id` directly if already available locally.
    ///
    /// Checks [`Self::transaction_id`] first, then attempts to parse [`Self::payment_id`]
    /// as a positive `u64`. Zero and non-numeric values return `None`.
    #[must_use]
    pub fn direct_transaction_id(&self) -> Option<u64> {
        if let Some(id) = self.transaction_id.filter(|&id| id > 0) {
            return Some(id);
        }
        self.payment_id.as_deref().and_then(parse_positive_u64)
    }
}

/// Subset of Paymob transaction fields returned by inquiry and transaction detail APIs.
///
/// `refunded_amount_cents` defaults to `0` when omitted by the Paymob response.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::tx_correlation::TransactionInquirySnapshot;
///
/// let snapshot = TransactionInquirySnapshot {
///     id: 777_001,
///     amount_cents: 50_000,
///     refunded_amount_cents: 12_500,
/// };
/// assert_eq!(snapshot.remaining_refund_cents(), Ok(37_500));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionInquirySnapshot {
    /// Authoritative Paymob numeric transaction identifier.
    pub id: u64,
    /// Original transaction amount in minor currency units.
    #[serde(default)]
    pub amount_cents: u64,
    /// Previously refunded amount in minor currency units (defaults to `0` if omitted).
    #[serde(default)]
    pub refunded_amount_cents: u64,
}

impl TransactionInquirySnapshot {
    /// Computes the remaining refundable minor units using checked subtraction.
    ///
    /// # Errors
    ///
    /// Returns [`TxCorrelationError::ArithmeticUnderflow`] if `refunded_amount_cents`
    /// exceeds `amount_cents`, or [`TxCorrelationError::NothingRemainingToRefund`] if
    /// the remaining balance is zero.
    pub fn remaining_refund_cents(&self) -> Result<u64, TxCorrelationError> {
        compute_remaining_refund_cents(self.amount_cents, self.refunded_amount_cents)
    }
}

#[derive(Serialize)]
struct TransactionInquiryRequest<'a> {
    auth_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    order_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merchant_order_id: Option<String>,
}

impl fmt::Debug for TransactionInquiryRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionInquiryRequest")
            .field("auth_token", &"[REDACTED]")
            .field("order_id", &self.order_id)
            .field("merchant_order_id", &self.merchant_order_id)
            .finish()
    }
}

/// Computes the remaining refundable minor units with a TM-2 integer underflow guard.
///
/// Uses `u64::checked_sub` with zero floating-point arithmetic and fails closed if
/// the balance would underflow or equals zero.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::tx_correlation::{
///     TxCorrelationError, compute_remaining_refund_cents,
/// };
///
/// assert_eq!(compute_remaining_refund_cents(10_000, 0), Ok(10_000));
/// assert_eq!(compute_remaining_refund_cents(10_000, 2_500), Ok(7_500));
/// assert_eq!(
///     compute_remaining_refund_cents(10_000, 10_000),
///     Err(TxCorrelationError::NothingRemainingToRefund {
///         amount_cents: 10_000,
///         refunded_amount_cents: 10_000,
///     }),
/// );
/// assert_eq!(
///     compute_remaining_refund_cents(10_000, 12_000),
///     Err(TxCorrelationError::ArithmeticUnderflow {
///         amount_cents: 10_000,
///         refunded_amount_cents: 12_000,
///     }),
/// );
/// ```
///
/// # Errors
///
/// - [`TxCorrelationError::ArithmeticUnderflow`] when `refunded_amount_cents > amount_cents`.
/// - [`TxCorrelationError::NothingRemainingToRefund`] when the remaining balance is `0`.
pub fn compute_remaining_refund_cents(
    amount_cents: u64,
    refunded_amount_cents: u64,
) -> Result<u64, TxCorrelationError> {
    let Some(remaining) = amount_cents.checked_sub(refunded_amount_cents) else {
        return Err(TxCorrelationError::ArithmeticUnderflow {
            amount_cents,
            refunded_amount_cents,
        });
    };
    if remaining == 0 {
        return Err(TxCorrelationError::NothingRemainingToRefund {
            amount_cents,
            refunded_amount_cents,
        });
    }
    Ok(remaining)
}

/// Resolves an authoritative positive numeric Paymob `transaction_id`.
///
/// If `lookup` already carries a positive numeric `transaction_id` or a `payment_id`
/// string that parses as a positive `u64`, this returns immediately with zero HTTP
/// requests. Otherwise it calls `POST {base_url}/api/ecommerce/orders/transaction_inquiry`
/// with `auth_token` and the supplied `order_id` or `merchant_order_id`
/// (falling back to `special_reference`).
///
/// # Examples
///
/// ```
/// use secrecy::SecretString;
/// use some_paymob::alignment::tx_correlation::{
///     TransactionLookupRef, resolve_transaction_id,
/// };
///
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_all()
///     .build()
///     .expect("runtime");
/// let client = reqwest::Client::new();
/// let token = SecretString::from("example-jwt-token");
/// let lookup = TransactionLookupRef::from_transaction_id(424_242);
///
/// let tx_id = rt
///     .block_on(resolve_transaction_id(
///         &client,
///         "https://accept.paymob.com",
///         &token,
///         &lookup,
///     ))
///     .expect("direct numeric id resolves without HTTP");
/// assert_eq!(tx_id, 424_242);
/// ```
///
/// # Errors
///
/// Returns [`TxCorrelationError`] if the lookup reference, base URL, or auth token is
/// missing/invalid, if the gateway returns an error status, or if the returned ID is `0`.
pub async fn resolve_transaction_id(
    client: &reqwest::Client,
    base_url: &str,
    auth_token: &SecretString,
    lookup: &TransactionLookupRef,
) -> Result<u64, TxCorrelationError> {
    if let Some(id) = lookup.direct_transaction_id() {
        return Ok(id);
    }
    let base = validate_base_url(base_url)?;
    let token = validate_auth_token(auth_token)?;
    let payload = build_inquiry_request(token, lookup)?;
    let url = format!("{base}{TRANSACTION_INQUIRY_PATH}");
    let response = client
        .post(&url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| transport_error(TRANSACTION_INQUIRY_PATH, err))?;
    let snapshot: TransactionInquirySnapshot =
        parse_json_response(response, TRANSACTION_INQUIRY_PATH).await?;
    if snapshot.id == 0 {
        return Err(TxCorrelationError::InvalidTransactionId(0));
    }
    Ok(snapshot.id)
}

/// Resolves the remaining refundable amount in minor units for a full refund.
///
/// Queries `GET {base_url}/api/acceptance/transactions/{transaction_id}` using
/// `Authorization: Bearer <auth_token>` and computes
/// `amount_cents.checked_sub(refunded_amount_cents)` via
/// [`compute_remaining_refund_cents`].
///
/// # Examples
///
/// ```no_run
/// use secrecy::SecretString;
/// use some_paymob::alignment::tx_correlation::resolve_full_refund_amount;
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let client = reqwest::Client::new();
/// let token = SecretString::from("example-jwt-token");
/// let remaining = resolve_full_refund_amount(
///     &client,
///     "https://accept.paymob.com",
///     &token,
///     777_001,
/// )
/// .await?;
/// assert!(remaining > 0);
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`TxCorrelationError`] if `transaction_id` is `0`, if the base URL or auth
/// token is empty, if the Paymob API call fails, or if the remaining balance is zero
/// or would underflow.
pub async fn resolve_full_refund_amount(
    client: &reqwest::Client,
    base_url: &str,
    auth_token: &SecretString,
    transaction_id: u64,
) -> Result<u64, TxCorrelationError> {
    if transaction_id == 0 {
        return Err(TxCorrelationError::InvalidTransactionId(0));
    }
    let base = validate_base_url(base_url)?;
    let token = validate_auth_token(auth_token)?;
    let url = format!("{base}{TRANSACTION_DETAILS_PREFIX}{transaction_id}");
    let response = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|err| transport_error(TRANSACTION_DETAILS_ENDPOINT, err))?;
    let snapshot: TransactionInquirySnapshot =
        parse_json_response(response, TRANSACTION_DETAILS_ENDPOINT).await?;
    compute_remaining_refund_cents(snapshot.amount_cents, snapshot.refunded_amount_cents)
}

fn parse_positive_u64(raw: &str) -> Option<u64> {
    raw.trim().parse::<u64>().ok().filter(|&id| id > 0)
}

fn non_empty_trimmed(raw: Option<&str>) -> Option<String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn validate_base_url(base_url: &str) -> Result<&str, TxCorrelationError> {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(TxCorrelationError::InvalidBaseUrl);
    }
    Ok(trimmed)
}

fn validate_auth_token(auth_token: &SecretString) -> Result<&str, TxCorrelationError> {
    let exposed = auth_token.expose_secret().trim();
    if exposed.is_empty() {
        return Err(TxCorrelationError::EmptyAuthToken);
    }
    Ok(exposed)
}

fn build_inquiry_request<'a>(
    auth_token: &'a str,
    lookup: &TransactionLookupRef,
) -> Result<TransactionInquiryRequest<'a>, TxCorrelationError> {
    let order_id = non_empty_trimmed(lookup.order_id.as_deref());
    let merchant_order_id = non_empty_trimmed(lookup.merchant_order_id.as_deref())
        .or_else(|| non_empty_trimmed(lookup.special_reference.as_deref()));
    if order_id.is_none() && merchant_order_id.is_none() {
        return Err(TxCorrelationError::MissingLookupReference);
    }
    Ok(TransactionInquiryRequest {
        auth_token,
        order_id,
        merchant_order_id,
    })
}

fn transport_error(endpoint: &'static str, err: reqwest::Error) -> TxCorrelationError {
    TxCorrelationError::Transport {
        endpoint,
        detail: err.without_url().to_string(),
    }
}

async fn parse_json_response<T: DeserializeOwned>(
    response: reqwest::Response,
    endpoint: &'static str,
) -> Result<T, TxCorrelationError> {
    let status = response.status();
    if !status.is_success() {
        return Err(TxCorrelationError::HttpStatus {
            status: status.as_u16(),
            endpoint,
        });
    }
    response
        .json::<T>()
        .await
        .map_err(|err| TxCorrelationError::Decode {
            endpoint,
            detail: err.without_url().to_string(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use wiremock::matchers::{body_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn start_inquiry_server(
        expected_body: Option<Value>,
        response: ResponseTemplate,
        expected_calls: u64,
    ) -> MockServer {
        let server = MockServer::start().await;
        let mut builder = Mock::given(method("POST")).and(path(TRANSACTION_INQUIRY_PATH));
        if let Some(body) = expected_body {
            builder = builder.and(body_json(body));
        }
        builder
            .respond_with(response)
            .expect(expected_calls)
            .mount(&server)
            .await;
        server
    }

    async fn start_tx_details_server(
        tx_id: u64,
        bearer_token: Option<&str>,
        response: ResponseTemplate,
    ) -> MockServer {
        let server = MockServer::start().await;
        let endpoint = format!("{TRANSACTION_DETAILS_PREFIX}{tx_id}");
        let mut builder = Mock::given(method("GET")).and(path(endpoint));
        if let Some(token) = bearer_token {
            builder = builder.and(header("authorization", format!("Bearer {token}")));
        }
        builder
            .respond_with(response)
            .expect(1)
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn direct_numeric_transaction_id_makes_zero_http_calls() {
        let server = start_inquiry_server(None, ResponseTemplate::new(500), 0).await;
        let token = SecretString::from("jwt-secret-never-sent");
        let lookup = TransactionLookupRef::from_transaction_id(987_654);

        let tx_id = resolve_transaction_id(&reqwest::Client::new(), &server.uri(), &token, &lookup)
            .await
            .expect("direct transaction_id should resolve without HTTP");
        assert_eq!(tx_id, 987_654);
    }

    #[tokio::test]
    async fn numeric_payment_id_string_makes_zero_http_calls() {
        let server = start_inquiry_server(None, ResponseTemplate::new(500), 0).await;
        let token = SecretString::from("jwt-secret-never-sent");
        let lookup = TransactionLookupRef::from_payment_id(" 424242 ");

        let tx_id = resolve_transaction_id(&reqwest::Client::new(), &server.uri(), &token, &lookup)
            .await
            .expect("numeric payment_id should resolve without HTTP");
        assert_eq!(tx_id, 424_242);
    }

    #[tokio::test]
    async fn transaction_inquiry_fallback_via_order_id() {
        let expected = json!({
            "auth_token": "jwt-order-lookup-token",
            "order_id": "ord-1001"
        });
        let resp = ResponseTemplate::new(200).set_body_json(json!({
            "id": 555_001,
            "amount_cents": 10_000,
            "refunded_amount_cents": 0
        }));
        let server = start_inquiry_server(Some(expected), resp, 1).await;
        let token = SecretString::from("jwt-order-lookup-token");
        let lookup = TransactionLookupRef::from_order_id("ord-1001");

        let tx_id = resolve_transaction_id(&reqwest::Client::new(), &server.uri(), &token, &lookup)
            .await
            .expect("order_id fallback should resolve transaction_id");
        assert_eq!(tx_id, 555_001);
    }

    #[tokio::test]
    async fn transaction_inquiry_fallback_via_merchant_order_id() {
        let expected = json!({
            "auth_token": "jwt-merchant-lookup-token",
            "merchant_order_id": "merch-ref-99"
        });
        let resp = ResponseTemplate::new(200).set_body_json(json!({ "id": 555_002 }));
        let server = start_inquiry_server(Some(expected), resp, 1).await;
        let token = SecretString::from("jwt-merchant-lookup-token");
        let lookup = TransactionLookupRef::from_merchant_order_id("merch-ref-99");

        let tx_id = resolve_transaction_id(&reqwest::Client::new(), &server.uri(), &token, &lookup)
            .await
            .expect("merchant_order_id fallback should resolve transaction_id");
        assert_eq!(tx_id, 555_002);
    }

    #[tokio::test]
    async fn transaction_inquiry_fallback_via_special_reference() {
        let expected = json!({
            "auth_token": "jwt-special-ref-token",
            "merchant_order_id": "spec-ref-77"
        });
        let resp = ResponseTemplate::new(200).set_body_json(json!({ "id": 555_003 }));
        let server = start_inquiry_server(Some(expected), resp, 1).await;
        let token = SecretString::from("jwt-special-ref-token");
        let lookup = TransactionLookupRef::from_special_reference("spec-ref-77");

        let tx_id = resolve_transaction_id(&reqwest::Client::new(), &server.uri(), &token, &lookup)
            .await
            .expect("special_reference fallback should resolve transaction_id");
        assert_eq!(tx_id, 555_003);
    }

    #[tokio::test]
    async fn resolve_transaction_id_missing_reference_fails_closed() {
        let token = SecretString::from("jwt-token");
        let lookup = TransactionLookupRef {
            transaction_id: Some(0),
            payment_id: Some("not-a-number".to_owned()),
            ..TransactionLookupRef::default()
        };

        let err = resolve_transaction_id(
            &reqwest::Client::new(),
            "https://accept.paymob.com",
            &token,
            &lookup,
        )
        .await
        .expect_err("missing reference must fail closed");
        assert_eq!(err, TxCorrelationError::MissingLookupReference);
    }

    #[tokio::test]
    async fn resolve_transaction_id_rejects_zero_id_from_gateway() {
        let resp = ResponseTemplate::new(200).set_body_json(json!({ "id": 0 }));
        let server = start_inquiry_server(None, resp, 1).await;
        let token = SecretString::from("jwt-token");
        let lookup = TransactionLookupRef::from_order_id("ord-zero");

        let err = resolve_transaction_id(&reqwest::Client::new(), &server.uri(), &token, &lookup)
            .await
            .expect_err("zero transaction id from gateway must fail");
        assert_eq!(err, TxCorrelationError::InvalidTransactionId(0));
    }

    #[tokio::test]
    async fn resolve_full_refund_amount_when_refunded_field_omitted() {
        let resp = ResponseTemplate::new(200).set_body_json(json!({
            "id": 777_001,
            "amount_cents": 25_000
        }));
        let server = start_tx_details_server(777_001, Some("jwt-refund-token"), resp).await;
        let token = SecretString::from("jwt-refund-token");

        let remaining =
            resolve_full_refund_amount(&reqwest::Client::new(), &server.uri(), &token, 777_001)
                .await
                .expect("omitted refunded_amount_cents should default to 0");
        assert_eq!(remaining, 25_000);
    }

    #[tokio::test]
    async fn resolve_full_refund_amount_with_partial_prior_refund() {
        let resp = ResponseTemplate::new(200).set_body_json(json!({
            "id": 777_002,
            "amount_cents": 25_000,
            "refunded_amount_cents": 7_500
        }));
        let server = start_tx_details_server(777_002, Some("jwt-refund-token"), resp).await;
        let token = SecretString::from("jwt-refund-token");

        let remaining =
            resolve_full_refund_amount(&reqwest::Client::new(), &server.uri(), &token, 777_002)
                .await
                .expect("partial prior refund should return exact remainder");
        assert_eq!(remaining, 17_500);
    }

    #[tokio::test]
    async fn resolve_full_refund_amount_rejects_zero_remaining_balance() {
        let resp = ResponseTemplate::new(200).set_body_json(json!({
            "id": 777_003,
            "amount_cents": 25_000,
            "refunded_amount_cents": 25_000
        }));
        let server = start_tx_details_server(777_003, None, resp).await;
        let token = SecretString::from("jwt-refund-token");

        let err =
            resolve_full_refund_amount(&reqwest::Client::new(), &server.uri(), &token, 777_003)
                .await
                .expect_err("already fully refunded transaction must fail closed");
        assert_eq!(
            err,
            TxCorrelationError::NothingRemainingToRefund {
                amount_cents: 25_000,
                refunded_amount_cents: 25_000,
            }
        );
    }

    #[tokio::test]
    async fn resolve_full_refund_amount_rejects_integer_underflow() {
        let resp = ResponseTemplate::new(200).set_body_json(json!({
            "id": 777_004,
            "amount_cents": 10_000,
            "refunded_amount_cents": 15_000
        }));
        let server = start_tx_details_server(777_004, None, resp).await;
        let token = SecretString::from("jwt-refund-token");

        let err =
            resolve_full_refund_amount(&reqwest::Client::new(), &server.uri(), &token, 777_004)
                .await
                .expect_err("refunded > amount must fail closed with underflow");
        assert_eq!(
            err,
            TxCorrelationError::ArithmeticUnderflow {
                amount_cents: 10_000,
                refunded_amount_cents: 15_000,
            }
        );
    }

    #[tokio::test]
    async fn http_error_never_exposes_auth_token() {
        let secret = "super-sensitive-jwt-token-999";
        let resp = ResponseTemplate::new(401).set_body_string(secret);
        let server = start_tx_details_server(777_005, None, resp).await;
        let token = SecretString::from(secret);

        let err =
            resolve_full_refund_amount(&reqwest::Client::new(), &server.uri(), &token, 777_005)
                .await
                .expect_err("401 must return HttpStatus error");
        assert_eq!(
            err,
            TxCorrelationError::HttpStatus {
                status: 401,
                endpoint: TRANSACTION_DETAILS_ENDPOINT,
            }
        );
        assert!(!format!("{err:?}").contains(secret));
        assert!(!format!("{err}").contains(secret));
    }

    #[test]
    fn compute_remaining_refund_cents_covers_boundaries() {
        assert_eq!(compute_remaining_refund_cents(50_000, 0), Ok(50_000));
        assert_eq!(compute_remaining_refund_cents(50_000, 12_345), Ok(37_655));
        assert_eq!(
            compute_remaining_refund_cents(u64::MAX, 1),
            Ok(u64::MAX - 1)
        );
        assert_eq!(
            compute_remaining_refund_cents(0, 0),
            Err(TxCorrelationError::NothingRemainingToRefund {
                amount_cents: 0,
                refunded_amount_cents: 0,
            })
        );
        assert_eq!(
            compute_remaining_refund_cents(100, 101),
            Err(TxCorrelationError::ArithmeticUnderflow {
                amount_cents: 100,
                refunded_amount_cents: 101,
            })
        );
    }

    #[test]
    fn snapshot_and_request_redaction_invariants() {
        let snapshot = TransactionInquirySnapshot {
            id: 1,
            amount_cents: 5_000,
            refunded_amount_cents: 1_000,
        };
        assert_eq!(snapshot.remaining_refund_cents(), Ok(4_000));

        let secret = "live-secret-jwt-value";
        let request = TransactionInquiryRequest {
            auth_token: secret,
            order_id: Some("ord-42".to_owned()),
            merchant_order_id: None,
        };
        let debug_output = format!("{request:?}");
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains(secret));
    }
}
