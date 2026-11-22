#![forbid(unsafe_code)]
//! US-9.2.0 Unit 2: Shared `notification_url` callback dispatcher for Paymob.
//!
//! Routes incoming requests on a shared Paymob `notification_url` into strongly
//! typed, verified callback payloads using the constant-time triple `HMAC-SHA512`
//! verifiers in [`crate::alignment::triple_hmac`]:
//!
//! 1. **`GET` query redirect** — verified with
//!    [`verify_tx_get_hmac`](crate::alignment::triple_hmac::verify_tx_get_hmac)
//!    against `?hmac=` and tagged as
//!    [`CallbackAuthority::CustomerGetReturn`](crate::alignment::callback_dispatcher::CallbackAuthority::CustomerGetReturn)
//!    (`TM-3`: never treated as authoritative settlement).
//! 2. **`POST` JSON with `type == "TOKEN"`** — verified with
//!    [`verify_token_hmac`](crate::alignment::triple_hmac::verify_token_hmac)
//!    against `?hmac=` and returned as
//!    [`DispatchedPaymobCallback::CardToken`](crate::alignment::callback_dispatcher::DispatchedPaymobCallback::CardToken)
//!    with redacted `Debug` and `Display` output (`TM-4`).
//! 3. **`POST` JSON with `trigger_type` + `subscription_data`** — verified with
//!    [`verify_subscription_hmac`](crate::alignment::triple_hmac::verify_subscription_hmac)
//!    strictly against the JSON body `hmac` field while ignoring `?hmac=` (`TM-6`),
//!    and returned as
//!    [`DispatchedPaymobCallback::Subscription`](crate::alignment::callback_dispatcher::DispatchedPaymobCallback::Subscription).
//! 4. **`POST` JSON with `type == "TRANSACTION"` (or transaction `obj`)** — verified
//!    with [`verify_tx_hmac`](crate::alignment::triple_hmac::verify_tx_hmac)
//!    against `?hmac=`, tagged as
//!    [`CallbackAuthority::AuthoritativePostWebhook`](crate::alignment::callback_dispatcher::CallbackAuthority::AuthoritativePostWebhook),
//!    and returned as
//!    [`DispatchedPaymobCallback::Transaction`](crate::alignment::callback_dispatcher::DispatchedPaymobCallback::Transaction).
//! 5. **Unknown or unsupported callback types** — rejected fail-closed with
//!    [`CallbackDispatchError::UnsupportedCallbackType`](crate::alignment::callback_dispatcher::CallbackDispatchError::UnsupportedCallbackType)
//!    (`TM-1`).
//!
//! Use [`dispatch_and_verify_paymob_callback`](crate::alignment::callback_dispatcher::dispatch_and_verify_paymob_callback)
//! as the single entry point and [`raw_redacted`](crate::alignment::callback_dispatcher::raw_redacted)
//! to scrub sensitive JSON fields before logging or persistence.

use std::collections::BTreeMap;
use std::fmt;

use serde_json::{Map, Value};
use thiserror::Error;

use crate::alignment::triple_hmac::{
    TripleHmacError, verify_subscription_hmac, verify_token_hmac, verify_tx_get_hmac,
    verify_tx_hmac,
};

/// Placeholder string used whenever sensitive values are redacted (`TM-4`).
const REDACTED: &str = "[REDACTED]";

/// JSON object keys (matched case-insensitively on leaf segment) scrubbed by [`raw_redacted`].
const SENSITIVE_KEYS: &[&str] = &["token", "hmac", "email", "phone_number", "pan"];

/// HTTP method of an incoming request on a shared Paymob `notification_url`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymobCallbackMethod {
    /// Customer browser redirect callback (`GET`) carrying query parameters.
    Get,
    /// Server-to-server webhook callback (`POST`) carrying a JSON body.
    Post,
}

/// Authority level of a verified Paymob callback (`TM-3`).
///
/// Customer browser `GET` return callbacks must never be used to mark an order
/// settled; only server-to-server `POST` webhooks carry authoritative state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackAuthority {
    /// Verified server-to-server `POST` webhook from Paymob.
    AuthoritativePostWebhook,
    /// Verified customer browser `GET` redirect return (non-authoritative).
    CustomerGetReturn,
}

impl CallbackAuthority {
    /// Returns `true` only when the callback is an authoritative server-to-server `POST` webhook.
    #[must_use]
    pub const fn is_authoritative(self) -> bool {
        matches!(self, Self::AuthoritativePostWebhook)
    }
}

/// Raw incoming request data delivered to a shared Paymob `notification_url`.
///
/// Custom `Debug` output redacts query parameters and JSON body values to prevent
/// accidental exposure of card tokens, HMAC digests, or customer PII (`TM-4`).
#[derive(Clone, PartialEq, Eq)]
pub struct PaymobCallbackInput {
    /// HTTP method (`GET` or `POST`).
    pub method: PaymobCallbackMethod,
    /// Parsed URL query parameters (for example `?hmac=...` and GET transaction fields).
    pub query_params: BTreeMap<String, String>,
    /// Optional parsed JSON body for `POST` callbacks.
    pub body: Option<Value>,
}

impl PaymobCallbackInput {
    /// Constructs a `GET` callback input from an iterator of `(key, value)` query parameters.
    #[must_use]
    pub fn get<K, V, I>(query_params: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            method: PaymobCallbackMethod::Get,
            query_params: collect_query_params(query_params),
            body: None,
        }
    }

    /// Constructs a `POST` callback input from query parameters and a parsed JSON body.
    #[must_use]
    pub fn post<K, V, I>(query_params: I, body: Value) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        Self {
            method: PaymobCallbackMethod::Post,
            query_params: collect_query_params(query_params),
            body: Some(body),
        }
    }

    /// Constructs a `POST` callback input with no query parameters (typical for Subscriptions).
    #[must_use]
    pub fn post_without_query(body: Value) -> Self {
        Self {
            method: PaymobCallbackMethod::Post,
            query_params: BTreeMap::new(),
            body: Some(body),
        }
    }
}

impl fmt::Debug for PaymobCallbackInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobCallbackInput")
            .field("method", &self.method)
            .field("query_param_count", &self.query_params.len())
            .field("has_body", &self.body.is_some())
            .finish()
    }
}

/// Verified and normalized Paymob Transaction callback payload (`HMAC 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionCallbackData {
    /// Whether this transaction event came from an authoritative `POST` webhook or a `GET` return.
    pub authority: CallbackAuthority,
    /// Paymob numeric transaction identifier serialized as a string.
    pub transaction_id: Option<String>,
    /// Paymob order identifier (`obj.order.id` in POST, `order` in GET).
    pub order_id: Option<String>,
    /// Transaction amount in minor currency units (cents/piastres).
    pub amount_cents: Option<i64>,
    /// Three-letter ISO currency code (for example `"EGP"` or `"SAR"`).
    pub currency: Option<String>,
    /// Whether Paymob marked the transaction successful.
    pub success: Option<bool>,
    /// Whether Paymob marked the transaction pending.
    pub pending: Option<bool>,
    /// Whether this transaction is an authorization hold.
    pub is_auth: Option<bool>,
    /// Whether this transaction is a capture.
    pub is_capture: Option<bool>,
    /// Whether this transaction has been voided.
    pub is_voided: Option<bool>,
    /// Whether this transaction has been refunded.
    pub is_refunded: Option<bool>,
    /// Paymob's `error_occured` (single `r`) flag.
    pub error_occured: Option<bool>,
    /// Paymob integration identifier.
    pub integration_id: Option<String>,
    /// Payment instrument source type (for example `"card"` or `"wallet"`).
    pub source_type: Option<String>,
    /// Payment instrument sub-type (for example `"MasterCard"` or `"Visa"`).
    pub source_sub_type: Option<String>,
    /// Scrubbed JSON representation with sensitive keys replaced by `"[REDACTED]"`.
    pub raw_redacted: Value,
}

/// Verified and normalized Paymob Card `TOKEN` callback payload (`HMAC 2`).
///
/// Both `Debug` and `Display` redact [`Self::token`] and [`Self::email`] as `"[REDACTED]"`
/// to enforce `TM-4` secret and PII non-exposure.
#[derive(Clone, PartialEq, Eq)]
pub struct CardTokenCallbackData {
    /// Paymob token record identifier.
    pub id: Option<String>,
    /// Merchant or Paymob order identifier associated with the saved card.
    pub order_id: Option<String>,
    /// Masked card PAN (for example `"xxxx-xxxx-xxxx-2346"`).
    pub masked_pan: Option<String>,
    /// Card network / subtype (for example `"MasterCard"` or `"Visa"`).
    pub card_subtype: Option<String>,
    /// ISO-8601 creation timestamp reported by Paymob.
    pub created_at: Option<String>,
    /// Paymob merchant identifier.
    pub merchant_id: Option<String>,
    /// Customer email associated with the token (redacted in `Debug` and `Display`).
    pub email: Option<String>,
    /// Reusable card token string (redacted in `Debug` and `Display`).
    pub token: String,
    /// Scrubbed JSON representation with sensitive keys replaced by `"[REDACTED]"`.
    pub raw_redacted: Value,
}

impl fmt::Debug for CardTokenCallbackData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardTokenCallbackData")
            .field("id", &self.id)
            .field("order_id", &self.order_id)
            .field("masked_pan", &self.masked_pan)
            .field("card_subtype", &self.card_subtype)
            .field("created_at", &self.created_at)
            .field("merchant_id", &self.merchant_id)
            .field("email", &self.email.as_ref().map(|_| REDACTED))
            .field("token", &REDACTED)
            .field("raw_redacted", &self.raw_redacted)
            .finish()
    }
}

impl fmt::Display for CardTokenCallbackData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CardTokenCallbackData(order_id={:?}, card_subtype={:?}, masked_pan={:?}, token={REDACTED})",
            self.order_id, self.card_subtype, self.masked_pan
        )
    }
}

/// Verified and normalized Paymob Subscription callback payload (`HMAC 3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubscriptionCallbackData {
    /// Subscription lifecycle trigger (for example `"suspended"` or `"resumed"`).
    pub trigger_type: String,
    /// Paymob subscription identifier serialized as a string.
    pub subscription_id: String,
    /// Optional Paymob subscription plan identifier.
    pub plan_id: Option<String>,
    /// Optional subscription state string from `subscription_data.state`.
    pub state: Option<String>,
    /// Scrubbed JSON representation with sensitive keys replaced by `"[REDACTED]"`.
    pub raw_redacted: Value,
}

/// Verified callback event emitted by [`dispatch_and_verify_paymob_callback`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchedPaymobCallback {
    /// Transaction callback (verified via `HMAC 1`), tagged with [`CallbackAuthority`].
    Transaction(TransactionCallbackData),
    /// Saved-card `TOKEN` callback (verified via `HMAC 2`).
    CardToken(CardTokenCallbackData),
    /// Subscription lifecycle callback (verified via `HMAC 3` using body `hmac` only).
    Subscription(SubscriptionCallbackData),
}

impl DispatchedPaymobCallback {
    /// Returns the [`CallbackAuthority`] of this dispatched callback.
    #[must_use]
    pub const fn authority(&self) -> CallbackAuthority {
        match self {
            Self::Transaction(tx) => tx.authority,
            Self::CardToken(_) | Self::Subscription(_) => {
                CallbackAuthority::AuthoritativePostWebhook
            }
        }
    }

    /// Returns the scrubbed JSON payload with all sensitive keys redacted (`TM-4`).
    #[must_use]
    pub const fn raw_redacted(&self) -> &Value {
        match self {
            Self::Transaction(tx) => &tx.raw_redacted,
            Self::CardToken(token) => &token.raw_redacted,
            Self::Subscription(sub) => &sub.raw_redacted,
        }
    }
}

/// Errors returned by [`dispatch_and_verify_paymob_callback`].
///
/// Neither `Display` nor `Debug` ever exposes `hmac_secret`, raw card tokens,
/// or expected HMAC digests (`TM-4`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CallbackDispatchError {
    /// Constant-time HMAC verification failed or the verifier rejected the payload structure.
    #[error("callback HMAC verification failed: {0}")]
    VerificationFailed(#[from] TripleHmacError),
    /// Required `?hmac=` query parameter was missing or empty for a GET/Transaction/TOKEN callback.
    #[error("missing required query parameter `hmac`")]
    MissingQueryHmac,
    /// A `POST` callback did not include a JSON body.
    #[error("missing JSON body for POST callback")]
    MissingPostBody,
    /// Structural error in the callback payload.
    #[error("invalid callback payload: {0}")]
    InvalidPayload(&'static str),
    /// Unknown or unrecognized Paymob callback type rejected fail-closed (`TM-1`).
    #[error("unsupported or unrecognized Paymob callback type")]
    UnsupportedCallbackType,
}

/// Recursively scrubs sensitive JSON keys (`token`, `hmac`, `email`, `phone_number`, `pan`)
/// by replacing their values with `"[REDACTED]"` (`TM-4`).
///
/// Matching is case-insensitive on the final dot-separated segment so nested keys
/// (such as `"pan"`) and flattened GET keys (such as `"source_data.pan"`) are both redacted.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use some_paymob::alignment::callback_dispatcher::raw_redacted;
///
/// let input = json!({
///     "hmac": "deadbeef",
///     "obj": {
///         "token": "tok_secret_123",
///         "email": "buyer@example.com",
///         "phone_number": "+201001234567",
///         "pan": "2346",
///         "masked_pan": "xxxx-xxxx-xxxx-2346"
///     }
/// });
/// let scrubbed = raw_redacted(&input);
/// assert_eq!(scrubbed["hmac"], "[REDACTED]");
/// assert_eq!(scrubbed["obj"]["token"], "[REDACTED]");
/// assert_eq!(scrubbed["obj"]["email"], "[REDACTED]");
/// assert_eq!(scrubbed["obj"]["phone_number"], "[REDACTED]");
/// assert_eq!(scrubbed["obj"]["pan"], "[REDACTED]");
/// assert_eq!(scrubbed["obj"]["masked_pan"], "xxxx-xxxx-xxxx-2346");
/// ```
#[must_use]
pub fn raw_redacted(payload: &Value) -> Value {
    match payload {
        Value::Object(map) => Value::Object(redact_object(map)),
        Value::Array(items) => Value::Array(items.iter().map(raw_redacted).collect()),
        other => other.clone(),
    }
}

/// Dispatches and cryptographically verifies an incoming Paymob callback on a shared
/// `notification_url` using constant-time `HMAC-SHA512`.
///
/// # Routing Matrix
///
/// - `GET` query parameters -> `HMAC 1` ([`verify_tx_get_hmac`]) against `?hmac=`, tagged
///   [`CallbackAuthority::CustomerGetReturn`] (`TM-3`).
/// - `POST` JSON with `type == "TOKEN"` -> `HMAC 2` ([`verify_token_hmac`]) against `?hmac=`,
///   returned as [`DispatchedPaymobCallback::CardToken`] (`TM-4`).
/// - `POST` JSON with `trigger_type` + `subscription_data` -> `HMAC 3`
///   ([`verify_subscription_hmac`]) strictly against JSON body `hmac` (ignoring `?hmac=`, `TM-6`),
///   returned as [`DispatchedPaymobCallback::Subscription`].
/// - `POST` JSON with `type == "TRANSACTION"` (or transaction `obj`) -> `HMAC 1`
///   ([`verify_tx_hmac`]) against `?hmac=`, tagged [`CallbackAuthority::AuthoritativePostWebhook`],
///   returned as [`DispatchedPaymobCallback::Transaction`].
/// - Any unknown or ambiguous payload -> fails closed with
///   [`CallbackDispatchError::UnsupportedCallbackType`] (`TM-1`).
///
/// # Errors
///
/// Returns [`CallbackDispatchError`] if the callback type is unsupported, required inputs
/// (`?hmac=` or `POST` body) are missing, the payload is malformed, or constant-time
/// `HMAC-SHA512` verification fails.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use some_paymob::alignment::callback_dispatcher::{
///     CallbackAuthority, DispatchedPaymobCallback, PaymobCallbackInput,
///     dispatch_and_verify_paymob_callback,
/// };
/// use some_paymob::alignment::triple_hmac::compute_hmac_sha512_hex;
///
/// let sig = compute_hmac_sha512_hex("suspendedfor1264", "secret-key");
/// let body = json!({
///     "trigger_type": "suspended",
///     "subscription_data": { "id": 1264, "state": "suspended" },
///     "hmac": sig
/// });
/// let input = PaymobCallbackInput::post_without_query(body);
/// let dispatched = dispatch_and_verify_paymob_callback(&input, "secret-key")
///     .expect("valid subscription callback");
/// assert_eq!(dispatched.authority(), CallbackAuthority::AuthoritativePostWebhook);
/// assert!(matches!(dispatched, DispatchedPaymobCallback::Subscription(_)));
/// ```
pub fn dispatch_and_verify_paymob_callback(
    input: &PaymobCallbackInput,
    hmac_secret: &str,
) -> Result<DispatchedPaymobCallback, CallbackDispatchError> {
    match input.method {
        PaymobCallbackMethod::Get => dispatch_get_transaction(input, hmac_secret),
        PaymobCallbackMethod::Post => dispatch_post_callback(input, hmac_secret),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PostCallbackKind {
    CardToken,
    Subscription,
    Transaction,
}

fn dispatch_get_transaction(
    input: &PaymobCallbackInput,
    hmac_secret: &str,
) -> Result<DispatchedPaymobCallback, CallbackDispatchError> {
    let query_hmac = require_query_hmac(&input.query_params)?;
    verify_tx_get_hmac(&input.query_params, query_hmac, hmac_secret)?;
    Ok(DispatchedPaymobCallback::Transaction(
        extract_get_transaction_data(&input.query_params),
    ))
}

fn dispatch_post_callback(
    input: &PaymobCallbackInput,
    hmac_secret: &str,
) -> Result<DispatchedPaymobCallback, CallbackDispatchError> {
    let body = input
        .body
        .as_ref()
        .ok_or(CallbackDispatchError::MissingPostBody)?;
    if !body.is_object() {
        return Err(CallbackDispatchError::InvalidPayload(
            "expected JSON object for POST callback body",
        ));
    }
    match classify_post_payload(body)? {
        PostCallbackKind::CardToken => dispatch_post_token(input, body, hmac_secret),
        PostCallbackKind::Subscription => dispatch_post_subscription(body, hmac_secret),
        PostCallbackKind::Transaction => dispatch_post_transaction(input, body, hmac_secret),
    }
}

fn dispatch_post_token(
    input: &PaymobCallbackInput,
    body: &Value,
    hmac_secret: &str,
) -> Result<DispatchedPaymobCallback, CallbackDispatchError> {
    let query_hmac = require_query_hmac(&input.query_params)?;
    verify_token_hmac(body, query_hmac, hmac_secret)?;
    Ok(DispatchedPaymobCallback::CardToken(
        extract_card_token_data(body)?,
    ))
}

fn dispatch_post_subscription(
    body: &Value,
    hmac_secret: &str,
) -> Result<DispatchedPaymobCallback, CallbackDispatchError> {
    verify_subscription_hmac(body, hmac_secret)?;
    Ok(DispatchedPaymobCallback::Subscription(
        extract_subscription_data(body)?,
    ))
}

fn dispatch_post_transaction(
    input: &PaymobCallbackInput,
    body: &Value,
    hmac_secret: &str,
) -> Result<DispatchedPaymobCallback, CallbackDispatchError> {
    let query_hmac = require_query_hmac(&input.query_params)?;
    verify_tx_hmac(body, query_hmac, hmac_secret)?;
    Ok(DispatchedPaymobCallback::Transaction(
        extract_post_transaction_data(body),
    ))
}

fn classify_post_payload(body: &Value) -> Result<PostCallbackKind, CallbackDispatchError> {
    if let Some(kind) = body.get("type").and_then(Value::as_str) {
        return classify_explicit_type(kind);
    }
    if is_subscription_payload(body) {
        return Ok(PostCallbackKind::Subscription);
    }
    if body.get("obj").is_some_and(is_transaction_obj) {
        return Ok(PostCallbackKind::Transaction);
    }
    Err(CallbackDispatchError::UnsupportedCallbackType)
}

fn classify_explicit_type(kind: &str) -> Result<PostCallbackKind, CallbackDispatchError> {
    match kind {
        "TOKEN" => Ok(PostCallbackKind::CardToken),
        "TRANSACTION" => Ok(PostCallbackKind::Transaction),
        _ => Err(CallbackDispatchError::UnsupportedCallbackType),
    }
}

fn is_subscription_payload(body: &Value) -> bool {
    body.get("trigger_type").is_some() && body.get("subscription_data").is_some()
}

fn is_transaction_obj(obj: &Value) -> bool {
    obj.is_object()
        && obj.get("amount_cents").is_some()
        && obj.get("currency").is_some()
        && obj.get("token").is_none()
}

fn require_query_hmac(
    query_params: &BTreeMap<String, String>,
) -> Result<&str, CallbackDispatchError> {
    query_params
        .get("hmac")
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(CallbackDispatchError::MissingQueryHmac)
}

fn collect_query_params<K, V, I>(query_params: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (K, V)>,
    K: Into<String>,
    V: Into<String>,
{
    query_params
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
}

fn redact_object(map: &Map<String, Value>) -> Map<String, Value> {
    map.iter()
        .map(|(key, val)| (key.clone(), redact_entry(key, val)))
        .collect()
}

fn redact_entry(key: &str, val: &Value) -> Value {
    if is_sensitive_key(key) {
        Value::String(REDACTED.to_owned())
    } else {
        raw_redacted(val)
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let leaf = key.rsplit('.').next().unwrap_or(key);
    SENSITIVE_KEYS
        .iter()
        .any(|sensitive| leaf.eq_ignore_ascii_case(sensitive))
}

fn json_value_as_string(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn parse_query_bool(params: &BTreeMap<String, String>, key: &str) -> Option<bool> {
    match params.get(key).map(String::as_str) {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    }
}

fn query_params_to_json(params: &BTreeMap<String, String>) -> Value {
    let map: Map<String, Value> = params
        .iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect();
    Value::Object(map)
}

fn extract_get_transaction_data(query_params: &BTreeMap<String, String>) -> TransactionCallbackData {
    TransactionCallbackData {
        authority: CallbackAuthority::CustomerGetReturn,
        transaction_id: query_params.get("id").cloned(),
        order_id: query_params.get("order").cloned(),
        amount_cents: query_params
            .get("amount_cents")
            .and_then(|v| v.parse::<i64>().ok()),
        currency: query_params.get("currency").cloned(),
        success: parse_query_bool(query_params, "success"),
        pending: parse_query_bool(query_params, "pending"),
        is_auth: parse_query_bool(query_params, "is_auth"),
        is_capture: parse_query_bool(query_params, "is_capture"),
        is_voided: parse_query_bool(query_params, "is_voided"),
        is_refunded: parse_query_bool(query_params, "is_refunded"),
        error_occured: parse_query_bool(query_params, "error_occured"),
        integration_id: query_params.get("integration_id").cloned(),
        source_type: query_params.get("source_data.type").cloned(),
        source_sub_type: query_params.get("source_data.sub_type").cloned(),
        raw_redacted: raw_redacted(&query_params_to_json(query_params)),
    }
}

fn extract_post_transaction_data(body: &Value) -> TransactionCallbackData {
    let obj = body.get("obj").unwrap_or(body);
    let source = obj.get("source_data");
    TransactionCallbackData {
        authority: CallbackAuthority::AuthoritativePostWebhook,
        transaction_id: json_value_as_string(obj.get("id")),
        order_id: obj
            .get("order")
            .and_then(|order| json_value_as_string(order.get("id"))),
        amount_cents: obj.get("amount_cents").and_then(Value::as_i64),
        currency: json_value_as_string(obj.get("currency")),
        success: obj.get("success").and_then(Value::as_bool),
        pending: obj.get("pending").and_then(Value::as_bool),
        is_auth: obj.get("is_auth").and_then(Value::as_bool),
        is_capture: obj.get("is_capture").and_then(Value::as_bool),
        is_voided: obj.get("is_voided").and_then(Value::as_bool),
        is_refunded: obj.get("is_refunded").and_then(Value::as_bool),
        error_occured: obj.get("error_occured").and_then(Value::as_bool),
        integration_id: json_value_as_string(obj.get("integration_id")),
        source_type: source.and_then(|s| json_value_as_string(s.get("type"))),
        source_sub_type: source.and_then(|s| json_value_as_string(s.get("sub_type"))),
        raw_redacted: raw_redacted(body),
    }
}

fn extract_card_token_data(body: &Value) -> Result<CardTokenCallbackData, CallbackDispatchError> {
    let obj = body.get("obj").unwrap_or(body);
    let token = json_value_as_string(obj.get("token"))
        .filter(|s| !s.is_empty())
        .ok_or(CallbackDispatchError::InvalidPayload(
            "missing card token in TOKEN callback",
        ))?;
    Ok(CardTokenCallbackData {
        id: json_value_as_string(obj.get("id")),
        order_id: json_value_as_string(obj.get("order_id")),
        masked_pan: json_value_as_string(obj.get("masked_pan")),
        card_subtype: json_value_as_string(obj.get("card_subtype")),
        created_at: json_value_as_string(obj.get("created_at")),
        merchant_id: json_value_as_string(obj.get("merchant_id")),
        email: json_value_as_string(obj.get("email")),
        token,
        raw_redacted: raw_redacted(body),
    })
}

fn extract_subscription_data(
    body: &Value,
) -> Result<SubscriptionCallbackData, CallbackDispatchError> {
    let trigger_type = body
        .get("trigger_type")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or(CallbackDispatchError::InvalidPayload(
            "missing subscription trigger_type",
        ))?;
    let sub_obj = body.get("subscription_data");
    let subscription_id = sub_obj
        .and_then(|s| json_value_as_string(s.get("id")))
        .or_else(|| json_value_as_string(body.get("subscription_id")))
        .filter(|s| !s.is_empty())
        .ok_or(CallbackDispatchError::InvalidPayload(
            "missing subscription identifier",
        ))?;
    Ok(SubscriptionCallbackData {
        trigger_type,
        subscription_id,
        plan_id: sub_obj.and_then(|s| json_value_as_string(s.get("plan_id"))),
        state: sub_obj.and_then(|s| json_value_as_string(s.get("state"))),
        raw_redacted: raw_redacted(body),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::alignment::triple_hmac::compute_hmac_sha512_hex;

    const TEST_SECRET: &str = "super_secret_paymob_hmac_key_unit2";

    fn sample_tx_obj() -> Value {
        json!({
            "amount_cents": 25000,
            "created_at": "2026-11-22T14:30:00.123456",
            "currency": "EGP",
            "error_occured": false,
            "has_parent_transaction": false,
            "id": 192837465,
            "integration_id": 543210,
            "is_3d_secure": true,
            "is_auth": false,
            "is_capture": false,
            "is_refunded": false,
            "is_standalone_payment": true,
            "is_voided": false,
            "order": { "id": 987654321 },
            "owner": 112233,
            "pending": false,
            "source_data": {
                "pan": "2346",
                "sub_type": "MasterCard",
                "type": "card"
            },
            "success": true
        })
    }

    fn sample_tx_canonical() -> &'static str {
        concat!(
            "25000",
            "2026-11-22T14:30:00.123456",
            "EGP",
            "false",
            "false",
            "192837465",
            "543210",
            "true",
            "false",
            "false",
            "false",
            "true",
            "false",
            "987654321",
            "112233",
            "false",
            "2346",
            "MasterCard",
            "card",
            "true"
        )
    }

    fn sample_tx_get_params(hmac_sig: &str) -> Vec<(&'static str, String)> {
        vec![
            ("amount_cents", "25000".to_owned()),
            ("created_at", "2026-11-22T14:30:00.123456".to_owned()),
            ("currency", "EGP".to_owned()),
            ("error_occured", "false".to_owned()),
            ("has_parent_transaction", "false".to_owned()),
            ("id", "192837465".to_owned()),
            ("integration_id", "543210".to_owned()),
            ("is_3d_secure", "true".to_owned()),
            ("is_auth", "false".to_owned()),
            ("is_capture", "false".to_owned()),
            ("is_refunded", "false".to_owned()),
            ("is_standalone_payment", "true".to_owned()),
            ("is_voided", "false".to_owned()),
            ("order", "987654321".to_owned()),
            ("owner", "112233".to_owned()),
            ("pending", "false".to_owned()),
            ("source_data.pan", "2346".to_owned()),
            ("source_data.sub_type", "MasterCard".to_owned()),
            ("source_data.type", "card".to_owned()),
            ("success", "true".to_owned()),
            ("hmac", hmac_sig.to_owned()),
        ]
    }

    fn sample_token_payload() -> (Value, String) {
        let payload = json!({
            "type": "TOKEN",
            "obj": {
                "card_subtype": "Visa",
                "created_at": "2026-11-22T15:00:00",
                "email": "sensitive-buyer@example.com",
                "id": 4242,
                "masked_pan": "xxxx-xxxx-xxxx-4242",
                "merchant_id": 1001,
                "order_id": "ORD-77",
                "token": "tok_live_ultra_secret_999"
            }
        });
        let canonical = concat!(
            "Visa",
            "2026-11-22T15:00:00",
            "sensitive-buyer@example.com",
            "4242",
            "xxxx-xxxx-xxxx-4242",
            "1001",
            "ORD-77",
            "tok_live_ultra_secret_999"
        );
        let sig = compute_hmac_sha512_hex(canonical, TEST_SECRET);
        (payload, sig)
    }

    #[test]
    fn dispatches_post_transaction_as_authoritative_webhook() {
        let sig = compute_hmac_sha512_hex(sample_tx_canonical(), TEST_SECRET);
        let envelope = json!({ "type": "TRANSACTION", "obj": sample_tx_obj() });
        let input = PaymobCallbackInput::post([("hmac", sig.as_str())], envelope);
        let dispatched = dispatch_and_verify_paymob_callback(&input, TEST_SECRET)
            .expect("valid POST transaction webhook");

        assert_eq!(
            dispatched.authority(),
            CallbackAuthority::AuthoritativePostWebhook
        );
        assert!(dispatched.authority().is_authoritative());
        let DispatchedPaymobCallback::Transaction(tx) = dispatched else {
            panic!("expected Transaction variant");
        };
        assert_eq!(tx.transaction_id.as_deref(), Some("192837465"));
        assert_eq!(tx.order_id.as_deref(), Some("987654321"));
        assert_eq!(tx.amount_cents, Some(25000));
        assert_eq!(tx.currency.as_deref(), Some("EGP"));
        assert_eq!(tx.success, Some(true));
        assert_eq!(tx.source_sub_type.as_deref(), Some("MasterCard"));
        assert_eq!(tx.raw_redacted["obj"]["source_data"]["pan"], "[REDACTED]");

        let untyped_obj = json!({ "obj": sample_tx_obj() });
        let untyped_input = PaymobCallbackInput::post([("hmac", sig.as_str())], untyped_obj);
        let untyped_dispatched = dispatch_and_verify_paymob_callback(&untyped_input, TEST_SECRET)
            .expect("valid untyped POST transaction obj");
        assert!(matches!(
            untyped_dispatched,
            DispatchedPaymobCallback::Transaction(_)
        ));
    }

    #[test]
    fn dispatches_get_return_as_non_authoritative_customer_redirect() {
        let sig = compute_hmac_sha512_hex(sample_tx_canonical(), TEST_SECRET);
        let input = PaymobCallbackInput::get(sample_tx_get_params(&sig));
        let dispatched = dispatch_and_verify_paymob_callback(&input, TEST_SECRET)
            .expect("valid GET return callback");

        assert_eq!(dispatched.authority(), CallbackAuthority::CustomerGetReturn);
        assert!(!dispatched.authority().is_authoritative());
        let DispatchedPaymobCallback::Transaction(tx) = dispatched else {
            panic!("expected Transaction variant");
        };
        assert_eq!(tx.transaction_id.as_deref(), Some("192837465"));
        assert_eq!(tx.order_id.as_deref(), Some("987654321"));
        assert_eq!(tx.raw_redacted["hmac"], "[REDACTED]");
        assert_eq!(tx.raw_redacted["source_data.pan"], "[REDACTED]");
    }

    #[test]
    fn dispatches_post_token_callback_with_redacted_debug_and_display() {
        let (payload, sig) = sample_token_payload();
        let input = PaymobCallbackInput::post([("hmac", sig.as_str())], payload);
        let dispatched = dispatch_and_verify_paymob_callback(&input, TEST_SECRET)
            .expect("valid POST TOKEN callback");

        assert_eq!(
            dispatched.authority(),
            CallbackAuthority::AuthoritativePostWebhook
        );
        let DispatchedPaymobCallback::CardToken(card) = dispatched else {
            panic!("expected CardToken variant");
        };
        assert_eq!(card.masked_pan.as_deref(), Some("xxxx-xxxx-xxxx-4242"));
        assert_eq!(card.card_subtype.as_deref(), Some("Visa"));
        assert_eq!(card.order_id.as_deref(), Some("ORD-77"));
        assert_eq!(card.token, "tok_live_ultra_secret_999");

        let debug_str = format!("{card:?}");
        let display_str = format!("{card}");
        assert!(!debug_str.contains("tok_live_ultra_secret_999"));
        assert!(!debug_str.contains("sensitive-buyer@example.com"));
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!display_str.contains("tok_live_ultra_secret_999"));
        assert!(!display_str.contains("sensitive-buyer@example.com"));
        assert!(display_str.contains("[REDACTED]"));
        assert_eq!(card.raw_redacted["obj"]["token"], "[REDACTED]");
        assert_eq!(card.raw_redacted["obj"]["email"], "[REDACTED]");
    }

    #[test]
    fn dispatches_post_subscription_using_body_hmac_and_ignoring_query_hmac() {
        let body_sig = compute_hmac_sha512_hex("suspendedfor1264", TEST_SECRET);
        let body = json!({
            "trigger_type": "suspended",
            "subscription_data": {
                "id": 1264,
                "plan_id": 55,
                "state": "suspended"
            },
            "hmac": body_sig
        });
        let with_bogus_query_hmac =
            PaymobCallbackInput::post([("hmac", "not_even_valid_hex")], body);
        let dispatched = dispatch_and_verify_paymob_callback(&with_bogus_query_hmac, TEST_SECRET)
            .expect("subscription callback must ignore query ?hmac= and verify body hmac");

        let DispatchedPaymobCallback::Subscription(sub) = dispatched else {
            panic!("expected Subscription variant");
        };
        assert_eq!(sub.trigger_type, "suspended");
        assert_eq!(sub.subscription_id, "1264");
        assert_eq!(sub.plan_id.as_deref(), Some("55"));
        assert_eq!(sub.state.as_deref(), Some("suspended"));
        assert_eq!(sub.raw_redacted["hmac"], "[REDACTED]");

        let missing_body_hmac = json!({
            "trigger_type": "suspended",
            "subscription_data": { "id": 1264 }
        });
        let query_only_attempt =
            PaymobCallbackInput::post([("hmac", body_sig.as_str())], missing_body_hmac);
        assert_eq!(
            dispatch_and_verify_paymob_callback(&query_only_attempt, TEST_SECRET),
            Err(CallbackDispatchError::VerificationFailed(
                TripleHmacError::WebhookVerificationFailed
            ))
        );
    }

    #[test]
    fn rejects_unknown_and_unsupported_callback_types_fail_closed() {
        let unknown_typed = json!({ "type": "DELIVERY_STATUS", "obj": { "id": 1 } });
        let input_typed = PaymobCallbackInput::post([("hmac", "00")], unknown_typed);
        assert_eq!(
            dispatch_and_verify_paymob_callback(&input_typed, TEST_SECRET),
            Err(CallbackDispatchError::UnsupportedCallbackType)
        );

        let unknown_untyped = json!({ "event": "mystery", "data": { "foo": "bar" } });
        let input_untyped = PaymobCallbackInput::post([("hmac", "00")], unknown_untyped);
        assert_eq!(
            dispatch_and_verify_paymob_callback(&input_untyped, TEST_SECRET),
            Err(CallbackDispatchError::UnsupportedCallbackType)
        );
    }

    #[test]
    fn rejects_cross_type_forgeries_and_missing_inputs() {
        let tx_sig = compute_hmac_sha512_hex(sample_tx_canonical(), TEST_SECRET);
        let forged_tx_as_token = json!({ "type": "TOKEN", "obj": sample_tx_obj() });
        let input_forged_token =
            PaymobCallbackInput::post([("hmac", tx_sig.as_str())], forged_tx_as_token);
        assert_eq!(
            dispatch_and_verify_paymob_callback(&input_forged_token, TEST_SECRET),
            Err(CallbackDispatchError::VerificationFailed(
                TripleHmacError::WebhookVerificationFailed
            ))
        );

        let (token_payload, token_sig) = sample_token_payload();
        let forged_token_as_tx = json!({
            "type": "TRANSACTION",
            "obj": token_payload["obj"].clone()
        });
        let input_forged_tx =
            PaymobCallbackInput::post([("hmac", token_sig.as_str())], forged_token_as_tx);
        assert_eq!(
            dispatch_and_verify_paymob_callback(&input_forged_tx, TEST_SECRET),
            Err(CallbackDispatchError::VerificationFailed(
                TripleHmacError::WebhookVerificationFailed
            ))
        );

        let missing_query_hmac = PaymobCallbackInput::post_without_query(json!({
            "type": "TRANSACTION",
            "obj": sample_tx_obj()
        }));
        assert_eq!(
            dispatch_and_verify_paymob_callback(&missing_query_hmac, TEST_SECRET),
            Err(CallbackDispatchError::MissingQueryHmac)
        );

        let missing_body = PaymobCallbackInput {
            method: PaymobCallbackMethod::Post,
            query_params: BTreeMap::new(),
            body: None,
        };
        assert_eq!(
            dispatch_and_verify_paymob_callback(&missing_body, TEST_SECRET),
            Err(CallbackDispatchError::MissingPostBody)
        );
    }

    #[test]
    fn redacts_sensitive_fields_in_raw_redacted_debug_and_errors() {
        let raw = json!({
            "hmac": "abcdef0123456789",
            "nested": {
                "token": "tok_secret_value",
                "email": "user@example.com",
                "phone_number": "+201009998877",
                "pan": "4242",
                "safe_field": "kept"
            },
            "items": [
                { "token": "tok_in_array", "label": "ok" }
            ]
        });
        let scrubbed = raw_redacted(&raw);
        let serialized = scrubbed.to_string();
        assert!(!serialized.contains("abcdef0123456789"));
        assert!(!serialized.contains("tok_secret_value"));
        assert!(!serialized.contains("tok_in_array"));
        assert!(!serialized.contains("user@example.com"));
        assert!(!serialized.contains("+201009998877"));
        assert!(!serialized.contains("4242"));
        assert_eq!(scrubbed["nested"]["safe_field"], "kept");
        assert_eq!(scrubbed["items"][0]["token"], "[REDACTED]");
        assert_eq!(scrubbed["items"][0]["label"], "ok");

        let bad_input = PaymobCallbackInput::post(
            [("hmac", &"00".repeat(64))],
            json!({ "type": "TRANSACTION", "obj": sample_tx_obj() }),
        );
        let err = dispatch_and_verify_paymob_callback(&bad_input, TEST_SECRET).unwrap_err();
        let err_debug = format!("{err:?}");
        let err_display = format!("{err}");
        let input_debug = format!("{bad_input:?}");
        assert!(!err_debug.contains(TEST_SECRET));
        assert!(!err_display.contains(TEST_SECRET));
        assert!(!input_debug.contains(&"00".repeat(64)));
    }
}
