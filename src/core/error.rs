#![forbid(unsafe_code)]
//! Error hierarchy, multi-shape Paymob API error parser, and PII/secret redaction.
//!
//! This module defines [`PaymobError`], the canonical error type returned across
//! `some-paymob`, along with [`PaymobError::from_response`] for normalizing Paymob's
//! heterogeneous error payloads (Accept, Intention, Subscription, Refund, and Payouts)
//! and automatic secret/PII redaction in `Display` and `Debug` output.

use std::error::Error;
use std::fmt;

use serde_json::Value;

const REDACTED: &str = "[REDACTED]";

const SECRET_PREFIXES: &[&str] = &[
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "egy_sk_",
    "egy_pk_",
    "sau_sk_",
    "sau_pk_",
    "are_sk_",
    "are_pk_",
    "omn_sk_",
    "omn_pk_",
    "pak_sk_",
    "pak_pk_",
    "eyJ",
];

const SENSITIVE_KEYS: &[&str] = &[
    "api_key",
    "secret_key",
    "client_secret",
    "auth_token",
    "access_token",
    "refresh_token",
    "password",
    "hmac",
    "card_token",
    "secret",
    "phone",
    "phone_number",
    "mobile",
    "pan",
    "card_number",
    "cvv",
    "cvc",
    "token",
];

const KNOWN_FIELDS: &[&str] = &[
    "phone_number",
    "email",
    "first_name",
    "last_name",
    "street",
    "building",
    "floor",
    "apartment",
    "city",
    "state",
    "country",
    "postal_code",
    "billing_data",
    "amount",
    "currency",
    "payment_methods",
    "integration_id",
    "items",
    "special_reference",
    "notification_url",
    "redirection_url",
    "transaction_id",
    "order_id",
    "auth_token",
    "api_key",
    "non_field_errors",
    "detail",
    "message",
];

/// Canonical error type for all `some-paymob` operations.
///
/// Every variant redacts known secret prefixes (`sk_live_`, `pk_test_`, `egy_sk_`,
/// JWT `eyJ...`), bearer/token credentials, sensitive key-value pairs, email
/// addresses, and digit sequences (phone numbers / PANs) in both
/// [`fmt::Display`] and [`fmt::Debug`].
///
/// # Examples
///
/// ```
/// use some_paymob::core::error::PaymobError;
///
/// let err = PaymobError::from_response(
///     401,
///     r#"{"detail": "incorrect credentials"}"#,
///     None,
/// );
/// assert!(matches!(err, PaymobError::AuthenticationError(_)));
/// assert_eq!(err.to_string(), "Authentication failed: incorrect credentials");
/// ```
#[derive(Clone, PartialEq, Eq)]
pub enum PaymobError {
    /// Generic Paymob HTTP API error response.
    ApiError {
        /// HTTP status code returned by the Paymob gateway.
        status: u16,
        /// Human-readable error message extracted from the response body.
        message: String,
        /// Optional Paymob-specific error or status code.
        code: Option<String>,
    },
    /// Authentication or authorization failure (HTTP 401/403 or invalid token).
    AuthenticationError(String),
    /// Mismatch between Test and Live credentials, keys, or integration IDs.
    EnvironmentMismatch(String),
    /// Refund request exceeds the maximum permissible refundable balance.
    RefundExceedsPermissibleAmount {
        /// Gateway explanation of the permissible refund limit failure.
        message: String,
    },
    /// Rate limit exceeded on the Paymob gateway (HTTP 429).
    RateLimited {
        /// Gateway rate-limit message or status description.
        message: String,
        /// Optional `Retry-After` delay in seconds.
        retry_after_secs: Option<u64>,
    },
    /// Webhook signature, HMAC, or payload verification failure.
    WebhookError(String),
    /// Client-side or gateway field-level validation failure.
    ValidationError {
        /// Name of the invalid field.
        field: &'static str,
        /// Reason the field failed validation.
        reason: String,
    },
    /// Underlying HTTP transport, TLS, timeout, or connection failure.
    TransportError(String),
}

impl PaymobError {
    /// Parses a Paymob HTTP error response into a normalized [`PaymobError`].
    ///
    /// Supports Paymob's multi-shape JSON error payloads:
    /// - `{"detail": "..."}` (Accept / Intention / DRF auth & resource errors)
    /// - `{"message": "..."}` (Accept / Refund permissible-limit errors)
    /// - `{"status_description": "...", "status_code": 429}` (Payouts errors)
    /// - Nested field-level validation maps such as
    ///   `{"billing_data": {"phone_number": ["This field is required."]}}`
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::error::PaymobError;
    ///
    /// let body = r#"{"billing_data": {"phone_number": ["This field is required."]}}"#;
    /// let err = PaymobError::from_response(400, body, None);
    /// assert_eq!(
    ///     err,
    ///     PaymobError::ValidationError {
    ///         field: "phone_number",
    ///         reason: "This field is required.".to_string(),
    ///     }
    /// );
    /// ```
    pub fn from_response(status: u16, body: &str, retry_after_secs: Option<u64>) -> Self {
        let Ok(value) = serde_json::from_str::<Value>(body) else {
            return fallback_error(status, body, retry_after_secs);
        };

        if let Some(payout_err) = parse_payouts_error(status, &value, retry_after_secs) {
            return payout_err;
        }
        if let Some(msg) = extract_top_message(&value) {
            return classify_message_error(status, msg, extract_code(&value), retry_after_secs);
        }
        if let Some((field, reason)) = extract_field_error(&value) {
            return Self::ValidationError { field, reason };
        }
        fallback_error(status, body, retry_after_secs)
    }

    /// Returns `true` if the error represents a transient failure that can be retried.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::error::PaymobError;
    ///
    /// let rate_limited = PaymobError::RateLimited {
    ///     message: "Rate limit exceeded".to_string(),
    ///     retry_after_secs: Some(5),
    /// };
    /// assert!(rate_limited.is_retryable());
    /// ```
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimited { .. } | Self::TransportError(_) => true,
            Self::ApiError { status, .. } => matches!(status, 502 | 503 | 504),
            _ => false,
        }
    }

    /// Returns the associated HTTP status code if the error originated from an HTTP response.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::error::PaymobError;
    ///
    /// let body = r#"{"status_description": "Rate limit exceeded", "status_code": 429}"#;
    /// let err = PaymobError::from_response(429, body, Some(2));
    /// assert_eq!(err.status_code(), Some(429));
    /// ```
    pub fn status_code(&self) -> Option<u16> {
        match self {
            Self::ApiError { status, .. } => Some(*status),
            Self::RateLimited { .. } => Some(429),
            _ => None,
        }
    }
}

impl PaymobError {
    fn is_transport_variant(&self) -> bool {
        matches!(
            self,
            Self::ApiError { .. }
                | Self::RateLimited { .. }
                | Self::WebhookError(_)
                | Self::TransportError(_)
        )
    }

    fn fmt_display_transport(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiError {
                status,
                message,
                code,
            } => fmt_api_error_display(f, *status, message, code.as_deref()),
            Self::RateLimited {
                message,
                retry_after_secs,
            } => fmt_rate_limited_display(f, message, *retry_after_secs),
            Self::WebhookError(msg) => {
                write!(f, "Webhook verification error: {}", redact_sensitive(msg))
            }
            Self::TransportError(msg) => {
                write!(f, "HTTP transport error: {}", redact_sensitive(msg))
            }
            _ => Ok(()),
        }
    }

    fn fmt_display_domain(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationError(msg) => {
                write!(f, "Authentication failed: {}", redact_sensitive(msg))
            }
            Self::EnvironmentMismatch(msg) => write!(
                f,
                "Environment mismatch between Test and Live credentials or integration IDs: {}",
                redact_sensitive(msg)
            ),
            Self::RefundExceedsPermissibleAmount { message } => write!(
                f,
                "Refund amount exceeds maximum permissible balance: {}",
                redact_sensitive(message)
            ),
            Self::ValidationError { field, reason } => write!(
                f,
                "Validation error on field `{field}`: {}",
                redact_sensitive(reason)
            ),
            _ => Ok(()),
        }
    }

    fn fmt_debug_transport(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApiError {
                status,
                message,
                code,
            } => f
                .debug_struct("ApiError")
                .field("status", status)
                .field("message", &redact_sensitive(message))
                .field("code", &code.as_deref().map(redact_sensitive))
                .finish(),
            Self::RateLimited {
                message,
                retry_after_secs,
            } => f
                .debug_struct("RateLimited")
                .field("message", &redact_sensitive(message))
                .field("retry_after_secs", retry_after_secs)
                .finish(),
            Self::WebhookError(msg) => f
                .debug_tuple("WebhookError")
                .field(&redact_sensitive(msg))
                .finish(),
            Self::TransportError(msg) => f
                .debug_tuple("TransportError")
                .field(&redact_sensitive(msg))
                .finish(),
            _ => Ok(()),
        }
    }

    fn fmt_debug_domain(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationError(msg) => f
                .debug_tuple("AuthenticationError")
                .field(&redact_sensitive(msg))
                .finish(),
            Self::EnvironmentMismatch(msg) => f
                .debug_tuple("EnvironmentMismatch")
                .field(&redact_sensitive(msg))
                .finish(),
            Self::RefundExceedsPermissibleAmount { message } => f
                .debug_struct("RefundExceedsPermissibleAmount")
                .field("message", &redact_sensitive(message))
                .finish(),
            Self::ValidationError { field, reason } => f
                .debug_struct("ValidationError")
                .field("field", field)
                .field("reason", &redact_sensitive(reason))
                .finish(),
            _ => Ok(()),
        }
    }
}

impl fmt::Display for PaymobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_transport_variant() {
            self.fmt_display_transport(f)
        } else {
            self.fmt_display_domain(f)
        }
    }
}

impl fmt::Debug for PaymobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_transport_variant() {
            self.fmt_debug_transport(f)
        } else {
            self.fmt_debug_domain(f)
        }
    }
}

impl Error for PaymobError {}

fn fmt_api_error_display(
    f: &mut fmt::Formatter<'_>,
    status: u16,
    message: &str,
    code: Option<&str>,
) -> fmt::Result {
    write!(
        f,
        "Paymob API error (HTTP {status}): {}",
        redact_sensitive(message)
    )?;
    if let Some(c) = code {
        write!(f, " [code: {}]", redact_sensitive(c))?;
    }
    Ok(())
}

fn fmt_rate_limited_display(
    f: &mut fmt::Formatter<'_>,
    message: &str,
    retry_after_secs: Option<u64>,
) -> fmt::Result {
    write!(
        f,
        "Rate limited by Paymob gateway (HTTP 429): {}",
        redact_sensitive(message)
    )?;
    if let Some(secs) = retry_after_secs {
        write!(f, " (retry after {secs}s)")?;
    }
    Ok(())
}

fn parse_payouts_error(
    status: u16,
    value: &Value,
    retry_after_secs: Option<u64>,
) -> Option<PaymobError> {
    let desc = value.get("status_description")?.as_str()?.trim();
    if desc.is_empty() {
        return None;
    }
    let code_num = value.get("status_code").and_then(Value::as_u64);
    if status == 429 || code_num == Some(429) {
        return Some(PaymobError::RateLimited {
            message: desc.to_string(),
            retry_after_secs,
        });
    }
    let code = value.get("status_code").map(format_json_scalar);
    Some(classify_message_error(
        status,
        desc.to_string(),
        code,
        retry_after_secs,
    ))
}

fn extract_top_message(value: &Value) -> Option<String> {
    ["detail", "message"]
        .into_iter()
        .filter_map(|key| value.get(key).and_then(Value::as_str))
        .map(str::trim)
        .find(|s| !s.is_empty())
        .map(str::to_string)
}

fn extract_code(value: &Value) -> Option<String> {
    ["code", "error_code", "status_code"]
        .into_iter()
        .find_map(|key| value.get(key))
        .map(format_json_scalar)
        .filter(|s| !s.is_empty())
}

fn format_json_scalar(value: &Value) -> String {
    match value {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    }
}

fn classify_message_error(
    status: u16,
    message: String,
    code: Option<String>,
    retry_after_secs: Option<u64>,
) -> PaymobError {
    if status == 429 {
        return PaymobError::RateLimited {
            message,
            retry_after_secs,
        };
    }
    if is_refund_permissible_error(&message) {
        return PaymobError::RefundExceedsPermissibleAmount { message };
    }
    if matches!(status, 401 | 403) {
        return PaymobError::AuthenticationError(message);
    }
    PaymobError::ApiError {
        status,
        message,
        code,
    }
}

fn is_refund_permissible_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("refund")
        && (lower.contains("permissible")
            || lower.contains("maximum refund")
            || lower.contains("exceeds"))
}

fn extract_field_error(value: &Value) -> Option<(&'static str, String)> {
    let Value::Object(_) = value else {
        return None;
    };
    let (raw_key, msg) = flatten_first_leaf(None, value)?;
    let field = resolve_static_field(&raw_key);
    let reason = if field == "payload" && raw_key != "payload" {
        format!("{raw_key}: {msg}")
    } else {
        msg
    };
    Some((field, reason))
}

fn flatten_first_leaf(key_hint: Option<&str>, value: &Value) -> Option<(String, String)> {
    match value {
        Value::Object(map) => map
            .iter()
            .find_map(|(k, v)| flatten_first_leaf(Some(k), v)),
        Value::Array(items) => items
            .iter()
            .find_map(|item| flatten_first_leaf(key_hint, item)),
        Value::String(s) => non_empty_pair(key_hint, s),
        _ => None,
    }
}

fn non_empty_pair(key_hint: Option<&str>, msg: &str) -> Option<(String, String)> {
    let trimmed = msg.trim();
    if trimmed.is_empty() {
        return None;
    }
    let key = key_hint.unwrap_or("payload").to_string();
    Some((key, trimmed.to_string()))
}

fn resolve_static_field(key: &str) -> &'static str {
    KNOWN_FIELDS
        .iter()
        .copied()
        .find(|&known| known == key)
        .unwrap_or("payload")
}

fn fallback_error(status: u16, body: &str, retry_after_secs: Option<u64>) -> PaymobError {
    let trimmed = body.trim();
    let message = if trimmed.is_empty() {
        format!("HTTP {status} error with empty response body")
    } else {
        trimmed.to_string()
    };
    classify_message_error(status, message, None, retry_after_secs)
}

fn redact_sensitive(input: &str) -> String {
    let pre_scrubbed = redact_spaced_digit_runs(input);
    let mut out = String::with_capacity(pre_scrubbed.len());
    let mut prev_auth = false;
    let mut rest = pre_scrubbed.as_str();

    while !rest.is_empty() {
        let ws_len = rest.bytes().take_while(u8::is_ascii_whitespace).count();
        out.push_str(&rest[..ws_len]);
        rest = &rest[ws_len..];

        let word_len = rest.bytes().take_while(|b| !b.is_ascii_whitespace()).count();
        if word_len == 0 {
            break;
        }
        let word = &rest[..word_len];
        rest = &rest[word_len..];
        out.push_str(&redact_word(word, prev_auth));
        prev_auth = is_auth_scheme(word);
    }
    out
}

fn redact_spaced_digit_runs(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    while i < bytes.len() {
        if let Some(end) = try_consume_long_digit_run(bytes, i) {
            out.push_str(REDACTED);
            i = end;
            continue;
        }
        let ch = input[i..].chars().next().unwrap_or_default();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn try_consume_long_digit_run(bytes: &[u8], start: usize) -> Option<usize> {
    if !is_digit_run_start(bytes, start) {
        return None;
    }
    let (end, digits) = scan_digit_run(bytes, start);
    (digits >= 10).then_some(end)
}

fn is_digit_run_start(bytes: &[u8], i: usize) -> bool {
    if i > 0 && bytes[i - 1].is_ascii_alphanumeric() {
        return false;
    }
    bytes[i].is_ascii_digit()
        || (bytes[i] == b'+' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit))
}

fn scan_digit_run(bytes: &[u8], start: usize) -> (usize, usize) {
    let mut i = start;
    let mut digits = 0usize;
    let mut last_digit_end = start;
    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_digit() {
            digits += 1;
            last_digit_end = i + 1;
        } else if !matches!(b, b' ' | b'-' | b'+') {
            break;
        }
        i += 1;
    }
    (last_digit_end, digits)
}

fn redact_word(word: &str, prev_auth: bool) -> String {
    let (lead, core, trail) = split_punctuation(word);
    if core.is_empty() {
        return word.to_string();
    }
    if prev_auth || is_secret_token(core) {
        return format!("{lead}{REDACTED}{trail}");
    }
    if let Some(redacted_kv) = redact_sensitive_kv(core) {
        return format!("{lead}{redacted_kv}{trail}");
    }
    word.to_string()
}

fn split_punctuation(word: &str) -> (&str, &str, &str) {
    let lead_trim = word.trim_start_matches(['(', '"', '\'', '{', '[']);
    let lead_len = word.len() - lead_trim.len();
    let core = lead_trim.trim_end_matches([')', '"', '\'', '}', ']', ',', ';', '.']);
    let trail_start = lead_len + core.len();
    (&word[..lead_len], core, &word[trail_start..])
}

fn is_auth_scheme(word: &str) -> bool {
    let (_, core, _) = split_punctuation(word);
    core.eq_ignore_ascii_case("bearer") || core.eq_ignore_ascii_case("token")
}

fn is_secret_token(core: &str) -> bool {
    is_secret_prefix(core) || is_email(core) || is_long_digit_sequence(core)
}

fn is_secret_prefix(core: &str) -> bool {
    SECRET_PREFIXES.iter().any(|prefix| core.starts_with(prefix))
}

fn is_email(core: &str) -> bool {
    let Some((local, domain)) = core.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
}

fn is_long_digit_sequence(core: &str) -> bool {
    let mut digits = 0usize;
    for ch in core.chars() {
        if ch.is_ascii_digit() {
            digits += 1;
        } else if ch != '-' && ch != '+' {
            return false;
        }
    }
    digits >= 10
}

fn redact_sensitive_kv(core: &str) -> Option<String> {
    let (sep_idx, sep_char) = core
        .find('=')
        .map(|i| (i, '='))
        .or_else(|| core.find(':').map(|i| (i, ':')))?;
    let key = &core[..sep_idx];
    let val = &core[sep_idx + 1..];
    if val.is_empty() || !SENSITIVE_KEYS.iter().any(|k| key.eq_ignore_ascii_case(k)) {
        return None;
    }
    Some(format!("{key}{sep_char}{REDACTED}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_no_leaks(output: &str, leaks: &[&str]) {
        assert!(output.contains(REDACTED));
        assert!(leaks.iter().all(|secret| !output.contains(secret)));
    }

    #[test]
    fn tc_1_3_1_detail_401_maps_to_authentication_error() {
        let err = PaymobError::from_response(401, r#"{"detail": "incorrect credentials"}"#, None);
        assert_eq!(
            err,
            PaymobError::AuthenticationError("incorrect credentials".to_string())
        );
        assert_eq!(
            err.to_string(),
            "Authentication failed: incorrect credentials"
        );
    }

    #[test]
    fn tc_1_3_1_authentication_error_metadata() {
        let err = PaymobError::from_response(401, r#"{"detail": "incorrect credentials"}"#, None);
        assert!(!err.is_retryable());
        assert_eq!(err.status_code(), None);
    }

    #[test]
    fn tc_1_3_1_detail_404_maps_to_api_error() {
        let err = PaymobError::from_response(
            404,
            r#"{"detail": "Not found.", "code": "NOT_FOUND"}"#,
            None,
        );
        assert_eq!(
            err,
            PaymobError::ApiError {
                status: 404,
                message: "Not found.".to_string(),
                code: Some("NOT_FOUND".to_string()),
            }
        );
    }

    #[test]
    fn tc_1_3_1_api_error_404_metadata() {
        let err = PaymobError::from_response(404, r#"{"detail": "Not found."}"#, None);
        assert_eq!(err.status_code(), Some(404));
        assert!(!err.is_retryable());
    }

    #[test]
    fn tc_1_3_1_message_refund_permissible_maps_to_refund_variant() {
        let body = r#"{"message": "Requested Refund Amount is greater than the maximum refund amount permissible for this transaction"}"#;
        let err = PaymobError::from_response(400, body, None);
        assert!(matches!(
            err,
            PaymobError::RefundExceedsPermissibleAmount { .. }
        ));
        assert!(err
            .to_string()
            .starts_with("Refund amount exceeds maximum permissible balance:"));
    }

    #[test]
    fn tc_1_3_1_payouts_429_maps_to_rate_limited_with_retry_after() {
        let body = r#"{"status_description": "Rate limit exceeded", "status_code": 429}"#;
        let err = PaymobError::from_response(429, body, Some(15));
        assert_eq!(
            err,
            PaymobError::RateLimited {
                message: "Rate limit exceeded".to_string(),
                retry_after_secs: Some(15),
            }
        );
        assert_eq!(
            err.to_string(),
            "Rate limited by Paymob gateway (HTTP 429): Rate limit exceeded (retry after 15s)"
        );
    }

    #[test]
    fn tc_1_3_1_rate_limited_metadata() {
        let body = r#"{"status_description": "Rate limit exceeded", "status_code": 429}"#;
        let err = PaymobError::from_response(429, body, Some(15));
        assert!(err.is_retryable());
        assert_eq!(err.status_code(), Some(429));
    }

    #[test]
    fn tc_1_3_1_payouts_status_code_429_on_non_429_http_status() {
        let body = r#"{"status_description": "Too many requests", "status_code": 429}"#;
        let err = PaymobError::from_response(200, body, Some(3));
        assert!(matches!(
            err,
            PaymobError::RateLimited {
                retry_after_secs: Some(3),
                ..
            }
        ));
    }

    #[test]
    fn tc_1_3_1_nested_field_error_map_maps_to_validation_error() {
        let body = r#"{"billing_data": {"phone_number": ["This field is required."]}}"#;
        let err = PaymobError::from_response(400, body, None);
        assert_eq!(
            err,
            PaymobError::ValidationError {
                field: "phone_number",
                reason: "This field is required.".to_string(),
            }
        );
        assert_eq!(
            err.to_string(),
            "Validation error on field `phone_number`: This field is required."
        );
    }

    #[test]
    fn tc_1_3_1_unknown_nested_field_falls_back_to_payload_field() {
        let body = r#"{"custom_block": {"unknown_attr": ["Invalid value"]}}"#;
        let err = PaymobError::from_response(422, body, None);
        assert_eq!(
            err,
            PaymobError::ValidationError {
                field: "payload",
                reason: "unknown_attr: Invalid value".to_string(),
            }
        );
    }

    #[test]
    fn tc_1_3_1_malformed_body_503_is_retryable_api_error() {
        let malformed = PaymobError::from_response(503, "Service Unavailable", None);
        assert_eq!(
            malformed,
            PaymobError::ApiError {
                status: 503,
                message: "Service Unavailable".to_string(),
                code: None,
            }
        );
        assert!(malformed.is_retryable());
    }

    #[test]
    fn tc_1_3_1_empty_body_500_fallback() {
        let empty = PaymobError::from_response(500, "   ", None);
        assert_eq!(
            empty,
            PaymobError::ApiError {
                status: 500,
                message: "HTTP 500 error with empty response body".to_string(),
                code: None,
            }
        );
    }

    #[test]
    fn tc_1_3_1_redacts_api_keys_and_jwt_in_display_and_debug() {
        let msg = "sk_live_abc123xyz egy_sk_secret999 Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig";
        let err = PaymobError::AuthenticationError(msg.to_string());
        let leaks = [
            "sk_live_abc123xyz",
            "egy_sk_secret999",
            "eyJhbGciOiJIUzI1NiJ9",
        ];
        assert_no_leaks(&err.to_string(), &leaks);
        assert_no_leaks(&format!("{err:?}"), &leaks);
    }

    #[test]
    fn tc_1_3_1_redacts_kv_pii_and_card_keys() {
        let msg = "phone_number=+201012345678 pan=4111-1111-1111-1111 cvv=123 token=tok_xyz";
        let err = PaymobError::ValidationError {
            field: "payload",
            reason: msg.to_string(),
        };
        assert_no_leaks(
            &err.to_string(),
            &["+201012345678", "4111-1111-1111-1111", "123", "tok_xyz"],
        );
    }

    #[test]
    fn tc_1_3_1_redacts_spaced_pan_and_phone_numbers() {
        let msg = "card 4111 1111 1111 1111 mobile +20 101 234 5678 failed";
        let err = PaymobError::WebhookError(msg.to_string());
        assert_no_leaks(
            &format!("{err:?}"),
            &["4111 1111 1111 1111", "+20 101 234 5678"],
        );
    }

    #[test]
    fn tc_1_3_1_redacts_emails_in_display_and_debug() {
        let err = PaymobError::WebhookError("customer user@example.com rejected".to_string());
        assert_no_leaks(&err.to_string(), &["user@example.com"]);
        assert_no_leaks(&format!("{err:?}"), &["user@example.com"]);
    }

    #[test]
    fn tc_1_3_1_env_mismatch_variant_not_retryable() {
        let env_err = PaymobError::EnvironmentMismatch("Test key with Live ID".to_string());
        assert!(!env_err.is_retryable());
        assert!(format!("{env_err:?}").contains("EnvironmentMismatch"));
    }

    #[test]
    fn tc_1_3_1_webhook_variant_not_retryable() {
        let webhook_err = PaymobError::WebhookError("HMAC mismatch".to_string());
        assert!(!webhook_err.is_retryable());
        assert!(format!("{webhook_err:?}").contains("WebhookError"));
    }

    #[test]
    fn tc_1_3_1_transport_variant_is_retryable() {
        let transport_err = PaymobError::TransportError("connection reset".to_string());
        assert!(transport_err.is_retryable());
        assert_eq!(transport_err.status_code(), None);
    }
}
