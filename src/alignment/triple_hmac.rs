#![forbid(unsafe_code)]
//! US-9.2.0 Unit 1: Constant-time triple `HMAC-SHA512` verifiers for Paymob callbacks.
//!
//! Covers all three Paymob webhook verification protocols required by `US-9.2.0`:
//!
//! 1. **Transaction callback (20-key POST JSON & GET query)** —
//!    [`verify_tx_hmac`](crate::alignment::triple_hmac::verify_tx_hmac) and
//!    [`verify_tx_get_hmac`](crate::alignment::triple_hmac::verify_tx_get_hmac) over
//!    [`TX_HMAC_KEYS`](crate::alignment::triple_hmac::TX_HMAC_KEYS).
//! 2. **Card `TOKEN` callback (8-key POST JSON)** —
//!    [`verify_token_hmac`](crate::alignment::triple_hmac::verify_token_hmac) over
//!    [`TOKEN_HMAC_KEYS`](crate::alignment::triple_hmac::TOKEN_HMAC_KEYS).
//! 3. **Subscription callback (body `hmac` field)** —
//!    [`verify_subscription_hmac`](crate::alignment::triple_hmac::verify_subscription_hmac)
//!    over `"{trigger_type}for{subscription_id}"`, verified strictly against the JSON body
//!    `hmac` field (never `?hmac=`).
//!
//! All comparisons decode the hex digest into bytes without panicking and compare the
//! 64-byte `SHA-512` MAC using [`subtle::ConstantTimeEq::ct_eq`]. Secrets and expected
//! digests are never included in
//! [`TripleHmacError`](crate::alignment::triple_hmac::TripleHmacError) messages or `Debug`
//! output.

use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha512;
use subtle::ConstantTimeEq;
use thiserror::Error;

type HmacSha512 = Hmac<Sha512>;

/// Expected byte length of an `HMAC-SHA512` digest (512 bits = 64 bytes).
const SHA512_DIGEST_LEN: usize = 64;

/// Lexicographically sorted 20-key table for Paymob Transaction callbacks.
///
/// Each tuple maps `(post_json_path, get_query_key)`. Note that Paymob spells
/// `error_occured` with a single `r`, and maps POST `obj.order.id` to GET `order`.
pub const TX_HMAC_KEYS: &[(&str, &str)] = &[
    ("amount_cents", "amount_cents"),
    ("created_at", "created_at"),
    ("currency", "currency"),
    ("error_occured", "error_occured"),
    ("has_parent_transaction", "has_parent_transaction"),
    ("id", "id"),
    ("integration_id", "integration_id"),
    ("is_3d_secure", "is_3d_secure"),
    ("is_auth", "is_auth"),
    ("is_capture", "is_capture"),
    ("is_refunded", "is_refunded"),
    ("is_standalone_payment", "is_standalone_payment"),
    ("is_voided", "is_voided"),
    ("order.id", "order"),
    ("owner", "owner"),
    ("pending", "pending"),
    ("source_data.pan", "source_data.pan"),
    ("source_data.sub_type", "source_data.sub_type"),
    ("source_data.type", "source_data.type"),
    ("success", "success"),
];

/// Boolean keys within [`TX_HMAC_KEYS`] that must serialize strictly as lowercase
/// `"true"` or `"false"` in GET query parameters.
const TX_BOOLEAN_KEYS: &[&str] = &[
    "error_occured",
    "has_parent_transaction",
    "is_3d_secure",
    "is_auth",
    "is_capture",
    "is_refunded",
    "is_standalone_payment",
    "is_voided",
    "pending",
    "success",
];

/// Lexicographically sorted 8-key table for Paymob Card `TOKEN` callbacks (`obj.*`).
pub const TOKEN_HMAC_KEYS: &[&str] = &[
    "card_subtype",
    "created_at",
    "email",
    "id",
    "masked_pan",
    "merchant_id",
    "order_id",
    "token",
];

/// Errors returned by constant-time triple `HMAC-SHA512` verifiers.
///
/// Neither `Display` nor `Debug` ever exposes the `hmac_secret` or expected digest.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TripleHmacError {
    /// Signature mismatch, malformed hex, wrong digest length, invalid GET boolean
    /// casing, or missing body `hmac` field.
    #[error("webhook HMAC-SHA512 verification failed")]
    WebhookVerificationFailed,
    /// Structural error in the callback JSON payload before digest verification.
    #[error("invalid callback payload: {0}")]
    InvalidPayload(&'static str),
}

/// Computes the lowercase hex-encoded `HMAC-SHA512` digest of `payload` using `hmac_secret`.
///
/// Useful for signing deterministic test fixtures and verifying canonical strings.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::triple_hmac::compute_hmac_sha512_hex;
///
/// let digest = compute_hmac_sha512_hex("suspendedfor1264", "test-secret");
/// assert_eq!(digest.len(), 128);
/// ```
#[must_use]
pub fn compute_hmac_sha512_hex(payload: &str, hmac_secret: &str) -> String {
    hex::encode(compute_hmac_sha512_bytes(payload, hmac_secret))
}

/// Verifies a Paymob 20-key Transaction POST callback (`HMAC 1`) in constant time.
///
/// Accepts either the full webhook envelope (`{"type": "TRANSACTION", "obj": { ... }}`)
/// or the inner `obj` JSON object directly. Booleans are serialized strictly as lowercase
/// `"true"` / `"false"`.
///
/// # Errors
///
/// Returns [`TripleHmacError::InvalidPayload`] if the input is not a JSON object, or
/// [`TripleHmacError::WebhookVerificationFailed`] if the hex digest is malformed, has
/// the wrong length, or does not match the computed `HMAC-SHA512`.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use some_paymob::alignment::triple_hmac::{compute_hmac_sha512_hex, verify_tx_hmac};
///
/// let obj = json!({
///     "amount_cents": 10000,
///     "created_at": "2026-11-22T12:00:00",
///     "currency": "EGP",
///     "error_occured": false,
///     "has_parent_transaction": false,
///     "id": 999111,
///     "integration_id": 445566,
///     "is_3d_secure": true,
///     "is_auth": false,
///     "is_capture": false,
///     "is_refunded": false,
///     "is_standalone_payment": true,
///     "is_voided": false,
///     "order": { "id": 777888 },
///     "owner": 12345,
///     "pending": false,
///     "source_data": { "pan": "2346", "sub_type": "MasterCard", "type": "card" },
///     "success": true
/// });
/// let canonical = concat!(
///     "10000", "2026-11-22T12:00:00", "EGP", "false", "false",
///     "999111", "445566", "true", "false", "false", "false",
///     "true", "false", "777888", "12345", "false",
///     "2346", "MasterCard", "card", "true",
/// );
/// let sig = compute_hmac_sha512_hex(canonical, "secret-key");
/// assert!(verify_tx_hmac(&obj, &sig, "secret-key").is_ok());
/// ```
pub fn verify_tx_hmac(
    payload: &Value,
    provided_hmac: &str,
    hmac_secret: &str,
) -> Result<(), TripleHmacError> {
    let obj = extract_obj(payload)?;
    let mut canonical = String::new();
    for &(post_path, _) in TX_HMAC_KEYS {
        append_json_value(resolve_json_path(obj, post_path), &mut canonical);
    }
    verify_hmac_sha512_ct(&canonical, provided_hmac, hmac_secret)
}

/// Verifies a Paymob 20-key Transaction GET redirect callback (`HMAC 1`) in constant time.
///
/// Maps GET parameter `order` to the `order.id` slot in [`TX_HMAC_KEYS`]. All boolean
/// keys must be strictly lowercase `"true"` or `"false"`; uppercase variants such as
/// `"True"` or `"FALSE"` are rejected with [`TripleHmacError::WebhookVerificationFailed`].
///
/// # Errors
///
/// Returns [`TripleHmacError::WebhookVerificationFailed`] if any boolean query parameter
/// is not strictly lowercase `"true"` / `"false"`, or if the provided hex digest fails
/// constant-time verification.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::triple_hmac::{compute_hmac_sha512_hex, verify_tx_get_hmac};
///
/// let params = [
///     ("amount_cents", "10000"),
///     ("created_at", "2026-11-22T12:00:00"),
///     ("currency", "EGP"),
///     ("error_occured", "false"),
///     ("has_parent_transaction", "false"),
///     ("id", "999111"),
///     ("integration_id", "445566"),
///     ("is_3d_secure", "true"),
///     ("is_auth", "false"),
///     ("is_capture", "false"),
///     ("is_refunded", "false"),
///     ("is_standalone_payment", "true"),
///     ("is_voided", "false"),
///     ("order", "777888"),
///     ("owner", "12345"),
///     ("pending", "false"),
///     ("source_data.pan", "2346"),
///     ("source_data.sub_type", "MasterCard"),
///     ("source_data.type", "card"),
///     ("success", "true"),
/// ];
/// let canonical = concat!(
///     "10000", "2026-11-22T12:00:00", "EGP", "false", "false",
///     "999111", "445566", "true", "false", "false", "false",
///     "true", "false", "777888", "12345", "false",
///     "2346", "MasterCard", "card", "true",
/// );
/// let sig = compute_hmac_sha512_hex(canonical, "secret-key");
/// assert!(verify_tx_get_hmac(params, &sig, "secret-key").is_ok());
/// ```
pub fn verify_tx_get_hmac<K, V, I>(
    params: I,
    provided_hmac: &str,
    hmac_secret: &str,
) -> Result<(), TripleHmacError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let map: BTreeMap<String, String> = params
        .into_iter()
        .map(|(k, v)| (k.as_ref().to_owned(), v.as_ref().to_owned()))
        .collect();
    let mut canonical = String::new();
    for &(_, get_key) in TX_HMAC_KEYS {
        let value = map.get(get_key).map(String::as_str).unwrap_or("");
        validate_get_boolean(get_key, value)?;
        canonical.push_str(value);
    }
    verify_hmac_sha512_ct(&canonical, provided_hmac, hmac_secret)
}

/// Verifies a Paymob 8-key Card `TOKEN` callback (`HMAC 2`) against `?hmac=` in constant time.
///
/// Accepts either the full envelope (`{"type": "TOKEN", "obj": { ... }}`) or the inner
/// `obj` JSON object directly. If a top-level `"type"` string is present, it must equal
/// `"TOKEN"`.
///
/// # Errors
///
/// Returns [`TripleHmacError::InvalidPayload`] if `"type"` is present and not `"TOKEN"`
/// or if the payload is not a JSON object, or [`TripleHmacError::WebhookVerificationFailed`]
/// if constant-time `HMAC-SHA512` verification fails.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use some_paymob::alignment::triple_hmac::{compute_hmac_sha512_hex, verify_token_hmac};
///
/// let payload = json!({
///     "type": "TOKEN",
///     "obj": {
///         "card_subtype": "MasterCard",
///         "created_at": "2026-11-22T12:00:00",
///         "email": "buyer@example.com",
///         "id": 501,
///         "masked_pan": "xxxx-xxxx-xxxx-2346",
///         "merchant_id": 77,
///         "order_id": "8899",
///         "token": "tok_abc123"
///     }
/// });
/// let canonical = concat!(
///     "MasterCard", "2026-11-22T12:00:00", "buyer@example.com",
///     "501", "xxxx-xxxx-xxxx-2346", "77", "8899", "tok_abc123",
/// );
/// let sig = compute_hmac_sha512_hex(canonical, "secret-key");
/// assert!(verify_token_hmac(&payload, &sig, "secret-key").is_ok());
/// ```
pub fn verify_token_hmac(
    payload: &Value,
    provided_hmac: &str,
    hmac_secret: &str,
) -> Result<(), TripleHmacError> {
    if payload
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind != "TOKEN")
    {
        return Err(TripleHmacError::InvalidPayload(
            "expected TOKEN callback type",
        ));
    }
    let obj = extract_obj(payload)?;
    let mut canonical = String::new();
    for &key in TOKEN_HMAC_KEYS {
        append_json_value(obj.get(key), &mut canonical);
    }
    verify_hmac_sha512_ct(&canonical, provided_hmac, hmac_secret)
}

/// Verifies a Paymob Subscription callback (`HMAC 3`) strictly against the JSON body `hmac`.
///
/// Computes `HMAC-SHA512` over `format!("{trigger_type}for{subscription_id}")` (for
/// example, `"suspendedfor1264"`) and verifies it in constant time against `payload["hmac"]`.
/// Query-string `?hmac=` parameters are intentionally excluded from this function's
/// signature to enforce body-only verification (`TM-6`).
///
/// Resolves `subscription_id` from `payload["subscription_data"]["id"]` first, falling
/// back to top-level `payload["subscription_id"]`.
///
/// # Errors
///
/// Returns [`TripleHmacError::WebhookVerificationFailed`] if the body `hmac` field is
/// missing, malformed, or does not match, or [`TripleHmacError::InvalidPayload`] if
/// `trigger_type` or the subscription identifier is missing or empty.
///
/// # Examples
///
/// ```
/// use serde_json::json;
/// use some_paymob::alignment::triple_hmac::{
///     compute_hmac_sha512_hex, verify_subscription_hmac,
/// };
///
/// let sig = compute_hmac_sha512_hex("suspendedfor1264", "secret-key");
/// let payload = json!({
///     "trigger_type": "suspended",
///     "subscription_data": { "id": 1264 },
///     "hmac": sig
/// });
/// assert!(verify_subscription_hmac(&payload, "secret-key").is_ok());
/// ```
pub fn verify_subscription_hmac(payload: &Value, hmac_secret: &str) -> Result<(), TripleHmacError> {
    let body_hmac = payload
        .get("hmac")
        .and_then(Value::as_str)
        .ok_or(TripleHmacError::WebhookVerificationFailed)?;
    let trigger_type = payload
        .get("trigger_type")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(TripleHmacError::InvalidPayload(
            "missing or empty subscription trigger_type",
        ))?;
    let subscription_id = extract_subscription_id(payload)?;
    let canonical = format!("{trigger_type}for{subscription_id}");
    verify_hmac_sha512_ct(&canonical, body_hmac, hmac_secret)
}

fn compute_hmac_sha512_bytes(payload: &str, hmac_secret: &str) -> [u8; SHA512_DIGEST_LEN] {
    let mut mac = HmacSha512::new_from_slice(hmac_secret.as_bytes())
        .expect("HMAC-SHA512 accepts keys of any length");
    mac.update(payload.as_bytes());
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; SHA512_DIGEST_LEN];
    out.copy_from_slice(&bytes);
    out
}

fn verify_hmac_sha512_ct(
    canonical: &str,
    provided_hmac: &str,
    hmac_secret: &str,
) -> Result<(), TripleHmacError> {
    let decoded =
        hex::decode(provided_hmac).map_err(|_| TripleHmacError::WebhookVerificationFailed)?;
    if decoded.len() != SHA512_DIGEST_LEN {
        return Err(TripleHmacError::WebhookVerificationFailed);
    }
    let expected = compute_hmac_sha512_bytes(canonical, hmac_secret);
    if bool::from(expected.as_slice().ct_eq(decoded.as_slice())) {
        Ok(())
    } else {
        Err(TripleHmacError::WebhookVerificationFailed)
    }
}

fn extract_obj(payload: &Value) -> Result<&Value, TripleHmacError> {
    let target = payload.get("obj").unwrap_or(payload);
    if !target.is_object() {
        return Err(TripleHmacError::InvalidPayload(
            "expected JSON object for callback payload",
        ));
    }
    Ok(target)
}

fn resolve_json_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

fn append_json_value(value: Option<&Value>, out: &mut String) {
    let Some(v) = value else {
        return;
    };
    match v {
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::String(s) => out.push_str(s),
        Value::Null => {}
        other => out.push_str(&other.to_string()),
    }
}

fn validate_get_boolean(key: &str, value: &str) -> Result<(), TripleHmacError> {
    if TX_BOOLEAN_KEYS.contains(&key) && value != "true" && value != "false" {
        return Err(TripleHmacError::WebhookVerificationFailed);
    }
    Ok(())
}

fn extract_subscription_id(payload: &Value) -> Result<String, TripleHmacError> {
    let raw = resolve_json_path(payload, "subscription_data.id")
        .or_else(|| payload.get("subscription_id"))
        .ok_or(TripleHmacError::InvalidPayload(
            "missing subscription_data.id or subscription_id",
        ))?;
    let mut out = String::new();
    append_json_value(Some(raw), &mut out);
    if out.is_empty() {
        return Err(TripleHmacError::InvalidPayload(
            "empty subscription identifier",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const TEST_SECRET: &str = "super_secret_paymob_hmac_key_920";

    fn tamper_first_nibble(hex_sig: &str) -> String {
        let mut chars: Vec<char> = hex_sig.chars().collect();
        chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
        chars.into_iter().collect()
    }

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

    fn sample_tx_get_params() -> Vec<(&'static str, &'static str)> {
        vec![
            ("amount_cents", "25000"),
            ("created_at", "2026-11-22T14:30:00.123456"),
            ("currency", "EGP"),
            ("error_occured", "false"),
            ("has_parent_transaction", "false"),
            ("id", "192837465"),
            ("integration_id", "543210"),
            ("is_3d_secure", "true"),
            ("is_auth", "false"),
            ("is_capture", "false"),
            ("is_refunded", "false"),
            ("is_standalone_payment", "true"),
            ("is_voided", "false"),
            ("order", "987654321"),
            ("owner", "112233"),
            ("pending", "false"),
            ("source_data.pan", "2346"),
            ("source_data.sub_type", "MasterCard"),
            ("source_data.type", "card"),
            ("success", "true"),
        ]
    }

    #[test]
    fn key_tables_are_exact_and_lexicographically_sorted() {
        assert_eq!(TX_HMAC_KEYS.len(), 20);
        assert!(TX_HMAC_KEYS.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(TOKEN_HMAC_KEYS.len(), 8);
        assert!(TOKEN_HMAC_KEYS.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn hmac_1_tx_post_golden_and_tampered() {
        let obj = sample_tx_obj();
        let envelope = json!({ "type": "TRANSACTION", "obj": obj.clone() });
        let sig = compute_hmac_sha512_hex(sample_tx_canonical(), TEST_SECRET);

        assert!(verify_tx_hmac(&obj, &sig, TEST_SECRET).is_ok());
        assert!(verify_tx_hmac(&envelope, &sig, TEST_SECRET).is_ok());

        let tampered_sig = tamper_first_nibble(&sig);
        assert_eq!(
            verify_tx_hmac(&envelope, &tampered_sig, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );

        let mut tampered_obj = obj;
        tampered_obj["amount_cents"] = json!(25001);
        assert_eq!(
            verify_tx_hmac(&tampered_obj, &sig, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );
    }

    #[test]
    fn hmac_1_tx_get_golden_and_tampered() {
        let params = sample_tx_get_params();
        let sig = compute_hmac_sha512_hex(sample_tx_canonical(), TEST_SECRET);

        assert!(verify_tx_get_hmac(params.clone(), &sig, TEST_SECRET).is_ok());

        let tampered_sig = tamper_first_nibble(&sig);
        assert_eq!(
            verify_tx_get_hmac(params, &tampered_sig, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );
    }

    #[test]
    fn hmac_1_tx_get_rejects_uppercase_booleans() {
        let mut params = sample_tx_get_params();
        params[19] = ("success", "True");
        let canonical_with_upper = sample_tx_canonical().replace("cardtrue", "cardTrue");
        let sig = compute_hmac_sha512_hex(&canonical_with_upper, TEST_SECRET);

        assert_eq!(
            verify_tx_get_hmac(params, &sig, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );

        let mut params_false = sample_tx_get_params();
        params_false[3] = ("error_occured", "FALSE");
        let canonical_upper_false = sample_tx_canonical().replacen("false", "FALSE", 1);
        let sig_false = compute_hmac_sha512_hex(&canonical_upper_false, TEST_SECRET);

        assert_eq!(
            verify_tx_get_hmac(params_false, &sig_false, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );
    }

    #[test]
    fn hmac_2_token_golden_and_tampered() {
        let payload = json!({
            "type": "TOKEN",
            "obj": {
                "card_subtype": "Visa",
                "created_at": "2026-11-22T15:00:00",
                "email": "customer@example.com",
                "id": 4242,
                "masked_pan": "xxxx-xxxx-xxxx-4242",
                "merchant_id": 1001,
                "order_id": "ORD-77",
                "token": "tok_live_999"
            }
        });
        let canonical = concat!(
            "Visa",
            "2026-11-22T15:00:00",
            "customer@example.com",
            "4242",
            "xxxx-xxxx-xxxx-4242",
            "1001",
            "ORD-77",
            "tok_live_999"
        );
        let sig = compute_hmac_sha512_hex(canonical, TEST_SECRET);

        assert!(verify_token_hmac(&payload, &sig, TEST_SECRET).is_ok());
        assert!(verify_token_hmac(&payload["obj"], &sig, TEST_SECRET).is_ok());

        let tampered_sig = tamper_first_nibble(&sig);
        assert_eq!(
            verify_token_hmac(&payload, &tampered_sig, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );

        let wrong_type = json!({ "type": "TRANSACTION", "obj": payload["obj"].clone() });
        assert_eq!(
            verify_token_hmac(&wrong_type, &sig, TEST_SECRET),
            Err(TripleHmacError::InvalidPayload(
                "expected TOKEN callback type"
            ))
        );
    }

    #[test]
    fn hmac_3_subscription_golden_tampered_and_body_only() {
        let sig = compute_hmac_sha512_hex("suspendedfor1264", TEST_SECRET);
        let payload = json!({
            "trigger_type": "suspended",
            "subscription_data": { "id": 1264 },
            "hmac": sig
        });
        assert!(verify_subscription_hmac(&payload, TEST_SECRET).is_ok());

        let flat_payload = json!({
            "trigger_type": "suspended",
            "subscription_id": 1264,
            "hmac": sig
        });
        assert!(verify_subscription_hmac(&flat_payload, TEST_SECRET).is_ok());

        let tampered = json!({
            "trigger_type": "suspended",
            "subscription_data": { "id": 1264 },
            "hmac": tamper_first_nibble(&sig)
        });
        assert_eq!(
            verify_subscription_hmac(&tampered, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );

        let missing_body_hmac = json!({
            "trigger_type": "suspended",
            "subscription_data": { "id": 1264 }
        });
        assert_eq!(
            verify_subscription_hmac(&missing_body_hmac, TEST_SECRET),
            Err(TripleHmacError::WebhookVerificationFailed)
        );
    }

    #[test]
    fn malformed_hex_and_wrong_length_never_panic() {
        let obj = sample_tx_obj();
        let short_hex = "00".repeat(32);
        let long_hex = "ab".repeat(65);
        let bad_inputs = ["", "abc", "zzzzzzzzzzzzzzzz", &short_hex, &long_hex];

        for bad in bad_inputs {
            assert_eq!(
                verify_tx_hmac(&obj, bad, TEST_SECRET),
                Err(TripleHmacError::WebhookVerificationFailed)
            );
        }
    }

    #[test]
    fn errors_never_leak_secret_or_expected_digest() {
        let obj = sample_tx_obj();
        let expected_sig = compute_hmac_sha512_hex(sample_tx_canonical(), TEST_SECRET);
        let err = verify_tx_hmac(&obj, &"00".repeat(64), TEST_SECRET).unwrap_err();

        let debug_str = format!("{err:?}");
        let display_str = format!("{err}");
        assert!(!debug_str.contains(TEST_SECRET));
        assert!(!display_str.contains(TEST_SECRET));
        assert!(!debug_str.contains(&expected_sig));
        assert!(!display_str.contains(&expected_sig));
    }
}
