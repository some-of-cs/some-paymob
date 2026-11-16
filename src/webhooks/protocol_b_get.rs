//! Protocol B: Transaction Response GET redirect 20-key HMAC-SHA512 verifier.
//!
//! Verifies client-side redirect query parameters returned by Paymob after
//! checkout completion.
//!
//! # Security Note
//!
//! Browser redirect parameters (GET) must **never** be trusted as the sole
//! source of truth for order fulfillment because a customer may close the
//! browser before the redirect completes. Always rely on Protocol A
//! (`verify_transaction_post`) server-to-server webhooks for fulfillment.
//!
//! # Key #14 Fallback (`order_id` vs `order`)
//!
//! While Paymob's HMAC Transaction Callback specification documents `order_id`,
//! Paymob's Transaction Response Callback redirect URLs emit `order=<id>` in
//! the query string. [`PaymobWebhookEngine::verify_transaction_get`] resolves
//! key #14 from `order_id` or `order`, while rejecting conflicting values
//! (`SEC-1` HTTP parameter pollution defense).

use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::{BuildHasher, Hash};

use zeroize::{Zeroize, ZeroizeOnDrop};

use super::canonical_tx::{CanonicalTransactionConcatenator, TX_HMAC_KEYS};
use super::verifier::{PaymobWebhookEngine, WebhookError, WebhookResult};

/// Abstraction over key-value query parameter maps and slices for Paymob Protocol B
/// (Transaction Response GET redirect) verification.
pub trait QueryParams {
    /// Returns the parameter value associated with `key`, if present.
    fn get_param(&self, key: &str) -> Option<&str>;
}

impl<K, V> QueryParams for BTreeMap<K, V>
where
    K: Borrow<str> + Ord,
    V: AsRef<str>,
{
    fn get_param(&self, key: &str) -> Option<&str> {
        self.get(key).map(AsRef::as_ref)
    }
}

impl<K, V, S> QueryParams for HashMap<K, V, S>
where
    K: Borrow<str> + Eq + Hash,
    V: AsRef<str>,
    S: BuildHasher,
{
    fn get_param(&self, key: &str) -> Option<&str> {
        self.get(key).map(AsRef::as_ref)
    }
}

impl<K: AsRef<str>, V: AsRef<str>> QueryParams for [(K, V)] {
    fn get_param(&self, key: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.as_ref() == key)
            .map(|(_, v)| v.as_ref())
    }
}

impl<K: AsRef<str>, V: AsRef<str>> QueryParams for Vec<(K, V)> {
    fn get_param(&self, key: &str) -> Option<&str> {
        self.as_slice().get_param(key)
    }
}

impl<T: QueryParams + ?Sized> QueryParams for &T {
    fn get_param(&self, key: &str) -> Option<&str> {
        (**self).get_param(key)
    }
}

/// Verified 20-field transaction summary extracted from a Paymob Protocol B
/// (Transaction Response GET) redirect query string.
///
/// Implements [`Zeroize`] and [`ZeroizeOnDrop`] to scrub redirect parameters on drop,
/// and a custom `Debug` implementation that redacts [`Self::source_data_pan`] as
/// `"[REDACTED]"` to prevent masked or partial card PANs from leaking into logs.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct TransactionRedirectParams {
    /// Transaction amount in minor currency units (e.g., `"50000"` for 500.00 EGP).
    pub amount_cents: String,
    /// ISO-8601 creation timestamp string from Paymob.
    pub created_at: String,
    /// Three-letter ISO-4217 currency code (e.g., `"EGP"`).
    pub currency: String,
    /// Whether an error occurred (`"true"` or `"false"`).
    ///
    /// Preserves Paymob's single-`'r'` wire spelling (`error_occured`).
    pub error_occured: String,
    /// Whether this transaction references a parent transaction (`"true"` or `"false"`).
    pub has_parent_transaction: String,
    /// Paymob transaction identifier.
    pub id: String,
    /// Paymob payment integration identifier.
    pub integration_id: String,
    /// Whether 3D Secure authentication was used (`"true"` or `"false"`).
    pub is_3d_secure: String,
    /// Whether this is an authorization transaction (`"true"` or `"false"`).
    pub is_auth: String,
    /// Whether this is a capture transaction (`"true"` or `"false"`).
    pub is_capture: String,
    /// Whether this transaction has been refunded (`"true"` or `"false"`).
    pub is_refunded: String,
    /// Whether this is a standalone payment (`"true"` or `"false"`).
    pub is_standalone_payment: String,
    /// Whether this transaction has been voided (`"true"` or `"false"`).
    pub is_voided: String,
    /// Paymob order identifier (resolved from `order_id` or `order`).
    pub order_id: String,
    /// Paymob merchant/profile owner identifier.
    pub owner: String,
    /// Whether the transaction is pending (`"true"` or `"false"`).
    pub pending: String,
    /// Last 4 digits or masked PAN of the payment source (redacted in `Debug`).
    pub source_data_pan: String,
    /// Payment source sub-type (e.g., `"MasterCard"`).
    pub source_data_sub_type: String,
    /// Payment source type (e.g., `"card"`).
    pub source_data_type: String,
    /// Whether the transaction succeeded (`"true"` or `"false"`).
    pub success: String,
}

impl TransactionRedirectParams {
    /// Returns `true` if `success == "true"`, `pending == "false"`, and `error_occured == "false"`.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        if self.pending != "false" || self.error_occured != "false" {
            return false;
        }
        self.success == "true"
    }

    /// Returns `true` if `pending == "true"`.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.pending == "true"
    }

    /// Returns `true` if `is_voided == "true"`.
    #[must_use]
    pub fn is_voided(&self) -> bool {
        self.is_voided == "true"
    }

    /// Returns `true` if `is_refunded == "true"`.
    #[must_use]
    pub fn is_refunded(&self) -> bool {
        self.is_refunded == "true"
    }

    /// Returns `true` if `is_3d_secure == "true"`.
    #[must_use]
    pub fn is_3ds_authenticated(&self) -> bool {
        self.is_3d_secure == "true"
    }

    /// Returns `true` if `error_occured == "true"`.
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.error_occured == "true"
    }

    /// Parses [`Self::id`] as an unsigned 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::InvalidJsonPayload`] if `id` is not a valid `u64`.
    pub fn transaction_id_u64(&self) -> WebhookResult<u64> {
        parse_redirect_u64(&self.id, "redirect `id` is not a valid u64")
    }

    /// Parses [`Self::order_id`] as an unsigned 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::InvalidJsonPayload`] if `order_id` is not a valid `u64`.
    pub fn order_id_u64(&self) -> WebhookResult<u64> {
        parse_redirect_u64(&self.order_id, "redirect `order_id` is not a valid u64")
    }

    /// Parses [`Self::amount_cents`] as an unsigned 64-bit integer.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::InvalidJsonPayload`] if `amount_cents` is not a valid `u64`.
    pub fn amount_cents_u64(&self) -> WebhookResult<u64> {
        parse_redirect_u64(
            &self.amount_cents,
            "redirect `amount_cents` is not a valid u64",
        )
    }

    /// Builds the 20-key canonical HMAC concatenation string for these redirect parameters.
    #[must_use]
    pub fn canonical_hmac_string(&self) -> String {
        let mut concat = CanonicalTransactionConcatenator::new();
        for part in self.canonical_field_values() {
            concat.push_str(part);
        }
        concat.finish()
    }

    fn canonical_field_values(&self) -> [&str; 20] {
        [
            &self.amount_cents,
            &self.created_at,
            &self.currency,
            &self.error_occured,
            &self.has_parent_transaction,
            &self.id,
            &self.integration_id,
            &self.is_3d_secure,
            &self.is_auth,
            &self.is_capture,
            &self.is_refunded,
            &self.is_standalone_payment,
            &self.is_voided,
            &self.order_id,
            &self.owner,
            &self.pending,
            &self.source_data_pan,
            &self.source_data_sub_type,
            &self.source_data_type,
            &self.success,
        ]
    }
}

fn parse_redirect_u64(raw: &str, error_msg: &'static str) -> WebhookResult<u64> {
    raw.parse::<u64>()
        .map_err(|_| WebhookError::InvalidJsonPayload(error_msg.into()))
}

impl fmt::Debug for TransactionRedirectParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = f.debug_struct("TransactionRedirectParams");
        for (&key, val) in TX_HMAC_KEYS.iter().zip(self.canonical_field_values()) {
            let shown = if key == "source_data.pan" {
                "[REDACTED]"
            } else {
                val
            };
            debug.field(key, &shown);
        }
        debug.finish()
    }
}

/// Builds the canonical 20-key concatenation string from Protocol B redirect query parameters.
///
/// Resolves key #14 via `order_id` with fallback to `order`, rejecting conflicting values
/// with [`WebhookError::InvalidJsonPayload`] and missing required keys with
/// [`WebhookError::MissingRequiredField`].
///
/// # Errors
///
/// Returns [`WebhookError`] if any of the 20 keys is missing or if `order_id` and `order`
/// contain conflicting values.
pub fn build_protocol_b_canonical_string<P: QueryParams + ?Sized>(
    params: &P,
) -> WebhookResult<String> {
    let (concatenated, _) = collect_canonical_redirect_values(params)?;
    Ok(concatenated)
}

impl PaymobWebhookEngine {
    /// Verifies a Paymob Protocol B (Transaction Response GET) redirect query
    /// parameter map in constant time using HMAC-SHA512.
    ///
    /// Extracts the `hmac` query parameter, iterates [`TX_HMAC_KEYS`] in
    /// lexicographical order, resolves `"order_id"` with fallback to `"order"`,
    /// concatenates all 20 values without separators, and verifies the digest
    /// via [`Self::verify_concatenated_str`].
    ///
    /// # Errors
    ///
    /// - [`WebhookError::MissingQueryHmac`] if `hmac` is absent or blank.
    /// - [`WebhookError::MissingRequiredField`] if any of the 20 canonical
    ///   transaction fields is missing from `params` (or if `id`/`order_id` is empty).
    /// - [`WebhookError::InvalidJsonPayload`] if both `order_id` and `order` are present
    ///   with conflicting values.
    /// - [`WebhookError::MalformedSignatureHex`] if `hmac` is not valid hex.
    /// - [`WebhookError::InvalidSecretKeyLength`] if the HMAC secret is invalid.
    /// - [`WebhookError::SignatureMismatch`] if constant-time digest comparison fails.
    ///
    /// # Example
    ///
    /// ```
    /// use std::collections::BTreeMap;
    /// use some_paymob::webhooks::verifier::{PaymobWebhookEngine, WebhookError};
    ///
    /// let engine = PaymobWebhookEngine::new("3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE")?;
    /// let mut params = BTreeMap::new();
    /// params.insert("amount_cents".to_string(), "50000".to_string());
    /// params.insert("created_at".to_string(), "2024-06-25T15:16:25.910710+04:00".to_string());
    /// params.insert("currency".to_string(), "EGP".to_string());
    /// params.insert("error_occured".to_string(), "false".to_string());
    /// params.insert("has_parent_transaction".to_string(), "false".to_string());
    /// params.insert("id".to_string(), "316004".to_string());
    /// params.insert("integration_id".to_string(), "2936".to_string());
    /// params.insert("is_3d_secure".to_string(), "true".to_string());
    /// params.insert("is_auth".to_string(), "false".to_string());
    /// params.insert("is_capture".to_string(), "false".to_string());
    /// params.insert("is_refunded".to_string(), "false".to_string());
    /// params.insert("is_standalone_payment".to_string(), "true".to_string());
    /// params.insert("is_voided".to_string(), "false".to_string());
    /// params.insert("order".to_string(), "378804".to_string());
    /// params.insert("owner".to_string(), "211".to_string());
    /// params.insert("pending".to_string(), "false".to_string());
    /// params.insert("source_data.pan".to_string(), "2346".to_string());
    /// params.insert("source_data.sub_type".to_string(), "MasterCard".to_string());
    /// params.insert("source_data.type".to_string(), "card".to_string());
    /// params.insert("success".to_string(), "true".to_string());
    /// params.insert(
    ///     "hmac".to_string(),
    ///     "5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5\
    ///      826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812"
    ///         .to_string(),
    /// );
    ///
    /// let verified = engine.verify_transaction_get(&params).expect("valid redirect");
    /// assert_eq!(verified.id, "316004");
    /// assert_eq!(verified.order_id, "378804");
    /// # Ok::<(), WebhookError>(())
    /// ```
    pub fn verify_transaction_get<P: QueryParams + ?Sized>(
        &self,
        params: &P,
    ) -> WebhookResult<TransactionRedirectParams> {
        let raw_hmac = params.get_param("hmac");
        let received_hmac = super::verifier::require_non_empty_query_hmac(raw_hmac)?;
        let (concatenated, values) = collect_canonical_redirect_values(params)?;
        self.verify_concatenated_str(&concatenated, received_hmac)?;
        Ok(build_redirect_params(values))
    }

    /// Parses a raw URL query string (with or without a leading `'?'`), percent-decodes
    /// keys and values, rejects duplicate parameters, and verifies the redirect via
    /// [`Self::verify_transaction_get`].
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::InvalidJsonPayload`] if percent-encoding is malformed or
    /// duplicate query keys are present, or any error returned by
    /// [`Self::verify_transaction_get`].
    pub fn verify_transaction_get_query_str(
        &self,
        raw_query: &str,
    ) -> WebhookResult<TransactionRedirectParams> {
        let map = parse_query_string_map(raw_query)?;
        self.verify_transaction_get(&map)
    }
}

fn resolve_order_id_param<P: QueryParams + ?Sized>(params: &P) -> WebhookResult<&str> {
    match (params.get_param("order_id"), params.get_param("order")) {
        (Some(oid), Some(ord)) if oid != ord => Err(WebhookError::InvalidJsonPayload(
            "conflicting order_id and order query parameters".into(),
        )),
        (Some(oid), _) => Ok(oid),
        (None, Some(ord)) => Ok(ord),
        (None, None) => Err(WebhookError::MissingRequiredField("order_id".into())),
    }
}

fn is_primary_redirect_id_key(key: &str) -> bool {
    key == "id" || key == "order_id"
}

fn resolve_redirect_param<'a, P: QueryParams + ?Sized>(
    params: &'a P,
    key: &str,
) -> WebhookResult<&'a str> {
    let value = if key == "order_id" {
        resolve_order_id_param(params)?
    } else {
        params
            .get_param(key)
            .ok_or_else(|| WebhookError::MissingRequiredField(key.to_string()))?
    };
    if is_primary_redirect_id_key(key) && value.trim().is_empty() {
        return Err(WebhookError::MissingRequiredField(key.to_string()));
    }
    Ok(value)
}

fn collect_canonical_redirect_values<P: QueryParams + ?Sized>(
    params: &P,
) -> WebhookResult<(String, [&str; 20])> {
    let mut values = [""; 20];
    let mut concat = CanonicalTransactionConcatenator::new();
    for (idx, &key) in TX_HMAC_KEYS.iter().enumerate() {
        let value = resolve_redirect_param(params, key)?;
        values[idx] = value;
        concat.push_str(value);
    }
    Ok((concat.finish(), values))
}

fn parse_query_string_map(raw_query: &str) -> WebhookResult<BTreeMap<String, String>> {
    let query = raw_query.strip_prefix('?').unwrap_or(raw_query);
    let mut map = BTreeMap::new();
    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (raw_k, raw_v) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode_str(raw_k)?;
        let val = percent_decode_str(raw_v)?;
        if map.insert(key.clone(), val).is_some() {
            return Err(WebhookError::InvalidJsonPayload(format!(
                "duplicate query parameter: {key}"
            )));
        }
    }
    Ok(map)
}

fn decode_hex_pair(hi: u8, lo: u8) -> WebhookResult<u8> {
    let mut out = [0u8; 1];
    hex::decode_to_slice([hi, lo], &mut out).map_err(|_| {
        WebhookError::InvalidJsonPayload("malformed percent-encoding in query".into())
    })?;
    Ok(out[0])
}

fn decode_percent_escape(bytes: &[u8], idx: usize) -> WebhookResult<(u8, usize)> {
    if idx + 2 >= bytes.len() {
        return Err(WebhookError::InvalidJsonPayload(
            "truncated percent-encoding in query".into(),
        ));
    }
    let decoded = decode_hex_pair(bytes[idx + 1], bytes[idx + 2])?;
    Ok((decoded, idx + 3))
}

fn decode_next_query_byte(bytes: &[u8], idx: usize) -> WebhookResult<(u8, usize)> {
    match bytes[idx] {
        b'+' => Ok((b' ', idx + 1)),
        b'%' => decode_percent_escape(bytes, idx),
        byte => Ok((byte, idx + 1)),
    }
}

fn percent_decode_str(input: &str) -> WebhookResult<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut idx = 0;
    while idx < bytes.len() {
        let (decoded, next_idx) = decode_next_query_byte(bytes, idx)?;
        out.push(decoded);
        idx = next_idx;
    }
    String::from_utf8(out)
        .map_err(|_| WebhookError::InvalidJsonPayload("decoded query is not valid UTF-8".into()))
}

fn build_redirect_params(values: [&str; 20]) -> TransactionRedirectParams {
    TransactionRedirectParams {
        amount_cents: values[0].to_owned(),
        created_at: values[1].to_owned(),
        currency: values[2].to_owned(),
        error_occured: values[3].to_owned(),
        has_parent_transaction: values[4].to_owned(),
        id: values[5].to_owned(),
        integration_id: values[6].to_owned(),
        is_3d_secure: values[7].to_owned(),
        is_auth: values[8].to_owned(),
        is_capture: values[9].to_owned(),
        is_refunded: values[10].to_owned(),
        is_standalone_payment: values[11].to_owned(),
        is_voided: values[12].to_owned(),
        order_id: values[13].to_owned(),
        owner: values[14].to_owned(),
        pending: values[15].to_owned(),
        source_data_pan: values[16].to_owned(),
        source_data_sub_type: values[17].to_owned(),
        source_data_type: values[18].to_owned(),
        success: values[19].to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_HMAC_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";
    const VECTOR_316004_HMAC: &str = "5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5\
         826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812";

    fn test_engine() -> PaymobWebhookEngine {
        PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret")
    }

    fn vector_316004_btreemap(use_order_id_key: bool) -> BTreeMap<String, String> {
        let order_key = if use_order_id_key {
            "order_id"
        } else {
            "order"
        };
        [
            ("amount_cents", "50000"),
            ("created_at", "2024-06-25T15:16:25.910710+04:00"),
            ("currency", "EGP"),
            ("error_occured", "false"),
            ("has_parent_transaction", "false"),
            ("id", "316004"),
            ("integration_id", "2936"),
            ("is_3d_secure", "true"),
            ("is_auth", "false"),
            ("is_capture", "false"),
            ("is_refunded", "false"),
            ("is_standalone_payment", "true"),
            ("is_voided", "false"),
            (order_key, "378804"),
            ("owner", "211"),
            ("pending", "false"),
            ("source_data.pan", "2346"),
            ("source_data.sub_type", "MasterCard"),
            ("source_data.type", "card"),
            ("success", "true"),
            ("hmac", VECTOR_316004_HMAC),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    #[test]
    fn vector_316004_order_fallback_btreemap_succeeds() {
        let params = vector_316004_btreemap(false);
        let verified = test_engine()
            .verify_transaction_get(&params)
            .expect("Official Redirect Test Vector 316004 with order= fallback should verify");

        assert_eq!(verified.id, "316004");
        assert_eq!(verified.order_id, "378804");
        assert_eq!(
            (verified.amount_cents.as_str(), verified.currency.as_str()),
            ("50000", "EGP")
        );
        assert_eq!(verified.source_data_pan, "2346");
        assert_eq!(verified.source_data_sub_type, "MasterCard");
        assert!(verified.is_approved() && verified.is_3ds_authenticated());
        assert_eq!(
            verified.canonical_hmac_string(),
            build_protocol_b_canonical_string(&params).unwrap()
        );
    }

    #[test]
    fn vector_316004_order_id_hashmap_and_slice_containers_succeed() {
        let engine = test_engine();
        let params: HashMap<String, String> = vector_316004_btreemap(true).into_iter().collect();
        let verified = engine
            .verify_transaction_get(&params)
            .expect("hashmap verify");
        assert_eq!(verified.transaction_id_u64(), Ok(316004));
        assert_eq!(verified.order_id_u64(), Ok(378804));
        assert_eq!(verified.amount_cents_u64(), Ok(50000));

        let vec_pairs: Vec<(String, String)> = params.into_iter().collect();
        assert!(engine.verify_transaction_get(&vec_pairs).is_ok());
        assert!(engine.verify_transaction_get(vec_pairs.as_slice()).is_ok());
    }

    #[test]
    fn str_map_and_str_slice_query_params_succeed() {
        let engine = test_engine();
        let owned = vector_316004_btreemap(true);
        let str_vec: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let str_btree: BTreeMap<&str, &str> = str_vec.iter().copied().collect();
        let str_hash: HashMap<&str, &str> = str_vec.iter().copied().collect();

        assert!(engine.verify_transaction_get(&str_vec).is_ok());
        assert!(engine.verify_transaction_get(str_vec.as_slice()).is_ok());
        assert!(engine.verify_transaction_get(&str_btree).is_ok());
        assert!(engine.verify_transaction_get(&str_hash).is_ok());
    }

    #[test]
    fn order_id_and_order_conflict_rejected_while_matching_accepted() {
        let engine = test_engine();
        let mut matching = vector_316004_btreemap(true);
        matching.insert("order".to_string(), "378804".to_string());
        assert!(engine.verify_transaction_get(&matching).is_ok());

        let mut conflicting = matching;
        conflicting.insert("order".to_string(), "999999".to_string());
        let err = engine.verify_transaction_get(&conflicting).unwrap_err();
        assert!(matches!(err, WebhookError::InvalidJsonPayload(_)));
    }

    #[test]
    fn missing_any_of_20_keys_returns_missing_required_field() {
        let base = vector_316004_btreemap(true);
        let all_missing_detected = TX_HMAC_KEYS.iter().all(|&key| {
            let mut candidate = base.clone();
            candidate.remove(key);
            build_protocol_b_canonical_string(&candidate)
                == Err(WebhookError::MissingRequiredField(key.to_string()))
        });
        assert!(all_missing_detected);
    }

    #[test]
    fn tampering_any_of_20_keys_returns_signature_mismatch() {
        let engine = test_engine();
        for key in TX_HMAC_KEYS {
            let mut map = vector_316004_btreemap(true);
            *map.get_mut(key).unwrap() = "tampered_value".to_string();
            assert_eq!(
                engine.verify_transaction_get(&map),
                Err(WebhookError::SignatureMismatch)
            );
        }
    }

    #[test]
    fn empty_id_or_order_id_or_missing_hmac_rejected() {
        let engine = test_engine();
        let mut blank_id = vector_316004_btreemap(true);
        blank_id.insert("id".to_string(), "   ".to_string());
        assert_eq!(
            engine.verify_transaction_get(&blank_id).unwrap_err(),
            WebhookError::MissingRequiredField("id".into())
        );

        let mut no_hmac = vector_316004_btreemap(false);
        no_hmac.remove("hmac");
        assert_eq!(
            engine.verify_transaction_get(&no_hmac).unwrap_err(),
            WebhookError::MissingQueryHmac
        );
    }

    #[test]
    fn verify_transaction_get_query_str_decodes_url_and_rejects_duplicates() {
        let engine = test_engine();
        let map = vector_316004_btreemap(false);
        let raw_query = format!(
            "?{}",
            map.iter()
                .map(|(k, v)| format!("{k}={}", v.replace(':', "%3A").replace('+', "%2B")))
                .collect::<Vec<_>>()
                .join("&")
        );
        let verified = engine
            .verify_transaction_get_query_str(&raw_query)
            .expect("URL-encoded query string must verify");
        assert_eq!(verified.id, "316004");

        let dup_query = format!("{raw_query}&amount_cents=100");
        assert!(matches!(
            engine
                .verify_transaction_get_query_str(&dup_query)
                .unwrap_err(),
            WebhookError::InvalidJsonPayload(_)
        ));
    }

    #[test]
    fn debug_redacts_source_data_pan_and_status_helpers_work() {
        let params = vector_316004_btreemap(false);
        let verified = test_engine().verify_transaction_get(&params).unwrap();
        let debug_output = format!("{verified:?}");

        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("2346"));
        assert!(!verified.is_pending() && !verified.is_voided());
        assert!(!verified.is_refunded() && !verified.has_error());
    }
}
