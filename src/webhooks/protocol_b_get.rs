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
//! key #14 via `params.get_param("order_id").or_else(|| params.get_param("order"))`.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::BuildHasher;

use super::canonical_tx::TX_HMAC_KEYS;
use super::verifier::{PaymobWebhookEngine, WebhookError};

/// Abstraction over key-value query parameter maps for Paymob Protocol B
/// (Transaction Response GET redirect) verification.
pub trait QueryParams {
    /// Returns the parameter value associated with `key`, if present.
    fn get_param(&self, key: &str) -> Option<&str>;
}

impl QueryParams for BTreeMap<String, String> {
    fn get_param(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

impl<S: BuildHasher> QueryParams for HashMap<String, String, S> {
    fn get_param(&self, key: &str) -> Option<&str> {
        self.get(key).map(String::as_str)
    }
}

impl QueryParams for BTreeMap<&str, &str> {
    fn get_param(&self, key: &str) -> Option<&str> {
        self.get(key).copied()
    }
}

impl<S: BuildHasher> QueryParams for HashMap<&str, &str, S> {
    fn get_param(&self, key: &str) -> Option<&str> {
        self.get(key).copied()
    }
}

/// Verified 20-field transaction summary extracted from a Paymob Protocol B
/// (Transaction Response GET) redirect query string.
///
/// The `Debug` implementation redacts [`Self::source_data_pan`] as
/// `"[REDACTED]"` to prevent masked or partial card PANs from leaking into logs.
#[derive(Clone, PartialEq, Eq)]
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

impl fmt::Debug for TransactionRedirectParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransactionRedirectParams")
            .field("amount_cents", &self.amount_cents)
            .field("created_at", &self.created_at)
            .field("currency", &self.currency)
            .field("error_occured", &self.error_occured)
            .field("has_parent_transaction", &self.has_parent_transaction)
            .field("id", &self.id)
            .field("integration_id", &self.integration_id)
            .field("is_3d_secure", &self.is_3d_secure)
            .field("is_auth", &self.is_auth)
            .field("is_capture", &self.is_capture)
            .field("is_refunded", &self.is_refunded)
            .field("is_standalone_payment", &self.is_standalone_payment)
            .field("is_voided", &self.is_voided)
            .field("order_id", &self.order_id)
            .field("owner", &self.owner)
            .field("pending", &self.pending)
            .field("source_data_pan", &"[REDACTED]")
            .field("source_data_sub_type", &self.source_data_sub_type)
            .field("source_data_type", &self.source_data_type)
            .field("success", &self.success)
            .finish()
    }
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
    ///   transaction fields is missing from `params`.
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
    pub fn verify_transaction_get<P: QueryParams>(
        &self,
        params: &P,
    ) -> Result<TransactionRedirectParams, WebhookError> {
        let received_hmac = match params.get_param("hmac") {
            Some(hmac_hex) if !hmac_hex.trim().is_empty() => hmac_hex,
            _ => return Err(WebhookError::MissingQueryHmac),
        };

        let (concatenated, values) = collect_canonical_redirect_values(params)?;
        self.verify_concatenated_str(&concatenated, received_hmac)?;
        Ok(build_redirect_params(values))
    }
}

fn resolve_redirect_param<'a, P: QueryParams>(
    params: &'a P,
    key: &str,
) -> Result<&'a str, WebhookError> {
    let value = if key == "order_id" {
        params
            .get_param("order_id")
            .or_else(|| params.get_param("order"))
    } else {
        params.get_param(key)
    };
    value.ok_or_else(|| WebhookError::MissingRequiredField(key.to_string()))
}

fn collect_canonical_redirect_values<'a, P: QueryParams>(
    params: &'a P,
) -> Result<(String, [&'a str; 20]), WebhookError> {
    let mut values = [""; 20];
    let mut concatenated = String::with_capacity(256);
    for (idx, &key) in TX_HMAC_KEYS.iter().enumerate() {
        let value = resolve_redirect_param(params, key)?;
        values[idx] = value;
        concatenated.push_str(value);
    }
    Ok((concatenated, values))
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
    const VECTOR_316004_HMAC: &str =
        "5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5\
         826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812";

    fn vector_316004_btree(use_order_id_key: bool) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("amount_cents".to_string(), "50000".to_string());
        map.insert(
            "created_at".to_string(),
            "2024-06-25T15:16:25.910710+04:00".to_string(),
        );
        map.insert("currency".to_string(), "EGP".to_string());
        map.insert("error_occured".to_string(), "false".to_string());
        map.insert("has_parent_transaction".to_string(), "false".to_string());
        map.insert("id".to_string(), "316004".to_string());
        map.insert("integration_id".to_string(), "2936".to_string());
        map.insert("is_3d_secure".to_string(), "true".to_string());
        map.insert("is_auth".to_string(), "false".to_string());
        map.insert("is_capture".to_string(), "false".to_string());
        map.insert("is_refunded".to_string(), "false".to_string());
        map.insert("is_standalone_payment".to_string(), "true".to_string());
        map.insert("is_voided".to_string(), "false".to_string());
        let order_key = if use_order_id_key {
            "order_id"
        } else {
            "order"
        };
        map.insert(order_key.to_string(), "378804".to_string());
        map.insert("owner".to_string(), "211".to_string());
        map.insert("pending".to_string(), "false".to_string());
        map.insert("source_data.pan".to_string(), "2346".to_string());
        map.insert("source_data.sub_type".to_string(), "MasterCard".to_string());
        map.insert("source_data.type".to_string(), "card".to_string());
        map.insert("success".to_string(), "true".to_string());
        map.insert("hmac".to_string(), VECTOR_316004_HMAC.to_string());
        map
    }

    #[test]
    fn vector_316004_order_fallback_btreemap_succeeds() {
        let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret");
        let params = vector_316004_btree(false);
        let verified = engine
            .verify_transaction_get(&params)
            .expect("Official Redirect Test Vector 316004 with order= fallback should verify");

        assert_eq!(verified.id, "316004");
        assert_eq!(verified.order_id, "378804");
        assert_eq!(verified.amount_cents, "50000");
        assert_eq!(verified.currency, "EGP");
        assert_eq!(verified.error_occured, "false");
        assert_eq!(verified.source_data_pan, "2346");
        assert_eq!(verified.source_data_sub_type, "MasterCard");
        assert_eq!(verified.source_data_type, "card");
        assert_eq!(verified.success, "true");
    }

    #[test]
    fn vector_316004_order_id_hashmap_succeeds() {
        let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret");
        let params: HashMap<String, String> = vector_316004_btree(true).into_iter().collect();
        let verified = engine
            .verify_transaction_get(&params)
            .expect("Official Redirect Test Vector 316004 with order_id= should verify");

        assert_eq!(verified.id, "316004");
        assert_eq!(verified.order_id, "378804");
    }

    #[test]
    fn missing_hmac_returns_missing_query_hmac() {
        let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret");
        let mut params = vector_316004_btree(false);
        params.remove("hmac");

        let err = engine.verify_transaction_get(&params).unwrap_err();
        assert!(matches!(err, WebhookError::MissingQueryHmac));

        params.insert("hmac".to_string(), "   ".to_string());
        let blank_err = engine.verify_transaction_get(&params).unwrap_err();
        assert!(matches!(blank_err, WebhookError::MissingQueryHmac));
    }

    #[test]
    fn missing_required_field_returns_error() {
        let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret");

        let mut missing_amount = vector_316004_btree(false);
        missing_amount.remove("amount_cents");
        assert!(matches!(
            engine.verify_transaction_get(&missing_amount),
            Err(WebhookError::MissingRequiredField(ref field)) if field == "amount_cents"
        ));

        let mut missing_order = vector_316004_btree(false);
        missing_order.remove("order");
        assert!(matches!(
            engine.verify_transaction_get(&missing_order),
            Err(WebhookError::MissingRequiredField(ref field)) if field == "order_id"
        ));
    }

    #[test]
    fn tampered_field_returns_signature_mismatch() {
        let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret");
        let mut params = vector_316004_btree(false);
        params.insert("amount_cents".to_string(), "100".to_string());

        let err = engine.verify_transaction_get(&params).unwrap_err();
        assert!(matches!(err, WebhookError::SignatureMismatch));
    }

    #[test]
    fn malformed_hmac_hex_returns_error() {
        let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret");
        let mut params = vector_316004_btree(false);
        params.insert("hmac".to_string(), "not-valid-hex!".to_string());

        let err = engine.verify_transaction_get(&params).unwrap_err();
        assert!(matches!(err, WebhookError::MalformedSignatureHex));
    }

    #[test]
    fn debug_redacts_source_data_pan() {
        let engine = PaymobWebhookEngine::new(TEST_HMAC_SECRET).expect("valid test secret");
        let params = vector_316004_btree(false);
        let verified = engine.verify_transaction_get(&params).unwrap();
        let debug_output = format!("{verified:?}");

        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("2346"));
    }
}
