//! Fail-closed auto-dispatcher for Paymob webhook callbacks (Protocols A–E).
//!
//! Inspects incoming JSON callback payloads to identify the Paymob protocol
//! surface, delegates to the corresponding constant-time HMAC-SHA512 verifier,
//! and returns a strongly-typed [`WebhookEvent`] only after verification
//! succeeds.

use super::verifier::{PaymobWebhookEngine, WebhookError};

/// Unified, cryptographically verified Paymob webhook event.
///
/// Returned by [`PaymobWebhookEngine::construct_event`] (or protocol-specific
/// verifiers such as Protocol B GET redirect verification) only after the
/// underlying constant-time HMAC-SHA512 check succeeds.
///
/// # Examples
///
/// ```rust
/// use some_paymob::webhooks::dispatcher::WebhookEvent;
///
/// fn route_event(event: WebhookEvent) -> &'static str {
///     match event {
///         WebhookEvent::TransactionProcessed(_) => "transaction_processed",
///         WebhookEvent::TransactionResponseRedirect(_) => "transaction_redirect",
///         WebhookEvent::CardTokenSaved(_) => "card_token_saved",
///         WebhookEvent::SubscriptionLifecycle(_) => "subscription_lifecycle",
///         WebhookEvent::PayoutDisbursement(_) => "payout_disbursement",
///         WebhookEvent::PayoutTopup(_) => "payout_topup",
///     }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookEvent {
    /// Protocol A: Transaction Processed POST JSON callback.
    TransactionProcessed(super::tx_models::TransactionProcessedEvent),
    /// Protocol B: Transaction Response GET query-parameter redirect callback.
    TransactionResponseRedirect(super::protocol_b_get::TransactionRedirectParams),
    /// Protocol C: Saved Card Token POST JSON callback (`type == "TOKEN"`).
    CardTokenSaved(super::protocol_c_token::CardTokenWebhookEvent),
    /// Protocol D: Subscription Lifecycle POST JSON callback (`trigger_type` present).
    SubscriptionLifecycle(super::protocol_d_subscription::SubscriptionWebhookEvent),
    /// Protocol E: Payouts Disbursement POST JSON callback (`transaction_id` & `issuer`).
    PayoutDisbursement(super::protocol_e_payouts::DisbursementCallback),
    /// Protocol E: Payouts Topup POST JSON callback (`topup_id` present).
    PayoutTopup(super::protocol_e_payouts::TopupCallback),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectedWebhookKind {
    Subscription,
    CardToken,
    TransactionPost,
    PayoutTopup,
    PayoutDisbursement,
}

fn parse_webhook_json(raw_body: &str) -> Result<serde_json::Value, WebhookError> {
    serde_json::from_str(raw_body).map_err(|err| WebhookError::InvalidJsonPayload(err.to_string()))
}

fn require_query_hmac(query_hmac: Option<&str>) -> Result<&str, WebhookError> {
    query_hmac.ok_or(WebhookError::MissingQueryHmac)
}

fn detect_payout_kind(value: &serde_json::Value) -> Option<DetectedWebhookKind> {
    if value.get("topup_id").is_some() {
        return Some(DetectedWebhookKind::PayoutTopup);
    }
    if value.get("transaction_id").is_some() && value.get("issuer").is_some() {
        return Some(DetectedWebhookKind::PayoutDisbursement);
    }
    None
}

fn detect_webhook_kind(value: &serde_json::Value) -> Option<DetectedWebhookKind> {
    if value.get("trigger_type").is_some() {
        return Some(DetectedWebhookKind::Subscription);
    }
    let event_type = value.get("type").and_then(serde_json::Value::as_str);
    if event_type == Some("TOKEN") {
        return Some(DetectedWebhookKind::CardToken);
    }
    if event_type == Some("TRANSACTION") || value.get("obj").is_some() {
        return Some(DetectedWebhookKind::TransactionPost);
    }
    detect_payout_kind(value)
}

impl PaymobWebhookEngine {
    /// Parses, auto-detects, and verifies an incoming Paymob JSON webhook payload.
    ///
    /// This entrypoint is strictly **fail-closed**:
    /// - Malformed JSON returns [`WebhookError::InvalidJsonPayload`].
    /// - `"trigger_type"` dispatches to [`PaymobWebhookEngine::verify_subscription`].
    /// - `type == "TOKEN"` requires `query_hmac` ([`WebhookError::MissingQueryHmac`] if `None`)
    ///   and dispatches to [`PaymobWebhookEngine::verify_card_token`].
    /// - `type == "TRANSACTION"` (or `"obj"` present) requires `query_hmac`
    ///   ([`WebhookError::MissingQueryHmac`] if `None`) and dispatches to
    ///   [`PaymobWebhookEngine::verify_transaction_post`].
    /// - `"topup_id"` dispatches to [`PaymobWebhookEngine::verify_payout_topup`].
    /// - `"transaction_id"` with `"issuer"` dispatches to
    ///   [`PaymobWebhookEngine::verify_payout_disbursement`].
    /// - Any unrecognized JSON shape returns
    ///   [`WebhookError::InvalidJsonPayload`] (`"unrecognized webhook event shape"`).
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError`] if JSON parsing fails, the event shape is
    /// unrecognized, a required query HMAC is missing, or constant-time
    /// signature verification fails.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::webhooks::dispatcher::WebhookEvent;
    /// use some_paymob::webhooks::verifier::PaymobWebhookEngine;
    ///
    /// fn handle_webhook(
    ///     engine: &PaymobWebhookEngine,
    ///     raw_body: &str,
    ///     query_hmac: Option<&str>,
    /// ) -> Result<(), some_paymob::webhooks::verifier::WebhookError> {
    ///     let event = engine.construct_event(raw_body, query_hmac)?;
    ///     if let WebhookEvent::CardTokenSaved(token_evt) = event {
    ///         let _ = token_evt;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn construct_event(
        &self,
        raw_body: &str,
        query_hmac: Option<&str>,
    ) -> Result<WebhookEvent, WebhookError> {
        let value = parse_webhook_json(raw_body)?;
        let kind = detect_webhook_kind(&value).ok_or_else(|| {
            WebhookError::InvalidJsonPayload("unrecognized webhook event shape".into())
        })?;
        self.dispatch_detected_kind(kind, raw_body, query_hmac)
    }

    fn dispatch_detected_kind(
        &self,
        kind: DetectedWebhookKind,
        raw_body: &str,
        query_hmac: Option<&str>,
    ) -> Result<WebhookEvent, WebhookError> {
        match kind {
            DetectedWebhookKind::Subscription => self
                .verify_subscription(raw_body)
                .map(WebhookEvent::SubscriptionLifecycle),
            DetectedWebhookKind::CardToken => self.dispatch_card_token(raw_body, query_hmac),
            DetectedWebhookKind::TransactionPost => {
                self.dispatch_transaction_post(raw_body, query_hmac)
            }
            DetectedWebhookKind::PayoutTopup => self
                .verify_payout_topup(raw_body, query_hmac)
                .map(WebhookEvent::PayoutTopup),
            DetectedWebhookKind::PayoutDisbursement => self
                .verify_payout_disbursement(raw_body, query_hmac)
                .map(WebhookEvent::PayoutDisbursement),
        }
    }

    fn dispatch_card_token(
        &self,
        raw_body: &str,
        query_hmac: Option<&str>,
    ) -> Result<WebhookEvent, WebhookError> {
        let hmac = require_query_hmac(query_hmac)?;
        self.verify_card_token(raw_body, hmac)
            .map(WebhookEvent::CardTokenSaved)
    }

    fn dispatch_transaction_post(
        &self,
        raw_body: &str,
        query_hmac: Option<&str>,
    ) -> Result<WebhookEvent, WebhookError> {
        let hmac = require_query_hmac(query_hmac)?;
        self.verify_transaction_post(raw_body, hmac)
            .map(WebhookEvent::TransactionProcessed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_subscription_by_trigger_type() {
        let value = serde_json::json!({
            "trigger_type": "suspended",
            "subscription_data": { "id": 1264 },
            "hmac": "deadbeef"
        });
        assert_eq!(
            detect_webhook_kind(&value),
            Some(DetectedWebhookKind::Subscription)
        );
    }

    #[test]
    fn detects_card_token_before_obj_fallback() {
        let value = serde_json::json!({
            "type": "TOKEN",
            "obj": { "id": 15978654, "token": "tok_test" }
        });
        assert_eq!(
            detect_webhook_kind(&value),
            Some(DetectedWebhookKind::CardToken)
        );
    }

    #[test]
    fn detects_transaction_post_by_type_and_by_obj_presence() {
        let by_type = serde_json::json!({
            "type": "TRANSACTION",
            "obj": { "id": 192036465 }
        });
        let by_obj_only = serde_json::json!({
            "obj": { "id": 192036465 }
        });
        assert_eq!(
            detect_webhook_kind(&by_type),
            Some(DetectedWebhookKind::TransactionPost)
        );
        assert_eq!(
            detect_webhook_kind(&by_obj_only),
            Some(DetectedWebhookKind::TransactionPost)
        );
    }

    #[test]
    fn detects_payout_topup_by_topup_id() {
        let value = serde_json::json!({
            "topup_id": 42,
            "status": "Approved"
        });
        assert_eq!(
            detect_webhook_kind(&value),
            Some(DetectedWebhookKind::PayoutTopup)
        );
    }

    #[test]
    fn detects_payout_disbursement_when_transaction_id_and_issuer_present() {
        let value = serde_json::json!({
            "transaction_id": "tx_99",
            "issuer": "bank_wallet"
        });
        assert_eq!(
            detect_webhook_kind(&value),
            Some(DetectedWebhookKind::PayoutDisbursement)
        );
    }

    #[test]
    fn rejects_partial_or_unrecognized_webhook_shapes() {
        let empty = serde_json::json!({});
        let tx_id_only = serde_json::json!({ "transaction_id": "tx_99" });
        let issuer_only = serde_json::json!({ "issuer": "bank_wallet" });
        let unknown_type = serde_json::json!({ "type": "REFUND" });
        let non_string_type = serde_json::json!({ "type": 42 });

        assert_eq!(detect_webhook_kind(&empty), None);
        assert_eq!(detect_webhook_kind(&tx_id_only), None);
        assert_eq!(detect_webhook_kind(&issuer_only), None);
        assert_eq!(detect_webhook_kind(&unknown_type), None);
        assert_eq!(detect_webhook_kind(&non_string_type), None);
    }

    #[test]
    fn parse_webhook_json_fails_closed_on_malformed_input() {
        let err = parse_webhook_json("{not-valid-json").expect_err("malformed JSON must fail");
        assert!(matches!(err, WebhookError::InvalidJsonPayload(_)));
    }

    #[test]
    fn require_query_hmac_fails_closed_when_missing() {
        let err = require_query_hmac(None).expect_err("missing query HMAC must fail");
        assert!(matches!(err, WebhookError::MissingQueryHmac));
        assert_eq!(require_query_hmac(Some("abc123")), Ok("abc123"));
    }
}
