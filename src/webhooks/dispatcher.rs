#![forbid(unsafe_code)]
//! Fail-closed auto-dispatcher for Paymob webhook callbacks (Protocols A–E).
//!
//! Inspects incoming JSON callback payloads to identify the Paymob protocol
//! surface, delegates to the corresponding constant-time HMAC-SHA512 verifier,
//! and returns a strongly-typed [`WebhookEvent`] only after verification
//! succeeds.

use super::verifier::{PaymobWebhookEngine, WebhookError, WebhookResult};

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
/// fn route_event(event: &WebhookEvent) -> &'static str {
///     event.event_type()
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

impl WebhookEvent {
    /// Returns a canonical `snake_case` identifier for this webhook event variant.
    #[must_use]
    pub const fn event_type(&self) -> &'static str {
        if let Some(kind) = self.acquiring_event_type() {
            return kind;
        }
        self.lifecycle_or_payout_event_type()
    }

    const fn acquiring_event_type(&self) -> Option<&'static str> {
        match self {
            Self::TransactionProcessed(_) => Some("transaction_processed"),
            Self::TransactionResponseRedirect(_) => Some("transaction_redirect"),
            Self::CardTokenSaved(_) => Some("card_token_saved"),
            _ => None,
        }
    }

    const fn lifecycle_or_payout_event_type(&self) -> &'static str {
        match self {
            Self::SubscriptionLifecycle(_) => "subscription_lifecycle",
            Self::PayoutDisbursement(_) => "payout_disbursement",
            _ => "payout_topup",
        }
    }

    /// Returns `true` if this event is a Protocol A or Protocol B transaction callback.
    #[must_use]
    pub const fn is_transaction(&self) -> bool {
        matches!(
            self,
            Self::TransactionProcessed(_) | Self::TransactionResponseRedirect(_)
        )
    }

    /// Returns `true` if this event is a Protocol A [`Self::TransactionProcessed`] callback.
    #[must_use]
    pub const fn is_transaction_processed(&self) -> bool {
        matches!(self, Self::TransactionProcessed(_))
    }

    /// Returns `true` if this event is a Protocol B [`Self::TransactionResponseRedirect`] callback.
    #[must_use]
    pub const fn is_transaction_redirect(&self) -> bool {
        matches!(self, Self::TransactionResponseRedirect(_))
    }

    /// Returns `true` if this event is a Protocol C [`Self::CardTokenSaved`] callback.
    #[must_use]
    pub const fn is_card_token(&self) -> bool {
        matches!(self, Self::CardTokenSaved(_))
    }

    /// Returns `true` if this event is a Protocol D [`Self::SubscriptionLifecycle`] callback.
    #[must_use]
    pub const fn is_subscription(&self) -> bool {
        matches!(self, Self::SubscriptionLifecycle(_))
    }

    /// Returns `true` if this event is a Protocol E payout disbursement or top-up callback.
    #[must_use]
    pub const fn is_payout(&self) -> bool {
        matches!(self, Self::PayoutDisbursement(_) | Self::PayoutTopup(_))
    }

    /// Returns `true` if this event is a Protocol E [`Self::PayoutDisbursement`] callback.
    #[must_use]
    pub const fn is_payout_disbursement(&self) -> bool {
        matches!(self, Self::PayoutDisbursement(_))
    }

    /// Returns `true` if this event is a Protocol E [`Self::PayoutTopup`] callback.
    #[must_use]
    pub const fn is_payout_topup(&self) -> bool {
        matches!(self, Self::PayoutTopup(_))
    }

    /// Returns the inner [`super::tx_models::TransactionProcessedEvent`] if this is [`Self::TransactionProcessed`].
    #[must_use]
    pub const fn as_transaction(&self) -> Option<&super::tx_models::TransactionProcessedEvent> {
        if let Self::TransactionProcessed(evt) = self {
            Some(evt)
        } else {
            None
        }
    }

    /// Returns the inner [`super::protocol_b_get::TransactionRedirectParams`] if this is [`Self::TransactionResponseRedirect`].
    #[must_use]
    pub const fn as_transaction_redirect(
        &self,
    ) -> Option<&super::protocol_b_get::TransactionRedirectParams> {
        if let Self::TransactionResponseRedirect(params) = self {
            Some(params)
        } else {
            None
        }
    }

    /// Returns the inner [`super::protocol_c_token::CardTokenWebhookEvent`] if this is [`Self::CardTokenSaved`].
    #[must_use]
    pub const fn as_card_token(&self) -> Option<&super::protocol_c_token::CardTokenWebhookEvent> {
        if let Self::CardTokenSaved(evt) = self {
            Some(evt)
        } else {
            None
        }
    }

    /// Returns the inner [`super::protocol_d_subscription::SubscriptionWebhookEvent`] if this is [`Self::SubscriptionLifecycle`].
    #[must_use]
    pub const fn as_subscription(
        &self,
    ) -> Option<&super::protocol_d_subscription::SubscriptionWebhookEvent> {
        if let Self::SubscriptionLifecycle(evt) = self {
            Some(evt)
        } else {
            None
        }
    }

    /// Returns the inner [`super::protocol_e_payouts::DisbursementCallback`] if this is [`Self::PayoutDisbursement`].
    #[must_use]
    pub const fn as_payout_disbursement(
        &self,
    ) -> Option<&super::protocol_e_payouts::DisbursementCallback> {
        if let Self::PayoutDisbursement(cb) = self {
            Some(cb)
        } else {
            None
        }
    }

    /// Returns the inner [`super::protocol_e_payouts::TopupCallback`] if this is [`Self::PayoutTopup`].
    #[must_use]
    pub const fn as_payout_topup(&self) -> Option<&super::protocol_e_payouts::TopupCallback> {
        if let Self::PayoutTopup(cb) = self {
            Some(cb)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectedWebhookKind {
    Subscription,
    CardToken,
    TransactionPost,
    PayoutTopup,
    PayoutDisbursement,
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

fn detect_typed_kind(type_val: &serde_json::Value) -> Option<DetectedWebhookKind> {
    match type_val.as_str() {
        Some("TOKEN") => Some(DetectedWebhookKind::CardToken),
        Some("TRANSACTION") => Some(DetectedWebhookKind::TransactionPost),
        _ => None,
    }
}

fn detect_webhook_kind(value: &serde_json::Value) -> Option<DetectedWebhookKind> {
    if value.get("trigger_type").is_some() {
        return Some(DetectedWebhookKind::Subscription);
    }
    if let Some(type_val) = value.get("type") {
        return detect_typed_kind(type_val);
    }
    if value.get("obj").is_some() {
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
    /// - `type == "TOKEN"` requires `query_hmac` ([`WebhookError::MissingQueryHmac`] if `None`
    ///   or whitespace) and dispatches to [`PaymobWebhookEngine::verify_card_token`].
    /// - `type == "TRANSACTION"` (or `"obj"` present when `"type"` is omitted) requires
    ///   `query_hmac` ([`WebhookError::MissingQueryHmac`] if `None` or whitespace) and dispatches
    ///   to [`PaymobWebhookEngine::verify_transaction_post`]. Any other `"type"` value fails closed
    ///   even if `"obj"` is present (`SEC-7.2-3`).
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
    ///     if let Some(token_evt) = event.as_card_token() {
    ///         let _ = token_evt;
    ///     }
    ///     Ok(())
    /// }
    /// ```
    pub fn construct_event(
        &self,
        raw_body: &str,
        query_hmac: Option<&str>,
    ) -> WebhookResult<WebhookEvent> {
        let value: serde_json::Value = super::verifier::parse_webhook_json_str(raw_body)?;
        let kind = detect_webhook_kind(&value).ok_or_else(|| {
            WebhookError::InvalidJsonPayload("unrecognized webhook event shape".into())
        })?;
        self.dispatch_detected_kind(kind, raw_body, query_hmac)
    }

    /// Parses, auto-detects, and verifies an incoming Paymob JSON webhook payload from raw bytes.
    ///
    /// Validates that `raw_body` is valid UTF-8 before delegating to [`Self::construct_event`].
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::InvalidJsonPayload`] if `raw_body` is not valid UTF-8, or any
    /// error returned by [`Self::construct_event`].
    pub fn construct_event_from_slice(
        &self,
        raw_body: &[u8],
        query_hmac: Option<&str>,
    ) -> WebhookResult<WebhookEvent> {
        let raw_str = super::verifier::decode_webhook_utf8(raw_body)?;
        self.construct_event(raw_str, query_hmac)
    }

    fn dispatch_detected_kind(
        &self,
        kind: DetectedWebhookKind,
        raw_body: &str,
        query_hmac: Option<&str>,
    ) -> WebhookResult<WebhookEvent> {
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
    ) -> WebhookResult<WebhookEvent> {
        let hmac = super::verifier::require_non_empty_query_hmac(query_hmac)?;
        self.verify_card_token(raw_body, hmac)
            .map(WebhookEvent::CardTokenSaved)
    }

    fn dispatch_transaction_post(
        &self,
        raw_body: &str,
        query_hmac: Option<&str>,
    ) -> WebhookResult<WebhookEvent> {
        let hmac = super::verifier::require_non_empty_query_hmac(query_hmac)?;
        self.verify_transaction_post(raw_body, hmac)
            .map(WebhookEvent::TransactionProcessed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";
    const TOKEN_VEC_JSON: &str = r#"{
        "type": "TOKEN",
        "obj": {
            "id": 15978654,
            "token": "tok_test_15978654_abcdef",
            "masked_pan": "xxxx-xxxx-xxxx-2346",
            "merchant_id": 302852,
            "card_subtype": "MasterCard",
            "created_at": "2024-06-13T11:33:44.592345",
            "email": "customer@example.com",
            "order_id": "593881581"
        }
    }"#;
    const TOKEN_VEC_HMAC: &str = "38ac96769330ae1b446ba94220b4a0fbf4a536ff407710d0637b32efc1c17cc17dde92a831467724a16e09ea7b7054806275d78ce726ba243cc2fea25f30be0d";

    #[test]
    fn detects_subscription_and_card_token() {
        let sub_val = serde_json::json!({
            "trigger_type": "suspended",
            "subscription_data": { "id": 1264 },
            "hmac": "deadbeef"
        });
        let tok_val = serde_json::json!({
            "type": "TOKEN",
            "obj": { "id": 15978654, "token": "tok_test" }
        });
        assert_eq!(
            detect_webhook_kind(&sub_val),
            Some(DetectedWebhookKind::Subscription)
        );
        assert_eq!(
            detect_webhook_kind(&tok_val),
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
    fn detects_payout_topup_and_disbursement() {
        let topup = serde_json::json!({ "topup_id": 42, "status": "Approved" });
        let disb = serde_json::json!({ "transaction_id": "tx_99", "issuer": "bank_wallet" });
        assert_eq!(
            detect_webhook_kind(&topup),
            Some(DetectedWebhookKind::PayoutTopup)
        );
        assert_eq!(
            detect_webhook_kind(&disb),
            Some(DetectedWebhookKind::PayoutDisbursement)
        );
    }

    #[test]
    fn rejects_unknown_type_even_when_obj_present_sec_7_2_3() {
        let refund_with_obj = serde_json::json!({
            "type": "REFUND",
            "obj": { "id": 192036465 }
        });
        let numeric_type_with_obj = serde_json::json!({
            "type": 42,
            "obj": { "id": 192036465 }
        });
        assert_eq!(detect_webhook_kind(&refund_with_obj), None);
        assert_eq!(detect_webhook_kind(&numeric_type_with_obj), None);
        assert_eq!(detect_webhook_kind(&serde_json::json!({})), None);
        assert_eq!(
            detect_webhook_kind(&serde_json::json!({ "transaction_id": "tx_99" })),
            None
        );
    }

    fn sign_test_hmac(secret: &str, payload: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        let mut mac = Hmac::<Sha512>::new_from_slice(secret.as_bytes()).expect("hmac");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    #[test]
    fn construct_event_dispatches_card_token_and_payouts_end_to_end() {
        let engine = PaymobWebhookEngine::new(SAMPLE_SECRET)
            .expect("engine")
            .with_payouts_secret(SAMPLE_SECRET)
            .expect("payouts secret");
        let tok_evt = engine
            .construct_event(TOKEN_VEC_JSON, Some(TOKEN_VEC_HMAC))
            .expect("card token dispatch");
        assert!(tok_evt.is_card_token() && !tok_evt.is_transaction());
        assert_eq!(tok_evt.event_type(), "card_token_saved");
        assert!(tok_evt.as_card_token().is_some());

        let topup_json =
            r#"{"topup_id":"top_1","amount_cents":5000,"currency":"EGP","status":"Approved"}"#;
        let topup_sig = sign_test_hmac(SAMPLE_SECRET, topup_json);
        let topup_evt = engine
            .construct_event_from_slice(topup_json.as_bytes(), Some(&topup_sig))
            .expect("topup dispatch");
        assert!(topup_evt.is_payout() && topup_evt.is_payout_topup());
        assert_eq!(topup_evt.event_type(), "payout_topup");
        assert!(topup_evt.as_payout_topup().is_some());
    }

    #[test]
    fn construct_event_rejects_missing_hmac_invalid_utf8_and_refund_type() {
        let engine = PaymobWebhookEngine::new(SAMPLE_SECRET).expect("engine");
        assert_eq!(
            engine.construct_event(TOKEN_VEC_JSON, None),
            Err(WebhookError::MissingQueryHmac)
        );
        assert_eq!(
            engine.construct_event(TOKEN_VEC_JSON, Some("   ")),
            Err(WebhookError::MissingQueryHmac)
        );
        assert!(matches!(
            engine.construct_event(r#"{"type":"REFUND","obj":{"id":1}}"#, Some(TOKEN_VEC_HMAC)),
            Err(WebhookError::InvalidJsonPayload(_))
        ));
        assert!(matches!(
            engine.construct_event_from_slice(&[0xff, 0xfe], None),
            Err(WebhookError::InvalidJsonPayload(_))
        ));
    }

    #[test]
    fn webhook_event_accessors_cover_disbursement_and_subscription() {
        let engine = PaymobWebhookEngine::new(SAMPLE_SECRET)
            .expect("engine")
            .with_payouts_secret(SAMPLE_SECRET)
            .expect("payouts secret");
        let disb_json = "{\"transaction_id\":\"tx_7\",\"issuer\":\"bank_card\",\
            \"amount_cents\":900,\"currency\":\"EGP\",\"status\":\"ok\"}";
        let disb_sig = sign_test_hmac(SAMPLE_SECRET, disb_json);
        let disb_evt = engine
            .construct_event(disb_json, Some(&disb_sig))
            .expect("disb dispatch");
        assert!(disb_evt.is_payout_disbursement());
        assert_eq!(disb_evt.event_type(), "payout_disbursement");
        assert!(disb_evt.as_payout_disbursement().is_some());
        assert!(disb_evt.as_transaction().is_none());
        assert!(disb_evt.as_transaction_redirect().is_none());
        assert!(disb_evt.as_subscription().is_none());
    }
}
