#![forbid(unsafe_code)]
//! Protocol A–E (including Protocol B GET) webhook adapter and rich normalized event DTOs
//! (`US-9.2.0` Unit 2).
//!
//! Extends the northbound `some-payment` adapter with:
//! - [`UnifiedWebhookPayload`] supporting both HTTP `POST` JSON callbacks (Protocols A, C, D, E)
//!   and Protocol B HTTP `GET` redirect query strings.
//! - [`RichWebhookEvent`] extracting strongly-typed transaction, order, monetary, status, and
//!   payout fields with `[REDACTED]`-safe [`fmt::Debug`] formatting.
//! - [`normalize_rich_webhook_event`] and [`verify_and_normalize_webhook`] helpers adhering to
//!   strict cyclomatic complexity (`CC <= 6`) and nesting depth (`<= 2`) invariants.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::adapter::some_payments::normalize_webhook_event;
use crate::adapter::traits::UnifiedWebhookKind;
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::types::MinorUnitAmount;
use crate::webhooks::WebhookEvent;
use crate::webhooks::protocol_b_get::TransactionRedirectParams;
use crate::webhooks::protocol_c_token::CardTokenWebhookEvent;
use crate::webhooks::protocol_d_subscription::SubscriptionWebhookEvent;
use crate::webhooks::protocol_e_payouts::{DisbursementCallback, TopupCallback, TopupStatus};
use crate::webhooks::tx_models::TransactionProcessedEvent;

/// Incoming Paymob webhook payload covering both `POST` JSON callbacks
/// (Protocols A, C, D, E) and Protocol B `GET` redirect query strings.
///
/// Implements a `[REDACTED]`-safe [`fmt::Debug`] formatter so raw payloads,
/// query strings, and HMAC digests never leak into application logs.
///
/// # Examples
///
/// ```rust
/// use some_paymob::adapter::webhook_adapter::UnifiedWebhookPayload;
///
/// let post = UnifiedWebhookPayload::post_json("{\"type\":\"TRANSACTION\"}", Some("deadbeef"));
/// let debug_out = format!("{post:?}");
/// assert!(debug_out.contains("[REDACTED]"));
/// assert!(!debug_out.contains("deadbeef"));
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnifiedWebhookPayload<'a> {
    /// Server-to-server `POST` JSON webhook callback (Protocols A, C, D, or E).
    PostJson {
        /// Raw UTF-8 JSON request body.
        raw_body: &'a str,
        /// Optional `?hmac=` hex digest extracted from the request query string.
        signature_hmac: Option<&'a str>,
    },
    /// Client-side `GET` redirect callback (Protocol B Transaction Response).
    GetRedirect {
        /// Raw URL query string (with or without a leading `'?'`), including `hmac`.
        query_string: &'a str,
    },
}

impl<'a> UnifiedWebhookPayload<'a> {
    /// Constructs a [`Self::PostJson`] webhook payload.
    #[must_use]
    pub const fn post_json(raw_body: &'a str, signature_hmac: Option<&'a str>) -> Self {
        Self::PostJson {
            raw_body,
            signature_hmac,
        }
    }

    /// Constructs a [`Self::GetRedirect`] webhook payload for Protocol B redirects.
    #[must_use]
    pub const fn get_redirect(query_string: &'a str) -> Self {
        Self::GetRedirect { query_string }
    }
}

impl fmt::Debug for UnifiedWebhookPayload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PostJson {
                raw_body,
                signature_hmac,
            } => f
                .debug_struct("UnifiedWebhookPayload::PostJson")
                .field("raw_body_len", &raw_body.len())
                .field("raw_body", &"[REDACTED]")
                .field("signature_hmac", &signature_hmac.map(|_| "[REDACTED]"))
                .finish(),
            Self::GetRedirect { query_string } => f
                .debug_struct("UnifiedWebhookPayload::GetRedirect")
                .field("query_string_len", &query_string.len())
                .field("query_string", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Rich, gateway-normalized webhook event extracted after cryptographic verification.
///
/// Combines the base [`crate::adapter::traits::UnifiedWebhookOutcome`] metadata
/// (`kind`, `event_type`, `idempotency_key`, `correlation_id`) with strongly-typed
/// transaction, order, monetary, status, and payout attributes.
///
/// Implements a `[REDACTED]`-safe [`fmt::Debug`] formatter that redacts
/// [`Self::correlation_id`] and [`Self::order_reference`] as `"[REDACTED]"`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichWebhookEvent {
    /// High-level normalized webhook classification.
    pub kind: UnifiedWebhookKind,
    /// Canonical `snake_case` Paymob event type identifier.
    pub event_type: &'static str,
    /// Deterministic idempotency key for deduplicating webhook retries.
    pub idempotency_key: String,
    /// Order, subscription, or payout correlation identifier (redacted in `Debug`).
    pub correlation_id: String,
    /// Acquiring transaction identifier, when applicable.
    pub transaction_id: Option<String>,
    /// Merchant or gateway order/subscription reference (redacted in `Debug`).
    pub order_reference: Option<String>,
    /// Monetary amount in integer minor units, when present on the event.
    pub amount_minor: Option<MinorUnitAmount>,
    /// Three-letter ISO-4217 currency code, when present on the event.
    pub currency: Option<String>,
    /// Whether the underlying operation succeeded, when reported.
    pub success: Option<bool>,
    /// Whether the underlying operation is still pending, when reported.
    pub pending: Option<bool>,
    /// Paymob Send disbursement or top-up identifier, for Protocol E events.
    pub payout_id: Option<String>,
    /// Normalized lifecycle or settlement status label, when available.
    pub status: Option<String>,
}

impl fmt::Debug for RichWebhookEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted_order = self.order_reference.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("RichWebhookEvent")
            .field("kind", &self.kind)
            .field("event_type", &self.event_type)
            .field("idempotency_key", &self.idempotency_key)
            .field("correlation_id", &"[REDACTED]")
            .field("transaction_id", &self.transaction_id)
            .field("order_reference", &redacted_order)
            .field("amount_minor", &self.amount_minor)
            .field("currency", &self.currency)
            .field("success", &self.success)
            .field("pending", &self.pending)
            .field("payout_id", &self.payout_id)
            .field("status", &self.status)
            .finish()
    }
}

/// Normalizes any verified [`WebhookEvent`] (Protocols A–E) into a [`RichWebhookEvent`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::adapter::traits::UnifiedWebhookKind;
/// use some_paymob::adapter::webhook_adapter::normalize_rich_webhook_event;
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::webhooks::WebhookEvent;
/// use some_paymob::webhooks::protocol_e_payouts::{TopupCallback, TopupStatus};
///
/// let event = WebhookEvent::PayoutTopup(TopupCallback {
///     topup_id: "topup_42".to_owned(),
///     amount_cents: 100_000,
///     currency: "EGP".to_owned(),
///     status: TopupStatus::Approved,
/// });
/// let rich = normalize_rich_webhook_event(&event);
/// assert_eq!(rich.kind, UnifiedWebhookKind::PayoutTopup);
/// assert_eq!(rich.payout_id.as_deref(), Some("topup_42"));
/// assert_eq!(rich.amount_minor, Some(MinorUnitAmount::new(100_000)));
/// assert_eq!(rich.success, Some(true));
/// ```
#[must_use]
pub fn normalize_rich_webhook_event(event: &WebhookEvent) -> RichWebhookEvent {
    let base = base_rich_event(event);
    if let Some(enriched) = enrich_acquiring_event(base.clone(), event) {
        return enriched;
    }
    enrich_lifecycle_or_payout_event(base, event)
}

/// Verifies an incoming Paymob webhook payload (either `POST` JSON for Protocols A, C, D, E
/// or Protocol B `GET` redirect query string) in constant time and normalizes it into a
/// [`RichWebhookEvent`].
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] if `hmac_secret` is not configured on `client`,
/// or [`PaymobError::WebhookError`] if signature verification or payload parsing fails.
///
/// # Examples
///
/// ```rust
/// use some_paymob::adapter::traits::UnifiedWebhookKind;
/// use some_paymob::adapter::webhook_adapter::{
///     UnifiedWebhookPayload, verify_and_normalize_webhook,
/// };
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::HmacSecret;
/// use some_paymob::core::region::PaymobRegion;
/// use some_paymob::core::types::MinorUnitAmount;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .hmac_secret(HmacSecret::new("3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE")?)
///     .build()?;
/// let client = PaymobClient::new(config)?;
/// let query = concat!(
///     "amount_cents=50000&created_at=2024-06-25T15%3A16%3A25.910710%2B04%3A00",
///     "&currency=EGP&error_occured=false&has_parent_transaction=false&id=316004",
///     "&integration_id=2936&is_3d_secure=true&is_auth=false&is_capture=false",
///     "&is_refunded=false&is_standalone_payment=true&is_voided=false&order=378804",
///     "&owner=211&pending=false&source_data.pan=2346&source_data.sub_type=MasterCard",
///     "&source_data.type=card&success=true",
///     "&hmac=5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5",
///     "826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812"
/// );
/// let rich = verify_and_normalize_webhook(&client, &UnifiedWebhookPayload::get_redirect(query))?;
/// assert_eq!(rich.kind, UnifiedWebhookKind::TransactionRedirect);
/// assert_eq!(rich.transaction_id.as_deref(), Some("316004"));
/// assert_eq!(rich.amount_minor, Some(MinorUnitAmount::new(50_000)));
/// # Ok(())
/// # }
/// ```
pub fn verify_and_normalize_webhook(
    client: &PaymobClient,
    payload: &UnifiedWebhookPayload<'_>,
) -> Result<RichWebhookEvent, PaymobError> {
    let event = verify_webhook_payload(client, payload)?;
    Ok(normalize_rich_webhook_event(&event))
}

fn verify_webhook_payload(
    client: &PaymobClient,
    payload: &UnifiedWebhookPayload<'_>,
) -> Result<WebhookEvent, PaymobError> {
    let engine = client.webhooks()?;
    match payload {
        UnifiedWebhookPayload::PostJson {
            raw_body,
            signature_hmac,
        } => engine
            .construct_event(raw_body, *signature_hmac)
            .map_err(|err| PaymobError::WebhookError(err.to_string())),
        UnifiedWebhookPayload::GetRedirect { query_string } => engine
            .verify_transaction_get_query_str(query_string)
            .map(WebhookEvent::TransactionResponseRedirect)
            .map_err(|err| PaymobError::WebhookError(err.to_string())),
    }
}

fn base_rich_event(event: &WebhookEvent) -> RichWebhookEvent {
    let outcome = normalize_webhook_event(event);
    RichWebhookEvent {
        kind: outcome.kind,
        event_type: outcome.event_type,
        idempotency_key: outcome.idempotency_key,
        correlation_id: outcome.correlation_id,
        transaction_id: None,
        order_reference: None,
        amount_minor: None,
        currency: None,
        success: None,
        pending: None,
        payout_id: None,
        status: None,
    }
}

fn enrich_acquiring_event(
    base: RichWebhookEvent,
    event: &WebhookEvent,
) -> Option<RichWebhookEvent> {
    match event {
        WebhookEvent::TransactionProcessed(evt) => Some(enrich_transaction_post(base, evt)),
        WebhookEvent::TransactionResponseRedirect(params) => {
            Some(enrich_transaction_redirect(base, params))
        }
        WebhookEvent::CardTokenSaved(evt) => Some(enrich_card_token(base, evt)),
        _ => None,
    }
}

fn enrich_lifecycle_or_payout_event(
    base: RichWebhookEvent,
    event: &WebhookEvent,
) -> RichWebhookEvent {
    match event {
        WebhookEvent::SubscriptionLifecycle(evt) => enrich_subscription(base, evt),
        WebhookEvent::PayoutDisbursement(cb) => enrich_payout_disbursement(base, cb),
        WebhookEvent::PayoutTopup(cb) => enrich_payout_topup(base, cb),
        _ => base,
    }
}

fn enrich_transaction_post(
    mut base: RichWebhookEvent,
    evt: &TransactionProcessedEvent,
) -> RichWebhookEvent {
    base.transaction_id = Some(evt.transaction_id().to_string());
    base.order_reference = Some(evt.order_id().to_string());
    base.amount_minor = Some(evt.amount());
    base.currency = Some(evt.currency().to_owned());
    base.success = Some(evt.obj.success);
    base.pending = Some(evt.obj.pending);
    base.status =
        Some(tx_status_label(evt.obj.success, evt.obj.pending, evt.obj.error_occured).to_owned());
    base
}

fn enrich_transaction_redirect(
    mut base: RichWebhookEvent,
    params: &TransactionRedirectParams,
) -> RichWebhookEvent {
    let success = params.success == "true";
    let pending = params.is_pending();
    base.transaction_id = Some(params.id.clone());
    base.order_reference = Some(params.order_id.clone());
    base.amount_minor = params.amount().ok();
    base.currency = Some(params.currency.clone());
    base.success = Some(success);
    base.pending = Some(pending);
    base.status = Some(tx_status_label(success, pending, params.has_error()).to_owned());
    base
}

fn enrich_card_token(mut base: RichWebhookEvent, evt: &CardTokenWebhookEvent) -> RichWebhookEvent {
    base.order_reference = Some(evt.obj.order_id.clone());
    base.status = Some("token_saved".to_owned());
    base
}

fn enrich_subscription(
    mut base: RichWebhookEvent,
    evt: &SubscriptionWebhookEvent,
) -> RichWebhookEvent {
    base.transaction_id = evt
        .subscription_data
        .initial_transaction
        .map(|id| id.to_string());
    base.order_reference = Some(evt.subscription_data.id.to_string());
    base.amount_minor = evt.subscription_data.amount();
    base.status = evt
        .subscription_data
        .state
        .clone()
        .or_else(|| Some(evt.trigger_type.as_wire().to_owned()));
    base
}

fn enrich_payout_disbursement(
    mut base: RichWebhookEvent,
    cb: &DisbursementCallback,
) -> RichWebhookEvent {
    let is_success =
        cb.status.eq_ignore_ascii_case("success") || cb.status.eq_ignore_ascii_case("succeeded");
    let is_pending = cb.status.eq_ignore_ascii_case("pending");
    base.amount_minor = Some(cb.amount());
    base.currency = Some(cb.currency.clone());
    base.success = Some(is_success);
    base.pending = Some(is_pending);
    base.payout_id = Some(cb.transaction_id.clone());
    base.status = Some(cb.status.clone());
    base
}

fn enrich_payout_topup(mut base: RichWebhookEvent, cb: &TopupCallback) -> RichWebhookEvent {
    base.amount_minor = Some(cb.amount());
    base.currency = Some(cb.currency.clone());
    base.success = Some(cb.status == TopupStatus::Approved);
    base.pending = Some(false);
    base.payout_id = Some(cb.topup_id.clone());
    base.status = Some(topup_status_label(cb.status).to_owned());
    base
}

const fn tx_status_label(success: bool, pending: bool, error_occured: bool) -> &'static str {
    if pending {
        return "pending";
    }
    if success && !error_occured {
        return "succeeded";
    }
    "failed"
}

const fn topup_status_label(status: TopupStatus) -> &'static str {
    match status {
        TopupStatus::Approved => "approved",
        TopupStatus::Rejected => "rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::HmacSecret;
    use crate::core::region::PaymobRegion;
    use crate::webhooks::protocol_c_token::CardTokenObj;
    use crate::webhooks::protocol_d_subscription::{SubscriptionData, SubscriptionTriggerType};
    use crate::webhooks::protocol_e_payouts::DisbursementIssuer;

    const TEST_HMAC_SECRET: &str = "3qUAg2xx6JW89Qav5GzzmXoalgjf5XxE";
    const TEST_CANONICAL_HMAC: &str = concat!(
        "5839e3844172a1ce57a5e05dc8a47d57235d080bd7f497ed2ae7cc54bc6249d5",
        "826ef93f1d502f8d354d775ecb5bd519a02ee730028137b07e66fed2bb6c1812"
    );

    fn client_with_hmac() -> PaymobClient {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .hmac_secret(HmacSecret::new(TEST_HMAC_SECRET).expect("valid hmac secret"))
            .build()
            .expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    fn protocol_a_post_json() -> &'static str {
        r#"{
            "type": "TRANSACTION",
            "obj": {
                "id": 316004,
                "pending": false,
                "amount_cents": 50000,
                "success": true,
                "is_auth": false,
                "is_capture": false,
                "is_standalone_payment": true,
                "is_voided": false,
                "is_refunded": false,
                "is_3d_secure": true,
                "integration_id": 2936,
                "has_parent_transaction": false,
                "order": { "id": 378804 },
                "created_at": "2024-06-25T15:16:25.910710+04:00",
                "currency": "EGP",
                "source_data": {
                    "pan": "2346",
                    "sub_type": "MasterCard",
                    "type": "card"
                },
                "error_occured": false,
                "owner": 211
            }
        }"#
    }

    fn protocol_b_redirect_query() -> String {
        format!(
            concat!(
                "?amount_cents=50000&created_at=2024-06-25T15%3A16%3A25.910710%2B04%3A00",
                "&currency=EGP&error_occured=false&has_parent_transaction=false&id=316004",
                "&integration_id=2936&is_3d_secure=true&is_auth=false&is_capture=false",
                "&is_refunded=false&is_standalone_payment=true&is_voided=false&order=378804",
                "&owner=211&pending=false&source_data.pan=2346&source_data.sub_type=MasterCard",
                "&source_data.type=card&success=true&hmac={}"
            ),
            TEST_CANONICAL_HMAC
        )
    }

    fn assert_canonical_tx_rich_event(rich: &RichWebhookEvent, expected_kind: UnifiedWebhookKind) {
        assert_eq!(rich.kind, expected_kind);
        assert_eq!(rich.transaction_id.as_deref(), Some("316004"));
        assert_eq!(rich.order_reference.as_deref(), Some("378804"));
        assert_eq!(rich.amount_minor, Some(MinorUnitAmount::new(50_000)));
        assert_eq!(rich.currency.as_deref(), Some("EGP"));
        assert_eq!(rich.success, Some(true));
        assert_eq!(rich.pending, Some(false));
        assert_eq!(rich.payout_id, None);
        assert_eq!(rich.status.as_deref(), Some("succeeded"));
    }

    #[test]
    fn verify_and_normalize_protocol_a_post_extracts_rich_fields() {
        let client = client_with_hmac();
        let payload =
            UnifiedWebhookPayload::post_json(protocol_a_post_json(), Some(TEST_CANONICAL_HMAC));
        let rich =
            verify_and_normalize_webhook(&client, &payload).expect("protocol A POST should verify");

        assert_canonical_tx_rich_event(&rich, UnifiedWebhookKind::TransactionProcessed);
        assert_eq!(rich.event_type, "transaction_processed");

        let dbg = format!("{rich:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("378804"));
    }

    #[test]
    fn verify_and_normalize_protocol_b_get_extracts_rich_fields() {
        let client = client_with_hmac();
        let query = protocol_b_redirect_query();
        let payload = UnifiedWebhookPayload::get_redirect(&query);
        let rich =
            verify_and_normalize_webhook(&client, &payload).expect("protocol B GET should verify");

        assert_canonical_tx_rich_event(&rich, UnifiedWebhookKind::TransactionRedirect);
        assert_eq!(rich.event_type, "transaction_redirect");
    }

    #[test]
    fn verify_and_normalize_rejects_tampered_protocol_b_hmac_and_missing_secret() {
        let client = client_with_hmac();
        let tampered = protocol_b_redirect_query().replace("amount_cents=50000", "amount_cents=1");
        let err =
            verify_and_normalize_webhook(&client, &UnifiedWebhookPayload::get_redirect(&tampered))
                .expect_err("tampered query must fail");
        assert!(matches!(err, PaymobError::WebhookError(_)));

        let unconfigured = PaymobClient::new(
            ClientConfig::builder()
                .region(PaymobRegion::Egypt)
                .build()
                .expect("config"),
        )
        .expect("client");
        let err = verify_and_normalize_webhook(
            &unconfigured,
            &UnifiedWebhookPayload::post_json("{}", None),
        )
        .expect_err("missing hmac_secret must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "hmac_secret",
                ..
            }
        ));
    }

    #[test]
    fn normalize_rich_webhook_event_covers_card_token() {
        let token_evt = WebhookEvent::CardTokenSaved(CardTokenWebhookEvent {
            event_type: "TOKEN".to_owned(),
            obj: CardTokenObj {
                id: 101,
                token: "tok_secret_value".to_owned(),
                masked_pan: "xxxx-xxxx-xxxx-2346".to_owned(),
                merchant_id: 99,
                card_subtype: "Visa".to_owned(),
                created_at: "2026-11-20T00:00:00Z".to_owned(),
                email: "user@example.com".to_owned(),
                order_id: "ORD-77".to_owned(),
            },
        });
        let rich_tok = normalize_rich_webhook_event(&token_evt);
        assert_eq!(rich_tok.kind, UnifiedWebhookKind::CardTokenSaved);
        assert_eq!(rich_tok.order_reference.as_deref(), Some("ORD-77"));
        assert_eq!(rich_tok.status.as_deref(), Some("token_saved"));
    }

    #[test]
    fn normalize_rich_webhook_event_covers_subscription() {
        let sub_evt = WebhookEvent::SubscriptionLifecycle(SubscriptionWebhookEvent {
            trigger_type: SubscriptionTriggerType::Suspended,
            subscription_data: SubscriptionData {
                id: 1264,
                state: Some("suspended".to_owned()),
                amount_cents: Some(3_300),
                initial_transaction: Some(888),
                ..Default::default()
            },
            paymob_request_id: "req-1264".to_owned(),
            hmac: None,
        });
        let rich_sub = normalize_rich_webhook_event(&sub_evt);
        assert_eq!(rich_sub.kind, UnifiedWebhookKind::SubscriptionLifecycle);
        assert_eq!(rich_sub.transaction_id.as_deref(), Some("888"));
        assert_eq!(rich_sub.order_reference.as_deref(), Some("1264"));
        assert_eq!(rich_sub.amount_minor, Some(MinorUnitAmount::new(3_300)));
        assert_eq!(rich_sub.status.as_deref(), Some("suspended"));
    }

    #[test]
    fn normalize_rich_webhook_event_covers_payout_disbursement() {
        let disb_evt = WebhookEvent::PayoutDisbursement(DisbursementCallback {
            transaction_id: "disb_9001".to_owned(),
            issuer: DisbursementIssuer::BankWallet,
            amount_cents: 25_000,
            currency: "EGP".to_owned(),
            status: "success".to_owned(),
            recipient_identifier: Some("+201001234567".to_owned()),
        });
        let rich_disb = normalize_rich_webhook_event(&disb_evt);
        assert_eq!(rich_disb.kind, UnifiedWebhookKind::PayoutDisbursement);
        assert_eq!(rich_disb.payout_id.as_deref(), Some("disb_9001"));
        assert_eq!(rich_disb.amount_minor, Some(MinorUnitAmount::new(25_000)));
        assert_eq!(rich_disb.success, Some(true));
        assert_eq!(rich_disb.pending, Some(false));
    }

    #[test]
    fn unified_webhook_payload_debug_redacts_secrets() {
        let post = UnifiedWebhookPayload::post_json("{\"secret\":\"123\"}", Some("hmac_abc"));
        let post_dbg = format!("{post:?}");
        assert!(post_dbg.contains("[REDACTED]"));
        assert!(!post_dbg.contains("hmac_abc"));
        assert!(!post_dbg.contains("123"));

        let get = UnifiedWebhookPayload::get_redirect("id=1&hmac=secret_sig");
        let get_dbg = format!("{get:?}");
        assert!(get_dbg.contains("[REDACTED]"));
        assert!(!get_dbg.contains("secret_sig"));
    }
}
