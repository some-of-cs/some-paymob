#![forbid(unsafe_code)]
//! Service 11b: `some-payments-adapter` Unified Cross-Gateway Endpoints.

use actix_web::{HttpResponse, web};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::webhooks::build_webhook_engine;
use super::{ApiServerError, AppState, parse_currency};

#[derive(Debug, Deserialize)]
pub struct UnifiedSessionPayload {
    pub amount_cents: u64,
    pub currency: String,
    pub payment_methods: Vec<String>,
    pub customer_phone: Option<String>,
    pub customer_email: Option<String>,
    pub special_reference: Option<String>,
}

/// `POST /unified/sessions` — Creates a unified payment session.
pub async fn create_session(
    state: web::Data<AppState>,
    body: web::Json<UnifiedSessionPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let mut req =
        UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(body.amount_cents), currency)
            .with_payment_methods(body.payment_methods.clone());
    req.customer_email = body.customer_email.clone();
    req.customer_phone = body.customer_phone.clone();
    if let Some(sr) = &body.special_reference {
        req = req.with_special_reference(sr);
    }
    let session = state.client.create_payment_session(&req).await?;
    Ok(HttpResponse::Created().json(json!({
        "session_id": session.session_id,
        "order_id": session.order_id,
        "checkout_url": session.checkout_url,
        "status": session.status,
        "client_secret": "[REDACTED]",
    })))
}

#[derive(Debug, Deserialize)]
pub struct UnifiedCapturePayload {
    pub transaction_id: u64,
    pub amount_cents: u64,
}

async fn run_tx_amount_op(
    state: &web::Data<AppState>,
    body: &UnifiedCapturePayload,
    is_refund: bool,
) -> Result<HttpResponse, ApiServerError> {
    let amt = MinorUnitAmount::new(body.amount_cents);
    if is_refund {
        let req = UnifiedRefundRequest::new(body.transaction_id, amt);
        let r = state.client.refund_payment(&req).await?;
        Ok(HttpResponse::Ok().json(json!({
            "refund_id": r.refund_id,
            "amount_cents": r.amount.as_u64(),
            "success": r.success,
            "is_refunded": r.is_refunded,
        })))
    } else {
        let req = UnifiedCaptureRequest::new(body.transaction_id, amt);
        let r = state.client.capture_payment(&req).await?;
        Ok(HttpResponse::Ok().json(json!({
            "transaction_id": r.transaction_id,
            "amount_cents": r.amount.as_u64(),
            "success": r.success,
        })))
    }
}

/// `POST /unified/capture` — Captures an authorized payment via unified trait.
pub async fn capture(
    state: web::Data<AppState>,
    body: web::Json<UnifiedCapturePayload>,
) -> Result<HttpResponse, ApiServerError> {
    run_tx_amount_op(&state, &body, false).await
}

/// `POST /unified/refund` — Refunds a transaction via unified trait.
pub async fn refund(
    state: web::Data<AppState>,
    body: web::Json<UnifiedCapturePayload>,
) -> Result<HttpResponse, ApiServerError> {
    run_tx_amount_op(&state, &body, true).await
}

#[derive(Debug, Deserialize)]
pub struct UnifiedVoidPayload {
    pub transaction_id: u64,
}

/// `POST /unified/void` — Voids an unsettled transaction via unified trait.
pub async fn void(
    state: web::Data<AppState>,
    body: web::Json<UnifiedVoidPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let req = UnifiedVoidRequest::new(body.transaction_id);
    let receipt = state.client.void_payment(&req).await?;
    Ok(HttpResponse::Ok().json(json!({
        "transaction_id": receipt.transaction_id,
        "success": receipt.success,
        "is_voided": receipt.is_voided,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UnifiedChargeSavedPayload {
    pub payment_token: String,
    pub saved_method_token: String,
    pub cvn: Option<String>,
}

/// `POST /unified/charge-saved` — Charges a saved card via unified trait.
pub async fn charge_saved(
    state: web::Data<AppState>,
    body: web::Json<UnifiedChargeSavedPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut req = UnifiedSavedMethodChargeRequest::new(
        SecretString::from(body.payment_token.clone()),
        SecretString::from(body.saved_method_token.clone()),
    );
    if let Some(cvn) = &body.cvn {
        req = req.with_cvn(SecretString::from(cvn.clone()));
    }
    let receipt = state.client.charge_saved_method(&req).await?;
    Ok(HttpResponse::Ok().json(json!({
        "transaction_id": receipt.transaction_id,
        "success": receipt.success,
        "pending": receipt.pending,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UnifiedSubRefundPayload {
    pub subscription_id: u64,
    pub amount_cents: Option<u64>,
}

/// `POST /unified/subscriptions/refund` — Refunds last subscription tx via unified trait.
pub async fn sub_refund(
    state: web::Data<AppState>,
    body: web::Json<UnifiedSubRefundPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let req = UnifiedSubscriptionRefundRequest::new(
        body.subscription_id,
        body.amount_cents.map(MinorUnitAmount::new),
    );
    let receipt = state.client.refund_last_transaction(&req).await?;
    Ok(HttpResponse::Ok().json(json!({
        "refund_id": receipt.refund_id,
        "amount_cents": receipt.amount.as_u64(),
        "success": receipt.success,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UnifiedPayoutPayload {
    pub recipient_identifier: String,
    pub amount_cents: u64,
    pub currency: String,
    pub issuer: String,
    pub reference: Option<String>,
}

/// `POST /unified/payouts` — Executes a payout via unified trait.
pub async fn payout(
    state: web::Data<AppState>,
    body: web::Json<UnifiedPayoutPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let mut req = UnifiedPayoutRequest::new(
        &body.recipient_identifier,
        MinorUnitAmount::new(body.amount_cents),
        currency,
        &body.issuer,
    );
    if let Some(r) = &body.reference {
        req = req.with_reference(r);
    }
    let receipt = state.client.execute_payout(&req).await?;
    Ok(HttpResponse::Ok().json(json!({
        "payout_id": receipt.payout_id,
        "amount_cents": receipt.amount.as_u64(),
        "status": receipt.status,
        "issuer": receipt.issuer,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UnifiedWebhookQuery {
    pub hmac: Option<String>,
}

/// `POST /unified/webhooks` — Verifies, deduplicates, and normalizes a webhook via unified trait.
pub async fn webhook(
    state: web::Data<AppState>,
    query: web::Query<UnifiedWebhookQuery>,
    body: web::Bytes,
) -> Result<HttpResponse, ApiServerError> {
    let raw_body = std::str::from_utf8(&body).map_err(|_| {
        WebhookError::InvalidJsonPayload("request body is not valid UTF-8".to_owned())
    })?;
    let engine = build_webhook_engine(&state)?;
    let event = engine.construct_event(raw_body, query.hmac.as_deref())?;
    state.webhook_dedup.claim_or_reject(&event)?;
    let input = UnifiedWebhookInput::new(raw_body, query.hmac.as_deref());
    let outcome = state.client.verify_webhook(&input)?;
    Ok(HttpResponse::Ok().json(json!({
        "event_type": outcome.event_type,
        "idempotency_key": outcome.idempotency_key,
        "correlation_id": outcome.correlation_id,
    })))
}

/// Registers Service 11b routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/unified/sessions", web::post().to(create_session))
        .route("/unified/capture", web::post().to(capture))
        .route("/unified/refund", web::post().to(refund))
        .route("/unified/void", web::post().to(void))
        .route("/unified/charge-saved", web::post().to(charge_saved))
        .route("/unified/subscriptions/refund", web::post().to(sub_refund))
        .route("/unified/payouts", web::post().to(payout))
        .route("/unified/webhooks", web::post().to(webhook));
}
