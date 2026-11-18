#![forbid(unsafe_code)]
//! Service 11a: Constant-Time HMAC-SHA512 Webhooks (Protocols A–E + Replay Deduplication).

use std::collections::BTreeMap;

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

#[derive(Debug, Deserialize)]
pub struct HmacQuery {
    pub hmac: Option<String>,
}

pub(crate) fn build_webhook_engine(
    state: &AppState,
) -> Result<PaymobWebhookEngine, ApiServerError> {
    let secret = state.client.config().hmac_secret().ok_or_else(|| {
        PaymobError::AuthenticationError("HMAC secret is not configured".to_owned())
    })?;
    Ok(PaymobWebhookEngine::new(secret.expose_secret())?)
}

/// `POST /webhooks/paymob` — Verifies Protocols A, C, D, or E and guards against replays.
pub async fn handle_webhook_post(
    state: web::Data<AppState>,
    query: web::Query<HmacQuery>,
    body: web::Bytes,
) -> Result<HttpResponse, ApiServerError> {
    let engine = build_webhook_engine(&state)?;
    let event = engine.construct_event_from_slice(&body, query.hmac.as_deref())?;
    state.webhook_dedup.claim_or_reject(&event)?;
    let (idempotency_key, correlation_id) = event.idempotency_tuple();
    Ok(HttpResponse::Ok().json(json!({
        "verified": true,
        "kind": event.event_type(),
        "idempotency_key": idempotency_key,
        "correlation_id": correlation_id,
    })))
}

/// `GET /webhooks/paymob/redirect` — Verifies Protocol B redirect query parameters and guards against replay.
pub async fn handle_webhook_redirect(
    state: web::Data<AppState>,
    query: web::Query<BTreeMap<String, String>>,
) -> Result<HttpResponse, ApiServerError> {
    let engine = build_webhook_engine(&state)?;
    let params = engine.verify_transaction_get(&query.into_inner())?;
    state.webhook_dedup.claim_or_reject(&params)?;
    Ok(HttpResponse::Ok().json(json!({
        "verified": true,
        "transaction_id": params.id,
        "order_id": params.order_id,
        "success": params.success,
        "amount_cents": params.amount_cents,
    })))
}

/// Registers Service 11a routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/webhooks/paymob", web::post().to(handle_webhook_post))
        .route(
            "/webhooks/paymob/redirect",
            web::get().to(handle_webhook_redirect),
        );
}
