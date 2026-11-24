#![forbid(unsafe_code)]
//! Service 11a: Constant-Time HMAC-SHA512 Webhooks (Protocols A–E + Replay Deduplication).

use std::fmt;

use actix_web::{HttpRequest, HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

#[derive(Deserialize)]
pub struct HmacQuery {
    pub hmac: Option<String>,
}

impl fmt::Debug for HmacQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HmacQuery")
            .field("hmac", &self.hmac.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// `POST /webhooks/paymob` — Verifies Protocols A, C, D, or E and guards against replays.
pub async fn handle_webhook_post(
    state: web::Data<AppState>,
    query: web::Query<HmacQuery>,
    body: web::Bytes,
) -> Result<HttpResponse, ApiServerError> {
    let engine = state.client.webhooks()?;
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

/// `GET /webhooks/paymob/redirect` — Verifies Protocol B redirect query string (rejecting duplicate keys) and guards against replay.
pub async fn handle_webhook_redirect(
    state: web::Data<AppState>,
    req: HttpRequest,
) -> Result<HttpResponse, ApiServerError> {
    let engine = state.client.webhooks()?;
    let params = engine.verify_transaction_get_query_str(req.query_string())?;
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
