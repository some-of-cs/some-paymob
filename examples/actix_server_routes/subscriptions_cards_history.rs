#![forbid(unsafe_code)]
//! Service 8c: Subscription Cards Vault, History & Composite Last-Transaction Refund.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::{Value, json};
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

fn card_json(c: &SubscriptionCard) -> Value {
    json!({
        "id": c.id,
        "masked_pan": c.masked_pan,
        "is_primary": c.is_primary,
        "failed_attempts": c.failed_attempts,
        "token": "[REDACTED]",
    })
}

fn tx_json(id: u64, amount_cents: u64, success: bool, is_refunded: bool) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "id": id,
        "amount_cents": amount_cents,
        "success": success,
        "is_refunded": is_refunded,
    }))
}

#[derive(Debug, Deserialize)]
pub struct CardMutationPayload {
    pub card_token: Option<String>,
    pub card_id: Option<u64>,
    pub integration_id: Option<u64>,
    pub redirect_url: Option<String>,
}

async fn mutate_card(
    state: &web::Data<AppState>,
    sub_id: u64,
    body: &CardMutationPayload,
    promote_primary: bool,
) -> Result<HttpResponse, ApiServerError> {
    let cards = state.client.subscriptions().cards();
    let card = if promote_primary {
        let cid = body.card_id.ok_or_else(|| PaymobError::ValidationError {
            field: "card_id",
            reason: "card_id is required".to_owned(),
        })?;
        cards.change_primary(sub_id, cid).await?
    } else {
        let tok = body
            .card_token
            .as_deref()
            .ok_or_else(|| PaymobError::ValidationError {
                field: "card_token",
                reason: "card_token is required".to_owned(),
            })?;
        let mut p = AddSecondaryCardParams::new(tok)?;
        if let Some(id) = body.integration_id {
            p = p.with_integration_id(id);
        }
        if let Some(url) = &body.redirect_url {
            p = p.with_redirect_url(url)?;
        }
        cards.add_secondary(sub_id, p).await?
    };
    Ok(HttpResponse::Ok().json(card_json(&card)))
}

#[derive(Clone, Copy)]
enum ReadSubOp {
    Cards,
    LastTx,
    TxList,
}

async fn run_read_op(
    state: &web::Data<AppState>,
    sub_id: u64,
    op: ReadSubOp,
) -> Result<HttpResponse, ApiServerError> {
    let svc = state.client.subscriptions();
    match op {
        ReadSubOp::Cards => {
            let cards = svc.cards().list(sub_id).await?;
            let items: Vec<Value> = cards.iter().map(card_json).collect();
            Ok(HttpResponse::Ok().json(json!({ "count": items.len(), "cards": items })))
        }
        ReadSubOp::LastTx => {
            let tx = svc.last_transaction(sub_id).await?;
            Ok(tx_json(tx.id, tx.amount_cents, tx.success, tx.is_refunded))
        }
        ReadSubOp::TxList => {
            let txs = svc.list_transactions(sub_id).await?;
            Ok(HttpResponse::Ok().json(json!({ "count": txs.len() })))
        }
    }
}

/// `GET /subscriptions/{sub_id}/cards` — Lists cards attached to a subscription.
pub async fn list_cards(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    run_read_op(&state, path.into_inner(), ReadSubOp::Cards).await
}

/// `POST /subscriptions/{sub_id}/cards/secondary` — Adds a secondary card to a subscription.
pub async fn add_secondary_card(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<CardMutationPayload>,
) -> Result<HttpResponse, ApiServerError> {
    mutate_card(&state, path.into_inner(), &body, false).await
}

/// `POST /subscriptions/{sub_id}/cards/primary` — Switches the primary subscription card.
pub async fn change_primary_card(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<CardMutationPayload>,
) -> Result<HttpResponse, ApiServerError> {
    mutate_card(&state, path.into_inner(), &body, true).await
}

/// `DELETE /subscriptions/{sub_id}/cards/{card_id}` — Deletes a secondary card.
pub async fn delete_secondary_card(
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
) -> Result<HttpResponse, ApiServerError> {
    let (sub_id, card_id) = path.into_inner();
    let resp = state
        .client
        .subscriptions()
        .cards()
        .delete_secondary(sub_id, card_id)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "detail": resp.detail,
        "message": resp.message,
    })))
}

#[derive(Debug, Deserialize)]
pub struct RegisterWebhookPayload {
    pub webhook_url: String,
}

/// `POST /subscriptions/{sub_id}/webhook` — Registers a subscription webhook URL.
pub async fn register_webhook(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<RegisterWebhookPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let reg = state
        .client
        .subscriptions()
        .register_webhook(path.into_inner(), &body.webhook_url)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": reg.id,
        "webhook_url": reg.webhook_url,
        "detail": reg.detail,
    })))
}

/// `GET /subscriptions/{sub_id}/last-transaction` — Fetches the latest subscription transaction.
pub async fn last_transaction(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    run_read_op(&state, path.into_inner(), ReadSubOp::LastTx).await
}

/// `GET /subscriptions/{sub_id}/transactions` — Lists subscription transactions.
pub async fn list_transactions(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    run_read_op(&state, path.into_inner(), ReadSubOp::TxList).await
}

#[derive(Debug, Deserialize)]
pub struct RefundLastTxPayload {
    pub amount_cents: Option<u64>,
}

/// `POST /subscriptions/{sub_id}/refund-last-transaction` — Refunds the latest subscription charge.
pub async fn refund_last_transaction(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<RefundLastTxPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let r = state
        .client
        .subscriptions()
        .refund_last_transaction(path.into_inner(), body.amount_cents)
        .await?;
    Ok(tx_json(r.id, r.amount_cents, r.success, r.is_refunded))
}

/// Registers Service 8c routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/subscriptions/{sub_id}/cards", web::get().to(list_cards))
        .route(
            "/subscriptions/{sub_id}/cards/secondary",
            web::post().to(add_secondary_card),
        )
        .route(
            "/subscriptions/{sub_id}/cards/primary",
            web::post().to(change_primary_card),
        )
        .route(
            "/subscriptions/{sub_id}/cards/{card_id}",
            web::delete().to(delete_secondary_card),
        )
        .route(
            "/subscriptions/{sub_id}/webhook",
            web::post().to(register_webhook),
        )
        .route(
            "/subscriptions/{sub_id}/last-transaction",
            web::get().to(last_transaction),
        )
        .route(
            "/subscriptions/{sub_id}/transactions",
            web::get().to(list_transactions),
        )
        .route(
            "/subscriptions/{sub_id}/refund-last-transaction",
            web::post().to(refund_last_transaction),
        );
}
