#![forbid(unsafe_code)]
//! Services 4 & 5: Payment Lifecycle Management & Transaction/Order Inquiries.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::{Value, json};
use some_paymob::prelude::*;
use some_paymob::resources::manage::models::Transaction;

use super::{ApiServerError, AppState};

fn manage_tx_json(tx: &Transaction, flag_key: &str, flag_val: bool) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "id": tx.id,
        "success": tx.success,
        flag_key: flag_val,
        "amount_cents": tx.amount_cents,
    }))
}

#[derive(Debug, Deserialize)]
pub struct RefundPayload {
    pub transaction_id: u64,
    pub amount_cents: u64,
}

/// `POST /manage/refund` — Full or partial refund.
pub async fn manage_refund(
    state: web::Data<AppState>,
    body: web::Json<RefundPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = RefundParams::try_new(body.transaction_id, body.amount_cents)?;
    let tx = state.client.manage().refund(params).await?;
    Ok(manage_tx_json(&tx, "is_refund", tx.is_refund))
}

#[derive(Debug, Deserialize)]
pub struct VoidPayload {
    pub transaction_id: u64,
}

/// `POST /manage/void` — Voids an unsettled transaction.
pub async fn manage_void(
    state: web::Data<AppState>,
    body: web::Json<VoidPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = VoidParams::try_new(body.transaction_id)?;
    let tx = state.client.manage().void(params).await?;
    Ok(manage_tx_json(&tx, "is_void", tx.is_void))
}

#[derive(Debug, Deserialize)]
pub struct CapturePayload {
    pub transaction_id: u64,
    pub amount_cents: u64,
}

/// `POST /manage/capture` — Captures an authorized transaction.
pub async fn manage_capture(
    state: web::Data<AppState>,
    body: web::Json<CapturePayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = CaptureParams::try_new(body.transaction_id, body.amount_cents)?;
    let tx = state.client.manage().capture(params).await?;
    Ok(manage_tx_json(&tx, "is_capture", tx.is_capture))
}

/// `GET /inquiries/transactions/{tx_id}` — Fetches a transaction by ID.
pub async fn inquiry_transaction(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let tx = state
        .client
        .inquiries()
        .by_transaction_id(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": tx.id,
        "success": tx.success,
        "amount_cents": tx.amount_cents,
        "currency": tx.currency,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ByOrderPayload {
    pub order_id: Option<u64>,
    pub merchant_order_id: Option<String>,
}

/// `POST /inquiries/by-order` — Fetches a transaction by order ID or merchant reference.
pub async fn inquiry_by_order(
    state: web::Data<AppState>,
    body: web::Json<ByOrderPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = if let Some(oid) = body.order_id {
        some_paymob::resources::inquiries::TransactionInquiryParams {
            order_id: Some(oid),
            merchant_order_id: None,
        }
    } else if let Some(ref_id) = &body.merchant_order_id {
        some_paymob::resources::inquiries::TransactionInquiryParams::by_merchant_order_id(ref_id)
    } else {
        return Err(PaymobError::ValidationError {
            field: "order_id",
            reason: "order_id or merchant_order_id is required".to_owned(),
        }
        .into());
    };
    let tx = state
        .client
        .inquiries()
        .by_order_or_reference(params)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": tx.id,
        "success": tx.success,
        "amount_cents": tx.amount_cents,
    })))
}

/// `GET /inquiries/orders/{order_id}` — Fetches full order details.
pub async fn inquiry_order(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let order = state.client.inquiries().order(path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": order.id,
        "amount_cents": order.amount_cents,
        "paid_amount_cents": order.paid_amount_cents,
        "payment_status": order.payment_status,
    })))
}

/// `POST /inquiries/orders/{order_id}/card-tokens` — Lists saved card tokens for an order.
pub async fn inquiry_card_tokens(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let tokens = state
        .client
        .inquiries()
        .card_tokens(path.into_inner())
        .await?;
    let items: Vec<Value> = tokens
        .iter()
        .map(|t| {
            json!({
                "token_type": t.token_type,
                "id": t.obj.id,
                "masked_pan": t.obj.masked_pan,
                "card_subtype": t.obj.card_subtype,
            })
        })
        .collect();
    Ok(HttpResponse::Ok().json(json!({ "tokens": items })))
}

/// Registers Services 4 & 5 routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/manage/refund", web::post().to(manage_refund))
        .route("/manage/void", web::post().to(manage_void))
        .route("/manage/capture", web::post().to(manage_capture))
        .route(
            "/inquiries/transactions/{tx_id}",
            web::get().to(inquiry_transaction),
        )
        .route("/inquiries/by-order", web::post().to(inquiry_by_order))
        .route("/inquiries/orders/{order_id}", web::get().to(inquiry_order))
        .route(
            "/inquiries/orders/{order_id}/card-tokens",
            web::post().to(inquiry_card_tokens),
        );
}
