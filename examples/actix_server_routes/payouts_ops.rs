#![forbid(unsafe_code)]
//! Service 9b: Paymob Send Payouts Inquiries, Budget & Topups.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

fn inquiry_resp(resp: &TransactionInquiryResponse) -> Result<HttpResponse, ApiServerError> {
    Ok(HttpResponse::Ok().json(json!({
        "count": resp.results.len(),
        "status_code": resp.status_code,
        "status_description": resp.status_description,
    })))
}

fn topup_resp(rec: TopupRecord) -> Result<HttpResponse, ApiServerError> {
    Ok(HttpResponse::Ok().json(json!({
        "id": rec.id,
        "amount": rec.amount,
        "status": rec.status,
        "transfer_type": rec.transfer_type,
    })))
}

#[derive(Debug, Deserialize)]
pub struct PayoutInquiryPayload {
    #[serde(default)]
    pub transactions_ids: Vec<String>,
    #[serde(default)]
    pub client_reference_ids: Vec<String>,
    #[serde(default)]
    pub is_bulk: bool,
    pub bank_transactions: Option<bool>,
}

async fn run_inquiry(
    state: &web::Data<AppState>,
    body: &PayoutInquiryPayload,
    by_ref: bool,
) -> Result<HttpResponse, ApiServerError> {
    let inq = state.client.payouts().inquiries();
    let resp = if by_ref {
        let mut p = ReferenceInquiryParams::new(body.client_reference_ids.clone());
        if let Some(bt) = body.bank_transactions {
            p = p.with_bank_transactions(bt);
        }
        inq.by_reference(p).await?
    } else {
        let mut p =
            TransactionInquiryParams::new(body.transactions_ids.clone()).with_bulk(body.is_bulk);
        if let Some(bt) = body.bank_transactions {
            p = p.with_bank_transactions(bt);
        }
        inq.transactions(p).await?
    };
    inquiry_resp(&resp)
}

/// `POST /payouts/inquiries/transactions` — Inquires payout transactions by ID.
pub async fn inquire_transactions(
    state: web::Data<AppState>,
    body: web::Json<PayoutInquiryPayload>,
) -> Result<HttpResponse, ApiServerError> {
    run_inquiry(&state, &body, false).await
}

/// `POST /payouts/inquiries/by-reference` — Inquires payouts by client reference ID.
pub async fn inquire_by_reference(
    state: web::Data<AppState>,
    body: web::Json<PayoutInquiryPayload>,
) -> Result<HttpResponse, ApiServerError> {
    run_inquiry(&state, &body, true).await
}

/// `GET /payouts/inquiries/budget` — Fetches current Paymob Send user budget.
pub async fn inquire_budget(state: web::Data<AppState>) -> Result<HttpResponse, ApiServerError> {
    let resp = state.client.payouts().inquiries().user_budget().await?;
    Ok(HttpResponse::Ok().json(json!({
        "current_budget": resp.current_budget,
    })))
}

#[derive(Debug, Deserialize)]
pub struct TopupQuery {
    pub page: Option<u32>,
    pub id: Option<u64>,
}

/// `GET /payouts/inquiries/topups` — Lists or retrieves payout topup records.
pub async fn inquire_topups(
    state: web::Data<AppState>,
    query: web::Query<TopupQuery>,
) -> Result<HttpResponse, ApiServerError> {
    let params = TopupInquiryParams {
        page: query.page,
        id: query.id,
    };
    let resp = state.client.payouts().inquiries().topup(params).await?;
    Ok(HttpResponse::Ok().json(json!({
        "count": resp.results.len(),
        "total": resp.count,
    })))
}

#[derive(Debug, Deserialize)]
pub struct BankTransferTopupPayload {
    pub amount: u64,
    pub currency: String,
    pub proof_bytes: Vec<u8>,
    pub proof_filename: String,
    pub from_bank_name: Option<String>,
    pub reference_number: Option<String>,
}

/// `POST /payouts/topups/bank-transfer` — Submits a bank-transfer topup with proof attachment.
pub async fn topup_bank_transfer(
    state: web::Data<AppState>,
    body: web::Json<BankTransferTopupPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = BankTransferTopupParams {
        amount: body.amount,
        currency: body.currency.clone(),
        to_attach_proof: body.proof_bytes.clone(),
        proof_filename: body.proof_filename.clone(),
        from_bank_name: body.from_bank_name.clone(),
        reference_number: body.reference_number.clone(),
    };
    topup_resp(
        state
            .client
            .payouts()
            .topups()
            .from_bank_transfer(params)
            .await?,
    )
}

#[derive(Debug, Deserialize)]
pub struct AcceptBalanceTopupPayload {
    pub amount: u64,
    pub currency: String,
    pub username: String,
}

/// `POST /payouts/topups/accept-balance` — Transfers funds from Accept balance to Payouts.
pub async fn topup_accept_balance(
    state: web::Data<AppState>,
    body: web::Json<AcceptBalanceTopupPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = AcceptBalanceTopupParams::new(body.amount, &body.currency, &body.username);
    topup_resp(
        state
            .client
            .payouts()
            .topups()
            .from_accept_balance(params)
            .await?,
    )
}

/// Registers Service 9b routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/payouts/inquiries/transactions",
        web::post().to(inquire_transactions),
    )
    .route(
        "/payouts/inquiries/by-reference",
        web::post().to(inquire_by_reference),
    )
    .route("/payouts/inquiries/budget", web::get().to(inquire_budget))
    .route("/payouts/inquiries/topups", web::get().to(inquire_topups))
    .route(
        "/payouts/topups/bank-transfer",
        web::post().to(topup_bank_transfer),
    )
    .route(
        "/payouts/topups/accept-balance",
        web::post().to(topup_accept_balance),
    );
}
