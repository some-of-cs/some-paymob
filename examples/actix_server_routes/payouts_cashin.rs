#![forbid(unsafe_code)]
//! Service 9a: Paymob Send Payouts OAuth2 & Cashin (Wallet, Bank, Post, Aman, Bulk).

use actix_web::{HttpResponse, web};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

#[derive(Debug, Deserialize)]
pub struct RefreshTokenPayload {
    pub refresh_token: String,
}

fn token_json(tok: &PayoutsTokenResponse) -> serde_json::Value {
    json!({
        "token_type": tok.token_type,
        "expires_in": tok.expires_in,
        "scope": tok.scope,
        "access_token": "[REDACTED]",
        "refresh_token": "[REDACTED]",
    })
}

/// `POST /payouts/auth/token` — Acquires a Regime 3 OAuth 2.0 token.
pub async fn auth_token(state: web::Data<AppState>) -> Result<HttpResponse, ApiServerError> {
    let tok = state.client.payouts().auth().generate_token().await?;
    Ok(HttpResponse::Ok().json(token_json(&tok)))
}

/// `POST /payouts/auth/refresh` — Refreshes a Regime 3 OAuth 2.0 token.
pub async fn auth_refresh(
    state: web::Data<AppState>,
    body: web::Json<RefreshTokenPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let rt = SecretString::from(body.refresh_token.clone());
    let tok = state.client.payouts().auth().refresh_token(&rt).await?;
    Ok(HttpResponse::Ok().json(token_json(&tok)))
}

#[derive(Debug, Deserialize)]
pub struct WalletCashinPayload {
    pub msisdn: String,
    pub amount: u64,
    pub client_reference_id: Option<String>,
    pub customer_bears_fees: Option<bool>,
}

fn build_wallet_params(body: &WalletCashinPayload) -> MobileWalletCashinParams {
    let mut p = MobileWalletCashinParams::new(&body.msisdn, body.amount);
    if let Some(ref_id) = &body.client_reference_id {
        p = p.with_client_reference_id(ref_id);
    }
    if let Some(bears) = body.customer_bears_fees {
        p = p.with_customer_bears_fees(bears);
    }
    p
}

fn disburse_json(resp: &DisbursementResponse) -> serde_json::Value {
    json!({
        "transaction_id": resp.transaction_id,
        "issuer": resp.issuer,
        "amount": resp.amount,
        "disbursement_status": resp.disbursement_status,
        "status_code": resp.status_code,
        "status_description": resp.status_description,
    })
}

/// `POST /payouts/cashin/wallet/{issuer}` — Disburses to mobile/bank wallet issuers.
pub async fn cashin_wallet(
    state: web::Data<AppState>,
    path: web::Path<String>,
    body: web::Json<WalletCashinPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = build_wallet_params(&body);
    let cashin = state.client.payouts().cashin();
    let resp = match path.into_inner().trim().to_ascii_lowercase().as_str() {
        "vodafone" => cashin.vodafone(params).await?,
        "etisalat" => cashin.etisalat(params).await?,
        "orange" => cashin.orange(params).await?,
        "bank_wallet" => cashin.bank_wallet(params).await?,
        _ => {
            return Err(PaymobError::ValidationError {
                field: "issuer",
                reason: "unsupported wallet issuer (expected vodafone, etisalat, orange, or bank_wallet)".to_owned(),
            }
            .into());
        }
    };
    Ok(HttpResponse::Ok().json(disburse_json(&resp)))
}

#[derive(Debug, Deserialize)]
pub struct BankCardCashinPayload {
    pub amount: u64,
    pub bank_card_number: String,
    pub bank_code: String,
    pub bank_transaction_type: String,
    pub full_name: String,
    pub client_reference_id: Option<String>,
    pub customer_bears_fees: Option<bool>,
}

/// `POST /payouts/cashin/bank-card` — Disburses to a bank card.
pub async fn cashin_bank_card(
    state: web::Data<AppState>,
    body: web::Json<BankCardCashinPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let tx_type = BankTransactionType::from_wire(&body.bank_transaction_type).ok_or_else(|| {
        PaymobError::ValidationError {
            field: "bank_transaction_type",
            reason: "expected salary, credit_card, prepaid_card, or cash_transfer".to_owned(),
        }
    })?;
    let params = BankCardCashinParams {
        amount: body.amount,
        bank_card_number: SecretString::from(body.bank_card_number.clone()),
        bank_code: body.bank_code.clone(),
        bank_transaction_type: tx_type,
        full_name: body.full_name.clone(),
        client_reference_id: body.client_reference_id.clone(),
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = state.client.payouts().cashin().bank_card(params).await?;
    Ok(HttpResponse::Ok().json(disburse_json(&resp)))
}

#[derive(Debug, Deserialize)]
pub struct InstantBankCashinPayload {
    pub amount: u64,
    pub bank_code: String,
    pub bank_account_number: String,
    pub full_name: String,
    pub client_reference_id: Option<String>,
    pub customer_bears_fees: Option<bool>,
}

/// `POST /payouts/cashin/bank-instant` — Disburses via instant bank transfer.
pub async fn cashin_bank_instant(
    state: web::Data<AppState>,
    body: web::Json<InstantBankCashinPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = InstantBankCashinParams {
        amount: body.amount,
        bank_code: body.bank_code.clone(),
        bank_account_number: SecretString::from(body.bank_account_number.clone()),
        full_name: body.full_name.clone(),
        client_reference_id: body.client_reference_id.clone(),
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = state.client.payouts().cashin().bank_instant(params).await?;
    Ok(HttpResponse::Ok().json(disburse_json(&resp)))
}

#[derive(Debug, Deserialize)]
pub struct EgyptianPostCashinPayload {
    pub amount: u64,
    pub msisdn: String,
    pub full_name: String,
    pub national_id: String,
    pub client_reference_id: Option<String>,
    pub customer_bears_fees: Option<bool>,
}

/// `POST /payouts/cashin/egyptian-post` — Disburses via Egyptian Post.
pub async fn cashin_egyptian_post(
    state: web::Data<AppState>,
    body: web::Json<EgyptianPostCashinPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = EgyptianPostCashinParams {
        amount: body.amount,
        msisdn: body.msisdn.clone(),
        full_name: body.full_name.clone(),
        national_id: SecretString::from(body.national_id.clone()),
        client_reference_id: body.client_reference_id.clone(),
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = state.client.payouts().cashin().egyptian_post(params).await?;
    Ok(HttpResponse::Ok().json(disburse_json(&resp)))
}

#[derive(Debug, Deserialize)]
pub struct CancelAmanPayload {
    pub transaction_id: String,
}

/// `POST /payouts/cashin/aman/cancel` — Cancels an Aman cashout transaction.
pub async fn cancel_aman(
    state: web::Data<AppState>,
    body: web::Json<CancelAmanPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = CancelAmanParams::new(&body.transaction_id);
    let resp = state.client.payouts().cashin().cancel_aman(params).await?;
    Ok(HttpResponse::Ok().json(disburse_json(&resp)))
}

#[derive(Debug, Deserialize)]
pub struct BulkItemPayload {
    pub issuer: String,
    pub amount: u64,
    pub msisdn: Option<String>,
    pub full_name: Option<String>,
    pub bank_code: Option<String>,
    pub client_reference_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BulkCashinPayload {
    pub bank_transaction: Option<bool>,
    pub transactions: Vec<BulkItemPayload>,
}

/// `POST /payouts/cashin/bulk` — Executes a bulk disbursement batch.
pub async fn cashin_bulk(
    state: web::Data<AppState>,
    body: web::Json<BulkCashinPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut items = Vec::with_capacity(body.transactions.len());
    for item in &body.transactions {
        let issuer = DisburseIssuer::from_wire(&item.issuer).ok_or_else(|| {
            PaymobError::ValidationError {
                field: "issuer",
                reason: "unknown disbursement issuer".to_owned(),
            }
        })?;
        items.push(BulkDisbursementItem {
            issuer,
            amount: item.amount,
            msisdn: item.msisdn.clone(),
            full_name: item.full_name.clone(),
            bank_code: item.bank_code.clone(),
            client_reference_id: item.client_reference_id.clone(),
        });
    }
    let mut params = BulkDisbursementParams::new(items);
    if let Some(is_bank) = body.bank_transaction {
        params = params.with_bank_transaction(is_bank);
    }
    let resp = state.client.payouts().cashin().bulk(&params).await?;
    Ok(HttpResponse::Ok().json(json!({
        "status": resp.status,
        "status_code": resp.status_code,
        "count": resp.results.len(),
    })))
}

/// Registers Service 9a routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/payouts/auth/token", web::post().to(auth_token))
        .route("/payouts/auth/refresh", web::post().to(auth_refresh))
        .route("/payouts/cashin/wallet/{issuer}", web::post().to(cashin_wallet))
        .route("/payouts/cashin/bank-card", web::post().to(cashin_bank_card))
        .route("/payouts/cashin/bank-instant", web::post().to(cashin_bank_instant))
        .route("/payouts/cashin/egyptian-post", web::post().to(cashin_egyptian_post))
        .route("/payouts/cashin/aman/cancel", web::post().to(cancel_aman))
        .route("/payouts/cashin/bulk", web::post().to(cashin_bulk));
}
