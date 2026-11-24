#![forbid(unsafe_code)]
//! Service 7: Saved Cards (CIT/MIT) & Headless Payments.

use actix_web::{HttpResponse, web};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

#[derive(Deserialize)]
pub struct MitPayPayload {
    pub payment_token: String,
    pub saved_token: String,
    pub cvn: Option<String>,
    pub use_cvc_with_moto: Option<bool>,
}

impl std::fmt::Debug for MitPayPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitPayPayload").finish_non_exhaustive()
    }
}

/// `POST /saved-cards/pay/mit` — Executes a saved-card MIT/CIT charge.
pub async fn pay_mit(
    state: web::Data<AppState>,
    body: web::Json<MitPayPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let cvn_secret = body.cvn.as_deref().map(SecretString::from);
    if let Some(use_cvc) = body.use_cvc_with_moto {
        validate_use_cvc_with_moto(use_cvc, cvn_secret.as_ref())?;
    }
    let mut params = MitPayParams::new(
        SecretString::from(body.payment_token.clone()),
        SecretString::from(body.saved_token.clone()),
    )?;
    if let Some(cvn) = cvn_secret {
        params = params.with_cvn(cvn)?;
    }
    let resp = state
        .client
        .saved_cards()
        .pay_with_token_mit(&params)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "transaction_id": resp.transaction.id,
        "success": resp.transaction.success,
        "pending": resp.transaction.pending,
        "redirect_url": resp.redirect_url,
    })))
}

#[derive(Debug, Deserialize)]
pub struct WalletPayPayload {
    pub payment_token: String,
    pub wallet_phone: String,
}

/// `POST /saved-cards/pay/wallet` — Executes a mobile wallet headless payment.
pub async fn pay_wallet(
    state: web::Data<AppState>,
    body: web::Json<WalletPayPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = WalletPayParams::new(
        SecretString::from(body.payment_token.clone()),
        &body.wallet_phone,
    )?;
    let resp = state.client.saved_cards().pay_with_wallet(&params).await?;
    Ok(HttpResponse::Ok().json(json!({
        "transaction_id": resp.transaction.id,
        "pending": resp.transaction.pending,
        "redirect_url": resp.redirect_url,
    })))
}

#[derive(Debug, Deserialize)]
pub struct KioskPayPayload {
    pub payment_token: String,
}

/// `POST /saved-cards/pay/kiosk` — Generates an Aman/Masary kiosk bill reference.
pub async fn pay_kiosk(
    state: web::Data<AppState>,
    body: web::Json<KioskPayPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = KioskPayParams::new(SecretString::from(body.payment_token.clone()))?;
    let resp = state.client.saved_cards().pay_with_kiosk(&params).await?;
    Ok(HttpResponse::Ok().json(json!({
        "transaction_id": resp.transaction.id,
        "kiosk_bill_reference": resp.kiosk_bill_reference,
    })))
}

#[derive(Debug, Deserialize)]
pub struct RawPayPayload {
    pub payment_token: String,
    pub source: Value,
}

/// `POST /saved-cards/pay/raw` — Executes a raw headless payment payload.
pub async fn pay_raw(
    state: web::Data<AppState>,
    body: web::Json<RawPayPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let params = RawPayParams::new(
        SecretString::from(body.payment_token.clone()),
        body.source.clone(),
    )?;
    let resp = state.client.saved_cards().pay_raw(&params).await?;
    Ok(HttpResponse::Ok().json(json!({
        "transaction_id": resp.transaction.id,
        "success": resp.transaction.success,
    })))
}

/// Registers Service 7 routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/saved-cards/pay/mit", web::post().to(pay_mit))
        .route("/saved-cards/pay/wallet", web::post().to(pay_wallet))
        .route("/saved-cards/pay/kiosk", web::post().to(pay_kiosk))
        .route("/saved-cards/pay/raw", web::post().to(pay_raw));
}
