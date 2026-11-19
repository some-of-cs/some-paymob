#![forbid(unsafe_code)]
//! Service 3: Legacy Accept v2 3-Step Checkout endpoints.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState, parse_currency};

#[derive(Debug, Deserialize)]
pub struct LegacyOrderPayload {
    pub amount_cents: u64,
    pub currency: String,
    pub merchant_order_id: Option<String>,
}

/// `POST /legacy/orders` — Creates a Legacy v2 order.
pub async fn legacy_create_order(
    state: web::Data<AppState>,
    body: web::Json<LegacyOrderPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let mut params = CreateLegacyOrderParams::new(body.amount_cents, currency);
    if let Some(ref_id) = &body.merchant_order_id {
        params = params.merchant_order_id(ref_id);
    }
    let legacy = LegacyV2Service::new(state.client.clone())?;
    let order = legacy.create_order(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "id": order.id,
        "amount_cents": order.amount_cents,
        "merchant_order_id": order.merchant_order_id,
    })))
}

#[derive(Debug, Deserialize)]
pub struct LegacyPaymentKeyPayload {
    pub order_id: u64,
    pub amount_cents: u64,
    pub currency: String,
    pub integration_id: u64,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone_number: String,
}

/// `POST /legacy/payment-keys` — Generates a Legacy v2 payment key.
pub async fn legacy_create_payment_key(
    state: web::Data<AppState>,
    body: web::Json<LegacyPaymentKeyPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let billing = LegacyBillingData::new(
        &body.first_name,
        &body.last_name,
        &body.email,
        &body.phone_number,
    );
    let params = CreatePaymentKeyParams::new(
        body.order_id,
        body.amount_cents,
        currency,
        body.integration_id,
        billing,
    );
    let legacy = LegacyV2Service::new(state.client.clone())?;
    let key = legacy.create_payment_key(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "token_present": !key.expose_token().is_empty(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct LegacyCheckoutPayload {
    pub amount_cents: u64,
    pub currency: String,
    pub integration_id: u64,
    pub iframe_id: u64,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub phone_number: String,
}

/// `POST /legacy/checkout` — Orchestrates full Legacy v2 3-step checkout.
pub async fn legacy_create_checkout(
    state: web::Data<AppState>,
    body: web::Json<LegacyCheckoutPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let billing = LegacyBillingData::new(
        &body.first_name,
        &body.last_name,
        &body.email,
        &body.phone_number,
    );
    let params = LegacyCheckoutParams::new(
        body.amount_cents,
        currency,
        body.integration_id,
        body.iframe_id,
        billing,
    );
    let legacy = LegacyV2Service::new(state.client.clone())?;
    let session = legacy.create_checkout(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "order_id": session.order.id,
        "iframe_url": session.iframe_url.as_str(),
    })))
}

/// Registers Service 3 routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/legacy/orders", web::post().to(legacy_create_order))
        .route(
            "/legacy/payment-keys",
            web::post().to(legacy_create_payment_key),
        )
        .route("/legacy/checkout", web::post().to(legacy_create_checkout));
}
