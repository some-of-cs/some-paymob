#![forbid(unsafe_code)]
//! Service 2: Unified Payment Intentions & Checkout (Pixel, Affordability).

use actix_web::{HttpResponse, web};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState, parse_currency};

#[derive(Debug, Deserialize)]
pub struct BillingPayload {
    pub phone_number: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateIntentionPayload {
    pub amount_cents: u64,
    pub currency: String,
    pub payment_methods: Vec<u64>,
    pub billing_data: BillingPayload,
    pub special_reference: Option<String>,
    pub notification_url: Option<String>,
    pub redirection_url: Option<String>,
    pub pre_selected_plan: Option<u64>,
    pub integration_mode: Option<String>,
}

fn build_billing_data(p: &BillingPayload) -> Result<BillingData, ApiServerError> {
    let mut b = BillingData::builder().phone_number(&p.phone_number);
    if let Some(v) = &p.first_name {
        b = b.first_name(v);
    }
    if let Some(v) = &p.last_name {
        b = b.last_name(v);
    }
    if let Some(v) = &p.email {
        b = b.email(v);
    }
    if let Some(v) = &p.city {
        b = b.city(v);
    }
    if let Some(v) = &p.country {
        b = b.country(v);
    }
    Ok(b.build()?)
}

fn parse_env_mode(raw: &str) -> Result<EnvironmentMode, ApiServerError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "test" => Ok(EnvironmentMode::Test),
        "live" => Ok(EnvironmentMode::Live),
        _ => Err(PaymobError::ValidationError {
            field: "integration_mode",
            reason: "expected 'test' or 'live'".to_owned(),
        }
        .into()),
    }
}

fn apply_optionals(
    mut b: CreateIntentionParamsBuilder,
    body: &CreateIntentionPayload,
) -> CreateIntentionParamsBuilder {
    if let Some(r) = &body.special_reference {
        b = b.special_reference(r);
    }
    if let Some(u) = &body.notification_url {
        b = b.notification_url(u);
    }
    if let Some(u) = &body.redirection_url {
        b = b.redirection_url(u);
    }
    if let Some(p) = body.pre_selected_plan {
        b = b.pre_selected_plan(p);
    }
    b
}

/// `POST /intentions` — Creates a v1 payment intention.
pub async fn create_intention(
    state: web::Data<AppState>,
    body: web::Json<CreateIntentionPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let billing = build_billing_data(&body.billing_data)?;
    let methods: Vec<PaymentMethodInput> = body
        .payment_methods
        .iter()
        .copied()
        .map(PaymentMethodInput::IntegrationId)
        .collect();
    let b = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(body.amount_cents))
        .currency(currency)
        .payment_methods(methods)
        .billing_data(billing);
    let params = apply_optionals(b, &body).build()?;
    let mut svc = state.client.intentions();
    if let (Some(mode_str), Some(first_id)) = (&body.integration_mode, body.payment_methods.first())
    {
        svc = svc.with_integration_mode(*first_id, parse_env_mode(mode_str)?);
    }
    let resp = svc.create(params).await?;
    Ok(HttpResponse::Created().json(json!({
        "id": resp.id,
        "status": resp.status,
        "intention_order_id": resp.intention_order_id,
        "client_secret": "[REDACTED]",
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateIntentionPayload {
    pub client_secret: String,
    pub amount_cents: Option<u64>,
    pub currency: Option<String>,
    pub notification_url: Option<String>,
    pub redirection_url: Option<String>,
}

/// `PUT /intentions` — Updates an existing v1 payment intention.
pub async fn update_intention(
    state: web::Data<AppState>,
    body: web::Json<UpdateIntentionPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut b = UpdateIntentionParams::builder();
    if let Some(amt) = body.amount_cents {
        b = b.amount(MinorUnitAmount::new(amt));
    }
    if let Some(cur) = &body.currency {
        b = b.currency(parse_currency(cur)?);
    }
    if let Some(u) = &body.notification_url {
        b = b.notification_url(u);
    }
    if let Some(u) = &body.redirection_url {
        b = b.redirection_url(u);
    }
    let params = b.build()?;
    let resp = state
        .client
        .intentions()
        .update(params)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": resp.id,
        "status": resp.status,
        "intention_order_id": resp.intention_order_id,
    })))
}

#[derive(Debug, Deserialize)]
pub struct PixelPayload {
    pub public_key: String,
    pub client_secret: String,
    pub show_save_card: Option<bool>,
    pub force_save_card: Option<bool>,
}

/// `POST /checkout/pixel` — Builds an embedded Pixel JS configuration.
pub async fn checkout_pixel(body: web::Json<PixelPayload>) -> Result<HttpResponse, ApiServerError> {
    let pk = PublicKey::new(body.public_key.clone())?;
    let mut b = PixelConfig::builder(&pk, SecretString::from(body.client_secret.clone()))
        .add_payment_method(PixelPaymentMethod::Card);
    if let Some(s) = body.show_save_card {
        b = b.show_save_card(s);
    }
    if let Some(f) = body.force_save_card {
        b = b.force_save_card(f);
    }
    let cfg = b.build()?;
    Ok(HttpResponse::Ok().json(json!({
        "public_key": cfg.public_key,
        "show_save_card": cfg.show_save_card,
        "force_save_card": cfg.force_save_card,
        "payment_methods_count": cfg.payment_methods.len(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct AffordabilityPayload {
    pub public_key: String,
    pub amount_cents: u64,
    pub currency: String,
    pub pre_selected_plan: Option<u64>,
    pub tenure_months: Option<u16>,
}

/// `POST /checkout/affordability` — Builds a bank installment Affordability Widget config.
pub async fn checkout_affordability(
    body: web::Json<AffordabilityPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let pk = PublicKey::new(body.public_key.clone())?;
    let currency = parse_currency(&body.currency)?;
    let mut b = AffordabilityWidgetConfig::builder(
        &pk,
        MinorUnitAmount::new(body.amount_cents),
        currency,
    );
    if let Some(plan) = body.pre_selected_plan {
        b = b.pre_selected_plan(plan);
    }
    if let Some(months) = body.tenure_months {
        b = b.tenure_months(months);
    }
    let cfg = b.build()?;
    Ok(HttpResponse::Ok().json(json!({
        "public_key": cfg.public_key,
        "amount_cents": cfg.amount_cents(),
        "selected_plan_id": cfg.selected_plan_id(),
    })))
}

/// Registers Service 2 routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/intentions", web::post().to(create_intention))
        .route("/intentions", web::put().to(update_intention))
        .route("/checkout/pixel", web::post().to(checkout_pixel))
        .route(
            "/checkout/affordability",
            web::post().to(checkout_affordability),
        );
}
