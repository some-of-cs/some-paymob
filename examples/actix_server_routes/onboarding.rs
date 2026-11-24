#![forbid(unsafe_code)]
//! Service 10: Partner Merchant Onboarding & Multi-Tenant Client Scoping.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use some_paymob::prelude::*;

use super::{ApiServerError, AppState, parse_currency};

#[derive(Deserialize)]
pub struct PartnerLoginPayload {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for PartnerLoginPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartnerLoginPayload")
            .finish_non_exhaustive()
    }
}

/// `POST /onboarding/auth/login` — Authenticates a partner and returns a redacted bearer token summary.
pub async fn partner_login(
    state: web::Data<AppState>,
    body: web::Json<PartnerLoginPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let creds = PartnerLoginCredentials::new(&body.username, &body.password);
    let resp = state.client.onboarding().auth().login(creds).await?;
    Ok(HttpResponse::Ok().json(json!({
        "token": "[REDACTED]",
        "has_token": !resp.token().is_empty(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyPayload {
    pub label: Option<String>,
}

/// `POST /onboarding/auth/api-keys` — Provisions a partner API key.
pub async fn create_api_key(
    state: web::Data<AppState>,
    body: web::Json<CreateApiKeyPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut params = CreatePartnerApiKeyParams::new();
    if let Some(label) = &body.label {
        params = params.with_label(label);
    }
    let resp = state
        .client
        .onboarding()
        .auth()
        .create_api_key(params)
        .await?;
    Ok(HttpResponse::Created().json(json!({
        "label": resp.label,
        "api_key": "[REDACTED]",
    })))
}

/// `GET /onboarding/auth/hmac-secret` — Retrieves the partner HMAC secret.
pub async fn get_partner_hmac(state: web::Data<AppState>) -> Result<HttpResponse, ApiServerError> {
    let resp = state
        .client
        .onboarding()
        .auth()
        .retrieve_hmac_secret()
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "status": resp.status,
        "code": resp.code,
        "hmac_secret": "[REDACTED]",
    })))
}

#[derive(Debug, Deserialize)]
pub struct RegisterMerchantPayload {
    pub partner: String,
    pub email: String,
    pub phone_number: String,
    pub first_name: String,
    pub last_name: String,
    pub company_name: Option<String>,
    pub country: Option<String>,
}

/// `POST /onboarding/flow/register` — Registers a sub-merchant.
pub async fn register_merchant(
    state: web::Data<AppState>,
    body: web::Json<RegisterMerchantPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut params = RegisterMerchantParams::new(
        &body.partner,
        &body.email,
        &body.phone_number,
        &body.first_name,
        &body.last_name,
    )?;
    if let Some(company) = &body.company_name {
        params = params.with_company_name(company);
    }
    if let Some(country) = &body.country {
        params = params.with_country(country);
    }
    let resp = state
        .client
        .onboarding()
        .flow()
        .register_merchant(&params)
        .await?;
    Ok(HttpResponse::Created().json(json!({
        "paymob_mid": resp.paymob_mid,
        "status": resp.status,
        "onboarding_url": resp.onboarding_url,
    })))
}

#[derive(Debug, Deserialize)]
pub struct SchemaQuery {
    pub partner: String,
    pub resubmission: Option<bool>,
    pub paymob_mid: Option<u64>,
}

/// `GET /onboarding/flow/schema` — Fetches the onboarding KYC schema.
pub async fn get_schema(
    state: web::Data<AppState>,
    query: web::Query<SchemaQuery>,
) -> Result<HttpResponse, ApiServerError> {
    let mut q = OnboardingSchemaQuery::new(&query.partner)?;
    if let Some(r) = query.resubmission {
        q = q.with_resubmission(r);
    }
    if let Some(mid) = query.paymob_mid {
        q = q.with_paymob_mid(mid);
    }
    let schema = state.client.onboarding().flow().get_schema(&q).await?;
    Ok(HttpResponse::Ok().json(json!({
        "partner": schema.partner,
        "steps_count": schema.steps.len(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct SubmitStepPayload {
    pub paymob_mid: u64,
    pub step_id: String,
    pub partner: Option<String>,
    pub data: Map<String, Value>,
}

/// `POST /onboarding/flow/submit-step` — Submits a KYC onboarding step.
pub async fn submit_step(
    state: web::Data<AppState>,
    body: web::Json<SubmitStepPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut params =
        SubmitOnboardingStepParams::new(body.paymob_mid, &body.step_id, body.data.clone())?;
    if let Some(p) = &body.partner {
        params = params.with_partner(p);
    }
    let resp = state
        .client
        .onboarding()
        .flow()
        .submit_step(&params)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "paymob_mid": resp.paymob_mid,
        "step_id": resp.step_id,
        "status": resp.status,
    })))
}

/// `GET /onboarding/flow/merchants/{mid}` — Inquires sub-merchant onboarding status.
pub async fn merchant_inquiry(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let resp = state
        .client
        .onboarding()
        .flow()
        .merchant_inquiry(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "paymob_mid": resp.paymob_mid,
        "status": resp.status,
        "is_live": resp.is_live,
        "is_approved": resp.is_approved(),
    })))
}

#[derive(Debug, Deserialize)]
pub struct ScopedIntentionPayload {
    pub amount_cents: u64,
    pub currency: String,
    pub payment_methods: Vec<u64>,
    pub phone_number: String,
}

/// `POST /merchants/{mid}/intentions` — Creates a sub-merchant-scoped payment intention.
pub async fn scoped_create_intention(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<ScopedIntentionPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let scoped = state.client.with_merchant(path.into_inner())?;
    let currency = parse_currency(&body.currency)?;
    let billing = BillingData::builder()
        .phone_number(&body.phone_number)
        .build()?;
    let methods = body
        .payment_methods
        .iter()
        .copied()
        .map(PaymentMethodInput::IntegrationId)
        .collect();
    let params = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(body.amount_cents))
        .currency(currency)
        .payment_methods(methods)
        .billing_data(billing)
        .build()?;
    let resp = scoped.intentions().create(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "id": resp.id,
        "status": resp.status,
        "client_secret": "[REDACTED]",
    })))
}

/// `GET /merchants/{mid}/inquiries/transactions/{tx_id}` — Sub-merchant-scoped transaction inquiry.
pub async fn scoped_inquire_tx(
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
) -> Result<HttpResponse, ApiServerError> {
    let (mid, tx_id) = path.into_inner();
    let scoped = state.client.with_merchant(mid)?;
    let tx = scoped.inquiries().transaction(tx_id).await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": tx.id,
        "success": tx.success,
        "amount_cents": tx.amount_cents,
    })))
}

#[derive(Debug, Deserialize)]
pub struct ScopedRefundPayload {
    pub transaction_id: u64,
    pub amount_cents: u64,
}

/// `POST /merchants/{mid}/manage/refund` — Sub-merchant-scoped refund.
pub async fn scoped_refund(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<ScopedRefundPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let scoped = state.client.with_merchant(path.into_inner())?;
    let params = RefundParams::try_new(body.transaction_id, body.amount_cents)?;
    let tx = scoped.manage().refund(&params).await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": tx.id,
        "is_refund": tx.is_refund,
        "amount_cents": tx.amount_cents,
    })))
}

/// Registers Service 10 routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/onboarding/auth/login", web::post().to(partner_login))
        .route("/onboarding/auth/api-keys", web::post().to(create_api_key))
        .route(
            "/onboarding/auth/hmac-secret",
            web::get().to(get_partner_hmac),
        )
        .route(
            "/onboarding/flow/register",
            web::post().to(register_merchant),
        )
        .route("/onboarding/flow/schema", web::get().to(get_schema))
        .route("/onboarding/flow/submit-step", web::post().to(submit_step))
        .route(
            "/onboarding/flow/merchants/{mid}",
            web::get().to(merchant_inquiry),
        )
        .route(
            "/merchants/{mid}/intentions",
            web::post().to(scoped_create_intention),
        )
        .route(
            "/merchants/{mid}/inquiries/transactions/{tx_id}",
            web::get().to(scoped_inquire_tx),
        )
        .route(
            "/merchants/{mid}/manage/refund",
            web::post().to(scoped_refund),
        );
}
