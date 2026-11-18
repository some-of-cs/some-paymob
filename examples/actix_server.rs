#![forbid(unsafe_code)]
//! Reference Actix-Web HTTP Server demonstrating all 14 `some-paymob` services
//! and all 5 constant-time HMAC-SHA512 webhook verification protocols (`A`–`E`).

use std::fmt;
use std::sync::Arc;

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError, web};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Value, json};
use some_paymob::prelude::*;

/// Shared Actix-Web application state wrapping an `Arc`-backed [`PaymobClient`]
/// and an in-memory webhook replay deduplicator.
#[derive(Clone)]
pub struct AppState {
    /// Configured `some-paymob` microkernel client.
    pub client: PaymobClient,
    /// Thread-safe in-memory webhook replay guard.
    pub webhook_dedup: Arc<InMemoryWebhookDeduplicator>,
}

impl AppState {
    /// Creates a new [`AppState`] with a default [`InMemoryWebhookDeduplicator`].
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        Self {
            client,
            webhook_dedup: Arc::new(InMemoryWebhookDeduplicator::new()),
        }
    }
}

/// Deterministic HTTP error wrapper mapping `some-paymob` SDK, webhook, and
/// sandbox constraint errors to Actix-Web `ResponseError` status codes.
#[derive(Debug)]
pub enum ApiServerError {
    /// Core or resource SDK error.
    Paymob(PaymobError),
    /// Cryptographic webhook verification or replay error.
    Webhook(WebhookError),
    /// Sandbox constraint error (credential age >= 30 days or unsupported channel).
    Sandbox(SandboxConstraintError),
}

impl fmt::Display for ApiServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Paymob(err) => write!(f, "{err}"),
            Self::Webhook(err) => write!(f, "{err}"),
            Self::Sandbox(err) => write!(f, "{err}"),
        }
    }
}

impl From<PaymobError> for ApiServerError {
    fn from(err: PaymobError) -> Self {
        Self::Paymob(err)
    }
}

impl From<WebhookError> for ApiServerError {
    fn from(err: WebhookError) -> Self {
        Self::Webhook(err)
    }
}

impl From<SandboxConstraintError> for ApiServerError {
    fn from(err: SandboxConstraintError) -> Self {
        Self::Sandbox(err)
    }
}

fn map_paymob_status(err: &PaymobError) -> StatusCode {
    match err {
        PaymobError::ValidationError { .. } | PaymobError::WebhookError(_) => {
            StatusCode::BAD_REQUEST
        }
        PaymobError::AuthenticationError(_) => StatusCode::UNAUTHORIZED,
        PaymobError::EnvironmentMismatch(_)
        | PaymobError::RefundExceedsPermissibleAmount { .. } => StatusCode::UNPROCESSABLE_ENTITY,
        PaymobError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
        PaymobError::ApiError { status, .. } => {
            StatusCode::from_u16(*status).unwrap_or(StatusCode::BAD_GATEWAY)
        }
        PaymobError::TransportError(_) => StatusCode::BAD_GATEWAY,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn map_webhook_status(err: &WebhookError) -> StatusCode {
    match err {
        WebhookError::SignatureMismatch => StatusCode::UNAUTHORIZED,
        WebhookError::DuplicateWebhookDelivery { .. } => StatusCode::CONFLICT,
        _ => StatusCode::BAD_REQUEST,
    }
}

impl ResponseError for ApiServerError {
    fn status_code(&self) -> StatusCode {
        match self {
            Self::Paymob(err) => map_paymob_status(err),
            Self::Webhook(err) => map_webhook_status(err),
            Self::Sandbox(_) => StatusCode::UNPROCESSABLE_ENTITY,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let status = self.status_code();
        let mut builder = HttpResponse::build(status);
        if let Self::Paymob(PaymobError::RateLimited {
            retry_after_secs: Some(secs),
            ..
        }) = self
        {
            builder.insert_header(("Retry-After", secs.to_string()));
        }
        builder.json(json!({
            "error": self.to_string(),
            "status": status.as_u16(),
        }))
    }
}

pub(crate) fn parse_currency(raw: &str) -> Result<Currency, ApiServerError> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "EGP" => Ok(Currency::EGP),
        "SAR" => Ok(Currency::SAR),
        "AED" => Ok(Currency::AED),
        "OMR" => Ok(Currency::OMR),
        "PKR" => Ok(Currency::PKR),
        "USD" => Ok(Currency::USD),
        _ => Err(PaymobError::ValidationError {
            field: "currency".to_owned(),
            reason: "unsupported currency code".to_owned(),
        }
        .into()),
    }
}

// ---------------------------------------------------------------------------
// Service 1: Health & Sandbox Guard
// ---------------------------------------------------------------------------

/// `GET /health` — Service health probe.
pub async fn health_check(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "region": format!("{:?}", state.client.config().region()),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SandboxCheckPayload {
    pub is_sandbox: bool,
    pub credential_age_days: u64,
    pub channel: String,
}

fn parse_sandbox_channel(raw: &str) -> Result<SandboxPaymentChannel, ApiServerError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "card" => Ok(SandboxPaymentChannel::Card),
        "wallet" => Ok(SandboxPaymentChannel::Wallet),
        "kiosk" => Ok(SandboxPaymentChannel::Kiosk),
        "bnpl" => Ok(SandboxPaymentChannel::Bnpl),
        _ => Err(PaymobError::ValidationError {
            field: "channel".to_owned(),
            reason: "expected one of: card, wallet, kiosk, bnpl".to_owned(),
        }
        .into()),
    }
}

/// `POST /sandbox/check` — Validates sandbox credential age and channel support.
pub async fn sandbox_check(
    body: web::Json<SandboxCheckPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let channel = parse_sandbox_channel(&body.channel)?;
    let report = SandboxGuard::check_constraints(&SandboxCheckRequest {
        is_sandbox: body.is_sandbox,
        credential_age_days: body.credential_age_days,
        channel,
    });
    if let Some(first_err) = report.errors.first() {
        return Err(ApiServerError::Sandbox(first_err.clone()));
    }
    let warnings: Vec<String> = report.warnings.iter().map(ToString::to_string).collect();
    Ok(HttpResponse::Ok().json(json!({
        "ok": report.is_ok(),
        "warnings": warnings,
    })))
}

// ---------------------------------------------------------------------------
// Service 2: Unified Payment Intentions & Checkout
// ---------------------------------------------------------------------------

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
    let mut builder = BillingData::builder().phone_number(&p.phone_number);
    if let Some(v) = &p.first_name {
        builder = builder.first_name(v);
    }
    if let Some(v) = &p.last_name {
        builder = builder.last_name(v);
    }
    if let Some(v) = &p.email {
        builder = builder.email(v);
    }
    if let Some(v) = &p.city {
        builder = builder.city(v);
    }
    if let Some(v) = &p.country {
        builder = builder.country(v);
    }
    Ok(builder.build()?)
}

fn parse_env_mode(raw: &str) -> Result<EnvironmentMode, ApiServerError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "test" => Ok(EnvironmentMode::Test),
        "live" => Ok(EnvironmentMode::Live),
        _ => Err(PaymobError::ValidationError {
            field: "integration_mode".to_owned(),
            reason: "expected 'test' or 'live'".to_owned(),
        }
        .into()),
    }
}

fn apply_intention_optionals(
    mut builder: CreateIntentionParamsBuilder,
    body: &CreateIntentionPayload,
) -> CreateIntentionParamsBuilder {
    if let Some(r) = &body.special_reference {
        builder = builder.special_reference(r);
    }
    if let Some(u) = &body.notification_url {
        builder = builder.notification_url(u);
    }
    if let Some(u) = &body.redirection_url {
        builder = builder.redirection_url(u);
    }
    if let Some(p) = body.pre_selected_plan {
        builder = builder.pre_selected_plan(p);
    }
    builder
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
    let builder = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::from_minor(body.amount_cents))
        .currency(currency)
        .payment_methods(methods)
        .billing_data(billing);
    let params = apply_intention_optionals(builder, &body).build()?;
    let mut svc = state.client.intentions();
    if let (Some(mode_str), Some(first_id)) = (&body.integration_mode, body.payment_methods.first())
    {
        svc = svc.with_integration_mode(*first_id, parse_env_mode(mode_str)?);
    }
    let resp = svc.create(&params).await?;
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
    let mut builder = UpdateIntentionParams::builder();
    if let Some(amt) = body.amount_cents {
        builder = builder.amount(MinorUnitAmount::from_minor(amt));
    }
    if let Some(cur) = &body.currency {
        builder = builder.currency(parse_currency(cur)?);
    }
    if let Some(u) = &body.notification_url {
        builder = builder.notification_url(u);
    }
    if let Some(u) = &body.redirection_url {
        builder = builder.redirection_url(u);
    }
    let params = builder.build()?;
    let resp = state
        .client
        .intentions()
        .update(&SecretString::from(body.client_secret.clone()), &params)
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
    let mut builder = PixelConfig::builder(&pk, SecretString::from(body.client_secret.clone()))
        .add_payment_method(PixelPaymentMethod::Card);
    if let Some(s) = body.show_save_card {
        builder = builder.show_save_card(s);
    }
    if let Some(f) = body.force_save_card {
        builder = builder.force_save_card(f);
    }
    let cfg = builder.build()?;
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
    let mut builder = AffordabilityWidgetConfig::builder(
        &pk,
        MinorUnitAmount::from_minor(body.amount_cents),
        currency,
    );
    if let Some(plan) = body.pre_selected_plan {
        builder = builder.pre_selected_plan(plan);
    }
    if let Some(months) = body.tenure_months {
        builder = builder.tenure_months(months);
    }
    let cfg = builder.build()?;
    Ok(HttpResponse::Ok().json(json!({
        "public_key": cfg.public_key,
        "amount_cents": cfg.amount_cents(),
        "selected_plan_id": cfg.selected_plan_id(),
    })))
}

// ---------------------------------------------------------------------------
// Service 3: Legacy Accept v2 3-Step Checkout
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Service 4: Payment Lifecycle Management (Refund, Void, Capture)
// ---------------------------------------------------------------------------

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
    Ok(HttpResponse::Ok().json(json!({
        "id": tx.id,
        "success": tx.success,
        "is_refund": tx.is_refund,
        "amount_cents": tx.amount_cents,
    })))
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
    Ok(HttpResponse::Ok().json(json!({
        "id": tx.id,
        "success": tx.success,
        "is_void": tx.is_void,
    })))
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
    Ok(HttpResponse::Ok().json(json!({
        "id": tx.id,
        "success": tx.success,
        "is_capture": tx.is_capture,
        "amount_cents": tx.amount_cents,
    })))
}

// ---------------------------------------------------------------------------
// Service 5: Transaction, Order & Card Token Inquiries
// ---------------------------------------------------------------------------

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
            field: "order_id".to_owned(),
            reason: "order_id or merchant_order_id is required".to_owned(),
        }
        .into());
    };
    let tx = state
        .client
        .inquiries()
        .by_order_or_reference(&params)
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

// ---------------------------------------------------------------------------
// Service 6: QuickLinks & Marketplace Splits / Convenience Fees
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct QuickLinkPayload {
    pub amount_cents: u64,
    pub currency: String,
    pub integrations: Vec<u64>,
    pub description: Option<String>,
}

/// `POST /quicklinks` — Creates a QuickLink payment URL.
pub async fn create_quicklink(
    state: web::Data<AppState>,
    body: web::Json<QuickLinkPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut params =
        CreateQuickLinkParams::new(body.amount_cents, &body.currency, body.integrations.clone());
    if let Some(desc) = &body.description {
        params = params.with_description(desc);
    }
    let resp = state.client.quicklinks().create(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "id": resp.id,
        "url": resp.url,
        "client_url": resp.client_url,
    })))
}

/// `POST /quicklinks/{link_id}/cancel` — Cancels an active QuickLink.
pub async fn cancel_quicklink(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiServerError> {
    state
        .client
        .quicklinks()
        .cancel(&path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(json!({ "cancelled": true })))
}

#[derive(Debug, Deserialize)]
pub struct SplitRecipientInput {
    pub recipient_id: String,
    pub amount_cents: Option<u64>,
    pub percentage_bps: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct SplitCardInput {
    pub amount_cents: u64,
    pub integration_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SplitsQuotePayload {
    pub total_amount_cents: u64,
    pub recipients: Vec<SplitRecipientInput>,
    pub cards: Vec<SplitCardInput>,
    pub fixed_fee_cents: Option<u64>,
}

fn build_split_rule(r: &SplitRecipientInput) -> Result<SplitRecipientRule, ApiServerError> {
    match (r.amount_cents, r.percentage_bps) {
        (Some(amt), None) => Ok(SplitRecipientRule::fixed(&r.recipient_id, amt)),
        (None, Some(bps)) => Ok(SplitRecipientRule::percentage_bps(&r.recipient_id, bps)),
        _ => Err(PaymobError::ValidationError {
            field: "recipients".to_owned(),
            reason: "specify exactly one of amount_cents or percentage_bps".to_owned(),
        }
        .into()),
    }
}

/// `POST /splits/validate-and-quote` — Validates split rules, card portions, and convenience fees.
pub async fn splits_validate_and_quote(
    body: web::Json<SplitsQuotePayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut rules = Vec::with_capacity(body.recipients.len());
    for r in &body.recipients {
        rules.push(build_split_rule(r)?);
    }
    let split_desc = SplitDescription::new(rules)?;
    let cards: Vec<SplitCardPortion> = body
        .cards
        .iter()
        .map(|c| {
            let mut p = SplitCardPortion::new(c.amount_cents);
            if let Some(id) = c.integration_id {
                p = p.with_integration_id(id);
            }
            p
        })
        .collect();
    let card_cfg = SplitPaymentConfig::new(cards)?;
    card_cfg.validate_total(body.total_amount_cents)?;
    let fee_cfg = ConvenienceFeeConfig::new(FeeCalculationMode::Fixed {
        fee_cents: body.fixed_fee_cents.unwrap_or(0),
    });
    let total_with_fee = fee_cfg.total_with_fee_cents(body.total_amount_cents)?;
    Ok(HttpResponse::Ok().json(json!({
        "recipients_count": split_desc.recipients.len(),
        "cards_count": card_cfg.cards.len(),
        "total_with_fee_cents": total_with_fee,
    })))
}

/// Configures Unit 1 routes (Services 1–6).
pub fn configure_unit_1(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health_check))
        .route("/sandbox/check", web::post().to(sandbox_check))
        .route("/intentions", web::post().to(create_intention))
        .route("/intentions", web::put().to(update_intention))
        .route("/checkout/pixel", web::post().to(checkout_pixel))
        .route(
            "/checkout/affordability",
            web::post().to(checkout_affordability),
        )
        .route("/legacy/orders", web::post().to(legacy_create_order))
        .route(
            "/legacy/payment-keys",
            web::post().to(legacy_create_payment_key),
        )
        .route("/legacy/checkout", web::post().to(legacy_create_checkout))
        .route("/manage/refund", web::post().to(manage_refund))
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
        )
        .route("/quicklinks", web::post().to(create_quicklink))
        .route(
            "/quicklinks/{link_id}/cancel",
            web::post().to(cancel_quicklink),
        )
        .route(
            "/splits/validate-and-quote",
            web::post().to(splits_validate_and_quote),
        );
}

/// Configures the full Actix-Web service surface.
pub fn configure_app(cfg: &mut web::ServiceConfig) {
    configure_unit_1(cfg);
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    Ok(())
}
