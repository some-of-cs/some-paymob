#![forbid(unsafe_code)]
//! Axum router and handlers for Services 1–7 of the `some-paymob` example server.
//!
//! Covers:
//! - Service 1: Health diagnostics (`GET /health`) and sandbox constraint checks (`POST /sandbox/check`)
//! - Service 2: v1 Payment Intentions (`POST /intentions`, `PUT /intentions`) and Checkout builders
//!   (`POST /checkout/pixel`, `POST /checkout/affordability`)
//! - Service 3: Legacy Accept v2 3-step checkout (`POST /legacy/orders`, `POST /legacy/payment-keys`,
//!   `POST /legacy/checkout`)
//! - Service 4: Payment lifecycle management (`POST /manage/refund`, `POST /manage/void`,
//!   `POST /manage/capture`)
//! - Service 5: Transaction, order, and card-token inquiries
//! - Service 6: QuickLinks payment links (`POST /quicklinks`, `POST /quicklinks/{link_id}/cancel`)
//! - Service 7: Marketplace splits & convenience fee quote (`POST /splits/validate-and-quote`)

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use some_paymob::core::config::ClientConfig;
use some_paymob::core::credentials::EnvironmentMode;
use some_paymob::resources::manage::Transaction as ManageTransaction;
use some_paymob::resources::splits::CardFeeContext;
use some_paymob::{
    AffordabilityWidgetConfig, CaptureParams, CardTokenEnvelope, ConvenienceFeeConfig,
    CreateIntentionParams, CreateLegacyOrderParams, CreatePaymentKeyParams, CreateQuickLinkParams,
    Currency, IntentionResponse, LegacyBillingData, LegacyCheckoutParams, LegacyOrder,
    LegacyOrderItem, MinorUnitAmount, PaymobClient, PaymobError, PaymobRegion, PixelPaymentMethod,
    QuickLinkResponse, RefundParams, SandboxCheckRequest, SandboxGuard, SandboxPaymentChannel,
    SandboxReport, SplitDescription, SplitPaymentConfig, TransactionInquiryParams,
    UpdateIntentionParams, VoidParams,
};

use super::state::{ApiServerError, AppState};

const REDACTED_MARKER: &str = "[REDACTED]";

/// Builds the Axum [`Router`] for Services 1–7 backed by [`AppState`].
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health_handler))
        .route("/sandbox/check", post(sandbox_check_handler))
        .route("/intentions", post(create_intention_handler))
        .route("/intentions", put(update_intention_handler))
        .route("/checkout/pixel", post(pixel_checkout_handler))
        .route(
            "/checkout/affordability",
            post(affordability_checkout_handler),
        )
        .route("/legacy/orders", post(legacy_create_order_handler))
        .route(
            "/legacy/payment-keys",
            post(legacy_create_payment_key_handler),
        )
        .route("/legacy/checkout", post(legacy_create_checkout_handler))
        .route("/manage/refund", post(manage_refund_handler))
        .route("/manage/void", post(manage_void_handler))
        .route("/manage/capture", post(manage_capture_handler))
        .route(
            "/inquiries/transactions/{tx_id}",
            get(inquiry_by_tx_id_handler),
        )
        .route("/inquiries/by-order", post(inquiry_by_order_handler))
        .route("/inquiries/orders/{order_id}", get(inquiry_order_handler))
        .route(
            "/inquiries/orders/{order_id}/card-tokens",
            post(inquiry_card_tokens_handler),
        )
        .route("/quicklinks", post(create_quicklink_handler))
        .route(
            "/quicklinks/{link_id}/cancel",
            post(cancel_quicklink_handler),
        )
        .route(
            "/splits/validate-and-quote",
            post(splits_validate_and_quote_handler),
        )
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    region: PaymobRegion,
    environment: EnvironmentMode,
    accept_base_url: String,
    checkout_base_url: String,
    payouts_base_url: Option<String>,
    payouts_staging_base_url: Option<String>,
    client_state: String,
    known_integration_modes_count: usize,
}

async fn health_handler(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let config = state.paymob.config();
    let endpoints = state.paymob.endpoints();
    Json(HealthResponse {
        status: "ok",
        region: config.region().clone(),
        environment: config.environment(),
        accept_base_url: endpoints.accept_base_url.clone(),
        checkout_base_url: endpoints.checkout_base_url.clone(),
        payouts_base_url: endpoints.payouts_base_url.clone(),
        payouts_staging_base_url: endpoints.payouts_staging_base_url.clone(),
        client_state: format!("{:?}", state.paymob),
        known_integration_modes_count: state.known_integration_modes.len(),
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SandboxChannelInput {
    Card,
    MobileWallet,
    Kiosk,
    Bnpl,
    Payouts,
}

impl From<SandboxChannelInput> for SandboxPaymentChannel {
    fn from(value: SandboxChannelInput) -> Self {
        match value {
            SandboxChannelInput::Card => Self::Card,
            SandboxChannelInput::MobileWallet => Self::MobileWallet,
            SandboxChannelInput::Kiosk => Self::Kiosk,
            SandboxChannelInput::Bnpl => Self::Bnpl,
            SandboxChannelInput::Payouts => Self::Payouts,
        }
    }
}

#[derive(Deserialize)]
struct SandboxCheckInput {
    is_sandbox: bool,
    credential_age_days: u64,
    channel: SandboxChannelInput,
}

#[derive(Serialize)]
struct SandboxReportResponse {
    ok: bool,
    warnings: Vec<String>,
    errors: Vec<String>,
}

impl From<SandboxReport> for SandboxReportResponse {
    fn from(report: SandboxReport) -> Self {
        let ok = report.is_ok();
        let warnings = report.warnings.iter().map(|w| format!("{w:?}")).collect();
        let errors = report.errors.iter().map(ToString::to_string).collect();
        Self {
            ok,
            warnings,
            errors,
        }
    }
}

async fn sandbox_check_handler(
    Json(input): Json<SandboxCheckInput>,
) -> Json<SandboxReportResponse> {
    let req = SandboxCheckRequest {
        is_sandbox: input.is_sandbox,
        credential_age_days: input.credential_age_days,
        channel: input.channel.into(),
    };
    let report = SandboxGuard::check_constraints(&req);
    Json(report.into())
}

#[derive(Serialize)]
struct IntentionResponseDto {
    id: String,
    intention_order_id: u64,
    client_secret: &'static str,
    payment_keys_count: usize,
    card_tokens_count: usize,
    confirmed: bool,
    status: String,
    special_reference: Option<String>,
    created: Option<String>,
    object: Option<String>,
}

impl IntentionResponseDto {
    fn from_sdk(resp: &IntentionResponse) -> Self {
        Self {
            id: resp.id.clone(),
            intention_order_id: resp.intention_order_id,
            client_secret: REDACTED_MARKER,
            payment_keys_count: resp.payment_keys.len(),
            card_tokens_count: resp.card_tokens.len(),
            confirmed: resp.confirmed,
            status: resp.status.clone(),
            special_reference: resp.special_reference.clone(),
            created: resp.created.clone(),
            object: resp.object.clone(),
        }
    }
}

fn build_intentions_service(state: &AppState) -> some_paymob::IntentionsService<'_> {
    let mut service = state.paymob.intentions();
    for (&integration_id, &mode) in &state.known_integration_modes {
        service = service.with_integration_mode(integration_id, mode);
    }
    service
}

async fn create_intention_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CreateIntentionParams>,
) -> Result<Json<IntentionResponseDto>, ApiServerError> {
    let resp = build_intentions_service(&state).create(params).await?;
    Ok(Json(IntentionResponseDto::from_sdk(&resp)))
}

async fn update_intention_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<UpdateIntentionParams>,
) -> Result<Json<IntentionResponseDto>, ApiServerError> {
    let resp = build_intentions_service(&state).update(params).await?;
    Ok(Json(IntentionResponseDto::from_sdk(&resp)))
}

#[derive(Deserialize)]
struct PixelCheckoutInput {
    client_secret: String,
    payment_methods: Vec<PixelPaymentMethod>,
    #[serde(default)]
    show_save_card: Option<bool>,
    #[serde(default)]
    force_save_card: Option<bool>,
    #[serde(default)]
    locale: Option<String>,
}

async fn pixel_checkout_handler(
    State(state): State<Arc<AppState>>,
    Json(input): Json<PixelCheckoutInput>,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let mut builder = state
        .paymob
        .checkout()
        .pixel_config(SecretString::from(input.client_secret))?
        .payment_methods(input.payment_methods);

    if let Some(show) = input.show_save_card {
        builder = builder.show_save_card(show);
    }
    if let Some(force) = input.force_save_card {
        builder = builder.force_save_card(force);
    }
    if let Some(locale) = input.locale {
        builder = builder.locale(locale);
    }

    let config = builder.build()?;
    let value = config.to_json_value()?;
    Ok(Json(value))
}

#[derive(Deserialize)]
struct AffordabilityInput {
    amount_cents: u64,
    currency: Currency,
    #[serde(default)]
    pre_selected_plan: Option<u64>,
    #[serde(default)]
    supported_banks: Option<Vec<String>>,
    #[serde(default)]
    tenure_months: Option<u16>,
    #[serde(default)]
    down_payment_cents: Option<u64>,
}

async fn affordability_checkout_handler(
    State(state): State<Arc<AppState>>,
    Json(input): Json<AffordabilityInput>,
) -> Result<Json<AffordabilityWidgetConfig>, ApiServerError> {
    let mut builder = state
        .paymob
        .checkout()
        .affordability_widget(MinorUnitAmount::from(input.amount_cents), input.currency)?;

    if let Some(plan_id) = input.pre_selected_plan {
        builder = builder.pre_selected_plan(plan_id);
    }
    if let Some(banks) = input.supported_banks {
        builder = builder.supported_banks(banks);
    }
    if let Some(months) = input.tenure_months {
        builder = builder.tenure_months(months);
    }
    if let Some(dp) = input.down_payment_cents {
        builder = builder.down_payment(MinorUnitAmount::from(dp));
    }

    let config = builder.build()?;
    Ok(Json(config))
}

#[derive(Serialize)]
struct PaymentKeyDto {
    token: &'static str,
}

async fn legacy_create_order_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CreateLegacyOrderParams>,
) -> Result<Json<LegacyOrder>, ApiServerError> {
    let order = state.paymob.legacy_v2()?.create_order(&params).await?;
    Ok(Json(order))
}

async fn legacy_create_payment_key_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CreatePaymentKeyParams>,
) -> Result<Json<PaymentKeyDto>, ApiServerError> {
    let _key = state
        .paymob
        .legacy_v2()?
        .create_payment_key(&params)
        .await?;
    Ok(Json(PaymentKeyDto {
        token: REDACTED_MARKER,
    }))
}

#[derive(Deserialize)]
struct LegacyCheckoutInput {
    amount_cents: u64,
    currency: Currency,
    integration_id: u64,
    iframe_id: u64,
    billing_data: LegacyBillingData,
    #[serde(default)]
    delivery_needed: Option<bool>,
    #[serde(default)]
    merchant_order_id: Option<String>,
    #[serde(default)]
    items: Option<Vec<LegacyOrderItem>>,
    #[serde(default)]
    expiration: Option<u32>,
    #[serde(default)]
    lock_order_when_paid: Option<bool>,
}

#[derive(Serialize)]
struct LegacyCheckoutDto {
    order: LegacyOrder,
    payment_token: &'static str,
    iframe_url: String,
}

fn build_legacy_checkout_params(input: LegacyCheckoutInput) -> LegacyCheckoutParams {
    let mut params = LegacyCheckoutParams::new(
        input.amount_cents,
        input.currency,
        input.integration_id,
        input.iframe_id,
        input.billing_data,
    );
    if let Some(delivery) = input.delivery_needed {
        params = params.delivery_needed(delivery);
    }
    if let Some(merchant_order_id) = input.merchant_order_id {
        params = params.merchant_order_id(merchant_order_id);
    }
    if let Some(items) = input.items {
        params = params.items(items);
    }
    if let Some(exp) = input.expiration {
        params = params.expiration(exp);
    }
    if let Some(lock) = input.lock_order_when_paid {
        params = params.lock_order_when_paid(lock);
    }
    params
}

async fn legacy_create_checkout_handler(
    State(state): State<Arc<AppState>>,
    Json(input): Json<LegacyCheckoutInput>,
) -> Result<Json<LegacyCheckoutDto>, ApiServerError> {
    let params = build_legacy_checkout_params(input);
    let session = state.paymob.legacy_v2()?.create_checkout(&params).await?;
    Ok(Json(LegacyCheckoutDto {
        order: session.order,
        payment_token: REDACTED_MARKER,
        iframe_url: session.iframe_url.to_string(),
    }))
}

#[derive(Deserialize)]
struct VoidRequestInput {
    transaction_id: u64,
    #[serde(default)]
    legacy_v2_bearer: Option<bool>,
}

fn apply_optional_keys(
    mut builder: some_paymob::ClientConfigBuilder,
    cfg: &ClientConfig,
) -> some_paymob::ClientConfigBuilder {
    if let Some(sk) = cfg.secret_key() {
        builder = builder.secret_key(sk.clone());
    }
    if let Some(pk) = cfg.public_key() {
        builder = builder.public_key(pk.clone());
    }
    if let Some(ak) = cfg.api_key() {
        builder = builder.api_key(ak.clone());
    }
    if let Some(hmac) = cfg.hmac_secret() {
        builder = builder.hmac_secret(hmac.clone());
    }
    builder
}

fn apply_optional_partner_creds(
    mut builder: some_paymob::ClientConfigBuilder,
    cfg: &ClientConfig,
) -> some_paymob::ClientConfigBuilder {
    if let Some(payouts) = cfg.payouts_credentials() {
        builder = builder.payouts_credentials(payouts.clone());
    }
    if let Some(partner) = cfg.partner_credentials() {
        builder = builder.partner_credentials(partner.clone());
    }
    builder
}

fn clone_client_with_legacy_bearer(
    base: &PaymobClient,
    enabled: bool,
) -> Result<PaymobClient, PaymobError> {
    let cfg = base.config();
    let builder = ClientConfig::builder()
        .region(cfg.region().clone())
        .environment(cfg.environment())
        .timeout(cfg.timeout())
        .max_retries(cfg.max_retries())
        .use_payouts_staging(cfg.use_payouts_staging())
        .use_legacy_v2_bearer_for_capture(enabled);
    let builder = apply_optional_keys(builder, cfg);
    let builder = apply_optional_partner_creds(builder, cfg);
    PaymobClient::new(builder.build()?)
}

async fn manage_refund_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<RefundParams>,
) -> Result<Json<ManageTransaction>, ApiServerError> {
    let tx = state.paymob.manage().refund(params).await?;
    Ok(Json(tx))
}

async fn manage_void_handler(
    State(state): State<Arc<AppState>>,
    Json(input): Json<VoidRequestInput>,
) -> Result<Json<ManageTransaction>, ApiServerError> {
    let params = VoidParams::new(input.transaction_id);
    let tx = match input.legacy_v2_bearer {
        Some(flag) if flag != state.paymob.config().use_legacy_v2_bearer_for_capture() => {
            let client = clone_client_with_legacy_bearer(&state.paymob, flag)?;
            client.manage().void(params).await?
        }
        _ => state.paymob.manage().void(params).await?,
    };
    Ok(Json(tx))
}

async fn manage_capture_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<CaptureParams>,
) -> Result<Json<ManageTransaction>, ApiServerError> {
    let tx = state.paymob.manage().capture(params).await?;
    Ok(Json(tx))
}

async fn inquiry_by_tx_id_handler(
    State(state): State<Arc<AppState>>,
    Path(tx_id): Path<u64>,
) -> Result<Json<some_paymob::resources::inquiries::Transaction>, ApiServerError> {
    let tx = state.paymob.inquiries().by_transaction_id(tx_id).await?;
    Ok(Json(tx))
}

async fn inquiry_by_order_handler(
    State(state): State<Arc<AppState>>,
    Json(params): Json<TransactionInquiryParams>,
) -> Result<Json<some_paymob::resources::inquiries::by_order::InquiredTransaction>, ApiServerError>
{
    let tx = state
        .paymob
        .inquiries()
        .by_order_or_reference(params)
        .await?;
    Ok(Json(tx))
}

async fn inquiry_order_handler(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<u64>,
) -> Result<Json<some_paymob::OrderInquiryResponse>, ApiServerError> {
    let order = state.paymob.inquiries().order_inquiry(order_id).await?;
    Ok(Json(order))
}

#[derive(Serialize)]
struct CardTokenRedactedDto {
    token_type: String,
    id: u64,
    token: &'static str,
    masked_pan: String,
    merchant_id: u64,
    card_subtype: String,
    created_at: Option<String>,
    email: &'static str,
    order_id: String,
    next_payment_intention: Option<String>,
}

impl From<&CardTokenEnvelope> for CardTokenRedactedDto {
    fn from(env: &CardTokenEnvelope) -> Self {
        Self {
            token_type: env.token_type.clone(),
            id: env.obj.id,
            token: REDACTED_MARKER,
            masked_pan: env.obj.masked_pan.clone(),
            merchant_id: env.obj.merchant_id,
            card_subtype: env.obj.card_subtype.clone(),
            created_at: env.obj.created_at.clone(),
            email: REDACTED_MARKER,
            order_id: env.obj.order_id.clone(),
            next_payment_intention: env.obj.next_payment_intention.clone(),
        }
    }
}

async fn inquiry_card_tokens_handler(
    State(state): State<Arc<AppState>>,
    Path(order_id): Path<u64>,
) -> Result<Json<Vec<CardTokenRedactedDto>>, ApiServerError> {
    let tokens = state.paymob.inquiries().card_tokens(order_id).await?;
    let redacted = tokens.iter().map(CardTokenRedactedDto::from).collect();
    Ok(Json(redacted))
}

#[derive(Deserialize)]
struct CreateQuickLinkInput {
    amount_cents: u64,
    currency: String,
    integrations: Vec<u64>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    full_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone_number: Option<String>,
    #[serde(default)]
    redirection_url: Option<String>,
}

fn build_quicklink_params(input: CreateQuickLinkInput) -> CreateQuickLinkParams {
    let mut params =
        CreateQuickLinkParams::new(input.amount_cents, input.currency, input.integrations);
    if let Some(desc) = input.description {
        params = params.with_description(desc);
    }
    if let Some(name) = input.full_name {
        params = params.with_full_name(name);
    }
    if let Some(email) = input.email {
        params = params.with_email(email);
    }
    if let Some(phone) = input.phone_number {
        params = params.with_phone_number(phone);
    }
    if let Some(url) = input.redirection_url {
        params = params.with_redirection_url(url);
    }
    params
}

async fn create_quicklink_handler(
    State(state): State<Arc<AppState>>,
    Json(input): Json<CreateQuickLinkInput>,
) -> Result<Json<QuickLinkResponse>, ApiServerError> {
    let params = build_quicklink_params(input);
    let resp = state.paymob.quicklinks().create(&params).await?;
    Ok(Json(resp))
}

#[derive(Serialize)]
struct CancelQuickLinkResponse {
    cancelled: bool,
    link_id: String,
}

async fn cancel_quicklink_handler(
    State(state): State<Arc<AppState>>,
    Path(link_id): Path<String>,
) -> Result<Json<CancelQuickLinkResponse>, ApiServerError> {
    state.paymob.quicklinks().cancel(&link_id).await?;
    Ok(Json(CancelQuickLinkResponse {
        cancelled: true,
        link_id,
    }))
}

#[derive(Deserialize)]
struct SplitValidateAndQuoteInput {
    amount_cents: u64,
    #[serde(default)]
    split_description: Option<SplitDescription>,
    #[serde(default)]
    split_payment: Option<SplitPaymentConfig>,
    #[serde(default)]
    expected_total_cents: Option<u64>,
    #[serde(default)]
    convenience_fee: Option<ConvenienceFeeConfig>,
    #[serde(default)]
    is_credit: bool,
    #[serde(default)]
    is_international: bool,
    #[serde(default)]
    bin_prefix: Option<String>,
}

#[derive(Serialize)]
struct SplitQuoteOutput {
    valid: bool,
    amount_cents: u64,
    split_total_cents: Option<u64>,
    convenience_fee_cents: Option<u64>,
    total_with_fee_cents: Option<u64>,
}

async fn splits_validate_and_quote_handler(
    Json(input): Json<SplitValidateAndQuoteInput>,
) -> Result<Json<SplitQuoteOutput>, ApiServerError> {
    if let Some(ref desc) = input.split_description {
        desc.validate()?;
    }
    let split_total_cents = validate_split_payment(&input)?;
    let (convenience_fee_cents, total_with_fee_cents) = compute_convenience_quote(&input)?;
    Ok(Json(SplitQuoteOutput {
        valid: true,
        amount_cents: input.amount_cents,
        split_total_cents,
        convenience_fee_cents,
        total_with_fee_cents,
    }))
}

fn validate_split_payment(input: &SplitValidateAndQuoteInput) -> Result<Option<u64>, PaymobError> {
    let Some(ref split) = input.split_payment else {
        return Ok(None);
    };
    split.validate()?;
    if let Some(expected) = input.expected_total_cents {
        split.validate_total(expected)?;
    }
    Ok(Some(split.total_amount_cents()?))
}

fn compute_convenience_quote(
    input: &SplitValidateAndQuoteInput,
) -> Result<(Option<u64>, Option<u64>), PaymobError> {
    let Some(ref fee_cfg) = input.convenience_fee else {
        return Ok((None, None));
    };
    fee_cfg.validate()?;
    let mut ctx = CardFeeContext::new(input.is_credit, input.is_international);
    if let Some(ref bin) = input.bin_prefix {
        ctx = ctx.with_bin_prefix(bin);
    }
    let fee = fee_cfg.compute_fee_for_card_cents(input.amount_cents, &ctx)?;
    let total =
        input
            .amount_cents
            .checked_add(fee)
            .ok_or_else(|| PaymobError::ValidationError {
                field: "amount_cents",
                reason: String::from("total with convenience fee overflows u64"),
            })?;
    Ok((Some(fee), Some(total)))
}
