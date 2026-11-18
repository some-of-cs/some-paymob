#![forbid(unsafe_code)]
//! Unit 1 routes: Services 1-7 (core, SandboxGuard, intentions, checkout, legacy-v2, manage, inquiries, quicklinks, splits).

use rocket::response::status::Created;
use rocket::serde::json::Json;
use rocket::{Route, State, get, post, put, routes as rocket_routes};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use some_paymob::resources::inquiries::TransactionInquiryParams;
use some_paymob::test_utils::sandbox::{
    SandboxCheckRequest, SandboxGuard, SandboxPaymentChannel, SandboxWarning,
};
use some_paymob::{
    AffordabilityWidgetConfig, BillingData, CaptureParams, ConvenienceFeeConfig,
    CreateIntentionParams, CreateIntentionParamsBuilder, CreateLegacyOrderParams,
    CreatePaymentKeyParams, CreateQuickLinkParams, Currency, IntentionCustomer, IntentionItem,
    IntentionResponse, LegacyBillingData, LegacyCheckoutParams, LegacyOrder, LegacyOrderItem,
    MinorUnitAmount, OrderInquiryResponse, PaymentMethodInput, PaymobError, PixelConfig,
    PixelPaymentMethod, QuickLinkResponse, RefundParams, SplitDescription, SplitRecipientRule,
    UpdateIntentionParams, UpdateIntentionParamsBuilder, VoidParams,
};

use super::{ApiServerError, AppState};

/// Response returned by `GET /health`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service health status (`"ok"`).
    pub status: &'static str,
    /// Configured Paymob region name.
    pub region: String,
    /// Whether the SDK client is operating in sandbox/test mode.
    pub is_sandbox: bool,
}

/// Request payload for `POST /sandbox/check`.
#[derive(Debug, Deserialize)]
pub struct SandboxCheckPayload {
    /// Whether sandbox mode is active.
    pub is_sandbox: bool,
    /// Age of the sandbox credentials in days.
    pub credential_age_days: u64,
    /// Payment channel (`card`, `mobile_wallet`, `kiosk`, `bnpl`, or `payouts`).
    pub channel: String,
}

/// Response returned by `POST /sandbox/check`.
#[derive(Debug, Serialize)]
pub struct SandboxCheckResponse {
    /// `true` when zero blocking sandbox constraint errors were found.
    pub ok: bool,
    /// Non-blocking sandbox diagnostic warnings.
    pub warnings: Vec<String>,
}

/// Request payload for `POST /intentions`.
#[derive(Debug, Deserialize)]
pub struct CreateIntentionRequest {
    /// Payment amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code (e.g., `"EGP"`).
    pub currency: String,
    /// Integration IDs or payment method names.
    pub payment_methods: Vec<PaymentMethodInput>,
    /// Optional line items.
    pub items: Option<Vec<IntentionItem>>,
    /// Optional billing details.
    pub billing_data: Option<BillingData>,
    /// Optional customer details.
    pub customer: Option<IntentionCustomer>,
    /// Optional merchant extras JSON payload.
    pub extras: Option<serde_json::Value>,
    /// Optional merchant special reference.
    pub special_reference: Option<String>,
    /// Optional webhook notification URL.
    pub notification_url: Option<String>,
    /// Optional browser redirection URL.
    pub redirection_url: Option<String>,
    /// Optional saved card tokens.
    pub card_tokens: Option<Vec<String>>,
}

/// Request payload for `PUT /intentions`.
#[derive(Debug, Deserialize)]
pub struct UpdateIntentionRequest {
    /// Optional updated amount in integer minor units.
    pub amount_cents: Option<u64>,
    /// Optional updated ISO-4217 currency code.
    pub currency: Option<String>,
    /// Optional updated integration IDs or payment method names.
    pub payment_methods: Option<Vec<PaymentMethodInput>>,
    /// Optional updated line items.
    pub items: Option<Vec<IntentionItem>>,
    /// Optional updated billing details.
    pub billing_data: Option<BillingData>,
    /// Optional updated customer details.
    pub customer: Option<IntentionCustomer>,
    /// Optional updated merchant extras JSON payload.
    pub extras: Option<serde_json::Value>,
    /// Merchant special reference identifying the intention to update.
    pub special_reference: Option<String>,
    /// Optional updated webhook notification URL.
    pub notification_url: Option<String>,
    /// Optional updated browser redirection URL.
    pub redirection_url: Option<String>,
    /// Optional updated saved card tokens.
    pub card_tokens: Option<Vec<String>>,
}

/// Serializable response DTO for `POST /intentions` and `PUT /intentions`.
#[derive(Debug, Serialize)]
pub struct IntentionRouteResponse {
    /// Paymob Payment Intention identifier.
    pub id: String,
    /// Paymob internal order ID created for this intention.
    pub intention_order_id: u64,
    /// Single-use Unified Checkout client secret.
    pub client_secret: String,
    /// Optional merchant `special_reference`.
    pub special_reference: Option<String>,
    /// Whether the intention has been confirmed/paid.
    pub confirmed: bool,
    /// Current intention lifecycle status.
    pub status: String,
    /// Optional object type discriminator.
    pub object: Option<String>,
}

/// Request payload for `POST /checkout/pixel`.
#[derive(Debug, Deserialize)]
pub struct PixelConfigRequest {
    /// Intention `client_secret` returned by `POST /intentions`.
    pub client_secret: String,
    /// Optional enabled Pixel payment methods.
    pub payment_methods: Option<Vec<PixelPaymentMethod>>,
    /// Optional UI locale (e.g., `"en"` or `"ar"`).
    pub locale: Option<String>,
}

/// Request payload for `POST /checkout/affordability`.
#[derive(Debug, Deserialize)]
pub struct AffordabilityRequest {
    /// Payment amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Optional supported bank identifiers.
    pub supported_banks: Option<Vec<String>>,
    /// Optional pre-selected installment plan ID.
    pub selected_plan_id: Option<u64>,
}

/// Line item input for legacy v2 orders.
#[derive(Debug, Deserialize)]
pub struct LegacyOrderItemInput {
    /// Item name.
    pub name: String,
    /// Item unit amount in minor units.
    pub amount_cents: u64,
    /// Item quantity.
    pub quantity: u32,
    /// Optional item description.
    pub description: Option<String>,
}

/// Request payload for `POST /legacy/orders`.
#[derive(Debug, Deserialize)]
pub struct CreateLegacyOrderRequest {
    /// Order amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Optional merchant order reference.
    pub merchant_order_id: Option<String>,
    /// Optional order line items.
    pub items: Option<Vec<LegacyOrderItemInput>>,
}

/// Billing details input for legacy v2 payment keys and checkout.
#[derive(Debug, Deserialize)]
pub struct LegacyBillingInput {
    /// Customer first name.
    pub first_name: String,
    /// Customer last name.
    pub last_name: String,
    /// Customer email address.
    pub email: String,
    /// Customer phone number.
    pub phone_number: String,
    /// Optional city.
    pub city: Option<String>,
    /// Optional country.
    pub country: Option<String>,
    /// Optional street.
    pub street: Option<String>,
}

/// Request payload for `POST /legacy/payment-keys`.
#[derive(Debug, Deserialize)]
pub struct CreatePaymentKeyRequest {
    /// Registered legacy order ID.
    pub order_id: u64,
    /// Payment amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Paymob integration ID.
    pub integration_id: u64,
    /// Customer billing details.
    pub billing_data: LegacyBillingInput,
}

/// Response returned by `POST /legacy/payment-keys`.
#[derive(Debug, Serialize)]
pub struct PaymentKeyRouteResponse {
    /// Short-lived payment key token.
    pub token: String,
}

/// Request payload for `POST /legacy/checkout`.
#[derive(Debug, Deserialize)]
pub struct LegacyCheckoutRequest {
    /// Payment amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Paymob integration ID.
    pub integration_id: u64,
    /// Paymob iframe ID.
    pub iframe_id: u64,
    /// Customer billing details.
    pub billing_data: LegacyBillingInput,
    /// Optional merchant order reference.
    pub merchant_order_id: Option<String>,
    /// Optional order line items.
    pub items: Option<Vec<LegacyOrderItemInput>>,
}

/// Response returned by `POST /legacy/checkout`.
#[derive(Debug, Serialize)]
pub struct LegacyCheckoutRouteResponse {
    /// Registered legacy order.
    pub order: LegacyOrder,
    /// Generated short-lived payment key token.
    pub payment_token: String,
    /// Ready-to-render iframe URL.
    pub iframe_url: String,
}

/// Serializable saved card token item returned by `POST /inquiries/orders/<order_id>/card-tokens`.
#[derive(Debug, Serialize)]
pub struct CardTokenRouteItem {
    /// Envelope type discriminator (typically `"TOKEN"`).
    pub token_type: String,
    /// Saved card token record identifier.
    pub id: u64,
    /// Masked card PAN.
    pub masked_pan: String,
    /// Paymob merchant identifier.
    pub merchant_id: u64,
    /// Card network or subtype.
    pub card_subtype: String,
    /// ISO-8601 creation timestamp, if provided.
    pub created_at: Option<String>,
    /// Associated Paymob order identifier.
    pub order_id: String,
    /// Optional next payment intention identifier.
    pub next_payment_intention: Option<String>,
}

/// Request payload for `POST /quicklinks`.
#[derive(Debug, Deserialize)]
pub struct CreateQuickLinkRequest {
    /// Payment link amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: String,
    /// Enabled integration IDs.
    pub integrations: Vec<u64>,
    /// Optional link description.
    pub description: Option<String>,
    /// Optional customer full name.
    pub full_name: Option<String>,
    /// Optional customer email.
    pub email: Option<String>,
    /// Optional customer phone number.
    pub phone_number: Option<String>,
    /// Optional redirection URL.
    pub redirection_url: Option<String>,
}

/// Response returned by `POST /quicklinks/<link_id>/cancel`.
#[derive(Debug, Serialize)]
pub struct CancelQuickLinkResponse {
    /// Cancelled QuickLink identifier.
    pub link_id: String,
    /// Always `true` when cancellation succeeded.
    pub cancelled: bool,
}

/// Request payload for `POST /splits/validate-and-quote`.
#[derive(Debug, Deserialize)]
pub struct SplitsValidateAndQuoteRequest {
    /// Marketplace split recipient rules.
    pub recipients: Vec<SplitRecipientRule>,
    /// Gross transaction amount in integer minor units.
    pub amount_cents: u64,
    /// Optional convenience fee configuration to quote alongside the split.
    pub fee_config: Option<ConvenienceFeeConfig>,
}

/// Response returned by `POST /splits/validate-and-quote`.
#[derive(Debug, Serialize)]
pub struct SplitsValidateAndQuoteResponse {
    /// Validated split description.
    pub split: SplitDescription,
    /// Total fixed split amount in minor units.
    pub total_fixed_cents: u64,
    /// Total percentage split in basis points.
    pub total_percentage_bps: u32,
    /// Quoted convenience fee in minor units (if `fee_config` was provided).
    pub fee_cents: Option<u64>,
    /// Total amount including convenience fee in minor units (if `fee_config` was provided).
    pub total_with_fee_cents: Option<u64>,
}

/// Request payload for `POST /manage/void`.
#[derive(Debug, Deserialize)]
pub struct ManageVoidRequest {
    /// Identifier of the unsettled transaction to void.
    pub transaction_id: u64,
    /// Optional flag to authenticate via Legacy Accept v2 Regime 2 (`Bearer <auth_token>`).
    #[serde(default)]
    pub use_legacy_v2_bearer: Option<bool>,
}

/// Request payload for `POST /manage/capture`.
#[derive(Debug, Deserialize)]
pub struct ManageCaptureRequest {
    /// Identifier of the authorized parent transaction to capture.
    pub transaction_id: u64,
    /// Capture amount in integer minor currency units.
    pub amount_cents: u64,
    /// Optional flag to authenticate via Legacy Accept v2 Regime 2 (`Bearer <auth_token>`).
    #[serde(default)]
    pub use_legacy_v2_bearer: Option<bool>,
}

const SANDBOX_CHANNELS: &[(&str, SandboxPaymentChannel)] = &[
    ("card", SandboxPaymentChannel::Card),
    ("mobile_wallet", SandboxPaymentChannel::MobileWallet),
    ("wallet", SandboxPaymentChannel::MobileWallet),
    ("kiosk", SandboxPaymentChannel::Kiosk),
    ("bnpl", SandboxPaymentChannel::Bnpl),
    ("payouts", SandboxPaymentChannel::Payouts),
];

fn parse_sandbox_channel(raw: &str) -> Result<SandboxPaymentChannel, PaymobError> {
    let normalized = raw.trim().to_ascii_lowercase();
    SANDBOX_CHANNELS
        .iter()
        .find(|(name, _)| *name == normalized)
        .map(|(_, ch)| *ch)
        .ok_or_else(|| PaymobError::ValidationError {
            field: "channel",
            reason: format!("unsupported sandbox channel `{raw}`"),
        })
}

fn format_sandbox_warning(warning: &SandboxWarning) -> String {
    match warning {
        SandboxWarning::CredentialExpiringSoon {
            age_days,
            days_remaining,
        } => format!(
            "sandbox credentials expiring soon ({age_days} days old, {days_remaining} days remaining)"
        ),
    }
}

fn intention_to_dto(resp: IntentionResponse) -> IntentionRouteResponse {
    IntentionRouteResponse {
        id: resp.id,
        intention_order_id: resp.intention_order_id,
        client_secret: resp.client_secret.expose_secret().to_owned(),
        special_reference: resp.special_reference,
        confirmed: resp.confirmed,
        status: resp.status,
        object: resp.object,
    }
}

fn build_legacy_billing(input: LegacyBillingInput) -> LegacyBillingData {
    let mut billing = LegacyBillingData::new(
        input.first_name,
        input.last_name,
        input.email,
        input.phone_number,
    );
    if let Some(city) = input.city {
        billing = billing.with_city(city);
    }
    if let Some(country) = input.country {
        billing = billing.with_country(country);
    }
    if let Some(street) = input.street {
        billing = billing.with_street(street);
    }
    billing
}

fn build_legacy_items(items: Vec<LegacyOrderItemInput>) -> Vec<LegacyOrderItem> {
    items
        .into_iter()
        .map(|item| {
            let order_item = LegacyOrderItem::new(item.name, item.amount_cents, item.quantity);
            match item.description {
                Some(desc) => order_item.with_description(desc),
                None => order_item,
            }
        })
        .collect()
}

fn apply_create_intention_content(
    mut builder: CreateIntentionParamsBuilder,
    req: &mut CreateIntentionRequest,
) -> CreateIntentionParamsBuilder {
    if let Some(items) = req.items.take() {
        builder = builder.items(items);
    }
    if let Some(billing_data) = req.billing_data.take() {
        builder = builder.billing_data(billing_data);
    }
    if let Some(customer) = req.customer.take() {
        builder = builder.customer(customer);
    }
    if let Some(extras) = req.extras.take() {
        builder = builder.extras(extras);
    }
    builder
}

fn apply_create_intention_routing(
    mut builder: CreateIntentionParamsBuilder,
    req: CreateIntentionRequest,
) -> CreateIntentionParamsBuilder {
    if let Some(special_reference) = req.special_reference {
        builder = builder.special_reference(special_reference);
    }
    if let Some(notification_url) = req.notification_url {
        builder = builder.notification_url(notification_url);
    }
    if let Some(redirection_url) = req.redirection_url {
        builder = builder.redirection_url(redirection_url);
    }
    if let Some(card_tokens) = req.card_tokens {
        builder = builder.card_tokens(card_tokens);
    }
    builder
}

fn apply_create_intention_optionals(
    builder: CreateIntentionParamsBuilder,
    mut req: CreateIntentionRequest,
) -> CreateIntentionParamsBuilder {
    let builder = apply_create_intention_content(builder, &mut req);
    apply_create_intention_routing(builder, req)
}

fn apply_update_intention_core(
    mut builder: UpdateIntentionParamsBuilder,
    req: &UpdateIntentionRequest,
) -> UpdateIntentionParamsBuilder {
    if let Some(amount_cents) = req.amount_cents {
        builder = builder.amount(MinorUnitAmount::new(amount_cents));
    }
    if let Some(ref currency) = req.currency {
        builder = builder.currency(Currency::from_code(currency));
    }
    if let Some(ref payment_methods) = req.payment_methods {
        builder = builder.payment_methods(payment_methods.clone());
    }
    if let Some(ref items) = req.items {
        builder = builder.items(items.clone());
    }
    builder
}

fn apply_update_intention_parties(
    mut builder: UpdateIntentionParamsBuilder,
    req: &mut UpdateIntentionRequest,
) -> UpdateIntentionParamsBuilder {
    if let Some(billing_data) = req.billing_data.take() {
        builder = builder.billing_data(billing_data);
    }
    if let Some(customer) = req.customer.take() {
        builder = builder.customer(customer);
    }
    if let Some(extras) = req.extras.take() {
        builder = builder.extras(extras);
    }
    builder
}

fn apply_update_intention_routing(
    mut builder: UpdateIntentionParamsBuilder,
    req: UpdateIntentionRequest,
) -> UpdateIntentionParamsBuilder {
    if let Some(special_reference) = req.special_reference {
        builder = builder.special_reference(special_reference);
    }
    if let Some(notification_url) = req.notification_url {
        builder = builder.notification_url(notification_url);
    }
    if let Some(redirection_url) = req.redirection_url {
        builder = builder.redirection_url(redirection_url);
    }
    if let Some(card_tokens) = req.card_tokens {
        builder = builder.card_tokens(card_tokens);
    }
    builder
}

fn apply_update_intention_meta(
    builder: UpdateIntentionParamsBuilder,
    mut req: UpdateIntentionRequest,
) -> UpdateIntentionParamsBuilder {
    let builder = apply_update_intention_parties(builder, &mut req);
    apply_update_intention_routing(builder, req)
}

#[get("/health")]
fn health(state: &State<AppState>) -> Json<HealthResponse> {
    let config = state.client.config();
    Json(HealthResponse {
        status: "ok",
        region: format!("{:?}", config.region()),
        is_sandbox: config.environment() == some_paymob::core::credentials::EnvironmentMode::Test,
    })
}

#[post("/sandbox/check", data = "<payload>")]
fn sandbox_check(
    payload: Json<SandboxCheckPayload>,
) -> Result<Json<SandboxCheckResponse>, ApiServerError> {
    let channel = parse_sandbox_channel(&payload.channel)?;
    let req = SandboxCheckRequest {
        is_sandbox: payload.is_sandbox,
        credential_age_days: payload.credential_age_days,
        channel,
    };
    let report = SandboxGuard::check_constraints(&req);
    if let Some(first_err) = report.errors.into_iter().next() {
        return Err(ApiServerError::from(first_err));
    }
    let warnings = report.warnings.iter().map(format_sandbox_warning).collect();
    Ok(Json(SandboxCheckResponse { ok: true, warnings }))
}

#[post("/intentions", data = "<payload>")]
async fn create_intention(
    state: &State<AppState>,
    payload: Json<CreateIntentionRequest>,
) -> Result<Created<Json<IntentionRouteResponse>>, ApiServerError> {
    let req = payload.into_inner();
    let builder = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(req.amount_cents))
        .currency(Currency::from_code(&req.currency))
        .payment_methods(req.payment_methods.clone());
    let params = apply_create_intention_optionals(builder, req).build()?;
    let resp = state.client.intentions().create(params).await?;
    Ok(Created::new("").tagged_body(Json(intention_to_dto(resp))))
}

#[put("/intentions", data = "<payload>")]
async fn update_intention(
    state: &State<AppState>,
    payload: Json<UpdateIntentionRequest>,
) -> Result<Json<IntentionRouteResponse>, ApiServerError> {
    let req = payload.into_inner();
    let builder = apply_update_intention_core(UpdateIntentionParams::builder(), &req);
    let params = apply_update_intention_meta(builder, req).build()?;
    let resp = state.client.intentions().update(params).await?;
    Ok(Json(intention_to_dto(resp)))
}

#[post("/checkout/pixel", data = "<payload>")]
fn checkout_pixel(
    state: &State<AppState>,
    payload: Json<PixelConfigRequest>,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let req = payload.into_inner();
    let mut builder =
        PixelConfig::from_client(&state.client, SecretString::from(req.client_secret))?;
    if let Some(methods) = req.payment_methods {
        builder = builder.payment_methods(methods);
    }
    if let Some(locale) = req.locale {
        builder = builder.locale(locale);
    }
    let config = builder.build()?;
    Ok(Json(config.to_json_value()?))
}

#[post("/checkout/affordability", data = "<payload>")]
fn checkout_affordability(
    state: &State<AppState>,
    payload: Json<AffordabilityRequest>,
) -> Result<Json<AffordabilityWidgetConfig>, ApiServerError> {
    let req = payload.into_inner();
    let mut builder = AffordabilityWidgetConfig::from_client(
        &state.client,
        MinorUnitAmount::new(req.amount_cents),
        Currency::from_code(&req.currency),
    )?;
    if let Some(banks) = req.supported_banks {
        builder = builder.supported_banks(banks);
    }
    let mut config = builder.build()?;
    if let Some(plan_id) = req.selected_plan_id {
        config = config.with_selected_plan(plan_id)?;
    }
    Ok(Json(config))
}

#[post("/legacy/orders", data = "<payload>")]
async fn legacy_create_order(
    state: &State<AppState>,
    payload: Json<CreateLegacyOrderRequest>,
) -> Result<Created<Json<LegacyOrder>>, ApiServerError> {
    let req = payload.into_inner();
    let mut params =
        CreateLegacyOrderParams::new(req.amount_cents, Currency::from_code(&req.currency));
    if let Some(merchant_order_id) = req.merchant_order_id {
        params = params.merchant_order_id(merchant_order_id);
    }
    if let Some(items) = req.items {
        params = params.items(build_legacy_items(items));
    }
    let service = state.client.legacy_v2()?;
    let order = service.create_order(&params).await?;
    Ok(Created::new("").tagged_body(Json(order)))
}

#[post("/legacy/payment-keys", data = "<payload>")]
async fn legacy_create_payment_key(
    state: &State<AppState>,
    payload: Json<CreatePaymentKeyRequest>,
) -> Result<Created<Json<PaymentKeyRouteResponse>>, ApiServerError> {
    let req = payload.into_inner();
    let billing = build_legacy_billing(req.billing_data);
    let params = CreatePaymentKeyParams::new(
        req.order_id,
        req.amount_cents,
        Currency::from_code(&req.currency),
        req.integration_id,
        billing,
    );
    let service = state.client.legacy_v2()?;
    let resp = service.create_payment_key(&params).await?;
    Ok(Created::new("").tagged_body(Json(PaymentKeyRouteResponse {
        token: resp.expose_token().to_owned(),
    })))
}

#[post("/legacy/checkout", data = "<payload>")]
async fn legacy_create_checkout(
    state: &State<AppState>,
    payload: Json<LegacyCheckoutRequest>,
) -> Result<Created<Json<LegacyCheckoutRouteResponse>>, ApiServerError> {
    let req = payload.into_inner();
    let billing = build_legacy_billing(req.billing_data);
    let mut params = LegacyCheckoutParams::new(
        req.amount_cents,
        Currency::from_code(&req.currency),
        req.integration_id,
        req.iframe_id,
        billing,
    );
    if let Some(merchant_order_id) = req.merchant_order_id {
        params = params.merchant_order_id(merchant_order_id);
    }
    if let Some(items) = req.items {
        params = params.items(build_legacy_items(items));
    }
    let service = state.client.legacy_v2()?;
    let session = service.create_checkout(&params).await?;
    Ok(Created::new("").tagged_body(Json(LegacyCheckoutRouteResponse {
        order: session.order,
        payment_token: session.payment_key.expose_token().to_owned(),
        iframe_url: session.iframe_url.to_string(),
    })))
}

#[post("/manage/refund", data = "<payload>")]
async fn manage_refund(
    state: &State<AppState>,
    payload: Json<RefundParams>,
) -> Result<Json<some_paymob::resources::manage::Transaction>, ApiServerError> {
    let tx = state.client.manage().refund(payload.into_inner()).await?;
    Ok(Json(tx))
}

#[post("/manage/void", data = "<payload>")]
async fn manage_void(
    state: &State<AppState>,
    payload: Json<ManageVoidRequest>,
) -> Result<Json<some_paymob::resources::manage::Transaction>, ApiServerError> {
    let req = payload.into_inner();
    let params = VoidParams::new(req.transaction_id);
    let service = if req.use_legacy_v2_bearer.unwrap_or(false) {
        state.client.manage().with_legacy_v2_bearer()
    } else {
        state.client.manage()
    };
    let tx = service.void(params).await?;
    Ok(Json(tx))
}

#[post("/manage/capture", data = "<payload>")]
async fn manage_capture(
    state: &State<AppState>,
    payload: Json<ManageCaptureRequest>,
) -> Result<Json<some_paymob::resources::manage::Transaction>, ApiServerError> {
    let req = payload.into_inner();
    let params = CaptureParams::new(req.transaction_id, req.amount_cents);
    let service = if req.use_legacy_v2_bearer.unwrap_or(false) {
        state.client.manage().with_legacy_v2_bearer()
    } else {
        state.client.manage()
    };
    let tx = service.capture(params).await?;
    Ok(Json(tx))
}

#[get("/inquiries/transactions/<tx_id>")]
async fn inquiry_by_tx_id(
    state: &State<AppState>,
    tx_id: u64,
) -> Result<Json<some_paymob::resources::inquiries::Transaction>, ApiServerError> {
    let tx = state.client.inquiries().by_transaction_id(tx_id).await?;
    Ok(Json(tx))
}

#[post("/inquiries/by-order", data = "<payload>")]
async fn inquiry_by_order(
    state: &State<AppState>,
    payload: Json<TransactionInquiryParams>,
) -> Result<Json<some_paymob::resources::inquiries::by_order::InquiredTransaction>, ApiServerError>
{
    let tx = state
        .client
        .inquiries()
        .by_order_or_reference(payload.into_inner())
        .await?;
    Ok(Json(tx))
}

#[get("/inquiries/orders/<order_id>")]
async fn inquiry_order(
    state: &State<AppState>,
    order_id: u64,
) -> Result<Json<OrderInquiryResponse>, ApiServerError> {
    let order = state.client.inquiries().order_inquiry(order_id).await?;
    Ok(Json(order))
}

#[post("/inquiries/orders/<order_id>/card-tokens")]
async fn inquiry_order_card_tokens(
    state: &State<AppState>,
    order_id: u64,
) -> Result<Json<Vec<CardTokenRouteItem>>, ApiServerError> {
    let tokens = state.client.inquiries().card_tokens(order_id).await?;
    let items = tokens
        .into_iter()
        .map(|env| CardTokenRouteItem {
            token_type: env.token_type,
            id: env.obj.id,
            masked_pan: env.obj.masked_pan.clone(),
            merchant_id: env.obj.merchant_id,
            card_subtype: env.obj.card_subtype.clone(),
            created_at: env.obj.created_at.clone(),
            order_id: env.obj.order_id.clone(),
            next_payment_intention: env.obj.next_payment_intention.clone(),
        })
        .collect();
    Ok(Json(items))
}

fn apply_quicklink_contact(
    mut params: CreateQuickLinkParams,
    req: &mut CreateQuickLinkRequest,
) -> CreateQuickLinkParams {
    if let Some(full_name) = req.full_name.take() {
        params = params.with_full_name(full_name);
    }
    if let Some(email) = req.email.take() {
        params = params.with_email(email);
    }
    if let Some(phone_number) = req.phone_number.take() {
        params = params.with_phone_number(phone_number);
    }
    params
}

fn apply_quicklink_optionals(
    params: CreateQuickLinkParams,
    mut req: CreateQuickLinkRequest,
) -> CreateQuickLinkParams {
    let mut params = apply_quicklink_contact(params, &mut req);
    if let Some(description) = req.description {
        params = params.with_description(description);
    }
    if let Some(redirection_url) = req.redirection_url {
        params = params.with_redirection_url(redirection_url);
    }
    params
}

#[post("/quicklinks", data = "<payload>")]
async fn create_quicklink(
    state: &State<AppState>,
    payload: Json<CreateQuickLinkRequest>,
) -> Result<Created<Json<QuickLinkResponse>>, ApiServerError> {
    let req = payload.into_inner();
    let params = CreateQuickLinkParams::new(
        req.amount_cents,
        req.currency.clone(),
        req.integrations.clone(),
    );
    let params = apply_quicklink_optionals(params, req);
    let resp = state.client.quicklinks().create(&params).await?;
    Ok(Created::new("").tagged_body(Json(resp)))
}

#[post("/quicklinks/<link_id>/cancel")]
async fn cancel_quicklink(
    state: &State<AppState>,
    link_id: &str,
) -> Result<Json<CancelQuickLinkResponse>, ApiServerError> {
    state.client.quicklinks().cancel(link_id).await?;
    Ok(Json(CancelQuickLinkResponse {
        link_id: link_id.to_owned(),
        cancelled: true,
    }))
}

#[post("/splits/validate-and-quote", data = "<payload>")]
fn splits_validate_and_quote(
    payload: Json<SplitsValidateAndQuoteRequest>,
) -> Result<Json<SplitsValidateAndQuoteResponse>, ApiServerError> {
    let req = payload.into_inner();
    let split = SplitDescription::new(req.recipients)?;
    let total_fixed_cents = split.total_fixed_cents()?;
    let total_percentage_bps = split.total_percentage_bps()?;
    let (fee_cents, total_with_fee_cents) = match req.fee_config {
        Some(cfg) => {
            cfg.validate()?;
            (
                Some(cfg.compute_fee_cents(req.amount_cents)?),
                Some(cfg.total_with_fee_cents(req.amount_cents)?),
            )
        }
        None => (None, None),
    };
    Ok(Json(SplitsValidateAndQuoteResponse {
        split,
        total_fixed_cents,
        total_percentage_bps,
        fee_cents,
        total_with_fee_cents,
    }))
}

/// Returns all Unit 1 Rocket routes for Services 1-7.
#[must_use]
pub fn routes() -> Vec<Route> {
    rocket_routes![
        health,
        sandbox_check,
        create_intention,
        update_intention,
        checkout_pixel,
        checkout_affordability,
        legacy_create_order,
        legacy_create_payment_key,
        legacy_create_checkout,
        manage_refund,
        manage_void,
        manage_capture,
        inquiry_by_tx_id,
        inquiry_by_order,
        inquiry_order,
        inquiry_order_card_tokens,
        create_quicklink,
        cancel_quicklink,
        splits_validate_and_quote,
    ]
}
