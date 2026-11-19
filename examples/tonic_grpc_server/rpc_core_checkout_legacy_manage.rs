#![forbid(unsafe_code)]
//! Unit 1 gRPC RPCs: Services 1-7 (core, SandboxGuard, intentions, checkout, legacy-v2, manage, inquiries, quicklinks, splits).

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
use tonic::{Request, Response, Status};

use crate::PaymobGrpcService;
use crate::error::{map_error_to_grpc_status, map_sandbox_error_to_grpc_status};
use crate::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};

/// Response returned by `GetHealth`.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Service health status (`"ok"`).
    pub status: &'static str,
    /// Configured Paymob region name.
    pub region: String,
    /// Whether the SDK client is operating in sandbox/test mode.
    pub is_sandbox: bool,
}

/// Request payload for `CheckSandboxConstraints`.
#[derive(Debug, Deserialize)]
pub struct SandboxCheckPayload {
    /// Whether sandbox mode is active.
    pub is_sandbox: bool,
    /// Age of the sandbox credentials in days.
    pub credential_age_days: u64,
    /// Payment channel (`card`, `mobile_wallet`, `kiosk`, `bnpl`, or `payouts`).
    pub channel: String,
}

/// Response returned by `CheckSandboxConstraints`.
#[derive(Debug, Serialize)]
pub struct SandboxCheckResponse {
    /// `true` when zero blocking sandbox constraint errors were found.
    pub ok: bool,
    /// Non-blocking sandbox diagnostic warnings.
    pub warnings: Vec<String>,
}

/// Request payload for `CreateIntention`.
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

/// Request payload for `UpdateIntention`.
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

/// Serializable response DTO for `CreateIntention` and `UpdateIntention`.
#[derive(Debug, Hash, Serialize)]
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

/// Request payload for `BuildPixelConfig`.
#[derive(Debug, Deserialize)]
pub struct PixelConfigRequest {
    /// Intention `client_secret` returned by `CreateIntention`.
    pub client_secret: String,
    /// Optional enabled Pixel payment methods.
    pub payment_methods: Option<Vec<PixelPaymentMethod>>,
    /// Optional UI locale (e.g., `"en"` or `"ar"`).
    pub locale: Option<String>,
}

/// Request payload for `BuildAffordabilityWidget`.
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

/// Request payload for `CreateLegacyOrder`.
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

/// Request payload for `CreateLegacyPaymentKey`.
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

/// Response returned by `CreateLegacyPaymentKey`.
#[derive(Debug, Hash, Serialize)]
pub struct PaymentKeyRouteResponse {
    /// Short-lived payment key token.
    pub token: String,
}

/// Request payload for `CreateLegacyCheckout`.
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

/// Response returned by `CreateLegacyCheckout`.
#[derive(Debug, Serialize)]
pub struct LegacyCheckoutRouteResponse {
    /// Registered legacy order.
    pub order: LegacyOrder,
    /// Generated short-lived payment key token.
    pub payment_token: String,
    /// Ready-to-render iframe URL.
    pub iframe_url: String,
}

/// Request payload for `InquireTransactionById`.
#[derive(Debug, Deserialize)]
pub struct InquireTransactionByIdRequest {
    /// Paymob transaction identifier.
    #[serde(alias = "tx_id", alias = "id")]
    pub transaction_id: u64,
}

/// Request payload for `InquireOrder` and `ListOrderCardTokens`.
#[derive(Debug, Deserialize)]
pub struct OrderIdRequest {
    /// Paymob order identifier.
    #[serde(alias = "id")]
    pub order_id: u64,
}

/// Serializable saved card token item returned by `ListOrderCardTokens`.
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

/// Request payload for `CreateQuickLink`.
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

/// Request payload for `CancelQuickLink`.
#[derive(Debug, Deserialize)]
pub struct CancelQuickLinkRequest {
    /// QuickLink identifier to cancel.
    #[serde(alias = "id")]
    pub link_id: String,
}

/// Response returned by `CancelQuickLink`.
#[derive(Debug, Serialize)]
pub struct CancelQuickLinkResponse {
    /// Cancelled QuickLink identifier.
    pub link_id: String,
    /// Always `true` when cancellation succeeded.
    pub cancelled: bool,
}

/// Request payload for `ValidateSplitsAndCalculateFee`.
#[derive(Debug, Deserialize)]
pub struct SplitsValidateAndQuoteRequest {
    /// Marketplace split recipient rules.
    pub recipients: Vec<SplitRecipientRule>,
    /// Gross transaction amount in integer minor units.
    pub amount_cents: u64,
    /// Optional convenience fee configuration to quote alongside the split.
    pub fee_config: Option<ConvenienceFeeConfig>,
}

/// Response returned by `ValidateSplitsAndCalculateFee`.
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

/// Request payload for `VoidTransaction`.
#[derive(Debug, Deserialize)]
pub struct ManageVoidRequest {
    /// Identifier of the unsettled transaction to void.
    pub transaction_id: u64,
    /// Optional flag to authenticate via Legacy Accept v2 Regime 2 (`Bearer <auth_token>`).
    #[serde(default)]
    pub use_legacy_v2_bearer: Option<bool>,
}

/// Request payload for `CaptureTransaction`.
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

fn get_health(service: &PaymobGrpcService) -> Result<Response<JsonRpcResponse>, Status> {
    let config = service.client.config();
    encode_response(&HealthResponse {
        status: "ok",
        region: format!("{:?}", config.region()),
        is_sandbox: config.environment() == some_paymob::core::credentials::EnvironmentMode::Test,
    })
}

fn check_sandbox_constraints(
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: SandboxCheckPayload = decode_request(req)?;
    let channel = parse_sandbox_channel(&payload.channel).map_err(map_error_to_grpc_status)?;
    let check_req = SandboxCheckRequest {
        is_sandbox: payload.is_sandbox,
        credential_age_days: payload.credential_age_days,
        channel,
    };
    let report = SandboxGuard::check_constraints(&check_req);
    if let Some(first_err) = report.errors.into_iter().next() {
        return Err(map_sandbox_error_to_grpc_status(first_err));
    }
    let warnings = report.warnings.iter().map(format_sandbox_warning).collect();
    encode_response(&SandboxCheckResponse { ok: true, warnings })
}

async fn create_intention(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: CreateIntentionRequest = decode_request(req)?;
    let builder = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(payload.amount_cents))
        .currency(Currency::from_code(&payload.currency))
        .payment_methods(payload.payment_methods.clone());
    let params = apply_create_intention_optionals(builder, payload)
        .build()
        .map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .intentions()
        .create(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&intention_to_dto(resp))
}

async fn update_intention(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: UpdateIntentionRequest = decode_request(req)?;
    let builder = apply_update_intention_core(UpdateIntentionParams::builder(), &payload);
    let params = apply_update_intention_meta(builder, payload)
        .build()
        .map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .intentions()
        .update(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&intention_to_dto(resp))
}

fn build_pixel_config(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: PixelConfigRequest = decode_request(req)?;
    let mut builder =
        PixelConfig::from_client(&service.client, SecretString::from(payload.client_secret))
            .map_err(map_error_to_grpc_status)?;
    if let Some(methods) = payload.payment_methods {
        builder = builder.payment_methods(methods);
    }
    if let Some(locale) = payload.locale {
        builder = builder.locale(locale);
    }
    let config = builder.build().map_err(map_error_to_grpc_status)?;
    let value = config.to_json_value().map_err(map_error_to_grpc_status)?;
    encode_response(&value)
}

fn build_affordability_widget(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: AffordabilityRequest = decode_request(req)?;
    let mut builder = AffordabilityWidgetConfig::from_client(
        &service.client,
        MinorUnitAmount::new(payload.amount_cents),
        Currency::from_code(&payload.currency),
    )
    .map_err(map_error_to_grpc_status)?;
    if let Some(banks) = payload.supported_banks {
        builder = builder.supported_banks(banks);
    }
    let mut config = builder.build().map_err(map_error_to_grpc_status)?;
    if let Some(plan_id) = payload.selected_plan_id {
        config = config
            .with_selected_plan(plan_id)
            .map_err(map_error_to_grpc_status)?;
    }
    encode_response(&config)
}

async fn create_legacy_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: CreateLegacyOrderRequest = decode_request(req)?;
    let mut params = CreateLegacyOrderParams::new(
        payload.amount_cents,
        Currency::from_code(&payload.currency),
    );
    if let Some(merchant_order_id) = payload.merchant_order_id {
        params = params.merchant_order_id(merchant_order_id);
    }
    if let Some(items) = payload.items {
        params = params.items(build_legacy_items(items));
    }
    let legacy = service.client.legacy_v2().map_err(map_error_to_grpc_status)?;
    let order = legacy
        .create_order(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&order)
}

async fn create_legacy_payment_key(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: CreatePaymentKeyRequest = decode_request(req)?;
    let billing = build_legacy_billing(payload.billing_data);
    let params = CreatePaymentKeyParams::new(
        payload.order_id,
        payload.amount_cents,
        Currency::from_code(&payload.currency),
        payload.integration_id,
        billing,
    );
    let legacy = service.client.legacy_v2().map_err(map_error_to_grpc_status)?;
    let resp = legacy
        .create_payment_key(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&PaymentKeyRouteResponse {
        token: resp.expose_token().to_owned(),
    })
}

async fn create_legacy_checkout(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: LegacyCheckoutRequest = decode_request(req)?;
    let billing = build_legacy_billing(payload.billing_data);
    let mut params = LegacyCheckoutParams::new(
        payload.amount_cents,
        Currency::from_code(&payload.currency),
        payload.integration_id,
        payload.iframe_id,
        billing,
    );
    if let Some(merchant_order_id) = payload.merchant_order_id {
        params = params.merchant_order_id(merchant_order_id);
    }
    if let Some(items) = payload.items {
        params = params.items(build_legacy_items(items));
    }
    let legacy = service.client.legacy_v2().map_err(map_error_to_grpc_status)?;
    let session = legacy
        .create_checkout(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&LegacyCheckoutRouteResponse {
        order: session.order,
        payment_token: session.payment_key.expose_token().to_owned(),
        iframe_url: session.iframe_url.to_string(),
    })
}

async fn refund_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let params: RefundParams = decode_request(req)?;
    let tx = service
        .client
        .manage()
        .refund(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn void_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: ManageVoidRequest = decode_request(req)?;
    let params = VoidParams::new(payload.transaction_id);
    let manage = if payload.use_legacy_v2_bearer.unwrap_or(false) {
        service.client.manage().with_legacy_v2_bearer()
    } else {
        service.client.manage()
    };
    let tx = manage.void(params).await.map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn capture_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: ManageCaptureRequest = decode_request(req)?;
    let params = CaptureParams::new(payload.transaction_id, payload.amount_cents);
    let manage = if payload.use_legacy_v2_bearer.unwrap_or(false) {
        service.client.manage().with_legacy_v2_bearer()
    } else {
        service.client.manage()
    };
    let tx = manage
        .capture(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn inquire_transaction_by_id(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: InquireTransactionByIdRequest = decode_request(req)?;
    let tx = service
        .client
        .inquiries()
        .by_transaction_id(payload.transaction_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn inquire_transaction_by_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let params: TransactionInquiryParams = decode_request(req)?;
    let tx = service
        .client
        .inquiries()
        .by_order_or_reference(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn inquire_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: OrderIdRequest = decode_request(req)?;
    let order: OrderInquiryResponse = service
        .client
        .inquiries()
        .order_inquiry(payload.order_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&order)
}

async fn list_order_card_tokens(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: OrderIdRequest = decode_request(req)?;
    let tokens = service
        .client
        .inquiries()
        .card_tokens(payload.order_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    let items: Vec<CardTokenRouteItem> = tokens
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
    encode_response(&items)
}

async fn create_quick_link(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: CreateQuickLinkRequest = decode_request(req)?;
    let params = CreateQuickLinkParams::new(
        payload.amount_cents,
        payload.currency.clone(),
        payload.integrations.clone(),
    );
    let params = apply_quicklink_optionals(params, payload);
    let resp: QuickLinkResponse = service
        .client
        .quicklinks()
        .create(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn cancel_quick_link(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: CancelQuickLinkRequest = decode_request(req)?;
    service
        .client
        .quicklinks()
        .cancel(&payload.link_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&CancelQuickLinkResponse {
        link_id: payload.link_id,
        cancelled: true,
    })
}

fn validate_splits_and_calculate_fee(
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let payload: SplitsValidateAndQuoteRequest = decode_request(req)?;
    let split = SplitDescription::new(payload.recipients).map_err(map_error_to_grpc_status)?;
    let total_fixed_cents = split
        .total_fixed_cents()
        .map_err(map_error_to_grpc_status)?;
    let total_percentage_bps = split
        .total_percentage_bps()
        .map_err(map_error_to_grpc_status)?;
    let (fee_cents, total_with_fee_cents) = match payload.fee_config {
        Some(cfg) => {
            cfg.validate().map_err(map_error_to_grpc_status)?;
            (
                Some(
                    cfg.compute_fee_cents(payload.amount_cents)
                        .map_err(map_error_to_grpc_status)?,
                ),
                Some(
                    cfg.total_with_fee_cents(payload.amount_cents)
                        .map_err(map_error_to_grpc_status)?,
                ),
            )
        }
        None => (None, None),
    };
    encode_response(&SplitsValidateAndQuoteResponse {
        split,
        total_fixed_cents,
        total_percentage_bps,
        fee_cents,
        total_with_fee_cents,
    })
}

async fn dispatch_core_and_checkout(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    match method {
        "GetHealth" => get_health(service),
        "CheckSandboxConstraints" => check_sandbox_constraints(req),
        "BuildPixelConfig" => build_pixel_config(service, req),
        "BuildAffordabilityWidget" => build_affordability_widget(service, req),
        _ => Err(Status::unimplemented(format!("unknown method `{method}`"))),
    }
}

async fn dispatch_intentions_and_legacy(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    match method {
        "CreateIntention" => create_intention(service, req).await,
        "UpdateIntention" => update_intention(service, req).await,
        "CreateLegacyOrder" => create_legacy_order(service, req).await,
        "CreateLegacyPaymentKey" => create_legacy_payment_key(service, req).await,
        "CreateLegacyCheckout" => create_legacy_checkout(service, req).await,
        _ => Err(Status::unimplemented(format!("unknown method `{method}`"))),
    }
}

async fn dispatch_manage_and_inquiries(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    match method {
        "RefundTransaction" => refund_transaction(service, req).await,
        "VoidTransaction" => void_transaction(service, req).await,
        "CaptureTransaction" => capture_transaction(service, req).await,
        "InquireTransactionById" => inquire_transaction_by_id(service, req).await,
        "InquireTransactionByOrder" => inquire_transaction_by_order(service, req).await,
        _ => Err(Status::unimplemented(format!("unknown method `{method}`"))),
    }
}

async fn dispatch_order_quicklinks_splits(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    match method {
        "InquireOrder" => inquire_order(service, req).await,
        "ListOrderCardTokens" => list_order_card_tokens(service, req).await,
        "CreateQuickLink" => create_quick_link(service, req).await,
        "CancelQuickLink" => cancel_quick_link(service, req).await,
        "ValidateSplitsAndCalculateFee" => validate_splits_and_calculate_fee(req),
        _ => Err(Status::unimplemented(format!("unknown method `{method}`"))),
    }
}

/// Dispatches Unit 1 gRPC unary RPCs (Services 1-7) to `PaymobGrpcService`.
pub async fn dispatch(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Option<Result<Response<JsonRpcResponse>, Status>> {
    match method {
        "GetHealth"
        | "CheckSandboxConstraints"
        | "BuildPixelConfig"
        | "BuildAffordabilityWidget" => Some(dispatch_core_and_checkout(service, method, req).await),
        "CreateIntention"
        | "UpdateIntention"
        | "CreateLegacyOrder"
        | "CreateLegacyPaymentKey"
        | "CreateLegacyCheckout" => Some(dispatch_intentions_and_legacy(service, method, req).await),
        "RefundTransaction"
        | "VoidTransaction"
        | "CaptureTransaction"
        | "InquireTransactionById"
        | "InquireTransactionByOrder" => {
            Some(dispatch_manage_and_inquiries(service, method, req).await)
        }
        "InquireOrder"
        | "ListOrderCardTokens"
        | "CreateQuickLink"
        | "CancelQuickLink"
        | "ValidateSplitsAndCalculateFee" => {
            Some(dispatch_order_quicklinks_splits(service, method, req).await)
        }
        _ => None,
    }
}
