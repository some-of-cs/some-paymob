#![forbid(unsafe_code)]
//! Unit 1a gRPC RPCs: Services 1-3 (core, SandboxGuard, intentions, checkout, legacy-v2).

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use some_paymob::test_utils::sandbox::{
    SandboxCheckRequest, SandboxGuard, SandboxPaymentChannel, SandboxWarning,
};
use some_paymob::{
    AffordabilityWidgetConfig, BillingData, CreateIntentionParams, CreateLegacyOrderParams,
    CreatePaymentKeyParams, Currency, IntentionCustomer, IntentionItem, IntentionResponse,
    LegacyBillingData, LegacyCheckoutParams, LegacyOrder, LegacyOrderItem, MinorUnitAmount,
    PaymentMethodInput, PaymobError, PixelConfig, PixelPaymentMethod, UpdateIntentionParams,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::{map_error_to_grpc_status, map_sandbox_error_to_grpc_status};
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};

macro_rules! apply_opt {
    ($builder:expr, $src:expr, $($field:ident),+ $(,)?) => {{
        let mut b = $builder;
        $(
            if let Some(val) = $src.$field.take() {
                b = b.$field(val);
            }
        )+
        b
    }};
}

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
        } => {
            let msg = format!("{age_days} days old, {days_remaining} days remaining");
            format!("sandbox credentials expiring soon ({msg})")
        }
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
    let mut payload: CreateIntentionRequest = decode_request(req)?;
    let builder = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(payload.amount_cents))
        .currency(Currency::from_code(&payload.currency))
        .payment_methods(payload.payment_methods.clone());
    let builder = apply_opt!(
        builder,
        payload,
        items,
        billing_data,
        customer,
        extras,
        special_reference,
        notification_url,
        redirection_url,
        card_tokens,
    );
    let params = builder.build().map_err(map_error_to_grpc_status)?;
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
    let mut payload: UpdateIntentionRequest = decode_request(req)?;
    let mut builder = UpdateIntentionParams::builder();
    if let Some(amount_cents) = payload.amount_cents {
        builder = builder.amount(MinorUnitAmount::new(amount_cents));
    }
    if let Some(ref currency) = payload.currency {
        builder = builder.currency(Currency::from_code(currency));
    }
    builder = apply_opt!(
        builder,
        payload,
        payment_methods,
        items,
        billing_data,
        customer,
        extras,
        special_reference,
        notification_url,
        redirection_url,
        card_tokens,
    );
    let params = builder.build().map_err(map_error_to_grpc_status)?;
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
    let mut params =
        CreateLegacyOrderParams::new(payload.amount_cents, Currency::from_code(&payload.currency));
    if let Some(merchant_order_id) = payload.merchant_order_id {
        params = params.merchant_order_id(merchant_order_id);
    }
    if let Some(items) = payload.items {
        params = params.items(build_legacy_items(items));
    }
    let legacy = service
        .client
        .legacy_v2()
        .map_err(map_error_to_grpc_status)?;
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
    let legacy = service
        .client
        .legacy_v2()
        .map_err(map_error_to_grpc_status)?;
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
    let legacy = service
        .client
        .legacy_v2()
        .map_err(map_error_to_grpc_status)?;
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

pub(super) async fn dispatch_core_and_checkout(
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

pub(super) async fn dispatch_intentions_and_legacy(
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
