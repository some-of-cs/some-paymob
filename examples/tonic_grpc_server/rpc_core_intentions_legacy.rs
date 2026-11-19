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

macro_rules! apply_intention_common {
    ($builder:expr, $src:expr) => {{
        let mut b = $builder;
        if let Some(v) = $src.items.take() {
            b = b.items(v);
        }
        if let Some(v) = $src.billing_data.take() {
            b = b.billing_data(v);
        }
        if let Some(v) = $src.customer.take() {
            b = b.customer(v);
        }
        if let Some(v) = $src.extras.take() {
            b = b.extras(v);
        }
        if let Some(v) = $src.special_reference.take() {
            b = b.special_reference(v);
        }
        if let Some(v) = $src.notification_url.take() {
            b = b.notification_url(v);
        }
        if let Some(v) = $src.redirection_url.take() {
            b = b.redirection_url(v);
        }
        if let Some(v) = $src.card_tokens.take() {
            b = b.card_tokens(v);
        }
        b
    }};
}

macro_rules! apply_legacy_opts {
    ($params:expr, $src:expr) => {{
        let mut p = $params;
        if let Some(id) = $src.merchant_order_id {
            p = p.merchant_order_id(id);
        }
        if let Some(items) = $src.items {
            p = p.items(build_legacy_items(items));
        }
        p
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

async fn get_health(
    service: &PaymobGrpcService,
    _req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let config = service.client.config();
    encode_response(&HealthResponse {
        status: "ok",
        region: format!("{:?}", config.region()),
        is_sandbox: config.environment() == some_paymob::core::credentials::EnvironmentMode::Test,
    })
}

async fn check_sandbox_constraints(
    _service: &PaymobGrpcService,
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
    rpc_call!(req, |mut p: CreateIntentionRequest| async {
        let builder = CreateIntentionParams::builder()
            .amount(MinorUnitAmount::new(p.amount_cents))
            .currency(Currency::from_code(&p.currency))
            .payment_methods(p.payment_methods.clone());
        let builder = apply_intention_common!(builder, p);
        let resp = service.client.intentions().create(builder.build()?).await?;
        Ok(intention_to_dto(resp))
    }
    .await)
}

async fn update_intention(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |mut p: UpdateIntentionRequest| async {
        let mut builder = UpdateIntentionParams::builder();
        if let Some(amount_cents) = p.amount_cents {
            builder = builder.amount(MinorUnitAmount::new(amount_cents));
        }
        if let Some(ref currency) = p.currency {
            builder = builder.currency(Currency::from_code(currency));
        }
        if let Some(methods) = p.payment_methods.take() {
            builder = builder.payment_methods(methods);
        }
        builder = apply_intention_common!(builder, p);
        let resp = service.client.intentions().update(builder.build()?).await?;
        Ok(intention_to_dto(resp))
    }
    .await)
}

async fn build_pixel_config(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: PixelConfigRequest| async {
        let mut builder =
            PixelConfig::from_client(&service.client, SecretString::from(p.client_secret))?;
        if let Some(methods) = p.payment_methods {
            builder = builder.payment_methods(methods);
        }
        if let Some(locale) = p.locale {
            builder = builder.locale(locale);
        }
        builder.build()?.to_json_value()
    }
    .await)
}

async fn build_affordability_widget(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: AffordabilityRequest| async {
        let mut builder = AffordabilityWidgetConfig::from_client(
            &service.client,
            MinorUnitAmount::new(p.amount_cents),
            Currency::from_code(&p.currency),
        )?;
        if let Some(banks) = p.supported_banks {
            builder = builder.supported_banks(banks);
        }
        let mut config = builder.build()?;
        if let Some(plan_id) = p.selected_plan_id {
            config = config.with_selected_plan(plan_id)?;
        }
        Ok(config)
    }
    .await)
}

async fn create_legacy_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: CreateLegacyOrderRequest| async {
        let params = apply_legacy_opts!(
            CreateLegacyOrderParams::new(p.amount_cents, Currency::from_code(&p.currency)),
            p
        );
        service.client.legacy_v2()?.create_order(&params).await
    }
    .await)
}

async fn create_legacy_payment_key(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: CreatePaymentKeyRequest| async {
        let params = CreatePaymentKeyParams::new(
            p.order_id,
            p.amount_cents,
            Currency::from_code(&p.currency),
            p.integration_id,
            build_legacy_billing(p.billing_data),
        );
        let resp = service
            .client
            .legacy_v2()?
            .create_payment_key(&params)
            .await?;
        Ok(PaymentKeyRouteResponse {
            token: resp.expose_token().to_owned(),
        })
    }
    .await)
}

async fn create_legacy_checkout(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    rpc_call!(req, |p: LegacyCheckoutRequest| async {
        let params = apply_legacy_opts!(
            LegacyCheckoutParams::new(
                p.amount_cents,
                Currency::from_code(&p.currency),
                p.integration_id,
                p.iframe_id,
                build_legacy_billing(p.billing_data),
            ),
            p
        );
        let session = service.client.legacy_v2()?.create_checkout(&params).await?;
        Ok(LegacyCheckoutRouteResponse {
            order: session.order,
            payment_token: session.payment_key.expose_token().to_owned(),
            iframe_url: session.iframe_url.to_string(),
        })
    }
    .await)
}

dispatch_group!(
    dispatch_core_and_checkout,
    "GetHealth" => get_health,
    "CheckSandboxConstraints" => check_sandbox_constraints,
    "BuildPixelConfig" => build_pixel_config,
    "BuildAffordabilityWidget" => build_affordability_widget,
);

dispatch_group!(
    dispatch_intentions_and_legacy,
    "CreateIntention" => create_intention,
    "UpdateIntention" => update_intention,
    "CreateLegacyOrder" => create_legacy_order,
    "CreateLegacyPaymentKey" => create_legacy_payment_key,
    "CreateLegacyCheckout" => create_legacy_checkout,
);
