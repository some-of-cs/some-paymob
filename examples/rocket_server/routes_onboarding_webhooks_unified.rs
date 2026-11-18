#![forbid(unsafe_code)]
//! Unit 3 routes: Services 13-14 (onboarding, multi-tenant scoped, webhooks Protocols A-E, unified adapter).

use rocket::data::{ByteUnit, Data};
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome, Request};
use rocket::response::status::Created;
use rocket::serde::json::Json;
use rocket::{Route, State, get, post, put, routes};
use serde::{Deserialize, Serialize};
use some_paymob::resources::inquiries::TransactionInquiryParams;
use some_paymob::{
    CaptureParams, CreateIntentionParams, CreatePartnerApiKeyParams, Currency, IntentionResponse,
    MinorUnitAmount, OnboardingSchemaQuery, PartnerLoginCredentials,
    PartnerMerchantInquiryResponse, PaymentMethodInput, PaymentProvider, PayoutProvider,
    RefundParams, RegisterMerchantParams, RegisteredMerchantResponse, SubmitOnboardingStepParams,
    SubmitOnboardingStepResponse, SubscriptionProvider, UnifiedCaptureReceipt,
    UnifiedCaptureRequest, UnifiedPaymentSessionRequest, UnifiedPayoutReceipt,
    UnifiedPayoutRequest, UnifiedRefundReceipt, UnifiedRefundRequest,
    UnifiedSavedMethodChargeReceipt, UnifiedSavedMethodChargeRequest,
    UnifiedSubscriptionRefundReceipt, UnifiedSubscriptionRefundRequest, UnifiedVoidReceipt,
    UnifiedVoidRequest, UnifiedWebhookOutcome, UpdateIntentionParams, VoidParams,
};

use super::{ApiServerError, AppState};

struct RawQuery(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RawQuery {
    type Error = std::convert::Infallible;

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let query = req
            .uri()
            .query()
            .map_or_else(String::new, |q| q.as_str().to_owned());
        Outcome::Success(Self(query))
    }
}

#[derive(Debug, Deserialize)]
struct PartnerLoginInput {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct PartnerAuthAck {
    authenticated: bool,
    token_present: bool,
}

#[derive(Debug, Serialize)]
struct PartnerApiKeyAck {
    provisioned: bool,
    label: Option<String>,
}

#[derive(Debug, Serialize)]
struct PartnerHmacAck {
    status: String,
    code: u16,
    label: Option<String>,
    hmac_present: bool,
}

#[derive(Debug, Deserialize)]
struct ScopedCreateIntentionInput {
    amount: MinorUnitAmount,
    currency: Currency,
    payment_methods: Vec<PaymentMethodInput>,
    #[serde(default)]
    special_reference: Option<String>,
    #[serde(default)]
    notification_url: Option<String>,
    #[serde(default)]
    redirection_url: Option<String>,
    #[serde(default)]
    expiration: Option<u64>,
    #[serde(default)]
    extras: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct ScopedUpdateIntentionInput {
    #[serde(default)]
    amount: Option<MinorUnitAmount>,
    #[serde(default)]
    currency: Option<Currency>,
    #[serde(default)]
    payment_methods: Option<Vec<PaymentMethodInput>>,
    #[serde(default)]
    special_reference: Option<String>,
    #[serde(default)]
    notification_url: Option<String>,
    #[serde(default)]
    redirection_url: Option<String>,
}

#[derive(Debug, Hash, Serialize)]
struct IntentionSummaryDto {
    id: String,
    intention_order_id: u64,
    status: String,
    confirmed: bool,
    special_reference: Option<String>,
    created: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebhookAckDto {
    event_type: String,
    verified: bool,
    deduplicated: bool,
}

#[derive(Debug, Serialize)]
struct RedirectWebhookAckDto {
    id: String,
    order_id: String,
    currency: String,
    amount_cents: String,
    approved: bool,
    pending: bool,
    deduplicated: bool,
}

#[derive(Debug, Hash, Serialize)]
struct UnifiedSessionDto {
    session_id: String,
    order_id: String,
    status: String,
    confirmed: bool,
}

#[derive(Debug, Deserialize)]
struct UnifiedSavedChargeInput {
    payment_token: String,
    saved_method_token: String,
    #[serde(default)]
    cvn: Option<String>,
}

fn intention_summary(resp: IntentionResponse) -> IntentionSummaryDto {
    IntentionSummaryDto {
        id: resp.id,
        intention_order_id: resp.intention_order_id,
        status: resp.status,
        confirmed: resp.confirmed,
        special_reference: resp.special_reference,
        created: resp.created,
    }
}

fn apply_scoped_create_urls(
    mut builder: some_paymob::CreateIntentionParamsBuilder,
    input: &mut ScopedCreateIntentionInput,
) -> some_paymob::CreateIntentionParamsBuilder {
    if let Some(reference) = input.special_reference.take() {
        builder = builder.special_reference(reference);
    }
    if let Some(url) = input.notification_url.take() {
        builder = builder.notification_url(url);
    }
    if let Some(url) = input.redirection_url.take() {
        builder = builder.redirection_url(url);
    }
    builder
}

fn build_scoped_create_params(
    mut input: ScopedCreateIntentionInput,
) -> Result<CreateIntentionParams, ApiServerError> {
    let builder = CreateIntentionParams::builder()
        .amount(input.amount)
        .currency(input.currency.clone())
        .payment_methods(std::mem::take(&mut input.payment_methods));
    let mut builder = apply_scoped_create_urls(builder, &mut input);
    if let Some(exp) = input.expiration {
        builder = builder.expiration(exp);
    }
    if let Some(extras) = input.extras {
        builder = builder.extras(extras);
    }
    builder.build().map_err(ApiServerError::from)
}

fn apply_scoped_update_core(
    mut builder: some_paymob::UpdateIntentionParamsBuilder,
    input: &mut ScopedUpdateIntentionInput,
) -> some_paymob::UpdateIntentionParamsBuilder {
    if let Some(amount) = input.amount.take() {
        builder = builder.amount(amount);
    }
    if let Some(currency) = input.currency.take() {
        builder = builder.currency(currency);
    }
    if let Some(methods) = input.payment_methods.take() {
        builder = builder.payment_methods(methods);
    }
    builder
}

fn apply_scoped_update_urls(
    mut builder: some_paymob::UpdateIntentionParamsBuilder,
    input: ScopedUpdateIntentionInput,
) -> some_paymob::UpdateIntentionParamsBuilder {
    if let Some(reference) = input.special_reference {
        builder = builder.special_reference(reference);
    }
    if let Some(url) = input.notification_url {
        builder = builder.notification_url(url);
    }
    if let Some(url) = input.redirection_url {
        builder = builder.redirection_url(url);
    }
    builder
}

fn build_scoped_update_params(
    mut input: ScopedUpdateIntentionInput,
) -> Result<UpdateIntentionParams, ApiServerError> {
    let builder = apply_scoped_update_core(UpdateIntentionParams::builder(), &mut input);
    let builder = apply_scoped_update_urls(builder, input);
    builder.build().map_err(ApiServerError::from)
}

async fn read_body_text(data: Data<'_>) -> Result<String, ApiServerError> {
    let limited = data
        .open(ByteUnit::Megabyte(1))
        .into_string()
        .await
        .map_err(|err| ApiServerError {
            status: Status::BadRequest,
            error: "invalid_body".to_string(),
            message: err.to_string(),
            retry_after_secs: None,
        })?;
    if !limited.is_complete() {
        return Err(ApiServerError {
            status: Status::PayloadTooLarge,
            error: "payload_too_large".to_string(),
            message: "webhook payload exceeds 1 MiB limit".to_string(),
            retry_after_secs: None,
        });
    }
    Ok(limited.into_inner())
}

// ---------------------------------------------------------------------------
// Service 13: Partner Merchant Onboarding (/onboarding/auth/*, /onboarding/flow/*)
// ---------------------------------------------------------------------------

#[post("/onboarding/auth/login", data = "<body>")]
async fn onboarding_auth_login(
    state: &State<AppState>,
    body: Json<PartnerLoginInput>,
) -> Result<Json<PartnerAuthAck>, ApiServerError> {
    let input = body.into_inner();
    let creds = PartnerLoginCredentials::try_new(input.username, input.password)?;
    let resp = state.client.onboarding().auth().login(creds).await?;
    Ok(Json(PartnerAuthAck {
        authenticated: true,
        token_present: !resp.token().is_empty(),
    }))
}

#[post("/onboarding/auth/api-key", data = "<body>")]
async fn onboarding_auth_create_api_key(
    state: &State<AppState>,
    body: Json<CreatePartnerApiKeyParams>,
) -> Result<Json<PartnerApiKeyAck>, ApiServerError> {
    let resp = state
        .client
        .onboarding()
        .auth()
        .create_api_key(body.into_inner())
        .await?;
    Ok(Json(PartnerApiKeyAck {
        provisioned: !resp.api_key().is_empty(),
        label: resp.label.clone(),
    }))
}

#[get("/onboarding/auth/hmac-secret")]
async fn onboarding_auth_hmac_secret(
    state: &State<AppState>,
) -> Result<Json<PartnerHmacAck>, ApiServerError> {
    let env = state
        .client
        .onboarding()
        .auth()
        .retrieve_hmac_secret()
        .await?;
    Ok(Json(PartnerHmacAck {
        status: env.status.clone(),
        code: env.code,
        label: env.label.clone(),
        hmac_present: !env.hmac_secret().is_empty(),
    }))
}

#[get("/onboarding/auth/merchants/<mid>/hmac-secret")]
async fn onboarding_auth_merchant_hmac_secret(
    state: &State<AppState>,
    mid: u64,
) -> Result<Json<PartnerHmacAck>, ApiServerError> {
    let env = state
        .client
        .onboarding()
        .auth()
        .retrieve_merchant_hmac_secret(mid)
        .await?;
    Ok(Json(PartnerHmacAck {
        status: env.status.clone(),
        code: env.code,
        label: env.label.clone(),
        hmac_present: !env.hmac_secret().is_empty(),
    }))
}

#[get("/onboarding/flow/schema?<partner>&<resubmission>&<paymob_mid>")]
async fn onboarding_flow_schema(
    state: &State<AppState>,
    partner: String,
    resubmission: Option<bool>,
    paymob_mid: Option<u64>,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let mut query = OnboardingSchemaQuery::new(partner)?;
    query.resubmission = resubmission;
    query.paymob_mid = paymob_mid;
    let schema = state.client.onboarding().flow().get_schema(&query).await?;
    let val = serde_json::to_value(schema).map_err(|err| ApiServerError {
        status: Status::InternalServerError,
        error: "serialization_error".to_string(),
        message: err.to_string(),
        retry_after_secs: None,
    })?;
    Ok(Json(val))
}

#[post("/onboarding/flow/register", data = "<body>")]
async fn onboarding_flow_register(
    state: &State<AppState>,
    body: Json<RegisterMerchantParams>,
) -> Result<Created<Json<RegisteredMerchantResponse>>, ApiServerError> {
    let resp = state
        .client
        .onboarding()
        .flow()
        .register_merchant(&body.into_inner())
        .await?;
    Ok(Created::new("").body(Json(resp)))
}

#[post("/onboarding/flow/submit-step", data = "<body>")]
async fn onboarding_flow_submit_step(
    state: &State<AppState>,
    body: Json<SubmitOnboardingStepParams>,
) -> Result<Json<SubmitOnboardingStepResponse>, ApiServerError> {
    let resp = state
        .client
        .onboarding()
        .flow()
        .submit_step(&body.into_inner())
        .await?;
    Ok(Json(resp))
}

#[get("/onboarding/flow/inquiry/<mid>")]
async fn onboarding_flow_inquiry(
    state: &State<AppState>,
    mid: u64,
) -> Result<Json<PartnerMerchantInquiryResponse>, ApiServerError> {
    let resp = state
        .client
        .onboarding()
        .flow()
        .merchant_inquiry(mid)
        .await?;
    Ok(Json(resp))
}

// ---------------------------------------------------------------------------
// Service 14: Multi-Tenant Scoping (/merchants/<mid>/...)
// ---------------------------------------------------------------------------

#[post("/merchants/<mid>/intentions", data = "<body>")]
async fn merchant_create_intention(
    state: &State<AppState>,
    mid: u64,
    body: Json<ScopedCreateIntentionInput>,
) -> Result<Created<Json<IntentionSummaryDto>>, ApiServerError> {
    let params = build_scoped_create_params(body.into_inner())?;
    let scoped = state.client.with_merchant(mid)?;
    let resp = scoped.intentions().create(&params).await?;
    Ok(Created::new("").tagged_body(Json(intention_summary(resp))))
}

#[put("/merchants/<mid>/intentions", data = "<body>")]
async fn merchant_update_intention(
    state: &State<AppState>,
    mid: u64,
    body: Json<ScopedUpdateIntentionInput>,
) -> Result<Json<IntentionSummaryDto>, ApiServerError> {
    let params = build_scoped_update_params(body.into_inner())?;
    let scoped = state.client.with_merchant(mid)?;
    let resp = scoped.intentions().update(&params).await?;
    Ok(Json(intention_summary(resp)))
}

#[put("/merchants/<mid>/intentions/<client_secret>", data = "<body>")]
async fn merchant_update_intention_by_secret(
    state: &State<AppState>,
    mid: u64,
    client_secret: String,
    body: Json<ScopedUpdateIntentionInput>,
) -> Result<Json<IntentionSummaryDto>, ApiServerError> {
    let params = build_scoped_update_params(body.into_inner())?;
    let scoped = state.client.with_merchant(mid)?;
    let resp = scoped
        .intentions()
        .update_by_client_secret(&client_secret, &params)
        .await?;
    Ok(Json(intention_summary(resp)))
}

#[get("/merchants/<mid>/inquiries/transactions/<tx_id>")]
async fn merchant_inquire_transaction(
    state: &State<AppState>,
    mid: u64,
    tx_id: u64,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let scoped = state.client.with_merchant(mid)?;
    let tx = scoped.inquiries().transaction(tx_id).await?;
    let val = serde_json::to_value(tx).map_err(|err| ApiServerError {
        status: Status::InternalServerError,
        error: "serialization_error".to_string(),
        message: err.to_string(),
        retry_after_secs: None,
    })?;
    Ok(Json(val))
}

#[get("/merchants/<mid>/inquiries/transactions/<tx_id>/raw")]
async fn merchant_inquire_transaction_raw(
    state: &State<AppState>,
    mid: u64,
    tx_id: u64,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let scoped = state.client.with_merchant(mid)?;
    let val = scoped.inquiries().transaction_by_id(tx_id).await?;
    Ok(Json(val))
}

#[post("/merchants/<mid>/inquiries/by-order", data = "<body>")]
async fn merchant_inquire_by_order(
    state: &State<AppState>,
    mid: u64,
    body: Json<TransactionInquiryParams>,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let scoped = state.client.with_merchant(mid)?;
    let tx = scoped.inquiries().by_order(&body.into_inner()).await?;
    let val = serde_json::to_value(tx).map_err(|err| ApiServerError {
        status: Status::InternalServerError,
        error: "serialization_error".to_string(),
        message: err.to_string(),
        retry_after_secs: None,
    })?;
    Ok(Json(val))
}

#[post("/merchants/<mid>/manage/void", data = "<body>")]
async fn merchant_manage_void(
    state: &State<AppState>,
    mid: u64,
    body: Json<VoidParams>,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let scoped = state.client.with_merchant(mid)?;
    let tx = scoped.manage().void(&body.into_inner()).await?;
    let val = serde_json::to_value(tx).map_err(|err| ApiServerError {
        status: Status::InternalServerError,
        error: "serialization_error".to_string(),
        message: err.to_string(),
        retry_after_secs: None,
    })?;
    Ok(Json(val))
}

#[post("/merchants/<mid>/manage/void/<tx_id>")]
async fn merchant_manage_void_by_id(
    state: &State<AppState>,
    mid: u64,
    tx_id: u64,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let scoped = state.client.with_merchant(mid)?;
    let val = scoped.manage().void_transaction(tx_id).await?;
    Ok(Json(val))
}

#[post("/merchants/<mid>/manage/capture", data = "<body>")]
async fn merchant_manage_capture(
    state: &State<AppState>,
    mid: u64,
    body: Json<CaptureParams>,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let scoped = state.client.with_merchant(mid)?;
    let tx = scoped.manage().capture(&body.into_inner()).await?;
    let val = serde_json::to_value(tx).map_err(|err| ApiServerError {
        status: Status::InternalServerError,
        error: "serialization_error".to_string(),
        message: err.to_string(),
        retry_after_secs: None,
    })?;
    Ok(Json(val))
}

#[post("/merchants/<mid>/manage/refund", data = "<body>")]
async fn merchant_manage_refund(
    state: &State<AppState>,
    mid: u64,
    body: Json<RefundParams>,
) -> Result<Json<serde_json::Value>, ApiServerError> {
    let scoped = state.client.with_merchant(mid)?;
    let tx = scoped.manage().refund(&body.into_inner()).await?;
    let val = serde_json::to_value(tx).map_err(|err| ApiServerError {
        status: Status::InternalServerError,
        error: "serialization_error".to_string(),
        message: err.to_string(),
        retry_after_secs: None,
    })?;
    Ok(Json(val))
}

// ---------------------------------------------------------------------------
// Constant-Time Webhooks (Protocols A-E + Replay Deduplication)
// ---------------------------------------------------------------------------

#[post("/webhooks/paymob?<hmac>", data = "<body>")]
async fn webhook_paymob_post(
    state: &State<AppState>,
    hmac: Option<String>,
    body: Data<'_>,
) -> Result<Json<WebhookAckDto>, ApiServerError> {
    let raw_body = read_body_text(body).await?;
    let event = state
        .webhook_engine
        .construct_event(&raw_body, hmac.as_deref())?;
    state.deduplicator.claim_or_reject(&event)?;
    Ok(Json(WebhookAckDto {
        event_type: event.event_type().to_string(),
        verified: true,
        deduplicated: true,
    }))
}

#[get("/webhooks/paymob/redirect")]
async fn webhook_paymob_redirect(
    state: &State<AppState>,
    raw_query: RawQuery,
) -> Result<Json<RedirectWebhookAckDto>, ApiServerError> {
    let params = state
        .webhook_engine
        .verify_transaction_get_query_str(&raw_query.0)?;
    state.deduplicator.claim_or_reject(&params)?;
    Ok(Json(RedirectWebhookAckDto {
        id: params.id.clone(),
        order_id: params.order_id.clone(),
        currency: params.currency.clone(),
        amount_cents: params.amount_cents.clone(),
        approved: params.is_approved(),
        pending: params.is_pending(),
        deduplicated: true,
    }))
}

// ---------------------------------------------------------------------------
// Unified Adapter (`some-payments-adapter`)
// ---------------------------------------------------------------------------

#[post("/unified/sessions", data = "<body>")]
async fn unified_create_session(
    state: &State<AppState>,
    body: Json<UnifiedPaymentSessionRequest>,
) -> Result<Created<Json<UnifiedSessionDto>>, ApiServerError> {
    let session = state
        .client
        .create_payment_session(&body.into_inner())
        .await?;
    Ok(Created::new("").tagged_body(Json(UnifiedSessionDto {
        session_id: session.session_id.clone(),
        order_id: session.order_id.clone(),
        status: session.status.clone(),
        confirmed: session.confirmed,
    })))
}

#[post("/unified/capture", data = "<body>")]
async fn unified_capture(
    state: &State<AppState>,
    body: Json<UnifiedCaptureRequest>,
) -> Result<Json<UnifiedCaptureReceipt>, ApiServerError> {
    let receipt = state.client.capture_payment(&body.into_inner()).await?;
    Ok(Json(receipt))
}

#[post("/unified/refund", data = "<body>")]
async fn unified_refund(
    state: &State<AppState>,
    body: Json<UnifiedRefundRequest>,
) -> Result<Json<UnifiedRefundReceipt>, ApiServerError> {
    let receipt = state.client.refund_payment(&body.into_inner()).await?;
    Ok(Json(receipt))
}

#[post("/unified/void", data = "<body>")]
async fn unified_void(
    state: &State<AppState>,
    body: Json<UnifiedVoidRequest>,
) -> Result<Json<UnifiedVoidReceipt>, ApiServerError> {
    let receipt = state.client.void_payment(&body.into_inner()).await?;
    Ok(Json(receipt))
}

#[post("/unified/charge-saved", data = "<body>")]
async fn unified_charge_saved(
    state: &State<AppState>,
    body: Json<UnifiedSavedChargeInput>,
) -> Result<Json<UnifiedSavedMethodChargeReceipt>, ApiServerError> {
    let input = body.into_inner();
    let mut req =
        UnifiedSavedMethodChargeRequest::new(input.payment_token, input.saved_method_token);
    if let Some(cvn) = input.cvn {
        req = req.with_cvn(cvn);
    }
    let receipt = state.client.charge_saved_method(&req).await?;
    Ok(Json(receipt))
}

#[post("/unified/subscriptions/refund", data = "<body>")]
async fn unified_subscription_refund(
    state: &State<AppState>,
    body: Json<UnifiedSubscriptionRefundRequest>,
) -> Result<Json<UnifiedSubscriptionRefundReceipt>, ApiServerError> {
    let receipt = state
        .client
        .refund_last_transaction(&body.into_inner())
        .await?;
    Ok(Json(receipt))
}

#[post("/unified/payouts", data = "<body>")]
async fn unified_payout(
    state: &State<AppState>,
    body: Json<UnifiedPayoutRequest>,
) -> Result<Json<UnifiedPayoutReceipt>, ApiServerError> {
    let receipt = state.client.execute_payout(&body.into_inner()).await?;
    Ok(Json(receipt))
}

#[post("/unified/webhooks?<hmac>", data = "<body>")]
async fn unified_webhook(
    state: &State<AppState>,
    hmac: Option<String>,
    body: Data<'_>,
) -> Result<Json<UnifiedWebhookOutcome>, ApiServerError> {
    let raw_body = read_body_text(body).await?;
    let event = state
        .webhook_engine
        .construct_event(&raw_body, hmac.as_deref())?;
    state.deduplicator.claim_or_reject(&event)?;
    Ok(Json(some_paymob::normalize_webhook_event(&event)))
}

/// Returns all Unit 3 Rocket routes.
pub fn routes() -> Vec<Route> {
    routes![
        onboarding_auth_login,
        onboarding_auth_create_api_key,
        onboarding_auth_hmac_secret,
        onboarding_auth_merchant_hmac_secret,
        onboarding_flow_schema,
        onboarding_flow_register,
        onboarding_flow_submit_step,
        onboarding_flow_inquiry,
        merchant_create_intention,
        merchant_update_intention,
        merchant_update_intention_by_secret,
        merchant_inquire_transaction,
        merchant_inquire_transaction_raw,
        merchant_inquire_by_order,
        merchant_manage_void,
        merchant_manage_void_by_id,
        merchant_manage_capture,
        merchant_manage_refund,
        webhook_paymob_post,
        webhook_paymob_redirect,
        unified_create_session,
        unified_capture,
        unified_refund,
        unified_void,
        unified_charge_saved,
        unified_subscription_refund,
        unified_payout,
        unified_webhook,
    ]
}
