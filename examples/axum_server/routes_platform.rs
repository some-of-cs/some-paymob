#![forbid(unsafe_code)]
//! Unit 3 routes: Services 13–14 covering Partner Onboarding, multi-tenant
//! `with_merchant(mid)` scoping, constant-time HMAC-SHA512 webhook verification
//! (Protocols A–E + replay deduplication), and the `some-payments-adapter`
//! unified cross-gateway traits.

use axum::extract::RawQuery;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use some_paymob::prelude::{
    BillingData, CaptureParams, CreateIntentionParams, CreatePartnerApiKeyParams, Currency,
    MinorUnitAmount, OnboardingSchemaQuery, PartnerLoginCredentials, PaymentMethodInput,
    PaymentProvider, PaymobClient, PaymobError, PaymobExt, PayoutProvider, RefundParams,
    RegisterMerchantParams, SplitRecipientRule, SubmitOnboardingStepParams, SubscriptionProvider,
    UnifiedCaptureRequest, UnifiedPaymentSessionRequest, UnifiedPayoutRequest,
    UnifiedRefundRequest, UnifiedSavedMethodChargeRequest, UnifiedSubscriptionRefundRequest,
    UnifiedVoidRequest, UpdateIntentionParams, VoidParams, WebhookEvent,
    normalize_webhook_event,
};

use super::state::{ApiServerError, AppState};

/// Builds the Axum router for Services 13–14 (onboarding, multi-tenant scoping,
/// constant-time webhooks, and unified adapter endpoints).
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(onboarding_router())
        .merge(merchant_scoped_router())
        .merge(webhook_router())
        .merge(unified_router())
}

fn onboarding_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/onboarding/auth/login", post(onboarding_login))
        .route("/onboarding/auth/api-keys", post(onboarding_create_api_key))
        .route("/onboarding/auth/hmac-secret", get(onboarding_hmac_secret))
        .route(
            "/onboarding/auth/merchants/{mid}/hmac-secret",
            get(onboarding_merchant_hmac_secret),
        )
        .route("/onboarding/flow/register", post(onboarding_register))
        .route("/onboarding/flow/schema", get(onboarding_schema))
        .route("/onboarding/flow/submit-step", post(onboarding_submit_step))
        .route("/onboarding/flow/merchants/{mid}", get(onboarding_inquiry))
}

fn merchant_scoped_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/merchants/{mid}/intentions",
            post(merchant_create_intention).put(merchant_update_intention),
        )
        .route(
            "/merchants/{mid}/transactions/{tx_id}",
            get(merchant_get_transaction),
        )
        .route(
            "/merchants/{mid}/orders/inquiry",
            post(merchant_order_inquiry),
        )
        .route("/merchants/{mid}/manage/refund", post(merchant_refund))
        .route("/merchants/{mid}/manage/void", post(merchant_void))
        .route("/merchants/{mid}/manage/capture", post(merchant_capture))
}

fn webhook_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/webhooks/paymob", post(webhook_post))
        .route("/webhooks/paymob/redirect", get(webhook_redirect))
}

fn unified_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/unified/sessions", post(unified_create_session))
        .route("/unified/capture", post(unified_capture))
        .route("/unified/refund", post(unified_refund))
        .route("/unified/void", post(unified_void))
        .route("/unified/charge-saved", post(unified_charge_saved))
        .route(
            "/unified/subscriptions/refund",
            post(unified_subscription_refund),
        )
        .route("/unified/payouts", post(unified_payout))
        .route("/unified/webhooks", post(unified_webhook))
}

fn client_ref(state: &AppState) -> &PaymobClient {
    &state.paymob
}

fn ok_serialized<T: Serialize>(value: T) -> (StatusCode, Json<Value>) {
    (StatusCode::OK, Json(json!(value)))
}

fn merge_extra_fields(base: &mut Value, extra: Value) {
    if let (Some(dst), Some(src)) = (base.as_object_mut(), extra.as_object()) {
        for (k, v) in src {
            dst.insert(k.clone(), v.clone());
        }
    }
}

fn parse_currency(raw: &str) -> Result<Currency, ApiServerError> {
    let currency = Currency::from_code(raw);
    if !currency.is_known() {
        return Err(PaymobError::ValidationError {
            field: "currency",
            reason: "unsupported currency code".to_owned(),
        }
        .into());
    }
    Ok(currency)
}

// ---------------------------------------------------------------------------
// Service 13a: Partner Onboarding Auth & Flow
// ---------------------------------------------------------------------------

/// Request body for `POST /onboarding/auth/login`.
#[derive(Deserialize)]
pub struct OnboardingLoginPayload {
    /// Partner account username.
    pub username: String,
    /// Partner account password.
    pub password: String,
}

impl std::fmt::Debug for OnboardingLoginPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnboardingLoginPayload").finish_non_exhaustive()
    }
}

/// `POST /onboarding/auth/login` — Authenticates a partner and obtains a Regime 4 bearer token.
async fn onboarding_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<OnboardingLoginPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let creds = PartnerLoginCredentials::try_new(body.username, body.password)?;
    let resp = state.paymob.onboarding().auth().login(creds).await?;
    Ok(ok_serialized(json!({
        "authenticated": true,
        "token_present": !resp.token().is_empty(),
    })))
}

/// Request body for `POST /onboarding/auth/api-keys`.
#[derive(Debug, Deserialize)]
pub struct CreateApiKeyPayload {
    /// Optional human-readable label for the provisioned API key.
    pub label: Option<String>,
}

/// `POST /onboarding/auth/api-keys` — Provisions a partner API key.
async fn onboarding_create_api_key(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateApiKeyPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let mut params = CreatePartnerApiKeyParams::new();
    if let Some(label) = body.label {
        params = params.with_label(label);
    }
    let resp = state
        .paymob
        .onboarding()
        .auth()
        .create_api_key(params)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "label": resp.label,
            "api_key_present": !resp.api_key().is_empty(),
        })),
    ))
}

fn hmac_secret_response<L: Serialize, S: Serialize, C: Serialize>(
    mid: Option<u64>,
    label: L,
    status: S,
    code: C,
    hmac_secret_present: bool,
) -> (StatusCode, Json<Value>) {
    let mut body = json!({
        "label": label,
        "status": status,
        "code": code,
        "hmac_secret_present": hmac_secret_present,
    });
    if let Some(id) = mid {
        merge_extra_fields(&mut body, json!({ "mid": id }));
    }
    ok_serialized(body)
}

/// `GET /onboarding/auth/hmac-secret` — Retrieves the partner-level HMAC secret envelope.
async fn onboarding_hmac_secret(
    State(state): State<Arc<AppState>>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let resp = state
        .paymob
        .onboarding()
        .auth()
        .retrieve_hmac_secret()
        .await?;
    let present = !resp.hmac_secret().is_empty();
    Ok(hmac_secret_response(
        None,
        resp.label.clone(),
        resp.status.clone(),
        resp.code,
        present,
    ))
}

/// `GET /onboarding/auth/merchants/{mid}/hmac-secret` — Retrieves a sub-merchant HMAC secret.
async fn onboarding_merchant_hmac_secret(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let resp = state
        .paymob
        .onboarding()
        .auth()
        .retrieve_merchant_hmac_secret(mid)
        .await?;
    let present = !resp.hmac_secret().is_empty();
    Ok(hmac_secret_response(
        Some(mid),
        resp.label.clone(),
        resp.status.clone(),
        resp.code,
        present,
    ))
}

/// Request body for `POST /onboarding/flow/register`.
#[derive(Debug, Deserialize)]
pub struct RegisterMerchantPayload {
    /// Partner slug registered with Paymob.
    pub partner: String,
    /// Merchant primary contact email.
    pub email: String,
    /// Merchant primary contact phone number.
    pub phone_number: String,
    /// Merchant contact first name.
    pub first_name: String,
    /// Merchant contact last name.
    pub last_name: String,
    /// Optional registered company name.
    pub company_name: Option<String>,
    /// Optional ISO country code.
    pub country: Option<String>,
}

/// `POST /onboarding/flow/register` — Registers a new sub-merchant under the partner.
async fn onboarding_register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterMerchantPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let mut params = RegisterMerchantParams::new(
        body.partner,
        body.email,
        body.phone_number,
        body.first_name,
        body.last_name,
    )?;
    if let Some(company) = body.company_name {
        params = params.with_company_name(company);
    }
    if let Some(country) = body.country {
        params = params.with_country(country);
    }
    let resp = state
        .paymob
        .onboarding()
        .flow()
        .register_merchant(&params)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "paymob_mid": resp.paymob_mid,
            "partner": resp.partner,
            "status": resp.status,
            "onboarding_url": resp.onboarding_url,
        })),
    ))
}

/// Query parameters for `GET /onboarding/flow/schema`.
#[derive(Debug, Deserialize)]
pub struct SchemaQueryPayload {
    /// Partner slug.
    pub partner: String,
    /// Optional resubmission flag.
    pub resubmission: Option<bool>,
    /// Optional sub-merchant Paymob ID.
    pub paymob_mid: Option<u64>,
}

/// `GET /onboarding/flow/schema` — Fetches the dynamic KYC onboarding schema.
async fn onboarding_schema(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SchemaQueryPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let mut params = OnboardingSchemaQuery::new(query.partner)?;
    if let Some(resubmission) = query.resubmission {
        params = params.with_resubmission(resubmission);
    }
    if let Some(mid) = query.paymob_mid {
        params = params.with_paymob_mid(mid);
    }
    let schema = state.paymob.onboarding().flow().get_schema(&params).await?;
    Ok(ok_serialized(schema))
}

/// Request body for `POST /onboarding/flow/submit-step`.
#[derive(Debug, Deserialize)]
pub struct SubmitStepPayload {
    /// Target sub-merchant Paymob ID.
    pub paymob_mid: u64,
    /// KYC step identifier.
    pub step_id: String,
    /// Optional partner slug.
    pub partner: Option<String>,
    /// Step form field values.
    pub data: Map<String, Value>,
}

/// `POST /onboarding/flow/submit-step` — Submits a KYC onboarding step for a sub-merchant.
async fn onboarding_submit_step(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SubmitStepPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let mut params = SubmitOnboardingStepParams::new(body.paymob_mid, body.step_id, body.data)?;
    if let Some(partner) = body.partner {
        params = params.with_partner(partner);
    }
    let resp = state
        .paymob
        .onboarding()
        .flow()
        .submit_step(&params)
        .await?;
    Ok(ok_serialized(resp))
}

/// `GET /onboarding/flow/merchants/{mid}` — Queries sub-merchant onboarding approval status.
async fn onboarding_inquiry(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let resp = state
        .paymob
        .onboarding()
        .flow()
        .merchant_inquiry(mid)
        .await?;
    Ok(ok_serialized(resp))
}

// ---------------------------------------------------------------------------
// Service 13b: Multi-Tenant Sub-Merchant Scoping (`with_merchant(mid)`)
// ---------------------------------------------------------------------------

/// Billing details for scoped sub-merchant intention creation.
#[derive(Debug, Deserialize)]
pub struct ScopedBillingPayload {
    /// Customer phone number.
    pub phone_number: String,
    /// Optional customer first name.
    pub first_name: Option<String>,
    /// Optional customer last name.
    pub last_name: Option<String>,
    /// Optional customer email address.
    pub email: Option<String>,
}

/// Request body for `POST /merchants/{mid}/intentions`.
#[derive(Debug, Deserialize)]
pub struct ScopedCreateIntentionPayload {
    /// Payment amount in minor units (e.g. cents/piasters).
    pub amount_cents: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Integration IDs to enable on the intention.
    pub payment_methods: Vec<u64>,
    /// Customer billing information.
    pub billing_data: ScopedBillingPayload,
    /// Optional merchant reference ID.
    pub special_reference: Option<String>,
    /// Optional webhook notification URL.
    pub notification_url: Option<String>,
    /// Optional browser redirection URL.
    pub redirection_url: Option<String>,
}

fn build_scoped_billing(p: &ScopedBillingPayload) -> Result<BillingData, ApiServerError> {
    let mut builder = BillingData::builder().phone_number(&p.phone_number);
    if let Some(first) = &p.first_name {
        builder = builder.first_name(first);
    }
    if let Some(last) = &p.last_name {
        builder = builder.last_name(last);
    }
    if let Some(email) = &p.email {
        builder = builder.email(email);
    }
    Ok(builder.build()?)
}

fn build_scoped_create_params(
    body: &ScopedCreateIntentionPayload,
) -> Result<CreateIntentionParams, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let billing = build_scoped_billing(&body.billing_data)?;
    let methods: Vec<PaymentMethodInput> = body
        .payment_methods
        .iter()
        .copied()
        .map(PaymentMethodInput::IntegrationId)
        .collect();
    let mut builder = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(body.amount_cents))
        .currency(currency)
        .payment_methods(methods)
        .billing_data(billing);
    if let Some(ref_id) = &body.special_reference {
        builder = builder.special_reference(ref_id);
    }
    if let Some(url) = &body.notification_url {
        builder = builder.notification_url(url);
    }
    if let Some(url) = &body.redirection_url {
        builder = builder.redirection_url(url);
    }
    Ok(builder.build()?)
}

fn scoped_intention_json<I: Serialize, S: Serialize, O: Serialize>(
    status_code: StatusCode,
    merchant_id: u64,
    id: I,
    status: S,
    order_id: O,
    redact_secret: bool,
) -> (StatusCode, Json<Value>) {
    let mut body = json!({
        "merchant_id": merchant_id,
        "id": id,
        "status": status,
        "intention_order_id": order_id,
    });
    if redact_secret {
        merge_extra_fields(&mut body, json!({ "client_secret": "[REDACTED]" }));
    }
    (status_code, Json(body))
}

fn scoped_tx_json(
    merchant_id: u64,
    id: u64,
    success: bool,
    extra: Value,
) -> (StatusCode, Json<Value>) {
    let mut body = json!({
        "merchant_id": merchant_id,
        "id": id,
        "success": success,
    });
    merge_extra_fields(&mut body, extra);
    ok_serialized(body)
}

/// `POST /merchants/{mid}/intentions` — Creates a v1 payment intention scoped to a sub-merchant.
async fn merchant_create_intention(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
    Json(body): Json<ScopedCreateIntentionPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let params = build_scoped_create_params(&body)?;
    let scoped = state.paymob.with_merchant(mid)?;
    let resp = scoped.intentions().create(&params).await?;
    Ok(scoped_intention_json(
        StatusCode::CREATED,
        scoped.merchant_id(),
        resp.id,
        resp.status,
        resp.intention_order_id,
        true,
    ))
}

/// Request body for `PUT /merchants/{mid}/intentions`.
#[derive(Debug, Deserialize)]
pub struct ScopedUpdateIntentionPayload {
    /// Optional client secret to target a specific intention.
    pub client_secret: Option<String>,
    /// Optional updated amount in minor units.
    pub amount_cents: Option<u64>,
    /// Optional updated currency code.
    pub currency: Option<String>,
    /// Optional updated notification URL.
    pub notification_url: Option<String>,
    /// Optional updated redirection URL.
    pub redirection_url: Option<String>,
}

fn apply_scoped_urls(
    mut builder: some_paymob::resources::intentions::UpdateIntentionParamsBuilder,
    body: &ScopedUpdateIntentionPayload,
) -> some_paymob::resources::intentions::UpdateIntentionParamsBuilder {
    if let Some(url) = &body.notification_url {
        builder = builder.notification_url(url);
    }
    if let Some(url) = &body.redirection_url {
        builder = builder.redirection_url(url);
    }
    builder
}

fn build_scoped_update_params(
    body: &ScopedUpdateIntentionPayload,
) -> Result<UpdateIntentionParams, ApiServerError> {
    let mut builder = UpdateIntentionParams::builder();
    if let Some(amt) = body.amount_cents {
        builder = builder.amount(MinorUnitAmount::new(amt));
    }
    if let Some(cur) = &body.currency {
        builder = builder.currency(parse_currency(cur)?);
    }
    Ok(apply_scoped_urls(builder, body).build()?)
}

/// `PUT /merchants/{mid}/intentions` — Updates an intention scoped to a sub-merchant.
async fn merchant_update_intention(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
    Json(body): Json<ScopedUpdateIntentionPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let params = build_scoped_update_params(&body)?;
    let scoped = state.paymob.with_merchant(mid)?;
    let resp = match body.client_secret.as_deref() {
        Some(secret) if !secret.trim().is_empty() => {
            scoped
                .intentions()
                .update_by_client_secret(secret, &params)
                .await?
        }
        _ => scoped.intentions().update(&params).await?,
    };
    Ok(scoped_intention_json(
        StatusCode::OK,
        scoped.merchant_id(),
        resp.id,
        resp.status,
        resp.intention_order_id,
        false,
    ))
}

/// `GET /merchants/{mid}/transactions/{tx_id}` — Fetches a sub-merchant transaction by ID.
async fn merchant_get_transaction(
    State(state): State<Arc<AppState>>,
    Path((mid, tx_id)): Path<(u64, u64)>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let scoped = state.paymob.with_merchant(mid)?;
    let tx = scoped.inquiries().transaction(tx_id).await?;
    Ok(scoped_tx_json(
        scoped.merchant_id(),
        tx.id,
        tx.success,
        json!({ "amount_cents": tx.amount_cents, "currency": tx.currency }),
    ))
}

/// Request body for `POST /merchants/{mid}/orders/inquiry`.
#[derive(Debug, Deserialize)]
pub struct ScopedOrderInquiryPayload {
    /// Paymob order ID.
    pub order_id: Option<u64>,
    /// Merchant order reference ID.
    pub merchant_order_id: Option<String>,
    /// Intention special reference.
    pub special_reference: Option<String>,
}

fn build_order_inquiry_params(
    body: &ScopedOrderInquiryPayload,
) -> Result<some_paymob::resources::inquiries::by_order::TransactionInquiryParams, ApiServerError> {
    use some_paymob::resources::inquiries::by_order::TransactionInquiryParams as OrderTxInquiry;
    if let Some(oid) = body.order_id {
        return Ok(OrderTxInquiry::by_order_id(oid));
    }
    if let Some(ref_id) = &body.merchant_order_id {
        return Ok(OrderTxInquiry::by_merchant_order_id(ref_id));
    }
    if let Some(sref) = &body.special_reference {
        return Ok(OrderTxInquiry::by_special_reference(sref));
    }
    Err(PaymobError::ValidationError {
        field: "order_id",
        reason: "order_id, merchant_order_id, or special_reference is required".to_owned(),
    }
    .into())
}

/// `POST /merchants/{mid}/orders/inquiry` — Inquiries a sub-merchant transaction by order ref.
async fn merchant_order_inquiry(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
    Json(body): Json<ScopedOrderInquiryPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let params = build_order_inquiry_params(&body)?;
    let scoped = state.paymob.with_merchant(mid)?;
    let tx = scoped.inquiries().by_order(&params).await?;
    Ok(scoped_tx_json(
        scoped.merchant_id(),
        tx.id,
        tx.success,
        json!({ "pending": tx.pending, "amount_cents": tx.amount_cents }),
    ))
}

enum ScopedManageOp {
    Refund(RefundParams),
    Void(VoidParams),
    Capture(CaptureParams),
}

async fn run_scoped_manage(
    state: &AppState,
    mid: u64,
    op: ScopedManageOp,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let scoped = state.paymob.with_merchant(mid)?;
    let manage = scoped.manage();
    let (tx, extra) = match op {
        ScopedManageOp::Refund(p) => {
            let tx = manage.refund(&p).await?;
            let extra = json!({ "is_refund": tx.is_refund, "amount_cents": tx.amount_cents });
            (tx, extra)
        }
        ScopedManageOp::Void(p) => {
            let tx = manage.void(&p).await?;
            let extra = json!({ "is_void": tx.is_void });
            (tx, extra)
        }
        ScopedManageOp::Capture(p) => {
            let tx = manage.capture(&p).await?;
            let extra = json!({ "is_capture": tx.is_capture, "amount_cents": tx.amount_cents });
            (tx, extra)
        }
    };
    Ok(scoped_tx_json(
        scoped.merchant_id(),
        tx.id,
        tx.success,
        extra,
    ))
}

/// Request body for `POST /merchants/{mid}/manage/refund`.
#[derive(Debug, Deserialize)]
pub struct ScopedRefundPayload {
    /// Target Paymob transaction ID.
    pub transaction_id: u64,
    /// Refund amount in minor units.
    pub amount_cents: u64,
}

/// `POST /merchants/{mid}/manage/refund` — Refunds a sub-merchant transaction.
async fn merchant_refund(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
    Json(body): Json<ScopedRefundPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let params = RefundParams::try_new(body.transaction_id, body.amount_cents)?;
    run_scoped_manage(&state, mid, ScopedManageOp::Refund(params)).await
}

/// Request body for `POST /merchants/{mid}/manage/void`.
#[derive(Debug, Deserialize)]
pub struct ScopedVoidPayload {
    /// Target Paymob transaction ID.
    pub transaction_id: u64,
}

/// `POST /merchants/{mid}/manage/void` — Voids an unsettled sub-merchant transaction.
async fn merchant_void(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
    Json(body): Json<ScopedVoidPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let params = VoidParams::try_new(body.transaction_id)?;
    run_scoped_manage(&state, mid, ScopedManageOp::Void(params)).await
}

/// Request body for `POST /merchants/{mid}/manage/capture`.
#[derive(Debug, Deserialize)]
pub struct ScopedCapturePayload {
    /// Target authorized Paymob transaction ID.
    pub transaction_id: u64,
    /// Capture amount in minor units.
    pub amount_cents: u64,
}

/// `POST /merchants/{mid}/manage/capture` — Captures an authorized sub-merchant transaction.
async fn merchant_capture(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
    Json(body): Json<ScopedCapturePayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let params = CaptureParams::try_new(body.transaction_id, body.amount_cents)?;
    run_scoped_manage(&state, mid, ScopedManageOp::Capture(params)).await
}

// ---------------------------------------------------------------------------
// Service 13c: Constant-Time Webhooks (Protocols A–E + Replay Deduplicator)
// ---------------------------------------------------------------------------

/// Query string parameters carrying the optional `hmac` digest.
#[derive(Deserialize)]
pub struct HmacQuery {
    /// Hex-encoded HMAC-SHA512 signature.
    pub hmac: Option<String>,
}

impl std::fmt::Debug for HmacQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HmacQuery").finish_non_exhaustive()
    }
}

/// `POST /webhooks/paymob` — Verifies Protocols A, C, D, or E webhooks in constant time
/// and enforces atomic replay deduplication (`409 Conflict` on duplicate delivery).
async fn webhook_post(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HmacQuery>,
    raw_body: String,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let engine = state.paymob.webhooks()?;
    let event = engine.construct_event(&raw_body, query.hmac.as_deref())?;
    state.deduplicator.claim_or_reject(&event)?;
    Ok(ok_serialized(normalize_webhook_event(&event)))
}

/// `GET /webhooks/paymob/redirect` — Verifies Protocol B transaction redirect raw query
/// string in constant time (rejecting duplicate keys) and enforces atomic replay deduplication.
async fn webhook_redirect(
    State(state): State<Arc<AppState>>,
    RawQuery(raw_query): RawQuery,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let engine = state.paymob.webhooks()?;
    let verified = engine.verify_transaction_get_query_str(raw_query.as_deref().unwrap_or(""))?;
    let approved = verified.is_approved();
    let event = WebhookEvent::TransactionResponseRedirect(verified);
    state.deduplicator.claim_or_reject(&event)?;
    let outcome = normalize_webhook_event(&event);
    Ok(ok_serialized(json!({
        "event_type": outcome.event_type,
        "idempotency_key": outcome.idempotency_key,
        "correlation_id": outcome.correlation_id,
        "approved": approved,
    })))
}

// ---------------------------------------------------------------------------
// Service 14: Unified Adapter (`some-payments-adapter`)
// ---------------------------------------------------------------------------

/// Split recipient rule input for `POST /unified/sessions`.
#[derive(Debug, Deserialize)]
pub struct UnifiedSplitInput {
    /// Recipient identifier.
    pub recipient_id: String,
    /// Fixed amount in minor units.
    pub amount_cents: Option<u64>,
    /// Percentage in basis points.
    pub percentage_bps: Option<u32>,
}

/// Request body for `POST /unified/sessions`.
#[derive(Debug, Deserialize)]
pub struct UnifiedSessionPayload {
    /// Payment amount in minor units.
    pub amount_cents: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Integration IDs or method names.
    pub payment_methods: Vec<String>,
    /// Optional merchant reference.
    pub special_reference: Option<String>,
    /// Optional webhook notification URL.
    pub notification_url: Option<String>,
    /// Optional browser redirection URL.
    pub redirection_url: Option<String>,
    /// Optional customer email.
    pub customer_email: Option<String>,
    /// Optional customer phone.
    pub customer_phone: Option<String>,
    /// Optional customer first name.
    pub customer_first_name: Option<String>,
    /// Optional customer last name.
    pub customer_last_name: Option<String>,
    /// Optional Paymob pre-selected installment plan ID via [`PaymobExt`].
    pub pre_selected_plan: Option<u64>,
    /// Optional split recipient rules via [`PaymobExt`].
    pub split_recipients: Option<Vec<UnifiedSplitInput>>,
    /// Optional mobile wallet phone number for headless execution via [`PaymobExt`].
    pub headless_wallet_phone: Option<String>,
    /// Optional kiosk flag for headless execution via [`PaymobExt`].
    pub headless_kiosk: Option<bool>,
}

fn build_split_rule(input: &UnifiedSplitInput) -> Result<SplitRecipientRule, ApiServerError> {
    match (input.amount_cents, input.percentage_bps) {
        (Some(amt), None) => Ok(SplitRecipientRule::fixed(&input.recipient_id, amt)),
        (None, Some(bps)) => Ok(SplitRecipientRule::percentage_bps(&input.recipient_id, bps)),
        _ => Err(PaymobError::ValidationError {
            field: "split_recipients",
            reason: "specify exactly one of amount_cents or percentage_bps".to_owned(),
        }
        .into()),
    }
}

fn apply_paymob_ext(
    req: UnifiedPaymentSessionRequest,
    body: &UnifiedSessionPayload,
) -> Result<UnifiedPaymentSessionRequest, ApiServerError> {
    let mut ext = PaymobExt::new();
    if let Some(plan) = body.pre_selected_plan {
        ext = ext.with_pre_selected_plan(plan);
    }
    if let Some(ref_id) = &body.special_reference {
        ext = ext.with_special_reference(ref_id);
    }
    if let Some(splits) = &body.split_recipients {
        let rules = splits
            .iter()
            .map(build_split_rule)
            .collect::<Result<Vec<_>, _>>()?;
        ext = ext.with_split_description(rules);
    }
    if let Some(phone) = &body.headless_wallet_phone {
        ext = ext.with_mobile_wallet(phone);
    } else if body.headless_kiosk == Some(true) {
        ext = ext.with_kiosk();
    }
    Ok(ext.apply_to_session_request(req)?)
}

fn build_unified_session_request(
    body: &UnifiedSessionPayload,
) -> Result<UnifiedPaymentSessionRequest, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let mut req =
        UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(body.amount_cents), currency)
            .with_payment_methods(body.payment_methods.clone());
    if let Some(url) = &body.notification_url {
        req = req.with_notification_url(url);
    }
    if let Some(url) = &body.redirection_url {
        req = req.with_redirection_url(url);
    }
    if let (Some(email), Some(phone)) = (&body.customer_email, &body.customer_phone) {
        req = req.with_customer_contact(email, phone);
    }
    if let (Some(first), Some(last)) = (&body.customer_first_name, &body.customer_last_name) {
        req = req.with_customer_name(first, last);
    }
    apply_paymob_ext(req, body)
}

/// `POST /unified/sessions` — Creates a unified payment session with `PaymobExt`.
async fn unified_create_session(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnifiedSessionPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let req = build_unified_session_request(&body)?;
    let session = PaymentProvider::create_payment_session(client_ref(&state), &req).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "session_id": session.session_id,
            "order_id": session.order_id,
            "checkout_url": session.checkout_url,
            "status": session.status,
            "confirmed": session.confirmed,
            "client_secret": "[REDACTED]",
        })),
    ))
}

/// Request body for `POST /unified/capture`.
#[derive(Debug, Deserialize)]
pub struct UnifiedCapturePayload {
    /// Authorized Paymob transaction ID.
    pub transaction_id: u64,
    /// Capture amount in minor units.
    pub amount_cents: u64,
}

/// `POST /unified/capture` — Captures an authorized payment via [`PaymentProvider`].
async fn unified_capture(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnifiedCapturePayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let req =
        UnifiedCaptureRequest::new(body.transaction_id, MinorUnitAmount::new(body.amount_cents));
    Ok(ok_serialized(
        PaymentProvider::capture_payment(client_ref(&state), &req).await?,
    ))
}

/// Request body for `POST /unified/refund`.
#[derive(Debug, Deserialize)]
pub struct UnifiedRefundPayload {
    /// Target Paymob transaction ID.
    pub transaction_id: u64,
    /// Refund amount in minor units.
    pub amount_cents: u64,
}

/// `POST /unified/refund` — Refunds a transaction via [`PaymentProvider`].
async fn unified_refund(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnifiedRefundPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let req =
        UnifiedRefundRequest::new(body.transaction_id, MinorUnitAmount::new(body.amount_cents));
    Ok(ok_serialized(
        PaymentProvider::refund_payment(client_ref(&state), &req).await?,
    ))
}

/// Request body for `POST /unified/void`.
#[derive(Debug, Deserialize)]
pub struct UnifiedVoidPayload {
    /// Target Paymob transaction ID.
    pub transaction_id: u64,
}

/// `POST /unified/void` — Voids an unsettled transaction via [`PaymentProvider`].
async fn unified_void(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnifiedVoidPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let req = UnifiedVoidRequest::new(body.transaction_id);
    Ok(ok_serialized(
        PaymentProvider::void_payment(client_ref(&state), &req).await?,
    ))
}

/// Request body for `POST /unified/charge-saved`.
#[derive(Deserialize)]
pub struct UnifiedChargeSavedPayload {
    /// Short-lived payment key token.
    pub payment_token: String,
    /// Vaulted saved card token.
    pub saved_method_token: String,
    /// Optional card security code.
    pub cvn: Option<String>,
}

impl std::fmt::Debug for UnifiedChargeSavedPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnifiedChargeSavedPayload").finish_non_exhaustive()
    }
}

/// `POST /unified/charge-saved` — Charges a saved payment method via [`PaymentProvider`].
async fn unified_charge_saved(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnifiedChargeSavedPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let mut req = UnifiedSavedMethodChargeRequest::new(
        SecretString::from(body.payment_token),
        SecretString::from(body.saved_method_token),
    );
    if let Some(cvn) = body.cvn {
        req = req.with_cvn(SecretString::from(cvn));
    }
    Ok(ok_serialized(
        PaymentProvider::charge_saved_method(client_ref(&state), &req).await?,
    ))
}

/// Request body for `POST /unified/subscriptions/refund`.
#[derive(Debug, Deserialize)]
pub struct UnifiedSubscriptionRefundPayload {
    /// Subscription identifier.
    pub subscription_id: u64,
    /// Optional partial refund amount in minor units.
    pub amount_cents: Option<u64>,
}

/// `POST /unified/subscriptions/refund` — Refunds a subscription's last transaction via
/// [`SubscriptionProvider`].
async fn unified_subscription_refund(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnifiedSubscriptionRefundPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let req = UnifiedSubscriptionRefundRequest::new(
        body.subscription_id,
        body.amount_cents.map(MinorUnitAmount::new),
    );
    Ok(ok_serialized(
        SubscriptionProvider::refund_last_transaction(client_ref(&state), &req).await?,
    ))
}

/// Request body for `POST /unified/payouts`.
#[derive(Debug, Deserialize)]
pub struct UnifiedPayoutPayload {
    /// Recipient wallet MSISDN or account identifier.
    pub recipient_identifier: String,
    /// Disbursement amount in minor units.
    pub amount_cents: u64,
    /// ISO 4217 currency code.
    pub currency: String,
    /// Payout issuer wire name (e.g. `vodafone`, `etisalat`, `orange`, `bank_wallet`).
    pub issuer: String,
    /// Optional client reference ID.
    pub reference: Option<String>,
}

/// `POST /unified/payouts` — Executes a disbursement via [`PayoutProvider`].
async fn unified_payout(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnifiedPayoutPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let mut req = UnifiedPayoutRequest::new(
        body.recipient_identifier,
        MinorUnitAmount::new(body.amount_cents),
        currency,
        body.issuer,
    );
    if let Some(ref_id) = body.reference {
        req = req.with_reference(ref_id);
    }
    Ok(ok_serialized(
        PayoutProvider::execute_payout(client_ref(&state), &req).await?,
    ))
}

/// `POST /unified/webhooks` — Verifies, deduplicates, and normalizes a webhook.
async fn unified_webhook(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HmacQuery>,
    raw_body: String,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let engine = state.paymob.webhooks()?;
    let event = engine.construct_event(&raw_body, query.hmac.as_deref())?;
    state.deduplicator.claim_or_reject(&event)?;
    Ok(ok_serialized(normalize_webhook_event(&event)))
}
