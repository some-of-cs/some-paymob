#![forbid(unsafe_code)]
//! Unit 3 routes: Services 13–14 covering Partner Onboarding, multi-tenant
//! `with_merchant(mid)` scoping, constant-time HMAC-SHA512 webhook verification
//! (Protocols A–E + replay deduplication), and the `some-payments-adapter`
//! unified cross-gateway traits.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use secrecy::SecretString;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use some_paymob::prelude::{
    BillingData, CaptureParams, CreateIntentionParams, CreatePartnerApiKeyParams, Currency,
    MinorUnitAmount, OnboardingSchemaQuery, PartnerLoginCredentials, PaymentMethodInput,
    PaymentProvider, PaymobClient, PaymobError, PaymobExt, PayoutProvider, RefundParams,
    RegisterMerchantParams, SplitRecipientRule, SubmitOnboardingStepParams, SubscriptionProvider,
    TransactionInquiryParams, UnifiedCaptureRequest, UnifiedPaymentSessionRequest,
    UnifiedPayoutRequest, UnifiedRefundRequest, UnifiedSavedMethodChargeRequest,
    UnifiedSubscriptionRefundRequest, UnifiedVoidRequest, UnifiedWebhookInput,
    UpdateIntentionParams, VoidParams, WebhookEvent, WebhookVerifier, normalize_webhook_event,
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
    &state.client
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
#[derive(Debug, Deserialize)]
pub struct OnboardingLoginPayload {
    /// Partner account username.
    pub username: String,
    /// Partner account password.
    pub password: String,
}

/// `POST /onboarding/auth/login` — Authenticates a partner and obtains a Regime 4 bearer token.
async fn onboarding_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<OnboardingLoginPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let creds = PartnerLoginCredentials::try_new(body.username, body.password)?;
    let resp = state.paymob.onboarding().auth().login(creds).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "authenticated": true,
            "token_present": !resp.token().is_empty(),
        })),
    ))
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
    Ok((
        StatusCode::OK,
        Json(json!({
            "label": resp.label,
            "status": resp.status,
            "code": resp.code,
            "hmac_secret_present": !resp.hmac_secret().is_empty(),
        })),
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
    Ok((
        StatusCode::OK,
        Json(json!({
            "mid": mid,
            "label": resp.label,
            "status": resp.status,
            "code": resp.code,
            "hmac_secret_present": !resp.hmac_secret().is_empty(),
        })),
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
    Ok((StatusCode::OK, Json(json!(schema))))
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
    Ok((StatusCode::OK, Json(json!(resp))))
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
    Ok((StatusCode::OK, Json(json!(resp))))
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

/// `POST /merchants/{mid}/intentions` — Creates a v1 payment intention scoped to a sub-merchant.
async fn merchant_create_intention(
    State(state): State<Arc<AppState>>,
    Path(mid): Path<u64>,
    Json(body): Json<ScopedCreateIntentionPayload>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let params = build_scoped_create_params(&body)?;
    let scoped = state.paymob.with_merchant(mid)?;
    let resp = scoped.intentions().create(&params).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "merchant_id": scoped.merchant_id(),
            "id": resp.id,
            "status": resp.status,
            "intention_order_id": resp.intention_order_id,
            "client_secret": "[REDACTED]",
        })),
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
    if let Some(url) = &body.notification_url {
        builder = builder.notification_url(url);
    }
    if let Some(url) = &body.redirection_url {
        builder = builder.redirection_url(url);
    }
    Ok(builder.build()?)
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
    Ok((
        StatusCode::OK,
        Json(json!({
            "merchant_id": scoped.merchant_id(),
            "id": resp.id,
            "status": resp.status,
            "intention_order_id": resp.intention_order_id,
        })),
    ))
}

/// `GET /merchants/{mid}/transactions/{tx_id}` — Fetches a sub-merchant transaction by ID.
async fn merchant_get_transaction(
    State(state): State<Arc<AppState>>,
    Path((mid, tx_id)): Path<(u64, u64)>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let scoped = state.paymob.with_merchant(mid)?;
    let tx = scoped.inquiries().transaction(tx_id).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "merchant_id": scoped.merchant_id(),
            "id": tx.id,
            "success": tx.success,
            "amount_cents": tx.amount_cents,
            "currency": tx.currency,
        })),
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
    Ok((
        StatusCode::OK,
        Json(json!({
            "merchant_id": scoped.merchant_id(),
            "id": tx.id,
            "success": tx.success,
            "pending": tx.pending,
            "amount_cents": tx.amount_cents,
        })),
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
    let scoped = state.paymob.with_merchant(mid)?;
    let tx = scoped.manage().refund(&params).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "merchant_id": scoped.merchant_id(),
            "id": tx.id,
            "success": tx.success,
            "is_refund": tx.is_refund,
            "amount_cents": tx.amount_cents,
        })),
    ))
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
    let scoped = state.paymob.with_merchant(mid)?;
    let tx = scoped.manage().void(&params).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "merchant_id": scoped.merchant_id(),
            "id": tx.id,
            "success": tx.success,
            "is_void": tx.is_void,
        })),
    ))
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
    let scoped = state.paymob.with_merchant(mid)?;
    let tx = scoped.manage().capture(&params).await?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "merchant_id": scoped.merchant_id(),
            "id": tx.id,
            "success": tx.success,
            "is_capture": tx.is_capture,
            "amount_cents": tx.amount_cents,
        })),
    ))
}

// ---------------------------------------------------------------------------
// Service 13c: Constant-Time Webhooks (Protocols A–E + Replay Deduplicator)
// ---------------------------------------------------------------------------

/// Query string parameters carrying the optional `hmac` digest.
#[derive(Debug, Deserialize)]
pub struct HmacQuery {
    /// Hex-encoded HMAC-SHA512 signature.
    pub hmac: Option<String>,
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
    let outcome = normalize_webhook_event(&event);
    Ok((StatusCode::OK, Json(json!(outcome))))
}

/// `GET /webhooks/paymob/redirect` — Verifies Protocol B transaction redirect query
/// parameters in constant time and enforces atomic replay deduplication.
async fn webhook_redirect(
    State(state): State<Arc<AppState>>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let engine = state.paymob.webhooks()?;
    let verified = engine.verify_transaction_get(&params)?;
    let approved = verified.is_approved();
    let event = WebhookEvent::TransactionResponseRedirect(verified);
    state.deduplicator.claim_or_reject(&event)?;
    let outcome = normalize_webhook_event(&event);
    Ok((
        StatusCode::OK,
        Json(json!({
            "event_type": outcome.event_type,
            "idempotency_key": outcome.idempotency_key,
            "correlation_id": outcome.correlation_id,
            "approved": approved,
        })),
    ))
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
    let receipt = PaymentProvider::capture_payment(client_ref(&state), &req).await?;
    Ok((StatusCode::OK, Json(json!(receipt))))
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
    let receipt = PaymentProvider::refund_payment(client_ref(&state), &req).await?;
    Ok((StatusCode::OK, Json(json!(receipt))))
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
    let receipt = PaymentProvider::void_payment(client_ref(&state), &req).await?;
    Ok((StatusCode::OK, Json(json!(receipt))))
}

/// Request body for `POST /unified/charge-saved`.
#[derive(Debug, Deserialize)]
pub struct UnifiedChargeSavedPayload {
    /// Short-lived payment key token.
    pub payment_token: String,
    /// Vaulted saved card token.
    pub saved_method_token: String,
    /// Optional card security code.
    pub cvn: Option<String>,
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
    let receipt = PaymentProvider::charge_saved_method(client_ref(&state), &req).await?;
    Ok((StatusCode::OK, Json(json!(receipt))))
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
    let receipt = SubscriptionProvider::refund_last_transaction(client_ref(&state), &req).await?;
    Ok((StatusCode::OK, Json(json!(receipt))))
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
    let receipt = PayoutProvider::execute_payout(client_ref(&state), &req).await?;
    Ok((StatusCode::OK, Json(json!(receipt))))
}

/// `POST /unified/webhooks` — Verifies and normalizes a webhook via [`WebhookVerifier`].
async fn unified_webhook(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HmacQuery>,
    raw_body: String,
) -> Result<(StatusCode, Json<Value>), ApiServerError> {
    let input = UnifiedWebhookInput::new(&raw_body, query.hmac.as_deref());
    let outcome = WebhookVerifier::verify_webhook(client_ref(&state), &input)?;
    Ok((StatusCode::OK, Json(json!(outcome))))
}
