#![forbid(unsafe_code)]
//! Axum route handlers for Services 9–12: Saved Cards, Subscriptions, and Payouts.
//!
//! Exposes [`router`] mounting all headless saved-card/token payments,
//! subscription plans, subscription lifecycle, card vault, history/refund,
//! and Paymob Send payouts endpoints onto [`AppState`].

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use some_paymob::core::pagination::PaginatedResponse;
use some_paymob::resources::payouts::{
    AcceptBalanceTopupParams, BankCardCashinParams, BankTransactionType, BankTransferTopupParams,
    BulkDisbursementItem, BulkDisbursementParams, BulkDisbursementResponse, CancelAmanParams,
    DisbursementResponse, EgyptianPostCashinParams, InstantBankCashinParams,
    MobileWalletCashinParams, PayoutsTokenResponse, ReferenceInquiryParams, TopupInquiryParams,
    TopupInquiryResponse, TopupRecord, TransactionInquiryParams, TransactionInquiryResponse,
    UserBudgetResponse,
};
use some_paymob::resources::saved_cards::{
    HeadlessPayResponse, HeadlessTransaction, KioskPayParams, MitPayParams, RawPayParams,
    WalletPayParams, validate_use_cvc_with_moto,
};
use some_paymob::resources::subscriptions::{
    AddSecondaryCardParams, CreateSubscriptionParams, CreateSubscriptionPlanParams,
    DeleteSecondaryCardResponse, PlanFrequency, Subscription, SubscriptionCard,
    SubscriptionEnrollmentResponse, SubscriptionListFilter, SubscriptionPlan,
    SubscriptionRefundResponse, SubscriptionState, SubscriptionTransaction,
    SubscriptionWebhookRegistration, UpdateSubscriptionParams, UpdateSubscriptionPlanParams,
};
use some_paymob::{Currency, MinorUnitAmount, PaymobError};

use super::state::{ApiServerError, AppState};

/// Builds the Axum [`Router`] for Services 9–12 (Saved Cards, Subscriptions, and Payouts).
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .merge(saved_cards_router())
        .merge(subscription_plans_router())
        .merge(subscriptions_lifecycle_router())
        .merge(subscription_cards_router())
        .merge(subscription_history_router())
        .merge(payouts_router())
}

fn saved_cards_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/saved-cards/pay/mit", post(pay_with_token_mit))
        .route("/saved-cards/pay/wallet", post(pay_with_wallet))
        .route("/saved-cards/pay/kiosk", post(pay_with_kiosk))
        .route("/saved-cards/pay/raw", post(pay_raw))
}

fn subscription_plans_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/subscriptions/plans",
            post(create_subscription_plan).get(list_subscription_plans),
        )
        .route(
            "/subscriptions/plans/{plan_id}",
            put(update_subscription_plan),
        )
        .route(
            "/subscriptions/plans/{plan_id}/suspend",
            post(suspend_subscription_plan),
        )
        .route(
            "/subscriptions/plans/{plan_id}/resume",
            post(resume_subscription_plan),
        )
}

fn subscriptions_lifecycle_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/subscriptions",
            post(create_subscription).get(list_subscriptions),
        )
        .route(
            "/subscriptions/{sub_id}",
            get(retrieve_subscription).put(update_subscription),
        )
        .route(
            "/subscriptions/{sub_id}/suspend",
            post(suspend_subscription),
        )
        .route("/subscriptions/{sub_id}/resume", post(resume_subscription))
        .route("/subscriptions/{sub_id}/cancel", post(cancel_subscription))
}

fn subscription_cards_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/subscriptions/{sub_id}/cards",
            get(list_subscription_cards),
        )
        .route(
            "/subscriptions/{sub_id}/cards/secondary",
            post(add_secondary_card),
        )
        .route(
            "/subscriptions/{sub_id}/cards/primary",
            post(change_primary_card),
        )
        .route(
            "/subscriptions/{sub_id}/cards/{card_id}",
            delete(delete_secondary_card),
        )
}

fn subscription_history_router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/subscriptions/{sub_id}/webhook",
            post(register_subscription_webhook),
        )
        .route(
            "/subscriptions/{sub_id}/last-transaction",
            get(subscription_last_transaction),
        )
        .route(
            "/subscriptions/{sub_id}/transactions",
            get(list_subscription_transactions),
        )
        .route(
            "/subscriptions/{sub_id}/refund-last-transaction",
            post(refund_last_subscription_transaction),
        )
}

fn payouts_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/payouts/auth/token", post(generate_payouts_token))
        .route("/payouts/auth/refresh", post(refresh_payouts_token))
        .route("/payouts/cashin/wallet/{issuer}", post(cashin_wallet))
        .route("/payouts/cashin/bank-card", post(cashin_bank_card))
        .route("/payouts/cashin/bank-instant", post(cashin_bank_instant))
        .route("/payouts/cashin/egyptian-post", post(cashin_egyptian_post))
        .route("/payouts/cashin/aman/cancel", post(cancel_aman_cashin))
        .route("/payouts/cashin/bulk", post(cashin_bulk))
        .route(
            "/payouts/inquiries/transactions",
            post(inquire_transactions),
        )
        .route(
            "/payouts/inquiries/by-reference",
            post(inquire_by_reference),
        )
        .route("/payouts/inquiries/budget", get(inquire_budget))
        .route("/payouts/inquiries/topups", get(inquire_topups))
        .route("/payouts/topups/bank-transfer", post(topup_bank_transfer))
        .route("/payouts/topups/accept-balance", post(topup_accept_balance))
}

// ---------------------------------------------------------------------------
// Service 9: Saved Cards / Tokens DTOs & Handlers
// ---------------------------------------------------------------------------

/// Request payload for `POST /saved-cards/pay/mit`.
#[derive(Debug, Deserialize)]
pub struct MitPayRequest {
    /// Short-lived payment key token from the Intention/Payment Key step.
    pub payment_token: String,
    /// Saved card token identifier.
    pub saved_token: String,
    /// Whether MOTO CVN verification is enabled for this charge.
    #[serde(default)]
    pub use_cvc_with_moto: bool,
    /// Optional 3- or 4-digit CVN (required when `use_cvc_with_moto` is `true`).
    #[serde(default)]
    pub cvn: Option<String>,
}

/// Request payload for `POST /saved-cards/pay/wallet`.
#[derive(Debug, Deserialize)]
pub struct WalletPayRequest {
    /// Short-lived payment key token.
    pub payment_token: String,
    /// Customer mobile wallet phone number / MSISDN.
    pub wallet_phone: String,
}

/// Request payload for `POST /saved-cards/pay/kiosk`.
#[derive(Debug, Deserialize)]
pub struct KioskPayRequest {
    /// Short-lived payment key token.
    pub payment_token: String,
}

/// Request payload for `POST /saved-cards/pay/raw`.
#[derive(Debug, Deserialize)]
pub struct RawPayRequest {
    /// Short-lived payment key token.
    pub payment_token: String,
    /// Raw Paymob `source` JSON object.
    pub source: Value,
}

/// Serializable response DTO for headless saved-card/token payments.
#[derive(Debug, Serialize)]
pub struct HeadlessPayResponseDto {
    /// Parsed transaction details from the gateway response.
    pub transaction: HeadlessTransaction,
    /// Optional redirect URL for Mobile Wallet or 3DS challenges.
    pub redirect_url: Option<String>,
    /// Optional offline Kiosk bill reference number.
    pub kiosk_bill_reference: Option<String>,
}

impl From<HeadlessPayResponse> for HeadlessPayResponseDto {
    fn from(resp: HeadlessPayResponse) -> Self {
        Self {
            transaction: resp.transaction,
            redirect_url: resp.redirect_url,
            kiosk_bill_reference: resp.kiosk_bill_reference,
        }
    }
}

fn build_mit_pay_params(
    payment_token: String,
    saved_token: String,
    cvn: Option<SecretString>,
) -> Result<MitPayParams, PaymobError> {
    let params = MitPayParams::new(payment_token, saved_token)?;
    match cvn {
        Some(code) => params.with_cvn(code),
        None => Ok(params),
    }
}

/// Executes a Merchant-Initiated Transaction (MIT) using a saved card token.
async fn pay_with_token_mit(
    State(state): State<Arc<AppState>>,
    Json(req): Json<MitPayRequest>,
) -> Result<Json<HeadlessPayResponseDto>, ApiServerError> {
    let cvn_secret = req.cvn.map(SecretString::from);
    validate_use_cvc_with_moto(req.use_cvc_with_moto, cvn_secret.as_ref())?;
    let params = build_mit_pay_params(req.payment_token, req.saved_token, cvn_secret)?;
    let resp = state
        .paymob
        .saved_cards()
        .pay_with_token_mit(&params)
        .await?;
    Ok(Json(resp.into()))
}

/// Executes a headless mobile wallet payment.
async fn pay_with_wallet(
    State(state): State<Arc<AppState>>,
    Json(req): Json<WalletPayRequest>,
) -> Result<Json<HeadlessPayResponseDto>, ApiServerError> {
    let params = WalletPayParams::new(req.payment_token, req.wallet_phone)?;
    let resp = state.paymob.saved_cards().pay_with_wallet(&params).await?;
    Ok(Json(resp.into()))
}

/// Executes a headless kiosk aggregator payment.
async fn pay_with_kiosk(
    State(state): State<Arc<AppState>>,
    Json(req): Json<KioskPayRequest>,
) -> Result<Json<HeadlessPayResponseDto>, ApiServerError> {
    let params = KioskPayParams::new(req.payment_token)?;
    let resp = state.paymob.saved_cards().pay_with_kiosk(&params).await?;
    Ok(Json(resp.into()))
}

/// Executes a headless payment with a raw JSON `source` object.
async fn pay_raw(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RawPayRequest>,
) -> Result<Json<HeadlessPayResponseDto>, ApiServerError> {
    let params = RawPayParams::new(req.payment_token, req.source)?;
    let resp = state.paymob.saved_cards().pay_raw(&params).await?;
    Ok(Json(resp.into()))
}

// ---------------------------------------------------------------------------
// Service 10a: Subscription Plans DTOs & Handlers
// ---------------------------------------------------------------------------

/// Request payload for `POST /subscriptions/plans`.
#[derive(Debug, Deserialize)]
pub struct CreatePlanRequest {
    /// Billing interval in days (`7 | 15 | 30 | 60 | 90 | 180 | 360`).
    pub frequency: u16,
    /// Human-readable subscription plan name.
    pub name: String,
    /// Paymob MIGS MOTO integration ID (`> 0`).
    pub integration: u64,
    /// Optional webhook callback URL.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Optional reminder lead time in days.
    #[serde(default)]
    pub reminder_days: Option<u16>,
    /// Optional retrial interval in days.
    #[serde(default)]
    pub retrial_days: Option<u16>,
    /// Optional Paymob plan type (e.g., `"rent"`).
    #[serde(default)]
    pub plan_type: Option<String>,
    /// Optional maximum number of deductions.
    #[serde(default)]
    pub number_of_deductions: Option<u32>,
    /// Optional recurring amount in minor currency units.
    #[serde(default)]
    pub amount_cents: Option<u64>,
    /// Whether to reuse initial transaction amount.
    #[serde(default)]
    pub use_transaction_amount: Option<bool>,
    /// Whether the plan is active upon creation.
    #[serde(default)]
    pub is_active: Option<bool>,
    /// Optional plan fee in minor currency units.
    #[serde(default)]
    pub fee: Option<u64>,
}

/// Request payload for `PUT /subscriptions/plans/{plan_id}`.
#[derive(Debug, Deserialize)]
pub struct UpdatePlanRequest {
    /// Updated billing interval in days (`7 | 15 | 30 | 60 | 90 | 180 | 360`).
    #[serde(default)]
    pub frequency: Option<u16>,
    /// Updated subscription plan name.
    #[serde(default)]
    pub name: Option<String>,
    /// Updated Paymob MIGS MOTO integration ID.
    #[serde(default)]
    pub integration: Option<u64>,
    /// Updated webhook callback URL.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Updated reminder lead time in days.
    #[serde(default)]
    pub reminder_days: Option<u16>,
    /// Updated retrial interval in days.
    #[serde(default)]
    pub retrial_days: Option<u16>,
    /// Updated plan type.
    #[serde(default)]
    pub plan_type: Option<String>,
    /// Updated maximum number of deductions.
    #[serde(default)]
    pub number_of_deductions: Option<u32>,
    /// Updated recurring amount in minor currency units.
    #[serde(default)]
    pub amount_cents: Option<u64>,
    /// Updated flag controlling reuse of initial transaction amount.
    #[serde(default)]
    pub use_transaction_amount: Option<bool>,
    /// Updated active status flag.
    #[serde(default)]
    pub is_active: Option<bool>,
    /// Updated plan fee in minor currency units.
    #[serde(default)]
    pub fee: Option<u64>,
}

/// Query parameters for `GET /subscriptions/plans`.
#[derive(Debug, Deserialize)]
pub struct ListPlansQuery {
    /// Optional 1-based page number.
    #[serde(default)]
    pub page: Option<u32>,
}

impl TryFrom<CreatePlanRequest> for CreateSubscriptionPlanParams {
    type Error = ApiServerError;

    fn try_from(req: CreatePlanRequest) -> Result<Self, Self::Error> {
        let params = Self {
            frequency: PlanFrequency::from_days(req.frequency)?,
            name: req.name,
            integration: req.integration,
            webhook_url: req.webhook_url,
            reminder_days: req.reminder_days,
            retrial_days: req.retrial_days,
            plan_type: req.plan_type,
            number_of_deductions: req.number_of_deductions,
            amount_cents: req.amount_cents,
            use_transaction_amount: req.use_transaction_amount,
            is_active: req.is_active,
            fee: req.fee,
        };
        params.validate()?;
        Ok(params)
    }
}

impl TryFrom<UpdatePlanRequest> for UpdateSubscriptionPlanParams {
    type Error = ApiServerError;

    fn try_from(req: UpdatePlanRequest) -> Result<Self, Self::Error> {
        let params = Self {
            frequency: req.frequency.map(PlanFrequency::from_days).transpose()?,
            name: req.name,
            integration: req.integration,
            webhook_url: req.webhook_url,
            reminder_days: req.reminder_days,
            retrial_days: req.retrial_days,
            plan_type: req.plan_type,
            number_of_deductions: req.number_of_deductions,
            amount_cents: req.amount_cents,
            use_transaction_amount: req.use_transaction_amount,
            is_active: req.is_active,
            fee: req.fee,
        };
        params.validate()?;
        Ok(params)
    }
}

enum PlanTransition {
    Suspend,
    Resume,
}

async fn transition_plan(
    state: &AppState,
    plan_id: u64,
    action: PlanTransition,
) -> Result<Json<SubscriptionPlan>, ApiServerError> {
    let plans = state.paymob.subscriptions().plans();
    let plan = match action {
        PlanTransition::Suspend => plans.suspend(plan_id).await?,
        PlanTransition::Resume => plans.resume(plan_id).await?,
    };
    Ok(Json(plan))
}

/// Creates a new subscription plan.
async fn create_subscription_plan(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePlanRequest>,
) -> Result<Json<SubscriptionPlan>, ApiServerError> {
    let params = CreateSubscriptionPlanParams::try_from(req)?;
    Ok(Json(
        state.paymob.subscriptions().plans().create(&params).await?,
    ))
}

/// Updates an existing subscription plan by ID.
async fn update_subscription_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<u64>,
    Json(req): Json<UpdatePlanRequest>,
) -> Result<Json<SubscriptionPlan>, ApiServerError> {
    let params = UpdateSubscriptionPlanParams::try_from(req)?;
    Ok(Json(
        state
            .paymob
            .subscriptions()
            .plans()
            .update(plan_id, &params)
            .await?,
    ))
}

/// Lists subscription plans with optional pagination.
async fn list_subscription_plans(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListPlansQuery>,
) -> Result<Json<PaginatedResponse<SubscriptionPlan>>, ApiServerError> {
    Ok(Json(
        state
            .paymob
            .subscriptions()
            .plans()
            .list(query.page)
            .await?,
    ))
}

/// Suspends a subscription plan.
async fn suspend_subscription_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<u64>,
) -> Result<Json<SubscriptionPlan>, ApiServerError> {
    transition_plan(&state, plan_id, PlanTransition::Suspend).await
}

/// Resumes a suspended subscription plan.
async fn resume_subscription_plan(
    State(state): State<Arc<AppState>>,
    Path(plan_id): Path<u64>,
) -> Result<Json<SubscriptionPlan>, ApiServerError> {
    transition_plan(&state, plan_id, PlanTransition::Resume).await
}

// ---------------------------------------------------------------------------
// Service 10b: Subscriptions Lifecycle DTOs & Handlers
// ---------------------------------------------------------------------------

/// Request payload for `POST /subscriptions`.
#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionRequest {
    /// Subscription plan identifier to enroll into.
    pub subscription_plan_id: u64,
    /// Initial 3DS charge amount in integer minor units.
    pub amount: MinorUnitAmount,
    /// ISO-4217 currency code.
    pub currency: Currency,
    /// One or more Paymob 3DS card integration IDs.
    pub payment_methods: Vec<u64>,
    /// Optional customer billing metadata.
    #[serde(default)]
    pub billing_data: Option<Value>,
    /// Optional merchant-defined idempotency or order reference.
    #[serde(default)]
    pub special_reference: Option<String>,
    /// Optional webhook callback URL.
    #[serde(default)]
    pub notification_url: Option<String>,
    /// Optional 3DS browser redirect URL.
    #[serde(default)]
    pub redirection_url: Option<String>,
    /// Optional extra JSON metadata.
    #[serde(default)]
    pub extras: Option<Value>,
}

/// Serializable response DTO for `POST /subscriptions`.
#[derive(Debug, Serialize)]
pub struct SubscriptionEnrollmentResponseDto {
    /// Paymob Payment Intention identifier.
    pub id: String,
    /// Intention client secret for Unified Checkout.
    pub client_secret: String,
    /// Associated Paymob order identifier, if created.
    pub intention_order_id: Option<u64>,
    /// Current intention status.
    pub status: Option<String>,
    /// Linked subscription plan identifier.
    pub subscription_plan_id: Option<u64>,
    /// Raw payment keys returned by the Intention API.
    pub payment_keys: Vec<Value>,
}

impl From<SubscriptionEnrollmentResponse> for SubscriptionEnrollmentResponseDto {
    fn from(resp: SubscriptionEnrollmentResponse) -> Self {
        Self {
            id: resp.id,
            client_secret: resp.client_secret.expose_secret().to_owned(),
            intention_order_id: resp.intention_order_id,
            status: resp.status,
            subscription_plan_id: resp.subscription_plan_id,
            payment_keys: resp.payment_keys,
        }
    }
}

/// Query parameters for `GET /subscriptions`.
#[derive(Debug, Deserialize)]
pub struct ListSubscriptionsQuery {
    /// Filter by associated transaction identifier.
    #[serde(default)]
    pub transaction: Option<u64>,
    /// Filter by subscription plan identifier.
    #[serde(default)]
    pub plan_id: Option<u64>,
    /// Filter by subscription lifecycle state string.
    #[serde(default)]
    pub state: Option<String>,
    /// Optional 1-based page number.
    #[serde(default)]
    pub page: Option<u32>,
}

/// Request payload for `PUT /subscriptions/{sub_id}`.
#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    /// Updated recurring charge amount in minor units.
    #[serde(default)]
    pub amount_cents: Option<MinorUnitAmount>,
    /// Updated subscription plan identifier.
    #[serde(default)]
    pub plan_id: Option<u64>,
    /// Updated ISO-8601 start timestamp.
    #[serde(default)]
    pub starts_at: Option<String>,
    /// Updated ISO-8601 end timestamp.
    #[serde(default)]
    pub ends_at: Option<String>,
    /// Updated reminder lead time in days.
    #[serde(default)]
    pub reminder_days: Option<u32>,
    /// Updated retry interval in days.
    #[serde(default)]
    pub retrial_days: Option<u32>,
    /// Updated subscription webhook URL.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Updated active flag.
    #[serde(default)]
    pub is_active: Option<bool>,
}

impl From<CreateSubscriptionRequest> for CreateSubscriptionParams {
    fn from(req: CreateSubscriptionRequest) -> Self {
        Self {
            subscription_plan_id: req.subscription_plan_id,
            amount: req.amount,
            currency: req.currency,
            payment_methods: req.payment_methods,
            billing_data: req.billing_data,
            special_reference: req.special_reference,
            notification_url: req.notification_url,
            redirection_url: req.redirection_url,
            extras: req.extras,
        }
    }
}

impl From<UpdateSubscriptionRequest> for UpdateSubscriptionParams {
    fn from(req: UpdateSubscriptionRequest) -> Self {
        Self {
            amount_cents: req.amount_cents,
            plan_id: req.plan_id,
            starts_at: req.starts_at,
            ends_at: req.ends_at,
            reminder_days: req.reminder_days,
            retrial_days: req.retrial_days,
            webhook_url: req.webhook_url,
            is_active: req.is_active,
        }
    }
}

enum SubscriptionTransition {
    Retrieve,
    Suspend,
    Resume,
    Cancel,
}

async fn transition_subscription(
    state: &AppState,
    sub_id: u64,
    action: SubscriptionTransition,
) -> Result<Json<Subscription>, ApiServerError> {
    let subs = state.paymob.subscriptions();
    let sub = match action {
        SubscriptionTransition::Retrieve => subs.retrieve(sub_id).await?,
        SubscriptionTransition::Suspend => subs.suspend(sub_id).await?,
        SubscriptionTransition::Resume => subs.resume(sub_id).await?,
        SubscriptionTransition::Cancel => subs.cancel(sub_id).await?,
    };
    Ok(Json(sub))
}

/// Enrolls a customer into a subscription plan via the Intention API.
async fn create_subscription(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSubscriptionRequest>,
) -> Result<Json<SubscriptionEnrollmentResponseDto>, ApiServerError> {
    let params = CreateSubscriptionParams::from(req);
    params.validate()?;
    let enrollment = state.paymob.subscriptions().create(&params).await?;
    Ok(Json(enrollment.into()))
}

/// Retrieves a subscription by ID.
async fn retrieve_subscription(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
) -> Result<Json<Subscription>, ApiServerError> {
    transition_subscription(&state, sub_id, SubscriptionTransition::Retrieve).await
}

/// Lists subscriptions matching optional query filters.
async fn list_subscriptions(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ListSubscriptionsQuery>,
) -> Result<Json<PaginatedResponse<Subscription>>, ApiServerError> {
    let filters = SubscriptionListFilter {
        transaction: query.transaction,
        plan_id: query.plan_id,
        state: query.state.as_deref().map(SubscriptionState::from_state),
        page: query.page,
    };
    Ok(Json(state.paymob.subscriptions().list(&filters).await?))
}

/// Updates an existing subscription by ID.
async fn update_subscription(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
    Json(req): Json<UpdateSubscriptionRequest>,
) -> Result<Json<Subscription>, ApiServerError> {
    let params = UpdateSubscriptionParams::from(req);
    params.validate()?;
    Ok(Json(
        state.paymob.subscriptions().update(sub_id, &params).await?,
    ))
}

/// Suspends an active subscription.
async fn suspend_subscription(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
) -> Result<Json<Subscription>, ApiServerError> {
    transition_subscription(&state, sub_id, SubscriptionTransition::Suspend).await
}

/// Resumes a suspended subscription.
async fn resume_subscription(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
) -> Result<Json<Subscription>, ApiServerError> {
    transition_subscription(&state, sub_id, SubscriptionTransition::Resume).await
}

/// Permanently cancels a subscription.
async fn cancel_subscription(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
) -> Result<Json<Subscription>, ApiServerError> {
    transition_subscription(&state, sub_id, SubscriptionTransition::Cancel).await
}

// ---------------------------------------------------------------------------
// Service 10c: Subscription Card Vault DTOs & Handlers
// ---------------------------------------------------------------------------

/// Request payload for `POST /subscriptions/{sub_id}/cards/secondary`.
#[derive(Debug, Deserialize)]
pub struct AddSecondaryCardRequest {
    /// Tokenized card identifier to attach as a secondary card.
    pub token: String,
    /// Optional 3DS browser redirect URL.
    #[serde(default)]
    pub redirect_url: Option<String>,
}

/// Request payload for `POST /subscriptions/{sub_id}/cards/primary`.
#[derive(Debug, Deserialize)]
pub struct ChangePrimaryCardRequest {
    /// Card vault entry identifier to promote as primary.
    #[serde(alias = "card_id")]
    pub card: u64,
}

/// Serializable response DTO for a subscription card vault entry.
#[derive(Debug, Serialize)]
pub struct SubscriptionCardDto {
    /// Unique card vault entry identifier.
    pub id: u64,
    /// Optional card metadata payload.
    pub card_data: Option<Value>,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// Whether this card is the primary billing card.
    pub is_primary: bool,
    /// Masked Primary Account Number.
    pub masked_pan: String,
    /// Number of consecutive failed recurring charge attempts.
    pub failed_attempts: u32,
}

impl From<SubscriptionCard> for SubscriptionCardDto {
    fn from(card: SubscriptionCard) -> Self {
        Self {
            id: card.id,
            card_data: card.card_data.clone(),
            created_at: card.created_at.clone(),
            is_primary: card.is_primary,
            masked_pan: card.masked_pan.clone(),
            failed_attempts: card.failed_attempts,
        }
    }
}

/// Serializable response DTO for deleting a secondary card.
#[derive(Debug, Serialize)]
pub struct DeleteSecondaryCardResponseDto {
    /// Optional status detail message.
    pub detail: Option<String>,
    /// Optional status message.
    pub message: Option<String>,
}

impl From<DeleteSecondaryCardResponse> for DeleteSecondaryCardResponseDto {
    fn from(resp: DeleteSecondaryCardResponse) -> Self {
        Self {
            detail: resp.detail,
            message: resp.message,
        }
    }
}

fn build_secondary_card_params(
    req: AddSecondaryCardRequest,
) -> Result<AddSecondaryCardParams, PaymobError> {
    let params = AddSecondaryCardParams::new(req.token)?;
    match req.redirect_url {
        Some(url) => params.with_redirect_url(url),
        None => Ok(params),
    }
}

/// Lists all cards attached to a subscription's card vault.
async fn list_subscription_cards(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
) -> Result<Json<Vec<SubscriptionCardDto>>, ApiServerError> {
    let cards = state.paymob.subscriptions().cards().list(sub_id).await?;
    Ok(Json(cards.into_iter().map(Into::into).collect()))
}

/// Attaches a secondary card to a subscription's card vault.
async fn add_secondary_card(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
    Json(req): Json<AddSecondaryCardRequest>,
) -> Result<Json<SubscriptionCardDto>, ApiServerError> {
    let params = build_secondary_card_params(req)?;
    let card = state
        .paymob
        .subscriptions()
        .cards()
        .add_secondary(sub_id, params)
        .await?;
    Ok(Json(card.into()))
}

/// Promotes an existing card in the vault to primary.
async fn change_primary_card(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
    Json(req): Json<ChangePrimaryCardRequest>,
) -> Result<Json<SubscriptionCardDto>, ApiServerError> {
    let card = state
        .paymob
        .subscriptions()
        .cards()
        .change_primary(sub_id, req.card)
        .await?;
    Ok(Json(card.into()))
}

/// Removes a secondary card from a subscription's card vault.
async fn delete_secondary_card(
    State(state): State<Arc<AppState>>,
    Path((sub_id, card_id)): Path<(u64, u64)>,
) -> Result<Json<DeleteSecondaryCardResponseDto>, ApiServerError> {
    let resp = state
        .paymob
        .subscriptions()
        .cards()
        .delete_secondary(sub_id, card_id)
        .await?;
    Ok(Json(resp.into()))
}

// ---------------------------------------------------------------------------
// Service 10d: Subscription History & Refund DTOs & Handlers
// ---------------------------------------------------------------------------

/// Request payload for `POST /subscriptions/{sub_id}/webhook`.
#[derive(Debug, Deserialize)]
pub struct RegisterWebhookRequest {
    /// HTTPS callback URL for subscription lifecycle events.
    pub webhook_url: String,
}

/// Request payload for `POST /subscriptions/{sub_id}/refund-last-transaction`.
#[derive(Debug, Deserialize)]
pub struct RefundLastTransactionRequest {
    /// Optional partial refund amount in minor units (full amount if omitted).
    #[serde(default)]
    pub amount_cents: Option<u64>,
}

/// Registers or updates the webhook URL for a subscription.
async fn register_subscription_webhook(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
    Json(req): Json<RegisterWebhookRequest>,
) -> Result<Json<SubscriptionWebhookRegistration>, ApiServerError> {
    Ok(Json(
        state
            .paymob
            .subscriptions()
            .history()
            .register_webhook(sub_id, &req.webhook_url)
            .await?,
    ))
}

/// Retrieves the most recent transaction for a subscription.
async fn subscription_last_transaction(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
) -> Result<Json<SubscriptionTransaction>, ApiServerError> {
    Ok(Json(
        state
            .paymob
            .subscriptions()
            .history()
            .last_transaction(sub_id)
            .await?,
    ))
}

/// Lists all recorded transactions for a subscription.
async fn list_subscription_transactions(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
) -> Result<Json<Vec<SubscriptionTransaction>>, ApiServerError> {
    Ok(Json(
        state
            .paymob
            .subscriptions()
            .history()
            .list_transactions(sub_id)
            .await?,
    ))
}

/// Refunds the latest successful transaction on a subscription.
async fn refund_last_subscription_transaction(
    State(state): State<Arc<AppState>>,
    Path(sub_id): Path<u64>,
    Json(req): Json<RefundLastTransactionRequest>,
) -> Result<Json<SubscriptionRefundResponse>, ApiServerError> {
    Ok(Json(
        state
            .paymob
            .subscriptions()
            .refund_last_transaction(sub_id, req.amount_cents)
            .await?,
    ))
}

// ---------------------------------------------------------------------------
// Services 11–12: Payouts Auth, Cashin, Inquiries & Topups DTOs & Handlers
// ---------------------------------------------------------------------------

/// Request payload for `POST /payouts/auth/refresh`.
#[derive(Debug, Deserialize)]
pub struct RefreshPayoutsTokenRequest {
    /// OAuth 2.0 refresh token obtained from `POST /payouts/auth/token`.
    pub refresh_token: String,
}

/// Serializable response DTO for Payouts OAuth 2.0 tokens.
#[derive(Debug, Serialize)]
pub struct PayoutsTokenResponseDto {
    /// Short-lived OAuth 2.0 bearer access token.
    pub access_token: String,
    /// OAuth 2.0 refresh token.
    pub refresh_token: String,
    /// Token lifetime in seconds.
    pub expires_in: u64,
    /// Granted OAuth 2.0 scope string.
    pub scope: String,
    /// Token type (typically `"Bearer"`).
    pub token_type: String,
}

impl From<PayoutsTokenResponse> for PayoutsTokenResponseDto {
    fn from(tok: PayoutsTokenResponse) -> Self {
        Self {
            access_token: tok.access_token.expose_secret().to_owned(),
            refresh_token: tok.refresh_token.expose_secret().to_owned(),
            expires_in: tok.expires_in,
            scope: tok.scope.clone(),
            token_type: tok.token_type.clone(),
        }
    }
}

/// Request payload for `POST /payouts/cashin/wallet/{issuer}`.
#[derive(Debug, Deserialize)]
pub struct WalletCashinRequest {
    /// Recipient mobile wallet number (10–15 digits).
    pub msisdn: String,
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Optional idempotent client reference ID.
    #[serde(default)]
    pub client_reference_id: Option<String>,
    /// Whether the recipient bears the disbursement fee.
    #[serde(default)]
    pub customer_bears_fees: Option<bool>,
}

/// Request payload for `POST /payouts/cashin/bank-card`.
#[derive(Debug, Deserialize)]
pub struct BankCardCashinRequest {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Recipient bank card number (12–19 ASCII digits).
    pub bank_card_number: String,
    /// Bank routing code (e.g., `"CIB"`, `"NBE"`).
    pub bank_code: String,
    /// Bank transaction classification.
    pub bank_transaction_type: BankTransactionType,
    /// Recipient full name.
    pub full_name: String,
    /// Optional client reference ID.
    #[serde(default)]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[serde(default)]
    pub customer_bears_fees: Option<bool>,
}

/// Request payload for `POST /payouts/cashin/bank-instant`.
#[derive(Debug, Deserialize)]
pub struct InstantBankCashinRequest {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Bank routing code.
    pub bank_code: String,
    /// Recipient bank account number or IBAN.
    pub bank_account_number: String,
    /// Recipient full name.
    pub full_name: String,
    /// Optional client reference ID.
    #[serde(default)]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[serde(default)]
    pub customer_bears_fees: Option<bool>,
}

/// Request payload for `POST /payouts/cashin/egyptian-post`.
#[derive(Debug, Deserialize)]
pub struct EgyptianPostCashinRequest {
    /// Disbursement amount (`u64`).
    pub amount: u64,
    /// Recipient mobile number (10–15 digits).
    pub msisdn: String,
    /// Recipient full name.
    pub full_name: String,
    /// Recipient 14-digit Egyptian national ID.
    pub national_id: String,
    /// Optional client reference ID.
    #[serde(default)]
    pub client_reference_id: Option<String>,
    /// Whether customer bears fees.
    #[serde(default)]
    pub customer_bears_fees: Option<bool>,
}

/// Request payload for `POST /payouts/cashin/aman/cancel`.
#[derive(Debug, Deserialize)]
pub struct CancelAmanRequest {
    /// Payouts transaction ID to cancel.
    pub transaction_id: String,
}

/// Request payload for `POST /payouts/cashin/bulk`.
#[derive(Debug, Deserialize)]
pub struct BulkCashinRequest {
    /// Whether this batch contains banking transactions.
    #[serde(default)]
    pub bank_transaction: Option<bool>,
    /// Non-empty list of disbursement items.
    pub transactions: Vec<BulkDisbursementItem>,
}

/// Serializable response DTO for `POST /payouts/cashin/bulk`.
#[derive(Debug, Serialize)]
pub struct BulkDisbursementResponseDto {
    /// Overall bulk batch status.
    pub status: Option<String>,
    /// Gateway status code.
    pub status_code: Option<String>,
    /// Human-readable status description.
    pub status_description: Option<String>,
    /// Individual disbursement results.
    pub results: Vec<DisbursementResponse>,
}

impl From<BulkDisbursementResponse> for BulkDisbursementResponseDto {
    fn from(resp: BulkDisbursementResponse) -> Self {
        Self {
            status: resp.status,
            status_code: resp.status_code,
            status_description: resp.status_description,
            results: resp.results,
        }
    }
}

/// Request payload for `POST /payouts/inquiries/transactions`.
#[derive(Debug, Deserialize)]
pub struct TransactionInquiryRequest {
    /// Transaction IDs to inquire.
    pub transactions_ids: Vec<String>,
    /// Whether to query the bulk disbursement inquiry endpoint.
    #[serde(default)]
    pub is_bulk: bool,
    /// Optional banking-transaction flag for bulk inquiries.
    #[serde(default)]
    pub bank_transactions: Option<bool>,
}

/// Request payload for `POST /payouts/inquiries/by-reference`.
#[derive(Debug, Deserialize)]
pub struct ReferenceInquiryRequest {
    /// Client reference IDs to look up.
    pub client_reference_ids: Vec<String>,
    /// Optional banking-transaction flag.
    #[serde(default)]
    pub bank_transactions: Option<bool>,
}

/// Serializable response DTO for Payouts transaction/reference inquiries.
#[derive(Debug, Serialize)]
pub struct TransactionInquiryResponseDto {
    /// Matching disbursement records.
    pub results: Vec<DisbursementResponse>,
    /// Optional gateway status code.
    pub status_code: Option<String>,
    /// Optional gateway status description.
    pub status_description: Option<String>,
}

impl From<TransactionInquiryResponse> for TransactionInquiryResponseDto {
    fn from(resp: TransactionInquiryResponse) -> Self {
        Self {
            results: resp.results,
            status_code: resp.status_code,
            status_description: resp.status_description,
        }
    }
}

/// Serializable response DTO for `GET /payouts/inquiries/budget`.
#[derive(Debug, Serialize)]
pub struct UserBudgetResponseDto {
    /// Human-readable current budget string.
    pub current_budget: String,
}

impl From<UserBudgetResponse> for UserBudgetResponseDto {
    fn from(resp: UserBudgetResponse) -> Self {
        Self {
            current_budget: resp.current_budget,
        }
    }
}

/// Query parameters for `GET /payouts/inquiries/topups`.
#[derive(Debug, Deserialize)]
pub struct TopupInquiryQuery {
    /// Optional 1-indexed page number.
    #[serde(default)]
    pub page: Option<u32>,
    /// Optional topup ID filter.
    #[serde(default)]
    pub id: Option<u64>,
}

/// Serializable response DTO for a single Payouts topup record.
#[derive(Debug, Serialize)]
pub struct TopupRecordDto {
    /// Topup request identifier.
    pub id: Option<u64>,
    /// Topup amount (`u64`).
    pub amount: Option<u64>,
    /// Topup status.
    pub status: Option<String>,
    /// Topup transfer type.
    #[serde(rename = "type")]
    pub transfer_type: Option<String>,
    /// Currency string.
    pub currency: Option<String>,
    /// Source bank account number.
    pub from_account_number: Option<String>,
    /// Destination bank account number.
    pub to_account_number: Option<String>,
    /// Optional status description.
    pub status_description: Option<String>,
}

impl From<TopupRecord> for TopupRecordDto {
    fn from(rec: TopupRecord) -> Self {
        Self {
            id: rec.id,
            amount: rec.amount,
            status: rec.status,
            transfer_type: rec.transfer_type,
            currency: rec.currency,
            from_account_number: rec.from_account_number,
            to_account_number: rec.to_account_number,
            status_description: rec.status_description,
        }
    }
}

/// Serializable response DTO for `GET /payouts/inquiries/topups`.
#[derive(Debug, Serialize)]
pub struct TopupInquiryResponseDto {
    /// Returned topup records.
    pub results: Vec<TopupRecordDto>,
    /// Total count if provided by gateway.
    pub count: Option<u64>,
}

impl From<TopupInquiryResponse> for TopupInquiryResponseDto {
    fn from(resp: TopupInquiryResponse) -> Self {
        Self {
            results: resp.results.into_iter().map(Into::into).collect(),
            count: resp.count,
        }
    }
}

/// Request payload for `POST /payouts/topups/bank-transfer`.
#[derive(Debug, Deserialize)]
pub struct BankTransferTopupRequest {
    /// Topup amount (`u64`).
    pub amount: u64,
    /// Currency name (e.g., `"egyptian_pound"`).
    pub currency: String,
    /// Base64-encoded proof file bytes (`1..=2_936_012` bytes decoded).
    pub to_attach_proof_base64: String,
    /// Proof filename (e.g., `"receipt.pdf"`).
    pub proof_filename: String,
    /// Optional source bank name.
    #[serde(default)]
    pub from_bank_name: Option<String>,
    /// Optional bank transfer reference number.
    #[serde(default)]
    pub reference_number: Option<String>,
}

/// Request payload for `POST /payouts/topups/accept-balance`.
#[derive(Debug, Deserialize)]
pub struct AcceptBalanceTopupRequest {
    /// Topup amount (`u64`).
    pub amount: u64,
    /// Currency string (e.g., `"egyptian_pound"`).
    pub currency: String,
    /// Paymob Payouts username.
    pub username: String,
}

impl From<WalletCashinRequest> for MobileWalletCashinParams {
    fn from(req: WalletCashinRequest) -> Self {
        Self {
            msisdn: req.msisdn,
            amount: req.amount,
            client_reference_id: req.client_reference_id,
            customer_bears_fees: req.customer_bears_fees,
        }
    }
}

impl From<BankCardCashinRequest> for BankCardCashinParams {
    fn from(req: BankCardCashinRequest) -> Self {
        Self {
            amount: req.amount,
            bank_card_number: SecretString::from(req.bank_card_number),
            bank_code: req.bank_code,
            bank_transaction_type: req.bank_transaction_type,
            full_name: req.full_name,
            client_reference_id: req.client_reference_id,
            customer_bears_fees: req.customer_bears_fees,
        }
    }
}

impl From<InstantBankCashinRequest> for InstantBankCashinParams {
    fn from(req: InstantBankCashinRequest) -> Self {
        Self {
            amount: req.amount,
            bank_code: req.bank_code,
            bank_account_number: SecretString::from(req.bank_account_number),
            full_name: req.full_name,
            client_reference_id: req.client_reference_id,
            customer_bears_fees: req.customer_bears_fees,
        }
    }
}

impl From<EgyptianPostCashinRequest> for EgyptianPostCashinParams {
    fn from(req: EgyptianPostCashinRequest) -> Self {
        Self {
            amount: req.amount,
            msisdn: req.msisdn,
            full_name: req.full_name,
            national_id: SecretString::from(req.national_id),
            client_reference_id: req.client_reference_id,
            customer_bears_fees: req.customer_bears_fees,
        }
    }
}

/// Generates a new Payouts OAuth 2.0 access and refresh token pair.
async fn generate_payouts_token(
    State(state): State<Arc<AppState>>,
) -> Result<Json<PayoutsTokenResponseDto>, ApiServerError> {
    Ok(Json(
        state.paymob.payouts().auth().generate_token().await?.into(),
    ))
}

/// Refreshes an expired Payouts OAuth 2.0 access token.
async fn refresh_payouts_token(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RefreshPayoutsTokenRequest>,
) -> Result<Json<PayoutsTokenResponseDto>, ApiServerError> {
    let refresh = SecretString::from(req.refresh_token);
    Ok(Json(
        state
            .paymob
            .payouts()
            .auth()
            .refresh_token(&refresh)
            .await?
            .into(),
    ))
}

enum CashinChannel {
    BankCard(BankCardCashinParams),
    BankInstant(InstantBankCashinParams),
    EgyptianPost(EgyptianPostCashinParams),
    CancelAman(CancelAmanParams),
}

async fn execute_cashin(
    state: &AppState,
    channel: CashinChannel,
) -> Result<Json<DisbursementResponse>, ApiServerError> {
    let cashin = state.paymob.payouts().cashin();
    let resp = match channel {
        CashinChannel::BankCard(p) => cashin.bank_card(p).await?,
        CashinChannel::BankInstant(p) => cashin.bank_instant(p).await?,
        CashinChannel::EgyptianPost(p) => cashin.egyptian_post(p).await?,
        CashinChannel::CancelAman(p) => cashin.cancel_aman(p).await?,
    };
    Ok(Json(resp))
}

/// Disburses funds to a mobile wallet (`vodafone`, `etisalat`, `orange`, or `bank_wallet`).
async fn cashin_wallet(
    State(state): State<Arc<AppState>>,
    Path(issuer): Path<String>,
    Json(req): Json<WalletCashinRequest>,
) -> Result<Json<DisbursementResponse>, ApiServerError> {
    let params = MobileWalletCashinParams::from(req);
    let cashin = state.paymob.payouts().cashin();
    let resp = match issuer.as_str() {
        "vodafone" => cashin.vodafone(params).await?,
        "etisalat" => cashin.etisalat(params).await?,
        "orange" => cashin.orange(params).await?,
        "bank_wallet" => cashin.bank_wallet(params).await?,
        _ => {
            return Err(PaymobError::ValidationError {
                field: "issuer",
                reason: format!(
                    "unsupported wallet issuer '{issuer}'; expected vodafone, etisalat, \
                     orange, or bank_wallet"
                ),
            }
            .into());
        }
    };
    Ok(Json(resp))
}

/// Disburses funds to a recipient bank card.
async fn cashin_bank_card(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BankCardCashinRequest>,
) -> Result<Json<DisbursementResponse>, ApiServerError> {
    execute_cashin(&state, CashinChannel::BankCard(req.into())).await
}

/// Disburses funds via Instant Bank transfer.
async fn cashin_bank_instant(
    State(state): State<Arc<AppState>>,
    Json(req): Json<InstantBankCashinRequest>,
) -> Result<Json<DisbursementResponse>, ApiServerError> {
    execute_cashin(&state, CashinChannel::BankInstant(req.into())).await
}

/// Disburses funds via Egyptian Post.
async fn cashin_egyptian_post(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EgyptianPostCashinRequest>,
) -> Result<Json<DisbursementResponse>, ApiServerError> {
    execute_cashin(&state, CashinChannel::EgyptianPost(req.into())).await
}

/// Cancels an active Aman cashout transaction.
async fn cancel_aman_cashin(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CancelAmanRequest>,
) -> Result<Json<DisbursementResponse>, ApiServerError> {
    let params = CancelAmanParams::new(req.transaction_id);
    execute_cashin(&state, CashinChannel::CancelAman(params)).await
}

/// Executes a bulk disbursement batch.
async fn cashin_bulk(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BulkCashinRequest>,
) -> Result<Json<BulkDisbursementResponseDto>, ApiServerError> {
    let params = BulkDisbursementParams {
        bank_transaction: req.bank_transaction,
        transactions: req.transactions,
    };
    Ok(Json(
        state.paymob.payouts().cashin().bulk(params).await?.into(),
    ))
}

enum PayoutInquiryKind {
    ByTransaction(TransactionInquiryParams),
    ByReference(ReferenceInquiryParams),
}

async fn execute_payout_inquiry(
    state: &AppState,
    kind: PayoutInquiryKind,
) -> Result<Json<TransactionInquiryResponseDto>, ApiServerError> {
    let inquiries = state.paymob.payouts().inquiries();
    let resp = match kind {
        PayoutInquiryKind::ByTransaction(p) => inquiries.transactions(p).await?,
        PayoutInquiryKind::ByReference(p) => inquiries.by_reference(p).await?,
    };
    Ok(Json(resp.into()))
}

/// Queries Payouts transactions by transaction IDs (single or bulk).
async fn inquire_transactions(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TransactionInquiryRequest>,
) -> Result<Json<TransactionInquiryResponseDto>, ApiServerError> {
    let params = TransactionInquiryParams {
        transactions_ids: req.transactions_ids,
        is_bulk: req.is_bulk,
        bank_transactions: req.bank_transactions,
    };
    execute_payout_inquiry(&state, PayoutInquiryKind::ByTransaction(params)).await
}

/// Queries Payouts transactions by client reference IDs.
async fn inquire_by_reference(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReferenceInquiryRequest>,
) -> Result<Json<TransactionInquiryResponseDto>, ApiServerError> {
    let params = ReferenceInquiryParams {
        client_reference_ids: req.client_reference_ids,
        bank_transactions: req.bank_transactions,
    };
    execute_payout_inquiry(&state, PayoutInquiryKind::ByReference(params)).await
}

/// Retrieves the current Payouts user budget.
async fn inquire_budget(
    State(state): State<Arc<AppState>>,
) -> Result<Json<UserBudgetResponseDto>, ApiServerError> {
    Ok(Json(
        state
            .paymob
            .payouts()
            .inquiries()
            .user_budget()
            .await?
            .into(),
    ))
}

/// Lists Payouts topup records with optional pagination or ID filter.
async fn inquire_topups(
    State(state): State<Arc<AppState>>,
    Query(query): Query<TopupInquiryQuery>,
) -> Result<Json<TopupInquiryResponseDto>, ApiServerError> {
    let params = TopupInquiryParams {
        page: query.page,
        id: query.id,
    };
    Ok(Json(
        state
            .paymob
            .payouts()
            .inquiries()
            .topup(params)
            .await?
            .into(),
    ))
}

/// Submits a Bank Transfer topup request with a base64-encoded proof attachment.
async fn topup_bank_transfer(
    State(state): State<Arc<AppState>>,
    Json(req): Json<BankTransferTopupRequest>,
) -> Result<Json<TopupRecordDto>, ApiServerError> {
    let proof_bytes = BASE64_STANDARD
        .decode(req.to_attach_proof_base64.trim())
        .map_err(|err| PaymobError::ValidationError {
            field: "to_attach_proof_base64",
            reason: format!("invalid base64 proof payload: {err}"),
        })?;
    let params = BankTransferTopupParams {
        amount: req.amount,
        currency: req.currency,
        to_attach_proof: proof_bytes,
        proof_filename: req.proof_filename,
        from_bank_name: req.from_bank_name,
        reference_number: req.reference_number,
    };
    let rec = state
        .paymob
        .payouts()
        .topups()
        .from_bank_transfer(params)
        .await?;
    Ok(Json(rec.into()))
}

/// Submits an Accept Balance topup request.
async fn topup_accept_balance(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AcceptBalanceTopupRequest>,
) -> Result<Json<TopupRecordDto>, ApiServerError> {
    let params = AcceptBalanceTopupParams::new(req.amount, req.currency, req.username);
    let rec = state
        .paymob
        .payouts()
        .topups()
        .from_accept_balance(params)
        .await?;
    Ok(Json(rec.into()))
}
