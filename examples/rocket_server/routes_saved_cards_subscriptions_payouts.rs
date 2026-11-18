#![forbid(unsafe_code)]
//! Unit 2 routes: Services 9–12 (saved-cards/tokens, subscriptions, payouts).

use base64::Engine as _;
use rocket::http::Status;
use rocket::response::status::Created;
use rocket::serde::json::Json;
use rocket::{Route, State, delete, get, post, put, routes};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use some_paymob::core::pagination::PaginatedResponse;
use some_paymob::resources::payouts::{
    AcceptBalanceTopupParams, BankCardCashinParams, BankTransactionType, BankTransferTopupParams,
    BulkDisbursementItem, BulkDisbursementParams, BulkDisbursementResponse, CancelAmanParams,
    DisburseIssuer, DisbursementResponse, EgyptianPostCashinParams, InstantBankCashinParams,
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
use some_paymob::{Currency, MinorUnitAmount};

use super::{ApiServerError, AppState};

type ApiResult<T> = Result<Json<T>, ApiServerError>;
type ApiCreatedResult<T> = Result<Created<Json<T>>, ApiServerError>;

fn bad_request(message: impl Into<String>) -> ApiServerError {
    ApiServerError {
        status: Status::BadRequest,
        error: String::from("validation_error"),
        message: message.into(),
        retry_after_secs: None,
    }
}

// ============================================================================
// Service 9: Saved Cards & Headless Payments
// ============================================================================

#[derive(Debug, Deserialize)]
struct MitPayRequest {
    payment_token: String,
    saved_token: String,
    #[serde(default)]
    cvn: Option<String>,
    #[serde(default)]
    use_cvc_with_moto: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WalletPayRequest {
    payment_token: String,
    wallet_phone: String,
}

#[derive(Debug, Deserialize)]
struct KioskPayRequest {
    payment_token: String,
}

#[derive(Debug, Deserialize)]
struct RawPayRequest {
    payment_token: String,
    source: Value,
}

#[derive(Debug, Serialize)]
struct HeadlessPayResponseDto {
    transaction: HeadlessTransaction,
    redirect_url: Option<String>,
    kiosk_bill_reference: Option<String>,
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

#[post("/saved-cards/pay/mit", data = "<body>")]
async fn pay_mit(
    app_state: &State<AppState>,
    body: Json<MitPayRequest>,
) -> ApiResult<HeadlessPayResponseDto> {
    let req = body.into_inner();
    let cvn_secret = req.cvn.map(SecretString::from);
    let use_cvc = req.use_cvc_with_moto.unwrap_or(false);
    validate_use_cvc_with_moto(use_cvc, cvn_secret.as_ref())?;
    let mut params = MitPayParams::new(req.payment_token, req.saved_token)?;
    if let Some(cvn) = cvn_secret {
        params = params.with_cvn(cvn)?;
    }
    let resp = app_state
        .client
        .saved_cards()
        .pay_with_token_mit(&params)
        .await?;
    Ok(Json(resp.into()))
}

#[post("/saved-cards/pay/wallet", data = "<body>")]
async fn pay_wallet(
    app_state: &State<AppState>,
    body: Json<WalletPayRequest>,
) -> ApiResult<HeadlessPayResponseDto> {
    let req = body.into_inner();
    let params = WalletPayParams::new(req.payment_token, req.wallet_phone)?;
    let resp = app_state
        .client
        .saved_cards()
        .pay_with_wallet(&params)
        .await?;
    Ok(Json(resp.into()))
}

#[post("/saved-cards/pay/kiosk", data = "<body>")]
async fn pay_kiosk(
    app_state: &State<AppState>,
    body: Json<KioskPayRequest>,
) -> ApiResult<HeadlessPayResponseDto> {
    let req = body.into_inner();
    let params = KioskPayParams::new(req.payment_token)?;
    let resp = app_state
        .client
        .saved_cards()
        .pay_with_kiosk(&params)
        .await?;
    Ok(Json(resp.into()))
}

#[post("/saved-cards/pay/raw", data = "<body>")]
async fn pay_raw(
    app_state: &State<AppState>,
    body: Json<RawPayRequest>,
) -> ApiResult<HeadlessPayResponseDto> {
    let req = body.into_inner();
    let params = RawPayParams::new(req.payment_token, req.source)?;
    let resp = app_state.client.saved_cards().pay_raw(&params).await?;
    Ok(Json(resp.into()))
}

// ============================================================================
// Service 10: Subscription Plans
// ============================================================================

#[derive(Debug, Deserialize)]
struct CreatePlanRequest {
    frequency: u16,
    name: String,
    integration: u64,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    reminder_days: Option<u16>,
    #[serde(default)]
    retrial_days: Option<u16>,
    #[serde(default)]
    plan_type: Option<String>,
    #[serde(default)]
    number_of_deductions: Option<u32>,
    #[serde(default)]
    amount_cents: Option<u64>,
    #[serde(default)]
    use_transaction_amount: Option<bool>,
    #[serde(default)]
    is_active: Option<bool>,
    #[serde(default)]
    fee: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct UpdatePlanRequest {
    #[serde(default)]
    frequency: Option<u16>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    integration: Option<u64>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    reminder_days: Option<u16>,
    #[serde(default)]
    retrial_days: Option<u16>,
    #[serde(default)]
    plan_type: Option<String>,
    #[serde(default)]
    number_of_deductions: Option<u32>,
    #[serde(default)]
    amount_cents: Option<u64>,
    #[serde(default)]
    use_transaction_amount: Option<bool>,
    #[serde(default)]
    is_active: Option<bool>,
    #[serde(default)]
    fee: Option<u64>,
}

#[post("/subscriptions/plans", data = "<body>")]
async fn create_plan(
    app_state: &State<AppState>,
    body: Json<CreatePlanRequest>,
) -> ApiCreatedResult<SubscriptionPlan> {
    let req = body.into_inner();
    let params = CreateSubscriptionPlanParams {
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
    let plan = app_state
        .client
        .subscriptions()
        .plans()
        .create(&params)
        .await?;
    Ok(Created::new("").body(Json(plan)))
}

#[put("/subscriptions/plans/<plan_id>", data = "<body>")]
async fn update_plan(
    app_state: &State<AppState>,
    plan_id: u64,
    body: Json<UpdatePlanRequest>,
) -> ApiResult<SubscriptionPlan> {
    let req = body.into_inner();
    let frequency = req.frequency.map(PlanFrequency::from_days).transpose()?;
    let params = UpdateSubscriptionPlanParams {
        frequency,
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
    let plan = app_state
        .client
        .subscriptions()
        .plans()
        .update(plan_id, &params)
        .await?;
    Ok(Json(plan))
}

#[get("/subscriptions/plans?<page>")]
async fn list_plans(
    app_state: &State<AppState>,
    page: Option<u32>,
) -> ApiResult<PaginatedResponse<SubscriptionPlan>> {
    let plans = app_state.client.subscriptions().plans().list(page).await?;
    Ok(Json(plans))
}

#[post("/subscriptions/plans/<plan_id>/suspend")]
async fn suspend_plan(app_state: &State<AppState>, plan_id: u64) -> ApiResult<SubscriptionPlan> {
    let plan = app_state
        .client
        .subscriptions()
        .plans()
        .suspend(plan_id)
        .await?;
    Ok(Json(plan))
}

#[post("/subscriptions/plans/<plan_id>/resume")]
async fn resume_plan(app_state: &State<AppState>, plan_id: u64) -> ApiResult<SubscriptionPlan> {
    let plan = app_state
        .client
        .subscriptions()
        .plans()
        .resume(plan_id)
        .await?;
    Ok(Json(plan))
}

// ============================================================================
// Service 11: Subscriptions Lifecycle, Cards, History & Refund
// ============================================================================

#[derive(Debug, Deserialize)]
struct CreateSubscriptionRequest {
    subscription_plan_id: u64,
    #[serde(alias = "amount_cents")]
    amount: u64,
    currency: String,
    payment_methods: Vec<u64>,
    #[serde(default)]
    billing_data: Option<Value>,
    #[serde(default)]
    special_reference: Option<String>,
    #[serde(default)]
    notification_url: Option<String>,
    #[serde(default)]
    redirection_url: Option<String>,
    #[serde(default)]
    extras: Option<Value>,
}

#[derive(Debug, Serialize)]
struct SubscriptionEnrollmentResponseDto {
    id: String,
    client_secret: String,
    intention_order_id: Option<u64>,
    status: Option<String>,
    subscription_plan_id: Option<u64>,
    payment_keys: Vec<Value>,
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

#[derive(Debug, Deserialize)]
struct UpdateSubscriptionRequest {
    #[serde(default)]
    amount_cents: Option<u64>,
    #[serde(default)]
    plan_id: Option<u64>,
    #[serde(default)]
    starts_at: Option<String>,
    #[serde(default)]
    ends_at: Option<String>,
    #[serde(default)]
    reminder_days: Option<u32>,
    #[serde(default)]
    retrial_days: Option<u32>,
    #[serde(default)]
    webhook_url: Option<String>,
    #[serde(default)]
    is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
struct SubscriptionCardDto {
    id: u64,
    card_data: Option<Value>,
    created_at: String,
    is_primary: bool,
    masked_pan: String,
    failed_attempts: u32,
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

#[derive(Debug, Deserialize)]
struct AddSecondaryCardRequest {
    #[serde(alias = "token")]
    card_token: String,
    #[serde(default)]
    integration_id: Option<u64>,
    #[serde(default)]
    redirect_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChangePrimaryCardRequest {
    #[serde(alias = "card")]
    card_id: u64,
}

#[derive(Debug, Serialize)]
struct DeleteSecondaryCardResponseDto {
    detail: Option<String>,
    message: Option<String>,
}

impl From<DeleteSecondaryCardResponse> for DeleteSecondaryCardResponseDto {
    fn from(resp: DeleteSecondaryCardResponse) -> Self {
        Self {
            detail: resp.detail,
            message: resp.message,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RegisterWebhookRequest {
    #[serde(alias = "url")]
    webhook_url: String,
}

#[derive(Debug, Default, Deserialize)]
struct RefundLastTransactionRequest {
    #[serde(default)]
    amount_cents: Option<u64>,
}

#[post("/subscriptions", data = "<body>")]
async fn create_subscription(
    app_state: &State<AppState>,
    body: Json<CreateSubscriptionRequest>,
) -> ApiCreatedResult<SubscriptionEnrollmentResponseDto> {
    let req = body.into_inner();
    let params = CreateSubscriptionParams {
        subscription_plan_id: req.subscription_plan_id,
        amount: MinorUnitAmount::new(req.amount),
        currency: Currency::from_code(&req.currency),
        payment_methods: req.payment_methods,
        billing_data: req.billing_data,
        special_reference: req.special_reference,
        notification_url: req.notification_url,
        redirection_url: req.redirection_url,
        extras: req.extras,
    };
    let resp = app_state.client.subscriptions().create(&params).await?;
    Ok(Created::new("").body(Json(resp.into())))
}

#[get("/subscriptions/<sub_id>")]
async fn retrieve_subscription(
    app_state: &State<AppState>,
    sub_id: u64,
) -> ApiResult<Subscription> {
    let sub = app_state.client.subscriptions().retrieve(sub_id).await?;
    Ok(Json(sub))
}

#[get("/subscriptions?<plan_id>&<state>&<page>")]
async fn list_subscriptions(
    app_state: &State<AppState>,
    plan_id: Option<u64>,
    state: Option<String>,
    page: Option<u32>,
) -> ApiResult<PaginatedResponse<Subscription>> {
    let filter = SubscriptionListFilter {
        transaction: None,
        plan_id,
        state: state.as_deref().map(SubscriptionState::from_state),
        page,
    };
    let subs = app_state.client.subscriptions().list(&filter).await?;
    Ok(Json(subs))
}

#[put("/subscriptions/<sub_id>", data = "<body>")]
async fn update_subscription(
    app_state: &State<AppState>,
    sub_id: u64,
    body: Json<UpdateSubscriptionRequest>,
) -> ApiResult<Subscription> {
    let req = body.into_inner();
    let params = UpdateSubscriptionParams {
        amount_cents: req.amount_cents.map(MinorUnitAmount::new),
        plan_id: req.plan_id,
        starts_at: req.starts_at,
        ends_at: req.ends_at,
        reminder_days: req.reminder_days,
        retrial_days: req.retrial_days,
        webhook_url: req.webhook_url,
        is_active: req.is_active,
    };
    let sub = app_state
        .client
        .subscriptions()
        .update(sub_id, &params)
        .await?;
    Ok(Json(sub))
}

#[post("/subscriptions/<sub_id>/suspend")]
async fn suspend_subscription(app_state: &State<AppState>, sub_id: u64) -> ApiResult<Subscription> {
    let sub = app_state.client.subscriptions().suspend(sub_id).await?;
    Ok(Json(sub))
}

#[post("/subscriptions/<sub_id>/resume")]
async fn resume_subscription(app_state: &State<AppState>, sub_id: u64) -> ApiResult<Subscription> {
    let sub = app_state.client.subscriptions().resume(sub_id).await?;
    Ok(Json(sub))
}

#[post("/subscriptions/<sub_id>/cancel")]
async fn cancel_subscription(app_state: &State<AppState>, sub_id: u64) -> ApiResult<Subscription> {
    let sub = app_state.client.subscriptions().cancel(sub_id).await?;
    Ok(Json(sub))
}

#[get("/subscriptions/<sub_id>/cards")]
async fn list_subscription_cards(
    app_state: &State<AppState>,
    sub_id: u64,
) -> ApiResult<Vec<SubscriptionCardDto>> {
    let cards = app_state
        .client
        .subscriptions()
        .cards()
        .list(sub_id)
        .await?;
    Ok(Json(cards.into_iter().map(Into::into).collect()))
}

#[post("/subscriptions/<sub_id>/cards/secondary", data = "<body>")]
async fn add_secondary_card(
    app_state: &State<AppState>,
    sub_id: u64,
    body: Json<AddSecondaryCardRequest>,
) -> ApiResult<SubscriptionCardDto> {
    let req = body.into_inner();
    let mut params = AddSecondaryCardParams::new(req.card_token)?;
    if let Some(id) = req.integration_id {
        params = params.with_integration_id(id);
    }
    if let Some(url) = req.redirect_url {
        params = params.with_redirect_url(url)?;
    }
    let card = app_state
        .client
        .subscriptions()
        .cards()
        .add_secondary(sub_id, params)
        .await?;
    Ok(Json(card.into()))
}

#[post("/subscriptions/<sub_id>/cards/primary", data = "<body>")]
async fn change_primary_card(
    app_state: &State<AppState>,
    sub_id: u64,
    body: Json<ChangePrimaryCardRequest>,
) -> ApiResult<SubscriptionCardDto> {
    let card = app_state
        .client
        .subscriptions()
        .cards()
        .change_primary(sub_id, body.card_id)
        .await?;
    Ok(Json(card.into()))
}

#[delete("/subscriptions/<sub_id>/cards/<card_id>")]
async fn delete_secondary_card(
    app_state: &State<AppState>,
    sub_id: u64,
    card_id: u64,
) -> ApiResult<DeleteSecondaryCardResponseDto> {
    let resp = app_state
        .client
        .subscriptions()
        .cards()
        .delete_secondary(sub_id, card_id)
        .await?;
    Ok(Json(resp.into()))
}

#[post("/subscriptions/<sub_id>/webhook", data = "<body>")]
async fn register_subscription_webhook(
    app_state: &State<AppState>,
    sub_id: u64,
    body: Json<RegisterWebhookRequest>,
) -> ApiResult<SubscriptionWebhookRegistration> {
    let resp = app_state
        .client
        .subscriptions()
        .register_webhook(sub_id, &body.webhook_url)
        .await?;
    Ok(Json(resp))
}

#[get("/subscriptions/<sub_id>/last-transaction")]
async fn subscription_last_transaction(
    app_state: &State<AppState>,
    sub_id: u64,
) -> ApiResult<SubscriptionTransaction> {
    let tx = app_state
        .client
        .subscriptions()
        .last_transaction(sub_id)
        .await?;
    Ok(Json(tx))
}

#[get("/subscriptions/<sub_id>/transactions")]
async fn subscription_transactions(
    app_state: &State<AppState>,
    sub_id: u64,
) -> ApiResult<Vec<SubscriptionTransaction>> {
    let txs = app_state
        .client
        .subscriptions()
        .list_transactions(sub_id)
        .await?;
    Ok(Json(txs))
}

#[post("/subscriptions/<sub_id>/refund-last-transaction", data = "<body>")]
async fn refund_last_transaction(
    app_state: &State<AppState>,
    sub_id: u64,
    body: Option<Json<RefundLastTransactionRequest>>,
) -> ApiResult<SubscriptionRefundResponse> {
    let amount_cents = body.and_then(|b| b.into_inner().amount_cents);
    let resp = app_state
        .client
        .subscriptions()
        .refund_last_transaction(sub_id, amount_cents)
        .await?;
    Ok(Json(resp))
}

// ============================================================================
// Service 12: Paymob Send (Payouts)
// ============================================================================

#[derive(Debug, Serialize)]
struct PayoutsTokenResponseDto {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    scope: String,
    token_type: String,
}

impl From<PayoutsTokenResponse> for PayoutsTokenResponseDto {
    fn from(resp: PayoutsTokenResponse) -> Self {
        Self {
            access_token: resp.access_token.expose_secret().to_owned(),
            refresh_token: resp.refresh_token.expose_secret().to_owned(),
            expires_in: resp.expires_in,
            scope: resp.scope.clone(),
            token_type: resp.token_type.clone(),
        }
    }
}

#[derive(Debug, Deserialize)]
struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct WalletCashinRequest {
    msisdn: String,
    amount: u64,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct BankCardCashinRequest {
    amount: u64,
    bank_card_number: String,
    bank_code: String,
    bank_transaction_type: String,
    full_name: String,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct InstantBankCashinRequest {
    amount: u64,
    bank_code: String,
    bank_account_number: String,
    full_name: String,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct EgyptianPostCashinRequest {
    amount: u64,
    msisdn: String,
    full_name: String,
    national_id: String,
    #[serde(default)]
    client_reference_id: Option<String>,
    #[serde(default)]
    customer_bears_fees: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct CancelAmanRequest {
    transaction_id: String,
}

#[derive(Debug, Deserialize)]
struct BulkDisbursementRequest {
    #[serde(default)]
    bank_transaction: Option<bool>,
    transactions: Vec<BulkDisbursementItem>,
}

#[derive(Debug, Serialize)]
struct BulkDisbursementResponseDto {
    status: Option<String>,
    status_code: Option<String>,
    status_description: Option<String>,
    results: Vec<DisbursementResponse>,
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

#[derive(Debug, Deserialize)]
struct TransactionInquiryRequest {
    transactions_ids: Vec<String>,
    #[serde(default)]
    is_bulk: bool,
    #[serde(default)]
    bank_transactions: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ReferenceInquiryRequest {
    client_reference_ids: Vec<String>,
    #[serde(default)]
    bank_transactions: Option<bool>,
}

#[derive(Debug, Serialize)]
struct TransactionInquiryResponseDto {
    results: Vec<DisbursementResponse>,
    status_code: Option<String>,
    status_description: Option<String>,
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

#[derive(Debug, Serialize)]
struct UserBudgetResponseDto {
    current_budget: String,
}

impl From<UserBudgetResponse> for UserBudgetResponseDto {
    fn from(resp: UserBudgetResponse) -> Self {
        Self {
            current_budget: resp.current_budget,
        }
    }
}

#[derive(Debug, Serialize)]
struct TopupRecordDto {
    id: Option<u64>,
    amount: Option<u64>,
    status: Option<String>,
    #[serde(rename = "type")]
    transfer_type: Option<String>,
    currency: Option<String>,
    from_account_number: Option<String>,
    to_account_number: Option<String>,
    status_description: Option<String>,
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

#[derive(Debug, Serialize)]
struct TopupInquiryResponseDto {
    results: Vec<TopupRecordDto>,
    count: Option<u64>,
}

impl From<TopupInquiryResponse> for TopupInquiryResponseDto {
    fn from(resp: TopupInquiryResponse) -> Self {
        Self {
            results: resp.results.into_iter().map(Into::into).collect(),
            count: resp.count,
        }
    }
}

#[derive(Debug, Deserialize)]
struct BankTransferTopupRequest {
    amount: u64,
    currency: String,
    #[serde(default)]
    proof_base64: Option<String>,
    #[serde(default)]
    to_attach_proof: Option<Vec<u8>>,
    proof_filename: String,
    #[serde(default)]
    from_bank_name: Option<String>,
    #[serde(default)]
    reference_number: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AcceptBalanceTopupRequest {
    amount: u64,
    currency: String,
    username: String,
}

async fn dispatch_wallet_cashin(
    app_state: &AppState,
    issuer: DisburseIssuer,
    params: MobileWalletCashinParams,
) -> Result<DisbursementResponse, ApiServerError> {
    let cashin = app_state.client.payouts().cashin();
    let res = match issuer {
        DisburseIssuer::Vodafone => cashin.vodafone(params).await,
        DisburseIssuer::Etisalat => cashin.etisalat(params).await,
        DisburseIssuer::Orange => cashin.orange(params).await,
        DisburseIssuer::BankWallet => cashin.bank_wallet(params).await,
        _ => return Err(bad_request("issuer is not a supported mobile wallet")),
    };
    Ok(res?)
}

#[allow(clippy::manual_div_ceil)]
fn decode_proof_bytes(
    req: BankTransferTopupRequest,
) -> Result<(Vec<u8>, BankTransferTopupMeta), ApiServerError> {
    let bytes = match (req.proof_base64, req.to_attach_proof) {
        (Some(b64), _) => {
            if b64.trim().len() > ((some_paymob::MAX_TOPUP_PROOF_BYTES + 2) / 3) * 4 {
                return Err(bad_request("proof_base64 exceeds maximum allowed length"));
            }
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|err| bad_request(format!("invalid proof_base64: {err}")))?
        }
        (None, Some(raw)) => {
            if raw.len() > some_paymob::MAX_TOPUP_PROOF_BYTES {
                return Err(bad_request("to_attach_proof exceeds maximum allowed size"));
            }
            raw
        }
        (None, None) => return Err(bad_request("proof_base64 or to_attach_proof is required")),
    };
    let meta = BankTransferTopupMeta {
        amount: req.amount,
        currency: req.currency,
        proof_filename: req.proof_filename,
        from_bank_name: req.from_bank_name,
        reference_number: req.reference_number,
    };
    Ok((bytes, meta))
}

struct BankTransferTopupMeta {
    amount: u64,
    currency: String,
    proof_filename: String,
    from_bank_name: Option<String>,
    reference_number: Option<String>,
}

#[post("/payouts/auth/token")]
async fn payouts_auth_token(app_state: &State<AppState>) -> ApiResult<PayoutsTokenResponseDto> {
    let token = app_state.client.payouts().auth().generate_token().await?;
    Ok(Json(token.into()))
}

#[post("/payouts/auth/refresh", data = "<body>")]
async fn payouts_auth_refresh(
    app_state: &State<AppState>,
    body: Json<RefreshTokenRequest>,
) -> ApiResult<PayoutsTokenResponseDto> {
    let refresh = SecretString::from(body.into_inner().refresh_token);
    let token = app_state
        .client
        .payouts()
        .auth()
        .refresh_token(&refresh)
        .await?;
    Ok(Json(token.into()))
}

#[post("/payouts/cashin/wallet/<issuer>", data = "<body>")]
async fn payouts_cashin_wallet(
    app_state: &State<AppState>,
    issuer: &str,
    body: Json<WalletCashinRequest>,
) -> ApiResult<DisbursementResponse> {
    let parsed_issuer =
        DisburseIssuer::from_wire(issuer).ok_or_else(|| bad_request("unknown wallet issuer"))?;
    let req = body.into_inner();
    let params = MobileWalletCashinParams {
        msisdn: req.msisdn,
        amount: req.amount,
        client_reference_id: req.client_reference_id,
        customer_bears_fees: req.customer_bears_fees,
    };
    let resp = dispatch_wallet_cashin(app_state, parsed_issuer, params).await?;
    Ok(Json(resp))
}

#[post("/payouts/cashin/bank-card", data = "<body>")]
async fn payouts_cashin_bank_card(
    app_state: &State<AppState>,
    body: Json<BankCardCashinRequest>,
) -> ApiResult<DisbursementResponse> {
    let req = body.into_inner();
    let tx_type = BankTransactionType::from_wire(&req.bank_transaction_type)
        .ok_or_else(|| bad_request("unknown bank_transaction_type"))?;
    let params = BankCardCashinParams {
        amount: req.amount,
        bank_card_number: SecretString::from(req.bank_card_number),
        bank_code: req.bank_code,
        bank_transaction_type: tx_type,
        full_name: req.full_name,
        client_reference_id: req.client_reference_id,
        customer_bears_fees: req.customer_bears_fees,
    };
    let resp = app_state
        .client
        .payouts()
        .cashin()
        .bank_card(params)
        .await?;
    Ok(Json(resp))
}

#[post("/payouts/cashin/bank-instant", data = "<body>")]
async fn payouts_cashin_bank_instant(
    app_state: &State<AppState>,
    body: Json<InstantBankCashinRequest>,
) -> ApiResult<DisbursementResponse> {
    let req = body.into_inner();
    let params = InstantBankCashinParams {
        amount: req.amount,
        bank_code: req.bank_code,
        bank_account_number: SecretString::from(req.bank_account_number),
        full_name: req.full_name,
        client_reference_id: req.client_reference_id,
        customer_bears_fees: req.customer_bears_fees,
    };
    let resp = app_state
        .client
        .payouts()
        .cashin()
        .bank_instant(params)
        .await?;
    Ok(Json(resp))
}

#[post("/payouts/cashin/egyptian-post", data = "<body>")]
async fn payouts_cashin_egyptian_post(
    app_state: &State<AppState>,
    body: Json<EgyptianPostCashinRequest>,
) -> ApiResult<DisbursementResponse> {
    let req = body.into_inner();
    let params = EgyptianPostCashinParams {
        amount: req.amount,
        msisdn: req.msisdn,
        full_name: req.full_name,
        national_id: SecretString::from(req.national_id),
        client_reference_id: req.client_reference_id,
        customer_bears_fees: req.customer_bears_fees,
    };
    let resp = app_state
        .client
        .payouts()
        .cashin()
        .egyptian_post(params)
        .await?;
    Ok(Json(resp))
}

#[post("/payouts/cashin/aman/cancel", data = "<body>")]
async fn payouts_cashin_aman_cancel(
    app_state: &State<AppState>,
    body: Json<CancelAmanRequest>,
) -> ApiResult<DisbursementResponse> {
    let params = CancelAmanParams::new(body.into_inner().transaction_id);
    let resp = app_state
        .client
        .payouts()
        .cashin()
        .cancel_aman(params)
        .await?;
    Ok(Json(resp))
}

#[post("/payouts/cashin/bulk", data = "<body>")]
async fn payouts_cashin_bulk(
    app_state: &State<AppState>,
    body: Json<BulkDisbursementRequest>,
) -> ApiResult<BulkDisbursementResponseDto> {
    let req = body.into_inner();
    let params = BulkDisbursementParams {
        bank_transaction: req.bank_transaction,
        transactions: req.transactions,
    };
    let resp = app_state.client.payouts().cashin().bulk(params).await?;
    Ok(Json(resp.into()))
}

#[post("/payouts/inquiries/transactions", data = "<body>")]
async fn payouts_inquiries_transactions(
    app_state: &State<AppState>,
    body: Json<TransactionInquiryRequest>,
) -> ApiResult<TransactionInquiryResponseDto> {
    let req = body.into_inner();
    let params = TransactionInquiryParams {
        transactions_ids: req.transactions_ids,
        is_bulk: req.is_bulk,
        bank_transactions: req.bank_transactions,
    };
    let resp = app_state
        .client
        .payouts()
        .inquiries()
        .transactions(params)
        .await?;
    Ok(Json(resp.into()))
}

#[post("/payouts/inquiries/by-reference", data = "<body>")]
async fn payouts_inquiries_by_reference(
    app_state: &State<AppState>,
    body: Json<ReferenceInquiryRequest>,
) -> ApiResult<TransactionInquiryResponseDto> {
    let req = body.into_inner();
    let params = ReferenceInquiryParams {
        client_reference_ids: req.client_reference_ids,
        bank_transactions: req.bank_transactions,
    };
    let resp = app_state
        .client
        .payouts()
        .inquiries()
        .by_reference(params)
        .await?;
    Ok(Json(resp.into()))
}

#[get("/payouts/inquiries/budget")]
async fn payouts_inquiries_budget(app_state: &State<AppState>) -> ApiResult<UserBudgetResponseDto> {
    let resp = app_state.client.payouts().inquiries().user_budget().await?;
    Ok(Json(resp.into()))
}

#[get("/payouts/inquiries/topups?<page>&<id>")]
async fn payouts_inquiries_topups(
    app_state: &State<AppState>,
    page: Option<u32>,
    id: Option<u64>,
) -> ApiResult<TopupInquiryResponseDto> {
    let params = TopupInquiryParams { page, id };
    let resp = app_state.client.payouts().inquiries().topup(params).await?;
    Ok(Json(resp.into()))
}

#[post("/payouts/topups/bank-transfer", data = "<body>")]
async fn payouts_topups_bank_transfer(
    app_state: &State<AppState>,
    body: Json<BankTransferTopupRequest>,
) -> ApiResult<TopupRecordDto> {
    let (to_attach_proof, meta) = decode_proof_bytes(body.into_inner())?;
    let params = BankTransferTopupParams {
        amount: meta.amount,
        currency: meta.currency,
        to_attach_proof,
        proof_filename: meta.proof_filename,
        from_bank_name: meta.from_bank_name,
        reference_number: meta.reference_number,
    };
    let rec = app_state
        .client
        .payouts()
        .topups()
        .from_bank_transfer(params)
        .await?;
    Ok(Json(rec.into()))
}

#[post("/payouts/topups/accept-balance", data = "<body>")]
async fn payouts_topups_accept_balance(
    app_state: &State<AppState>,
    body: Json<AcceptBalanceTopupRequest>,
) -> ApiResult<TopupRecordDto> {
    let req = body.into_inner();
    let params = AcceptBalanceTopupParams::new(req.amount, req.currency, req.username);
    let rec = app_state
        .client
        .payouts()
        .topups()
        .from_accept_balance(params)
        .await?;
    Ok(Json(rec.into()))
}

/// Returns all Unit 2 Rocket routes covering Services 9–12.
pub fn routes() -> Vec<Route> {
    routes![
        pay_mit,
        pay_wallet,
        pay_kiosk,
        pay_raw,
        create_plan,
        update_plan,
        list_plans,
        suspend_plan,
        resume_plan,
        create_subscription,
        retrieve_subscription,
        list_subscriptions,
        update_subscription,
        suspend_subscription,
        resume_subscription,
        cancel_subscription,
        list_subscription_cards,
        add_secondary_card,
        change_primary_card,
        delete_secondary_card,
        register_subscription_webhook,
        subscription_last_transaction,
        subscription_transactions,
        refund_last_transaction,
        payouts_auth_token,
        payouts_auth_refresh,
        payouts_cashin_wallet,
        payouts_cashin_bank_card,
        payouts_cashin_bank_instant,
        payouts_cashin_egyptian_post,
        payouts_cashin_aman_cancel,
        payouts_cashin_bulk,
        payouts_inquiries_transactions,
        payouts_inquiries_by_reference,
        payouts_inquiries_budget,
        payouts_inquiries_topups,
        payouts_topups_bank_transfer,
        payouts_topups_accept_balance,
    ]
}
