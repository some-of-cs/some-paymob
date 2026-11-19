#![forbid(unsafe_code)]
//! Unit 2 RPCs: Services 9–12 (saved-cards/tokens, subscriptions, payouts).

use std::future::Future;
use std::pin::Pin;

use base64::Engine as _;
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
use tonic::{Request, Response, Status};

use super::PaymobGrpcService;
use super::error::map_error_to_grpc_status;
use super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};

type RpcFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<JsonRpcResponse>, Status>> + Send + 'a>>;
type RpcHandler = fn(&PaymobGrpcService, Request<JsonRpcRequest>) -> RpcFuture<'_>;

macro_rules! define_routes {
    ($( $name:literal => $handler:ident ),* $(,)?) => {
        const RPC_ROUTES: &[(&str, RpcHandler)] = &[
            $((
                $name,
                {
                    fn wrapper(
                        service: &PaymobGrpcService,
                        req: Request<JsonRpcRequest>,
                    ) -> RpcFuture<'_> {
                        Box::pin($handler(service, req))
                    }
                    wrapper
                }
            ),)*
        ];
    };
}

define_routes![
    // Service 9: Saved Cards & Headless Payments (4)
    "PayWithTokenMit" => pay_with_token_mit,
    "PayWithWallet" => pay_with_wallet,
    "PayWithKiosk" => pay_with_kiosk,
    "PayRaw" => pay_raw,
    // Service 10: Subscription Plans (5)
    "CreateSubscriptionPlan" => create_subscription_plan,
    "UpdateSubscriptionPlan" => update_subscription_plan,
    "ListSubscriptionPlans" => list_subscription_plans,
    "SuspendSubscriptionPlan" => suspend_subscription_plan,
    "ResumeSubscriptionPlan" => resume_subscription_plan,
    // Service 11: Subscriptions Lifecycle, Cards, History & Refund (15)
    "CreateSubscription" => create_subscription,
    "RetrieveSubscription" => retrieve_subscription,
    "ListSubscriptions" => list_subscriptions,
    "UpdateSubscription" => update_subscription,
    "SuspendSubscription" => suspend_subscription,
    "ResumeSubscription" => resume_subscription,
    "CancelSubscription" => cancel_subscription,
    "ListSubscriptionCards" => list_subscription_cards,
    "AddSecondarySubscriptionCard" => add_secondary_subscription_card,
    "ChangePrimarySubscriptionCard" => change_primary_subscription_card,
    "DeleteSecondarySubscriptionCard" => delete_secondary_subscription_card,
    "RegisterSubscriptionWebhook" => register_subscription_webhook,
    "GetSubscriptionLastTransaction" => get_subscription_last_transaction,
    "ListSubscriptionTransactions" => list_subscription_transactions,
    "RefundSubscriptionLastTransaction" => refund_subscription_last_transaction,
    // Service 12: Paymob Send / Payouts (14)
    "GeneratePayoutsToken" => generate_payouts_token,
    "RefreshPayoutsToken" => refresh_payouts_token,
    "DisburseMobileWallet" => disburse_mobile_wallet,
    "DisburseBankCard" => disburse_bank_card,
    "DisburseInstantBank" => disburse_instant_bank,
    "DisburseEgyptianPost" => disburse_egyptian_post,
    "CancelAmanDisbursement" => cancel_aman_disbursement,
    "DisburseBulk" => disburse_bulk,
    "InquirePayoutTransactions" => inquire_payout_transactions,
    "InquirePayoutByReference" => inquire_payout_by_reference,
    "InquirePayoutUserBudget" => inquire_payout_user_budget,
    "InquirePayoutTopups" => inquire_payout_topups,
    "RequestBankTransferTopup" => request_bank_transfer_topup,
    "RequestAcceptBalanceTopup" => request_accept_balance_topup,
];

/// Dispatches a Unit 2 unary gRPC method by name.
pub async fn dispatch(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Option<Result<Response<JsonRpcResponse>, Status>> {
    let handler = RPC_ROUTES
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, handler)| *handler)?;
    Some(handler(service, req).await)
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

async fn pay_with_token_mit(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: MitPayRequest = decode_request(req)?;
    let cvn_secret = body.cvn.map(SecretString::from);
    let use_cvc = body.use_cvc_with_moto.unwrap_or(false);
    validate_use_cvc_with_moto(use_cvc, cvn_secret.as_ref()).map_err(map_error_to_grpc_status)?;
    let mut params =
        MitPayParams::new(body.payment_token, body.saved_token).map_err(map_error_to_grpc_status)?;
    if let Some(cvn) = cvn_secret {
        params = params.with_cvn(cvn).map_err(map_error_to_grpc_status)?;
    }
    let resp = service
        .client
        .saved_cards()
        .pay_with_token_mit(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

async fn pay_with_wallet(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: WalletPayRequest = decode_request(req)?;
    let params = WalletPayParams::new(body.payment_token, body.wallet_phone)
        .map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .saved_cards()
        .pay_with_wallet(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

async fn pay_with_kiosk(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: KioskPayRequest = decode_request(req)?;
    let params = KioskPayParams::new(body.payment_token).map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .saved_cards()
        .pay_with_kiosk(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

async fn pay_raw(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: RawPayRequest = decode_request(req)?;
    let params =
        RawPayParams::new(body.payment_token, body.source).map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .saved_cards()
        .pay_raw(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&HeadlessPayResponseDto::from(resp))
}

// ============================================================================
// Service 10: Subscription Plans
// ============================================================================

#[derive(Debug, Deserialize)]
struct PlanIdRequest {
    #[serde(alias = "id")]
    plan_id: u64,
}

#[derive(Debug, Default, Deserialize)]
struct ListPlansRequest {
    #[serde(default)]
    page: Option<u32>,
}

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
    #[serde(alias = "id")]
    plan_id: u64,
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

async fn create_subscription_plan(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: CreatePlanRequest = decode_request(req)?;
    let params = CreateSubscriptionPlanParams {
        frequency: PlanFrequency::from_days(body.frequency).map_err(map_error_to_grpc_status)?,
        name: body.name,
        integration: body.integration,
        webhook_url: body.webhook_url,
        reminder_days: body.reminder_days,
        retrial_days: body.retrial_days,
        plan_type: body.plan_type,
        number_of_deductions: body.number_of_deductions,
        amount_cents: body.amount_cents,
        use_transaction_amount: body.use_transaction_amount,
        is_active: body.is_active,
        fee: body.fee,
    };
    params.validate().map_err(map_error_to_grpc_status)?;
    let plan: SubscriptionPlan = service
        .client
        .subscriptions()
        .plans()
        .create(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&plan)
}

async fn update_subscription_plan(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: UpdatePlanRequest = decode_request(req)?;
    let frequency = body
        .frequency
        .map(PlanFrequency::from_days)
        .transpose()
        .map_err(map_error_to_grpc_status)?;
    let params = UpdateSubscriptionPlanParams {
        frequency,
        name: body.name,
        integration: body.integration,
        webhook_url: body.webhook_url,
        reminder_days: body.reminder_days,
        retrial_days: body.retrial_days,
        plan_type: body.plan_type,
        number_of_deductions: body.number_of_deductions,
        amount_cents: body.amount_cents,
        use_transaction_amount: body.use_transaction_amount,
        is_active: body.is_active,
        fee: body.fee,
    };
    params.validate().map_err(map_error_to_grpc_status)?;
    let plan: SubscriptionPlan = service
        .client
        .subscriptions()
        .plans()
        .update(body.plan_id, &params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&plan)
}

async fn list_subscription_plans(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: ListPlansRequest = decode_request(req)?;
    let plans: PaginatedResponse<SubscriptionPlan> = service
        .client
        .subscriptions()
        .plans()
        .list(body.page)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&plans)
}

async fn suspend_subscription_plan(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: PlanIdRequest = decode_request(req)?;
    let plan: SubscriptionPlan = service
        .client
        .subscriptions()
        .plans()
        .suspend(body.plan_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&plan)
}

async fn resume_subscription_plan(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: PlanIdRequest = decode_request(req)?;
    let plan: SubscriptionPlan = service
        .client
        .subscriptions()
        .plans()
        .resume(body.plan_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&plan)
}

// ============================================================================
// Service 11: Subscriptions Lifecycle, Cards, History & Refund
// ============================================================================

#[derive(Debug, Deserialize)]
struct SubscriptionIdRequest {
    #[serde(alias = "id", alias = "subscription_id")]
    sub_id: u64,
}

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

#[derive(Debug, Default, Deserialize)]
struct ListSubscriptionsRequest {
    #[serde(default)]
    plan_id: Option<u64>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    page: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct UpdateSubscriptionRequest {
    #[serde(alias = "id", alias = "subscription_id")]
    sub_id: u64,
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
            card_data: card.card_data,
            created_at: card.created_at,
            is_primary: card.is_primary,
            masked_pan: card.masked_pan,
            failed_attempts: card.failed_attempts,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AddSecondaryCardRequest {
    #[serde(alias = "id", alias = "subscription_id")]
    sub_id: u64,
    #[serde(alias = "token")]
    card_token: String,
    #[serde(default)]
    integration_id: Option<u64>,
    #[serde(default)]
    redirect_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChangePrimaryCardRequest {
    #[serde(alias = "id", alias = "subscription_id")]
    sub_id: u64,
    #[serde(alias = "card")]
    card_id: u64,
}

#[derive(Debug, Deserialize)]
struct DeleteSecondaryCardRequest {
    #[serde(alias = "id", alias = "subscription_id")]
    sub_id: u64,
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
    #[serde(alias = "id", alias = "subscription_id")]
    sub_id: u64,
    #[serde(alias = "url")]
    webhook_url: String,
}

#[derive(Debug, Deserialize)]
struct RefundLastTransactionRequest {
    #[serde(alias = "id", alias = "subscription_id")]
    sub_id: u64,
    #[serde(default)]
    amount_cents: Option<u64>,
}

async fn create_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: CreateSubscriptionRequest = decode_request(req)?;
    let params = CreateSubscriptionParams {
        subscription_plan_id: body.subscription_plan_id,
        amount: MinorUnitAmount::new(body.amount),
        currency: Currency::from_code(&body.currency),
        payment_methods: body.payment_methods,
        billing_data: body.billing_data,
        special_reference: body.special_reference,
        notification_url: body.notification_url,
        redirection_url: body.redirection_url,
        extras: body.extras,
    };
    let resp = service
        .client
        .subscriptions()
        .create(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&SubscriptionEnrollmentResponseDto::from(resp))
}

async fn retrieve_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: SubscriptionIdRequest = decode_request(req)?;
    let sub: Subscription = service
        .client
        .subscriptions()
        .retrieve(body.sub_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&sub)
}

async fn list_subscriptions(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: ListSubscriptionsRequest = decode_request(req)?;
    let filter = SubscriptionListFilter {
        transaction: None,
        plan_id: body.plan_id,
        state: body.state.as_deref().map(SubscriptionState::from_state),
        page: body.page,
    };
    let subs: PaginatedResponse<Subscription> = service
        .client
        .subscriptions()
        .list(&filter)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&subs)
}

async fn update_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: UpdateSubscriptionRequest = decode_request(req)?;
    let params = UpdateSubscriptionParams {
        amount_cents: body.amount_cents.map(MinorUnitAmount::new),
        plan_id: body.plan_id,
        starts_at: body.starts_at,
        ends_at: body.ends_at,
        reminder_days: body.reminder_days,
        retrial_days: body.retrial_days,
        webhook_url: body.webhook_url,
        is_active: body.is_active,
    };
    let sub: Subscription = service
        .client
        .subscriptions()
        .update(body.sub_id, &params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&sub)
}

async fn suspend_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: SubscriptionIdRequest = decode_request(req)?;
    let sub: Subscription = service
        .client
        .subscriptions()
        .suspend(body.sub_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&sub)
}

async fn resume_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: SubscriptionIdRequest = decode_request(req)?;
    let sub: Subscription = service
        .client
        .subscriptions()
        .resume(body.sub_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&sub)
}

async fn cancel_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: SubscriptionIdRequest = decode_request(req)?;
    let sub: Subscription = service
        .client
        .subscriptions()
        .cancel(body.sub_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&sub)
}

async fn list_subscription_cards(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: SubscriptionIdRequest = decode_request(req)?;
    let cards = service
        .client
        .subscriptions()
        .cards()
        .list(body.sub_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    let dtos: Vec<SubscriptionCardDto> = cards.into_iter().map(Into::into).collect();
    encode_response(&dtos)
}

async fn add_secondary_subscription_card(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: AddSecondaryCardRequest = decode_request(req)?;
    let mut params =
        AddSecondaryCardParams::new(body.card_token).map_err(map_error_to_grpc_status)?;
    if let Some(id) = body.integration_id {
        params = params.with_integration_id(id);
    }
    if let Some(url) = body.redirect_url {
        params = params
            .with_redirect_url(url)
            .map_err(map_error_to_grpc_status)?;
    }
    let card = service
        .client
        .subscriptions()
        .cards()
        .add_secondary(body.sub_id, params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&SubscriptionCardDto::from(card))
}

async fn change_primary_subscription_card(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: ChangePrimaryCardRequest = decode_request(req)?;
    let card = service
        .client
        .subscriptions()
        .cards()
        .change_primary(body.sub_id, body.card_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&SubscriptionCardDto::from(card))
}

async fn delete_secondary_subscription_card(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: DeleteSecondaryCardRequest = decode_request(req)?;
    let resp = service
        .client
        .subscriptions()
        .cards()
        .delete_secondary(body.sub_id, body.card_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&DeleteSecondaryCardResponseDto::from(resp))
}

async fn register_subscription_webhook(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: RegisterWebhookRequest = decode_request(req)?;
    let resp: SubscriptionWebhookRegistration = service
        .client
        .subscriptions()
        .register_webhook(body.sub_id, &body.webhook_url)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn get_subscription_last_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: SubscriptionIdRequest = decode_request(req)?;
    let tx: SubscriptionTransaction = service
        .client
        .subscriptions()
        .last_transaction(body.sub_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn list_subscription_transactions(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: SubscriptionIdRequest = decode_request(req)?;
    let txs: Vec<SubscriptionTransaction> = service
        .client
        .subscriptions()
        .list_transactions(body.sub_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&txs)
}

async fn refund_subscription_last_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: RefundLastTransactionRequest = decode_request(req)?;
    let resp: SubscriptionRefundResponse = service
        .client
        .subscriptions()
        .refund_last_transaction(body.sub_id, body.amount_cents)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
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
            scope: resp.scope,
            token_type: resp.token_type,
        }
    }
}

#[derive(Debug, Deserialize)]
struct RefreshTokenRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
struct WalletCashinRequest {
    issuer: String,
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

#[derive(Debug, Default, Deserialize)]
struct TopupsInquiryRequest {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    id: Option<u64>,
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

struct BankTransferTopupMeta {
    amount: u64,
    currency: String,
    proof_filename: String,
    from_bank_name: Option<String>,
    reference_number: Option<String>,
}

async fn dispatch_wallet_cashin(
    service: &PaymobGrpcService,
    issuer: DisburseIssuer,
    params: MobileWalletCashinParams,
) -> Result<DisbursementResponse, Status> {
    let cashin = service.client.payouts().cashin();
    let res = match issuer {
        DisburseIssuer::Vodafone => cashin.vodafone(params).await,
        DisburseIssuer::Etisalat => cashin.etisalat(params).await,
        DisburseIssuer::Orange => cashin.orange(params).await,
        DisburseIssuer::BankWallet => cashin.bank_wallet(params).await,
        _ => return Err(Status::invalid_argument("issuer is not a supported mobile wallet")),
    };
    res.map_err(map_error_to_grpc_status)
}

fn decode_proof_bytes(
    req: BankTransferTopupRequest,
) -> Result<(Vec<u8>, BankTransferTopupMeta), Status> {
    let bytes = match (req.proof_base64, req.to_attach_proof) {
        (Some(b64), _) => {
            if b64.trim().len() > some_paymob::MAX_TOPUP_PROOF_BYTES.div_ceil(3) * 4 {
                return Err(Status::invalid_argument(
                    "proof_base64 exceeds maximum allowed length",
                ));
            }
            base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|err| Status::invalid_argument(format!("invalid proof_base64: {err}")))?
        }
        (None, Some(raw)) => {
            if raw.len() > some_paymob::MAX_TOPUP_PROOF_BYTES {
                return Err(Status::invalid_argument(
                    "to_attach_proof exceeds maximum allowed size",
                ));
            }
            raw
        }
        (None, None) => {
            return Err(Status::invalid_argument(
                "proof_base64 or to_attach_proof is required",
            ));
        }
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

async fn generate_payouts_token(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let _: Value = decode_request(req)?;
    let token = service
        .client
        .payouts()
        .auth()
        .generate_token()
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&PayoutsTokenResponseDto::from(token))
}

async fn refresh_payouts_token(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: RefreshTokenRequest = decode_request(req)?;
    let refresh = SecretString::from(body.refresh_token);
    let token = service
        .client
        .payouts()
        .auth()
        .refresh_token(&refresh)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&PayoutsTokenResponseDto::from(token))
}

async fn disburse_mobile_wallet(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: WalletCashinRequest = decode_request(req)?;
    let parsed_issuer = DisburseIssuer::from_wire(&body.issuer)
        .ok_or_else(|| Status::invalid_argument("unknown wallet issuer"))?;
    let params = MobileWalletCashinParams {
        msisdn: body.msisdn,
        amount: body.amount,
        client_reference_id: body.client_reference_id,
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = dispatch_wallet_cashin(service, parsed_issuer, params).await?;
    encode_response(&resp)
}

async fn disburse_bank_card(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: BankCardCashinRequest = decode_request(req)?;
    let tx_type = BankTransactionType::from_wire(&body.bank_transaction_type)
        .ok_or_else(|| Status::invalid_argument("unknown bank_transaction_type"))?;
    let params = BankCardCashinParams {
        amount: body.amount,
        bank_card_number: SecretString::from(body.bank_card_number),
        bank_code: body.bank_code,
        bank_transaction_type: tx_type,
        full_name: body.full_name,
        client_reference_id: body.client_reference_id,
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = service
        .client
        .payouts()
        .cashin()
        .bank_card(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn disburse_instant_bank(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: InstantBankCashinRequest = decode_request(req)?;
    let params = InstantBankCashinParams {
        amount: body.amount,
        bank_code: body.bank_code,
        bank_account_number: SecretString::from(body.bank_account_number),
        full_name: body.full_name,
        client_reference_id: body.client_reference_id,
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = service
        .client
        .payouts()
        .cashin()
        .bank_instant(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn disburse_egyptian_post(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: EgyptianPostCashinRequest = decode_request(req)?;
    let params = EgyptianPostCashinParams {
        amount: body.amount,
        msisdn: body.msisdn,
        full_name: body.full_name,
        national_id: SecretString::from(body.national_id),
        client_reference_id: body.client_reference_id,
        customer_bears_fees: body.customer_bears_fees,
    };
    let resp = service
        .client
        .payouts()
        .cashin()
        .egyptian_post(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn cancel_aman_disbursement(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: CancelAmanRequest = decode_request(req)?;
    let params = CancelAmanParams::new(body.transaction_id);
    let resp = service
        .client
        .payouts()
        .cashin()
        .cancel_aman(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn disburse_bulk(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: BulkDisbursementRequest = decode_request(req)?;
    let params = BulkDisbursementParams {
        bank_transaction: body.bank_transaction,
        transactions: body.transactions,
    };
    let resp = service
        .client
        .payouts()
        .cashin()
        .bulk(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&BulkDisbursementResponseDto::from(resp))
}

async fn inquire_payout_transactions(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: TransactionInquiryRequest = decode_request(req)?;
    let params = TransactionInquiryParams {
        transactions_ids: body.transactions_ids,
        is_bulk: body.is_bulk,
        bank_transactions: body.bank_transactions,
    };
    let resp = service
        .client
        .payouts()
        .inquiries()
        .transactions(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&TransactionInquiryResponseDto::from(resp))
}

async fn inquire_payout_by_reference(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: ReferenceInquiryRequest = decode_request(req)?;
    let params = ReferenceInquiryParams {
        client_reference_ids: body.client_reference_ids,
        bank_transactions: body.bank_transactions,
    };
    let resp = service
        .client
        .payouts()
        .inquiries()
        .by_reference(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&TransactionInquiryResponseDto::from(resp))
}

async fn inquire_payout_user_budget(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let _: Value = decode_request(req)?;
    let resp = service
        .client
        .payouts()
        .inquiries()
        .user_budget()
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&UserBudgetResponseDto::from(resp))
}

async fn inquire_payout_topups(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: TopupsInquiryRequest = decode_request(req)?;
    let params = TopupInquiryParams {
        page: body.page,
        id: body.id,
    };
    let resp = service
        .client
        .payouts()
        .inquiries()
        .topup(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&TopupInquiryResponseDto::from(resp))
}

async fn request_bank_transfer_topup(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: BankTransferTopupRequest = decode_request(req)?;
    let (to_attach_proof, meta) = decode_proof_bytes(body)?;
    let params = BankTransferTopupParams {
        amount: meta.amount,
        currency: meta.currency,
        to_attach_proof,
        proof_filename: meta.proof_filename,
        from_bank_name: meta.from_bank_name,
        reference_number: meta.reference_number,
    };
    let rec = service
        .client
        .payouts()
        .topups()
        .from_bank_transfer(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&TopupRecordDto::from(rec))
}

async fn request_accept_balance_topup(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let body: AcceptBalanceTopupRequest = decode_request(req)?;
    let params = AcceptBalanceTopupParams::new(body.amount, body.currency, body.username);
    let rec = service
        .client
        .payouts()
        .topups()
        .from_accept_balance(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&TopupRecordDto::from(rec))
}
