#![forbid(unsafe_code)]
//! Services 10–11 RPCs: Subscription Plans, Lifecycle, Cards, History & Refund.

use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use some_paymob::core::pagination::PaginatedResponse;
use some_paymob::resources::subscriptions::{
    AddSecondaryCardParams, CreateSubscriptionParams, CreateSubscriptionPlanParams,
    DeleteSecondaryCardResponse, PlanFrequency, Subscription, SubscriptionCard,
    SubscriptionEnrollmentResponse, SubscriptionListFilter, SubscriptionPlan,
    SubscriptionRefundResponse, SubscriptionState, SubscriptionTransaction,
    SubscriptionWebhookRegistration, UpdateSubscriptionParams, UpdateSubscriptionPlanParams,
};
use some_paymob::{Currency, MinorUnitAmount};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::map_error_to_grpc_status;
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};
use super::{RpcFuture, RpcHandler};

define_routes![
    "CreateSubscriptionPlan" => create_subscription_plan,
    "UpdateSubscriptionPlan" => update_subscription_plan,
    "ListSubscriptionPlans" => list_subscription_plans,
    "SuspendSubscriptionPlan" => suspend_subscription_plan,
    "ResumeSubscriptionPlan" => resume_subscription_plan,
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
];

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

