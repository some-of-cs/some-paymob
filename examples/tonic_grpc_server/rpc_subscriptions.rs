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
use super::{RpcFuture, RpcHandler, encode_sdk_result};

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

macro_rules! plan_id_rpc {
    ($fn_name:ident, $method:ident) => {
        async fn $fn_name(
            service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            let body: PlanIdRequest = decode_request(req)?;
            let res = service
                .client
                .subscriptions()
                .plans()
                .$method(body.plan_id)
                .await;
            encode_sdk_result::<SubscriptionPlan, SubscriptionPlan>(res)
        }
    };
}

macro_rules! sub_id_rpc {
    ($fn_name:ident, $method:ident, $resp_ty:ty) => {
        async fn $fn_name(
            service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            let body: SubscriptionIdRequest = decode_request(req)?;
            let res = service.client.subscriptions().$method(body.sub_id).await;
            encode_sdk_result::<$resp_ty, $resp_ty>(res)
        }
    };
}

macro_rules! sub_card_rpc {
    ($fn_name:ident, $req_ty:ty, $method:ident, $dto:ty) => {
        async fn $fn_name(
            service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            let body: $req_ty = decode_request(req)?;
            let res = service
                .client
                .subscriptions()
                .cards()
                .$method(body.sub_id, body.card_id)
                .await;
            encode_sdk_result::<_, $dto>(res)
        }
    };
}

macro_rules! sub_rpc {
    ($fn:ident, $req:ty, $resp:ty, $dto:ty, |$svc:ident, $body:ident| $expr:expr) => {
        async fn $fn(
            $svc: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            let $body: $req = decode_request(req)?;
            let res = $expr;
            encode_sdk_result::<$resp, $dto>(res)
        }
    };
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

sub_rpc!(
    create_subscription_plan,
    CreatePlanRequest,
    SubscriptionPlan,
    SubscriptionPlan,
    |service, body| {
        let params = CreateSubscriptionPlanParams {
            frequency: PlanFrequency::from_days(body.frequency)
                .map_err(map_error_to_grpc_status)?,
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
        service.client.subscriptions().plans().create(&params).await
    }
);

sub_rpc!(
    update_subscription_plan,
    UpdatePlanRequest,
    SubscriptionPlan,
    SubscriptionPlan,
    |service, body| {
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
        service
            .client
            .subscriptions()
            .plans()
            .update(body.plan_id, &params)
            .await
    }
);

sub_rpc!(
    list_subscription_plans,
    ListPlansRequest,
    PaginatedResponse<SubscriptionPlan>,
    PaginatedResponse<SubscriptionPlan>,
    |service, body| service.client.subscriptions().plans().list(body.page).await
);

plan_id_rpc!(suspend_subscription_plan, suspend);
plan_id_rpc!(resume_subscription_plan, resume);

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
            id: resp.id.clone(),
            client_secret: resp.client_secret.expose_secret().to_owned(),
            intention_order_id: resp.intention_order_id,
            status: resp.status.clone(),
            subscription_plan_id: resp.subscription_plan_id,
            payment_keys: resp.payment_keys.clone(),
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

sub_rpc!(
    create_subscription,
    CreateSubscriptionRequest,
    SubscriptionEnrollmentResponse,
    SubscriptionEnrollmentResponseDto,
    |service, body| {
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
        service.client.subscriptions().create(&params).await
    }
);

sub_rpc!(
    list_subscriptions,
    ListSubscriptionsRequest,
    PaginatedResponse<Subscription>,
    PaginatedResponse<Subscription>,
    |service, body| {
        let filter = SubscriptionListFilter {
            transaction: None,
            plan_id: body.plan_id,
            state: body.state.as_deref().map(SubscriptionState::from_state),
            page: body.page,
        };
        service.client.subscriptions().list(&filter).await
    }
);

sub_rpc!(
    update_subscription,
    UpdateSubscriptionRequest,
    Subscription,
    Subscription,
    |service, body| {
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
        service
            .client
            .subscriptions()
            .update(body.sub_id, &params)
            .await
    }
);

sub_id_rpc!(retrieve_subscription, retrieve, Subscription);
sub_id_rpc!(suspend_subscription, suspend, Subscription);
sub_id_rpc!(resume_subscription, resume, Subscription);
sub_id_rpc!(cancel_subscription, cancel, Subscription);
sub_id_rpc!(
    get_subscription_last_transaction,
    last_transaction,
    SubscriptionTransaction
);
sub_id_rpc!(
    list_subscription_transactions,
    list_transactions,
    Vec<SubscriptionTransaction>
);

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

sub_rpc!(
    add_secondary_subscription_card,
    AddSecondaryCardRequest,
    SubscriptionCard,
    SubscriptionCardDto,
    |service, body| {
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
        service
            .client
            .subscriptions()
            .cards()
            .add_secondary(body.sub_id, params)
            .await
    }
);

sub_card_rpc!(
    change_primary_subscription_card,
    ChangePrimaryCardRequest,
    change_primary,
    SubscriptionCardDto
);
sub_card_rpc!(
    delete_secondary_subscription_card,
    DeleteSecondaryCardRequest,
    delete_secondary,
    DeleteSecondaryCardResponseDto
);

sub_rpc!(
    register_subscription_webhook,
    RegisterWebhookRequest,
    SubscriptionWebhookRegistration,
    SubscriptionWebhookRegistration,
    |service, body| {
        service
            .client
            .subscriptions()
            .register_webhook(body.sub_id, &body.webhook_url)
            .await
    }
);

sub_rpc!(
    refund_subscription_last_transaction,
    RefundLastTransactionRequest,
    SubscriptionRefundResponse,
    SubscriptionRefundResponse,
    |service, body| {
        service
            .client
            .subscriptions()
            .refund_last_transaction(body.sub_id, body.amount_cents)
            .await
    }
);
