#![forbid(unsafe_code)]
//! Unit 3 RPCs: Services 13-14 (onboarding, multi-tenant scoped, webhooks Protocols A-E, unified adapter).

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use some_paymob::resources::inquiries::TransactionInquiryParams;
use some_paymob::{
    CaptureParams, CreateIntentionParams, CreateIntentionParamsBuilder, CreatePartnerApiKeyParams,
    Currency, IntentionResponse, MinorUnitAmount, OnboardingSchemaQuery, PartnerLoginCredentials,
    PaymentMethodInput, PaymentProvider, PayoutProvider, RefundParams, RegisterMerchantParams,
    SubmitOnboardingStepParams, SubscriptionProvider, UnifiedCaptureRequest,
    UnifiedPaymentSessionRequest, UnifiedPayoutRequest, UnifiedRefundRequest,
    UnifiedSavedMethodChargeRequest, UnifiedSubscriptionRefundRequest, UnifiedVoidRequest,
    UpdateIntentionParams, UpdateIntentionParamsBuilder, VoidParams,
};
use tonic::{Request, Response, Status};

use super::PaymobGrpcService;
use super::error::{map_error_to_grpc_status, map_webhook_error_to_grpc_status};
use super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};

type RpcFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<JsonRpcResponse>, Status>> + Send + 'a>>;
type RpcHandler = for<'a> fn(&'a PaymobGrpcService, Request<JsonRpcRequest>) -> RpcFuture<'a>;

const HANDLERS: &[(&str, RpcHandler)] = &[
    ("PartnerLogin", |s, r| Box::pin(partner_login(s, r))),
    ("CreatePartnerApiKey", |s, r| {
        Box::pin(create_partner_api_key(s, r))
    }),
    ("RetrievePartnerHmacSecret", |s, r| {
        Box::pin(retrieve_partner_hmac_secret(s, r))
    }),
    ("RetrieveMerchantHmacSecret", |s, r| {
        Box::pin(retrieve_merchant_hmac_secret(s, r))
    }),
    ("RegisterPartnerMerchant", |s, r| {
        Box::pin(register_partner_merchant(s, r))
    }),
    ("GetOnboardingSchema", |s, r| {
        Box::pin(get_onboarding_schema(s, r))
    }),
    ("SubmitOnboardingStep", |s, r| {
        Box::pin(submit_onboarding_step(s, r))
    }),
    ("InquirePartnerMerchant", |s, r| {
        Box::pin(inquire_partner_merchant(s, r))
    }),
    ("ScopedCreateIntention", |s, r| {
        Box::pin(scoped_create_intention(s, r))
    }),
    ("ScopedUpdateIntention", |s, r| {
        Box::pin(scoped_update_intention(s, r))
    }),
    ("ScopedInquireTransaction", |s, r| {
        Box::pin(scoped_inquire_transaction(s, r))
    }),
    ("ScopedInquireByOrder", |s, r| {
        Box::pin(scoped_inquire_by_order(s, r))
    }),
    ("ScopedRefund", |s, r| Box::pin(scoped_refund(s, r))),
    ("ScopedVoid", |s, r| Box::pin(scoped_void(s, r))),
    ("ScopedCapture", |s, r| Box::pin(scoped_capture(s, r))),
    ("VerifyWebhookEvent", |s, r| {
        Box::pin(verify_webhook_event(s, r))
    }),
    ("VerifyWebhookRedirect", |s, r| {
        Box::pin(verify_webhook_redirect(s, r))
    }),
    ("UnifiedCreateSession", |s, r| {
        Box::pin(unified_create_session(s, r))
    }),
    ("UnifiedCapture", |s, r| Box::pin(unified_capture(s, r))),
    ("UnifiedRefund", |s, r| Box::pin(unified_refund(s, r))),
    ("UnifiedVoid", |s, r| Box::pin(unified_void(s, r))),
    ("UnifiedChargeSavedMethod", |s, r| {
        Box::pin(unified_charge_saved_method(s, r))
    }),
    ("UnifiedRefundSubscription", |s, r| {
        Box::pin(unified_refund_subscription(s, r))
    }),
    ("UnifiedExecutePayout", |s, r| {
        Box::pin(unified_execute_payout(s, r))
    }),
    ("UnifiedVerifyWebhook", |s, r| {
        Box::pin(unified_verify_webhook(s, r))
    }),
];

/// Dispatches Unit 3 unary RPC methods (Services 13-14, webhooks Protocols A-E, and unified adapter).
pub async fn dispatch(
    service: &PaymobGrpcService,
    method: &str,
    req: Request<JsonRpcRequest>,
) -> Option<Result<Response<JsonRpcResponse>, Status>> {
    let (_, handler) = HANDLERS.iter().find(|(name, _)| *name == method)?;
    Some(handler(service, req).await)
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
struct MerchantIdInput {
    mid: u64,
}

#[derive(Debug, Deserialize)]
struct OnboardingSchemaInput {
    partner: String,
    #[serde(default)]
    resubmission: Option<bool>,
    #[serde(default)]
    paymob_mid: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ScopedCreateIntentionInput {
    mid: u64,
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
    mid: u64,
    #[serde(default)]
    client_secret: Option<String>,
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

#[derive(Debug, Deserialize)]
struct ScopedTransactionInput {
    mid: u64,
    tx_id: u64,
    #[serde(default)]
    raw: bool,
}

#[derive(Debug, Deserialize)]
struct ScopedInquireByOrderInput {
    mid: u64,
    #[serde(flatten)]
    params: TransactionInquiryParams,
}

#[derive(Debug, Deserialize)]
struct ScopedRefundInput {
    mid: u64,
    #[serde(flatten)]
    params: RefundParams,
}

#[derive(Debug, Deserialize)]
struct ScopedVoidInput {
    mid: u64,
    #[serde(default)]
    tx_id: Option<u64>,
    #[serde(flatten)]
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct ScopedCaptureInput {
    mid: u64,
    #[serde(flatten)]
    params: CaptureParams,
}

#[derive(Debug, Deserialize)]
struct WebhookEventInput {
    #[serde(alias = "body")]
    raw_body: String,
    #[serde(default)]
    hmac: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WebhookRedirectInput {
    #[serde(alias = "query")]
    raw_query: String,
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
    mut builder: CreateIntentionParamsBuilder,
    input: &mut ScopedCreateIntentionInput,
) -> CreateIntentionParamsBuilder {
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
) -> Result<CreateIntentionParams, Status> {
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
    builder.build().map_err(map_error_to_grpc_status)
}

fn apply_scoped_update_core(
    mut builder: UpdateIntentionParamsBuilder,
    input: &mut ScopedUpdateIntentionInput,
) -> UpdateIntentionParamsBuilder {
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
    mut builder: UpdateIntentionParamsBuilder,
    input: ScopedUpdateIntentionInput,
) -> UpdateIntentionParamsBuilder {
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
) -> Result<(u64, Option<String>, UpdateIntentionParams), Status> {
    let mid = input.mid;
    let client_secret = input.client_secret.take();
    let builder = apply_scoped_update_core(UpdateIntentionParams::builder(), &mut input);
    let builder = apply_scoped_update_urls(builder, input);
    let params = builder.build().map_err(map_error_to_grpc_status)?;
    Ok((mid, client_secret, params))
}

async fn partner_login(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: PartnerLoginInput = decode_request(req)?;
    let creds = PartnerLoginCredentials::try_new(input.username, input.password)
        .map_err(map_error_to_grpc_status)?;
    let resp = service
        .client
        .onboarding()
        .auth()
        .login(creds)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&PartnerAuthAck {
        authenticated: true,
        token_present: !resp.token().is_empty(),
    })
}

async fn create_partner_api_key(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let params: CreatePartnerApiKeyParams = decode_request(req)?;
    let resp = service
        .client
        .onboarding()
        .auth()
        .create_api_key(params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&PartnerApiKeyAck {
        provisioned: !resp.api_key().is_empty(),
        label: resp.label.clone(),
    })
}

async fn retrieve_partner_hmac_secret(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let _: serde_json::Value = decode_request(req)?;
    let env = service
        .client
        .onboarding()
        .auth()
        .retrieve_hmac_secret()
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&PartnerHmacAck {
        status: env.status.clone(),
        code: env.code,
        label: env.label.clone(),
        hmac_present: !env.hmac_secret().is_empty(),
    })
}

async fn retrieve_merchant_hmac_secret(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: MerchantIdInput = decode_request(req)?;
    let env = service
        .client
        .onboarding()
        .auth()
        .retrieve_merchant_hmac_secret(input.mid)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&PartnerHmacAck {
        status: env.status.clone(),
        code: env.code,
        label: env.label.clone(),
        hmac_present: !env.hmac_secret().is_empty(),
    })
}

async fn register_partner_merchant(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let params: RegisterMerchantParams = decode_request(req)?;
    let resp = service
        .client
        .onboarding()
        .flow()
        .register_merchant(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn get_onboarding_schema(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: OnboardingSchemaInput = decode_request(req)?;
    let mut query = OnboardingSchemaQuery::new(input.partner).map_err(map_error_to_grpc_status)?;
    query.resubmission = input.resubmission;
    query.paymob_mid = input.paymob_mid;
    let schema = service
        .client
        .onboarding()
        .flow()
        .get_schema(&query)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&schema)
}

async fn submit_onboarding_step(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let params: SubmitOnboardingStepParams = decode_request(req)?;
    let resp = service
        .client
        .onboarding()
        .flow()
        .submit_step(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn inquire_partner_merchant(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: MerchantIdInput = decode_request(req)?;
    let resp = service
        .client
        .onboarding()
        .flow()
        .merchant_inquiry(input.mid)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn scoped_create_intention(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedCreateIntentionInput = decode_request(req)?;
    let mid = input.mid;
    let params = build_scoped_create_params(input)?;
    let scoped = service
        .client
        .with_merchant(mid)
        .map_err(map_error_to_grpc_status)?;
    let resp = scoped
        .intentions()
        .create(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&intention_summary(resp))
}

async fn scoped_update_intention(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedUpdateIntentionInput = decode_request(req)?;
    let (mid, client_secret, params) = build_scoped_update_params(input)?;
    let scoped = service
        .client
        .with_merchant(mid)
        .map_err(map_error_to_grpc_status)?;
    let resp = match client_secret {
        Some(secret) => {
            scoped
                .intentions()
                .update_by_client_secret(&secret, &params)
                .await
        }
        None => scoped.intentions().update(&params).await,
    }
    .map_err(map_error_to_grpc_status)?;
    encode_response(&intention_summary(resp))
}

async fn scoped_inquire_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedTransactionInput = decode_request(req)?;
    let scoped = service
        .client
        .with_merchant(input.mid)
        .map_err(map_error_to_grpc_status)?;
    if input.raw {
        let val = scoped
            .inquiries()
            .transaction_by_id(input.tx_id)
            .await
            .map_err(map_error_to_grpc_status)?;
        return encode_response(&val);
    }
    let tx = scoped
        .inquiries()
        .transaction(input.tx_id)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn scoped_inquire_by_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedInquireByOrderInput = decode_request(req)?;
    let scoped = service
        .client
        .with_merchant(input.mid)
        .map_err(map_error_to_grpc_status)?;
    let tx = scoped
        .inquiries()
        .by_order(&input.params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn scoped_refund(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedRefundInput = decode_request(req)?;
    let scoped = service
        .client
        .with_merchant(input.mid)
        .map_err(map_error_to_grpc_status)?;
    let tx = scoped
        .manage()
        .refund(&input.params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn scoped_void(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedVoidInput = decode_request(req)?;
    let scoped = service
        .client
        .with_merchant(input.mid)
        .map_err(map_error_to_grpc_status)?;
    if let Some(tx_id) = input.tx_id {
        let val = scoped
            .manage()
            .void_transaction(tx_id)
            .await
            .map_err(map_error_to_grpc_status)?;
        return encode_response(&val);
    }
    let params: VoidParams = serde_json::from_value(input.params)
        .map_err(|err| Status::invalid_argument(format!("invalid_void_params: {err}")))?;
    let tx = scoped
        .manage()
        .void(&params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn scoped_capture(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedCaptureInput = decode_request(req)?;
    let scoped = service
        .client
        .with_merchant(input.mid)
        .map_err(map_error_to_grpc_status)?;
    let tx = scoped
        .manage()
        .capture(&input.params)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&tx)
}

async fn verify_webhook_event(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: WebhookEventInput = decode_request(req)?;
    let event = service
        .webhook_engine
        .construct_event(&input.raw_body, input.hmac.as_deref())
        .map_err(map_webhook_error_to_grpc_status)?;
    service
        .deduplicator
        .claim_or_reject(&event)
        .map_err(map_webhook_error_to_grpc_status)?;
    encode_response(&WebhookAckDto {
        event_type: event.event_type().to_string(),
        verified: true,
        deduplicated: true,
    })
}

async fn verify_webhook_redirect(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: WebhookRedirectInput = decode_request(req)?;
    let params = service
        .webhook_engine
        .verify_transaction_get_query_str(&input.raw_query)
        .map_err(map_webhook_error_to_grpc_status)?;
    service
        .deduplicator
        .claim_or_reject(&params)
        .map_err(map_webhook_error_to_grpc_status)?;
    encode_response(&RedirectWebhookAckDto {
        id: params.id.clone(),
        order_id: params.order_id.clone(),
        currency: params.currency.clone(),
        amount_cents: params.amount_cents.clone(),
        approved: params.is_approved(),
        pending: params.is_pending(),
        deduplicated: true,
    })
}

async fn unified_create_session(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedPaymentSessionRequest = decode_request(req)?;
    let session = service
        .client
        .create_payment_session(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&UnifiedSessionDto {
        session_id: session.session_id.clone(),
        order_id: session.order_id.clone(),
        status: session.status.clone(),
        confirmed: session.confirmed,
    })
}

async fn unified_capture(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedCaptureRequest = decode_request(req)?;
    let receipt = service
        .client
        .capture_payment(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_refund(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedRefundRequest = decode_request(req)?;
    let receipt = service
        .client
        .refund_payment(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_void(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedVoidRequest = decode_request(req)?;
    let receipt = service
        .client
        .void_payment(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_charge_saved_method(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedSavedChargeInput = decode_request(req)?;
    let mut charge_req =
        UnifiedSavedMethodChargeRequest::new(input.payment_token, input.saved_method_token);
    if let Some(cvn) = input.cvn {
        charge_req = charge_req.with_cvn(cvn);
    }
    let receipt = service
        .client
        .charge_saved_method(&charge_req)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_refund_subscription(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedSubscriptionRefundRequest = decode_request(req)?;
    let receipt = service
        .client
        .refund_last_transaction(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_execute_payout(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: UnifiedPayoutRequest = decode_request(req)?;
    let receipt = service
        .client
        .execute_payout(&input)
        .await
        .map_err(map_error_to_grpc_status)?;
    encode_response(&receipt)
}

async fn unified_verify_webhook(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: WebhookEventInput = decode_request(req)?;
    let event = service
        .webhook_engine
        .construct_event(&input.raw_body, input.hmac.as_deref())
        .map_err(map_webhook_error_to_grpc_status)?;
    service
        .deduplicator
        .claim_or_reject(&event)
        .map_err(map_webhook_error_to_grpc_status)?;
    encode_response(&some_paymob::normalize_webhook_event(&event))
}
