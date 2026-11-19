#![forbid(unsafe_code)]
//! Service 13 (Partner Merchant Onboarding) & Service 14 (Multi-Tenant Scoped) unary RPCs.

use std::future::Future;

use serde::{Deserialize, Serialize};
use some_paymob::resources::inquiries::TransactionInquiryParams;
use some_paymob::{
    CaptureParams, CreateIntentionParams, CreateIntentionParamsBuilder, CreatePartnerApiKeyParams,
    Currency, IntentionResponse, MerchantScopedClient, MinorUnitAmount, OnboardingSchemaQuery,
    PartnerLoginCredentials, PaymentMethodInput, PaymobError, RefundParams, RegisterMerchantParams,
    SubmitOnboardingStepParams, UpdateIntentionParams, UpdateIntentionParamsBuilder, VoidParams,
};
use tonic::{Request, Response, Status};

use super::super::PaymobGrpcService;
use super::super::error::map_error_to_grpc_status;
use super::super::proto::{JsonRpcRequest, JsonRpcResponse, decode_request, encode_response};
use super::{RpcHandler, run_rpc};

macro_rules! rpc_entry {
    ($name:literal, $func:ident) => {
        ($name, |s, r| Box::pin($func(s, r)))
    };
}

const HANDLERS: &[(&str, RpcHandler)] = &[
    rpc_entry!("PartnerLogin", partner_login),
    rpc_entry!("CreatePartnerApiKey", create_partner_api_key),
    rpc_entry!("RetrievePartnerHmacSecret", retrieve_partner_hmac_secret),
    rpc_entry!("RetrieveMerchantHmacSecret", retrieve_merchant_hmac_secret),
    rpc_entry!("RegisterPartnerMerchant", register_partner_merchant),
    rpc_entry!("GetOnboardingSchema", get_onboarding_schema),
    rpc_entry!("SubmitOnboardingStep", submit_onboarding_step),
    rpc_entry!("InquirePartnerMerchant", inquire_partner_merchant),
    rpc_entry!("ScopedCreateIntention", scoped_create_intention),
    rpc_entry!("ScopedUpdateIntention", scoped_update_intention),
    rpc_entry!("ScopedInquireTransaction", scoped_inquire_transaction),
    rpc_entry!("ScopedInquireByOrder", scoped_inquire_by_order),
    rpc_entry!("ScopedRefund", scoped_refund),
    rpc_entry!("ScopedVoid", scoped_void),
    rpc_entry!("ScopedCapture", scoped_capture),
];

pub(super) fn find_handler(method: &str) -> Option<RpcHandler> {
    HANDLERS
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, handler)| *handler)
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
) -> Result<CreateIntentionParams, PaymobError> {
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
    builder.build()
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
) -> Result<(u64, Option<String>, UpdateIntentionParams), PaymobError> {
    let mid = input.mid;
    let client_secret = input.client_secret.take();
    let builder = apply_scoped_update_core(UpdateIntentionParams::builder(), &mut input);
    let builder = apply_scoped_update_urls(builder, input);
    let params = builder.build()?;
    Ok((mid, client_secret, params))
}

async fn run_scoped<Resp, F, Fut>(
    service: &PaymobGrpcService,
    mid: u64,
    op: F,
) -> Result<Response<JsonRpcResponse>, Status>
where
    Resp: Serialize,
    F: FnOnce(MerchantScopedClient) -> Fut,
    Fut: Future<Output = Result<Resp, PaymobError>>,
{
    let scoped = service
        .client
        .with_merchant(mid)
        .map_err(map_error_to_grpc_status)?;
    let resp = op(scoped).await.map_err(map_error_to_grpc_status)?;
    encode_response(&resp)
}

async fn partner_login(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: PartnerLoginInput| async move {
        let creds = PartnerLoginCredentials::try_new(input.username, input.password)?;
        let resp = service.client.onboarding().auth().login(creds).await?;
        Ok(PartnerAuthAck {
            authenticated: true,
            token_present: !resp.token().is_empty(),
        })
    })
    .await
}

async fn create_partner_api_key(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |params: CreatePartnerApiKeyParams| async move {
        let resp = service
            .client
            .onboarding()
            .auth()
            .create_api_key(params)
            .await?;
        Ok(PartnerApiKeyAck {
            provisioned: !resp.api_key().is_empty(),
            label: resp.label.clone(),
        })
    })
    .await
}

async fn retrieve_partner_hmac_secret(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |_: serde_json::Value| async move {
        let env = service
            .client
            .onboarding()
            .auth()
            .retrieve_hmac_secret()
            .await?;
        Ok(PartnerHmacAck {
            status: env.status.clone(),
            code: env.code,
            label: env.label.clone(),
            hmac_present: !env.hmac_secret().is_empty(),
        })
    })
    .await
}

async fn retrieve_merchant_hmac_secret(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: MerchantIdInput| async move {
        let env = service
            .client
            .onboarding()
            .auth()
            .retrieve_merchant_hmac_secret(input.mid)
            .await?;
        Ok(PartnerHmacAck {
            status: env.status.clone(),
            code: env.code,
            label: env.label.clone(),
            hmac_present: !env.hmac_secret().is_empty(),
        })
    })
    .await
}

async fn register_partner_merchant(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |params: RegisterMerchantParams| async move {
        service
            .client
            .onboarding()
            .flow()
            .register_merchant(&params)
            .await
    })
    .await
}

async fn get_onboarding_schema(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: OnboardingSchemaInput| async move {
        let mut query = OnboardingSchemaQuery::new(input.partner)?;
        query.resubmission = input.resubmission;
        query.paymob_mid = input.paymob_mid;
        service.client.onboarding().flow().get_schema(&query).await
    })
    .await
}

async fn submit_onboarding_step(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |params: SubmitOnboardingStepParams| async move {
        service.client.onboarding().flow().submit_step(&params).await
    })
    .await
}

async fn inquire_partner_merchant(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    run_rpc(req, |input: MerchantIdInput| async move {
        service
            .client
            .onboarding()
            .flow()
            .merchant_inquiry(input.mid)
            .await
    })
    .await
}

async fn scoped_create_intention(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedCreateIntentionInput = decode_request(req)?;
    let mid = input.mid;
    let params = build_scoped_create_params(input).map_err(map_error_to_grpc_status)?;
    run_scoped(service, mid, |scoped| async move {
        let resp = scoped.intentions().create(&params).await?;
        Ok(intention_summary(resp))
    })
    .await
}

async fn scoped_update_intention(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedUpdateIntentionInput = decode_request(req)?;
    let (mid, client_secret, params) =
        build_scoped_update_params(input).map_err(map_error_to_grpc_status)?;
    run_scoped(service, mid, |scoped| async move {
        let resp = match client_secret {
            Some(secret) => {
                scoped
                    .intentions()
                    .update_by_client_secret(&secret, &params)
                    .await?
            }
            None => scoped.intentions().update(&params).await?,
        };
        Ok(intention_summary(resp))
    })
    .await
}

async fn scoped_inquire_transaction(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedTransactionInput = decode_request(req)?;
    run_scoped(service, input.mid, |scoped| async move {
        if input.raw {
            return scoped.inquiries().transaction_by_id(input.tx_id).await;
        }
        let tx = scoped.inquiries().transaction(input.tx_id).await?;
        Ok(serde_json::to_value(tx).unwrap_or_default())
    })
    .await
}

async fn scoped_inquire_by_order(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedInquireByOrderInput = decode_request(req)?;
    run_scoped(service, input.mid, |scoped| async move {
        scoped.inquiries().by_order(&input.params).await
    })
    .await
}

async fn scoped_refund(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedRefundInput = decode_request(req)?;
    run_scoped(service, input.mid, |scoped| async move {
        scoped.manage().refund(&input.params).await
    })
    .await
}

async fn scoped_void(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedVoidInput = decode_request(req)?;
    if let Some(tx_id) = input.tx_id {
        return run_scoped(service, input.mid, |scoped| async move {
            scoped.manage().void_transaction(tx_id).await
        })
        .await;
    }
    let params: VoidParams = serde_json::from_value(input.params)
        .map_err(|err| Status::invalid_argument(format!("invalid_void_params: {err}")))?;
    run_scoped(service, input.mid, |scoped| async move {
        scoped.manage().void(&params).await
    })
    .await
}

async fn scoped_capture(
    service: &PaymobGrpcService,
    req: Request<JsonRpcRequest>,
) -> Result<Response<JsonRpcResponse>, Status> {
    let input: ScopedCaptureInput = decode_request(req)?;
    run_scoped(service, input.mid, |scoped| async move {
        scoped.manage().capture(&input.params).await
    })
    .await
}
