#![forbid(unsafe_code)]
//! Service 13 (Partner Merchant Onboarding) & Service 14 (Multi-Tenant Scoped) unary RPCs.

use std::future::Future;

use serde::{Deserialize, Serialize};
use some_paymob::resources::inquiries::TransactionInquiryParams;
use some_paymob::{
    CaptureParams, CreateIntentionParams, CreatePartnerApiKeyParams, Currency, IntentionResponse,
    MerchantScopedClient, MinorUnitAmount, OnboardingSchemaQuery, PartnerHmacEnvelope,
    PartnerLoginCredentials, PaymentMethodInput, PaymobError, RefundParams, RegisterMerchantParams,
    SubmitOnboardingStepParams, UpdateIntentionParams, VoidParams,
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

macro_rules! onboarding_rpc {
    ($fn_name:ident, $input_ty:ty, |$service:ident, $input:ident| $body:expr) => {
        async fn $fn_name(
            $service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            run_rpc(req, |$input: $input_ty| async move { $body }).await
        }
    };
}

macro_rules! scoped_rpc {
    ($fn_name:ident, $input_ty:ty, |$scoped:ident, $input:ident| $body:expr) => {
        async fn $fn_name(
            service: &PaymobGrpcService,
            req: Request<JsonRpcRequest>,
        ) -> Result<Response<JsonRpcResponse>, Status> {
            let $input: $input_ty = decode_request(req)?;
            run_scoped(service, $input.mid, |$scoped| async move { $body }).await
        }
    };
}

macro_rules! apply_opts {
    ($builder:expr, $($val:expr => $method:ident),+ $(,)?) => {{
        let mut b = $builder;
        $(
            if let Some(v) = $val {
                b = b.$method(v);
            }
        )+
        b
    }};
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

#[derive(Deserialize)]
struct PartnerLoginInput {
    username: String,
    password: String,
}

impl std::fmt::Debug for PartnerLoginInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PartnerLoginInput").finish_non_exhaustive()
    }
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

fn partner_hmac_ack(env: &PartnerHmacEnvelope) -> PartnerHmacAck {
    PartnerHmacAck {
        status: env.status.clone(),
        code: env.code,
        label: env.label.clone(),
        hmac_present: !env.hmac_secret().is_empty(),
    }
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

fn build_scoped_create_params(
    input: ScopedCreateIntentionInput,
) -> Result<CreateIntentionParams, PaymobError> {
    let builder = CreateIntentionParams::builder()
        .amount(input.amount)
        .currency(input.currency)
        .payment_methods(input.payment_methods);
    apply_opts!(
        builder,
        input.special_reference => special_reference,
        input.notification_url => notification_url,
        input.redirection_url => redirection_url,
        input.expiration => expiration,
        input.extras => extras,
    )
    .build()
}

fn build_scoped_update_params(
    input: ScopedUpdateIntentionInput,
) -> Result<(Option<String>, UpdateIntentionParams), PaymobError> {
    let params = apply_opts!(
        UpdateIntentionParams::builder(),
        input.amount => amount,
        input.currency => currency,
        input.payment_methods => payment_methods,
        input.special_reference => special_reference,
        input.notification_url => notification_url,
        input.redirection_url => redirection_url,
    )
    .build()?;
    Ok((input.client_secret, params))
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

onboarding_rpc!(partner_login, PartnerLoginInput, |service, input| {
    let creds = PartnerLoginCredentials::try_new(input.username, input.password)?;
    let resp = service.client.onboarding().auth().login(creds).await?;
    Ok(PartnerAuthAck {
        authenticated: true,
        token_present: !resp.token().is_empty(),
    })
});

onboarding_rpc!(
    create_partner_api_key,
    CreatePartnerApiKeyParams,
    |service, params| {
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
    }
);

onboarding_rpc!(
    retrieve_partner_hmac_secret,
    serde_json::Value,
    |service, _input| {
        let env = service
            .client
            .onboarding()
            .auth()
            .retrieve_hmac_secret()
            .await?;
        Ok(partner_hmac_ack(&env))
    }
);

onboarding_rpc!(
    retrieve_merchant_hmac_secret,
    MerchantIdInput,
    |service, input| {
        let env = service
            .client
            .onboarding()
            .auth()
            .retrieve_merchant_hmac_secret(input.mid)
            .await?;
        Ok(partner_hmac_ack(&env))
    }
);

onboarding_rpc!(
    register_partner_merchant,
    RegisterMerchantParams,
    |service, params| {
        service
            .client
            .onboarding()
            .flow()
            .register_merchant(&params)
            .await
    }
);

onboarding_rpc!(
    get_onboarding_schema,
    OnboardingSchemaInput,
    |service, input| {
        let mut query = OnboardingSchemaQuery::new(input.partner)?;
        query.resubmission = input.resubmission;
        query.paymob_mid = input.paymob_mid;
        service.client.onboarding().flow().get_schema(&query).await
    }
);

onboarding_rpc!(
    submit_onboarding_step,
    SubmitOnboardingStepParams,
    |service, params| {
        service
            .client
            .onboarding()
            .flow()
            .submit_step(&params)
            .await
    }
);

onboarding_rpc!(
    inquire_partner_merchant,
    MerchantIdInput,
    |service, input| {
        service
            .client
            .onboarding()
            .flow()
            .merchant_inquiry(input.mid)
            .await
    }
);

scoped_rpc!(
    scoped_create_intention,
    ScopedCreateIntentionInput,
    |scoped, input| {
        let params = build_scoped_create_params(input)?;
        let resp = scoped.intentions().create(&params).await?;
        Ok(intention_summary(resp))
    }
);

scoped_rpc!(
    scoped_update_intention,
    ScopedUpdateIntentionInput,
    |scoped, input| {
        let (client_secret, params) = build_scoped_update_params(input)?;
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
    }
);

scoped_rpc!(
    scoped_inquire_transaction,
    ScopedTransactionInput,
    |scoped, input| {
        if input.raw {
            return scoped.inquiries().transaction_by_id(input.tx_id).await;
        }
        let tx = scoped.inquiries().transaction(input.tx_id).await?;
        Ok(serde_json::to_value(tx).unwrap_or_default())
    }
);

scoped_rpc!(
    scoped_inquire_by_order,
    ScopedInquireByOrderInput,
    |scoped, input| scoped.inquiries().by_order(&input.params).await
);

scoped_rpc!(scoped_refund, ScopedRefundInput, |scoped, input| {
    scoped.manage().refund(&input.params).await
});

scoped_rpc!(scoped_capture, ScopedCaptureInput, |scoped, input| {
    scoped.manage().capture(&input.params).await
});

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
