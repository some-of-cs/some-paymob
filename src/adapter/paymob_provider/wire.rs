use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use some_payment_core::{
    CaptureMode, Money, PaymentError, PaymentResult, PaymentStatus, ProviderId, ProviderReference,
    RefundRequest, RefundResult, RefundStatus,
};

use crate::alignment::integration_validation::{
    AlignmentCaptureMode, IntentionBillingData, IntentionPreflightInput, ValidatedIntentionRouting,
};
use crate::alignment::status_synthesizer::{
    ChildTransactionKind, PaymobTransactionFlags, extract_parent_correlation,
    synthesize_paymob_status,
};
use crate::alignment::tx_correlation::TransactionLookupRef;

use super::errors::map_synthesized_status;

const ALIAS_METADATA_KEY: &str = "paymob_payment_method_alias";

pub(super) struct IntentionExecutionSpec<'a> {
    pub money: &'a Money,
    pub order_id: &'a str,
    pub capture_mode: CaptureMode,
    pub customer_email: Option<&'a str>,
    pub customer_phone: Option<&'a str>,
    pub notification_url: Option<&'a str>,
    pub redirection_url: Option<&'a str>,
    pub metadata: &'a BTreeMap<String, String>,
    pub is_checkout_session: bool,
}

#[derive(Serialize)]
pub(super) struct IntentionApiRequest<'a> {
    amount: u64,
    currency: &'a str,
    payment_methods: Vec<u64>,
    special_reference: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_data: Option<IntentionBillingPayload<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirection_url: Option<&'a str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    extras: &'a BTreeMap<String, String>,
}

#[derive(Serialize)]
struct IntentionBillingPayload<'a> {
    phone_number: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
}

#[derive(Deserialize)]
pub(super) struct IntentionApiResponse {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub intention_order_id: Option<u64>,
    pub client_secret: String,
}

#[derive(Serialize)]
pub(super) struct CaptureApiRequest<'a> {
    pub auth_token: &'a str,
    pub transaction_id: u64,
    pub amount_cents: u64,
}

#[derive(Serialize)]
pub(super) struct VoidApiRequest {
    pub transaction_id: u64,
}

#[derive(Serialize)]
pub(super) struct RefundApiRequest {
    pub transaction_id: u64,
    pub amount_cents: u64,
}

#[derive(Deserialize)]
pub(super) struct PaymobTransactionPayload {
    #[serde(flatten)]
    pub flags: PaymobTransactionFlags,
    #[serde(default)]
    pub currency: Option<String>,
    #[serde(default)]
    pub order: Option<Value>,
    #[serde(default)]
    pub is_live: Option<bool>,
}

#[derive(Clone, Copy)]
pub(super) struct RefundExecutionContext {
    pub tx_id: u64,
    pub amount_cents: u64,
}

pub(super) struct TxResultContext<'a> {
    pub default_livemode: bool,
    pub fallback_ref: Option<&'a ProviderReference>,
    pub fallback_currency: Option<&'a str>,
}

const fn to_alignment_capture_mode(mode: CaptureMode) -> AlignmentCaptureMode {
    match mode {
        CaptureMode::Automatic => AlignmentCaptureMode::Automatic,
        CaptureMode::Manual => AlignmentCaptureMode::Manual,
    }
}

pub(super) fn build_preflight_input(spec: &IntentionExecutionSpec<'_>) -> IntentionPreflightInput {
    let billing_data = spec.customer_phone.map(|phone| IntentionBillingData {
        phone_number: phone.to_owned(),
        email: spec.customer_email.map(ToOwned::to_owned),
        first_name: None,
        last_name: None,
    });
    IntentionPreflightInput {
        order_id: spec.order_id.to_owned(),
        capture_mode: to_alignment_capture_mode(spec.capture_mode),
        payment_method_alias: spec.metadata.get(ALIAS_METADATA_KEY).cloned(),
        billing_data,
        items: Vec::new(),
    }
}

pub(super) fn build_intention_payload<'a>(
    spec: &'a IntentionExecutionSpec<'a>,
    validated: &ValidatedIntentionRouting,
) -> IntentionApiRequest<'a> {
    let billing_data = spec.customer_phone.map(|phone| IntentionBillingPayload {
        phone_number: phone,
        email: spec.customer_email,
    });
    IntentionApiRequest {
        amount: spec.money.amount(),
        currency: spec.money.currency().as_str(),
        payment_methods: validated.payment_methods.clone(),
        special_reference: validated.special_reference.clone(),
        billing_data,
        notification_url: spec.notification_url,
        redirection_url: spec.redirection_url,
        extras: spec.metadata,
    }
}

pub(super) fn build_intention_reference(
    provider_id: &ProviderId,
    spec: &IntentionExecutionSpec<'_>,
    body: &IntentionApiResponse,
) -> Result<ProviderReference, PaymentError> {
    let mut builder = ProviderReference::builder(provider_id.clone());
    if let Some(id) = body.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        builder = builder.intent_id(id);
        if spec.is_checkout_session {
            builder = builder.checkout_session_id(id);
        }
    }
    let resolved_order = body
        .intention_order_id
        .map_or_else(|| spec.order_id.to_owned(), |id| id.to_string());
    builder.order_id(resolved_order).build()
}

pub(super) fn build_lookup_ref(reference: &ProviderReference) -> TransactionLookupRef {
    let direct_tx = reference
        .transaction_id()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&id| id > 0);
    let (numeric_order, merchant_order) = classify_order_id(reference.order_id());
    TransactionLookupRef {
        transaction_id: direct_tx,
        payment_id: reference.payment_id().map(ToOwned::to_owned),
        order_id: numeric_order,
        merchant_order_id: merchant_order,
        special_reference: reference.intent_id().map(ToOwned::to_owned),
    }
}

fn classify_order_id(order_id: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw) = order_id.map(str::trim).filter(|s| !s.is_empty()) else {
        return (None, None);
    };
    if raw.parse::<u64>().is_ok() {
        (Some(raw.to_owned()), None)
    } else {
        (None, Some(raw.to_owned()))
    }
}

pub(super) fn synthesize_effective_status(flags: &PaymobTransactionFlags) -> PaymentStatus {
    let correlation = extract_parent_correlation(flags);
    let succeeded = flags.success && !flags.pending && !flags.error_occured;
    if succeeded && correlation.child_kind == Some(ChildTransactionKind::Void) {
        return PaymentStatus::Voided;
    }
    map_synthesized_status(synthesize_paymob_status(flags))
}

pub(super) fn extract_payload_money(
    payload: &PaymobTransactionPayload,
    fallback_currency: Option<&str>,
    provider_id: &ProviderId,
) -> Result<Money, PaymentError> {
    let currency = payload
        .currency
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .or_else(|| fallback_currency.map(str::trim).filter(|c| !c.is_empty()))
        .ok_or_else(|| PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: None,
            vendor_code: None,
            message: "paymob transaction payload omitted currency".to_owned(),
        })?;
    if payload.flags.amount_cents == 0 {
        return Err(PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: None,
            vendor_code: None,
            message: "paymob transaction payload returned zero amount_cents".to_owned(),
        });
    }
    Money::new(payload.flags.amount_cents, currency)
}

fn extract_order_id_from_value(order: Option<&Value>) -> Option<String> {
    let val = order?;
    if let Some(n) = val.as_u64() {
        return Some(n.to_string());
    }
    if let Some(s) = val.as_str() {
        return Some(s.to_owned());
    }
    val.get("id").and_then(|id| {
        id.as_u64()
            .map(|n| n.to_string())
            .or_else(|| id.as_str().map(ToOwned::to_owned))
    })
}

pub(super) fn build_tx_payment_result(
    provider_id: &ProviderId,
    payload: &PaymobTransactionPayload,
    ctx: &TxResultContext<'_>,
) -> Result<PaymentResult, PaymentError> {
    let status = synthesize_effective_status(&payload.flags);
    let money = extract_payload_money(payload, ctx.fallback_currency, provider_id)?;
    let reference = build_tx_reference(provider_id, payload, ctx.fallback_ref)?;
    Ok(PaymentResult {
        reference,
        status,
        money,
        captured_amount: positive_u64(payload.flags.captured_amount),
        refunded_amount: positive_u64(payload.flags.refunded_amount_cents),
        next_action: None,
        checkout_url: None,
        livemode: payload.is_live.unwrap_or(ctx.default_livemode),
    })
}

fn build_tx_reference(
    provider_id: &ProviderId,
    payload: &PaymobTransactionPayload,
    fallback_ref: Option<&ProviderReference>,
) -> Result<ProviderReference, PaymentError> {
    let correlation = extract_parent_correlation(&payload.flags);
    let mut builder = ProviderReference::builder(provider_id.clone());
    if correlation.canonical_payment_id > 0 {
        builder = builder.payment_id(correlation.canonical_payment_id.to_string());
    }
    if payload.flags.id > 0 {
        builder = builder.transaction_id(payload.flags.id.to_string());
    }
    let order_id = extract_order_id_from_value(payload.order.as_ref())
        .or_else(|| fallback_ref.and_then(|r| r.order_id().map(ToOwned::to_owned)));
    if let Some(oid) = order_id {
        builder = builder.order_id(oid);
    }
    builder.build()
}

pub(super) fn build_refund_result(
    provider_id: &ProviderId,
    ctx: RefundExecutionContext,
    req: &RefundRequest,
    payload: &PaymobTransactionPayload,
) -> Result<RefundResult, PaymentError> {
    let refund_id = if payload.flags.id > 0 {
        payload.flags.id.to_string()
    } else {
        format!("refund-{}", ctx.tx_id)
    };
    let status = classify_refund_status(&payload.flags);
    let money = resolve_refund_money(provider_id, ctx.amount_cents, req, payload)?;
    let payment_reference = build_refund_payment_ref(provider_id, ctx.tx_id, &req.reference)?;
    Ok(RefundResult {
        refund_id,
        payment_reference,
        status,
        money,
        reason_detail: req.reason.clone(),
    })
}

fn resolve_refund_money(
    provider_id: &ProviderId,
    amount_cents: u64,
    req: &RefundRequest,
    payload: &PaymobTransactionPayload,
) -> Result<Money, PaymentError> {
    if let Some(money) = &req.amount {
        return Ok(money.clone());
    }
    let currency = payload
        .currency
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| PaymentError::ProviderError {
            provider: provider_id.clone(),
            http_status: None,
            vendor_code: None,
            message: "paymob refund response omitted currency".to_owned(),
        })?;
    Money::new(amount_cents, currency)
}

const fn classify_refund_status(flags: &PaymobTransactionFlags) -> RefundStatus {
    if flags.pending {
        return RefundStatus::Pending;
    }
    if flags.success && !flags.error_occured {
        return RefundStatus::Succeeded;
    }
    RefundStatus::Failed
}

fn build_refund_payment_ref(
    provider_id: &ProviderId,
    tx_id: u64,
    original: &ProviderReference,
) -> Result<ProviderReference, PaymentError> {
    let mut builder =
        ProviderReference::builder(provider_id.clone()).transaction_id(tx_id.to_string());
    if let Some(pid) = original.payment_id() {
        builder = builder.payment_id(pid);
    }
    if let Some(oid) = original.order_id() {
        builder = builder.order_id(oid);
    }
    builder.build()
}

const fn positive_u64(value: u64) -> Option<u64> {
    if value > 0 { Some(value) } else { None }
}
