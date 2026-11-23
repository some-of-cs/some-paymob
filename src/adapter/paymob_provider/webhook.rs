use secrecy::ExposeSecret;
use serde_json::Value;
use some_payment_core::{
    HttpMethod, Money, NormalizedWebhookEvent, PaymentError, PaymentStatus, ProviderId,
    ProviderReference, RawWebhookRequest,
};

use crate::alignment::callback_dispatcher::{
    CallbackAuthority, CardTokenCallbackData, DispatchedPaymobCallback, PaymobCallbackInput,
    SubscriptionCallbackData, TransactionCallbackData, dispatch_and_verify_paymob_callback,
};
use crate::alignment::status_synthesizer::{
    ChildTransactionKind, ParentTransactionCorrelation, PaymobTransactionFlags,
    extract_parent_correlation,
};

use super::config::PaymobProviderConfig;
use super::errors::map_callback_error;
use super::wire::synthesize_effective_status;

pub(super) fn parse_and_verify_paymob_webhook(
    provider_id: &ProviderId,
    config: &PaymobProviderConfig,
    raw: &RawWebhookRequest,
) -> Result<NormalizedWebhookEvent, PaymentError> {
    let (input, parsed_post_body) = build_callback_input(provider_id, raw)?;
    let hmac = config.credentials().hmac_secret().expose_secret();
    let dispatched = dispatch_and_verify_paymob_callback(&input, hmac)
        .map_err(|err| map_callback_error(provider_id, err))?;
    let livemode = config.livemode();
    match dispatched {
        DispatchedPaymobCallback::Transaction(tx) => Ok(map_transaction_webhook(
            provider_id,
            livemode,
            tx,
            parsed_post_body.as_ref(),
        )),
        DispatchedPaymobCallback::CardToken(token) => {
            Ok(map_card_token_webhook(provider_id, livemode, token))
        }
        DispatchedPaymobCallback::Subscription(sub) => {
            Ok(map_subscription_webhook(provider_id, livemode, sub))
        }
    }
}

fn build_callback_input(
    provider_id: &ProviderId,
    raw: &RawWebhookRequest,
) -> Result<(PaymobCallbackInput, Option<Value>), PaymentError> {
    match raw.method {
        HttpMethod::Get => Ok((PaymobCallbackInput::get(raw.query_params.clone()), None)),
        HttpMethod::Post => {
            let body: Value = serde_json::from_slice(&raw.raw_body).map_err(|_| {
                PaymentError::WebhookVerificationFailed {
                    provider: provider_id.clone(),
                    reason: "invalid JSON body in POST webhook".to_owned(),
                }
            })?;
            let input = PaymobCallbackInput::post(raw.query_params.clone(), body.clone());
            Ok((input, Some(body)))
        }
    }
}

fn build_webhook_tx_flags(
    tx: &TransactionCallbackData,
    post_body: Option<&Value>,
) -> PaymobTransactionFlags {
    let parsed_from_obj = post_body
        .and_then(|b| b.get("obj"))
        .and_then(|obj| serde_json::from_value::<PaymobTransactionFlags>(obj.clone()).ok());
    if let Some(flags) = parsed_from_obj {
        return flags;
    }
    PaymobTransactionFlags {
        id: tx
            .transaction_id
            .as_deref()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0),
        pending: tx.pending.unwrap_or(false),
        success: tx.success.unwrap_or(false),
        error_occured: tx.error_occured.unwrap_or(false),
        is_voided: tx.is_voided.unwrap_or(false),
        is_refunded: tx.is_refunded.unwrap_or(false),
        amount_cents: tx
            .amount_cents
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0),
        is_auth: tx.is_auth.unwrap_or(false),
        is_capture: tx.is_capture.unwrap_or(false),
        ..PaymobTransactionFlags::default()
    }
}

fn map_transaction_webhook(
    provider_id: &ProviderId,
    default_livemode: bool,
    tx: TransactionCallbackData,
    post_body: Option<&Value>,
) -> NormalizedWebhookEvent {
    let flags = build_webhook_tx_flags(&tx, post_body);
    let correlation = extract_parent_correlation(&flags);
    let status = synthesize_effective_status(&flags);
    let requires_hydration = tx.authority == CallbackAuthority::CustomerGetReturn;
    let event_type = resolve_tx_event_type(tx.authority, correlation.child_kind);
    let reference = build_webhook_tx_reference(provider_id, &tx, &correlation);
    let money = extract_webhook_money(&tx);
    let livemode = post_body
        .and_then(|b| b.get("obj"))
        .and_then(|o| o.get("is_live"))
        .and_then(Value::as_bool)
        .unwrap_or(default_livemode);
    let event_id = tx
        .transaction_id
        .unwrap_or_else(|| correlation.canonical_payment_id.to_string());
    NormalizedWebhookEvent {
        provider_id: provider_id.clone(),
        event_id,
        event_type,
        livemode,
        requires_hydration,
        reference,
        status: Some(status),
        money,
        verification_challenge: None,
        raw_redacted: tx.raw_redacted,
    }
}

fn resolve_tx_event_type(
    authority: CallbackAuthority,
    child_kind: Option<ChildTransactionKind>,
) -> String {
    if authority == CallbackAuthority::CustomerGetReturn {
        return "paymob.transaction.return".to_owned();
    }
    match child_kind {
        Some(ChildTransactionKind::Void) => "paymob.transaction.void".to_owned(),
        Some(ChildTransactionKind::Refund) => "paymob.transaction.refund".to_owned(),
        Some(ChildTransactionKind::Capture) => "paymob.transaction.capture".to_owned(),
        None => "paymob.transaction".to_owned(),
    }
}

fn build_webhook_tx_reference(
    provider_id: &ProviderId,
    tx: &TransactionCallbackData,
    correlation: &ParentTransactionCorrelation,
) -> Option<ProviderReference> {
    let mut builder = ProviderReference::builder(provider_id.clone());
    if correlation.canonical_payment_id > 0 {
        builder = builder.payment_id(correlation.canonical_payment_id.to_string());
    }
    let tx_id = correlation
        .child_transaction_id
        .map(|id| id.to_string())
        .or_else(|| tx.transaction_id.clone());
    if let Some(id) = tx_id {
        builder = builder.transaction_id(id);
    }
    if let Some(oid) = &tx.order_id {
        builder = builder.order_id(oid.clone());
    }
    builder.build().ok()
}

fn extract_webhook_money(tx: &TransactionCallbackData) -> Option<Money> {
    let amount = tx.amount_cents.and_then(|v| u64::try_from(v).ok())?;
    let currency = tx.currency.as_deref()?;
    Money::new(amount, currency).ok()
}

fn map_card_token_webhook(
    provider_id: &ProviderId,
    livemode: bool,
    token: CardTokenCallbackData,
) -> NormalizedWebhookEvent {
    let event_id = token
        .id
        .clone()
        .or_else(|| token.order_id.clone())
        .unwrap_or_else(|| "card_token".to_owned());
    let mut builder = ProviderReference::builder(provider_id.clone());
    if let Some(id) = &token.id {
        builder = builder.payment_id(id.clone());
    }
    if let Some(oid) = &token.order_id {
        builder = builder.order_id(oid.clone());
    }
    NormalizedWebhookEvent {
        provider_id: provider_id.clone(),
        event_id,
        event_type: "paymob.card_token".to_owned(),
        livemode,
        requires_hydration: false,
        reference: builder.build().ok(),
        status: Some(PaymentStatus::SetupCompleted),
        money: None,
        verification_challenge: None,
        raw_redacted: token.raw_redacted,
    }
}

fn map_subscription_webhook(
    provider_id: &ProviderId,
    livemode: bool,
    sub: SubscriptionCallbackData,
) -> NormalizedWebhookEvent {
    let reference = ProviderReference::builder(provider_id.clone())
        .payment_id(sub.subscription_id.clone())
        .build()
        .ok();
    NormalizedWebhookEvent {
        provider_id: provider_id.clone(),
        event_id: sub.subscription_id,
        event_type: format!("paymob.subscription.{}", sub.trigger_type),
        livemode,
        requires_hydration: false,
        reference,
        status: None,
        money: None,
        verification_challenge: None,
        raw_redacted: sub.raw_redacted,
    }
}
