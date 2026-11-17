#![forbid(unsafe_code)]
//! `PaymobClient` implementations of unified gateway traits (`US-8.1.0` Unit 2).
//!
//! Maps `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and
//! `PayoutProvider` onto `PaymobClient` services (`intentions`, `checkout`,
//! `manage`, `saved_cards`, `subscriptions`, `payouts`, and `webhooks`) without
//! floating-point arithmetic, redundant helpers, or secret leakage.

use std::future::Future;

use crate::adapter::traits::{
    PaymentProvider, PayoutProvider, SubscriptionProvider, UnifiedCaptureReceipt,
    UnifiedCaptureRequest, UnifiedPaymentSession, UnifiedPaymentSessionRequest,
    UnifiedPayoutReceipt, UnifiedPayoutRequest, UnifiedRefundReceipt, UnifiedRefundRequest,
    UnifiedSavedMethodChargeReceipt, UnifiedSavedMethodChargeRequest,
    UnifiedSubscriptionRefundReceipt, UnifiedSubscriptionRefundRequest, UnifiedVoidReceipt,
    UnifiedVoidRequest, UnifiedWebhookInput, UnifiedWebhookKind, UnifiedWebhookOutcome,
    WebhookVerifier,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::types::MinorUnitAmount;
use crate::resources::intentions::{
    BillingData, CreateIntentionParams, CreateIntentionParamsBuilder, IntentionCustomer,
    PaymentMethodInput,
};
use crate::resources::manage::models::Transaction;
use crate::resources::manage::refund::RefundParams;
use crate::resources::manage::void_capture::{CaptureParams, VoidParams};
use crate::resources::payouts::{DisburseIssuer, DisbursementResponse, MobileWalletCashinParams};
use crate::resources::saved_cards::service::MitPayParams;
use crate::webhooks::{IdempotentWebhookGuard, WebhookEvent};

/// Translates a [`UnifiedPaymentSessionRequest`] into Paymob [`CreateIntentionParams`].
///
/// Wires `amount`, `currency`, `payment_methods`, `special_reference`, `notification_url`,
/// `redirection_url`, `pre_selected_plan`, `extras`, and customer contact/name fields
/// (`billing_data` and `customer`) directly into [`CreateIntentionParamsBuilder`].
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] if `req` fails unified validation or
/// Paymob intention builder invariants.
///
/// # Examples
///
/// ```rust
/// use some_paymob::adapter::some_payments::build_intention_params;
/// use some_paymob::adapter::traits::UnifiedPaymentSessionRequest;
/// use some_paymob::core::types::{Currency, MinorUnitAmount};
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(10_000), Currency::EGP)
///     .with_payment_methods(vec!["4097558".to_owned()])
///     .with_special_reference("ORD-42")
///     .with_customer_contact("user@example.com", "+201001234567")
///     .with_customer_name("Oscar", "Arena");
/// let params = build_intention_params(&req)?;
/// assert_eq!(params.special_reference(), Some("ORD-42"));
/// assert!(params.billing_data().is_some());
/// assert!(params.customer().is_some());
/// # Ok(())
/// # }
/// ```
pub fn build_intention_params(
    req: &UnifiedPaymentSessionRequest,
) -> Result<CreateIntentionParams, PaymobError> {
    req.validate()?;
    let methods: Vec<PaymentMethodInput> = req
        .payment_methods
        .iter()
        .map(|entry| parse_payment_method_input(entry))
        .collect();

    let builder = CreateIntentionParams::builder()
        .amount(req.amount)
        .currency(req.currency.clone())
        .payment_methods(methods);
    let builder = apply_optional_intention_fields(builder, req);
    let builder = apply_contact_intention_fields(builder, req)?;
    builder.build()
}

fn apply_optional_intention_fields(
    mut builder: CreateIntentionParamsBuilder,
    req: &UnifiedPaymentSessionRequest,
) -> CreateIntentionParamsBuilder {
    if let Some(reference) = &req.special_reference {
        builder = builder.special_reference(reference.as_str());
    }
    if let Some(url) = &req.notification_url {
        builder = builder.notification_url(url.as_str());
    }
    if let Some(url) = &req.redirection_url {
        builder = builder.redirection_url(url.as_str());
    }
    if let Some(plan) = req.pre_selected_plan {
        builder = builder.pre_selected_plan(plan);
    }
    if let Some(extras) = &req.extras {
        builder = builder.extras(extras.clone());
    }
    builder
}

fn apply_contact_intention_fields(
    mut builder: CreateIntentionParamsBuilder,
    req: &UnifiedPaymentSessionRequest,
) -> Result<CreateIntentionParamsBuilder, PaymobError> {
    if let Some(billing) = build_billing_from_request(req)? {
        builder = builder.billing_data(billing);
    }
    if let Some(customer) = build_customer_from_request(req) {
        builder = builder.customer(customer);
    }
    Ok(builder)
}

fn build_billing_from_request(
    req: &UnifiedPaymentSessionRequest,
) -> Result<Option<BillingData>, PaymobError> {
    let Some(phone) = &req.customer_phone else {
        return Ok(None);
    };
    let mut billing = BillingData::builder().phone_number(phone.as_str());
    if let Some(first) = &req.customer_first_name {
        billing = billing.first_name(first.as_str());
    }
    if let Some(last) = &req.customer_last_name {
        billing = billing.last_name(last.as_str());
    }
    if let Some(email) = &req.customer_email {
        billing = billing.email(email.as_str());
    }
    billing.build().map(Some)
}

fn has_customer_identity(req: &UnifiedPaymentSessionRequest) -> bool {
    req.customer_first_name.is_some()
        || req.customer_last_name.is_some()
        || req.customer_email.is_some()
}

fn build_customer_from_request(req: &UnifiedPaymentSessionRequest) -> Option<IntentionCustomer> {
    if !has_customer_identity(req) {
        return None;
    }
    let mut customer = IntentionCustomer::new();
    if let Some(first) = &req.customer_first_name {
        customer = customer.with_first_name(first.as_str());
    }
    if let Some(last) = &req.customer_last_name {
        customer = customer.with_last_name(last.as_str());
    }
    if let Some(email) = &req.customer_email {
        customer = customer.with_email(email.as_str());
    }
    Some(customer)
}

fn parse_payment_method_input(entry: &str) -> PaymentMethodInput {
    match entry.trim().parse::<u64>() {
        Ok(id) => PaymentMethodInput::IntegrationId(id),
        Err(_) => PaymentMethodInput::MethodName(entry.to_owned()),
    }
}

fn build_mit_params(req: &UnifiedSavedMethodChargeRequest) -> Result<MitPayParams, PaymobError> {
    let mut params = MitPayParams::new(req.payment_token.clone(), req.saved_method_token.clone())?;
    if let Some(cvn) = &req.cvn {
        params = params.with_cvn(cvn.clone())?;
    }
    Ok(params)
}

fn classify_core_webhook_kind(event: &WebhookEvent) -> Option<UnifiedWebhookKind> {
    match event {
        WebhookEvent::TransactionProcessed(_) => Some(UnifiedWebhookKind::TransactionProcessed),
        WebhookEvent::TransactionResponseRedirect(_) => {
            Some(UnifiedWebhookKind::TransactionRedirect)
        }
        WebhookEvent::CardTokenSaved(_) => Some(UnifiedWebhookKind::CardTokenSaved),
        _ => None,
    }
}

fn classify_extended_webhook_kind(event: &WebhookEvent) -> UnifiedWebhookKind {
    match event {
        WebhookEvent::SubscriptionLifecycle(_) => UnifiedWebhookKind::SubscriptionLifecycle,
        WebhookEvent::PayoutDisbursement(_) => UnifiedWebhookKind::PayoutDisbursement,
        _ => UnifiedWebhookKind::PayoutTopup,
    }
}

fn classify_webhook_kind(event: &WebhookEvent) -> UnifiedWebhookKind {
    classify_core_webhook_kind(event).unwrap_or_else(|| classify_extended_webhook_kind(event))
}

/// Normalizes a verified [`WebhookEvent`] into a [`UnifiedWebhookOutcome`].
#[must_use]
pub fn normalize_webhook_event(event: &WebhookEvent) -> UnifiedWebhookOutcome {
    let (idempotency_key, correlation_id) = event.idempotency_tuple();
    UnifiedWebhookOutcome {
        kind: classify_webhook_kind(event),
        event_type: event.event_type(),
        idempotency_key,
        correlation_id,
    }
}

enum ManageOp {
    Capture(CaptureParams),
    Refund(RefundParams),
    Void(VoidParams),
}

async fn run_client_call<P, R, F, Fut>(
    client: PaymobClient,
    params_res: Result<P, PaymobError>,
    op: F,
) -> Result<R, PaymobError>
where
    F: FnOnce(PaymobClient, P) -> Fut,
    Fut: Future<Output = Result<R, PaymobError>>,
{
    let params = params_res?;
    op(client, params).await
}

async fn execute_manage_op(client: PaymobClient, op: ManageOp) -> Result<Transaction, PaymobError> {
    match op {
        ManageOp::Capture(params) => client.manage().capture(params).await,
        ManageOp::Refund(params) => client.manage().refund(params).await,
        ManageOp::Void(params) => client.manage().void(params).await,
    }
}

async fn run_manage_call<R>(
    client: PaymobClient,
    op_res: Result<ManageOp, PaymobError>,
    map_receipt: fn(Transaction) -> R,
) -> Result<R, PaymobError> {
    let tx = run_client_call(client, op_res, execute_manage_op).await?;
    Ok(map_receipt(tx))
}

fn to_capture_receipt(tx: Transaction) -> UnifiedCaptureReceipt {
    UnifiedCaptureReceipt {
        transaction_id: tx.id,
        amount: MinorUnitAmount::new(tx.amount_cents),
        success: tx.success,
        pending: tx.pending,
    }
}

fn to_refund_receipt(tx: Transaction) -> UnifiedRefundReceipt {
    UnifiedRefundReceipt {
        refund_id: tx.id,
        amount: MinorUnitAmount::new(tx.amount_cents),
        success: tx.success,
        pending: tx.pending,
        is_refunded: tx.is_refunded,
    }
}

fn to_void_receipt(tx: Transaction) -> UnifiedVoidReceipt {
    UnifiedVoidReceipt {
        transaction_id: tx.id,
        success: tx.success,
        is_voided: tx.is_voided,
    }
}

fn validate_subscription_refund_req(
    req: &UnifiedSubscriptionRefundRequest,
) -> Result<(u64, Option<u64>), PaymobError> {
    if req.subscription_id == 0 {
        return Err(PaymobError::ValidationError {
            field: "subscription_id",
            reason: "subscription_id must be greater than zero".to_owned(),
        });
    }
    if req.amount.is_some_and(MinorUnitAmount::is_zero) {
        return Err(PaymobError::ValidationError {
            field: "amount",
            reason: "subscription refund amount must be greater than zero".to_owned(),
        });
    }
    Ok((req.subscription_id, req.amount.map(MinorUnitAmount::as_u64)))
}

fn build_wallet_cashin_params(
    req: &UnifiedPayoutRequest,
) -> Result<(DisburseIssuer, MobileWalletCashinParams), PaymobError> {
    req.validate()?;
    let issuer =
        DisburseIssuer::from_wire(&req.issuer).ok_or_else(|| PaymobError::ValidationError {
            field: "issuer",
            reason: "unsupported payout issuer; expected wallet issuer".to_owned(),
        })?;
    let mut params =
        MobileWalletCashinParams::new(req.recipient_identifier.clone(), req.amount.as_u64());
    if let Some(reference) = &req.reference {
        params = params.with_client_reference_id(reference.clone());
    }
    Ok((issuer, params))
}

async fn dispatch_unified_wallet_payout(
    client: PaymobClient,
    (issuer, params): (DisburseIssuer, MobileWalletCashinParams),
) -> Result<UnifiedPayoutReceipt, PaymobError> {
    let fallback_amount = params.amount;
    let cashin = client.payouts().cashin();
    let resp = match issuer {
        DisburseIssuer::Vodafone => cashin.vodafone(params).await?,
        DisburseIssuer::Etisalat => cashin.etisalat(params).await?,
        DisburseIssuer::Orange => cashin.orange(params).await?,
        DisburseIssuer::BankWallet => cashin.bank_wallet(params).await?,
        _ => {
            return Err(PaymobError::ValidationError {
                field: "issuer",
                reason: "bank/post payout issuer requires client.payouts().cashin()".to_owned(),
            });
        }
    };
    Ok(to_payout_receipt(resp, issuer, fallback_amount))
}

fn to_payout_receipt(
    resp: DisbursementResponse,
    fallback_issuer: DisburseIssuer,
    fallback_amount: u64,
) -> UnifiedPayoutReceipt {
    UnifiedPayoutReceipt {
        payout_id: resp.transaction_id,
        amount: MinorUnitAmount::new(resp.amount.unwrap_or(fallback_amount)),
        status: resp
            .disbursement_status
            .unwrap_or_else(|| "submitted".to_owned()),
        issuer: resp.issuer.unwrap_or(fallback_issuer).as_str().to_owned(),
    }
}

impl PaymentProvider for PaymobClient {
    type Error = PaymobError;

    fn create_payment_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
    ) -> impl Future<Output = Result<UnifiedPaymentSession, Self::Error>> + Send + '_ {
        run_client_call(
            self.clone(),
            build_intention_params(req),
            |client, params| async move {
                let resp = client.intentions().create(params).await?;
                let checkout_url = client
                    .checkout()
                    .unified_url(&resp.client_secret)?
                    .to_string();
                Ok(UnifiedPaymentSession {
                    session_id: resp.id,
                    order_id: resp.intention_order_id.to_string(),
                    client_secret: resp.client_secret,
                    checkout_url,
                    status: resp.status,
                    confirmed: resp.confirmed,
                })
            },
        )
    }

    fn capture_payment(
        &self,
        req: &UnifiedCaptureRequest,
    ) -> impl Future<Output = Result<UnifiedCaptureReceipt, Self::Error>> + Send + '_ {
        let op =
            CaptureParams::try_new(req.transaction_id, req.amount.as_u64()).map(ManageOp::Capture);
        run_manage_call(self.clone(), op, to_capture_receipt)
    }

    fn refund_payment(
        &self,
        req: &UnifiedRefundRequest,
    ) -> impl Future<Output = Result<UnifiedRefundReceipt, Self::Error>> + Send + '_ {
        let op =
            RefundParams::try_new(req.transaction_id, req.amount.as_u64()).map(ManageOp::Refund);
        run_manage_call(self.clone(), op, to_refund_receipt)
    }

    fn void_payment(
        &self,
        req: &UnifiedVoidRequest,
    ) -> impl Future<Output = Result<UnifiedVoidReceipt, Self::Error>> + Send + '_ {
        let op = VoidParams::try_new(req.transaction_id).map(ManageOp::Void);
        run_manage_call(self.clone(), op, to_void_receipt)
    }

    fn charge_saved_method(
        &self,
        req: &UnifiedSavedMethodChargeRequest,
    ) -> impl Future<Output = Result<UnifiedSavedMethodChargeReceipt, Self::Error>> + Send + '_
    {
        run_client_call(
            self.clone(),
            build_mit_params(req),
            |client, params| async move {
                let resp = client.saved_cards().pay_with_token_mit(&params).await?;
                Ok(UnifiedSavedMethodChargeReceipt {
                    transaction_id: resp.transaction.id,
                    amount: MinorUnitAmount::new(resp.transaction.amount_cents),
                    success: resp.transaction.success,
                    pending: resp.transaction.pending,
                    redirect_url: resp.redirect_url,
                    kiosk_bill_reference: resp.kiosk_bill_reference,
                })
            },
        )
    }
}

impl WebhookVerifier for PaymobClient {
    type Error = PaymobError;

    fn verify_webhook(
        &self,
        input: &UnifiedWebhookInput<'_>,
    ) -> Result<UnifiedWebhookOutcome, Self::Error> {
        let engine = self.webhooks()?;
        let event = engine
            .construct_event(input.raw_body, input.signature_hmac)
            .map_err(|err| PaymobError::WebhookError(err.to_string()))?;
        Ok(normalize_webhook_event(&event))
    }
}

impl SubscriptionProvider for PaymobClient {
    type Error = PaymobError;

    fn refund_last_transaction(
        &self,
        req: &UnifiedSubscriptionRefundRequest,
    ) -> impl Future<Output = Result<UnifiedSubscriptionRefundReceipt, Self::Error>> + Send + '_
    {
        run_client_call(
            self.clone(),
            validate_subscription_refund_req(req),
            |client, (sub_id, amount_cents)| async move {
                let resp = client
                    .subscriptions()
                    .refund_last_transaction(sub_id, amount_cents)
                    .await?;
                Ok(UnifiedSubscriptionRefundReceipt {
                    refund_id: resp.id,
                    amount: MinorUnitAmount::new(resp.amount_cents),
                    success: resp.success,
                    pending: resp.pending,
                    parent_transaction_id: resp.parent_transaction,
                })
            },
        )
    }
}

impl PayoutProvider for PaymobClient {
    type Error = PaymobError;

    fn execute_payout(
        &self,
        req: &UnifiedPayoutRequest,
    ) -> impl Future<Output = Result<UnifiedPayoutReceipt, Self::Error>> + Send + '_ {
        run_client_call(
            self.clone(),
            build_wallet_cashin_params(req),
            dispatch_unified_wallet_payout,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::region::PaymobRegion;
    use crate::core::types::Currency;

    fn test_egypt_client() -> PaymobClient {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("config");
        PaymobClient::new(config).expect("client")
    }

    #[test]
    fn build_intention_params_maps_numeric_named_methods_and_customer() {
        let req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(15_000), Currency::EGP)
            .with_payment_methods(vec!["4097558".to_owned(), "card".to_owned()])
            .with_special_reference("ORD-810")
            .with_pre_selected_plan(24)
            .with_customer_contact("user@example.com", "+201001234567")
            .with_customer_name("Oscar", "Arena");
        let params = build_intention_params(&req).expect("valid params");
        assert_eq!(params.special_reference(), Some("ORD-810"));
        assert_eq!(params.pre_selected_plan(), Some(24));
        assert_eq!(
            params.payment_methods(),
            &[
                PaymentMethodInput::IntegrationId(4_097_558),
                PaymentMethodInput::MethodName("card".to_owned()),
            ]
        );
        assert_eq!(
            params.billing_data().map(BillingData::phone_number),
            Some("+201001234567")
        );
        assert_eq!(
            params.customer().and_then(IntentionCustomer::first_name),
            Some("Oscar")
        );
    }

    #[test]
    fn build_intention_params_rejects_zero_amount() {
        let req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(0), Currency::EGP)
            .with_payment_methods(vec!["4097558".to_owned()]);
        assert!(matches!(
            build_intention_params(&req),
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));
    }

    #[test]
    fn verify_webhook_rejects_missing_hmac_secret() {
        let client = test_egypt_client();
        let res = client.verify_webhook(&UnifiedWebhookInput::new("{}", None));
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn execute_payout_validates_empty_recipient_and_unsupported_issuer() {
        let client = test_egypt_client();
        let req =
            UnifiedPayoutRequest::new("", MinorUnitAmount::new(1000), Currency::EGP, "vodafone");
        assert!(matches!(
            client.execute_payout(&req).await,
            Err(PaymobError::ValidationError {
                field: "recipient_identifier",
                ..
            })
        ));

        let bad_issuer = UnifiedPayoutRequest::new(
            "01012345678",
            MinorUnitAmount::new(1000),
            Currency::EGP,
            "unknown_wallet",
        );
        assert!(matches!(
            client.execute_payout(&bad_issuer).await,
            Err(PaymobError::ValidationError {
                field: "issuer",
                ..
            })
        ));

        let bank_issuer = UnifiedPayoutRequest::new(
            "4111111111111234",
            MinorUnitAmount::new(1000),
            Currency::EGP,
            "bank_card",
        );
        assert!(matches!(
            client.execute_payout(&bank_issuer).await,
            Err(PaymobError::ValidationError {
                field: "issuer",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn subscription_refund_validates_zero_id_and_zero_amount() {
        let client = test_egypt_client();
        let zero_id = UnifiedSubscriptionRefundRequest::new(0, None);
        assert!(matches!(
            client.refund_last_transaction(&zero_id).await,
            Err(PaymobError::ValidationError {
                field: "subscription_id",
                ..
            })
        ));

        let zero_amt = UnifiedSubscriptionRefundRequest::new(10, Some(MinorUnitAmount::ZERO));
        assert!(matches!(
            client.refund_last_transaction(&zero_amt).await,
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));
    }
}
