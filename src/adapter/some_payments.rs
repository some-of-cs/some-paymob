#![forbid(unsafe_code)]
//! `PaymobClient` implementations of unified gateway traits (`US-8.1.0` Unit 2).
//!
//! Maps `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and
//! `PayoutProvider` onto `PaymobClient` services (`intentions`, `checkout`,
//! `manage`, `saved_cards`, `subscriptions`, and `webhooks`) without floating-point
//! arithmetic or secret leakage.

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
use crate::resources::intentions::{CreateIntentionParams, PaymentMethodInput};
use crate::resources::manage::refund::RefundParams;
use crate::resources::manage::void_capture::{CaptureParams, VoidParams};
use crate::resources::saved_cards::service::MitPayParams;
use crate::webhooks::{IdempotentWebhookGuard, WebhookEvent};

/// Translates a [`UnifiedPaymentSessionRequest`] into Paymob [`CreateIntentionParams`].
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
///     .with_special_reference("ORD-42");
/// let params = build_intention_params(&req)?;
/// assert_eq!(params.special_reference(), Some("ORD-42"));
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

    let mut builder = CreateIntentionParams::builder()
        .amount(req.amount)
        .currency(req.currency)
        .payment_methods(methods);

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
    builder.build()
}

fn parse_payment_method_input(entry: &str) -> PaymentMethodInput {
    match entry.trim().parse::<u64>() {
        Ok(id) => PaymentMethodInput::IntegrationId(id),
        Err(_) => PaymentMethodInput::MethodName(entry.to_owned()),
    }
}

/// Normalizes a verified [`WebhookEvent`] into a [`UnifiedWebhookOutcome`].
#[must_use]
pub fn normalize_webhook_event(event: &WebhookEvent) -> UnifiedWebhookOutcome {
    let kind = match event {
        WebhookEvent::TransactionProcessed(_) => UnifiedWebhookKind::TransactionProcessed,
        WebhookEvent::TransactionResponseRedirect(_) => UnifiedWebhookKind::TransactionRedirect,
        WebhookEvent::CardTokenSaved(_) => UnifiedWebhookKind::CardTokenSaved,
        WebhookEvent::SubscriptionLifecycle(_) => UnifiedWebhookKind::SubscriptionLifecycle,
        WebhookEvent::PayoutDisbursement(_) => UnifiedWebhookKind::PayoutDisbursement,
        WebhookEvent::PayoutTopup(_) => UnifiedWebhookKind::PayoutTopup,
    };
    let (idempotency_key, correlation_id) = event.idempotency_tuple();
    UnifiedWebhookOutcome {
        kind,
        event_type: event.event_type(),
        idempotency_key,
        correlation_id,
    }
}

impl PaymentProvider for PaymobClient {
    type Error = PaymobError;

    async fn create_payment_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
    ) -> Result<UnifiedPaymentSession, Self::Error> {
        let params = build_intention_params(req)?;
        let resp = self.intentions().create(params).await?;
        let checkout_url = self.checkout().unified_url(&resp.client_secret)?.to_string();
        Ok(UnifiedPaymentSession {
            session_id: resp.id,
            order_id: resp.intention_order_id.to_string(),
            client_secret: resp.client_secret,
            checkout_url,
            status: resp.status,
            confirmed: resp.confirmed,
        })
    }

    async fn capture_payment(
        &self,
        req: &UnifiedCaptureRequest,
    ) -> Result<UnifiedCaptureReceipt, Self::Error> {
        let params = CaptureParams::try_new(req.transaction_id, req.amount.as_u64())?;
        let tx = self.manage().capture(params).await?;
        Ok(UnifiedCaptureReceipt {
            transaction_id: tx.id,
            amount: MinorUnitAmount::new(tx.amount_cents),
            success: tx.success,
            pending: tx.pending,
        })
    }

    async fn refund_payment(
        &self,
        req: &UnifiedRefundRequest,
    ) -> Result<UnifiedRefundReceipt, Self::Error> {
        let params = RefundParams::try_new(req.transaction_id, req.amount.as_u64())?;
        let tx = self.manage().refund(params).await?;
        Ok(UnifiedRefundReceipt {
            refund_id: tx.id,
            amount: MinorUnitAmount::new(tx.amount_cents),
            success: tx.success,
            pending: tx.pending,
            is_refunded: tx.is_refunded,
        })
    }

    async fn void_payment(
        &self,
        req: &UnifiedVoidRequest,
    ) -> Result<UnifiedVoidReceipt, Self::Error> {
        let params = VoidParams::try_new(req.transaction_id)?;
        let tx = self.manage().void(params).await?;
        Ok(UnifiedVoidReceipt {
            transaction_id: tx.id,
            success: tx.success,
            is_voided: tx.is_voided,
        })
    }

    async fn charge_saved_method(
        &self,
        req: &UnifiedSavedMethodChargeRequest,
    ) -> Result<UnifiedSavedMethodChargeReceipt, Self::Error> {
        let mut params =
            MitPayParams::new(req.payment_token.clone(), req.saved_method_token.clone())?;
        if let Some(cvn) = &req.cvn {
            params = params.with_cvn(cvn.clone())?;
        }
        let resp = self.saved_cards().pay_with_token_mit(&params).await?;
        Ok(UnifiedSavedMethodChargeReceipt {
            transaction_id: resp.transaction.id,
            amount: MinorUnitAmount::new(resp.transaction.amount_cents),
            success: resp.transaction.success,
            pending: resp.transaction.pending,
            redirect_url: resp.redirect_url,
            kiosk_bill_reference: resp.kiosk_bill_reference,
        })
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

    async fn refund_last_transaction(
        &self,
        req: &UnifiedSubscriptionRefundRequest,
    ) -> Result<UnifiedSubscriptionRefundReceipt, Self::Error> {
        let amount_cents = req.amount.map(MinorUnitAmount::as_u64);
        let resp = self
            .subscriptions()
            .refund_last_transaction(req.subscription_id, amount_cents)
            .await?;
        Ok(UnifiedSubscriptionRefundReceipt {
            refund_id: resp.id,
            amount: MinorUnitAmount::new(resp.amount_cents),
            success: resp.success,
            pending: resp.pending,
            parent_transaction_id: resp.parent_transaction,
        })
    }
}

impl PayoutProvider for PaymobClient {
    type Error = PaymobError;

    async fn execute_payout(
        &self,
        req: &UnifiedPayoutRequest,
    ) -> Result<UnifiedPayoutReceipt, Self::Error> {
        req.validate()?;
        let _endpoint = self.payouts_url("/disburse/")?;
        Err(PaymobError::ValidationError {
            field: "payouts",
            reason: "outbound payouts execution requires the payouts resource module".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::region::PaymobRegion;
    use crate::core::types::Currency;

    #[test]
    fn build_intention_params_maps_numeric_and_named_methods() {
        let req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(15_000), Currency::EGP)
            .with_payment_methods(vec!["4097558".to_owned(), "card".to_owned()])
            .with_special_reference("ORD-810")
            .with_pre_selected_plan(24);
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
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("config");
        let client = PaymobClient::new(config).expect("client");
        let res = client.verify_webhook(&UnifiedWebhookInput::new("{}", None));
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn execute_payout_validates_empty_recipient() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("config");
        let client = PaymobClient::new(config).expect("client");
        let req = UnifiedPayoutRequest::new("", MinorUnitAmount::new(1000), Currency::EGP, "vodafone");
        assert!(matches!(
            client.execute_payout(&req).await,
            Err(PaymobError::ValidationError {
                field: "recipient_identifier",
                ..
            })
        ));
    }
}
