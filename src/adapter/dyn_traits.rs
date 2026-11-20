#![forbid(unsafe_code)]
//! Object-safe (`dyn`-compatible) capability traits and smart reversal helpers for `some-payment`
//! (`US-9.2.0` Unit 1).
//!
//! Provides dynamic-dispatch equivalents of `PaymentProvider`, `WebhookVerifier`,
//! `SubscriptionProvider`, and `PayoutProvider`, plus `DynSplitSettlementCapability`
//! and `UnifiedReversalReceipt` so downstream orchestrators such as `some-payment`'s
//! `PaymentHub` can store heterogeneous gateway adapters behind `Arc<dyn Dyn*>`.
//!
//! # Examples
//!
//! ```rust
//! use std::sync::Arc;
//!
//! use some_paymob::adapter::dyn_traits::{
//!     DynPaymentCapability, DynPayoutCapability, DynSplitSettlementCapability,
//!     DynSubscriptionCapability, DynWebhookCapability, UnifiedReversalReceipt,
//! };
//! use some_paymob::adapter::traits::UnifiedVoidReceipt;
//! use some_paymob::{ClientConfig, PaymobClient, PaymobRegion};
//!
//! # fn main() -> Result<(), some_paymob::PaymobError> {
//! let config = ClientConfig::builder()
//!     .region(PaymobRegion::Egypt)
//!     .build()?;
//! let client = Arc::new(PaymobClient::new(config)?);
//!
//! let _payment: Arc<dyn DynPaymentCapability> = Arc::<PaymobClient>::clone(&client);
//! let _webhook: Arc<dyn DynWebhookCapability> = Arc::<PaymobClient>::clone(&client);
//! let _subs: Arc<dyn DynSubscriptionCapability> = Arc::<PaymobClient>::clone(&client);
//! let _payout: Arc<dyn DynPayoutCapability> = Arc::<PaymobClient>::clone(&client);
//! let _splits: Arc<dyn DynSplitSettlementCapability> = client;
//!
//! let receipt = UnifiedReversalReceipt::Voided(UnifiedVoidReceipt {
//!     transaction_id: 42,
//!     success: true,
//!     is_voided: true,
//! });
//! assert!(receipt.is_voided());
//! assert_eq!(receipt.transaction_id(), 42);
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};

use crate::adapter::ext::PaymobExt;
use crate::adapter::traits::{
    PaymentProvider, PayoutProvider, SubscriptionProvider, UnifiedCaptureReceipt,
    UnifiedCaptureRequest, UnifiedPaymentSession, UnifiedPaymentSessionRequest,
    UnifiedPayoutReceipt, UnifiedPayoutRequest, UnifiedRefundReceipt, UnifiedRefundRequest,
    UnifiedSavedMethodChargeReceipt, UnifiedSavedMethodChargeRequest,
    UnifiedSubscriptionRefundReceipt, UnifiedSubscriptionRefundRequest, UnifiedVoidReceipt,
    UnifiedVoidRequest, UnifiedWebhookInput, UnifiedWebhookOutcome, WebhookVerifier,
};
use crate::core::client::PaymobClient;
use crate::core::error::PaymobError;
use crate::core::types::MinorUnitAmount;

/// Boxed, pinned, `Send` future type alias used by object-safe (`dyn`-compatible) traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Unified reversal outcome returned by [`DynPaymentCapability::refund_or_void`].
///
/// Represents either a pre-settlement [`UnifiedVoidReceipt`] or a post-settlement
/// [`UnifiedRefundReceipt`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::MinorUnitAmount;
/// use some_paymob::adapter::dyn_traits::UnifiedReversalReceipt;
/// use some_paymob::adapter::traits::UnifiedRefundReceipt;
///
/// let receipt = UnifiedReversalReceipt::Refunded(UnifiedRefundReceipt {
///     refund_id: 9001,
///     amount: MinorUnitAmount::new(5_000),
///     success: true,
///     pending: false,
///     is_refunded: true,
/// });
/// assert!(receipt.is_refunded());
/// assert_eq!(receipt.transaction_id(), 9001);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnifiedReversalReceipt {
    /// Unsettled authorization was voided prior to settlement.
    Voided(UnifiedVoidReceipt),
    /// Settled transaction was refunded.
    Refunded(UnifiedRefundReceipt),
}

impl UnifiedReversalReceipt {
    /// Returns `true` if the reversal executed as a pre-settlement void.
    #[must_use]
    pub const fn is_voided(&self) -> bool {
        matches!(self, Self::Voided(_))
    }

    /// Returns `true` if the reversal executed as a post-settlement refund.
    #[must_use]
    pub const fn is_refunded(&self) -> bool {
        matches!(self, Self::Refunded(_))
    }

    /// Returns the gateway transaction or refund identifier associated with this receipt.
    #[must_use]
    pub const fn transaction_id(&self) -> u64 {
        match self {
            Self::Voided(receipt) => receipt.transaction_id,
            Self::Refunded(receipt) => receipt.refund_id,
        }
    }
}

/// Object-safe (`dyn`-compatible) cross-gateway payment lifecycle capability.
///
/// Designed for dynamic dispatch inside `Arc<dyn DynPaymentCapability>` registries
/// such as `some-payment`'s `PaymentHub`.
pub trait DynPaymentCapability: Send + Sync {
    /// Creates a payment session and returns its checkout URL and client secret.
    fn create_payment_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
    ) -> BoxFuture<'_, Result<UnifiedPaymentSession, PaymobError>>;

    /// Captures an authorized payment transaction.
    fn capture_payment(
        &self,
        req: &UnifiedCaptureRequest,
    ) -> BoxFuture<'_, Result<UnifiedCaptureReceipt, PaymobError>>;

    /// Refunds a settled payment transaction.
    fn refund_payment(
        &self,
        req: &UnifiedRefundRequest,
    ) -> BoxFuture<'_, Result<UnifiedRefundReceipt, PaymobError>>;

    /// Voids an unsettled authorization transaction.
    fn void_payment(
        &self,
        req: &UnifiedVoidRequest,
    ) -> BoxFuture<'_, Result<UnifiedVoidReceipt, PaymobError>>;

    /// Smart reversal that voids unsettled authorizations and refunds settled charges.
    ///
    /// Routes to [`Self::void_payment`] when `is_settled` is `false` and to
    /// [`Self::refund_payment`] when `is_settled` is `true`.
    fn refund_or_void(
        &self,
        transaction_id: u64,
        amount: MinorUnitAmount,
        is_settled: bool,
    ) -> BoxFuture<'_, Result<UnifiedReversalReceipt, PaymobError>> {
        if is_settled {
            let req = UnifiedRefundRequest::new(transaction_id, amount);
            let fut = self.refund_payment(&req);
            Box::pin(async move { fut.await.map(UnifiedReversalReceipt::Refunded) })
        } else {
            let req = UnifiedVoidRequest::new(transaction_id);
            let fut = self.void_payment(&req);
            Box::pin(async move { fut.await.map(UnifiedReversalReceipt::Voided) })
        }
    }

    /// Charges a previously saved payment method (Merchant-Initiated Transaction).
    fn charge_saved_method(
        &self,
        req: &UnifiedSavedMethodChargeRequest,
    ) -> BoxFuture<'_, Result<UnifiedSavedMethodChargeReceipt, PaymobError>>;
}

/// Object-safe (`dyn`-compatible) cryptographic webhook verification capability.
pub trait DynWebhookCapability: Send + Sync {
    /// Verifies the webhook signature in constant time and normalizes the outcome.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError`] if the webhook engine is not configured or the signature
    /// fails constant-time verification.
    fn verify_webhook(
        &self,
        input: &UnifiedWebhookInput<'_>,
    ) -> Result<UnifiedWebhookOutcome, PaymobError>;
}

/// Object-safe (`dyn`-compatible) subscription lifecycle capability.
pub trait DynSubscriptionCapability: Send + Sync {
    /// Refunds the latest deduction transaction of a subscription.
    fn refund_last_transaction(
        &self,
        req: &UnifiedSubscriptionRefundRequest,
    ) -> BoxFuture<'_, Result<UnifiedSubscriptionRefundReceipt, PaymobError>>;
}

/// Object-safe (`dyn`-compatible) outbound payout disbursement capability.
pub trait DynPayoutCapability: Send + Sync {
    /// Executes an outbound payout disbursement to a recipient wallet or bank account.
    fn execute_payout(
        &self,
        req: &UnifiedPayoutRequest,
    ) -> BoxFuture<'_, Result<UnifiedPayoutReceipt, PaymobError>>;
}

/// Object-safe (`dyn`-compatible) split-settlement session creation capability.
pub trait DynSplitSettlementCapability: Send + Sync {
    /// Applies [`PaymobExt`] split/extension options to `req` and creates a payment session.
    fn apply_splits_and_create_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
        ext: &PaymobExt,
    ) -> BoxFuture<'_, Result<UnifiedPaymentSession, PaymobError>>;
}

/// Clones `client` and boxes an async provider call into a [`BoxFuture`].
fn box_call<Req, Resp, F, Fut>(
    client: &PaymobClient,
    req: Req,
    op: F,
) -> BoxFuture<'_, Result<Resp, PaymobError>>
where
    Req: Send + 'static,
    Resp: Send + 'static,
    F: FnOnce(PaymobClient, Req) -> Fut + Send + 'static,
    Fut: Future<Output = Result<Resp, PaymobError>> + Send + 'static,
{
    let client = client.clone();
    Box::pin(async move { op(client, req).await })
}

macro_rules! delegate_box_call {
    (
        $(
            $mode:ident $method:ident($req:ty) -> $resp:ty => $provider:ident::$op:ident;
        )+
    ) => {
        $(
            fn $method(&self, req: &$req) -> BoxFuture<'_, Result<$resp, PaymobError>> {
                let owned = delegate_box_call!(@own $mode, req);
                box_call(self, owned, |client, req| async move {
                    $provider::$op(&client, &req).await
                })
            }
        )+
    };
    (@own copy, $req:expr) => {
        *$req
    };
    (@own clone, $req:expr) => {
        $req.clone()
    };
}

impl DynPaymentCapability for PaymobClient {
    delegate_box_call! {
        clone create_payment_session(UnifiedPaymentSessionRequest)
            -> UnifiedPaymentSession => PaymentProvider::create_payment_session;
        copy capture_payment(UnifiedCaptureRequest)
            -> UnifiedCaptureReceipt => PaymentProvider::capture_payment;
        copy refund_payment(UnifiedRefundRequest)
            -> UnifiedRefundReceipt => PaymentProvider::refund_payment;
        copy void_payment(UnifiedVoidRequest)
            -> UnifiedVoidReceipt => PaymentProvider::void_payment;
        clone charge_saved_method(UnifiedSavedMethodChargeRequest)
            -> UnifiedSavedMethodChargeReceipt => PaymentProvider::charge_saved_method;
    }
}

impl DynWebhookCapability for PaymobClient {
    fn verify_webhook(
        &self,
        input: &UnifiedWebhookInput<'_>,
    ) -> Result<UnifiedWebhookOutcome, PaymobError> {
        WebhookVerifier::verify_webhook(self, input)
    }
}

impl DynSubscriptionCapability for PaymobClient {
    delegate_box_call! {
        copy refund_last_transaction(UnifiedSubscriptionRefundRequest)
            -> UnifiedSubscriptionRefundReceipt => SubscriptionProvider::refund_last_transaction;
    }
}

impl DynPayoutCapability for PaymobClient {
    delegate_box_call! {
        clone execute_payout(UnifiedPayoutRequest)
            -> UnifiedPayoutReceipt => PayoutProvider::execute_payout;
    }
}

impl DynSplitSettlementCapability for PaymobClient {
    fn apply_splits_and_create_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
        ext: &PaymobExt,
    ) -> BoxFuture<'_, Result<UnifiedPaymentSession, PaymobError>> {
        let wired = ext.apply_to_session_request(req.clone());
        box_call(self, wired, |client, wired| async move {
            let session_req = wired?;
            PaymentProvider::create_payment_session(&client, &session_req).await
        })
    }
}

const fn _assert_object_safe<T: ?Sized + Send + Sync>() {}

#[allow(dead_code)]
const fn _assert_dyn_safe() {
    _assert_object_safe::<dyn DynPaymentCapability>();
    _assert_object_safe::<dyn DynWebhookCapability>();
    _assert_object_safe::<dyn DynSubscriptionCapability>();
    _assert_object_safe::<dyn DynPayoutCapability>();
    _assert_object_safe::<dyn DynSplitSettlementCapability>();
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::region::PaymobRegion;
    use crate::core::types::Currency;

    fn ready_ok<'a, T: Send + 'a>(value: T) -> BoxFuture<'a, Result<T, PaymobError>> {
        Box::pin(async move { Ok(value) })
    }

    fn mock_err<'a, T: Send + 'a>(field: &'static str) -> BoxFuture<'a, Result<T, PaymobError>> {
        Box::pin(async move {
            Err(PaymobError::ValidationError {
                field,
                reason: "not used in mock".to_owned(),
            })
        })
    }

    fn assert_validation_err<T>(result: Result<T, PaymobError>, expected_field: &str) {
        assert!(matches!(
            result,
            Err(PaymobError::ValidationError { field, .. }) if field == expected_field
        ));
    }

    struct MockPaymentCapability;

    impl DynPaymentCapability for MockPaymentCapability {
        fn create_payment_session(
            &self,
            _req: &UnifiedPaymentSessionRequest,
        ) -> BoxFuture<'_, Result<UnifiedPaymentSession, PaymobError>> {
            mock_err("session")
        }

        fn capture_payment(
            &self,
            req: &UnifiedCaptureRequest,
        ) -> BoxFuture<'_, Result<UnifiedCaptureReceipt, PaymobError>> {
            ready_ok(UnifiedCaptureReceipt {
                transaction_id: req.transaction_id,
                amount: req.amount,
                success: true,
                pending: false,
            })
        }

        fn refund_payment(
            &self,
            req: &UnifiedRefundRequest,
        ) -> BoxFuture<'_, Result<UnifiedRefundReceipt, PaymobError>> {
            ready_ok(UnifiedRefundReceipt {
                refund_id: req.transaction_id,
                amount: req.amount,
                success: true,
                pending: false,
                is_refunded: true,
            })
        }

        fn void_payment(
            &self,
            req: &UnifiedVoidRequest,
        ) -> BoxFuture<'_, Result<UnifiedVoidReceipt, PaymobError>> {
            ready_ok(UnifiedVoidReceipt {
                transaction_id: req.transaction_id,
                success: true,
                is_voided: true,
            })
        }

        fn charge_saved_method(
            &self,
            _req: &UnifiedSavedMethodChargeRequest,
        ) -> BoxFuture<'_, Result<UnifiedSavedMethodChargeReceipt, PaymobError>> {
            mock_err("saved_method")
        }
    }

    fn test_egypt_client() -> PaymobClient {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .build()
            .expect("config");
        PaymobClient::new(config).expect("client")
    }

    #[test]
    fn paymob_client_coerces_to_all_dyn_trait_objects() {
        let client = Arc::new(test_egypt_client());
        let _payment: Arc<dyn DynPaymentCapability> = Arc::<PaymobClient>::clone(&client);
        let _webhook: Arc<dyn DynWebhookCapability> = Arc::<PaymobClient>::clone(&client);
        let _subs: Arc<dyn DynSubscriptionCapability> = Arc::<PaymobClient>::clone(&client);
        let _payout: Arc<dyn DynPayoutCapability> = Arc::<PaymobClient>::clone(&client);
        let _splits: Arc<dyn DynSplitSettlementCapability> = client;

        _assert_dyn_safe();
    }

    #[tokio::test]
    async fn smart_reversal_routes_void_when_unsettled_and_refund_when_settled() {
        let cap: Arc<dyn DynPaymentCapability> = Arc::new(MockPaymentCapability);

        let voided = cap
            .refund_or_void(101, MinorUnitAmount::new(5_000), false)
            .await
            .expect("void reversal");
        assert!(voided.is_voided());
        assert!(!voided.is_refunded());
        assert_eq!(voided.transaction_id(), 101);
        assert!(matches!(
            voided,
            UnifiedReversalReceipt::Voided(UnifiedVoidReceipt {
                transaction_id: 101,
                success: true,
                is_voided: true,
            })
        ));

        let refunded = cap
            .refund_or_void(202, MinorUnitAmount::new(7_500), true)
            .await
            .expect("refund reversal");
        assert!(refunded.is_refunded());
        assert!(!refunded.is_voided());
        assert_eq!(refunded.transaction_id(), 202);
        assert!(matches!(
            refunded,
            UnifiedReversalReceipt::Refunded(UnifiedRefundReceipt {
                refund_id: 202,
                amount,
                success: true,
                pending: false,
                is_refunded: true,
            }) if amount.as_u64() == 7_500
        ));
    }

    #[tokio::test]
    async fn paymob_client_dyn_payment_and_split_validation_paths() {
        let client = Arc::new(test_egypt_client());
        let payment: Arc<dyn DynPaymentCapability> = Arc::<PaymobClient>::clone(&client);
        let splits: Arc<dyn DynSplitSettlementCapability> = client;

        let zero_session = UnifiedPaymentSessionRequest::new(MinorUnitAmount::ZERO, Currency::EGP)
            .with_payment_methods(vec!["4097558".to_owned()]);
        assert_validation_err(payment.create_payment_session(&zero_session).await, "amount");

        let bad_capture = UnifiedCaptureRequest::new(0, MinorUnitAmount::new(1_000));
        assert!(payment.capture_payment(&bad_capture).await.is_err());
        assert!(
            payment
                .refund_or_void(0, MinorUnitAmount::new(1_000), false)
                .await
                .is_err()
        );
        assert!(
            payment
                .refund_or_void(0, MinorUnitAmount::new(1_000), true)
                .await
                .is_err()
        );

        let bad_mit = UnifiedSavedMethodChargeRequest::new("", "");
        assert!(payment.charge_saved_method(&bad_mit).await.is_err());

        let valid_session =
            UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(15_000), Currency::EGP)
                .with_payment_methods(vec!["4097558".to_owned()]);
        let bad_ext = PaymobExt::new().with_pre_selected_plan(0);
        assert_validation_err(
            splits
                .apply_splits_and_create_session(&valid_session, &bad_ext)
                .await,
            "pre_selected_plan",
        );
    }

    #[tokio::test]
    async fn paymob_client_dyn_webhook_subscription_and_payout_validation_paths() {
        let client = Arc::new(test_egypt_client());
        let webhook: Arc<dyn DynWebhookCapability> = Arc::<PaymobClient>::clone(&client);
        let subs: Arc<dyn DynSubscriptionCapability> = Arc::<PaymobClient>::clone(&client);
        let payout: Arc<dyn DynPayoutCapability> = client;

        assert!(
            webhook
                .verify_webhook(&UnifiedWebhookInput::new("{}", None))
                .is_err()
        );

        let bad_sub = UnifiedSubscriptionRefundRequest::new(0, None);
        assert_validation_err(subs.refund_last_transaction(&bad_sub).await, "subscription_id");

        let bad_payout =
            UnifiedPayoutRequest::new("", MinorUnitAmount::new(1_000), Currency::EGP, "vodafone");
        assert_validation_err(payout.execute_payout(&bad_payout).await, "recipient_identifier");
    }

    #[test]
    fn unified_reversal_receipt_serde_roundtrip() {
        let receipts = [
            UnifiedReversalReceipt::Voided(UnifiedVoidReceipt {
                transaction_id: 55,
                success: true,
                is_voided: true,
            }),
            UnifiedReversalReceipt::Refunded(UnifiedRefundReceipt {
                refund_id: 88,
                amount: MinorUnitAmount::new(2_500),
                success: true,
                pending: false,
                is_refunded: true,
            }),
        ];

        for receipt in receipts {
            let json = serde_json::to_string(&receipt).expect("serialize reversal receipt");
            let parsed: UnifiedReversalReceipt =
                serde_json::from_str(&json).expect("deserialize reversal receipt");
            assert_eq!(parsed, receipt);
        }
    }
}
