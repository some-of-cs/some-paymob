#![forbid(unsafe_code)]
//! Object-safe (`dyn`-compatible) capability traits and smart reversal helpers for `some-payment`
//! (`US-9.2.0` Unit 1).
//!
//! Provides dynamic-dispatch equivalents of [`PaymentProvider`], [`WebhookVerifier`],
//! [`SubscriptionProvider`], and [`PayoutProvider`], plus [`DynSplitSettlementCapability`]
//! and [`UnifiedReversalReceipt`] so downstream orchestrators such as `some-payment`'s
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
//! let _payment: Arc<dyn DynPaymentCapability> = Arc::clone(&client);
//! let _webhook: Arc<dyn DynWebhookCapability> = Arc::clone(&client);
//! let _subs: Arc<dyn DynSubscriptionCapability> = Arc::clone(&client);
//! let _payout: Arc<dyn DynPayoutCapability> = Arc::clone(&client);
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

impl DynPaymentCapability for PaymobClient {
    fn create_payment_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
    ) -> BoxFuture<'_, Result<UnifiedPaymentSession, PaymobError>> {
        let client = self.clone();
        let owned_req = req.clone();
        Box::pin(async move {
            PaymentProvider::create_payment_session(&client, &owned_req).await
        })
    }

    fn capture_payment(
        &self,
        req: &UnifiedCaptureRequest,
    ) -> BoxFuture<'_, Result<UnifiedCaptureReceipt, PaymobError>> {
        let client = self.clone();
        let owned_req = *req;
        Box::pin(async move { PaymentProvider::capture_payment(&client, &owned_req).await })
    }

    fn refund_payment(
        &self,
        req: &UnifiedRefundRequest,
    ) -> BoxFuture<'_, Result<UnifiedRefundReceipt, PaymobError>> {
        let client = self.clone();
        let owned_req = *req;
        Box::pin(async move { PaymentProvider::refund_payment(&client, &owned_req).await })
    }

    fn void_payment(
        &self,
        req: &UnifiedVoidRequest,
    ) -> BoxFuture<'_, Result<UnifiedVoidReceipt, PaymobError>> {
        let client = self.clone();
        let owned_req = *req;
        Box::pin(async move { PaymentProvider::void_payment(&client, &owned_req).await })
    }

    fn charge_saved_method(
        &self,
        req: &UnifiedSavedMethodChargeRequest,
    ) -> BoxFuture<'_, Result<UnifiedSavedMethodChargeReceipt, PaymobError>> {
        let client = self.clone();
        let owned_req = req.clone();
        Box::pin(async move {
            PaymentProvider::charge_saved_method(&client, &owned_req).await
        })
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
    fn refund_last_transaction(
        &self,
        req: &UnifiedSubscriptionRefundRequest,
    ) -> BoxFuture<'_, Result<UnifiedSubscriptionRefundReceipt, PaymobError>> {
        let client = self.clone();
        let owned_req = *req;
        Box::pin(async move {
            SubscriptionProvider::refund_last_transaction(&client, &owned_req).await
        })
    }
}

impl DynPayoutCapability for PaymobClient {
    fn execute_payout(
        &self,
        req: &UnifiedPayoutRequest,
    ) -> BoxFuture<'_, Result<UnifiedPayoutReceipt, PaymobError>> {
        let client = self.clone();
        let owned_req = req.clone();
        Box::pin(async move { PayoutProvider::execute_payout(&client, &owned_req).await })
    }
}

impl DynSplitSettlementCapability for PaymobClient {
    fn apply_splits_and_create_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
        ext: &PaymobExt,
    ) -> BoxFuture<'_, Result<UnifiedPaymentSession, PaymobError>> {
        let client = self.clone();
        let wired = ext.apply_to_session_request(req.clone());
        Box::pin(async move {
            let session_req = wired?;
            PaymentProvider::create_payment_session(&client, &session_req).await
        })
    }
}

#[allow(dead_code)]
const fn _assert_dyn_safe(
    _: &dyn DynPaymentCapability,
    _: &dyn DynWebhookCapability,
    _: &dyn DynSubscriptionCapability,
    _: &dyn DynPayoutCapability,
    _: &dyn DynSplitSettlementCapability,
) {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::region::PaymobRegion;
    use crate::core::types::Currency;

    struct MockPaymentCapability;

    impl DynPaymentCapability for MockPaymentCapability {
        fn create_payment_session(
            &self,
            _req: &UnifiedPaymentSessionRequest,
        ) -> BoxFuture<'_, Result<UnifiedPaymentSession, PaymobError>> {
            Box::pin(async {
                Err(PaymobError::ValidationError {
                    field: "session",
                    reason: "not used in mock".to_owned(),
                })
            })
        }

        fn capture_payment(
            &self,
            req: &UnifiedCaptureRequest,
        ) -> BoxFuture<'_, Result<UnifiedCaptureReceipt, PaymobError>> {
            let receipt = UnifiedCaptureReceipt {
                transaction_id: req.transaction_id,
                amount: req.amount,
                success: true,
                pending: false,
            };
            Box::pin(async move { Ok(receipt) })
        }

        fn refund_payment(
            &self,
            req: &UnifiedRefundRequest,
        ) -> BoxFuture<'_, Result<UnifiedRefundReceipt, PaymobError>> {
            let receipt = UnifiedRefundReceipt {
                refund_id: req.transaction_id,
                amount: req.amount,
                success: true,
                pending: false,
                is_refunded: true,
            };
            Box::pin(async move { Ok(receipt) })
        }

        fn void_payment(
            &self,
            req: &UnifiedVoidRequest,
        ) -> BoxFuture<'_, Result<UnifiedVoidReceipt, PaymobError>> {
            let receipt = UnifiedVoidReceipt {
                transaction_id: req.transaction_id,
                success: true,
                is_voided: true,
            };
            Box::pin(async move { Ok(receipt) })
        }

        fn charge_saved_method(
            &self,
            _req: &UnifiedSavedMethodChargeRequest,
        ) -> BoxFuture<'_, Result<UnifiedSavedMethodChargeReceipt, PaymobError>> {
            Box::pin(async {
                Err(PaymobError::ValidationError {
                    field: "saved_method",
                    reason: "not used in mock".to_owned(),
                })
            })
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
        let payment: Arc<dyn DynPaymentCapability> = Arc::clone(&client);
        let webhook: Arc<dyn DynWebhookCapability> = Arc::clone(&client);
        let subs: Arc<dyn DynSubscriptionCapability> = Arc::clone(&client);
        let payout: Arc<dyn DynPayoutCapability> = Arc::clone(&client);
        let splits: Arc<dyn DynSplitSettlementCapability> = client;

        _assert_dyn_safe(
            payment.as_ref(),
            webhook.as_ref(),
            subs.as_ref(),
            payout.as_ref(),
            splits.as_ref(),
        );
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
        let payment: Arc<dyn DynPaymentCapability> = Arc::clone(&client);
        let splits: Arc<dyn DynSplitSettlementCapability> = client;

        let zero_session = UnifiedPaymentSessionRequest::new(MinorUnitAmount::ZERO, Currency::EGP)
            .with_payment_methods(vec!["4097558".to_owned()]);
        assert!(matches!(
            payment.create_payment_session(&zero_session).await,
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));

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
        assert!(matches!(
            splits
                .apply_splits_and_create_session(&valid_session, &bad_ext)
                .await,
            Err(PaymobError::ValidationError {
                field: "pre_selected_plan",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn paymob_client_dyn_webhook_subscription_and_payout_validation_paths() {
        let client = Arc::new(test_egypt_client());
        let webhook: Arc<dyn DynWebhookCapability> = Arc::clone(&client);
        let subs: Arc<dyn DynSubscriptionCapability> = Arc::clone(&client);
        let payout: Arc<dyn DynPayoutCapability> = client;

        assert!(
            webhook
                .verify_webhook(&UnifiedWebhookInput::new("{}", None))
                .is_err()
        );

        let bad_sub = UnifiedSubscriptionRefundRequest::new(0, None);
        assert!(matches!(
            subs.refund_last_transaction(&bad_sub).await,
            Err(PaymobError::ValidationError {
                field: "subscription_id",
                ..
            })
        ));

        let bad_payout =
            UnifiedPayoutRequest::new("", MinorUnitAmount::new(1_000), Currency::EGP, "vodafone");
        assert!(matches!(
            payout.execute_payout(&bad_payout).await,
            Err(PaymobError::ValidationError {
                field: "recipient_identifier",
                ..
            })
        ));
    }

    #[test]
    fn unified_reversal_receipt_serde_roundtrip() {
        let voided = UnifiedReversalReceipt::Voided(UnifiedVoidReceipt {
            transaction_id: 55,
            success: true,
            is_voided: true,
        });
        let voided_json = serde_json::to_string(&voided).expect("serialize voided");
        let parsed_voided: UnifiedReversalReceipt =
            serde_json::from_str(&voided_json).expect("deserialize voided");
        assert_eq!(parsed_voided, voided);

        let refunded = UnifiedReversalReceipt::Refunded(UnifiedRefundReceipt {
            refund_id: 88,
            amount: MinorUnitAmount::new(2_500),
            success: true,
            pending: false,
            is_refunded: true,
        });
        let refunded_json = serde_json::to_string(&refunded).expect("serialize refunded");
        let parsed_refunded: UnifiedReversalReceipt =
            serde_json::from_str(&refunded_json).expect("deserialize refunded");
        assert_eq!(parsed_refunded, refunded);
    }
}
