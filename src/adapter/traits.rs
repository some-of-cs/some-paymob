#![forbid(unsafe_code)]
//! Unified gateway trait definitions and normalized request/response DTOs (`US-8.1.0` Unit 1).
//!
//! Provides the northbound `some-payments` trait surface ([`PaymentProvider`],
//! [`WebhookVerifier`], [`SubscriptionProvider`], and [`PayoutProvider`]) along with
//! zero-float (`MinorUnitAmount`), secret-redacting (`[REDACTED]`) normalized DTOs.

use std::fmt;
use std::future::Future;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::core::error::PaymobError;
use crate::core::types::{Currency, MinorUnitAmount};

/// Normalized request to create a cross-gateway payment session.
///
/// # Examples
///
/// ```rust
/// use some_paymob::adapter::traits::UnifiedPaymentSessionRequest;
/// use some_paymob::core::types::{Currency, MinorUnitAmount};
///
/// let req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(15_000), Currency::Egp)
///     .with_payment_methods(vec!["4097558".to_owned()])
///     .with_special_reference("ORD-2026-001");
/// assert_eq!(req.amount.as_u64(), 15_000);
/// assert_eq!(req.special_reference.as_deref(), Some("ORD-2026-001"));
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct UnifiedPaymentSessionRequest {
    /// Total payment amount in integer minor currency units.
    pub amount: MinorUnitAmount,
    /// ISO-4217 currency code.
    pub currency: Currency,
    /// Gateway integration IDs or method names (for example `"4097558"` or `"card"`).
    pub payment_methods: Vec<String>,
    /// Optional merchant-supplied order or correlation reference.
    pub special_reference: Option<String>,
    /// Optional asynchronous webhook notification URL.
    pub notification_url: Option<String>,
    /// Optional customer browser redirection URL after checkout.
    pub redirection_url: Option<String>,
    /// Optional customer email address (redacted in `Debug`).
    pub customer_email: Option<String>,
    /// Optional customer phone number (redacted in `Debug`).
    pub customer_phone: Option<String>,
    /// Optional customer first name (redacted in `Debug`).
    pub customer_first_name: Option<String>,
    /// Optional customer last name (redacted in `Debug`).
    pub customer_last_name: Option<String>,
    /// Optional installment plan ID for Paymob's Affordability Widget.
    pub pre_selected_plan: Option<u64>,
    /// Optional opaque JSON extras forwarded to the gateway.
    pub extras: Option<serde_json::Value>,
}

impl UnifiedPaymentSessionRequest {
    /// Creates a new [`UnifiedPaymentSessionRequest`] for `amount` and `currency`.
    #[must_use]
    pub fn new(amount: MinorUnitAmount, currency: Currency) -> Self {
        Self {
            amount,
            currency,
            payment_methods: Vec::new(),
            special_reference: None,
            notification_url: None,
            redirection_url: None,
            customer_email: None,
            customer_phone: None,
            customer_first_name: None,
            customer_last_name: None,
            pre_selected_plan: None,
            extras: None,
        }
    }

    /// Sets the gateway payment method identifiers or names.
    #[must_use]
    pub fn with_payment_methods(mut self, payment_methods: Vec<String>) -> Self {
        self.payment_methods = payment_methods;
        self
    }

    /// Sets the merchant `special_reference` correlation identifier.
    #[must_use]
    pub fn with_special_reference(mut self, reference: impl Into<String>) -> Self {
        self.special_reference = Some(reference.into());
        self
    }

    /// Sets the asynchronous `notification_url` webhook endpoint.
    #[must_use]
    pub fn with_notification_url(mut self, url: impl Into<String>) -> Self {
        self.notification_url = Some(url.into());
        self
    }

    /// Sets the browser `redirection_url` after checkout completion.
    #[must_use]
    pub fn with_redirection_url(mut self, url: impl Into<String>) -> Self {
        self.redirection_url = Some(url.into());
        self
    }

    /// Sets the customer email and phone number (both redacted in `Debug`).
    #[must_use]
    pub fn with_customer_contact(
        mut self,
        email: impl Into<String>,
        phone: impl Into<String>,
    ) -> Self {
        self.customer_email = Some(email.into());
        self.customer_phone = Some(phone.into());
        self
    }

    /// Sets the customer first and last name (both redacted in `Debug`).
    #[must_use]
    pub fn with_customer_name(
        mut self,
        first_name: impl Into<String>,
        last_name: impl Into<String>,
    ) -> Self {
        self.customer_first_name = Some(first_name.into());
        self.customer_last_name = Some(last_name.into());
        self
    }

    /// Sets the optional installment `pre_selected_plan` ID.
    #[must_use]
    pub const fn with_pre_selected_plan(mut self, plan_id: u64) -> Self {
        self.pre_selected_plan = Some(plan_id);
        self
    }

    /// Sets optional gateway-specific `extras` JSON metadata.
    #[must_use]
    pub fn with_extras(mut self, extras: serde_json::Value) -> Self {
        self.extras = Some(extras);
        self
    }

    /// Validates that required unified session invariants hold before dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount` is zero, `payment_methods`
    /// is empty, or `pre_selected_plan` is `Some(0)`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.amount.as_u64() == 0 {
            return Err(PaymobError::ValidationError {
                field: "amount",
                reason: "payment session amount must be greater than zero".to_owned(),
            });
        }
        if self.payment_methods.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "payment_methods",
                reason: "at least one payment method or integration ID is required".to_owned(),
            });
        }
        if self.pre_selected_plan == Some(0) {
            return Err(PaymobError::ValidationError {
                field: "pre_selected_plan",
                reason: "pre_selected_plan must be greater than zero".to_owned(),
            });
        }
        Ok(())
    }
}

impl fmt::Debug for UnifiedPaymentSessionRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnifiedPaymentSessionRequest")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("payment_methods", &self.payment_methods)
            .field("special_reference", &self.special_reference)
            .field("notification_url", &self.notification_url)
            .field("redirection_url", &self.redirection_url)
            .field("customer_email", &self.customer_email.as_ref().map(|_| "[REDACTED]"))
            .field("customer_phone", &self.customer_phone.as_ref().map(|_| "[REDACTED]"))
            .field(
                "customer_first_name",
                &self.customer_first_name.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "customer_last_name",
                &self.customer_last_name.as_ref().map(|_| "[REDACTED]"),
            )
            .field("pre_selected_plan", &self.pre_selected_plan)
            .field("extras", &self.extras)
            .finish()
    }
}

/// Normalized response returned when creating a cross-gateway payment session.
#[derive(Clone)]
pub struct UnifiedPaymentSession {
    /// Gateway session or intention identifier (for example `pi_*`).
    pub session_id: String,
    /// Gateway order identifier mapped as a string.
    pub order_id: String,
    /// Single-use checkout client secret (redacted in `Debug`).
    pub client_secret: SecretString,
    /// Hosted checkout URL for redirecting the customer.
    pub checkout_url: String,
    /// Gateway lifecycle status string (for example `"intended"`).
    pub status: String,
    /// Whether the session has already been confirmed/paid.
    pub confirmed: bool,
}

impl fmt::Debug for UnifiedPaymentSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnifiedPaymentSession")
            .field("session_id", &self.session_id)
            .field("order_id", &self.order_id)
            .field("client_secret", &"[REDACTED]")
            .field("checkout_url", &"[REDACTED]")
            .field("status", &self.status)
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

/// Normalized request to capture an authorized payment transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedCaptureRequest {
    /// Gateway transaction identifier to capture.
    pub transaction_id: u64,
    /// Amount to capture in integer minor currency units.
    pub amount: MinorUnitAmount,
}

impl UnifiedCaptureRequest {
    /// Creates a new [`UnifiedCaptureRequest`].
    #[must_use]
    pub const fn new(transaction_id: u64, amount: MinorUnitAmount) -> Self {
        Self {
            transaction_id,
            amount,
        }
    }
}

/// Normalized receipt returned after capturing an authorized payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedCaptureReceipt {
    /// Resulting capture transaction identifier.
    pub transaction_id: u64,
    /// Captured amount in integer minor currency units.
    pub amount: MinorUnitAmount,
    /// Whether the capture succeeded.
    pub success: bool,
    /// Whether the capture is still pending settlement.
    pub pending: bool,
}

/// Normalized request to refund a settled payment transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedRefundRequest {
    /// Gateway transaction identifier to refund.
    pub transaction_id: u64,
    /// Refund amount in integer minor currency units.
    pub amount: MinorUnitAmount,
}

impl UnifiedRefundRequest {
    /// Creates a new [`UnifiedRefundRequest`].
    #[must_use]
    pub const fn new(transaction_id: u64, amount: MinorUnitAmount) -> Self {
        Self {
            transaction_id,
            amount,
        }
    }
}

/// Normalized receipt returned after refunding a payment transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedRefundReceipt {
    /// Newly created refund transaction identifier.
    pub refund_id: u64,
    /// Refunded amount in integer minor currency units.
    pub amount: MinorUnitAmount,
    /// Whether the refund succeeded.
    pub success: bool,
    /// Whether the refund is still pending settlement.
    pub pending: bool,
    /// Whether the transaction is marked as refunded.
    pub is_refunded: bool,
}

/// Normalized request to void an unsettled authorization transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedVoidRequest {
    /// Gateway transaction identifier to void.
    pub transaction_id: u64,
}

impl UnifiedVoidRequest {
    /// Creates a new [`UnifiedVoidRequest`].
    #[must_use]
    pub const fn new(transaction_id: u64) -> Self {
        Self { transaction_id }
    }
}

/// Normalized receipt returned after voiding a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedVoidReceipt {
    /// Void transaction identifier.
    pub transaction_id: u64,
    /// Whether the void succeeded.
    pub success: bool,
    /// Whether the transaction is marked as voided.
    pub is_voided: bool,
}

/// Normalized request to charge a previously saved payment method (MIT).
#[derive(Clone)]
pub struct UnifiedSavedMethodChargeRequest {
    /// Single-use payment key generated from an intention (redacted in `Debug`).
    pub payment_token: SecretString,
    /// Saved payment method token (redacted in `Debug`).
    pub saved_method_token: SecretString,
    /// Optional card verification number (redacted in `Debug`).
    pub cvn: Option<SecretString>,
}

impl UnifiedSavedMethodChargeRequest {
    /// Creates a new [`UnifiedSavedMethodChargeRequest`].
    #[must_use]
    pub fn new(
        payment_token: impl Into<SecretString>,
        saved_method_token: impl Into<SecretString>,
    ) -> Self {
        Self {
            payment_token: payment_token.into(),
            saved_method_token: saved_method_token.into(),
            cvn: None,
        }
    }

    /// Attaches an optional CVN/CVC security code (redacted in `Debug`).
    #[must_use]
    pub fn with_cvn(mut self, cvn: impl Into<SecretString>) -> Self {
        self.cvn = Some(cvn.into());
        self
    }
}

impl fmt::Debug for UnifiedSavedMethodChargeRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnifiedSavedMethodChargeRequest")
            .field("payment_token", &"[REDACTED]")
            .field("saved_method_token", &"[REDACTED]")
            .field("cvn", &self.cvn.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Normalized receipt returned after charging a saved payment method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedSavedMethodChargeReceipt {
    /// Gateway transaction identifier.
    pub transaction_id: u64,
    /// Charged amount in integer minor currency units.
    pub amount: MinorUnitAmount,
    /// Whether the charge succeeded immediately.
    pub success: bool,
    /// Whether the charge is pending asynchronous completion or 3DS.
    pub pending: bool,
    /// Optional redirect URL for 3DS or wallet challenges.
    pub redirect_url: Option<String>,
    /// Optional offline Kiosk bill reference number.
    pub kiosk_bill_reference: Option<String>,
}

/// Borrowed input payload and optional query HMAC signature for webhook verification.
#[derive(Clone, Copy)]
pub struct UnifiedWebhookInput<'a> {
    /// Raw HTTP request body string (or query payload).
    pub raw_body: &'a str,
    /// Optional `?hmac=` signature extracted from the request query string.
    pub signature_hmac: Option<&'a str>,
}

impl<'a> UnifiedWebhookInput<'a> {
    /// Creates a new [`UnifiedWebhookInput`].
    #[must_use]
    pub const fn new(raw_body: &'a str, signature_hmac: Option<&'a str>) -> Self {
        Self {
            raw_body,
            signature_hmac,
        }
    }
}

impl fmt::Debug for UnifiedWebhookInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnifiedWebhookInput")
            .field("raw_body_len", &self.raw_body.len())
            .field("signature_hmac", &self.signature_hmac.map(|_| "[REDACTED]"))
            .finish()
    }
}

/// Canonical classification of a verified cross-gateway webhook event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnifiedWebhookKind {
    /// Acquiring transaction processed callback.
    TransactionProcessed,
    /// Acquiring transaction redirect callback.
    TransactionRedirect,
    /// Saved card token created/updated callback.
    CardTokenSaved,
    /// Subscription lifecycle callback.
    SubscriptionLifecycle,
    /// Payout disbursement callback.
    PayoutDisbursement,
    /// Payout wallet topup callback.
    PayoutTopup,
}

/// Normalized outcome produced after cryptographic webhook verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedWebhookOutcome {
    /// High-level webhook classification.
    pub kind: UnifiedWebhookKind,
    /// Canonical `snake_case` event type identifier.
    pub event_type: &'static str,
    /// Deterministic idempotency key for deduplicating retries.
    pub idempotency_key: String,
    /// Order or subscription correlation identifier.
    pub correlation_id: String,
}

/// Normalized request to refund the latest deduction of a subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedSubscriptionRefundRequest {
    /// Gateway subscription identifier.
    pub subscription_id: u64,
    /// Optional partial refund amount in minor units (`None` refunds the full deduction).
    pub amount: Option<MinorUnitAmount>,
}

impl UnifiedSubscriptionRefundRequest {
    /// Creates a new [`UnifiedSubscriptionRefundRequest`].
    #[must_use]
    pub const fn new(subscription_id: u64, amount: Option<MinorUnitAmount>) -> Self {
        Self {
            subscription_id,
            amount,
        }
    }
}

/// Normalized receipt returned after refunding a subscription's last deduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedSubscriptionRefundReceipt {
    /// Newly created refund transaction identifier.
    pub refund_id: u64,
    /// Refunded amount in integer minor currency units.
    pub amount: MinorUnitAmount,
    /// Whether the refund succeeded.
    pub success: bool,
    /// Whether the refund is still pending.
    pub pending: bool,
    /// Original parent deduction transaction identifier, if returned.
    pub parent_transaction_id: Option<u64>,
}

/// Normalized request to execute an outbound disbursement/payout.
#[derive(Clone, Serialize, Deserialize)]
pub struct UnifiedPayoutRequest {
    /// Recipient wallet MSISDN, IBAN, or card identifier (redacted in `Debug`).
    pub recipient_identifier: String,
    /// Disbursement amount in integer minor currency units.
    pub amount: MinorUnitAmount,
    /// ISO-4217 currency code.
    pub currency: Currency,
    /// Gateway payout issuer identifier (for example `"vodafone"`).
    pub issuer: String,
    /// Optional merchant-supplied payout reference.
    pub reference: Option<String>,
}

impl UnifiedPayoutRequest {
    /// Creates a new [`UnifiedPayoutRequest`].
    #[must_use]
    pub fn new(
        recipient_identifier: impl Into<String>,
        amount: MinorUnitAmount,
        currency: Currency,
        issuer: impl Into<String>,
    ) -> Self {
        Self {
            recipient_identifier: recipient_identifier.into(),
            amount,
            currency,
            issuer: issuer.into(),
            reference: None,
        }
    }

    /// Validates that required payout invariants hold before execution.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `recipient_identifier` or `issuer`
    /// is empty, or if `amount` is zero.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.recipient_identifier.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "recipient_identifier",
                reason: "recipient_identifier must not be empty".to_owned(),
            });
        }
        if self.amount.as_u64() == 0 {
            return Err(PaymobError::ValidationError {
                field: "amount",
                reason: "payout amount must be greater than zero".to_owned(),
            });
        }
        if self.issuer.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "issuer",
                reason: "payout issuer must not be empty".to_owned(),
            });
        }
        Ok(())
    }
}

impl fmt::Debug for UnifiedPayoutRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnifiedPayoutRequest")
            .field("recipient_identifier", &"[REDACTED]")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("issuer", &self.issuer)
            .field("reference", &self.reference)
            .finish()
    }
}

/// Normalized receipt returned after executing an outbound payout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnifiedPayoutReceipt {
    /// Gateway payout transaction identifier.
    pub payout_id: String,
    /// Disbursed amount in integer minor currency units.
    pub amount: MinorUnitAmount,
    /// Gateway payout status string.
    pub status: String,
    /// Gateway payout issuer identifier.
    pub issuer: String,
}

/// Unified cross-gateway payment lifecycle trait implemented by gateway clients.
pub trait PaymentProvider: Send + Sync {
    /// Gateway-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Creates a payment session and returns its checkout URL and client secret.
    fn create_payment_session(
        &self,
        req: &UnifiedPaymentSessionRequest,
    ) -> impl Future<Output = Result<UnifiedPaymentSession, Self::Error>> + Send + '_;

    /// Captures an authorized payment transaction.
    fn capture_payment(
        &self,
        req: &UnifiedCaptureRequest,
    ) -> impl Future<Output = Result<UnifiedCaptureReceipt, Self::Error>> + Send + '_;

    /// Refunds a settled payment transaction.
    fn refund_payment(
        &self,
        req: &UnifiedRefundRequest,
    ) -> impl Future<Output = Result<UnifiedRefundReceipt, Self::Error>> + Send + '_;

    /// Voids an unsettled authorization transaction.
    fn void_payment(
        &self,
        req: &UnifiedVoidRequest,
    ) -> impl Future<Output = Result<UnifiedVoidReceipt, Self::Error>> + Send + '_;

    /// Charges a previously saved payment method (Merchant-Initiated Transaction).
    fn charge_saved_method(
        &self,
        req: &UnifiedSavedMethodChargeRequest,
    ) -> impl Future<Output = Result<UnifiedSavedMethodChargeReceipt, Self::Error>> + Send + '_;
}

/// Unified cross-gateway cryptographic webhook verification trait.
pub trait WebhookVerifier: Send + Sync {
    /// Gateway-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Verifies the webhook signature in constant time and normalizes the outcome.
    ///
    /// # Errors
    ///
    /// Returns [`Self::Error`] if the signature is missing, malformed, or fails
    /// constant-time verification.
    fn verify_webhook(
        &self,
        input: &UnifiedWebhookInput<'_>,
    ) -> Result<UnifiedWebhookOutcome, Self::Error>;
}

/// Unified cross-gateway subscription management trait.
pub trait SubscriptionProvider: Send + Sync {
    /// Gateway-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Refunds the latest deduction transaction of a subscription.
    fn refund_last_transaction(
        &self,
        req: &UnifiedSubscriptionRefundRequest,
    ) -> impl Future<Output = Result<UnifiedSubscriptionRefundReceipt, Self::Error>> + Send + '_;
}

/// Unified cross-gateway outbound disbursement/payout trait.
pub trait PayoutProvider: Send + Sync {
    /// Gateway-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Executes an outbound payout disbursement to a recipient wallet or bank account.
    fn execute_payout(
        &self,
        req: &UnifiedPayoutRequest,
    ) -> impl Future<Output = Result<UnifiedPayoutReceipt, Self::Error>> + Send + '_;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_request_validates_positive_amount_and_methods() {
        let req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(5_000), Currency::Egp)
            .with_payment_methods(vec!["4097558".to_owned()])
            .with_special_reference("ORD-100")
            .with_pre_selected_plan(12);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn session_request_rejects_zero_amount_and_empty_methods() {
        let zero_amt = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(0), Currency::Egp)
            .with_payment_methods(vec!["4097558".to_owned()]);
        assert!(matches!(
            zero_amt.validate(),
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));

        let no_methods =
            UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(100), Currency::Egp);
        assert!(matches!(
            no_methods.validate(),
            Err(PaymobError::ValidationError {
                field: "payment_methods",
                ..
            })
        ));

        let zero_plan = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(100), Currency::Egp)
            .with_payment_methods(vec!["4097558".to_owned()])
            .with_pre_selected_plan(0);
        assert!(matches!(
            zero_plan.validate(),
            Err(PaymobError::ValidationError {
                field: "pre_selected_plan",
                ..
            })
        ));
    }

    #[test]
    fn debug_redacts_secrets_and_pii() {
        let req = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(1000), Currency::Egp)
            .with_payment_methods(vec!["card".to_owned()])
            .with_customer_contact("secret@example.com", "+201001234567")
            .with_customer_name("Oscar", "Arena");
        let req_dbg = format!("{req:?}");
        assert!(!req_dbg.contains("secret@example.com"));
        assert!(!req_dbg.contains("+201001234567"));
        assert!(!req_dbg.contains("Oscar"));
        assert!(req_dbg.contains("[REDACTED]"));

        let session = UnifiedPaymentSession {
            session_id: "pi_123".to_owned(),
            order_id: "999".to_owned(),
            client_secret: SecretString::from("egy_csk_secret_token"),
            checkout_url: "https://accept.paymob.com/unifiedcheckout/?clientSecret=egy_csk_secret_token".to_owned(),
            status: "intended".to_owned(),
            confirmed: false,
        };
        let sess_dbg = format!("{session:?}");
        assert!(!sess_dbg.contains("egy_csk_secret_token"));
        assert!(sess_dbg.contains("[REDACTED]"));

        let charge = UnifiedSavedMethodChargeRequest::new("pay_tok_secret", "saved_tok_secret")
            .with_cvn("999");
        let charge_dbg = format!("{charge:?}");
        assert!(!charge_dbg.contains("pay_tok_secret"));
        assert!(!charge_dbg.contains("saved_tok_secret"));
        assert!(!charge_dbg.contains("999"));
        assert!(charge_dbg.contains("[REDACTED]"));

        let webhook = UnifiedWebhookInput::new("{}", Some("deadbeef_hmac"));
        let wh_dbg = format!("{webhook:?}");
        assert!(!wh_dbg.contains("deadbeef_hmac"));
        assert!(wh_dbg.contains("[REDACTED]"));
    }

    #[test]
    fn payout_request_validates_fields_and_redacts_recipient() {
        let valid = UnifiedPayoutRequest::new(
            "01001234567",
            MinorUnitAmount::new(25_000),
            Currency::Egp,
            "vodafone",
        );
        assert!(valid.validate().is_ok());
        let dbg = format!("{valid:?}");
        assert!(!dbg.contains("01001234567"));
        assert!(dbg.contains("[REDACTED]"));

        let empty_recipient = UnifiedPayoutRequest::new(
            "   ",
            MinorUnitAmount::new(100),
            Currency::Egp,
            "vodafone",
        );
        assert!(matches!(
            empty_recipient.validate(),
            Err(PaymobError::ValidationError {
                field: "recipient_identifier",
                ..
            })
        ));
    }
}
