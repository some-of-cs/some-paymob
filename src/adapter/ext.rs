#![forbid(unsafe_code)]
//! `PaymobExt` and `ProviderExt::Paymob(PaymobExt)` escape hatch (`US-8.1.0` Unit 3).
//!
//! Exposes Paymob-specific capabilities (`pre_selected_plan` for the Affordability
//! Widget, `special_reference`, `split_description`, and Kiosk/Mobile Wallet headless
//! execution options) without polluting the cross-gateway core traits.

use std::fmt;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::adapter::traits::UnifiedPaymentSessionRequest;
use crate::core::error::PaymobError;
use crate::resources::saved_cards::service::{KioskPayParams, WalletPayParams};
use crate::resources::splits::models::SplitRecipientRule;

/// Headless Paymob execution options for Mobile Wallet or Kiosk channels.
///
/// Redacts `phone_number` in [`fmt::Debug`] and zeroizes customer MSISDN on drop.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub enum HeadlessExecutionOption {
    /// Execute a Mobile Wallet payment against the customer's MSISDN (redacted in `Debug`).
    MobileWallet {
        /// Customer mobile wallet phone number (MSISDN).
        phone_number: String,
    },
    /// Generate an offline Kiosk bill reference (for example Aman/Masary).
    Kiosk,
}

impl fmt::Debug for HeadlessExecutionOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MobileWallet { .. } => f
                .debug_struct("MobileWallet")
                .field("phone_number", &"[REDACTED]")
                .finish(),
            Self::Kiosk => f.write_str("Kiosk"),
        }
    }
}

/// Paymob-specific extension options passed through [`ProviderExt::Paymob`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::adapter::ext::{PaymobExt, ProviderExt};
/// use some_paymob::adapter::traits::UnifiedPaymentSessionRequest;
/// use some_paymob::core::types::{Currency, MinorUnitAmount};
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let ext = ProviderExt::Paymob(
///     PaymobExt::new()
///         .with_pre_selected_plan(42)
///         .with_special_reference("ORD-1"),
/// );
/// let base = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(20_000), Currency::EGP)
///     .with_payment_methods(vec!["4097558".to_owned()]);
/// let wired = ext.paymob().expect("paymob ext").apply_to_session_request(base)?;
/// assert_eq!(wired.pre_selected_plan, Some(42));
/// assert_eq!(wired.special_reference.as_deref(), Some("ORD-1"));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymobExt {
    /// Optional installment plan ID for Paymob's Affordability Widget.
    pub pre_selected_plan: Option<u64>,
    /// Optional merchant-supplied correlation reference.
    pub special_reference: Option<String>,
    /// Optional marketplace split recipient rules.
    pub split_description: Option<Vec<SplitRecipientRule>>,
    /// Optional headless execution channel (Mobile Wallet or Kiosk).
    pub headless_execution: Option<HeadlessExecutionOption>,
}

impl PaymobExt {
    /// Creates an empty [`PaymobExt`] configuration.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the installment `pre_selected_plan` ID for the Affordability Widget.
    #[must_use]
    pub const fn with_pre_selected_plan(mut self, plan_id: u64) -> Self {
        self.pre_selected_plan = Some(plan_id);
        self
    }

    /// Sets the merchant `special_reference` correlation identifier.
    #[must_use]
    pub fn with_special_reference(mut self, reference: impl Into<String>) -> Self {
        self.special_reference = Some(reference.into());
        self
    }

    /// Sets marketplace `split_description` recipient rules.
    #[must_use]
    pub fn with_split_description(mut self, rules: Vec<SplitRecipientRule>) -> Self {
        self.split_description = Some(rules);
        self
    }

    /// Configures headless Mobile Wallet execution for `phone_number`.
    #[must_use]
    pub fn with_mobile_wallet(mut self, phone_number: impl Into<String>) -> Self {
        self.headless_execution = Some(HeadlessExecutionOption::MobileWallet {
            phone_number: phone_number.into(),
        });
        self
    }

    /// Configures headless offline Kiosk bill-reference execution.
    #[must_use]
    pub fn with_kiosk(mut self) -> Self {
        self.headless_execution = Some(HeadlessExecutionOption::Kiosk);
        self
    }

    /// Validates Paymob extension invariants before wiring into a request.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `pre_selected_plan` is `Some(0)`,
    /// `special_reference` is empty/whitespace, `split_description` is empty or contains
    /// an invalid [`SplitRecipientRule`], or a Mobile Wallet phone number is empty.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.pre_selected_plan == Some(0) {
            return Err(PaymobError::ValidationError {
                field: "pre_selected_plan",
                reason: "pre_selected_plan must be greater than zero".to_owned(),
            });
        }
        self.validate_optional_strings()?;
        self.validate_splits()
    }

    fn validate_optional_strings(&self) -> Result<(), PaymobError> {
        if let Some(reference) = &self.special_reference
            && reference.trim().is_empty()
        {
            return Err(PaymobError::ValidationError {
                field: "special_reference",
                reason: "special_reference must not be blank when provided".to_owned(),
            });
        }
        if let Some(HeadlessExecutionOption::MobileWallet { phone_number }) =
            &self.headless_execution
            && phone_number.trim().is_empty()
        {
            return Err(PaymobError::ValidationError {
                field: "phone_number",
                reason: "mobile wallet phone_number must not be empty".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_splits(&self) -> Result<(), PaymobError> {
        let Some(rules) = &self.split_description else {
            return Ok(());
        };
        if rules.is_empty() {
            return Err(PaymobError::ValidationError {
                field: "split_description",
                reason: "split_description must contain at least one recipient rule".to_owned(),
            });
        }
        for rule in rules {
            rule.validate()?;
        }
        Ok(())
    }

    /// Wires [`PaymobExt`] options into a [`UnifiedPaymentSessionRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `self.validate()` fails or
    /// `split_description` cannot be serialized into JSON extras.
    pub fn apply_to_session_request(
        &self,
        mut req: UnifiedPaymentSessionRequest,
    ) -> Result<UnifiedPaymentSessionRequest, PaymobError> {
        self.validate()?;
        if let Some(plan) = self.pre_selected_plan {
            req.pre_selected_plan = Some(plan);
        }
        if let Some(reference) = &self.special_reference {
            req.special_reference = Some(reference.clone());
        }
        if let Some(rules) = &self.split_description {
            let encoded =
                serde_json::to_value(rules).map_err(|err| PaymobError::ValidationError {
                    field: "split_description",
                    reason: format!("failed to serialize split_description: {err}"),
                })?;
            req.extras = Some(merge_split_extras(req.extras.take(), encoded));
        }
        Ok(req)
    }

    /// Builds [`WalletPayParams`] when [`HeadlessExecutionOption::MobileWallet`] is set.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if Mobile Wallet execution is not
    /// configured or `phone_number` / `payment_token` is invalid.
    pub fn build_wallet_pay_params(
        &self,
        payment_token: impl Into<SecretString>,
    ) -> Result<WalletPayParams, PaymobError> {
        self.resolve_headless_params("MobileWallet", |opt| match opt {
            HeadlessExecutionOption::MobileWallet { phone_number } => {
                Some(WalletPayParams::new(payment_token, phone_number.clone()))
            }
            HeadlessExecutionOption::Kiosk => None,
        })
    }

    /// Builds [`KioskPayParams`] when [`HeadlessExecutionOption::Kiosk`] is set.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if Kiosk execution is not configured
    /// or `payment_token` is empty.
    pub fn build_kiosk_pay_params(
        &self,
        payment_token: impl Into<SecretString>,
    ) -> Result<KioskPayParams, PaymobError> {
        self.resolve_headless_params("Kiosk", |opt| match opt {
            HeadlessExecutionOption::Kiosk => Some(KioskPayParams::new(payment_token)),
            HeadlessExecutionOption::MobileWallet { .. } => None,
        })
    }

    fn resolve_headless_params<T, F>(&self, option_name: &str, build: F) -> Result<T, PaymobError>
    where
        F: FnOnce(&HeadlessExecutionOption) -> Option<Result<T, PaymobError>>,
    {
        self.headless_execution
            .as_ref()
            .and_then(build)
            .unwrap_or_else(|| {
                Err(PaymobError::ValidationError {
                    field: "headless_execution",
                    reason: format!("{option_name} headless option is not configured"),
                })
            })
    }
}

fn merge_split_extras(
    existing: Option<serde_json::Value>,
    split_value: serde_json::Value,
) -> serde_json::Value {
    match existing {
        Some(serde_json::Value::Object(mut map)) => {
            map.insert("split_description".to_owned(), split_value);
            serde_json::Value::Object(map)
        }
        _ => serde_json::json!({ "split_description": split_value }),
    }
}

/// Cross-gateway provider extension escape hatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderExt {
    /// Paymob-specific extension options.
    Paymob(PaymobExt),
}

impl ProviderExt {
    /// Returns the inner [`PaymobExt`] when this variant is [`ProviderExt::Paymob`].
    #[must_use]
    pub const fn paymob(&self) -> Option<&PaymobExt> {
        match self {
            Self::Paymob(ext) => Some(ext),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::types::{Currency, MinorUnitAmount};

    #[test]
    fn paymob_ext_wires_plan_reference_and_splits() {
        let ext = PaymobExt::new()
            .with_pre_selected_plan(42)
            .with_special_reference("ORD-1")
            .with_split_description(vec![SplitRecipientRule::fixed("sub_1", 5_000)]);
        let base = UnifiedPaymentSessionRequest::new(MinorUnitAmount::new(15_000), Currency::EGP)
            .with_payment_methods(vec!["4097558".to_owned()])
            .with_extras(serde_json::json!({"merchant_tag": "vip"}));
        let wired = ext.apply_to_session_request(base).expect("wired");
        assert_eq!(wired.pre_selected_plan, Some(42));
        assert_eq!(wired.special_reference.as_deref(), Some("ORD-1"));
        let extras = wired.extras.as_ref().expect("extras object");
        assert_eq!(extras["merchant_tag"], "vip");
        assert!(extras.get("split_description").is_some());
    }

    #[test]
    fn paymob_ext_rejects_invalid_plan_splits_and_blank_wallet() {
        let bad_plan = PaymobExt::new().with_pre_selected_plan(0);
        assert!(matches!(
            bad_plan.validate(),
            Err(PaymobError::ValidationError {
                field: "pre_selected_plan",
                ..
            })
        ));

        let bad_wallet = PaymobExt::new().with_mobile_wallet("   ");
        assert!(matches!(
            bad_wallet.validate(),
            Err(PaymobError::ValidationError {
                field: "phone_number",
                ..
            })
        ));

        let empty_splits = PaymobExt::new().with_split_description(vec![]);
        assert!(matches!(
            empty_splits.validate(),
            Err(PaymobError::ValidationError {
                field: "split_description",
                ..
            })
        ));

        let invalid_rule =
            PaymobExt::new().with_split_description(vec![SplitRecipientRule::fixed("   ", 100)]);
        assert!(matches!(
            invalid_rule.validate(),
            Err(PaymobError::ValidationError {
                field: "recipient_id",
                ..
            })
        ));
    }

    #[test]
    fn headless_wallet_redacts_phone_and_builds_params() {
        let ext = PaymobExt::new().with_mobile_wallet("01012345678");
        let dbg = format!("{ext:?}");
        assert!(!dbg.contains("01012345678"));
        assert!(dbg.contains("[REDACTED]"));

        let wallet = ext.build_wallet_pay_params("tok_123").expect("wallet");
        assert_eq!(wallet.wallet_phone(), "01012345678");
        assert!(ext.build_kiosk_pay_params("tok_123").is_err());

        let kiosk_ext = PaymobExt::new().with_kiosk();
        assert!(kiosk_ext.build_kiosk_pay_params("tok_123").is_ok());
        assert!(kiosk_ext.build_wallet_pay_params("tok_123").is_err());
    }
}
