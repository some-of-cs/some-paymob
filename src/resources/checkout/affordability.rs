#![forbid(unsafe_code)]
//! Bank installment Affordability Widget configuration & plan wiring (`US-2.2.0` Unit 3).
//!
//! Provides [`AffordabilityWidgetConfig`] and [`AffordabilityWidgetConfigBuilder`]
//! using strictly integer minor-unit amounts ([`MinorUnitAmount`], zero floats)
//! and [`PublicKey`] (`pk_*`), plus helper
//! methods for wiring selected installment plan IDs into
//! `CreateIntentionParams::pre_selected_plan`.

use serde::{Deserialize, Deserializer, Serialize};

use crate::core::client::PaymobClient;
use crate::core::credentials::PublicKey;
use crate::core::error::PaymobError;
use crate::core::types::{Currency, MinorUnitAmount};
use crate::resources::intentions::params::CreateIntentionParamsBuilder;

/// Frontend configuration for Paymob's bank installment Affordability Widget.
///
/// Uses [`MinorUnitAmount`] (`u64`) with zero floating-point types and never
/// reads server-side `SecretKey` or `ApiKey` credentials.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::credentials::PublicKey;
/// use some_paymob::core::types::{Currency, MinorUnitAmount};
/// use some_paymob::resources::checkout::affordability::AffordabilityWidgetConfig;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let pk = PublicKey::new("egy_pk_test_ABC")?;
/// let widget = AffordabilityWidgetConfig::builder(&pk, MinorUnitAmount::new(500_000), Currency::EGP)
///     .pre_selected_plan(42)
///     .supported_banks(["CIB", "NBE"])
///     .tenure_months(12)
///     .build()?;
///
/// let mut pre_selected_plan: Option<u64> = None;
/// widget.apply_to_pre_selected_plan(&mut pre_selected_plan)?;
/// assert_eq!(pre_selected_plan, Some(42));
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AffordabilityWidgetConfig {
    /// Client-side Paymob public key (`pk_*`).
    pub public_key: String,
    /// Order total in integer minor units (for example, piasters or halalas).
    #[serde(rename = "amount_cents")]
    pub amount: MinorUnitAmount,
    /// ISO-4217 currency code for installment calculation.
    pub currency: Currency,
    /// Optional pre-selected bank installment plan ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pre_selected_plan: Option<u64>,
    /// Optional bank codes/identifiers to display in the widget.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_banks: Vec<String>,
    /// Optional installment tenure filter in months.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenure_months: Option<u16>,
    /// Optional integer minor-unit down payment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub down_payment: Option<MinorUnitAmount>,
}

#[derive(Deserialize)]
struct RawAffordabilityWidgetConfig {
    public_key: String,
    #[serde(rename = "amount_cents")]
    amount: MinorUnitAmount,
    currency: Currency,
    #[serde(default)]
    pre_selected_plan: Option<u64>,
    #[serde(default)]
    supported_banks: Vec<String>,
    #[serde(default)]
    tenure_months: Option<u16>,
    #[serde(default)]
    down_payment: Option<MinorUnitAmount>,
}

impl<'de> Deserialize<'de> for AffordabilityWidgetConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawAffordabilityWidgetConfig::deserialize(deserializer)?;
        let config = Self {
            public_key: raw.public_key,
            amount: raw.amount,
            currency: raw.currency,
            pre_selected_plan: raw.pre_selected_plan,
            supported_banks: raw.supported_banks,
            tenure_months: raw.tenure_months,
            down_payment: raw.down_payment,
        };
        validate_affordability_inputs(&config).map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

impl AffordabilityWidgetConfig {
    /// Creates an [`AffordabilityWidgetConfigBuilder`] from a [`PublicKey`],
    /// integer [`MinorUnitAmount`], and [`Currency`].
    ///
    /// # Compile-Time Key Role Separation
    ///
    /// Passing a [`SecretKey`](crate::core::credentials::SecretKey) instead of a
    /// [`PublicKey`] fails at compile time:
    ///
    /// ```compile_fail
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::core::types::{Currency, MinorUnitAmount};
    /// use some_paymob::resources::checkout::affordability::AffordabilityWidgetConfig;
    ///
    /// let sk = SecretKey::new("egy_sk_test_123").unwrap();
    /// let _ = AffordabilityWidgetConfig::builder(&sk, MinorUnitAmount::new(50_000), Currency::EGP);
    /// ```
    #[must_use]
    pub fn builder(
        public_key: &PublicKey,
        amount: MinorUnitAmount,
        currency: Currency,
    ) -> AffordabilityWidgetConfigBuilder {
        AffordabilityWidgetConfigBuilder::new(public_key, amount, currency)
    }

    /// Creates an [`AffordabilityWidgetConfigBuilder`] using the [`PublicKey`]
    /// configured on `client`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `public_key` is missing on
    /// [`ClientConfig`](crate::core::config::ClientConfig).
    pub fn from_client(
        client: &PaymobClient,
        amount: MinorUnitAmount,
        currency: Currency,
    ) -> Result<AffordabilityWidgetConfigBuilder, PaymobError> {
        let public_key =
            client
                .config()
                .public_key()
                .ok_or_else(|| PaymobError::ValidationError {
                    field: "public_key",
                    reason:
                        "public_key must be configured on ClientConfig to build AffordabilityWidgetConfig"
                            .to_owned(),
                })?;
        Ok(Self::builder(public_key, amount, currency))
    }

    /// Returns the order amount in raw integer minor units (`u64`).
    #[must_use]
    pub const fn amount_cents(&self) -> u64 {
        self.amount.as_u64()
    }

    /// Returns the optional pre-selected installment plan ID.
    #[must_use]
    pub const fn selected_plan_id(&self) -> Option<u64> {
        self.pre_selected_plan
    }

    /// Returns the selected installment plan ID or fails if none is selected.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `pre_selected_plan` is `None` or `0`.
    pub fn require_selected_plan_id(&self) -> Result<u64, PaymobError> {
        match self.pre_selected_plan {
            Some(id) if id > 0 => Ok(id),
            _ => Err(PaymobError::ValidationError {
                field: "pre_selected_plan",
                reason: "a non-zero installment plan ID must be selected".to_owned(),
            }),
        }
    }

    /// Updates `pre_selected_plan` with a validated non-zero installment plan ID.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `plan_id == 0`.
    pub fn with_selected_plan(mut self, plan_id: u64) -> Result<Self, PaymobError> {
        validate_plan_id(plan_id)?;
        self.pre_selected_plan = Some(plan_id);
        Ok(self)
    }

    /// Wires `self.pre_selected_plan` into a target `Option<u64>` field
    /// (such as `CreateIntentionParams::pre_selected_plan`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `pre_selected_plan` is `None` or `0`.
    pub fn apply_to_pre_selected_plan(&self, target: &mut Option<u64>) -> Result<(), PaymobError> {
        let plan_id = self.require_selected_plan_id()?;
        *target = Some(plan_id);
        Ok(())
    }

    /// Wires `self.pre_selected_plan` directly into a [`CreateIntentionParamsBuilder`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `pre_selected_plan` is `None` or `0`.
    pub fn apply_to_intention_builder(
        &self,
        builder: CreateIntentionParamsBuilder,
    ) -> Result<CreateIntentionParamsBuilder, PaymobError> {
        let plan_id = self.require_selected_plan_id()?;
        Ok(builder.pre_selected_plan(plan_id))
    }

    /// Serializes this widget configuration into a JSON string.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if serialization fails.
    pub fn to_json(&self) -> Result<String, PaymobError> {
        serde_json::to_string(self).map_err(|err| PaymobError::ValidationError {
            field: "affordability_widget",
            reason: format!("failed to serialize AffordabilityWidgetConfig: {err}"),
        })
    }
}

/// Fluent builder for [`AffordabilityWidgetConfig`].
#[derive(Debug, Clone)]
pub struct AffordabilityWidgetConfigBuilder {
    public_key: String,
    amount: MinorUnitAmount,
    currency: Currency,
    pre_selected_plan: Option<u64>,
    supported_banks: Vec<String>,
    tenure_months: Option<u16>,
    down_payment: Option<MinorUnitAmount>,
}

impl AffordabilityWidgetConfigBuilder {
    /// Initializes a new [`AffordabilityWidgetConfigBuilder`].
    #[must_use]
    pub fn new(public_key: &PublicKey, amount: MinorUnitAmount, currency: Currency) -> Self {
        Self {
            public_key: public_key.expose_secret().trim().to_owned(),
            amount,
            currency,
            pre_selected_plan: None,
            supported_banks: Vec::new(),
            tenure_months: None,
            down_payment: None,
        }
    }

    /// Sets the pre-selected installment plan ID.
    #[must_use]
    pub const fn pre_selected_plan(mut self, plan_id: u64) -> Self {
        self.pre_selected_plan = Some(plan_id);
        self
    }

    /// Sets the supported bank codes for the widget.
    #[must_use]
    pub fn supported_banks<I, S>(mut self, banks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.supported_banks = banks.into_iter().map(Into::into).collect();
        self
    }

    /// Sets the desired installment tenure in months.
    #[must_use]
    pub const fn tenure_months(mut self, months: u16) -> Self {
        self.tenure_months = Some(months);
        self
    }

    /// Sets an integer minor-unit down payment.
    #[must_use]
    pub const fn down_payment(mut self, down_payment: MinorUnitAmount) -> Self {
        self.down_payment = Some(down_payment);
        self
    }

    /// Validates invariants and constructs an [`AffordabilityWidgetConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `public_key` is empty or uses
    /// an `sk_*` prefix, `amount` is zero, `down_payment` exceeds `amount`,
    /// `pre_selected_plan` is `Some(0)`, or `tenure_months` is `Some(0)`.
    pub fn build(self) -> Result<AffordabilityWidgetConfig, PaymobError> {
        let config = AffordabilityWidgetConfig {
            public_key: self.public_key,
            amount: self.amount,
            currency: self.currency,
            pre_selected_plan: self.pre_selected_plan,
            supported_banks: self.supported_banks,
            tenure_months: self.tenure_months,
            down_payment: self.down_payment,
        };
        validate_affordability_inputs(&config)?;
        Ok(config)
    }
}

fn validate_plan_id(plan_id: u64) -> Result<(), PaymobError> {
    if plan_id == 0 {
        return Err(PaymobError::ValidationError {
            field: "pre_selected_plan",
            reason: "pre_selected_plan must be greater than zero".to_owned(),
        });
    }
    Ok(())
}

fn validate_affordability_inputs(config: &AffordabilityWidgetConfig) -> Result<(), PaymobError> {
    validate_affordability_core(&config.public_key, config.amount)?;
    validate_affordability_options(config)
}

fn validate_affordability_core(
    public_key: &str,
    amount: MinorUnitAmount,
) -> Result<(), PaymobError> {
    super::unified::validate_public_key_str(public_key, "AffordabilityWidgetConfig")?;
    if amount.is_zero() {
        return Err(PaymobError::ValidationError {
            field: "amount",
            reason: "amount must be greater than zero minor units".to_owned(),
        });
    }
    Ok(())
}

fn validate_affordability_options(config: &AffordabilityWidgetConfig) -> Result<(), PaymobError> {
    if config.pre_selected_plan == Some(0) {
        return Err(PaymobError::ValidationError {
            field: "pre_selected_plan",
            reason: "pre_selected_plan must be greater than zero".to_owned(),
        });
    }
    if config.tenure_months == Some(0) {
        return Err(PaymobError::ValidationError {
            field: "tenure_months",
            reason: "tenure_months must be greater than zero".to_owned(),
        });
    }
    if config.down_payment.unwrap_or(MinorUnitAmount::ZERO) > config.amount {
        return Err(PaymobError::ValidationError {
            field: "down_payment",
            reason: "down_payment must not exceed total amount".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::SecretKey;
    use crate::core::region::PaymobRegion;
    use crate::resources::intentions::{BillingData, CreateIntentionParams, PaymentMethodInput};

    #[test]
    fn tc_2_2_3_affordability_widget_builds_and_wires_plan_id() {
        let pk = PublicKey::new("egy_pk_test_ABC").expect("valid pk");
        let widget =
            AffordabilityWidgetConfig::builder(&pk, MinorUnitAmount::new(100_000), Currency::EGP)
                .pre_selected_plan(77)
                .supported_banks(["CIB", "NBE"])
                .tenure_months(12)
                .down_payment(MinorUnitAmount::new(10_000))
                .build()
                .expect("valid widget config");

        assert_eq!(widget.amount_cents(), 100_000);
        assert_eq!(widget.selected_plan_id(), Some(77));
        assert_eq!(widget.require_selected_plan_id().unwrap(), 77);

        let mut target_plan: Option<u64> = None;
        widget
            .apply_to_pre_selected_plan(&mut target_plan)
            .expect("plan wiring should succeed");
        assert_eq!(target_plan, Some(77));

        let json = widget.to_json().expect("json serialization");
        assert!(json.contains("\"amount_cents\":100000"));
        assert!(json.contains("\"currency\":\"EGP\""));
        assert!(json.contains("\"pre_selected_plan\":77"));
    }

    #[test]
    fn tc_2_2_3_from_client_missing_public_key_fails_closed() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_only").expect("valid sk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("valid client");
        let err = AffordabilityWidgetConfig::from_client(
            &client,
            MinorUnitAmount::new(50_000),
            Currency::EGP,
        )
        .expect_err("missing public_key must fail closed");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "public_key",
                ..
            }
        ));
    }

    #[test]
    fn tc_2_2_3_rejects_zero_amount_invalid_plan_and_excess_down_payment() {
        let pk = PublicKey::new("egy_pk_test_ABC").expect("valid pk");

        let zero_amt =
            AffordabilityWidgetConfig::builder(&pk, MinorUnitAmount::ZERO, Currency::EGP)
                .build()
                .expect_err("zero amount must fail");
        assert!(matches!(
            zero_amt,
            PaymobError::ValidationError {
                field: "amount",
                ..
            }
        ));

        let zero_plan =
            AffordabilityWidgetConfig::builder(&pk, MinorUnitAmount::new(50_000), Currency::EGP)
                .pre_selected_plan(0)
                .build()
                .expect_err("zero plan must fail");
        assert!(matches!(
            zero_plan,
            PaymobError::ValidationError {
                field: "pre_selected_plan",
                ..
            }
        ));

        let excess_dp =
            AffordabilityWidgetConfig::builder(&pk, MinorUnitAmount::new(50_000), Currency::EGP)
                .down_payment(MinorUnitAmount::new(60_000))
                .build()
                .expect_err("down_payment > amount must fail");
        assert!(matches!(
            excess_dp,
            PaymobError::ValidationError {
                field: "down_payment",
                ..
            }
        ));
    }

    #[test]
    fn tc_2_2_3_with_selected_plan_updates_and_validates() {
        let pk = PublicKey::new("egy_pk_test_ABC").expect("valid pk");
        let widget =
            AffordabilityWidgetConfig::builder(&pk, MinorUnitAmount::new(25_000), Currency::SAR)
                .build()
                .expect("valid widget");
        assert!(widget.require_selected_plan_id().is_err());

        let updated = widget.with_selected_plan(99).expect("valid plan");
        assert_eq!(updated.selected_plan_id(), Some(99));
        assert!(updated.with_selected_plan(0).is_err());
    }

    #[test]
    fn tc_2_2_3_cycle2_deserialize_enforces_bounds_and_rejects_sk() {
        let valid_json = r#"{
            "public_key": "egy_pk_test_ABC",
            "amount_cents": 150000,
            "currency": "EGP",
            "pre_selected_plan": 12,
            "tenure_months": 6,
            "down_payment": 25000
        }"#;
        let parsed: AffordabilityWidgetConfig = serde_json::from_str(valid_json)
            .expect("valid AffordabilityWidgetConfig JSON should deserialize");
        assert_eq!(parsed.amount_cents(), 150_000);
        assert_eq!(parsed.selected_plan_id(), Some(12));

        let invalid_payloads = [
            r#"{"public_key":"","amount_cents":10000,"currency":"EGP"}"#,
            r#"{"public_key":"egy_sk_test_123","amount_cents":10000,"currency":"EGP"}"#,
            r#"{"public_key":"egy_pk_test_123","amount_cents":0,"currency":"EGP"}"#,
            r#"{"public_key":"egy_pk_test_123","amount_cents":10000,"currency":"EGP","pre_selected_plan":0}"#,
            r#"{"public_key":"egy_pk_test_123","amount_cents":10000,"currency":"EGP","tenure_months":0}"#,
            r#"{"public_key":"egy_pk_test_123","amount_cents":10000,"currency":"EGP","down_payment":20000}"#,
        ];
        for payload in invalid_payloads {
            assert!(
                serde_json::from_str::<AffordabilityWidgetConfig>(payload).is_err(),
                "expected AffordabilityWidgetConfig deserialization to reject: {payload}"
            );
        }
    }

    #[test]
    fn tc_2_2_3_cycle2_checkout_facade_and_apply_to_intention_builder() {
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .public_key(PublicKey::new("egy_pk_test_WIDGET").expect("valid pk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");
        let widget = client
            .checkout()
            .affordability_widget(200_000_u64, Currency::EGP)
            .expect("affordability_widget builder")
            .pre_selected_plan(55)
            .build()
            .expect("valid widget");

        let billing = BillingData::builder()
            .first_name("Maher")
            .last_name("Mansour")
            .email("maher@example.com")
            .phone_number("+201000000000")
            .build()
            .expect("valid billing");
        let intention_builder = CreateIntentionParams::builder()
            .amount(200_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![PaymentMethodInput::IntegrationId(123)])
            .billing_data(billing);
        let wired_params = widget
            .apply_to_intention_builder(intention_builder)
            .expect("apply_to_intention_builder should succeed")
            .build()
            .expect("valid CreateIntentionParams");
        assert_eq!(wired_params.pre_selected_plan(), Some(55));
    }

    #[test]
    fn res1_05_affordability_rejects_bad_pk_prefix_and_control_chars() {
        let bad_prefix =
            r#"{"public_key":"invalid_key_123","amount_cents":10000,"currency":"EGP"}"#;
        assert!(serde_json::from_str::<AffordabilityWidgetConfig>(bad_prefix).is_err());

        let ctrl_pk = r#"{"public_key":"egy_pk_test_
123","amount_cents":10000,"currency":"EGP"}"#;
        assert!(serde_json::from_str::<AffordabilityWidgetConfig>(ctrl_pk).is_err());
    }
}
