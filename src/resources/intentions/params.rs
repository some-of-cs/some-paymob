#![forbid(unsafe_code)]
//! Request parameters and validated builders for Paymob v1 Payment Intentions.
//!
//! Provides [`PaymentMethodInput`], [`CreateIntentionParams`], and
//! [`UpdateIntentionParams`] with zero-float minor-unit amounts, untagged
//! integration ID / method name serialization, builder-time and
//! deserialization-time validation, and `ZeroizeOnDrop` hygiene for saved
//! `card_tokens`.

use std::fmt;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use url::Url;
use zeroize::Zeroize;

use crate::core::error::PaymobError;
use crate::core::types::{Currency, MinorUnitAmount};

use super::billing::{BillingData, IntentionCustomer, IntentionItem};

const REDACTED: &str = "[REDACTED]";

/// Payment method selector accepted by `POST` and `PUT /v1/intention/`.
///
/// Serializes untagged as either a numeric Paymob integration ID (`4097558`)
/// or a payment method alias string (`"card"`).
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::intentions::params::PaymentMethodInput;
///
/// let by_id = PaymentMethodInput::IntegrationId(4_097_558);
/// let by_name = PaymentMethodInput::MethodName("card".to_owned());
///
/// assert_eq!(serde_json::to_string(&by_id).unwrap(), "4097558");
/// assert_eq!(serde_json::to_string(&by_name).unwrap(), "\"card\"");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PaymentMethodInput {
    /// Numeric Paymob integration identifier from the Merchant Dashboard.
    IntegrationId(u64),
    /// Named payment method alias (for example `"card"` or `"wallet"`).
    MethodName(String),
}

impl PaymentMethodInput {
    /// Returns the numeric integration ID if this variant is [`Self::IntegrationId`].
    #[must_use]
    pub const fn as_integration_id(&self) -> Option<u64> {
        match self {
            Self::IntegrationId(id) => Some(*id),
            Self::MethodName(_) => None,
        }
    }

    /// Returns the method name slice if this variant is [`Self::MethodName`].
    #[must_use]
    pub fn as_method_name(&self) -> Option<&str> {
        match self {
            Self::IntegrationId(_) => None,
            Self::MethodName(name) => Some(name.as_str()),
        }
    }
}

/// Validated request payload for `POST /v1/intention/`.
///
/// Construct via [`CreateIntentionParams::builder`] to enforce positive
/// minor-unit `amount`, non-empty `currency` and `payment_methods`, valid
/// line items, and mandatory `billing_data.phone_number` before network I/O.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::{Currency, MinorUnitAmount};
/// use some_paymob::resources::intentions::billing::BillingData;
/// use some_paymob::resources::intentions::params::{
///     CreateIntentionParams, PaymentMethodInput,
/// };
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let billing = BillingData::builder()
///     .phone_number("+201116491564")
///     .build()?;
///
/// let params = CreateIntentionParams::builder()
///     .amount(MinorUnitAmount::new(100_000))
///     .currency(Currency::EGP)
///     .payment_methods(vec![
///         PaymentMethodInput::IntegrationId(4_097_558),
///         PaymentMethodInput::MethodName("card".to_owned()),
///     ])
///     .billing_data(billing)
///     .build()?;
///
/// assert_eq!(params.amount().as_u64(), 100_000);
/// # Ok(())
/// # }
/// ```
///
/// Direct struct literal construction is rejected at compile time so callers
/// cannot bypass [`CreateIntentionParamsBuilder::build`]:
///
/// ```compile_fail
/// use some_paymob::core::types::{Currency, MinorUnitAmount};
/// use some_paymob::resources::intentions::params::CreateIntentionParams;
///
/// let _ = CreateIntentionParams {
///     amount: MinorUnitAmount::ZERO,
///     currency: Currency::EGP,
///     payment_methods: vec![],
///     items: None,
///     billing_data: None,
///     customer: None,
///     extras: None,
///     special_reference: None,
///     expiration: None,
///     notification_url: None,
///     redirection_url: None,
///     pre_selected_plan: None,
///     card_tokens: None,
/// };
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CreateIntentionParams {
    amount: MinorUnitAmount,
    currency: Currency,
    payment_methods: Vec<PaymentMethodInput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<Vec<IntentionItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_data: Option<BillingData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer: Option<IntentionCustomer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extras: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    special_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirection_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_selected_plan: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card_tokens: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawCreateIntentionParams {
    amount: MinorUnitAmount,
    currency: Currency,
    payment_methods: Vec<PaymentMethodInput>,
    #[serde(default)]
    items: Option<Vec<IntentionItem>>,
    #[serde(default)]
    billing_data: Option<BillingData>,
    #[serde(default)]
    customer: Option<IntentionCustomer>,
    #[serde(default)]
    extras: Option<serde_json::Value>,
    #[serde(default)]
    special_reference: Option<String>,
    #[serde(default)]
    expiration: Option<u64>,
    #[serde(default)]
    notification_url: Option<String>,
    #[serde(default)]
    redirection_url: Option<String>,
    #[serde(default)]
    pre_selected_plan: Option<u64>,
    #[serde(default)]
    card_tokens: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for CreateIntentionParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawCreateIntentionParams::deserialize(deserializer)?;
        from_raw_create_params(raw).map_err(D::Error::custom)
    }
}

fn from_raw_create_params(
    raw: RawCreateIntentionParams,
) -> Result<CreateIntentionParams, PaymobError> {
    CreateIntentionParamsBuilder {
        amount: Some(raw.amount),
        currency: Some(raw.currency),
        payment_methods: Some(raw.payment_methods),
        items: raw.items,
        billing_data: raw.billing_data,
        customer: raw.customer,
        extras: raw.extras,
        special_reference: raw.special_reference.and_then(trim_opt),
        expiration: raw.expiration,
        notification_url: raw.notification_url.and_then(trim_opt),
        redirection_url: raw.redirection_url.and_then(trim_opt),
        pre_selected_plan: raw.pre_selected_plan,
        card_tokens: raw.card_tokens,
    }
    .build()
}

impl Drop for CreateIntentionParams {
    fn drop(&mut self) {
        zeroize_card_tokens(&mut self.card_tokens);
    }
}

impl CreateIntentionParams {
    /// Re-validates all required and optional intention creation invariants.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any required or optional field
    /// violates Paymob's intention constraints.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_required_amount(Some(self.amount))?;
        validate_currency_value(&self.currency)?;
        validate_methods_slice(&self.payment_methods)?;
        validate_common_optional_fields(
            self.items.as_deref(),
            self.notification_url.as_deref(),
            self.redirection_url.as_deref(),
            self.expiration,
            self.pre_selected_plan,
            self.card_tokens.as_deref(),
        )
    }
    /// Creates a new [`CreateIntentionParamsBuilder`].
    #[must_use]
    pub fn builder() -> CreateIntentionParamsBuilder {
        CreateIntentionParamsBuilder::new()
    }

    /// Returns the total payment amount in integer minor units.
    #[must_use]
    pub const fn amount(&self) -> MinorUnitAmount {
        self.amount
    }

    /// Returns the ISO currency code.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Returns the configured payment methods or integration IDs.
    #[must_use]
    pub fn payment_methods(&self) -> &[PaymentMethodInput] {
        &self.payment_methods
    }

    /// Returns the optional line items.
    #[must_use]
    pub fn items(&self) -> Option<&[IntentionItem]> {
        self.items.as_deref()
    }

    /// Returns the optional billing data.
    #[must_use]
    pub const fn billing_data(&self) -> Option<&BillingData> {
        self.billing_data.as_ref()
    }

    /// Returns the optional customer profile.
    #[must_use]
    pub const fn customer(&self) -> Option<&IntentionCustomer> {
        self.customer.as_ref()
    }

    /// Returns the optional merchant `extras` JSON object.
    #[must_use]
    pub const fn extras(&self) -> Option<&serde_json::Value> {
        self.extras.as_ref()
    }

    /// Returns the optional merchant `special_reference`.
    #[must_use]
    pub fn special_reference(&self) -> Option<&str> {
        self.special_reference.as_deref()
    }

    /// Returns the optional intention expiration in seconds.
    #[must_use]
    pub const fn expiration(&self) -> Option<u64> {
        self.expiration
    }

    /// Returns the optional webhook `notification_url`.
    #[must_use]
    pub fn notification_url(&self) -> Option<&str> {
        self.notification_url.as_deref()
    }

    /// Returns the optional post-checkout `redirection_url`.
    #[must_use]
    pub fn redirection_url(&self) -> Option<&str> {
        self.redirection_url.as_deref()
    }

    /// Returns the optional installment `pre_selected_plan` ID.
    #[must_use]
    pub const fn pre_selected_plan(&self) -> Option<u64> {
        self.pre_selected_plan
    }
}

impl fmt::Debug for CreateIntentionParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateIntentionParams")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("payment_methods", &self.payment_methods)
            .field("items", &self.items)
            .field("billing_data", &self.billing_data)
            .field("customer", &self.customer)
            .field("special_reference", &self.special_reference)
            .field("expiration", &self.expiration)
            .field("notification_url", &self.notification_url)
            .field("redirection_url", &self.redirection_url)
            .field("pre_selected_plan", &self.pre_selected_plan)
            .field("card_tokens", &self.card_tokens.as_ref().map(|_| REDACTED))
            .finish_non_exhaustive()
    }
}

/// Builder for [`CreateIntentionParams`].
#[derive(Clone, Default)]
pub struct CreateIntentionParamsBuilder {
    amount: Option<MinorUnitAmount>,
    currency: Option<Currency>,
    payment_methods: Option<Vec<PaymentMethodInput>>,
    items: Option<Vec<IntentionItem>>,
    billing_data: Option<BillingData>,
    customer: Option<IntentionCustomer>,
    extras: Option<serde_json::Value>,
    special_reference: Option<String>,
    expiration: Option<u64>,
    notification_url: Option<String>,
    redirection_url: Option<String>,
    pre_selected_plan: Option<u64>,
    card_tokens: Option<Vec<String>>,
}

impl Drop for CreateIntentionParamsBuilder {
    fn drop(&mut self) {
        zeroize_card_tokens(&mut self.card_tokens);
    }
}

impl CreateIntentionParamsBuilder {
    /// Creates an empty [`CreateIntentionParamsBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the total payment amount in integer minor units.
    #[must_use]
    pub fn amount(mut self, amount: impl Into<MinorUnitAmount>) -> Self {
        self.amount = Some(amount.into());
        self
    }

    /// Sets the ISO currency code.
    #[must_use]
    pub fn currency(mut self, currency: Currency) -> Self {
        self.currency = Some(currency);
        self
    }

    /// Sets the list of payment methods or integration IDs.
    #[must_use]
    pub fn payment_methods(mut self, payment_methods: Vec<PaymentMethodInput>) -> Self {
        self.payment_methods = Some(payment_methods);
        self
    }

    /// Sets the optional line items.
    #[must_use]
    pub fn items(mut self, items: Vec<IntentionItem>) -> Self {
        self.items = Some(items);
        self
    }

    /// Sets the optional billing data.
    #[must_use]
    pub fn billing_data(mut self, billing_data: BillingData) -> Self {
        self.billing_data = Some(billing_data);
        self
    }

    /// Sets the optional customer profile.
    #[must_use]
    pub fn customer(mut self, customer: IntentionCustomer) -> Self {
        self.customer = Some(customer);
        self
    }

    /// Sets the optional merchant `extras` JSON object.
    #[must_use]
    pub fn extras(mut self, extras: serde_json::Value) -> Self {
        self.extras = Some(extras);
        self
    }

    /// Sets the optional merchant `special_reference`.
    #[must_use]
    pub fn special_reference(mut self, special_reference: impl Into<String>) -> Self {
        self.special_reference = trim_opt(special_reference.into());
        self
    }

    /// Sets the optional intention expiration in seconds.
    #[must_use]
    pub const fn expiration(mut self, expiration: u64) -> Self {
        self.expiration = Some(expiration);
        self
    }

    /// Sets the optional webhook `notification_url`.
    #[must_use]
    pub fn notification_url(mut self, notification_url: impl Into<String>) -> Self {
        self.notification_url = trim_opt(notification_url.into());
        self
    }

    /// Sets the optional post-checkout `redirection_url`.
    #[must_use]
    pub fn redirection_url(mut self, redirection_url: impl Into<String>) -> Self {
        self.redirection_url = trim_opt(redirection_url.into());
        self
    }

    /// Sets the optional installment `pre_selected_plan` ID.
    #[must_use]
    pub const fn pre_selected_plan(mut self, pre_selected_plan: u64) -> Self {
        self.pre_selected_plan = Some(pre_selected_plan);
        self
    }

    /// Sets optional saved `card_tokens` for one-click / MIT checkout.
    #[must_use]
    pub fn card_tokens(mut self, mut card_tokens: Vec<String>) -> Self {
        zeroize_card_tokens(&mut self.card_tokens);
        self.card_tokens = Some(std::mem::take(&mut card_tokens));
        self
    }

    /// Validates all invariants and builds [`CreateIntentionParams`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `amount` is missing or zero,
    /// `currency` is missing or empty, `payment_methods` is empty or invalid,
    /// or any optional URL, item, expiration, plan, or card token fails validation.
    pub fn build(mut self) -> Result<CreateIntentionParams, PaymobError> {
        let amount = validate_required_amount(self.amount)?;
        let currency = validate_required_currency(self.currency.take())?;
        let payment_methods = validate_required_methods(self.payment_methods.take())?;
        validate_common_optional_fields(
            self.items.as_deref(),
            self.notification_url.as_deref(),
            self.redirection_url.as_deref(),
            self.expiration,
            self.pre_selected_plan,
            self.card_tokens.as_deref(),
        )?;

        Ok(CreateIntentionParams {
            amount,
            currency,
            payment_methods,
            items: self.items.take(),
            billing_data: self.billing_data.take(),
            customer: self.customer.take(),
            extras: self.extras.take(),
            special_reference: self.special_reference.take(),
            expiration: self.expiration,
            notification_url: self.notification_url.take(),
            redirection_url: self.redirection_url.take(),
            pre_selected_plan: self.pre_selected_plan,
            card_tokens: self.card_tokens.take(),
        })
    }
}

impl fmt::Debug for CreateIntentionParamsBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateIntentionParamsBuilder")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("payment_methods", &self.payment_methods)
            .field("card_tokens", &self.card_tokens.as_ref().map(|_| REDACTED))
            .finish_non_exhaustive()
    }
}

/// Validated request payload for `PUT /v1/intention/`.
///
/// Construct via [`UpdateIntentionParams::builder`]. At least one updatable
/// field must be provided.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::resources::intentions::params::UpdateIntentionParams;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let update = UpdateIntentionParams::builder()
///     .amount(MinorUnitAmount::new(120_000))
///     .special_reference("order-123-v2")
///     .build()?;
///
/// assert_eq!(update.amount().map(MinorUnitAmount::as_u64), Some(120_000));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct UpdateIntentionParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<MinorUnitAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<Currency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payment_methods: Option<Vec<PaymentMethodInput>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    items: Option<Vec<IntentionItem>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    billing_data: Option<BillingData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    customer: Option<IntentionCustomer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extras: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    special_reference: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notification_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirection_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_selected_plan: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    card_tokens: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawUpdateIntentionParams {
    #[serde(default)]
    amount: Option<MinorUnitAmount>,
    #[serde(default)]
    currency: Option<Currency>,
    #[serde(default)]
    payment_methods: Option<Vec<PaymentMethodInput>>,
    #[serde(default)]
    items: Option<Vec<IntentionItem>>,
    #[serde(default)]
    billing_data: Option<BillingData>,
    #[serde(default)]
    customer: Option<IntentionCustomer>,
    #[serde(default)]
    extras: Option<serde_json::Value>,
    #[serde(default)]
    special_reference: Option<String>,
    #[serde(default)]
    expiration: Option<u64>,
    #[serde(default)]
    notification_url: Option<String>,
    #[serde(default)]
    redirection_url: Option<String>,
    #[serde(default)]
    pre_selected_plan: Option<u64>,
    #[serde(default)]
    card_tokens: Option<Vec<String>>,
}

impl<'de> Deserialize<'de> for UpdateIntentionParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawUpdateIntentionParams::deserialize(deserializer)?;
        from_raw_update_params(raw).map_err(D::Error::custom)
    }
}

fn from_raw_update_params(
    raw: RawUpdateIntentionParams,
) -> Result<UpdateIntentionParams, PaymobError> {
    UpdateIntentionParamsBuilder {
        amount: raw.amount,
        currency: raw.currency,
        payment_methods: raw.payment_methods,
        items: raw.items,
        billing_data: raw.billing_data,
        customer: raw.customer,
        extras: raw.extras,
        special_reference: raw.special_reference.and_then(trim_opt),
        expiration: raw.expiration,
        notification_url: raw.notification_url.and_then(trim_opt),
        redirection_url: raw.redirection_url.and_then(trim_opt),
        pre_selected_plan: raw.pre_selected_plan,
        card_tokens: raw.card_tokens,
    }
    .build()
}

impl Drop for UpdateIntentionParams {
    fn drop(&mut self) {
        zeroize_card_tokens(&mut self.card_tokens);
    }
}

impl UpdateIntentionParams {
    /// Re-validates all populated intention update fields and ensures at least
    /// one field is present.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if no fields are set or any
    /// populated field fails validation.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_update_params(self)
    }
    /// Creates a new [`UpdateIntentionParamsBuilder`].
    #[must_use]
    pub fn builder() -> UpdateIntentionParamsBuilder {
        UpdateIntentionParamsBuilder::new()
    }

    /// Returns the updated minor-unit amount, if set.
    #[must_use]
    pub const fn amount(&self) -> Option<MinorUnitAmount> {
        self.amount
    }

    /// Returns the updated currency, if set.
    #[must_use]
    pub const fn currency(&self) -> Option<&Currency> {
        self.currency.as_ref()
    }

    /// Returns the updated payment methods, if set.
    #[must_use]
    pub fn payment_methods(&self) -> Option<&[PaymentMethodInput]> {
        self.payment_methods.as_deref()
    }

    /// Returns the updated merchant `special_reference`, if set.
    #[must_use]
    pub fn special_reference(&self) -> Option<&str> {
        self.special_reference.as_deref()
    }
}

impl fmt::Debug for UpdateIntentionParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateIntentionParams")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("payment_methods", &self.payment_methods)
            .field("billing_data", &self.billing_data)
            .field("customer", &self.customer)
            .field("special_reference", &self.special_reference)
            .field("card_tokens", &self.card_tokens.as_ref().map(|_| REDACTED))
            .finish_non_exhaustive()
    }
}

/// Builder for [`UpdateIntentionParams`].
#[derive(Clone, Default)]
pub struct UpdateIntentionParamsBuilder {
    amount: Option<MinorUnitAmount>,
    currency: Option<Currency>,
    payment_methods: Option<Vec<PaymentMethodInput>>,
    items: Option<Vec<IntentionItem>>,
    billing_data: Option<BillingData>,
    customer: Option<IntentionCustomer>,
    extras: Option<serde_json::Value>,
    special_reference: Option<String>,
    expiration: Option<u64>,
    notification_url: Option<String>,
    redirection_url: Option<String>,
    pre_selected_plan: Option<u64>,
    card_tokens: Option<Vec<String>>,
}

impl Drop for UpdateIntentionParamsBuilder {
    fn drop(&mut self) {
        zeroize_card_tokens(&mut self.card_tokens);
    }
}

impl UpdateIntentionParamsBuilder {
    /// Creates an empty [`UpdateIntentionParamsBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the updated payment amount in integer minor units.
    #[must_use]
    pub fn amount(mut self, amount: impl Into<MinorUnitAmount>) -> Self {
        self.amount = Some(amount.into());
        self
    }

    /// Sets the updated ISO currency code.
    #[must_use]
    pub fn currency(mut self, currency: Currency) -> Self {
        self.currency = Some(currency);
        self
    }

    /// Sets the updated payment methods.
    #[must_use]
    pub fn payment_methods(mut self, payment_methods: Vec<PaymentMethodInput>) -> Self {
        self.payment_methods = Some(payment_methods);
        self
    }

    /// Sets the updated line items.
    #[must_use]
    pub fn items(mut self, items: Vec<IntentionItem>) -> Self {
        self.items = Some(items);
        self
    }

    /// Sets the updated billing data.
    #[must_use]
    pub fn billing_data(mut self, billing_data: BillingData) -> Self {
        self.billing_data = Some(billing_data);
        self
    }

    /// Sets the updated customer profile.
    #[must_use]
    pub fn customer(mut self, customer: IntentionCustomer) -> Self {
        self.customer = Some(customer);
        self
    }

    /// Sets the updated merchant `extras`.
    #[must_use]
    pub fn extras(mut self, extras: serde_json::Value) -> Self {
        self.extras = Some(extras);
        self
    }

    /// Sets the updated merchant `special_reference`.
    #[must_use]
    pub fn special_reference(mut self, special_reference: impl Into<String>) -> Self {
        self.special_reference = trim_opt(special_reference.into());
        self
    }

    /// Sets the updated expiration in seconds.
    #[must_use]
    pub const fn expiration(mut self, expiration: u64) -> Self {
        self.expiration = Some(expiration);
        self
    }

    /// Sets the updated webhook `notification_url`.
    #[must_use]
    pub fn notification_url(mut self, notification_url: impl Into<String>) -> Self {
        self.notification_url = trim_opt(notification_url.into());
        self
    }

    /// Sets the updated post-checkout `redirection_url`.
    #[must_use]
    pub fn redirection_url(mut self, redirection_url: impl Into<String>) -> Self {
        self.redirection_url = trim_opt(redirection_url.into());
        self
    }

    /// Sets the updated `pre_selected_plan` ID.
    #[must_use]
    pub const fn pre_selected_plan(mut self, pre_selected_plan: u64) -> Self {
        self.pre_selected_plan = Some(pre_selected_plan);
        self
    }

    /// Sets the updated saved `card_tokens`.
    #[must_use]
    pub fn card_tokens(mut self, mut card_tokens: Vec<String>) -> Self {
        zeroize_card_tokens(&mut self.card_tokens);
        self.card_tokens = Some(std::mem::take(&mut card_tokens));
        self
    }

    /// Validates provided fields and builds [`UpdateIntentionParams`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if no fields are set, or if any
    /// provided field violates domain constraints.
    pub fn build(mut self) -> Result<UpdateIntentionParams, PaymobError> {
        let params = UpdateIntentionParams {
            amount: self.amount,
            currency: self.currency.take(),
            payment_methods: self.payment_methods.take(),
            items: self.items.take(),
            billing_data: self.billing_data.take(),
            customer: self.customer.take(),
            extras: self.extras.take(),
            special_reference: self.special_reference.take(),
            expiration: self.expiration,
            notification_url: self.notification_url.take(),
            redirection_url: self.redirection_url.take(),
            pre_selected_plan: self.pre_selected_plan,
            card_tokens: self.card_tokens.take(),
        };
        validate_update_params(&params)?;
        Ok(params)
    }
}

impl fmt::Debug for UpdateIntentionParamsBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateIntentionParamsBuilder")
            .field("amount", &self.amount)
            .field("currency", &self.currency)
            .field("card_tokens", &self.card_tokens.as_ref().map(|_| REDACTED))
            .finish_non_exhaustive()
    }
}

fn zeroize_card_tokens(tokens: &mut Option<Vec<String>>) {
    if let Some(list) = tokens.as_mut() {
        for token in list.iter_mut() {
            token.zeroize();
        }
        list.clear();
    }
}

fn trim_opt(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn validate_required_amount(
    amount: Option<MinorUnitAmount>,
) -> Result<MinorUnitAmount, PaymobError> {
    let amt = amount.ok_or_else(|| PaymobError::ValidationError {
        field: "amount",
        reason: "amount is required".to_owned(),
    })?;
    if amt.is_zero() {
        return Err(PaymobError::ValidationError {
            field: "amount",
            reason: "amount must be greater than zero minor units".to_owned(),
        });
    }
    Ok(amt)
}

fn validate_required_currency(currency: Option<Currency>) -> Result<Currency, PaymobError> {
    let cur = currency.ok_or_else(|| PaymobError::ValidationError {
        field: "currency",
        reason: "currency is required".to_owned(),
    })?;
    validate_currency_value(&cur)?;
    Ok(cur)
}

fn validate_currency_value(currency: &Currency) -> Result<(), PaymobError> {
    if currency.as_str().trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field: "currency",
            reason: "currency cannot be empty".to_owned(),
        });
    }
    Ok(())
}

fn validate_required_methods(
    methods: Option<Vec<PaymentMethodInput>>,
) -> Result<Vec<PaymentMethodInput>, PaymobError> {
    let list = methods.ok_or_else(|| PaymobError::ValidationError {
        field: "payment_methods",
        reason: "payment_methods is required".to_owned(),
    })?;
    validate_methods_slice(&list)?;
    Ok(list)
}

fn validate_methods_slice(list: &[PaymentMethodInput]) -> Result<(), PaymobError> {
    if list.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "payment_methods",
            reason: "payment_methods must contain at least one integration ID or method name"
                .to_owned(),
        });
    }
    for method in list {
        validate_single_method(method)?;
    }
    Ok(())
}

fn validate_single_method(method: &PaymentMethodInput) -> Result<(), PaymobError> {
    match method {
        PaymentMethodInput::IntegrationId(0) => Err(PaymobError::ValidationError {
            field: "payment_methods",
            reason: "integration ID must be non-zero".to_owned(),
        }),
        PaymentMethodInput::MethodName(name) if name.trim().is_empty() => {
            Err(PaymobError::ValidationError {
                field: "payment_methods",
                reason: "payment method name cannot be empty".to_owned(),
            })
        }
        _ => Ok(()),
    }
}

fn validate_items_slice(items: Option<&[IntentionItem]>) -> Result<(), PaymobError> {
    let Some(list) = items else {
        return Ok(());
    };
    for item in list {
        item.validate()?;
    }
    Ok(())
}

fn validate_optional_urls(
    notification_url: Option<&str>,
    redirection_url: Option<&str>,
) -> Result<(), PaymobError> {
    if let Some(url) = notification_url {
        validate_http_url(url, "notification_url")?;
    }
    if let Some(url) = redirection_url {
        validate_http_url(url, "redirection_url")?;
    }
    Ok(())
}

fn validate_http_url(raw: &str, field: &'static str) -> Result<(), PaymobError> {
    if raw.chars().any(char::is_control) {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not contain control characters"),
        });
    }
    let parsed = Url::parse(raw.trim()).map_err(|err| PaymobError::ValidationError {
        field,
        reason: format!("invalid URL: {err}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must use http or https with a valid host"),
        });
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not contain embedded credentials"),
        });
    }
    Ok(())
}

fn validate_expiration_and_plan(
    expiration: Option<u64>,
    pre_selected_plan: Option<u64>,
) -> Result<(), PaymobError> {
    if expiration == Some(0) {
        return Err(PaymobError::ValidationError {
            field: "expiration",
            reason: "expiration must be greater than zero seconds".to_owned(),
        });
    }
    if pre_selected_plan == Some(0) {
        return Err(PaymobError::ValidationError {
            field: "pre_selected_plan",
            reason: "pre_selected_plan must be greater than zero".to_owned(),
        });
    }
    Ok(())
}

fn validate_card_tokens(tokens: Option<&[String]>) -> Result<(), PaymobError> {
    let Some(list) = tokens else {
        return Ok(());
    };
    if list.is_empty() || list.iter().any(|t| t.trim().is_empty()) {
        return Err(PaymobError::ValidationError {
            field: "card_tokens",
            reason: "card_tokens must be non-empty and contain no blank entries".to_owned(),
        });
    }
    Ok(())
}

fn validate_common_optional_fields(
    items: Option<&[IntentionItem]>,
    notification_url: Option<&str>,
    redirection_url: Option<&str>,
    expiration: Option<u64>,
    pre_selected_plan: Option<u64>,
    card_tokens: Option<&[String]>,
) -> Result<(), PaymobError> {
    validate_items_slice(items)?;
    validate_optional_urls(notification_url, redirection_url)?;
    validate_expiration_and_plan(expiration, pre_selected_plan)?;
    validate_card_tokens(card_tokens)
}

fn has_any_update_field(p: &UpdateIntentionParams) -> bool {
    [
        p.amount.is_some(),
        p.currency.is_some(),
        p.payment_methods.is_some(),
        p.items.is_some(),
        p.billing_data.is_some(),
        p.customer.is_some(),
        p.extras.is_some(),
        p.special_reference.is_some(),
        p.expiration.is_some(),
        p.notification_url.is_some(),
        p.redirection_url.is_some(),
        p.pre_selected_plan.is_some(),
        p.card_tokens.is_some(),
    ]
    .into_iter()
    .any(|present| present)
}

fn validate_optional_amount_and_currency(
    amount: Option<MinorUnitAmount>,
    currency: Option<&Currency>,
) -> Result<(), PaymobError> {
    if amount.is_some_and(MinorUnitAmount::is_zero) {
        return Err(PaymobError::ValidationError {
            field: "amount",
            reason: "amount must be greater than zero minor units".to_owned(),
        });
    }
    if let Some(cur) = currency {
        validate_currency_value(cur)?;
    }
    Ok(())
}

fn validate_update_params(p: &UpdateIntentionParams) -> Result<(), PaymobError> {
    if !has_any_update_field(p) {
        return Err(PaymobError::ValidationError {
            field: "update_params",
            reason: "at least one field must be provided to update an intention".to_owned(),
        });
    }
    validate_optional_amount_and_currency(p.amount, p.currency.as_ref())?;
    if let Some(methods) = p.payment_methods.as_deref() {
        validate_methods_slice(methods)?;
    }
    validate_common_optional_fields(
        p.items.as_deref(),
        p.notification_url.as_deref(),
        p.redirection_url.as_deref(),
        p.expiration,
        p.pre_selected_plan,
        p.card_tokens.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_2_1_2_payment_method_input_untagged_serde() {
        let methods = vec![
            PaymentMethodInput::IntegrationId(4_097_558),
            PaymentMethodInput::MethodName("card".to_owned()),
        ];
        let json = serde_json::to_string(&methods).expect("serialize");
        assert_eq!(json, r#"[4097558,"card"]"#);

        let parsed: Vec<PaymentMethodInput> = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, methods);
        assert_eq!(parsed[0].as_integration_id(), Some(4_097_558));
        assert_eq!(parsed[1].as_method_name(), Some("card"));
    }

    #[test]
    fn tc_2_1_2_create_params_builder_full_fields_and_validation() {
        let billing = BillingData::builder()
            .phone_number("+201116491564")
            .build()
            .expect("billing");
        let item = IntentionItem::new("Plan Pro", 100_000_u64).expect("item");

        let params = CreateIntentionParams::builder()
            .amount(100_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![PaymentMethodInput::IntegrationId(4_097_558)])
            .items(vec![item])
            .billing_data(billing)
            .customer(IntentionCustomer::new().with_first_name("Maher"))
            .extras(serde_json::json!({"source": "sdk"}))
            .special_reference("ref-001")
            .expiration(3600)
            .notification_url("https://example.com/webhook")
            .redirection_url("https://example.com/return")
            .pre_selected_plan(12)
            .card_tokens(vec!["tok_test_123".to_owned()])
            .build()
            .expect("valid params");

        let json = serde_json::to_value(&params).expect("serialize");
        assert_eq!(json["amount"], 100_000);
        assert_eq!(json["currency"], "EGP");
        assert_eq!(json["pre_selected_plan"], 12);

        let dbg = format!("{params:?}");
        assert!(dbg.contains("[REDACTED]"));
        assert!(!dbg.contains("tok_test_123"));
    }

    #[test]
    fn tc_2_1_2_create_params_rejects_malformed_inputs() {
        let missing_amount = CreateIntentionParams::builder()
            .currency(Currency::EGP)
            .payment_methods(vec![PaymentMethodInput::MethodName("card".to_owned())])
            .build();
        assert!(matches!(
            missing_amount,
            Err(PaymobError::ValidationError {
                field: "amount",
                ..
            })
        ));

        let empty_methods = CreateIntentionParams::builder()
            .amount(1_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![])
            .build();
        assert!(matches!(
            empty_methods,
            Err(PaymobError::ValidationError {
                field: "payment_methods",
                ..
            })
        ));

        let bad_url = CreateIntentionParams::builder()
            .amount(1_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![PaymentMethodInput::IntegrationId(123)])
            .notification_url("ftp://example.com/hook")
            .build();
        assert!(matches!(
            bad_url,
            Err(PaymobError::ValidationError {
                field: "notification_url",
                ..
            })
        ));

        let zero_plan = CreateIntentionParams::builder()
            .amount(1_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![PaymentMethodInput::IntegrationId(123)])
            .pre_selected_plan(0)
            .build();
        assert!(matches!(
            zero_plan,
            Err(PaymobError::ValidationError {
                field: "pre_selected_plan",
                ..
            })
        ));

        let zero_expiration = CreateIntentionParams::builder()
            .amount(1_000_u64)
            .currency(Currency::EGP)
            .payment_methods(vec![PaymentMethodInput::IntegrationId(123)])
            .expiration(0)
            .build();
        assert!(matches!(
            zero_expiration,
            Err(PaymobError::ValidationError {
                field: "expiration",
                ..
            })
        ));
    }

    #[test]
    fn tc_2_1_2_update_params_builder_validates_empty_and_partial_updates() {
        let empty = UpdateIntentionParams::builder().build();
        assert!(matches!(
            empty,
            Err(PaymobError::ValidationError {
                field: "update_params",
                ..
            })
        ));

        let valid = UpdateIntentionParams::builder()
            .amount(150_000_u64)
            .special_reference("ref-002")
            .build()
            .expect("valid update");
        assert_eq!(valid.amount().map(MinorUnitAmount::as_u64), Some(150_000));
        assert_eq!(valid.special_reference(), Some("ref-002"));
    }

    #[test]
    fn tc_2_1_cycle2_deserialize_create_and_update_params_enforce_bounds() {
        let zero_amount = serde_json::from_str::<CreateIntentionParams>(
            r#"{"amount":0,"currency":"EGP","payment_methods":[4097558]}"#,
        );
        assert!(zero_amount.is_err());

        let blank_currency = serde_json::from_str::<CreateIntentionParams>(
            r#"{"amount":1000,"currency":"   ","payment_methods":[4097558]}"#,
        );
        assert!(blank_currency.is_err());

        let empty_methods = serde_json::from_str::<CreateIntentionParams>(
            r#"{"amount":1000,"currency":"EGP","payment_methods":[]}"#,
        );
        assert!(empty_methods.is_err());

        let zero_plan = serde_json::from_str::<CreateIntentionParams>(
            r#"{"amount":1000,"currency":"EGP","payment_methods":[4097558],"pre_selected_plan":0}"#,
        );
        assert!(zero_plan.is_err());

        let zero_exp = serde_json::from_str::<CreateIntentionParams>(
            r#"{"amount":1000,"currency":"EGP","payment_methods":[4097558],"expiration":0}"#,
        );
        assert!(zero_exp.is_err());

        let bad_tokens = serde_json::from_str::<CreateIntentionParams>(
            r#"{"amount":1000,"currency":"EGP","payment_methods":[4097558],"card_tokens":[""]}"#,
        );
        assert!(bad_tokens.is_err());

        let empty_update = serde_json::from_str::<UpdateIntentionParams>(r#"{}"#);
        assert!(empty_update.is_err());

        let update_zero_plan =
            serde_json::from_str::<UpdateIntentionParams>(r#"{"pre_selected_plan":0}"#);
        assert!(update_zero_plan.is_err());
    }

    #[test]
    fn res1_06_validate_http_url_rejects_control_chars_missing_host_and_userinfo() {
        assert!(validate_http_url("https://example.com/hook\n", "notification_url").is_err());
        assert!(
            validate_http_url("https://user:pass@example.com/hook", "redirection_url").is_err()
        );
        assert!(validate_http_url("https://user@example.com/hook", "notification_url").is_err());
        assert!(validate_http_url("http:///no-host", "redirection_url").is_err());
        assert!(
            validate_http_url("https://merchant.example.com/callback", "notification_url").is_ok()
        );
    }
}
