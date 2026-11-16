#![forbid(unsafe_code)]
//! Subscription plan creation and update parameter builders (`US-4.2.0/unit-2`).
//!
//! Provides [`CreateSubscriptionPlanParams`] and [`UpdateSubscriptionPlanParams`]
//! along with their fluent builders and client-side validation for Paymob's
//! `/api/acceptance/subscription-plans` endpoints.
//!
//! Validation enforces Paymob's domain invariants before any network request is
//! dispatched:
//! - Plan `name` must be non-empty (non-whitespace) and at most 200 UTF-8 characters.
//! - `integration` (MIGS MOTO integration ID) must be greater than `0`.
//! - `webhook_url`, when provided, must be a valid `http` or `https` URL.
//! - `plan_type`, when provided, must be non-empty.
//! - All monetary amounts (`amount_cents`, `fee`) use integer minor units (`u64`),
//!   with zero floating-point types.

use serde::Serialize;
use url::Url;

use crate::core::error::PaymobError;

use super::plan_models::PlanFrequency;

/// Maximum allowed UTF-8 character length for a Paymob subscription plan name.
pub const MAX_PLAN_NAME_LEN: usize = 200;

/// Request payload for creating a Paymob subscription plan
/// (`POST /api/acceptance/subscription-plans`).
///
/// Construct instances via [`CreateSubscriptionPlanParams::builder()`] to
/// enforce required fields (`name`, `frequency`, `integration`) and domain
/// bounds at build time.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::plan_models::PlanFrequency;
/// use some_paymob::resources::subscriptions::plan_params::CreateSubscriptionPlanParams;
///
/// let params = CreateSubscriptionPlanParams::builder()
///     .name("Pro Monthly")
///     .frequency(PlanFrequency::Days30)
///     .integration(4_111_111)
///     .amount_cents(15_000)
///     .is_active(true)
///     .build()?;
///
/// assert_eq!(params.name, "Pro Monthly");
/// assert_eq!(params.frequency, PlanFrequency::Days30);
/// assert_eq!(params.integration, 4_111_111);
/// assert_eq!(params.amount_cents, Some(15_000));
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreateSubscriptionPlanParams {
    /// Billing interval in days (`7 | 15 | 30 | 60 | 90 | 180 | 360`).
    pub frequency: PlanFrequency,
    /// Human-readable subscription plan name (`1..=200` UTF-8 characters).
    pub name: String,
    /// Paymob MIGS MOTO integration ID (`> 0`).
    pub integration: u64,
    /// Optional webhook callback URL for subscription lifecycle events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Optional number of days before renewal to send a reminder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reminder_days: Option<u16>,
    /// Optional number of days between automatic retrial attempts on failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrial_days: Option<u16>,
    /// Optional Paymob plan type (for example, `"rent"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_type: Option<String>,
    /// Optional maximum number of recurring deductions before completion.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_deductions: Option<u32>,
    /// Optional recurring charge amount in integer minor currency units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<u64>,
    /// Whether to reuse the initial transaction amount for subsequent charges.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_transaction_amount: Option<bool>,
    /// Whether the subscription plan is immediately active upon creation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    /// Optional plan fee in integer minor currency units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
}

impl CreateSubscriptionPlanParams {
    /// Returns a new [`CreateSubscriptionPlanParamsBuilder`].
    #[must_use]
    pub fn builder() -> CreateSubscriptionPlanParamsBuilder {
        CreateSubscriptionPlanParamsBuilder::new()
    }

    /// Validates all fields of [`CreateSubscriptionPlanParams`] against
    /// Paymob's subscription plan constraints.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if:
    /// - `name` is empty/whitespace or exceeds `200` UTF-8 characters.
    /// - `integration` is `0`.
    /// - `webhook_url` is `Some` and is not a valid `http` or `https` URL.
    /// - `plan_type` is `Some` and is empty/whitespace.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_plan_name(&self.name)?;
        validate_integration_id(self.integration)?;
        validate_optional_webhook_url(self.webhook_url.as_deref())?;
        validate_optional_plan_type(self.plan_type.as_deref())
    }
}

/// Fluent builder for [`CreateSubscriptionPlanParams`].
#[derive(Debug, Clone, Default)]
pub struct CreateSubscriptionPlanParamsBuilder {
    frequency: Option<PlanFrequency>,
    name: Option<String>,
    integration: Option<u64>,
    webhook_url: Option<String>,
    reminder_days: Option<u16>,
    retrial_days: Option<u16>,
    plan_type: Option<String>,
    number_of_deductions: Option<u32>,
    amount_cents: Option<u64>,
    use_transaction_amount: Option<bool>,
    is_active: Option<bool>,
    fee: Option<u64>,
}

impl CreateSubscriptionPlanParamsBuilder {
    /// Creates an empty [`CreateSubscriptionPlanParamsBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the required billing [`PlanFrequency`].
    #[must_use]
    pub fn frequency(mut self, frequency: PlanFrequency) -> Self {
        self.frequency = Some(frequency);
        self
    }

    /// Sets the required subscription plan name (`1..=200` UTF-8 characters).
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the required Paymob MIGS MOTO integration ID (`> 0`).
    #[must_use]
    pub fn integration(mut self, integration: u64) -> Self {
        self.integration = Some(integration);
        self
    }

    /// Sets the optional webhook callback URL.
    #[must_use]
    pub fn webhook_url(mut self, webhook_url: impl Into<String>) -> Self {
        self.webhook_url = Some(webhook_url.into());
        self
    }

    /// Sets the optional reminder lead time in days.
    #[must_use]
    pub fn reminder_days(mut self, reminder_days: u16) -> Self {
        self.reminder_days = Some(reminder_days);
        self
    }

    /// Sets the optional retrial interval in days.
    #[must_use]
    pub fn retrial_days(mut self, retrial_days: u16) -> Self {
        self.retrial_days = Some(retrial_days);
        self
    }

    /// Sets the optional plan type (for example, `"rent"`).
    #[must_use]
    pub fn plan_type(mut self, plan_type: impl Into<String>) -> Self {
        self.plan_type = Some(plan_type.into());
        self
    }

    /// Sets the optional maximum number of recurring deductions.
    #[must_use]
    pub fn number_of_deductions(mut self, number_of_deductions: u32) -> Self {
        self.number_of_deductions = Some(number_of_deductions);
        self
    }

    /// Sets the optional recurring amount in integer minor currency units (`u64`).
    #[must_use]
    pub fn amount_cents(mut self, amount_cents: u64) -> Self {
        self.amount_cents = Some(amount_cents);
        self
    }

    /// Sets whether to reuse the initial transaction amount for renewals.
    #[must_use]
    pub fn use_transaction_amount(mut self, use_transaction_amount: bool) -> Self {
        self.use_transaction_amount = Some(use_transaction_amount);
        self
    }

    /// Sets whether the plan is active upon creation.
    #[must_use]
    pub fn is_active(mut self, is_active: bool) -> Self {
        self.is_active = Some(is_active);
        self
    }

    /// Sets the optional plan fee in integer minor currency units (`u64`).
    #[must_use]
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Validates required fields and domain bounds, returning
    /// [`CreateSubscriptionPlanParams`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any required field (`name`,
    /// `frequency`, `integration`) is missing or fails validation.
    pub fn build(self) -> Result<CreateSubscriptionPlanParams, PaymobError> {
        let frequency = self.frequency.ok_or_else(|| PaymobError::ValidationError {
            field: "frequency",
            reason: "frequency is required".to_owned(),
        })?;
        let name = self.name.ok_or_else(|| PaymobError::ValidationError {
            field: "name",
            reason: "name is required".to_owned(),
        })?;
        let integration = self.integration.ok_or_else(|| PaymobError::ValidationError {
            field: "integration",
            reason: "integration is required".to_owned(),
        })?;

        let params = CreateSubscriptionPlanParams {
            frequency,
            name,
            integration,
            webhook_url: self.webhook_url,
            reminder_days: self.reminder_days,
            retrial_days: self.retrial_days,
            plan_type: self.plan_type,
            number_of_deductions: self.number_of_deductions,
            amount_cents: self.amount_cents,
            use_transaction_amount: self.use_transaction_amount,
            is_active: self.is_active,
            fee: self.fee,
        };
        params.validate()?;
        Ok(params)
    }
}

/// Request payload for updating an existing Paymob subscription plan
/// (`PUT /api/acceptance/subscription-plans/{id}`).
///
/// All fields are optional so callers can submit partial updates; at least one
/// field must be populated before calling [`UpdateSubscriptionPlanParamsBuilder::build`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::subscriptions::plan_params::UpdateSubscriptionPlanParams;
///
/// let update = UpdateSubscriptionPlanParams::builder()
///     .name("Pro Monthly v2")
///     .amount_cents(20_000)
///     .is_active(true)
///     .build()?;
///
/// assert_eq!(update.name.as_deref(), Some("Pro Monthly v2"));
/// assert_eq!(update.amount_cents, Some(20_000));
/// assert_eq!(update.is_active, Some(true));
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UpdateSubscriptionPlanParams {
    /// Updated billing interval in days (`7 | 15 | 30 | 60 | 90 | 180 | 360`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency: Option<PlanFrequency>,
    /// Updated subscription plan name (`1..=200` UTF-8 characters).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Updated Paymob MIGS MOTO integration ID (`> 0`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integration: Option<u64>,
    /// Updated webhook callback URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webhook_url: Option<String>,
    /// Updated reminder lead time in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reminder_days: Option<u16>,
    /// Updated retrial interval in days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrial_days: Option<u16>,
    /// Updated plan type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_type: Option<String>,
    /// Updated maximum number of recurring deductions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number_of_deductions: Option<u32>,
    /// Updated recurring amount in integer minor currency units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_cents: Option<u64>,
    /// Updated flag controlling reuse of initial transaction amount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub use_transaction_amount: Option<bool>,
    /// Updated active status flag.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_active: Option<bool>,
    /// Updated plan fee in integer minor currency units (`u64`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,
}

impl UpdateSubscriptionPlanParams {
    /// Returns a new [`UpdateSubscriptionPlanParamsBuilder`].
    #[must_use]
    pub fn builder() -> UpdateSubscriptionPlanParamsBuilder {
        UpdateSubscriptionPlanParamsBuilder::new()
    }

    /// Validates all populated fields of [`UpdateSubscriptionPlanParams`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if no fields are set, or if
    /// any populated field violates its domain bounds.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if !self.has_any_field() {
            return Err(PaymobError::ValidationError {
                field: "update_params",
                reason: "at least one field must be provided to update a subscription plan"
                    .to_owned(),
            });
        }
        if let Some(ref name) = self.name {
            validate_plan_name(name)?;
        }
        if let Some(integration) = self.integration {
            validate_integration_id(integration)?;
        }
        validate_optional_webhook_url(self.webhook_url.as_deref())?;
        validate_optional_plan_type(self.plan_type.as_deref())
    }

    fn has_any_field(&self) -> bool {
        self.frequency.is_some()
            || self.name.is_some()
            || self.integration.is_some()
            || self.webhook_url.is_some()
            || self.reminder_days.is_some()
            || self.retrial_days.is_some()
            || self.plan_type.is_some()
            || self.number_of_deductions.is_some()
            || self.amount_cents.is_some()
            || self.use_transaction_amount.is_some()
            || self.is_active.is_some()
            || self.fee.is_some()
    }
}

/// Fluent builder for [`UpdateSubscriptionPlanParams`].
#[derive(Debug, Clone, Default)]
pub struct UpdateSubscriptionPlanParamsBuilder {
    inner: UpdateSubscriptionPlanParams,
}

impl UpdateSubscriptionPlanParamsBuilder {
    /// Creates an empty [`UpdateSubscriptionPlanParamsBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the updated billing [`PlanFrequency`].
    #[must_use]
    pub fn frequency(mut self, frequency: PlanFrequency) -> Self {
        self.inner.frequency = Some(frequency);
        self
    }

    /// Sets the updated subscription plan name (`1..=200` UTF-8 characters).
    #[must_use]
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.inner.name = Some(name.into());
        self
    }

    /// Sets the updated Paymob MIGS MOTO integration ID (`> 0`).
    #[must_use]
    pub fn integration(mut self, integration: u64) -> Self {
        self.inner.integration = Some(integration);
        self
    }

    /// Sets the updated webhook callback URL.
    #[must_use]
    pub fn webhook_url(mut self, webhook_url: impl Into<String>) -> Self {
        self.inner.webhook_url = Some(webhook_url.into());
        self
    }

    /// Sets the updated reminder lead time in days.
    #[must_use]
    pub fn reminder_days(mut self, reminder_days: u16) -> Self {
        self.inner.reminder_days = Some(reminder_days);
        self
    }

    /// Sets the updated retrial interval in days.
    #[must_use]
    pub fn retrial_days(mut self, retrial_days: u16) -> Self {
        self.inner.retrial_days = Some(retrial_days);
        self
    }

    /// Sets the updated plan type.
    #[must_use]
    pub fn plan_type(mut self, plan_type: impl Into<String>) -> Self {
        self.inner.plan_type = Some(plan_type.into());
        self
    }

    /// Sets the updated maximum number of recurring deductions.
    #[must_use]
    pub fn number_of_deductions(mut self, number_of_deductions: u32) -> Self {
        self.inner.number_of_deductions = Some(number_of_deductions);
        self
    }

    /// Sets the updated recurring amount in integer minor currency units (`u64`).
    #[must_use]
    pub fn amount_cents(mut self, amount_cents: u64) -> Self {
        self.inner.amount_cents = Some(amount_cents);
        self
    }

    /// Sets whether to reuse the initial transaction amount for renewals.
    #[must_use]
    pub fn use_transaction_amount(mut self, use_transaction_amount: bool) -> Self {
        self.inner.use_transaction_amount = Some(use_transaction_amount);
        self
    }

    /// Sets whether the plan is active.
    #[must_use]
    pub fn is_active(mut self, is_active: bool) -> Self {
        self.inner.is_active = Some(is_active);
        self
    }

    /// Sets the updated plan fee in integer minor currency units (`u64`).
    #[must_use]
    pub fn fee(mut self, fee: u64) -> Self {
        self.inner.fee = Some(fee);
        self
    }

    /// Validates populated fields and returns [`UpdateSubscriptionPlanParams`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if no fields are set or any
    /// populated field fails validation.
    pub fn build(self) -> Result<UpdateSubscriptionPlanParams, PaymobError> {
        self.inner.validate()?;
        Ok(self.inner)
    }
}

fn validate_plan_name(name: &str) -> Result<(), PaymobError> {
    if name.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field: "name",
            reason: "subscription plan name must not be empty".to_owned(),
        });
    }
    if name.chars().count() > MAX_PLAN_NAME_LEN {
        return Err(PaymobError::ValidationError {
            field: "name",
            reason: format!(
                "subscription plan name must not exceed {MAX_PLAN_NAME_LEN} characters"
            ),
        });
    }
    Ok(())
}

fn validate_integration_id(integration: u64) -> Result<(), PaymobError> {
    if integration == 0 {
        return Err(PaymobError::ValidationError {
            field: "integration",
            reason: "MIGS MOTO integration ID must be greater than 0".to_owned(),
        });
    }
    Ok(())
}

fn validate_optional_webhook_url(webhook_url: Option<&str>) -> Result<(), PaymobError> {
    let Some(raw) = webhook_url else {
        return Ok(());
    };
    if raw.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field: "webhook_url",
            reason: "webhook_url must not be empty when provided".to_owned(),
        });
    }
    let parsed = Url::parse(raw).map_err(|err| PaymobError::ValidationError {
        field: "webhook_url",
        reason: format!("invalid webhook_url: {err}"),
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(PaymobError::ValidationError {
            field: "webhook_url",
            reason: "webhook_url must use http or https scheme".to_owned(),
        });
    }
    Ok(())
}

fn validate_optional_plan_type(plan_type: Option<&str>) -> Result<(), PaymobError> {
    let Some(raw) = plan_type else {
        return Ok(());
    };
    if raw.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field: "plan_type",
            reason: "plan_type must not be empty when provided".to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_4_2_2_create_params_required_only_and_serialize() {
        let params = CreateSubscriptionPlanParams::builder()
            .name("Pro Monthly")
            .frequency(PlanFrequency::Days30)
            .integration(4_111_111)
            .build()
            .expect("valid required params");

        assert_eq!(params.name, "Pro Monthly");
        assert_eq!(params.frequency, PlanFrequency::Days30);
        assert_eq!(params.integration, 4_111_111);
        assert!(params.webhook_url.is_none());

        let json = serde_json::to_value(&params).expect("serialize create params");
        assert_eq!(json["name"], "Pro Monthly");
        assert_eq!(json["integration"], 4_111_111);
        assert!(json.get("frequency").is_some());
        assert!(json.get("webhook_url").is_none());
        assert!(json.get("amount_cents").is_none());
    }

    #[test]
    fn tc_4_2_2_create_params_all_optional_fields() {
        let params = CreateSubscriptionPlanParams::builder()
            .name("Enterprise Annual")
            .frequency(PlanFrequency::Days360)
            .integration(4_222_222)
            .webhook_url("https://merchant.example.com/webhooks/paymob")
            .reminder_days(5)
            .retrial_days(3)
            .plan_type("rent")
            .number_of_deductions(12)
            .amount_cents(250_000)
            .use_transaction_amount(false)
            .is_active(true)
            .fee(1_500)
            .build()
            .expect("valid full create params");

        assert_eq!(
            params.webhook_url.as_deref(),
            Some("https://merchant.example.com/webhooks/paymob")
        );
        assert_eq!(params.reminder_days, Some(5));
        assert_eq!(params.retrial_days, Some(3));
        assert_eq!(params.plan_type.as_deref(), Some("rent"));
        assert_eq!(params.number_of_deductions, Some(12));
        assert_eq!(params.amount_cents, Some(250_000));
        assert_eq!(params.use_transaction_amount, Some(false));
        assert_eq!(params.is_active, Some(true));
        assert_eq!(params.fee, Some(1_500));
    }

    #[test]
    fn tc_4_2_2_create_params_name_length_boundaries() {
        let min_name = "A";
        assert!(
            CreateSubscriptionPlanParams::builder()
                .name(min_name)
                .frequency(PlanFrequency::Days7)
                .integration(1)
                .build()
                .is_ok()
        );

        let max_name = "x".repeat(200);
        assert!(
            CreateSubscriptionPlanParams::builder()
                .name(max_name)
                .frequency(PlanFrequency::Days7)
                .integration(1)
                .build()
                .is_ok()
        );

        let utf8_max = "é".repeat(200);
        assert!(
            CreateSubscriptionPlanParams::builder()
                .name(utf8_max)
                .frequency(PlanFrequency::Days7)
                .integration(1)
                .build()
                .is_ok()
        );

        let too_long = "x".repeat(201);
        let err = CreateSubscriptionPlanParams::builder()
            .name(too_long)
            .frequency(PlanFrequency::Days30)
            .integration(1)
            .build()
            .expect_err("name > 200 chars must fail");
        assert!(err.is_validation_error());
        assert!(matches!(
            err,
            PaymobError::ValidationError { field: "name", .. }
        ));
    }

    #[test]
    fn tc_4_2_2_create_params_rejects_missing_or_malformed_fields() {
        let missing_freq = CreateSubscriptionPlanParams::builder()
            .name("Starter")
            .integration(4_111_111)
            .build()
            .expect_err("missing frequency must fail");
        assert!(matches!(
            missing_freq,
            PaymobError::ValidationError {
                field: "frequency",
                ..
            }
        ));

        let missing_name = CreateSubscriptionPlanParams::builder()
            .frequency(PlanFrequency::Days15)
            .integration(4_111_111)
            .build()
            .expect_err("missing name must fail");
        assert!(matches!(
            missing_name,
            PaymobError::ValidationError { field: "name", .. }
        ));

        let missing_integration = CreateSubscriptionPlanParams::builder()
            .name("Starter")
            .frequency(PlanFrequency::Days15)
            .build()
            .expect_err("missing integration must fail");
        assert!(matches!(
            missing_integration,
            PaymobError::ValidationError {
                field: "integration",
                ..
            }
        ));

        let empty_name = CreateSubscriptionPlanParams::builder()
            .name("   ")
            .frequency(PlanFrequency::Days30)
            .integration(4_111_111)
            .build()
            .expect_err("whitespace name must fail");
        assert!(matches!(
            empty_name,
            PaymobError::ValidationError { field: "name", .. }
        ));

        let zero_integration = CreateSubscriptionPlanParams::builder()
            .name("Starter")
            .frequency(PlanFrequency::Days30)
            .integration(0)
            .build()
            .expect_err("zero integration must fail");
        assert!(matches!(
            zero_integration,
            PaymobError::ValidationError {
                field: "integration",
                ..
            }
        ));

        let bad_url = CreateSubscriptionPlanParams::builder()
            .name("Starter")
            .frequency(PlanFrequency::Days30)
            .integration(4_111_111)
            .webhook_url("ftp://example.com/hook")
            .build()
            .expect_err("non-http webhook_url must fail");
        assert!(matches!(
            bad_url,
            PaymobError::ValidationError {
                field: "webhook_url",
                ..
            }
        ));

        let empty_plan_type = CreateSubscriptionPlanParams::builder()
            .name("Starter")
            .frequency(PlanFrequency::Days30)
            .integration(4_111_111)
            .plan_type("")
            .build()
            .expect_err("empty plan_type must fail");
        assert!(matches!(
            empty_plan_type,
            PaymobError::ValidationError {
                field: "plan_type",
                ..
            }
        ));
    }

    #[test]
    fn tc_4_2_2_update_params_partial_and_validation() {
        let empty_err = UpdateSubscriptionPlanParams::builder()
            .build()
            .expect_err("empty update params must fail");
        assert!(matches!(
            empty_err,
            PaymobError::ValidationError {
                field: "update_params",
                ..
            }
        ));

        let update = UpdateSubscriptionPlanParams::builder()
            .name("Pro Monthly Updated")
            .is_active(false)
            .fee(500)
            .build()
            .expect("valid partial update");

        let json = serde_json::to_value(&update).expect("serialize update params");
        assert_eq!(json["name"], "Pro Monthly Updated");
        assert_eq!(json["is_active"], false);
        assert_eq!(json["fee"], 500);
        assert!(json.get("frequency").is_none());
        assert!(json.get("integration").is_none());

        let overlong_err = UpdateSubscriptionPlanParams::builder()
            .name("x".repeat(201))
            .build()
            .expect_err("overlong update name must fail");
        assert!(matches!(
            overlong_err,
            PaymobError::ValidationError { field: "name", .. }
        ));

        let zero_int_err = UpdateSubscriptionPlanParams::builder()
            .integration(0)
            .build()
            .expect_err("zero update integration must fail");
        assert!(matches!(
            zero_int_err,
            PaymobError::ValidationError {
                field: "integration",
                ..
            }
        ));

        let bad_url_err = UpdateSubscriptionPlanParams::builder()
            .webhook_url("not-a-valid-url")
            .build()
            .expect_err("malformed update webhook_url must fail");
        assert!(matches!(
            bad_url_err,
            PaymobError::ValidationError {
                field: "webhook_url",
                ..
            }
        ));
    }
}
