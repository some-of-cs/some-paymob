#![forbid(unsafe_code)]
//! US-9.1.0 Unit 3: `auth_integration_id` Manual-capture guard, named integration aliases,
//! conditional Intention pre-flight validation, and `special_reference` mapping.
//!
//! This module enforces local fail-closed invariants before any Paymob Unified Intention
//! request is transmitted over the network:
//!
//! - **TM-6 Manual-capture guard**: [`AlignmentCaptureMode::Manual`] requires an explicit,
//!   non-zero `auth_integration_id` in [`IntegrationRoutingConfig`]. Missing or zero IDs
//!   fail closed with [`IntegrationValidationError::ConfigurationError`] and never silently
//!   fall back to auto-capture integration IDs.
//! - **Named alias resolution**: Resolves aliases such as `"card"`, `"wallet"`, `"valu"`,
//!   and `"apple_pay"` to validated non-zero Paymob integration IDs.
//! - **Conditional pre-flight checks**: Validates `billing_data.phone_number`, integer
//!   minor-unit `items` (with overflow-checked summation), and non-empty `order_id` ->
//!   `special_reference` mapping.
//! - **PII hygiene**: [`IntentionBillingData`] implements a custom [`fmt::Debug`] that
//!   redacts `phone_number` and `email` as `[REDACTED]`.
//!
//! # Example
//!
//! ```rust
//! use some_paymob::alignment::integration_validation::{
//!     AlignmentCaptureMode, IntegrationRoutingConfig, IntentionBillingData, IntentionLineItem,
//!     IntentionPreflightInput, validate_intention_preflight,
//! };
//!
//! let config = IntegrationRoutingConfig::new(vec![101_001])
//!     .with_auth_integration_id(202_002)
//!     .with_alias("card", 101_001)
//!     .with_alias("wallet", 101_002);
//!
//! let input = IntentionPreflightInput {
//!     order_id: "ord_2026_001".to_owned(),
//!     capture_mode: AlignmentCaptureMode::Manual,
//!     payment_method_alias: None,
//!     billing_data: Some(IntentionBillingData::new("+201001234567")),
//!     items: vec![IntentionLineItem::new("Annual Plan", 25_000)],
//! };
//!
//! let routing = validate_intention_preflight(&config, &input)?;
//! assert_eq!(routing.payment_methods, vec![202_002]);
//! assert_eq!(routing.special_reference, "ord_2026_001");
//! assert_eq!(routing.items_total_minor_units, Some(25_000));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Capture mode requested for a Paymob Unified Intention alignment flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlignmentCaptureMode {
    /// Immediate sale / auto-capture using default or alias-selected integration IDs.
    #[default]
    Automatic,
    /// Auth-only hold requiring a dedicated `auth_integration_id` (fail-closed per TM-6).
    Manual,
}

/// Fail-closed error taxonomy for integration routing configuration and Intention pre-flight
/// validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IntegrationValidationError {
    /// Integration routing configuration is missing, unknown, or contains an invalid ID (`0`),
    /// including missing `auth_integration_id` under [`AlignmentCaptureMode::Manual`].
    #[error("integration configuration error: {0}")]
    ConfigurationError(String),
    /// Caller-supplied Intention pre-flight input violated a local validation invariant.
    #[error("intention validation error: {0}")]
    ValidationError(String),
}

/// Integration routing configuration for Paymob Unified Intentions.
///
/// Holds default auto-capture integration IDs, an optional dedicated `auth_integration_id`
/// for [`AlignmentCaptureMode::Manual`], and named payment-method aliases (for example
/// `"card"`, `"wallet"`, `"valu"`, `"apple_pay"`).
///
/// # Example
///
/// ```rust
/// use some_paymob::alignment::integration_validation::{
///     AlignmentCaptureMode, IntegrationRoutingConfig,
/// };
///
/// let config = IntegrationRoutingConfig::new(vec![4_001]).with_alias("apple_pay", 4_005);
///
/// let ids = config.resolve_payment_methods(AlignmentCaptureMode::Automatic, Some("apple_pay"))?;
/// assert_eq!(ids, vec![4_005]);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationRoutingConfig {
    /// Default auto-capture Paymob integration IDs used when no alias is requested.
    pub default_integration_ids: Vec<u64>,
    /// Dedicated Paymob auth-only integration ID required for [`AlignmentCaptureMode::Manual`].
    pub auth_integration_id: Option<u64>,
    /// Named payment-method aliases mapped to Paymob integration IDs.
    pub aliases: BTreeMap<String, u64>,
}

impl IntegrationRoutingConfig {
    /// Creates a new routing configuration with the given default auto-capture integration IDs.
    #[must_use]
    pub fn new(default_integration_ids: Vec<u64>) -> Self {
        Self {
            default_integration_ids,
            auth_integration_id: None,
            aliases: BTreeMap::new(),
        }
    }

    /// Sets the dedicated auth-only integration ID used for [`AlignmentCaptureMode::Manual`].
    #[must_use]
    pub fn with_auth_integration_id(mut self, auth_integration_id: u64) -> Self {
        self.auth_integration_id = Some(auth_integration_id);
        self
    }

    /// Registers a named payment-method alias (stored trimmed and lowercased).
    #[must_use]
    pub fn with_alias(mut self, alias: impl Into<String>, integration_id: u64) -> Self {
        let normalized = alias.into().trim().to_ascii_lowercase();
        self.aliases.insert(normalized, integration_id);
        self
    }

    /// Resolves a named payment-method alias to a validated, non-zero integration ID.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationValidationError::ValidationError`] when `alias` is empty or
    /// whitespace-only, and [`IntegrationValidationError::ConfigurationError`] when the alias
    /// is not registered or maps to integration ID `0`.
    pub fn resolve_alias(&self, alias: &str) -> Result<u64, IntegrationValidationError> {
        let trimmed = alias.trim();
        if trimmed.is_empty() {
            return Err(IntegrationValidationError::ValidationError(
                "payment method alias must not be empty".to_owned(),
            ));
        }

        let Some(&id) = self
            .aliases
            .get(trimmed)
            .or_else(|| self.aliases.get(&trimmed.to_ascii_lowercase()))
        else {
            return Err(IntegrationValidationError::ConfigurationError(format!(
                "unknown payment method alias '{trimmed}'"
            )));
        };

        validate_nonzero_integration_id(id, "alias integration_id")
    }

    /// Resolves Paymob `payment_methods` integration IDs for the requested capture mode and
    /// optional named alias.
    ///
    /// Under [`AlignmentCaptureMode::Manual`], this method enforces TM-6 and fails closed with
    /// [`IntegrationValidationError::ConfigurationError`] whenever `auth_integration_id` is
    /// `None` or `Some(0)` without falling back to `default_integration_ids`.
    ///
    /// # Errors
    ///
    /// Returns [`IntegrationValidationError::ConfigurationError`] for missing/zero integration
    /// IDs or unknown aliases, and [`IntegrationValidationError::ValidationError`] for empty
    /// alias strings.
    pub fn resolve_payment_methods(
        &self,
        capture_mode: AlignmentCaptureMode,
        alias: Option<&str>,
    ) -> Result<Vec<u64>, IntegrationValidationError> {
        match capture_mode {
            AlignmentCaptureMode::Manual => self.resolve_manual_integration(),
            AlignmentCaptureMode::Automatic => self.resolve_automatic_integrations(alias),
        }
    }

    fn resolve_manual_integration(&self) -> Result<Vec<u64>, IntegrationValidationError> {
        let Some(auth_id) = self.auth_integration_id else {
            return Err(IntegrationValidationError::ConfigurationError(
                "Manual capture requires auth_integration_id; auto-capture fallback is forbidden"
                    .to_owned(),
            ));
        };

        let validated = validate_nonzero_integration_id(auth_id, "auth_integration_id")?;
        Ok(vec![validated])
    }

    fn resolve_automatic_integrations(
        &self,
        alias: Option<&str>,
    ) -> Result<Vec<u64>, IntegrationValidationError> {
        if let Some(raw_alias) = alias {
            let resolved = self.resolve_alias(raw_alias)?;
            return Ok(vec![resolved]);
        }

        self.validate_default_integration_ids()
    }

    fn validate_default_integration_ids(&self) -> Result<Vec<u64>, IntegrationValidationError> {
        if self.default_integration_ids.is_empty() {
            return Err(IntegrationValidationError::ConfigurationError(
                "default_integration_ids must not be empty for Automatic capture without an alias"
                    .to_owned(),
            ));
        }

        for &id in &self.default_integration_ids {
            validate_nonzero_integration_id(id, "default_integration_ids")?;
        }

        Ok(self.default_integration_ids.clone())
    }
}

/// Line item attached to a Paymob Unified Intention pre-flight payload.
///
/// Monetary amounts are represented strictly in integer minor units (`u64`); floating-point
/// types are intentionally excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentionLineItem {
    /// Human-readable item name (must be non-empty after trimming).
    pub name: String,
    /// Item amount in integer minor units (must be strictly greater than `0`).
    pub amount: u64,
    /// Optional item description.
    pub description: Option<String>,
    /// Optional item quantity (must be strictly greater than `0` when provided).
    pub quantity: Option<u32>,
}

impl IntentionLineItem {
    /// Creates a new line item with a name and positive integer minor-unit amount.
    #[must_use]
    pub fn new(name: impl Into<String>, amount: u64) -> Self {
        Self {
            name: name.into(),
            amount,
            description: None,
            quantity: None,
        }
    }
}

/// Billing contact metadata for a Paymob Unified Intention pre-flight payload.
///
/// Implements a custom [`fmt::Debug`] that redacts `phone_number` and `email` as
/// `[REDACTED]` to prevent PII leakage in logs and error diagnostics.
///
/// # Example
///
/// ```rust
/// use some_paymob::alignment::integration_validation::IntentionBillingData;
///
/// let billing = IntentionBillingData::new("+201001234567").with_email("payer@example.com");
/// let debug_output = format!("{billing:?}");
/// assert!(debug_output.contains("[REDACTED]"));
/// assert!(!debug_output.contains("+201001234567"));
/// assert!(!debug_output.contains("payer@example.com"));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentionBillingData {
    /// Customer phone number (required to be non-empty when billing data is supplied).
    pub phone_number: String,
    /// Optional customer email address (redacted in `Debug` output).
    pub email: Option<String>,
    /// Optional customer first name.
    pub first_name: Option<String>,
    /// Optional customer last name.
    pub last_name: Option<String>,
}

impl IntentionBillingData {
    /// Creates billing metadata with the supplied `phone_number`.
    #[must_use]
    pub fn new(phone_number: impl Into<String>) -> Self {
        Self {
            phone_number: phone_number.into(),
            email: None,
            first_name: None,
            last_name: None,
        }
    }

    /// Attaches an optional customer email address.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    /// Attaches optional customer first and last names.
    #[must_use]
    pub fn with_name(
        mut self,
        first_name: impl Into<String>,
        last_name: impl Into<String>,
    ) -> Self {
        self.first_name = Some(first_name.into());
        self.last_name = Some(last_name.into());
        self
    }
}

impl fmt::Debug for IntentionBillingData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentionBillingData")
            .field("phone_number", &"[REDACTED]")
            .field("email", &"[REDACTED]")
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .finish()
    }
}

/// Pre-flight input validated before constructing a Paymob Unified Intention request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentionPreflightInput {
    /// Merchant order identifier mapped verbatim (trimmed) to Paymob's `special_reference`.
    pub order_id: String,
    /// Requested payment capture mode (`Automatic` or `Manual`).
    pub capture_mode: AlignmentCaptureMode,
    /// Optional named payment-method alias resolved in [`AlignmentCaptureMode::Automatic`].
    pub payment_method_alias: Option<String>,
    /// Optional billing details; when present, `phone_number` must be non-empty.
    pub billing_data: Option<IntentionBillingData>,
    /// Optional line items; when non-empty, each item must have a non-empty `name` and
    /// positive integer minor-unit `amount` with an overflow-checked total.
    pub items: Vec<IntentionLineItem>,
}

/// Validated routing and pre-flight summary produced by [`validate_intention_preflight`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedIntentionRouting {
    /// Resolved non-zero Paymob integration IDs to send in `payment_methods`.
    pub payment_methods: Vec<u64>,
    /// Effective capture mode enforced during routing resolution.
    pub capture_mode: AlignmentCaptureMode,
    /// Validated `order_id` mapped to Paymob's `special_reference` field.
    pub special_reference: String,
    /// Overflow-checked sum of item amounts in integer minor units, or `None` if `items` is empty.
    pub items_total_minor_units: Option<u64>,
    /// Normalized alias name when an alias was resolved under [`AlignmentCaptureMode::Automatic`].
    pub resolved_alias: Option<String>,
}

/// Validates integration routing configuration and conditional Intention pre-flight invariants.
///
/// Enforces:
/// 1. Non-empty `order_id` mapped to `special_reference`.
/// 2. Fail-closed [`AlignmentCaptureMode::Manual`] guard requiring non-zero `auth_integration_id`.
/// 3. Validated `default_integration_ids` or named alias resolution for
///    [`AlignmentCaptureMode::Automatic`].
/// 4. Conditional `billing_data.phone_number` non-empty check when `billing_data` is `Some`.
/// 5. Conditional `items` non-empty `name`, positive `amount`, and `checked_add` sum check
///    when `items` is non-empty.
///
/// # Errors
///
/// Returns [`IntegrationValidationError::ConfigurationError`] if integration routing cannot
/// be safely resolved, or [`IntegrationValidationError::ValidationError`] if any pre-flight
/// input invariant fails.
pub fn validate_intention_preflight(
    config: &IntegrationRoutingConfig,
    input: &IntentionPreflightInput,
) -> Result<ValidatedIntentionRouting, IntegrationValidationError> {
    let special_reference = validate_special_reference(&input.order_id)?;
    let alias = input.payment_method_alias.as_deref();
    let payment_methods = config.resolve_payment_methods(input.capture_mode, alias)?;
    validate_billing_data(input.billing_data.as_ref())?;
    let items_total_minor_units = validate_line_items(&input.items)?;
    let resolved_alias = resolve_effective_alias(input.capture_mode, alias);

    Ok(ValidatedIntentionRouting {
        payment_methods,
        capture_mode: input.capture_mode,
        special_reference,
        items_total_minor_units,
        resolved_alias,
    })
}

fn validate_nonzero_integration_id(
    id: u64,
    field_name: &str,
) -> Result<u64, IntegrationValidationError> {
    if id == 0 {
        return Err(IntegrationValidationError::ConfigurationError(format!(
            "{field_name} must be a non-zero Paymob integration ID"
        )));
    }
    Ok(id)
}

fn validate_special_reference(order_id: &str) -> Result<String, IntegrationValidationError> {
    let trimmed = order_id.trim();
    if trimmed.is_empty() {
        return Err(IntegrationValidationError::ValidationError(
            "order_id must not be empty when mapping special_reference".to_owned(),
        ));
    }
    Ok(trimmed.to_owned())
}

fn validate_billing_data(
    billing_data: Option<&IntentionBillingData>,
) -> Result<(), IntegrationValidationError> {
    let Some(billing) = billing_data else {
        return Ok(());
    };
    if billing.phone_number.trim().is_empty() {
        return Err(IntegrationValidationError::ValidationError(
            "billing_data.phone_number must not be empty when billing_data is provided".to_owned(),
        ));
    }
    Ok(())
}

fn validate_line_items(
    items: &[IntentionLineItem],
) -> Result<Option<u64>, IntegrationValidationError> {
    if items.is_empty() {
        return Ok(None);
    }

    let mut total: u64 = 0;
    for (index, item) in items.iter().enumerate() {
        validate_single_item(index, item)?;
        total = total.checked_add(item.amount).ok_or_else(|| {
            IntegrationValidationError::ValidationError(
                "sum of item amounts overflowed u64 minor units".to_owned(),
            )
        })?;
    }

    Ok(Some(total))
}

fn validate_single_item(
    index: usize,
    item: &IntentionLineItem,
) -> Result<(), IntegrationValidationError> {
    if item.name.trim().is_empty() {
        return Err(IntegrationValidationError::ValidationError(format!(
            "items[{index}].name must not be empty"
        )));
    }
    if item.amount == 0 {
        return Err(IntegrationValidationError::ValidationError(format!(
            "items[{index}].amount must be greater than zero"
        )));
    }
    if item.quantity == Some(0) {
        return Err(IntegrationValidationError::ValidationError(format!(
            "items[{index}].quantity must be greater than zero when provided"
        )));
    }
    Ok(())
}

fn resolve_effective_alias(
    capture_mode: AlignmentCaptureMode,
    alias: Option<&str>,
) -> Option<String> {
    if capture_mode != AlignmentCaptureMode::Automatic {
        return None;
    }
    alias.map(|raw| raw.trim().to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> IntegrationRoutingConfig {
        IntegrationRoutingConfig::new(vec![100_001, 100_002])
            .with_auth_integration_id(900_009)
            .with_alias("card", 200_001)
            .with_alias("wallet", 200_002)
            .with_alias("valu", 200_003)
            .with_alias("apple_pay", 200_004)
    }

    fn base_input() -> IntentionPreflightInput {
        IntentionPreflightInput {
            order_id: "order-913-alpha".to_owned(),
            capture_mode: AlignmentCaptureMode::Automatic,
            payment_method_alias: None,
            billing_data: None,
            items: Vec::new(),
        }
    }

    #[test]
    fn manual_capture_without_auth_integration_id_fails_closed() {
        let config = IntegrationRoutingConfig::new(vec![100_001]).with_alias("card", 200_001);
        let mut input = base_input();
        input.capture_mode = AlignmentCaptureMode::Manual;
        input.payment_method_alias = Some("card".to_owned());

        let err = validate_intention_preflight(&config, &input)
            .expect_err("Manual capture without auth_integration_id must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ConfigurationError(_)
        ));
    }

    #[test]
    fn manual_capture_with_zero_auth_integration_id_fails_closed() {
        let config = IntegrationRoutingConfig::new(vec![100_001]).with_auth_integration_id(0);
        let mut input = base_input();
        input.capture_mode = AlignmentCaptureMode::Manual;

        let err = validate_intention_preflight(&config, &input)
            .expect_err("auth_integration_id == 0 must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ConfigurationError(_)
        ));
    }

    #[test]
    fn manual_capture_with_auth_integration_id_selects_it() {
        let config = sample_config();
        let mut input = base_input();
        input.capture_mode = AlignmentCaptureMode::Manual;

        let routing = validate_intention_preflight(&config, &input)
            .expect("Manual capture with valid auth_integration_id must succeed");
        assert_eq!(routing.payment_methods, vec![900_009]);
        assert_eq!(routing.capture_mode, AlignmentCaptureMode::Manual);
        assert_eq!(routing.special_reference, "order-913-alpha");
        assert_eq!(routing.resolved_alias, None);
    }

    #[test]
    fn named_aliases_resolve_cleanly_even_with_empty_defaults() {
        let config = IntegrationRoutingConfig::new(Vec::new())
            .with_alias("card", 300_001)
            .with_alias("wallet", 300_002)
            .with_alias("valu", 300_003)
            .with_alias("apple_pay", 300_004);

        for (alias, expected_id) in [
            ("card", 300_001),
            ("WALLET", 300_002),
            (" valu ", 300_003),
            ("apple_pay", 300_004),
        ] {
            let mut input = base_input();
            input.payment_method_alias = Some(alias.to_owned());

            let routing = validate_intention_preflight(&config, &input)
                .expect("registered alias must resolve cleanly");
            assert_eq!(routing.payment_methods, vec![expected_id]);
            assert_eq!(
                routing.resolved_alias.as_deref(),
                Some(alias.trim().to_ascii_lowercase().as_str())
            );
        }
    }

    #[test]
    fn automatic_capture_rejects_empty_defaults_zero_ids_and_unknown_aliases() {
        let empty_config = IntegrationRoutingConfig::new(Vec::new());
        let err = validate_intention_preflight(&empty_config, &base_input())
            .expect_err("empty default_integration_ids without alias must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ConfigurationError(_)
        ));

        let zero_default = IntegrationRoutingConfig::new(vec![100_001, 0]);
        let err = validate_intention_preflight(&zero_default, &base_input())
            .expect_err("default_integration_ids containing 0 must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ConfigurationError(_)
        ));

        let zero_alias = IntegrationRoutingConfig::new(vec![100_001]).with_alias("card", 0);
        let mut alias_input = base_input();
        alias_input.payment_method_alias = Some("card".to_owned());
        let err = validate_intention_preflight(&zero_alias, &alias_input)
            .expect_err("alias mapped to 0 must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ConfigurationError(_)
        ));

        alias_input.payment_method_alias = Some("unknown_rail".to_owned());
        let err = validate_intention_preflight(&sample_config(), &alias_input)
            .expect_err("unknown alias must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ConfigurationError(_)
        ));

        alias_input.payment_method_alias = Some("   ".to_owned());
        let err = validate_intention_preflight(&sample_config(), &alias_input)
            .expect_err("blank alias must fail with ValidationError");
        assert!(matches!(
            err,
            IntegrationValidationError::ValidationError(_)
        ));
    }

    #[test]
    fn items_missing_name_zero_amount_or_overflow_fail_closed() {
        let config = sample_config();

        let mut empty_name_input = base_input();
        empty_name_input.items = vec![IntentionLineItem::new("   ", 500)];
        let err = validate_intention_preflight(&config, &empty_name_input)
            .expect_err("item with blank name must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ValidationError(_)
        ));

        let mut zero_amount_input = base_input();
        zero_amount_input.items = vec![IntentionLineItem::new("Subscription", 0)];
        let err = validate_intention_preflight(&config, &zero_amount_input)
            .expect_err("item with amount == 0 must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ValidationError(_)
        ));

        let mut zero_qty_input = base_input();
        let mut item = IntentionLineItem::new("Subscription", 500);
        item.quantity = Some(0);
        zero_qty_input.items = vec![item];
        let err = validate_intention_preflight(&config, &zero_qty_input)
            .expect_err("item with quantity == Some(0) must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ValidationError(_)
        ));

        let mut overflow_input = base_input();
        overflow_input.items = vec![
            IntentionLineItem::new("Max", u64::MAX),
            IntentionLineItem::new("Overflow", 1),
        ];
        let err = validate_intention_preflight(&config, &overflow_input)
            .expect_err("overflowing item sum must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ValidationError(_)
        ));

        let mut valid_items_input = base_input();
        valid_items_input.items = vec![
            IntentionLineItem::new("Item A", 1_250),
            IntentionLineItem::new("Item B", 3_750),
        ];
        let routing = validate_intention_preflight(&config, &valid_items_input)
            .expect("valid items must pass pre-flight validation");
        assert_eq!(routing.items_total_minor_units, Some(5_000));
    }

    #[test]
    fn billing_data_missing_phone_number_fails_closed() {
        let config = sample_config();

        let mut missing_phone = base_input();
        missing_phone.billing_data =
            Some(IntentionBillingData::new("   ").with_email("user@example.com"));
        let err = validate_intention_preflight(&config, &missing_phone)
            .expect_err("billing_data without phone_number must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ValidationError(_)
        ));

        let mut valid_phone = base_input();
        valid_phone.billing_data = Some(
            IntentionBillingData::new("+201009998877")
                .with_email("user@example.com")
                .with_name("Ada", "Lovelace"),
        );
        let routing = validate_intention_preflight(&config, &valid_phone)
            .expect("billing_data with valid phone_number must succeed");
        assert_eq!(routing.payment_methods, vec![100_001, 100_002]);
    }

    #[test]
    fn special_reference_maps_order_id_and_rejects_empty() {
        let config = sample_config();

        let mut valid_order = base_input();
        valid_order.order_id = "  ord-2026-999  ".to_owned();
        let routing = validate_intention_preflight(&config, &valid_order)
            .expect("non-empty order_id must map to special_reference");
        assert_eq!(routing.special_reference, "ord-2026-999");

        let mut blank_order = base_input();
        blank_order.order_id = "   ".to_owned();
        let err = validate_intention_preflight(&config, &blank_order)
            .expect_err("blank order_id must fail closed");
        assert!(matches!(
            err,
            IntegrationValidationError::ValidationError(_)
        ));
    }

    #[test]
    fn billing_data_debug_redacts_pii() {
        let billing = IntentionBillingData::new("+201001234567")
            .with_email("sensitive.payer@example.com")
            .with_name("Grace", "Hopper");
        let rendered = format!("{billing:?}");
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("+201001234567"));
        assert!(!rendered.contains("sensitive.payer@example.com"));

        let mut input = base_input();
        input.billing_data = Some(billing);
        let rendered_input = format!("{input:?}");
        assert!(rendered_input.contains("[REDACTED]"));
        assert!(!rendered_input.contains("+201001234567"));
        assert!(!rendered_input.contains("sensitive.payer@example.com"));
    }
}
