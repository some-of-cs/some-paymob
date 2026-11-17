#![forbid(unsafe_code)]
//! Billing, customer, and line-item models for Paymob v1 Payment Intentions.
//!
//! Enforces builder-time and deserialization-time validation of mandatory
//! `billing_data.phone_number` and `IntentionItem` (`name`, positive integer
//! minor-unit `amount`, and non-zero `quantity`), while redacting all customer
//! PII in [`fmt::Debug`] output (`[REDACTED]`).

use std::fmt;

use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};

use crate::core::error::PaymobError;
use crate::core::types::MinorUnitAmount;

const REDACTED: &str = "[REDACTED]";

/// Validated billing address and contact details for a v1 Payment Intention.
///
/// Paymob requires `phone_number` whenever `billing_data` is supplied on
/// `POST /v1/intention/` or `PUT /v1/intention/`. Construct instances via
/// [`BillingData::builder`] to enforce non-empty `phone_number` before network I/O.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::intentions::billing::BillingData;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let billing = BillingData::builder()
///     .phone_number("+201116491564")
///     .first_name("Maher")
///     .last_name("Mansour")
///     .email("billing@example.com")
///     .city("Mansoura")
///     .country("EG")
///     .build()?;
///
/// assert_eq!(billing.phone_number(), "+201116491564");
/// assert!(format!("{billing:?}").contains("[REDACTED]"));
/// # Ok(())
/// # }
/// ```
///
/// Direct struct literal construction is rejected at compile time so callers
/// cannot bypass [`BillingDataBuilder::build`]:
///
/// ```compile_fail
/// use some_paymob::resources::intentions::billing::BillingData;
///
/// let _ = BillingData {
///     phone_number: String::new(),
///     first_name: None,
///     last_name: None,
///     email: None,
///     apartment: None,
///     floor: None,
///     street: None,
///     building: None,
///     shipping_method: None,
///     postal_code: None,
///     city: None,
///     country: None,
///     state: None,
/// };
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct BillingData {
    phone_number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    apartment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    floor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    street: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    building: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shipping_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Deserialize)]
struct RawBillingData {
    phone_number: String,
    #[serde(default)]
    first_name: Option<String>,
    #[serde(default)]
    last_name: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    apartment: Option<String>,
    #[serde(default)]
    floor: Option<String>,
    #[serde(default)]
    street: Option<String>,
    #[serde(default)]
    building: Option<String>,
    #[serde(default)]
    shipping_method: Option<String>,
    #[serde(default)]
    postal_code: Option<String>,
    #[serde(default)]
    city: Option<String>,
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

impl<'de> Deserialize<'de> for BillingData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawBillingData::deserialize(deserializer)?;
        from_raw_billing(raw).map_err(D::Error::custom)
    }
}

fn from_raw_billing(raw: RawBillingData) -> Result<BillingData, PaymobError> {
    let phone_number = require_non_empty(
        Some(raw.phone_number),
        "billing_data.phone_number",
        "billing_data.phone_number is required and cannot be empty",
    )?;
    Ok(BillingData {
        phone_number,
        first_name: raw.first_name.and_then(normalize_opt),
        last_name: raw.last_name.and_then(normalize_opt),
        email: raw.email.and_then(normalize_opt),
        apartment: raw.apartment.and_then(normalize_opt),
        floor: raw.floor.and_then(normalize_opt),
        street: raw.street.and_then(normalize_opt),
        building: raw.building.and_then(normalize_opt),
        shipping_method: raw.shipping_method.and_then(normalize_opt),
        postal_code: raw.postal_code.and_then(normalize_opt),
        city: raw.city.and_then(normalize_opt),
        country: raw.country.and_then(normalize_opt),
        state: raw.state.and_then(normalize_opt),
    })
}

impl BillingData {
    /// Creates a new [`BillingDataBuilder`] for constructing validated billing data.
    #[must_use]
    pub fn builder() -> BillingDataBuilder {
        BillingDataBuilder::new()
    }

    /// Returns the mandatory customer phone number.
    #[must_use]
    pub fn phone_number(&self) -> &str {
        &self.phone_number
    }

    /// Returns the optional customer first name.
    #[must_use]
    pub fn first_name(&self) -> Option<&str> {
        self.first_name.as_deref()
    }

    /// Returns the optional customer last name.
    #[must_use]
    pub fn last_name(&self) -> Option<&str> {
        self.last_name.as_deref()
    }

    /// Returns the optional customer email address.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Returns the optional apartment number.
    #[must_use]
    pub fn apartment(&self) -> Option<&str> {
        self.apartment.as_deref()
    }

    /// Returns the optional floor number.
    #[must_use]
    pub fn floor(&self) -> Option<&str> {
        self.floor.as_deref()
    }

    /// Returns the optional street address.
    #[must_use]
    pub fn street(&self) -> Option<&str> {
        self.street.as_deref()
    }

    /// Returns the optional building identifier.
    #[must_use]
    pub fn building(&self) -> Option<&str> {
        self.building.as_deref()
    }

    /// Returns the optional shipping method.
    #[must_use]
    pub fn shipping_method(&self) -> Option<&str> {
        self.shipping_method.as_deref()
    }

    /// Returns the optional postal code.
    #[must_use]
    pub fn postal_code(&self) -> Option<&str> {
        self.postal_code.as_deref()
    }

    /// Returns the optional city name.
    #[must_use]
    pub fn city(&self) -> Option<&str> {
        self.city.as_deref()
    }

    /// Returns the optional ISO country code or name.
    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// Returns the optional state or governorate name.
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }
}

impl fmt::Debug for BillingData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BillingData")
            .field("phone_number", &REDACTED)
            .field("first_name", &redact_opt(&self.first_name))
            .field("last_name", &redact_opt(&self.last_name))
            .field("email", &redact_opt(&self.email))
            .field("apartment", &redact_opt(&self.apartment))
            .field("floor", &redact_opt(&self.floor))
            .field("street", &redact_opt(&self.street))
            .field("building", &redact_opt(&self.building))
            .field("shipping_method", &self.shipping_method)
            .field("postal_code", &redact_opt(&self.postal_code))
            .field("city", &self.city)
            .field("country", &self.country)
            .field("state", &self.state)
            .finish()
    }
}

/// Builder for [`BillingData`] enforcing non-empty `phone_number` at `.build()` time.
#[derive(Clone, Default)]
pub struct BillingDataBuilder {
    phone_number: Option<String>,
    first_name: Option<String>,
    last_name: Option<String>,
    email: Option<String>,
    apartment: Option<String>,
    floor: Option<String>,
    street: Option<String>,
    building: Option<String>,
    shipping_method: Option<String>,
    postal_code: Option<String>,
    city: Option<String>,
    country: Option<String>,
    state: Option<String>,
}

impl BillingDataBuilder {
    /// Creates an empty [`BillingDataBuilder`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the mandatory customer phone number.
    #[must_use]
    pub fn phone_number(mut self, phone_number: impl Into<String>) -> Self {
        self.phone_number = Some(phone_number.into());
        self
    }

    /// Sets the customer first name.
    #[must_use]
    pub fn first_name(mut self, first_name: impl Into<String>) -> Self {
        self.first_name = normalize_opt(first_name.into());
        self
    }

    /// Sets the customer last name.
    #[must_use]
    pub fn last_name(mut self, last_name: impl Into<String>) -> Self {
        self.last_name = normalize_opt(last_name.into());
        self
    }

    /// Sets the customer email address.
    #[must_use]
    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.email = normalize_opt(email.into());
        self
    }

    /// Sets the apartment number.
    #[must_use]
    pub fn apartment(mut self, apartment: impl Into<String>) -> Self {
        self.apartment = normalize_opt(apartment.into());
        self
    }

    /// Sets the floor number.
    #[must_use]
    pub fn floor(mut self, floor: impl Into<String>) -> Self {
        self.floor = normalize_opt(floor.into());
        self
    }

    /// Sets the street address.
    #[must_use]
    pub fn street(mut self, street: impl Into<String>) -> Self {
        self.street = normalize_opt(street.into());
        self
    }

    /// Sets the building identifier.
    #[must_use]
    pub fn building(mut self, building: impl Into<String>) -> Self {
        self.building = normalize_opt(building.into());
        self
    }

    /// Sets the shipping method.
    #[must_use]
    pub fn shipping_method(mut self, shipping_method: impl Into<String>) -> Self {
        self.shipping_method = normalize_opt(shipping_method.into());
        self
    }

    /// Sets the postal code.
    #[must_use]
    pub fn postal_code(mut self, postal_code: impl Into<String>) -> Self {
        self.postal_code = normalize_opt(postal_code.into());
        self
    }

    /// Sets the state or governorate name.
    #[must_use]
    pub fn city(mut self, city: impl Into<String>) -> Self {
        self.city = normalize_opt(city.into());
        self
    }

    /// Sets the country code or name.
    #[must_use]
    pub fn country(mut self, country: impl Into<String>) -> Self {
        self.country = normalize_opt(country.into());
        self
    }

    /// Sets the state or governorate name.
    #[must_use]
    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = normalize_opt(state.into());
        self
    }

    /// Validates and constructs [`BillingData`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `phone_number` was omitted
    /// or contains only whitespace.
    pub fn build(self) -> Result<BillingData, PaymobError> {
        let phone = require_non_empty(
            self.phone_number,
            "billing_data.phone_number",
            "billing_data.phone_number is required and cannot be empty",
        )?;

        Ok(BillingData {
            phone_number: phone,
            first_name: self.first_name,
            last_name: self.last_name,
            email: self.email,
            apartment: self.apartment,
            floor: self.floor,
            street: self.street,
            building: self.building,
            shipping_method: self.shipping_method,
            postal_code: self.postal_code,
            city: self.city,
            country: self.country,
            state: self.state,
        })
    }
}

impl fmt::Debug for BillingDataBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BillingDataBuilder")
            .field("phone_number", &redact_opt(&self.phone_number))
            .field("first_name", &redact_opt(&self.first_name))
            .field("last_name", &redact_opt(&self.last_name))
            .field("email", &redact_opt(&self.email))
            .field("city", &self.city)
            .field("country", &self.country)
            .finish_non_exhaustive()
    }
}

/// Optional customer profile attached to a v1 Payment Intention.
///
/// Redacts PII fields (`first_name`, `last_name`, `email`) in [`fmt::Debug`].
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::intentions::billing::IntentionCustomer;
///
/// let customer = IntentionCustomer::new()
///     .with_first_name("Maher")
///     .with_last_name("Mansour")
///     .with_email("customer@example.com");
///
/// assert_eq!(customer.first_name(), Some("Maher"));
/// assert!(format!("{customer:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentionCustomer {
    #[serde(skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    extras: Option<serde_json::Value>,
}

impl IntentionCustomer {
    /// Creates an empty [`IntentionCustomer`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the customer first name.
    #[must_use]
    pub fn with_first_name(mut self, first_name: impl Into<String>) -> Self {
        self.first_name = normalize_opt(first_name.into());
        self
    }

    /// Sets the customer last name.
    #[must_use]
    pub fn with_last_name(mut self, last_name: impl Into<String>) -> Self {
        self.last_name = normalize_opt(last_name.into());
        self
    }

    /// Sets the customer email address.
    #[must_use]
    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = normalize_opt(email.into());
        self
    }

    /// Attaches arbitrary JSON metadata to `customer.extras`.
    #[must_use]
    pub fn with_extras(mut self, extras: serde_json::Value) -> Self {
        self.extras = Some(extras);
        self
    }

    /// Returns the customer first name, if set.
    #[must_use]
    pub fn first_name(&self) -> Option<&str> {
        self.first_name.as_deref()
    }

    /// Returns the customer last name, if set.
    #[must_use]
    pub fn last_name(&self) -> Option<&str> {
        self.last_name.as_deref()
    }

    /// Returns the customer email, if set.
    #[must_use]
    pub fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    /// Returns the customer extras JSON payload, if set.
    #[must_use]
    pub const fn extras(&self) -> Option<&serde_json::Value> {
        self.extras.as_ref()
    }
}

impl fmt::Debug for IntentionCustomer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntentionCustomer")
            .field("first_name", &redact_opt(&self.first_name))
            .field("last_name", &redact_opt(&self.last_name))
            .field("email", &redact_opt(&self.email))
            .field("extras", &self.extras.as_ref().map(|_| REDACTED))
            .finish()
    }
}

/// Validated line item in a v1 Payment Intention (`items[]`).
///
/// Enforces non-empty `name`, strictly positive integer minor-unit `amount`
/// (zero floats), and non-zero `quantity` when present.
///
/// # Examples
///
/// ```rust
/// use some_paymob::core::types::MinorUnitAmount;
/// use some_paymob::resources::intentions::billing::IntentionItem;
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let item = IntentionItem::new("Rust Systems Course", MinorUnitAmount::new(50_000))?
///     .with_quantity(1)
///     .with_description("Full-stack systems engineering");
///
/// assert_eq!(item.name(), "Rust Systems Course");
/// assert_eq!(item.amount().as_u64(), 50_000);
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IntentionItem {
    name: String,
    amount: MinorUnitAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    quantity: Option<u64>,
}

#[derive(Deserialize)]
struct RawIntentionItem {
    name: String,
    amount: MinorUnitAmount,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    quantity: Option<u64>,
}

impl<'de> Deserialize<'de> for IntentionItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawIntentionItem::deserialize(deserializer)?;
        from_raw_item(raw).map_err(D::Error::custom)
    }
}

fn from_raw_item(raw: RawIntentionItem) -> Result<IntentionItem, PaymobError> {
    let mut item = IntentionItem::new(raw.name, raw.amount)?;
    if let Some(desc) = raw.description {
        item.description = normalize_opt(desc);
    }
    if let Some(qty) = raw.quantity {
        item = item.try_with_quantity(qty)?;
    }
    Ok(item)
}

impl IntentionItem {
    /// Creates a validated [`IntentionItem`] with a non-empty `name` and
    /// positive minor-unit `amount`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `name` is empty/whitespace
    /// or `amount` is zero.
    pub fn new(
        name: impl Into<String>,
        amount: impl Into<MinorUnitAmount>,
    ) -> Result<Self, PaymobError> {
        let validated_name = require_non_empty(
            Some(name.into()),
            "items.name",
            "item name is required and cannot be empty",
        )?;
        let validated_amount = amount.into();
        if validated_amount.is_zero() {
            return Err(PaymobError::ValidationError {
                field: "items.amount",
                reason: "item amount must be greater than zero minor units".to_owned(),
            });
        }

        Ok(Self {
            name: validated_name,
            amount: validated_amount,
            description: None,
            quantity: None,
        })
    }

    /// Attaches an optional line-item description.
    #[must_use]
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = normalize_opt(description.into());
        self
    }

    /// Attaches an optional item quantity.
    #[must_use]
    pub const fn with_quantity(mut self, quantity: u64) -> Self {
        self.quantity = Some(quantity);
        self
    }

    /// Attaches a validated non-zero item quantity.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `quantity == 0`.
    pub fn try_with_quantity(mut self, quantity: u64) -> Result<Self, PaymobError> {
        if quantity == 0 {
            return Err(PaymobError::ValidationError {
                field: "items.quantity",
                reason: "item quantity must be greater than zero".to_owned(),
            });
        }
        self.quantity = Some(quantity);
        Ok(self)
    }

    /// Validates all domain invariants on this [`IntentionItem`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `name` is blank, `amount` is zero,
    /// or `quantity` is `Some(0)`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.name.trim().is_empty() {
            return Err(PaymobError::ValidationError {
                field: "items.name",
                reason: "item name is required and cannot be empty".to_owned(),
            });
        }
        if self.amount.is_zero() {
            return Err(PaymobError::ValidationError {
                field: "items.amount",
                reason: "item amount must be greater than zero minor units".to_owned(),
            });
        }
        if self.quantity == Some(0) {
            return Err(PaymobError::ValidationError {
                field: "items.quantity",
                reason: "item quantity must be greater than zero".to_owned(),
            });
        }
        Ok(())
    }

    /// Returns the item name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the item unit amount in integer minor units.
    #[must_use]
    pub const fn amount(&self) -> MinorUnitAmount {
        self.amount
    }

    /// Returns the optional item description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }

    /// Returns the optional item quantity.
    #[must_use]
    pub const fn quantity(&self) -> Option<u64> {
        self.quantity
    }
}

fn normalize_opt(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn require_non_empty(
    value: Option<String>,
    field: &'static str,
    reason: &str,
) -> Result<String, PaymobError> {
    let raw = value.ok_or_else(|| PaymobError::ValidationError {
        field,
        reason: reason.to_owned(),
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: reason.to_owned(),
        });
    }
    Ok(trimmed.to_owned())
}

fn redact_opt<T>(value: &Option<T>) -> Option<&'static str> {
    value.as_ref().map(|_| REDACTED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_2_1_1_billing_data_builder_happy_path_and_serde() {
        let billing = BillingData::builder()
            .phone_number(" +201116491564 ")
            .first_name("Maher")
            .last_name("Mansour")
            .email("billing@example.com")
            .city("Mansoura")
            .country("EG")
            .build()
            .expect("valid billing data");

        assert_eq!(billing.phone_number(), "+201116491564");
        assert_eq!(billing.first_name(), Some("Maher"));
        assert_eq!(billing.city(), Some("Mansoura"));

        let json = serde_json::to_value(&billing).expect("serialize billing_data");
        assert_eq!(json["phone_number"], "+201116491564");
        assert!(json.get("apartment").is_none());
    }

    #[test]
    fn tc_2_1_1_billing_data_rejects_missing_or_blank_phone_number() {
        let missing = BillingData::builder().first_name("Maher").build();
        assert!(matches!(
            missing,
            Err(PaymobError::ValidationError {
                field: "billing_data.phone_number",
                ..
            })
        ));

        let blank = BillingData::builder().phone_number("   \t\n ").build();
        assert!(matches!(
            blank,
            Err(PaymobError::ValidationError {
                field: "billing_data.phone_number",
                ..
            })
        ));
    }

    #[test]
    fn tc_2_1_1_intention_item_validates_name_and_minor_unit_amount() {
        let item = IntentionItem::new("Coffee", 4_000_u64)
            .expect("valid item")
            .with_quantity(2)
            .with_description("Specialty roast");

        assert_eq!(item.name(), "Coffee");
        assert_eq!(item.amount().as_u64(), 4_000);
        assert_eq!(item.quantity(), Some(2));
        item.validate().expect("valid item invariants");

        let empty_name = IntentionItem::new("  ", 4_000_u64);
        assert!(matches!(
            empty_name,
            Err(PaymobError::ValidationError {
                field: "items.name",
                ..
            })
        ));

        let zero_amount = IntentionItem::new("Coffee", 0_u64);
        assert!(matches!(
            zero_amount,
            Err(PaymobError::ValidationError {
                field: "items.amount",
                ..
            })
        ));

        let zero_qty = IntentionItem::new("Coffee", 4_000_u64)
            .expect("valid item")
            .try_with_quantity(0);
        assert!(matches!(
            zero_qty,
            Err(PaymobError::ValidationError {
                field: "items.quantity",
                ..
            })
        ));
    }

    #[test]
    fn tc_2_1_5_debug_redacts_billing_and_customer_pii() {
        let billing = BillingData::builder()
            .phone_number("+201116491564")
            .first_name("Maher")
            .email("secret.user@example.com")
            .street("El Gomhouria St")
            .build()
            .expect("valid billing");

        let billing_dbg = format!("{billing:?}");
        assert!(billing_dbg.contains("[REDACTED]"));
        assert!(!billing_dbg.contains("+201116491564"));
        assert!(!billing_dbg.contains("secret.user@example.com"));
        assert!(!billing_dbg.contains("El Gomhouria St"));

        let customer = IntentionCustomer::new()
            .with_first_name("Maher")
            .with_email("customer@example.com");
        let cust_dbg = format!("{customer:?}");
        assert!(cust_dbg.contains("[REDACTED]"));
        assert!(!cust_dbg.contains("customer@example.com"));
        assert!(!cust_dbg.contains("Maher"));
    }

    #[test]
    fn tc_2_1_cycle2_deserialize_billing_and_item_enforce_domain_bounds() {
        let blank_phone = serde_json::from_str::<BillingData>(r#"{"phone_number":"   "}"#);
        assert!(blank_phone.is_err());

        let normalized_billing = serde_json::from_str::<BillingData>(
            r#"{"phone_number":" +201116491564 ","first_name":"  ","city":" Mansoura "}"#,
        )
        .expect("valid billing deserialization");
        assert_eq!(normalized_billing.phone_number(), "+201116491564");
        assert_eq!(normalized_billing.first_name(), None);
        assert_eq!(normalized_billing.city(), Some("Mansoura"));

        let blank_item_name =
            serde_json::from_str::<IntentionItem>(r#"{"name":"  ","amount":1000}"#);
        assert!(blank_item_name.is_err());

        let zero_item_amount =
            serde_json::from_str::<IntentionItem>(r#"{"name":"Course","amount":0}"#);
        assert!(zero_item_amount.is_err());

        let zero_item_qty =
            serde_json::from_str::<IntentionItem>(r#"{"name":"Course","amount":1000,"quantity":0}"#);
        assert!(zero_item_qty.is_err());
    }
}
