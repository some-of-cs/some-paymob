#![forbid(unsafe_code)]
//! Partner merchant onboarding flow request and response models (`US-6.2.0`).
//!
//! Provides strongly typed, PII-redacted models for sub-merchant registration,
//! dynamic onboarding flow schema discovery, KYC step submission, and partner
//! merchant status inquiry under Regime 4 partner authentication.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::form_urlencoded;
use zeroize::Zeroize;

use crate::core::error::PaymobError;

/// Validates that a required string field is non-empty after trimming.
fn require_non_empty(field: &'static str, value: &str) -> Result<(), PaymobError> {
    if value.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

/// Validates that a partner identifier is non-empty and free of control characters.
fn validate_partner_slug(partner: &str) -> Result<(), PaymobError> {
    let trimmed = partner.trim();
    if trimmed.is_empty() || partner.bytes().any(|b| b.is_ascii_control()) {
        return Err(PaymobError::ValidationError {
            field: "partner",
            reason: "partner identifier must be non-empty and free of control characters"
                .to_owned(),
        });
    }
    Ok(())
}

/// Parameters for registering a new sub-merchant under a Paymob Partner (`POST /api/onboarding/register`).
///
/// PII fields (`email`, `phone_number`, `first_name`, `last_name`) are redacted as
/// `"[REDACTED]"` in [`fmt::Debug`] output and zeroized on drop.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::onboarding::flow_models::RegisterMerchantParams;
///
/// let params = RegisterMerchantParams::new(
///     "KeyPartner",
///     "merchant@example.com",
///     "+201000000000",
///     "Amira",
///     "Hassan",
/// )?
/// .with_company_name("Acme Commerce")
/// .with_country("EGY");
///
/// assert_eq!(params.partner(), "KeyPartner");
/// assert_eq!(params.company_name(), Some("Acme Commerce"));
/// assert!(format!("{params:?}").contains("[REDACTED]"));
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct RegisterMerchantParams {
    /// Partner identifier slug assigned by Paymob.
    partner: String,
    /// Sub-merchant primary contact email address.
    email: String,
    /// Sub-merchant primary contact phone number (E.164 or local format).
    phone_number: String,
    /// Sub-merchant representative first name.
    first_name: String,
    /// Sub-merchant representative last name.
    last_name: String,
    /// Optional legal or trading company name.
    #[serde(skip_serializing_if = "Option::is_none")]
    company_name: Option<String>,
    /// Optional ISO country code (e.g. `"EGY"`, `"KSA"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
    /// Additional partner-specific registration attributes.
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl Drop for RegisterMerchantParams {
    fn drop(&mut self) {
        self.email.zeroize();
        self.phone_number.zeroize();
        self.first_name.zeroize();
        self.last_name.zeroize();
    }
}

impl fmt::Debug for RegisterMerchantParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegisterMerchantParams")
            .field("partner", &self.partner)
            .field("email", &"[REDACTED]")
            .field("phone_number", &"[REDACTED]")
            .field("first_name", &"[REDACTED]")
            .field("last_name", &"[REDACTED]")
            .field("company_name", &self.company_name)
            .field("country", &self.country)
            .field("extra_keys", &self.extra.len())
            .finish()
    }
}

impl RegisterMerchantParams {
    /// Constructs and validates [`RegisterMerchantParams`] with required merchant fields.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any required field is empty or
    /// if `partner` contains control characters.
    pub fn new(
        partner: impl Into<String>,
        email: impl Into<String>,
        phone_number: impl Into<String>,
        first_name: impl Into<String>,
        last_name: impl Into<String>,
    ) -> Result<Self, PaymobError> {
        let params = Self {
            partner: partner.into(),
            email: email.into(),
            phone_number: phone_number.into(),
            first_name: first_name.into(),
            last_name: last_name.into(),
            company_name: None,
            country: None,
            extra: Map::new(),
        };
        params.validate()?;
        Ok(params)
    }

    /// Sets the optional company or trading name.
    #[must_use]
    pub fn with_company_name(mut self, company_name: impl Into<String>) -> Self {
        self.company_name = Some(company_name.into());
        self
    }

    /// Sets the optional country code (for example, `"EGY"` or `"KSA"`).
    #[must_use]
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = Some(country.into());
        self
    }

    /// Inserts an additional partner-specific registration attribute.
    #[must_use]
    pub fn with_extra(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra.insert(key.into(), value);
        self
    }

    /// Returns the partner identifier slug.
    #[must_use]
    pub fn partner(&self) -> &str {
        &self.partner
    }

    /// Returns the optional company name.
    #[must_use]
    pub fn company_name(&self) -> Option<&str> {
        self.company_name.as_deref()
    }

    /// Returns the optional country code.
    #[must_use]
    pub fn country(&self) -> Option<&str> {
        self.country.as_deref()
    }

    /// Validates all required registration fields.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any required field is empty.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_partner_slug(&self.partner)?;
        require_non_empty("email", &self.email)?;
        require_non_empty("phone_number", &self.phone_number)?;
        require_non_empty("first_name", &self.first_name)?;
        require_non_empty("last_name", &self.last_name)?;
        Ok(())
    }
}

/// Response returned after registering a sub-merchant with Paymob.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::onboarding::flow_models::RegisteredMerchantResponse;
///
/// let json = r#"{"paymob_mid": 987654, "partner": "KeyPartner", "status": "pending_kyc"}"#;
/// let resp: RegisteredMerchantResponse = serde_json::from_str(json)?;
/// assert_eq!(resp.paymob_mid, 987_654);
/// assert_eq!(resp.status.as_deref(), Some("pending_kyc"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredMerchantResponse {
    /// Assigned Paymob Merchant ID (`paymob_mid`).
    #[serde(alias = "id", alias = "merchant_id")]
    pub paymob_mid: u64,
    /// Partner identifier associated with the registered sub-merchant.
    #[serde(default)]
    pub partner: Option<String>,
    /// Initial onboarding status reported by Paymob.
    #[serde(default)]
    pub status: Option<String>,
    /// Optional hosted onboarding portal URL, if returned.
    #[serde(default)]
    pub onboarding_url: Option<String>,
    /// Additional response fields returned by Paymob.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Query parameters for `GET /api/onboarding/flow/schema`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::onboarding::flow_models::OnboardingSchemaQuery;
///
/// let query = OnboardingSchemaQuery::new("KeyPartner")?
///     .with_resubmission(true)
///     .with_paymob_mid(123);
///
/// assert_eq!(
///     query.to_query_string()?,
///     "partner=KeyPartner&resubmission=true&paymob_mid=123"
/// );
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingSchemaQuery {
    /// Partner identifier slug (required).
    pub partner: String,
    /// Whether to request the resubmission schema variant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resubmission: Option<bool>,
    /// Optional existing Paymob Merchant ID for merchant-specific schema state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymob_mid: Option<u64>,
}

impl OnboardingSchemaQuery {
    /// Constructs a validated [`OnboardingSchemaQuery`] for `partner`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `partner` is empty or contains
    /// control characters.
    pub fn new(partner: impl Into<String>) -> Result<Self, PaymobError> {
        let query = Self {
            partner: partner.into(),
            resubmission: None,
            paymob_mid: None,
        };
        query.validate()?;
        Ok(query)
    }

    /// Sets the `resubmission` query flag.
    #[must_use]
    pub const fn with_resubmission(mut self, resubmission: bool) -> Self {
        self.resubmission = Some(resubmission);
        self
    }

    /// Sets the `paymob_mid` query parameter.
    #[must_use]
    pub const fn with_paymob_mid(mut self, paymob_mid: u64) -> Self {
        self.paymob_mid = Some(paymob_mid);
        self
    }

    /// Validates query parameters before network dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `partner` is invalid or `paymob_mid` is `Some(0)`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        validate_partner_slug(&self.partner)?;
        if self.paymob_mid == Some(0) {
            return Err(PaymobError::ValidationError {
                field: "paymob_mid",
                reason: "paymob_mid must be a non-zero merchant ID".to_owned(),
            });
        }
        Ok(())
    }

    /// Encodes the validated parameters as a URL query string without leading `?`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if validation fails.
    pub fn to_query_string(&self) -> Result<String, PaymobError> {
        self.validate()?;
        let mut ser = form_urlencoded::Serializer::new(String::new());
        ser.append_pair("partner", self.partner.trim());
        if let Some(resubmission) = self.resubmission {
            ser.append_pair("resubmission", if resubmission { "true" } else { "false" });
        }
        if let Some(mid) = self.paymob_mid {
            ser.append_pair("paymob_mid", &mid.to_string());
        }
        Ok(ser.finish())
    }
}

/// Individual field descriptor inside an onboarding KYC step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingSchemaField {
    /// Machine-readable field key name.
    pub name: String,
    /// Optional field input type (for example, `"text"`, `"file"`, `"select"`).
    #[serde(default, rename = "type")]
    pub field_type: Option<String>,
    /// Whether the field is mandatory for step submission.
    #[serde(default)]
    pub required: Option<bool>,
    /// Additional field metadata returned by Paymob.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Single step definition inside an [`OnboardingFlowSchema`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingSchemaStep {
    /// Machine-readable step identifier.
    #[serde(default, alias = "id")]
    pub step_id: Option<String>,
    /// Human-readable step title.
    #[serde(default)]
    pub title: Option<String>,
    /// Optional 1-based step ordering index.
    #[serde(default)]
    pub order: Option<u32>,
    /// Input fields required or available in this step.
    #[serde(default)]
    pub fields: Vec<OnboardingSchemaField>,
    /// Additional step metadata returned by Paymob.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Dynamic onboarding flow schema returned by `GET /api/onboarding/flow/schema`.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::onboarding::flow_models::OnboardingFlowSchema;
///
/// let json = r#"{
///   "partner": "KeyPartner",
///   "resubmission": false,
///   "steps": [{"step_id": "business_profile", "order": 1, "fields": []}]
/// }"#;
/// let schema: OnboardingFlowSchema = serde_json::from_str(json)?;
/// assert_eq!(schema.steps.len(), 1);
/// assert_eq!(schema.steps[0].step_id.as_deref(), Some("business_profile"));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnboardingFlowSchema {
    /// Partner identifier echoed by Paymob.
    #[serde(default)]
    pub partner: Option<String>,
    /// Whether the returned schema represents a resubmission flow.
    #[serde(default)]
    pub resubmission: Option<bool>,
    /// Ordered onboarding steps to present or submit.
    #[serde(default)]
    pub steps: Vec<OnboardingSchemaStep>,
    /// Additional top-level schema fields returned by Paymob.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Request payload for submitting a completed onboarding KYC step (`POST /api/onboarding/flow/step`).
///
/// The `data` map is redacted as `"[REDACTED]"` in [`fmt::Debug`] output so
/// sensitive KYC documents, tax IDs, or bank account details are never logged.
///
/// # Examples
///
/// ```rust
/// use serde_json::{Map, Value};
/// use some_paymob::resources::onboarding::flow_models::SubmitOnboardingStepParams;
///
/// let mut data = Map::new();
/// data.insert("commercial_register".into(), Value::String("CR-998877".into()));
///
/// let params = SubmitOnboardingStepParams::new(987_654, "business_profile", data)?
///     .with_partner("KeyPartner");
/// assert_eq!(params.paymob_mid(), 987_654);
/// assert_eq!(params.step_id(), "business_profile");
/// assert!(format!("{params:?}").contains("[REDACTED]"));
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
#[derive(Clone, Serialize, Deserialize)]
pub struct SubmitOnboardingStepParams {
    /// Target sub-merchant Paymob MID.
    paymob_mid: u64,
    /// Identifier of the onboarding step being submitted.
    step_id: String,
    /// Optional partner identifier slug.
    #[serde(skip_serializing_if = "Option::is_none")]
    partner: Option<String>,
    /// Step field values matching the dynamic schema.
    data: Map<String, Value>,
}

impl fmt::Debug for SubmitOnboardingStepParams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SubmitOnboardingStepParams")
            .field("paymob_mid", &self.paymob_mid)
            .field("step_id", &self.step_id)
            .field("partner", &self.partner)
            .field("data", &"[REDACTED]")
            .finish()
    }
}

impl SubmitOnboardingStepParams {
    /// Constructs and validates [`SubmitOnboardingStepParams`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `paymob_mid == 0` or `step_id` is empty.
    pub fn new(
        paymob_mid: u64,
        step_id: impl Into<String>,
        data: Map<String, Value>,
    ) -> Result<Self, PaymobError> {
        let params = Self {
            paymob_mid,
            step_id: step_id.into(),
            partner: None,
            data,
        };
        params.validate()?;
        Ok(params)
    }

    /// Sets the optional partner identifier slug.
    #[must_use]
    pub fn with_partner(mut self, partner: impl Into<String>) -> Self {
        self.partner = Some(partner.into());
        self
    }

    /// Returns the target sub-merchant Paymob MID.
    #[must_use]
    pub const fn paymob_mid(&self) -> u64 {
        self.paymob_mid
    }

    /// Returns the step identifier.
    #[must_use]
    pub fn step_id(&self) -> &str {
        &self.step_id
    }

    /// Returns the optional partner identifier.
    #[must_use]
    pub fn partner(&self) -> Option<&str> {
        self.partner.as_deref()
    }

    /// Validates step submission parameters.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `paymob_mid == 0`, `step_id` is empty,
    /// or `partner` (when provided) is empty/contains control characters.
    pub fn validate(&self) -> Result<(), PaymobError> {
        if self.paymob_mid == 0 {
            return Err(PaymobError::ValidationError {
                field: "paymob_mid",
                reason: "paymob_mid must be a non-zero merchant ID".to_owned(),
            });
        }
        require_non_empty("step_id", &self.step_id)?;
        if let Some(partner) = &self.partner {
            validate_partner_slug(partner)?;
        }
        Ok(())
    }
}

/// Response returned by partner sub-merchant status & integration inquiry.
///
/// # Examples
///
/// ```rust
/// use some_paymob::resources::onboarding::flow_models::PartnerMerchantInquiryResponse;
///
/// let json = r#"{
///   "paymob_mid": 987654,
///   "status": "approved",
///   "is_live": true,
///   "live_integration_ids": [4097558, 4097559],
///   "pending_steps": []
/// }"#;
/// let inquiry: PartnerMerchantInquiryResponse = serde_json::from_str(json)?;
/// assert!(inquiry.is_approved());
/// assert!(inquiry.has_live_integrations());
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartnerMerchantInquiryResponse {
    /// Sub-merchant Paymob MID.
    #[serde(alias = "id", alias = "merchant_id")]
    pub paymob_mid: u64,
    /// Current onboarding/approval status (for example, `"pending"`, `"approved"`, `"rejected"`).
    #[serde(default)]
    pub status: String,
    /// Whether the sub-merchant is enabled for live acquiring traffic.
    #[serde(default)]
    pub is_live: Option<bool>,
    /// Provisioned live integration IDs ready for payment intentions.
    #[serde(default, alias = "integration_ids")]
    pub live_integration_ids: Vec<u64>,
    /// Provisioned sandbox/test integration IDs.
    #[serde(default)]
    pub test_integration_ids: Vec<u64>,
    /// Remaining onboarding step identifiers, if any.
    #[serde(default)]
    pub pending_steps: Vec<String>,
    /// Additional inquiry fields returned by Paymob.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PartnerMerchantInquiryResponse {
    /// Returns `true` when the sub-merchant is approved or active for processing.
    #[must_use]
    pub fn is_approved(&self) -> bool {
        self.status.eq_ignore_ascii_case("approved")
            || self.status.eq_ignore_ascii_case("active")
            || self.is_live.unwrap_or(false)
    }

    /// Returns `true` when at least one live integration ID has been provisioned.
    #[must_use]
    pub fn has_live_integrations(&self) -> bool {
        !self.live_integration_ids.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_6_2_1_register_merchant_params_validation_and_redaction() {
        let params = RegisterMerchantParams::new(
            "KeyPartner",
            "owner@acme.example",
            "+201116491564",
            "Amira",
            "Hassan",
        )
        .expect("valid params")
        .with_company_name("Acme LLC")
        .with_country("EGY")
        .with_extra("tax_id", Value::String("123-456-789".into()));

        assert_eq!(params.partner(), "KeyPartner");
        assert_eq!(params.company_name(), Some("Acme LLC"));
        assert_eq!(params.country(), Some("EGY"));

        let debug = format!("{params:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("owner@acme.example"));
        assert!(!debug.contains("+201116491564"));
        assert!(!debug.contains("Amira"));
        assert!(!debug.contains("Hassan"));
    }

    #[test]
    fn tc_6_2_1_register_merchant_params_rejects_empty_fields() {
        let err = RegisterMerchantParams::new(
            "   ",
            "owner@acme.example",
            "+201116491564",
            "Amira",
            "Hassan",
        )
        .expect_err("empty partner must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "partner",
                ..
            }
        ));

        let err = RegisterMerchantParams::new("KeyPartner", "", "+201116491564", "Amira", "Hassan")
            .expect_err("empty email must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError { field: "email", .. }
        ));
    }

    #[test]
    fn tc_6_2_1_onboarding_schema_query_builds_expected_query_string() {
        let query = OnboardingSchemaQuery::new("KeyPartner")
            .expect("valid query")
            .with_resubmission(true)
            .with_paymob_mid(123);

        assert_eq!(
            query.to_query_string().expect("query string"),
            "partner=KeyPartner&resubmission=true&paymob_mid=123"
        );
    }

    #[test]
    fn tc_6_2_1_onboarding_schema_query_rejects_zero_mid_and_bad_partner() {
        let bad_mid = OnboardingSchemaQuery::new("KeyPartner")
            .expect("valid partner")
            .with_paymob_mid(0);
        assert!(matches!(
            bad_mid.to_query_string(),
            Err(PaymobError::ValidationError {
                field: "paymob_mid",
                ..
            })
        ));

        let bad_partner = OnboardingSchemaQuery::new("Key\nPartner");
        assert!(matches!(
            bad_partner,
            Err(PaymobError::ValidationError {
                field: "partner",
                ..
            })
        ));
    }

    #[test]
    fn tc_6_2_1_submit_step_params_redaction_and_validation() {
        let mut data = Map::new();
        data.insert(
            "iban".into(),
            Value::String("EG380019000500000000263180002".into()),
        );
        let params = SubmitOnboardingStepParams::new(987_654, "bank_details", data)
            .expect("valid step params")
            .with_partner("KeyPartner");

        let debug = format!("{params:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("EG380019000500000000263180002"));

        assert!(matches!(
            SubmitOnboardingStepParams::new(0, "bank_details", Map::new()),
            Err(PaymobError::ValidationError {
                field: "paymob_mid",
                ..
            })
        ));
        assert!(matches!(
            SubmitOnboardingStepParams::new(987_654, "   ", Map::new()),
            Err(PaymobError::ValidationError {
                field: "step_id",
                ..
            })
        ));
    }

    #[test]
    fn tc_6_2_1_response_deserialization_and_approval_helpers() {
        let reg: RegisteredMerchantResponse =
            serde_json::from_str(r#"{"id": 555123, "status": "created"}"#)
                .expect("registered merchant");
        assert_eq!(reg.paymob_mid, 555_123);

        let schema: OnboardingFlowSchema = serde_json::from_str(
            r#"{"partner":"KeyPartner","steps":[{"id":"kyc","fields":[{"name":"cr_doc","type":"file","required":true}]}]}"#,
        )
        .expect("flow schema");
        assert_eq!(schema.steps.len(), 1);
        assert_eq!(schema.steps[0].fields[0].name, "cr_doc");

        let inquiry: PartnerMerchantInquiryResponse = serde_json::from_str(
            r#"{"merchant_id": 555123, "status": "approved", "live_integration_ids": [4097558]}"#,
        )
        .expect("inquiry response");
        assert!(inquiry.is_approved());
        assert!(inquiry.has_live_integrations());
    }
}
