#![forbid(unsafe_code)]
//! Legacy Accept v2 payment key generation (`POST /api/acceptance/payment_keys`, `US-2.3.0` Unit 2).
//!
//! Implements [`CreatePaymentKeyParams`], PII-redacting [`LegacyBillingData`],
//! [`PaymentKeyResponse`] (`token: SecretString` with `[REDACTED]` `Debug`),
//! and the Regime 2 payment key request helper.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::core::auth::accept_jwt::{AcceptJwtError, inject_body_auth_token};
use crate::core::error::PaymobError;
use crate::core::http::{HttpClient, HttpRequest};
use crate::core::types::Currency;

/// Relative endpoint path for Paymob Accept v2 payment key generation.
pub const LEGACY_PAYMENT_KEYS_PATH: &str = "/api/acceptance/payment_keys";

/// Default payment key expiration window in seconds (1 hour).
pub const DEFAULT_PAYMENT_KEY_EXPIRATION_SECS: u32 = 3_600;

/// Customer billing details required by `POST /api/acceptance/payment_keys`.
///
/// Implements a custom [`fmt::Debug`] that redacts all personal identifiable
/// information (`first_name`, `last_name`, `email`, `phone_number`, and street
/// address fields) as `"[REDACTED]"`.
///
/// # Examples
///
/// ```
/// use some_paymob::resources::legacy::payment_keys::LegacyBillingData;
///
/// let billing = LegacyBillingData::new("Maher", "Mansour", "dev@example.com", "+201000000000")
///     .with_city("Mansoura")
///     .with_country("EG");
/// assert!(billing.validate().is_ok());
/// assert!(format!("{billing:?}").contains("[REDACTED]"));
/// ```
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct LegacyBillingData {
    /// Customer first name.
    pub first_name: String,
    /// Customer last name.
    pub last_name: String,
    /// Customer email address.
    pub email: String,
    /// Customer phone number in international format.
    pub phone_number: String,
    /// Apartment number or `"NA"`.
    pub apartment: String,
    /// Floor number or `"NA"`.
    pub floor: String,
    /// Street name or `"NA"`.
    pub street: String,
    /// Building number or `"NA"`.
    pub building: String,
    /// Shipping method or `"NA"`.
    pub shipping_method: String,
    /// Postal/ZIP code or `"NA"`.
    pub postal_code: String,
    /// City name or `"NA"`.
    pub city: String,
    /// ISO-3166-1 alpha-2 country code (default `"EG"`).
    pub country: String,
    /// State or governorate or `"NA"`.
    pub state: String,
}

impl fmt::Debug for LegacyBillingData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LegacyBillingData")
            .field("first_name", &"[REDACTED]")
            .field("last_name", &"[REDACTED]")
            .field("email", &"[REDACTED]")
            .field("phone_number", &"[REDACTED]")
            .field("apartment", &"[REDACTED]")
            .field("floor", &"[REDACTED]")
            .field("street", &"[REDACTED]")
            .field("building", &"[REDACTED]")
            .field("shipping_method", &self.shipping_method)
            .field("postal_code", &"[REDACTED]")
            .field("city", &"[REDACTED]")
            .field("country", &self.country)
            .field("state", &"[REDACTED]")
            .finish()
    }
}

impl LegacyBillingData {
    /// Constructs [`LegacyBillingData`] with required customer identity fields
    /// and `"NA"` defaults for optional address fields (`country = "EG"`).
    #[must_use]
    pub fn new(
        first_name: impl Into<String>,
        last_name: impl Into<String>,
        email: impl Into<String>,
        phone_number: impl Into<String>,
    ) -> Self {
        Self {
            first_name: first_name.into(),
            last_name: last_name.into(),
            email: email.into(),
            phone_number: phone_number.into(),
            apartment: "NA".to_owned(),
            floor: "NA".to_owned(),
            street: "NA".to_owned(),
            building: "NA".to_owned(),
            shipping_method: "NA".to_owned(),
            postal_code: "NA".to_owned(),
            city: "NA".to_owned(),
            country: "EG".to_owned(),
            state: "NA".to_owned(),
        }
    }

    /// Sets the billing city.
    #[must_use]
    pub fn with_city(mut self, city: impl Into<String>) -> Self {
        self.city = city.into();
        self
    }

    /// Sets the ISO-3166-1 alpha-2 billing country code.
    #[must_use]
    pub fn with_country(mut self, country: impl Into<String>) -> Self {
        self.country = country.into();
        self
    }

    /// Sets the billing street.
    #[must_use]
    pub fn with_street(mut self, street: impl Into<String>) -> Self {
        self.street = street.into();
        self
    }

    /// Validates that required customer PII fields are non-empty and well-formed.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `first_name`, `last_name`,
    /// `email`, or `phone_number` is blank or `email` lacks `@`.
    pub fn validate(&self) -> Result<(), PaymobError> {
        require_non_blank("billing_data.first_name", &self.first_name)?;
        require_non_blank("billing_data.last_name", &self.last_name)?;
        require_non_blank("billing_data.phone_number", &self.phone_number)?;
        validate_email(&self.email)
    }
}

#[derive(Deserialize)]
struct RawLegacyBillingData {
    first_name: String,
    last_name: String,
    email: String,
    phone_number: String,
    apartment: String,
    floor: String,
    street: String,
    building: String,
    shipping_method: String,
    postal_code: String,
    city: String,
    country: String,
    state: String,
}

impl<'de> Deserialize<'de> for LegacyBillingData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawLegacyBillingData::deserialize(deserializer)?;
        let billing = Self {
            first_name: raw.first_name,
            last_name: raw.last_name,
            email: raw.email,
            phone_number: raw.phone_number,
            apartment: raw.apartment,
            floor: raw.floor,
            street: raw.street,
            building: raw.building,
            shipping_method: raw.shipping_method,
            postal_code: raw.postal_code,
            city: raw.city,
            country: raw.country,
            state: raw.state,
        };
        billing.validate().map_err(serde::de::Error::custom)?;
        Ok(billing)
    }
}

/// Request parameters for `POST /api/acceptance/payment_keys`.
///
/// # Examples
///
/// ```
/// use some_paymob::core::types::Currency;
/// use some_paymob::resources::legacy::payment_keys::{CreatePaymentKeyParams, LegacyBillingData};
///
/// let billing = LegacyBillingData::new("Ada", "Lovelace", "ada@example.com", "+201000000000");
/// let params = CreatePaymentKeyParams::new(998_877, 50_000, Currency::EGP, 4_097_558, billing)
///     .expiration(1_800)
///     .lock_order_when_paid(true);
/// assert!(params.validate().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CreatePaymentKeyParams {
    /// Paymob order identifier returned by `POST /api/ecommerce/orders`.
    pub order_id: u64,
    /// Payment amount in integer minor units.
    pub amount_cents: u64,
    /// ISO-4217 currency code.
    pub currency: Currency,
    /// Paymob payment integration identifier.
    pub integration_id: u64,
    /// Customer billing metadata.
    pub billing_data: LegacyBillingData,
    /// Payment key lifetime in seconds.
    pub expiration: u32,
    /// Whether to lock the order against further attempts once paid.
    pub lock_order_when_paid: bool,
}

impl CreatePaymentKeyParams {
    /// Creates a new [`CreatePaymentKeyParams`] with default `expiration = 3600`
    /// and `lock_order_when_paid = false`.
    #[must_use]
    pub fn new(
        order_id: u64,
        amount_cents: u64,
        currency: Currency,
        integration_id: u64,
        billing_data: LegacyBillingData,
    ) -> Self {
        Self {
            order_id,
            amount_cents,
            currency,
            integration_id,
            billing_data,
            expiration: DEFAULT_PAYMENT_KEY_EXPIRATION_SECS,
            lock_order_when_paid: false,
        }
    }

    /// Sets the payment key expiration in seconds.
    #[must_use]
    pub const fn expiration(mut self, expiration: u32) -> Self {
        self.expiration = expiration;
        self
    }

    /// Sets whether the order is locked once paid.
    #[must_use]
    pub const fn lock_order_when_paid(mut self, lock: bool) -> Self {
        self.lock_order_when_paid = lock;
        self
    }

    /// Validates all payment key parameters prior to network dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `order_id`, `amount_cents`,
    /// `integration_id`, or `expiration` is zero, `currency` is blank, or
    /// `billing_data` fails validation.
    pub fn validate(&self) -> Result<(), PaymobError> {
        self.validate_numeric_fields()?;
        require_non_blank("currency", self.currency.as_str())?;
        self.billing_data.validate()
    }

    fn validate_numeric_fields(&self) -> Result<(), PaymobError> {
        require_positive_u64("order_id", self.order_id)?;
        require_positive_u64("amount_cents", self.amount_cents)?;
        require_positive_u64("integration_id", self.integration_id)?;
        require_positive_u64("expiration", u64::from(self.expiration))
    }

    /// Serializes this payload and injects Regime 2 `"auth_token"` into the JSON object.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if validation or serialization fails, or
    /// [`PaymobError::AuthenticationError`] if `auth_token` is empty.
    pub fn to_authenticated_body(&self, auth_token: &SecretString) -> Result<Value, PaymobError> {
        self.validate()?;
        let mut body = serde_json::to_value(self).map_err(|err| PaymobError::ValidationError {
            field: "payment_key",
            reason: err.to_string(),
        })?;
        inject_body_auth_token(&mut body, auth_token).map_err(map_jwt_err)?;
        Ok(body)
    }
}

#[derive(Deserialize)]
struct RawCreatePaymentKeyParams {
    order_id: u64,
    amount_cents: u64,
    currency: Currency,
    integration_id: u64,
    billing_data: LegacyBillingData,
    expiration: u32,
    lock_order_when_paid: bool,
}

impl<'de> Deserialize<'de> for CreatePaymentKeyParams {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawCreatePaymentKeyParams::deserialize(deserializer)?;
        let params = Self {
            order_id: raw.order_id,
            amount_cents: raw.amount_cents,
            currency: raw.currency,
            integration_id: raw.integration_id,
            billing_data: raw.billing_data,
            expiration: raw.expiration,
            lock_order_when_paid: raw.lock_order_when_paid,
        };
        params.validate().map_err(serde::de::Error::custom)?;
        Ok(params)
    }
}

/// Response returned by `POST /api/acceptance/payment_keys`.
///
/// Wraps the short-lived `payment_token` in [`SecretString`] and emits
/// `"[REDACTED]"` in [`fmt::Debug`]. Intentionally omits [`Serialize`] so
/// short-lived payment tokens cannot be accidentally serialized into logs or
/// outbound responses:
///
/// ```compile_fail
/// use some_paymob::resources::legacy::payment_keys::PaymentKeyResponse;
///
/// fn assert_serializable<T: serde::Serialize>() {}
///
/// assert_serializable::<PaymentKeyResponse>();
/// ```
#[derive(Clone)]
pub struct PaymentKeyResponse {
    /// Short-lived payment key token passed to the Paymob iframe URL.
    pub token: SecretString,
}

impl fmt::Debug for PaymentKeyResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymentKeyResponse")
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl PaymentKeyResponse {
    /// Returns a reference to the underlying [`SecretString`] payment token.
    #[must_use]
    pub const fn token(&self) -> &SecretString {
        &self.token
    }

    /// Exposes the raw payment token string for iframe URL construction.
    #[must_use]
    pub fn expose_token(&self) -> &str {
        self.token.expose_secret()
    }

    /// Validates that `token` is non-empty, non-whitespace, and contains no ASCII control characters.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `token` is blank or contains ASCII control characters.
    pub fn validate(&self) -> Result<(), PaymobError> {
        let raw = self.token.expose_secret();
        require_non_blank("token", raw)?;
        if raw.bytes().any(|b| b.is_ascii_control()) {
            return Err(PaymobError::ValidationError {
                field: "token",
                reason: "payment key token must not contain ASCII control characters".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RawPaymentKeyResponse {
    token: SecretString,
}

impl<'de> Deserialize<'de> for PaymentKeyResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawPaymentKeyResponse::deserialize(deserializer)?;
        let resp = Self { token: raw.token };
        resp.validate().map_err(serde::de::Error::custom)?;
        Ok(resp)
    }
}

/// Executes `POST /api/acceptance/payment_keys` with Regime 2 `"auth_token"` body injection.
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] for invalid parameters,
/// [`PaymobError::TransportError`] on network failure, or a normalized
/// [`PaymobError`] for non-2xx gateway responses.
///
/// # Examples
///
/// ```rust,no_run
/// use secrecy::SecretString;
/// use some_paymob::core::http::{HttpClient, HttpClientConfig};
/// use some_paymob::core::types::Currency;
/// use some_paymob::resources::legacy::payment_keys::{
///     create_legacy_payment_key, CreatePaymentKeyParams, LegacyBillingData,
/// };
/// use url::Url;
///
/// # async fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let http = HttpClient::new(HttpClientConfig::default())?;
/// let url = Url::parse("https://accept.paymob.com/api/acceptance/payment_keys").unwrap();
/// let billing = LegacyBillingData::new("Ada", "Lovelace", "ada@example.com", "+201000000000");
/// let params = CreatePaymentKeyParams::new(100, 50_000, Currency::EGP, 4_097_558, billing);
/// let _key = create_legacy_payment_key(&http, url, &SecretString::from("jwt"), &params).await?;
/// # Ok(())
/// # }
/// ```
pub async fn create_legacy_payment_key(
    http: &HttpClient,
    url: Url,
    auth_token: &SecretString,
    params: &CreatePaymentKeyParams,
) -> Result<PaymentKeyResponse, PaymobError> {
    let body = params.to_authenticated_body(auth_token)?;
    let request = HttpRequest::post(url.as_str())?.with_json(&body)?;
    let response = http.execute(&request).await?;
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(&response));
    }
    response
        .json::<PaymentKeyResponse>()
        .map_err(PaymobError::from)
}

fn require_positive_u64(field: &'static str, value: u64) -> Result<(), PaymobError> {
    if value == 0 {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must be greater than zero"),
        });
    }
    Ok(())
}

fn require_non_blank(field: &'static str, value: &str) -> Result<(), PaymobError> {
    if value.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn validate_email(email: &str) -> Result<(), PaymobError> {
    let trimmed = email.trim();
    if trimmed.is_empty() || !trimmed.contains('@') {
        return Err(PaymobError::ValidationError {
            field: "billing_data.email",
            reason: "billing_data.email must be a valid non-empty email address".to_owned(),
        });
    }
    Ok(())
}

fn map_jwt_err(err: AcceptJwtError) -> PaymobError {
    match err {
        AcceptJwtError::EmptyApiKey | AcceptJwtError::InvalidCredentials => {
            PaymobError::AuthenticationError(err.to_string())
        }
        _ => PaymobError::ValidationError {
            field: "auth_token",
            reason: err.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::http::HttpClientConfig;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn sample_billing() -> LegacyBillingData {
        LegacyBillingData::new("Maher", "Mansour", "maher@example.com", "+201001234567")
            .with_city("Mansoura")
            .with_street("Gomhoria St")
    }

    #[test]
    fn tc_2_3_2_payment_key_params_validates_and_serializes_auth_token() {
        let params = CreatePaymentKeyParams::new(
            998_877,
            50_000,
            Currency::EGP,
            4_097_558,
            sample_billing(),
        )
        .expiration(1_800)
        .lock_order_when_paid(true);

        let body = params
            .to_authenticated_body(&SecretString::from("jwt-token-abc"))
            .expect("valid payment key body");

        assert_eq!(body["order_id"], 998_877);
        assert_eq!(body["amount_cents"], 50_000);
        assert_eq!(body["currency"], "EGP");
        assert_eq!(body["integration_id"], 4_097_558);
        assert_eq!(body["expiration"], 1_800);
        assert_eq!(body["lock_order_when_paid"], true);
        assert_eq!(body["auth_token"], "jwt-token-abc");
        assert_eq!(body["billing_data"]["email"], "maher@example.com");
    }

    #[test]
    fn tc_2_3_2_rejects_zero_ids_and_invalid_billing_data() {
        let zero_order =
            CreatePaymentKeyParams::new(0, 50_000, Currency::EGP, 10, sample_billing());
        assert!(matches!(
            zero_order.validate(),
            Err(PaymobError::ValidationError {
                field: "order_id",
                ..
            })
        ));

        let zero_int = CreatePaymentKeyParams::new(10, 50_000, Currency::EGP, 0, sample_billing());
        assert!(matches!(
            zero_int.validate(),
            Err(PaymobError::ValidationError {
                field: "integration_id",
                ..
            })
        ));

        let zero_exp = CreatePaymentKeyParams::new(10, 50_000, Currency::EGP, 1, sample_billing())
            .expiration(0);
        assert!(matches!(
            zero_exp.validate(),
            Err(PaymobError::ValidationError {
                field: "expiration",
                ..
            })
        ));

        let bad_email = CreatePaymentKeyParams::new(
            10,
            50_000,
            Currency::EGP,
            1,
            LegacyBillingData::new("Ada", "L", "not-an-email", "+20100"),
        );
        assert!(matches!(
            bad_email.validate(),
            Err(PaymobError::ValidationError {
                field: "billing_data.email",
                ..
            })
        ));
    }

    #[test]
    fn tc_2_3_cycle2_deserialize_enforces_validation_and_token_hygiene() {
        let mut billing_json = serde_json::to_value(sample_billing()).expect("billing json");
        billing_json["email"] = serde_json::json!("invalid-email");
        assert!(serde_json::from_value::<LegacyBillingData>(billing_json).is_err());

        let valid_params = CreatePaymentKeyParams::new(
            998_877,
            50_000,
            Currency::EGP,
            4_097_558,
            sample_billing(),
        );
        let mut params_json = serde_json::to_value(&valid_params).expect("params json");
        params_json["order_id"] = serde_json::json!(0);
        assert!(serde_json::from_value::<CreatePaymentKeyParams>(params_json).is_err());

        for bad_tok in ["", "   ", "tok\n123", "tok\r123", "tok\0null"] {
            let tok_json = serde_json::json!({ "token": bad_tok });
            assert!(serde_json::from_value::<PaymentKeyResponse>(tok_json).is_err());
        }
    }

    #[test]
    fn tc_2_3_4_redacts_pii_and_payment_token_in_debug() {
        let billing = sample_billing();
        let billing_dbg = format!("{billing:?}");
        assert!(billing_dbg.contains("[REDACTED]"));
        assert!(!billing_dbg.contains("maher@example.com"));
        assert!(!billing_dbg.contains("+201001234567"));
        assert!(!billing_dbg.contains("Maher"));
        assert!(!billing_dbg.contains("Mansoura"));

        let resp = PaymentKeyResponse {
            token: SecretString::from("ZXlKaGJHY2lPaUpJVXpJMU5pSjku"),
        };
        let resp_dbg = format!("{resp:?}");
        assert!(resp_dbg.contains("[REDACTED]"));
        assert!(!resp_dbg.contains("ZXlKaGJHY2lPaUpJVXpJMU5pSjku"));
    }

    #[tokio::test]
    async fn tc_2_3_2_create_payment_key_wiremock_roundtrip() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(LEGACY_PAYMENT_KEYS_PATH))
            .and(body_partial_json(serde_json::json!({
                "auth_token": "jwt-ok",
                "order_id": 555,
                "integration_id": 4_097_558
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "token": "pay_key_tok+1/2="
            })))
            .expect(1)
            .mount(&server)
            .await;

        let http = HttpClient::new(HttpClientConfig::default().with_allow_insecure_http(true))
            .expect("http client");
        let url =
            Url::parse(&format!("{}{}", server.uri(), LEGACY_PAYMENT_KEYS_PATH)).expect("url");
        let params =
            CreatePaymentKeyParams::new(555, 50_000, Currency::EGP, 4_097_558, sample_billing());
        let res = create_legacy_payment_key(&http, url, &SecretString::from("jwt-ok"), &params)
            .await
            .expect("payment key created");

        assert_eq!(res.expose_token(), "pay_key_tok+1/2=");
    }
}
