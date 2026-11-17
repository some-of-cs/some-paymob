#![forbid(unsafe_code)]
//! Embedded Pixel JS SDK configuration builder (`US-2.2.0` Unit 2).
//!
//! Provides [`PixelConfig`], [`PixelConfigBuilder`], [`PixelPaymentMethod`],
//! [`ApplePaySettings`], and [`GooglePaySettings`] for generating typed JSON
//! configurations for Paymob's embedded Pixel JS checkout component using only
//! [`PublicKey`] (`pk_*`).

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::core::client::PaymobClient;
use crate::core::credentials::PublicKey;
use crate::core::error::PaymobError;

const REDACTED: &str = "[REDACTED]";

/// Supported payment methods for Paymob's embedded Pixel JS SDK.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PixelPaymentMethod {
    /// Credit/debit card form rendered by Pixel JS.
    Card,
    /// Apple Pay express checkout button.
    ApplePay,
    /// Google Pay express checkout button.
    GooglePay,
}

/// Apple Pay domain verification and merchant certificate settings for Pixel JS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplePaySettings {
    /// Apple Pay merchant identifier registered with Paymob.
    pub merchant_id: String,
    /// Domain verification status or association file identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_verification: Option<String>,
    /// Apple Pay payment processing certificate identifier or fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,
    /// Display name shown on the Apple Pay payment sheet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl ApplePaySettings {
    /// Creates [`ApplePaySettings`] with the required Apple Pay `merchant_id`.
    #[must_use]
    pub fn new(merchant_id: impl Into<String>) -> Self {
        Self {
            merchant_id: merchant_id.into(),
            domain_verification: None,
            certificate_id: None,
            display_name: None,
        }
    }

    /// Sets the domain verification token or verified domain name.
    #[must_use]
    pub fn with_domain_verification(mut self, domain_verification: impl Into<String>) -> Self {
        self.domain_verification = Some(domain_verification.into());
        self
    }

    /// Sets the Apple Pay certificate identifier or fingerprint.
    #[must_use]
    pub fn with_certificate_id(mut self, certificate_id: impl Into<String>) -> Self {
        self.certificate_id = Some(certificate_id.into());
        self
    }

    /// Sets the merchant display name for the Apple Pay sheet.
    #[must_use]
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }
}

/// Google Pay merchant configuration for Pixel JS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GooglePaySettings {
    /// Google Pay merchant identifier.
    pub merchant_id: String,
    /// Gateway merchant identifier assigned by Paymob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_merchant_id: Option<String>,
    /// Optional Google Pay display name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_name: Option<String>,
}

impl GooglePaySettings {
    /// Creates [`GooglePaySettings`] with the required `merchant_id`.
    #[must_use]
    pub fn new(merchant_id: impl Into<String>) -> Self {
        Self {
            merchant_id: merchant_id.into(),
            gateway_merchant_id: None,
            merchant_name: None,
        }
    }

    /// Sets the Paymob gateway merchant identifier.
    #[must_use]
    pub fn with_gateway_merchant_id(mut self, gateway_merchant_id: impl Into<String>) -> Self {
        self.gateway_merchant_id = Some(gateway_merchant_id.into());
        self
    }

    /// Sets the merchant display name for Google Pay.
    #[must_use]
    pub fn with_merchant_name(mut self, merchant_name: impl Into<String>) -> Self {
        self.merchant_name = Some(merchant_name.into());
        self
    }
}

/// Typed frontend configuration for Paymob's embedded Pixel JS SDK.
///
/// Always redacts `client_secret` as `"[REDACTED]"` in [`fmt::Debug`] output
/// and never reads server-side `SecretKey` or `ApiKey` credentials.
///
/// # Examples
///
/// ```rust
/// use secrecy::SecretString;
/// use some_paymob::core::credentials::PublicKey;
/// use some_paymob::resources::checkout::pixel::{
///     ApplePaySettings, PixelConfig, PixelPaymentMethod,
/// };
///
/// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
/// let pk = PublicKey::new("egy_pk_test_ABC")?;
/// let secret = SecretString::from("egy_csk_test_XYZ".to_owned());
/// let config = PixelConfig::builder(&pk, secret)
///     .payment_methods([PixelPaymentMethod::Card, PixelPaymentMethod::ApplePay])
///     .show_save_card(true)
///     .apple_pay(
///         ApplePaySettings::new("merchant.com.example.pay")
///             .with_domain_verification("pay.example.com")
///             .with_certificate_id("cert_01"),
///     )
///     .build()?;
///
/// let json = config.to_json()?;
/// assert!(json.contains("\"public_key\":\"egy_pk_test_ABC\""));
/// assert!(format!("{config:?}").contains("[REDACTED]"));
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Serialize)]
pub struct PixelConfig {
    /// Client-side Paymob public key (`pk_*`).
    pub public_key: String,
    /// Intention `client_secret` token (`csk_*`), redacted in `Debug`.
    #[serde(serialize_with = "serialize_secret_string")]
    pub client_secret: SecretString,
    /// Enabled Pixel payment methods (`card`, `apple_pay`, `google_pay`).
    pub payment_methods: Vec<PixelPaymentMethod>,
    /// Whether to display the "Save card" checkbox to the customer.
    pub show_save_card: bool,
    /// Whether to force card tokenization without an opt-out checkbox.
    pub force_save_card: bool,
    /// Optional Apple Pay domain verification and certificate settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apple_pay: Option<ApplePaySettings>,
    /// Optional Google Pay merchant settings.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub google_pay: Option<GooglePaySettings>,
    /// Optional UI locale (for example, `"en"` or `"ar"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locale: Option<String>,
}

#[derive(Deserialize)]
struct RawPixelConfig {
    public_key: String,
    #[serde(deserialize_with = "deserialize_secret_string")]
    client_secret: SecretString,
    payment_methods: Vec<PixelPaymentMethod>,
    show_save_card: bool,
    force_save_card: bool,
    #[serde(default)]
    apple_pay: Option<ApplePaySettings>,
    #[serde(default)]
    google_pay: Option<GooglePaySettings>,
    #[serde(default)]
    locale: Option<String>,
}

impl<'de> Deserialize<'de> for PixelConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawPixelConfig::deserialize(deserializer)?;
        let config = Self {
            public_key: raw.public_key,
            client_secret: raw.client_secret,
            payment_methods: raw.payment_methods,
            show_save_card: raw.show_save_card,
            force_save_card: raw.force_save_card,
            apple_pay: raw.apple_pay,
            google_pay: raw.google_pay,
            locale: raw.locale,
        };
        validate_pixel_config(&config).map_err(serde::de::Error::custom)?;
        Ok(config)
    }
}

impl fmt::Debug for PixelConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PixelConfig")
            .field("public_key", &self.public_key)
            .field("client_secret", &REDACTED)
            .field("payment_methods", &self.payment_methods)
            .field("show_save_card", &self.show_save_card)
            .field("force_save_card", &self.force_save_card)
            .field("apple_pay", &self.apple_pay)
            .field("google_pay", &self.google_pay)
            .field("locale", &self.locale)
            .finish()
    }
}

impl PixelConfig {
    /// Creates a [`PixelConfigBuilder`] from a validated [`PublicKey`] and `client_secret`.
    ///
    /// # Compile-Time Key Role Separation
    ///
    /// Passing a [`SecretKey`](crate::core::credentials::SecretKey) instead of a
    /// [`PublicKey`] fails at compile time:
    ///
    /// ```compile_fail
    /// use secrecy::SecretString;
    /// use some_paymob::core::credentials::SecretKey;
    /// use some_paymob::resources::checkout::pixel::PixelConfig;
    ///
    /// let sk = SecretKey::new("egy_sk_test_123").unwrap();
    /// let secret = SecretString::from("egy_csk_test_XYZ".to_owned());
    /// let _ = PixelConfig::builder(&sk, secret);
    /// ```
    #[must_use]
    pub fn builder(public_key: &PublicKey, client_secret: SecretString) -> PixelConfigBuilder {
        PixelConfigBuilder::new(public_key, client_secret)
    }

    /// Creates a [`PixelConfigBuilder`] from a [`PaymobClient`]'s configured [`PublicKey`].
    ///
    /// Never accesses `SecretKey` or `ApiKey`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `public_key` is not configured
    /// on the client's [`ClientConfig`](crate::core::config::ClientConfig).
    pub fn from_client(
        client: &PaymobClient,
        client_secret: SecretString,
    ) -> Result<PixelConfigBuilder, PaymobError> {
        let public_key =
            client
                .config()
                .public_key()
                .ok_or_else(|| PaymobError::ValidationError {
                    field: "public_key",
                    reason: "public_key must be configured on ClientConfig to build PixelConfig"
                        .to_owned(),
                })?;
        Ok(Self::builder(public_key, client_secret))
    }

    /// Serializes this [`PixelConfig`] into a compact JSON string for Pixel JS.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if JSON serialization fails.
    pub fn to_json(&self) -> Result<String, PaymobError> {
        serde_json::to_string(self).map_err(|err| PaymobError::ValidationError {
            field: "pixel_config",
            reason: format!("failed to serialize PixelConfig: {err}"),
        })
    }

    /// Serializes this [`PixelConfig`] into a [`serde_json::Value`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if JSON conversion fails.
    pub fn to_json_value(&self) -> Result<serde_json::Value, PaymobError> {
        serde_json::to_value(self).map_err(|err| PaymobError::ValidationError {
            field: "pixel_config",
            reason: format!("failed to convert PixelConfig to JSON value: {err}"),
        })
    }
}

/// Fluent builder for [`PixelConfig`].
#[derive(Clone)]
pub struct PixelConfigBuilder {
    public_key: String,
    client_secret: SecretString,
    payment_methods: Vec<PixelPaymentMethod>,
    show_save_card: bool,
    force_save_card: bool,
    apple_pay: Option<ApplePaySettings>,
    google_pay: Option<GooglePaySettings>,
    locale: Option<String>,
}

impl fmt::Debug for PixelConfigBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PixelConfigBuilder")
            .field("public_key", &self.public_key)
            .field("client_secret", &REDACTED)
            .field("payment_methods", &self.payment_methods)
            .field("show_save_card", &self.show_save_card)
            .field("force_save_card", &self.force_save_card)
            .field("apple_pay", &self.apple_pay)
            .field("google_pay", &self.google_pay)
            .field("locale", &self.locale)
            .finish()
    }
}

impl PixelConfigBuilder {
    /// Initializes a builder with [`PixelPaymentMethod::Card`] enabled by default.
    #[must_use]
    pub fn new(public_key: &PublicKey, client_secret: SecretString) -> Self {
        Self {
            public_key: public_key.expose_secret().trim().to_owned(),
            client_secret,
            payment_methods: vec![PixelPaymentMethod::Card],
            show_save_card: false,
            force_save_card: false,
            apple_pay: None,
            google_pay: None,
            locale: None,
        }
    }

    /// Replaces the enabled [`PixelPaymentMethod`] list.
    #[must_use]
    pub fn payment_methods(
        mut self,
        methods: impl IntoIterator<Item = PixelPaymentMethod>,
    ) -> Self {
        self.payment_methods = methods.into_iter().collect();
        self
    }

    /// Appends a [`PixelPaymentMethod`] if not already present.
    #[must_use]
    pub fn add_payment_method(mut self, method: PixelPaymentMethod) -> Self {
        if !self.payment_methods.contains(&method) {
            self.payment_methods.push(method);
        }
        self
    }

    /// Sets whether the "Save card" checkbox is shown.
    #[must_use]
    pub const fn show_save_card(mut self, show: bool) -> Self {
        self.show_save_card = show;
        self
    }

    /// Sets whether card tokenization is forced.
    #[must_use]
    pub const fn force_save_card(mut self, force: bool) -> Self {
        self.force_save_card = force;
        self
    }

    /// Configures Apple Pay domain verification and certificate settings.
    #[must_use]
    pub fn apple_pay(mut self, settings: ApplePaySettings) -> Self {
        self.apple_pay = Some(settings);
        self
    }

    /// Configures Google Pay merchant settings.
    #[must_use]
    pub fn google_pay(mut self, settings: GooglePaySettings) -> Self {
        self.google_pay = Some(settings);
        self
    }

    /// Sets the Pixel UI locale (for example, `"en"` or `"ar"`).
    #[must_use]
    pub fn locale(mut self, locale: impl Into<String>) -> Self {
        self.locale = Some(locale.into());
        self
    }

    /// Validates all fields and constructs a [`PixelConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `public_key` or `client_secret`
    /// is empty or uses an `sk_*` prefix, `payment_methods` is empty, or Apple Pay
    /// / Google Pay settings contain empty identifiers.
    pub fn build(self) -> Result<PixelConfig, PaymobError> {
        let config = PixelConfig {
            public_key: self.public_key,
            client_secret: self.client_secret,
            payment_methods: self.payment_methods,
            show_save_card: self.show_save_card,
            force_save_card: self.force_save_card,
            apple_pay: self.apple_pay,
            google_pay: self.google_pay,
            locale: self.locale,
        };
        validate_pixel_config(&config)?;
        Ok(config)
    }
}

fn validate_pixel_config(config: &PixelConfig) -> Result<(), PaymobError> {
    validate_pixel_credentials(&config.public_key, config.client_secret.expose_secret())?;
    validate_pixel_methods(&config.payment_methods)?;
    validate_pixel_wallets(config.apple_pay.as_ref(), config.google_pay.as_ref())
}

fn validate_pixel_credentials(public_key: &str, client_secret: &str) -> Result<(), PaymobError> {
    validate_key_not_secret("public_key", public_key)?;
    validate_key_not_secret("client_secret", client_secret)
}

fn validate_key_not_secret(field: &'static str, value: &str) -> Result<(), PaymobError> {
    validate_non_empty(field, value)?;
    let lower = value.trim().to_ascii_lowercase();
    if super::unified::is_secret_key_like(&lower) {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("secret key (`sk_*`) cannot be used as {field}"),
        });
    }
    Ok(())
}

fn validate_pixel_methods(methods: &[PixelPaymentMethod]) -> Result<(), PaymobError> {
    if methods.is_empty() {
        return Err(PaymobError::ValidationError {
            field: "payment_methods",
            reason: "at least one PixelPaymentMethod must be enabled".to_owned(),
        });
    }
    Ok(())
}

fn validate_pixel_wallets(
    apple_pay: Option<&ApplePaySettings>,
    google_pay: Option<&GooglePaySettings>,
) -> Result<(), PaymobError> {
    if let Some(apple) = apple_pay {
        validate_apple_pay(apple)?;
    }
    if let Some(google) = google_pay {
        return validate_google_pay(google);
    }
    Ok(())
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), PaymobError> {
    if value.trim().is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    Ok(())
}

fn validate_optional_non_empty(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), PaymobError> {
    if let Some(inner) = value {
        return validate_non_empty(field, inner);
    }
    Ok(())
}

fn validate_apple_pay(settings: &ApplePaySettings) -> Result<(), PaymobError> {
    validate_non_empty("apple_pay.merchant_id", &settings.merchant_id)?;
    validate_optional_non_empty(
        "apple_pay.domain_verification",
        settings.domain_verification.as_deref(),
    )?;
    validate_optional_non_empty(
        "apple_pay.certificate_id",
        settings.certificate_id.as_deref(),
    )
}

fn validate_google_pay(settings: &GooglePaySettings) -> Result<(), PaymobError> {
    validate_non_empty("google_pay.merchant_id", &settings.merchant_id)?;
    validate_optional_non_empty(
        "google_pay.gateway_merchant_id",
        settings.gateway_merchant_id.as_deref(),
    )
}

fn serialize_secret_string<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}

fn deserialize_secret_string<'de, D>(deserializer: D) -> Result<SecretString, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    Ok(SecretString::from(raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::SecretKey;
    use crate::core::region::PaymobRegion;

    #[test]
    fn tc_2_2_2_pixel_config_builder_serializes_all_methods() {
        let pk = PublicKey::new("egy_pk_test_ABC").expect("valid pk");
        let secret = SecretString::from("egy_csk_test_XYZ".to_owned());
        let config = PixelConfig::builder(&pk, secret)
            .payment_methods([
                PixelPaymentMethod::Card,
                PixelPaymentMethod::ApplePay,
                PixelPaymentMethod::GooglePay,
            ])
            .show_save_card(true)
            .apple_pay(
                ApplePaySettings::new("merchant.com.someofcs.pay")
                    .with_domain_verification("pay.someofcs.tech")
                    .with_certificate_id("cert_sha256_abc"),
            )
            .google_pay(
                GooglePaySettings::new("gpay_merchant_1").with_gateway_merchant_id("paymob_gw_1"),
            )
            .locale("en")
            .build()
            .expect("valid pixel config");

        let val = config.to_json_value().expect("json value");
        assert_eq!(val["public_key"], "egy_pk_test_ABC");
        assert_eq!(val["client_secret"], "egy_csk_test_XYZ");
        assert_eq!(val["show_save_card"], true);
        assert_eq!(val["payment_methods"][0], "card");
        assert_eq!(val["payment_methods"][1], "apple_pay");
        assert_eq!(val["payment_methods"][2], "google_pay");
        assert_eq!(val["apple_pay"]["merchant_id"], "merchant.com.someofcs.pay");
        assert_eq!(val["apple_pay"]["domain_verification"], "pay.someofcs.tech");
        assert_eq!(val["apple_pay"]["certificate_id"], "cert_sha256_abc");
        assert_eq!(val["google_pay"]["merchant_id"], "gpay_merchant_1");
    }

    #[test]
    fn tc_2_2_2_from_client_requires_public_key() {
        let missing_pk_cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_only").expect("valid sk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(missing_pk_cfg).expect("valid client");
        let err = PixelConfig::from_client(&client, SecretString::from("csk_1".to_owned()))
            .expect_err("missing public_key must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "public_key",
                ..
            }
        ));
    }

    #[test]
    fn tc_2_2_2_rejects_empty_client_secret_and_methods() {
        let pk = PublicKey::new("egy_pk_test_ABC").expect("valid pk");
        let empty_secret = PixelConfig::builder(&pk, SecretString::from("   ".to_owned()))
            .build()
            .expect_err("empty secret must fail");
        assert!(matches!(
            empty_secret,
            PaymobError::ValidationError {
                field: "client_secret",
                ..
            }
        ));

        let empty_methods = PixelConfig::builder(&pk, SecretString::from("csk_1".to_owned()))
            .payment_methods([])
            .build()
            .expect_err("empty payment_methods must fail");
        assert!(matches!(
            empty_methods,
            PaymobError::ValidationError {
                field: "payment_methods",
                ..
            }
        ));
    }

    #[test]
    fn tc_2_2_2_rejects_empty_apple_pay_merchant_id() {
        let pk = PublicKey::new("egy_pk_test_ABC").expect("valid pk");
        let err = PixelConfig::builder(&pk, SecretString::from("csk_1".to_owned()))
            .apple_pay(ApplePaySettings::new("   "))
            .build()
            .expect_err("empty apple_pay.merchant_id must fail");
        assert!(matches!(
            err,
            PaymobError::ValidationError {
                field: "apple_pay.merchant_id",
                ..
            }
        ));
    }

    #[test]
    fn tc_2_2_4_pixel_config_and_builder_redact_client_secret_in_debug() {
        let pk = PublicKey::new("egy_pk_test_ABC").expect("valid pk");
        let secret = SecretString::from("egy_csk_super_secret_token".to_owned());
        let builder = PixelConfig::builder(&pk, secret);
        let builder_dbg = format!("{builder:?}");
        assert!(builder_dbg.contains("[REDACTED]"));
        assert!(!builder_dbg.contains("egy_csk_super_secret_token"));

        let config = builder.build().expect("valid config");
        let config_dbg = format!("{config:?}");
        assert!(config_dbg.contains("[REDACTED]"));
        assert!(!config_dbg.contains("egy_csk_super_secret_token"));
    }

    #[test]
    fn tc_2_2_2_cycle2_deserialize_enforces_bounds_and_rejects_sk() {
        let valid_json = r#"{
            "public_key": "egy_pk_test_ABC",
            "client_secret": "egy_csk_test_XYZ",
            "payment_methods": ["card"],
            "show_save_card": false,
            "force_save_card": false
        }"#;
        let parsed: PixelConfig =
            serde_json::from_str(valid_json).expect("valid PixelConfig JSON should deserialize");
        assert_eq!(parsed.public_key, "egy_pk_test_ABC");

        let invalid_payloads = [
            r#"{"public_key":"","client_secret":"csk_1","payment_methods":["card"],"show_save_card":false,"force_save_card":false}"#,
            r#"{"public_key":"egy_sk_test_123","client_secret":"csk_1","payment_methods":["card"],"show_save_card":false,"force_save_card":false}"#,
            r#"{"public_key":"egy_pk_test_123","client_secret":"   ","payment_methods":["card"],"show_save_card":false,"force_save_card":false}"#,
            r#"{"public_key":"egy_pk_test_123","client_secret":"sk_live_secret","payment_methods":["card"],"show_save_card":false,"force_save_card":false}"#,
            r#"{"public_key":"egy_pk_test_123","client_secret":"csk_1","payment_methods":[],"show_save_card":false,"force_save_card":false}"#,
            r#"{"public_key":"egy_pk_test_123","client_secret":"csk_1","payment_methods":["apple_pay"],"show_save_card":false,"force_save_card":false,"apple_pay":{"merchant_id":"  "}}"#,
            r#"{"public_key":"egy_pk_test_123","client_secret":"csk_1","payment_methods":["google_pay"],"show_save_card":false,"force_save_card":false,"google_pay":{"merchant_id":""}}"#,
        ];
        for payload in invalid_payloads {
            assert!(
                serde_json::from_str::<PixelConfig>(payload).is_err(),
                "expected PixelConfig deserialization to reject: {payload}"
            );
        }
    }

    #[test]
    fn tc_2_2_2_cycle2_checkout_facade_pixel_config() {
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .public_key(PublicKey::new("egy_pk_test_FACADE").expect("valid pk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");
        let pixel = client
            .checkout()
            .pixel_config(SecretString::from("egy_csk_test_999".to_owned()))
            .expect("pixel_config builder")
            .build()
            .expect("valid PixelConfig");
        assert_eq!(pixel.public_key, "egy_pk_test_FACADE");
    }
}
