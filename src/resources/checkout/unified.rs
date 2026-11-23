#![forbid(unsafe_code)]
//! Unified Checkout redirect URL builder (`US-2.2.0` Unit 1).
//!
//! Provides [`CheckoutService`] and [`PaymobClient::checkout`] for constructing
//! percent-encoded Paymob Unified Checkout redirect URLs using only the
//! client-side [`PublicKey`] (`pk_*`).
//! Server-side [`SecretKey`](crate::core::credentials::SecretKey) and
//! [`ApiKey`](crate::core::credentials::ApiKey) credentials are never read or
//! exposed by this module.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use url::Url;

use super::affordability::AffordabilityWidgetConfig;
use super::pixel::PixelConfig;
use crate::core::client::PaymobClient;
use crate::core::credentials::PublicKey;
use crate::core::error::PaymobError;
use crate::core::types::{Currency, MinorUnitAmount};

/// Checkout experience builder service bound to a [`PaymobClient`].
///
/// Obtained via [`PaymobClient::checkout`]. Constructs frontend-safe Unified
/// Checkout redirect URLs, Embedded Pixel JS configurations, and Affordability
/// Widget configurations without accessing server-side secret credentials.
///
/// # Examples
///
/// ```rust,no_run
/// use secrecy::SecretString;
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::credentials::PublicKey;
/// use some_paymob::core::region::PaymobRegion;
///
/// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .public_key(PublicKey::new("egy_pk_test_ABC")?)
///     .build()?;
/// let client = PaymobClient::new(config)?;
/// let secret = SecretString::from("egy_csk_test_XYZ".to_owned());
/// let url = client.checkout().unified_url(&secret)?;
/// assert_eq!(
///     url.as_str(),
///     "https://accept.paymob.com/unifiedcheckout/?publicKey=egy_pk_test_ABC&clientSecret=egy_csk_test_XYZ"
/// );
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy)]
pub struct CheckoutService<'a> {
    client: &'a PaymobClient,
}

impl fmt::Debug for CheckoutService<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckoutService")
            .field("client", self.client)
            .finish()
    }
}

impl<'a> CheckoutService<'a> {
    /// Creates a new [`CheckoutService`] borrowing `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }

    /// Builds a regional Unified Checkout redirect [`Url`] for `client_secret`.
    ///
    /// Formats `{checkout_base_url}?publicKey={pk}&clientSecret={client_secret}`
    /// using [`Url::query_pairs_mut`] for strict percent-encoding of both query
    /// parameters. Only reads the configured [`PublicKey`] (`pk_*`); never reads
    /// `SecretKey` or `ApiKey`.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if:
    /// - `public_key` is missing on [`ClientConfig`](crate::core::config::ClientConfig)
    ///   or fails [`PublicKey`] (`pk_*`) verification,
    /// - `client_secret` is empty, whitespace-only, contains ASCII control
    ///   characters, or starts with a server `sk_*` / `*_sk_*` prefix, or
    /// - the regional checkout base URL cannot be parsed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secrecy::SecretString;
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::PublicKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .public_key(PublicKey::new("egy_pk_test_ABC")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let client_secret = SecretString::from("egy_csk_test_XYZ".to_owned());
    /// let url = client.checkout().unified_url(&client_secret)?;
    /// assert_eq!(
    ///     url.as_str(),
    ///     "https://accept.paymob.com/unifiedcheckout/?publicKey=egy_pk_test_ABC&clientSecret=egy_csk_test_XYZ"
    /// );
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Passing a [`SecretKey`](crate::core::credentials::SecretKey) where
    /// `&SecretString` or [`PublicKey`] is expected fails at compile time:
    ///
    /// ```compile_fail
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::{PublicKey, SecretKey};
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// let sk = SecretKey::new("egy_sk_test_123").unwrap();
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .public_key(PublicKey::new("egy_pk_test_ABC").unwrap())
    ///     .build()
    ///     .unwrap();
    /// let client = PaymobClient::new(config).unwrap();
    /// let _ = client.checkout().unified_url(&sk);
    /// ```
    pub fn unified_url(&self, client_secret: &SecretString) -> Result<Url, PaymobError> {
        let public_key =
            self.client
                .config()
                .public_key()
                .ok_or_else(|| {
                    PaymobError::ValidationError {
                field: "public_key",
                reason:
                    "public_key must be configured on ClientConfig to build a Unified Checkout URL"
                        .to_owned(),
            }
                })?;
        let pk_value = validate_public_key(public_key)?;
        let secret_value = validate_client_secret(client_secret)?;

        let mut url = Url::parse(&self.client.endpoints().checkout_base_url).map_err(|err| {
            PaymobError::ValidationError {
                field: "checkout_base_url",
                reason: format!("invalid regional checkout base URL: {err}"),
            }
        })?;
        url.query_pairs_mut()
            .clear()
            .append_pair("publicKey", pk_value)
            .append_pair("clientSecret", secret_value);
        Ok(url)
    }

    /// Creates a [`PixelConfigBuilder`](super::pixel::PixelConfigBuilder) using
    /// the [`PublicKey`] configured on the underlying [`PaymobClient`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `public_key` is not configured
    /// on the client's [`ClientConfig`](crate::core::config::ClientConfig).
    pub fn pixel_config(
        &self,
        client_secret: SecretString,
    ) -> Result<super::pixel::PixelConfigBuilder, PaymobError> {
        PixelConfig::from_client(self.client, client_secret)
    }

    /// Creates an [`AffordabilityWidgetConfigBuilder`](super::affordability::AffordabilityWidgetConfigBuilder)
    /// using the [`PublicKey`] configured on the underlying [`PaymobClient`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `public_key` is not configured
    /// on the client's [`ClientConfig`](crate::core::config::ClientConfig).
    pub fn affordability_widget(
        &self,
        amount: impl Into<MinorUnitAmount>,
        currency: Currency,
    ) -> Result<super::affordability::AffordabilityWidgetConfigBuilder, PaymobError> {
        AffordabilityWidgetConfig::from_client(self.client, amount.into(), currency)
    }
}

impl PaymobClient {
    /// Returns a [`CheckoutService`] handle for building Unified Checkout URLs,
    /// Pixel JS configurations, and Affordability Widget configurations.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use secrecy::SecretString;
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::credentials::PublicKey;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn main() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::SaudiArabia)
    ///     .public_key(PublicKey::new("ksa_pk_test_123")?)
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let url = client
    ///     .checkout()
    ///     .unified_url(&SecretString::from("ksa_csk_test_456".to_owned()))?;
    /// assert_eq!(
    ///     url.as_str(),
    ///     "https://ksa.paymob.com/unifiedcheckout/?publicKey=ksa_pk_test_123&clientSecret=ksa_csk_test_456"
    /// );
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub const fn checkout(&self) -> CheckoutService<'_> {
        CheckoutService::new(self)
    }
}

pub(super) fn is_secret_key_like(lower: &str) -> bool {
    lower.starts_with("sk_") || lower.contains("_sk_")
}

pub(super) fn has_valid_pk_prefix(lower: &str) -> bool {
    if let Some(suffix) = lower.strip_prefix("pk_") {
        return !suffix.is_empty();
    }
    match lower.split_once("_pk_") {
        Some((prefix, suffix)) => !prefix.is_empty() && !suffix.is_empty(),
        None => false,
    }
}

pub(super) fn validate_non_empty_no_control<'a>(
    field: &'static str,
    value: &'a str,
) -> Result<&'a str, PaymobError> {
    if value.chars().any(char::is_control) {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not contain control characters"),
        });
    }
    let raw = value.trim();
    if raw.is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    Ok(raw)
}

pub(super) fn validate_public_key_str<'a>(
    value: &'a str,
    context: &str,
) -> Result<&'a str, PaymobError> {
    let raw = validate_non_empty_no_control("public_key", value)?;
    let lower = raw.to_ascii_lowercase();
    if is_secret_key_like(&lower) {
        return Err(PaymobError::ValidationError {
            field: "public_key",
            reason: format!("secret key (`sk_*`) cannot be used in {context}"),
        });
    }
    if !has_valid_pk_prefix(&lower) {
        return Err(PaymobError::ValidationError {
            field: "public_key",
            reason: "public_key must have a valid `pk_` or `*_pk_*` prefix with a non-empty suffix"
                .to_owned(),
        });
    }
    Ok(raw)
}

fn validate_public_key(public_key: &PublicKey) -> Result<&str, PaymobError> {
    validate_public_key_str(public_key.expose_secret(), "Unified Checkout URLs")
}

fn validate_client_secret(client_secret: &SecretString) -> Result<&str, PaymobError> {
    let raw = validate_non_empty_no_control("client_secret", client_secret.expose_secret())?;
    let lower = raw.to_ascii_lowercase();
    if is_secret_key_like(&lower) {
        return Err(PaymobError::ValidationError {
            field: "client_secret",
            reason: "secret key (`sk_*`) cannot be used as client_secret".to_owned(),
        });
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::config::ClientConfig;
    use crate::core::credentials::SecretKey;
    use crate::core::region::PaymobRegion;

    fn client_with_pk(region: PaymobRegion, pk: &str) -> PaymobClient {
        let config = ClientConfig::builder()
            .region(region)
            .public_key(PublicKey::new(pk).expect("valid public key"))
            .build()
            .expect("valid config");
        PaymobClient::new(config).expect("valid client")
    }

    #[test]
    fn tc_2_2_1_unified_url_egypt_matches_ac1() {
        let client = client_with_pk(PaymobRegion::Egypt, "egy_pk_test_ABC");
        let secret = SecretString::from("egy_csk_test_XYZ".to_owned());
        let url = client
            .checkout()
            .unified_url(&secret)
            .expect("unified_url should succeed");
        assert_eq!(
            url.as_str(),
            "https://accept.paymob.com/unifiedcheckout/?publicKey=egy_pk_test_ABC&clientSecret=egy_csk_test_XYZ"
        );
    }

    #[test]
    fn tc_2_2_1_unified_url_all_builtin_regions() {
        let cases = [
            (
                PaymobRegion::SaudiArabia,
                "ksa_pk_live_1",
                "https://ksa.paymob.com/unifiedcheckout/?publicKey=ksa_pk_live_1&clientSecret=csk_1",
            ),
            (
                PaymobRegion::Uae,
                "uae_pk_live_1",
                "https://uae.paymob.com/unifiedcheckout/?publicKey=uae_pk_live_1&clientSecret=csk_1",
            ),
            (
                PaymobRegion::Oman,
                "omn_pk_live_1",
                "https://oman.paymob.com/unifiedcheckout/?publicKey=omn_pk_live_1&clientSecret=csk_1",
            ),
            (
                PaymobRegion::Pakistan,
                "pak_pk_live_1",
                "https://pakistan.paymob.com/unifiedcheckout/?publicKey=pak_pk_live_1&clientSecret=csk_1",
            ),
        ];
        let secret = SecretString::from("csk_1".to_owned());
        for (region, pk, expected) in cases {
            let client = client_with_pk(region, pk);
            let url = client.checkout().unified_url(&secret).unwrap();
            assert_eq!(url.as_str(), expected);
        }
    }

    #[test]
    fn tc_2_2_1_percent_encodes_query_injection_characters() {
        let client = client_with_pk(PaymobRegion::Egypt, "egy_pk_test_ABC");
        let secret = SecretString::from("egy_csk_1&admin=true?x=1#frag".to_owned());
        let url = client
            .checkout()
            .unified_url(&secret)
            .expect("percent-encoding should succeed");
        assert_eq!(
            url.as_str(),
            "https://accept.paymob.com/unifiedcheckout/?publicKey=egy_pk_test_ABC&clientSecret=egy_csk_1%26admin%3Dtrue%3Fx%3D1%23frag"
        );
    }

    #[test]
    fn tc_2_2_1_missing_public_key_fails_closed_ac3() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_only").expect("valid sk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("valid client");
        let secret = SecretString::from("egy_csk_test_XYZ".to_owned());
        let err = client
            .checkout()
            .unified_url(&secret)
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
    fn tc_2_2_1_rejects_empty_control_char_and_sk_client_secret() {
        let client = client_with_pk(PaymobRegion::Egypt, "egy_pk_test_ABC");
        for bad in [
            "",
            "   ",
            "csk_bad\nline",
            "csk_bad\0null",
            "sk_test_123",
            "egy_sk_test_123",
        ] {
            let secret = SecretString::from(bad.to_owned());
            let err = client
                .checkout()
                .unified_url(&secret)
                .expect_err("malformed or secret-key client_secret must be rejected");
            assert!(matches!(
                err,
                PaymobError::ValidationError {
                    field: "client_secret",
                    ..
                }
            ));
        }
    }

    #[test]
    fn tc_2_2_1_rejects_malformed_or_control_char_public_key() {
        let secret = SecretString::from("egy_csk_test_XYZ".to_owned());
        for bad_pk in [
            "pk_",
            "egy_pk_",
            "_pk_test",
            "not_a_public_key",
            "egy_pk_test_\n1",
        ] {
            let client = client_with_pk(PaymobRegion::Egypt, bad_pk);
            let err = client
                .checkout()
                .unified_url(&secret)
                .expect_err("invalid public_key must be rejected");
            assert!(matches!(
                err,
                PaymobError::ValidationError {
                    field: "public_key",
                    ..
                }
            ));
        }
    }

    #[test]
    fn tc_2_2_4_checkout_service_debug_redacts_credentials() {
        let config = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .secret_key(SecretKey::new("egy_sk_test_supersecret").expect("valid sk"))
            .public_key(PublicKey::new("egy_pk_test_superpublic").expect("valid pk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(config).expect("valid client");
        let debug = format!("{:?}", client.checkout());
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("egy_sk_test_supersecret"));
        assert!(!debug.contains("egy_pk_test_superpublic"));
    }

    #[test]
    fn res1_01_unified_url_does_not_expand_env_vars() {
        let cfg = ClientConfig::builder()
            .region(PaymobRegion::Egypt)
            .public_key(PublicKey::new("egy_pk_test_ENVTEST").expect("valid pk"))
            .build()
            .expect("valid config");
        let client = PaymobClient::new(cfg).expect("valid client");
        let literal_ref = SecretString::from("$PAYMOB_HMAC_SECRET".to_owned());
        let url = client
            .checkout()
            .unified_url(&literal_ref)
            .expect("literal $-prefixed token must not attempt env expansion");
        let query_pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(
            query_pairs
                .iter()
                .any(|(k, v)| k == "clientSecret" && v == "$PAYMOB_HMAC_SECRET"),
            "client_secret must be treated literally without env expansion"
        );
    }
}
