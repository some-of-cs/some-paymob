//! Arc-backed Paymob microkernel client and regional URL builders.
//!
//! [`PaymobClient`] is the primary entry point for `some-paymob`. It wraps a
//! shared [`PaymobCore`] inside an [`Arc`] so cloning the client across async
//! tasks or HTTP handlers is an atomic reference-count increment (`O(1)`),
//! with compile-time `Send + Sync` guarantees and `[REDACTED]` debug output.

use std::fmt;
use std::sync::Arc;

use reqwest::Client;
use url::Url;

use crate::core::config::ClientConfig;
use crate::core::error::PaymobError;
use crate::core::region::RegionalEndpoints;

/// Shared microkernel state backing [`PaymobClient`].
///
/// Holds the validated [`ClientConfig`], resolved [`RegionalEndpoints`], and
/// the underlying TLS 1.3 [`reqwest::Client`] transport pool.
pub struct PaymobCore {
    config: ClientConfig,
    endpoints: RegionalEndpoints,
    http: Client,
}

impl fmt::Debug for PaymobCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobCore")
            .field("region", self.config.region())
            .field("endpoints", &self.endpoints)
            .field("credentials", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Thread-safe, cheaply cloneable Paymob microkernel client.
///
/// Wraps `Arc<PaymobCore>` so it can be shared freely across Tokio tasks,
/// Axum/Actix state extractors, and Tonic gRPC services without duplicating
/// connection pools or credential buffers.
///
/// # Examples
///
/// ```rust,no_run
/// use some_paymob::core::client::PaymobClient;
/// use some_paymob::core::config::ClientConfig;
/// use some_paymob::core::region::PaymobRegion;
///
/// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
/// let config = ClientConfig::builder()
///     .region(PaymobRegion::Egypt)
///     .secret_key("egy_sk_test_example")
///     .public_key("egy_pk_test_example")
///     .build()?;
///
/// let client = PaymobClient::new(config)?;
/// let cloned = client.clone();
/// let intention_url = cloned.accept_url("/v1/intention/")?;
/// assert_eq!(intention_url.as_str(), "https://accept.paymob.com/v1/intention/");
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct PaymobClient {
    inner: Arc<PaymobCore>,
}

const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn check() {
        assert_send_sync::<PaymobClient>();
        assert_send_sync::<PaymobCore>();
    }
};

impl fmt::Debug for PaymobClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PaymobClient")
            .field("core", &self.inner)
            .finish()
    }
}

impl PaymobClient {
    /// Constructs a new [`PaymobClient`] from a validated [`ClientConfig`].
    ///
    /// Resolves [`RegionalEndpoints`] for the configured region and initializes
    /// the underlying [`reqwest::Client`] with the configured request timeout.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if regional endpoint resolution
    /// fails, or [`PaymobError::TransportError`] if the HTTP client fails to
    /// initialize.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key("egy_sk_test_example")
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// assert!(format!("{client:?}").contains("[REDACTED]"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(config: ClientConfig) -> Result<Self, PaymobError> {
        let endpoints = RegionalEndpoints::from_region(config.region())?;
        let http = Client::builder()
            .timeout(config.timeout())
            .build()
            .map_err(|err| PaymobError::TransportError(err.to_string()))?;
        let core = PaymobCore {
            config,
            endpoints,
            http,
        };
        Ok(Self {
            inner: Arc::new(core),
        })
    }

    /// Returns a reference to the validated [`ClientConfig`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::SaudiArabia)
    ///     .secret_key("ksa_sk_test_example")
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// assert_eq!(client.config().region(), &PaymobRegion::SaudiArabia);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn config(&self) -> &ClientConfig {
        &self.inner.config
    }

    /// Returns a reference to the resolved [`RegionalEndpoints`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key("egy_sk_test_example")
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let _endpoints = client.endpoints();
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn endpoints(&self) -> &RegionalEndpoints {
        &self.inner.endpoints
    }

    /// Returns a reference to the underlying [`reqwest::Client`] transport.
    #[must_use]
    pub fn http(&self) -> &Client {
        &self.inner.http
    }

    /// Builds a full Accept Acquiring URL by joining `path` onto the regional Accept base URL.
    ///
    /// Preserves trailing slashes on `path` (for example, `/v1/intention/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `path` contains an explicit URL
    /// scheme/authority or produces an invalid URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key("egy_sk_test_example")
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let url = client.accept_url("/v1/intention/")?;
    /// assert_eq!(url.as_str(), "https://accept.paymob.com/v1/intention/");
    /// # Ok(())
    /// # }
    /// ```
    pub fn accept_url(&self, path: &str) -> Result<Url, PaymobError> {
        join_regional_url(self.inner.endpoints.accept_base_url(), path, "accept_url")
    }

    /// Builds a full Unified Checkout URL by joining `path` onto the regional Checkout base URL.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `path` contains an explicit URL
    /// scheme/authority or produces an invalid URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key("egy_sk_test_example")
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let url = client.checkout_url("/?publicKey=egy_pk_test_1&clientSecret=cs_1")?;
    /// assert!(url.as_str().starts_with("https://accept.paymob.com/unifiedcheckout/"));
    /// # Ok(())
    /// # }
    /// ```
    pub fn checkout_url(&self, path: &str) -> Result<Url, PaymobError> {
        join_regional_url(
            self.inner.endpoints.checkout_base_url(),
            path,
            "checkout_url",
        )
    }

    /// Builds a full Payouts URL by joining `path` onto the regional Payouts base URL.
    ///
    /// Preserves trailing slashes required by Payouts endpoints (for example,
    /// `/api/secure/disburse/`).
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `path` contains an explicit URL
    /// scheme/authority or produces an invalid URL.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use some_paymob::core::client::PaymobClient;
    /// use some_paymob::core::config::ClientConfig;
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// # fn example() -> Result<(), some_paymob::core::error::PaymobError> {
    /// let config = ClientConfig::builder()
    ///     .region(PaymobRegion::Egypt)
    ///     .secret_key("egy_sk_test_example")
    ///     .build()?;
    /// let client = PaymobClient::new(config)?;
    /// let url = client.payouts_url("/api/secure/disburse/")?;
    /// assert_eq!(
    ///     url.as_str(),
    ///     "https://payouts.paymobsolutions.com/api/secure/disburse/"
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn payouts_url(&self, path: &str) -> Result<Url, PaymobError> {
        join_regional_url(self.inner.endpoints.payouts_base_url(), path, "payouts_url")
    }

    /// Returns `true` when two [`PaymobClient`] handles share the same underlying [`PaymobCore`].
    #[must_use]
    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

fn join_regional_url(base: &str, path: &str, field: &'static str) -> Result<Url, PaymobError> {
    let trimmed_base = base.trim_end_matches('/');
    let normalized_path = normalize_relative_path(path)?;
    let full = format!("{trimmed_base}/{normalized_path}");
    Url::parse(&full).map_err(|err| PaymobError::ValidationError {
        field,
        reason: format!("invalid regional URL: {err}"),
    })
}

fn normalize_relative_path(path: &str) -> Result<&str, PaymobError> {
    let trimmed = path.trim();
    if trimmed.contains("://") || trimmed.starts_with("//") {
        return Err(PaymobError::ValidationError {
            field: "path",
            reason: "relative endpoint path must not contain a URL scheme or authority".to_owned(),
        });
    }
    Ok(trimmed.trim_start_matches('/'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::region::PaymobRegion;

    fn sample_client(region: PaymobRegion) -> PaymobClient {
        let config = ClientConfig::builder()
            .region(region)
            .secret_key("egy_sk_test_626supersecretvalue")
            .public_key("egy_pk_test_999publicvalue")
            .build()
            .expect("valid test client config");
        PaymobClient::new(config).expect("valid PaymobClient")
    }

    #[test]
    fn tc_1_1_4_cheap_clone_shares_arc_core() {
        let client = sample_client(PaymobRegion::Egypt);
        let cloned = client.clone();
        assert!(client.ptr_eq(&cloned));
    }

    #[test]
    fn tc_1_1_4_send_sync_runtime_check() {
        fn requires_send_sync<T: Send + Sync>(_val: &T) {}
        let client = sample_client(PaymobRegion::Egypt);
        requires_send_sync(&client);
    }

    #[test]
    fn tc_1_1_4_regional_url_builders_preserve_trailing_slashes() {
        let client = sample_client(PaymobRegion::Egypt);
        let accept = client
            .accept_url("/v1/intention/")
            .expect("accept URL should parse");
        assert_eq!(accept.as_str(), "https://accept.paymob.com/v1/intention/");

        let checkout = client
            .checkout_url("?publicKey=pk_1&clientSecret=cs_1")
            .expect("checkout URL should parse");
        assert_eq!(
            checkout.as_str(),
            "https://accept.paymob.com/unifiedcheckout/?publicKey=pk_1&clientSecret=cs_1"
        );

        let payouts = client
            .payouts_url("/api/secure/disburse/")
            .expect("payouts URL should parse");
        assert_eq!(
            payouts.as_str(),
            "https://payouts.paymobsolutions.com/api/secure/disburse/"
        );
    }

    #[test]
    fn tc_1_1_4_regional_url_builders_reject_scheme_or_authority_injection() {
        let client = sample_client(PaymobRegion::Egypt);
        let scheme_err = client
            .accept_url("https://evil.example.com/steal")
            .expect_err("scheme injection must be rejected");
        assert!(matches!(
            scheme_err,
            PaymobError::ValidationError { field: "path", .. }
        ));

        let authority_err = client
            .payouts_url("//evil.example.com/steal")
            .expect_err("protocol-relative authority must be rejected");
        assert!(matches!(
            authority_err,
            PaymobError::ValidationError { field: "path", .. }
        ));
    }

    #[test]
    fn tc_1_1_4_config_and_endpoints_accessors_match_region() {
        let client = sample_client(PaymobRegion::SaudiArabia);
        assert_eq!(client.config().region(), &PaymobRegion::SaudiArabia);
        assert_eq!(
            client.endpoints().accept_base_url(),
            "https://ksa.paymob.com"
        );
    }

    #[test]
    fn tc_1_1_4_debug_output_redacts_secrets() {
        let client = sample_client(PaymobRegion::Egypt);
        let debug_str = format!("{client:?}");
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("626supersecretvalue"));
        assert!(!debug_str.contains("egy_sk_test_"));
    }

    #[test]
    fn tc_1_1_4_join_regional_url_handles_empty_path() {
        let url = join_regional_url("https://accept.paymob.com/", "", "accept_url")
            .expect("empty path should resolve to base");
        assert_eq!(url.as_str(), "https://accept.paymob.com/");
    }
}
