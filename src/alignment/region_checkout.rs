#![forbid(unsafe_code)]
//! `PaymobRegion` host router and Unified Checkout / Pixel URL builders (`US-9.1.0` Unit 1).
//!
//! Provides deterministic, SSRF-hardened regional host resolution across Paymob's
//! deployments (`Egypt`, `Ksa`, `Uae`, `Oman`, `Pakistan`, and validated `Custom`
//! HTTPS endpoints) with optional `checkout_base_url` overrides (for example,
//! `https://eg.checkout.paymob.com`).
//!
//! # Security Controls
//!
//! - **TM-1 (SSRF Guard)**: `PaymobRegion::Custom` and any `checkout_base_url`
//!   override reject non-HTTPS schemes, missing or empty hosts, embedded URL
//!   credentials (`user:pass@`), query strings, and fragments.
//! - **TM-4 (Secret Redaction)**: `PixelCheckoutConfig` implements a custom
//!   [`std::fmt::Debug`] representation that redacts `client_secret` and
//!   credential-bearing checkout URLs as `[REDACTED]`.
//!
//! # Examples
//!
//! ```
//! use some_paymob::alignment::region_checkout::{
//!     PaymobRegion, PixelCheckoutConfig, build_pixel_checkout_url, build_unified_checkout_url,
//! };
//!
//! let unified = build_unified_checkout_url(
//!     &PaymobRegion::Egypt,
//!     "egy_pk_test_123",
//!     "egy_csk_test_secret",
//!     Some("https://eg.checkout.paymob.com"),
//! )?;
//! assert_eq!(
//!     unified,
//!     "https://eg.checkout.paymob.com/unifiedcheckout/?publicKey=egy_pk_test_123&clientSecret=egy_csk_test_secret"
//! );
//!
//! let pixel = build_pixel_checkout_url(
//!     &PaymobRegion::Ksa,
//!     "sau_pk_test_123",
//!     "sau_csk_test_secret",
//!     None,
//! )?;
//! assert_eq!(
//!     pixel,
//!     "https://ksa.paymob.com/pixel/?publicKey=sau_pk_test_123&clientSecret=sau_csk_test_secret"
//! );
//!
//! let config = PixelCheckoutConfig::new(
//!     PaymobRegion::Uae,
//!     "are_pk_test_123",
//!     "are_csk_test_secret",
//!     None,
//! )?;
//! assert_eq!(config.script_url(), "https://uae.paymob.com/pixel/main.js");
//! assert!(!format!("{config:?}").contains("are_csk_test_secret"));
//! # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
//! ```

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{ParseError, Url};

/// Canonical Egypt Accept API & default checkout host.
const EGYPT_BASE_URL: &str = "https://accept.paymob.com";
/// Canonical Kingdom of Saudi Arabia host.
const KSA_BASE_URL: &str = "https://ksa.paymob.com";
/// Canonical United Arab Emirates host.
const UAE_BASE_URL: &str = "https://uae.paymob.com";
/// Canonical Sultanate of Oman host.
const OMAN_BASE_URL: &str = "https://oman.paymob.com";
/// Canonical Islamic Republic of Pakistan host.
const PAKISTAN_BASE_URL: &str = "https://pakistan.paymob.com";

/// Static lookup table mapping lowercase region codes and aliases to built-in
/// [`PaymobRegion`] variants.
///
/// Used by [`PaymobRegion::from_code`] and [`FromStr`] to keep string parsing
/// declarative with cyclomatic complexity `CC <= 3`.
pub const KNOWN_REGIONS: &[(&str, PaymobRegion)] = &[
    ("eg", PaymobRegion::Egypt),
    ("egy", PaymobRegion::Egypt),
    ("egypt", PaymobRegion::Egypt),
    ("sa", PaymobRegion::Ksa),
    ("ksa", PaymobRegion::Ksa),
    ("sau", PaymobRegion::Ksa),
    ("saudi", PaymobRegion::Ksa),
    ("saudi_arabia", PaymobRegion::Ksa),
    ("saudi-arabia", PaymobRegion::Ksa),
    ("ae", PaymobRegion::Uae),
    ("uae", PaymobRegion::Uae),
    ("are", PaymobRegion::Uae),
    ("om", PaymobRegion::Oman),
    ("omn", PaymobRegion::Oman),
    ("oman", PaymobRegion::Oman),
    ("pk", PaymobRegion::Pakistan),
    ("pak", PaymobRegion::Pakistan),
    ("pakistan", PaymobRegion::Pakistan),
];

/// Typed errors returned by [`PaymobRegion`] resolution and checkout URL builders.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegionCheckoutError {
    /// The supplied region code did not match any entry in [`KNOWN_REGIONS`].
    #[error("unknown Paymob region code: `{input}`")]
    UnknownRegion {
        /// The unrecognized region code input.
        input: String,
    },
    /// A URL string could not be parsed as a valid RFC 3986 URL.
    #[error("invalid URL in `{field}`: {reason}")]
    InvalidUrl {
        /// Name of the field carrying the invalid URL.
        field: &'static str,
        /// Parser diagnostic message.
        reason: String,
    },
    /// A custom or override URL used a non-HTTPS scheme (TM-1 SSRF guard).
    #[error("insecure URL scheme `{scheme}` in `{field}`: HTTPS is required")]
    InsecureScheme {
        /// Name of the field carrying the non-HTTPS URL.
        field: &'static str,
        /// The rejected URL scheme.
        scheme: String,
    },
    /// A custom or override URL lacked a valid non-empty host (TM-1 SSRF guard).
    #[error("missing or empty host in `{field}`")]
    MissingHost {
        /// Name of the field lacking a host.
        field: &'static str,
    },
    /// A custom or override URL contained embedded credentials (`user:pass@`).
    #[error("embedded credentials are forbidden in `{field}`")]
    EmbeddedCredentials {
        /// Name of the field containing embedded credentials.
        field: &'static str,
    },
    /// A custom or override base URL contained a query string (`?...`).
    #[error("query strings are forbidden in base URL `{field}`")]
    UnexpectedQuery {
        /// Name of the field containing a query string.
        field: &'static str,
    },
    /// A custom or override base URL contained a fragment (`#...`).
    #[error("fragments are forbidden in base URL `{field}`")]
    UnexpectedFragment {
        /// Name of the field containing a fragment.
        field: &'static str,
    },
    /// A required checkout credential (`public_key` or `client_secret`) was empty
    /// or contained only whitespace.
    #[error("`{field}` must not be empty or whitespace")]
    EmptyField {
        /// Name of the empty required field.
        field: &'static str,
    },
}

/// Alignment regional host router for Paymob deployments.
///
/// Resolves canonical HTTPS endpoints for Egypt, KSA, UAE, Oman, Pakistan, and
/// validated `Custom` hosts with zero hardcoded Egypt-only assumptions.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::region_checkout::PaymobRegion;
///
/// let region: PaymobRegion = "ksa".parse()?;
/// assert_eq!(region, PaymobRegion::Ksa);
/// assert_eq!(region.api_base_url()?, "https://ksa.paymob.com");
/// assert_eq!(
///     region.endpoint_url("v1/intention/")?,
///     "https://ksa.paymob.com/v1/intention/"
/// );
/// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PaymobRegion {
    /// Arab Republic of Egypt (`https://accept.paymob.com`).
    Egypt,
    /// Kingdom of Saudi Arabia (`https://ksa.paymob.com`).
    Ksa,
    /// United Arab Emirates (`https://uae.paymob.com`).
    Uae,
    /// Sultanate of Oman (`https://oman.paymob.com`).
    Oman,
    /// Islamic Republic of Pakistan (`https://pakistan.paymob.com`).
    Pakistan,
    /// Custom HTTPS-only deployment with an optional validated checkout host override.
    Custom {
        /// Validated HTTPS API base URL (no trailing slash).
        base_url: String,
        /// Optional validated HTTPS checkout base URL override (no trailing slash).
        checkout_base_url: Option<String>,
    },
}

impl PaymobRegion {
    /// Parses a case-insensitive region code or alias via [`KNOWN_REGIONS`].
    ///
    /// Supported inputs include ISO-2, ISO-3, and country names (for example,
    /// `"eg"`, `"EGY"`, `"ksa"`, `"uae"`, `"om"`, `"pk"`, `"pakistan"`).
    ///
    /// # Errors
    ///
    /// Returns [`RegionCheckoutError::UnknownRegion`] when `code` does not match
    /// any entry in [`KNOWN_REGIONS`].
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::alignment::region_checkout::PaymobRegion;
    ///
    /// assert_eq!(PaymobRegion::from_code("EG")?, PaymobRegion::Egypt);
    /// assert_eq!(PaymobRegion::from_code("  uae ")?, PaymobRegion::Uae);
    /// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
    /// ```
    pub fn from_code(code: &str) -> Result<Self, RegionCheckoutError> {
        let normalized = code.trim().to_ascii_lowercase();
        KNOWN_REGIONS
            .iter()
            .find(|(alias, _)| *alias == normalized)
            .map(|(_, region)| region.clone())
            .ok_or_else(|| RegionCheckoutError::UnknownRegion {
                input: code.to_owned(),
            })
    }

    /// Constructs a validated [`PaymobRegion::Custom`] using an HTTPS-only base URL.
    ///
    /// # Errors
    ///
    /// Returns a [`RegionCheckoutError`] if `base_url` is not a valid HTTPS URL
    /// with a host, or if it contains credentials, a query string, or a fragment.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::alignment::region_checkout::PaymobRegion;
    ///
    /// let custom = PaymobRegion::custom("https://sandbox.paymob.example/")?;
    /// assert_eq!(custom.api_base_url()?, "https://sandbox.paymob.example");
    /// assert_eq!(custom.checkout_base_url()?, "https://sandbox.paymob.example");
    /// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
    /// ```
    pub fn custom(base_url: impl AsRef<str>) -> Result<Self, RegionCheckoutError> {
        let normalized = normalize_https_base_url(base_url.as_ref(), "base_url")?;
        Ok(Self::Custom {
            base_url: normalized,
            checkout_base_url: None,
        })
    }

    /// Constructs a validated [`PaymobRegion::Custom`] with distinct API and
    /// checkout HTTPS base URLs.
    ///
    /// # Errors
    ///
    /// Returns a [`RegionCheckoutError`] if either `base_url` or
    /// `checkout_base_url` fails TM-1 HTTPS validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::alignment::region_checkout::PaymobRegion;
    ///
    /// let custom = PaymobRegion::custom_with_checkout(
    ///     "https://accept.paymob.com",
    ///     "https://eg.checkout.paymob.com",
    /// )?;
    /// assert_eq!(custom.api_base_url()?, "https://accept.paymob.com");
    /// assert_eq!(custom.checkout_base_url()?, "https://eg.checkout.paymob.com");
    /// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
    /// ```
    pub fn custom_with_checkout(
        base_url: impl AsRef<str>,
        checkout_base_url: impl AsRef<str>,
    ) -> Result<Self, RegionCheckoutError> {
        let normalized_api = normalize_https_base_url(base_url.as_ref(), "base_url")?;
        let normalized_checkout =
            normalize_https_base_url(checkout_base_url.as_ref(), "checkout_base_url")?;
        Ok(Self::Custom {
            base_url: normalized_api,
            checkout_base_url: Some(normalized_checkout),
        })
    }

    /// Returns a region with a validated HTTPS `checkout_base_url` override
    /// while preserving this region's API base URL.
    ///
    /// Commonly used to pair [`PaymobRegion::Egypt`] API traffic
    /// (`https://accept.paymob.com`) with `https://eg.checkout.paymob.com`.
    ///
    /// # Errors
    ///
    /// Returns a [`RegionCheckoutError`] if this region's API URL or the
    /// supplied `checkout_base_url` fails TM-1 HTTPS validation.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::alignment::region_checkout::PaymobRegion;
    ///
    /// let eg = PaymobRegion::Egypt.with_checkout_base_url("https://eg.checkout.paymob.com")?;
    /// assert_eq!(eg.api_base_url()?, "https://accept.paymob.com");
    /// assert_eq!(eg.checkout_base_url()?, "https://eg.checkout.paymob.com");
    /// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
    /// ```
    pub fn with_checkout_base_url(
        &self,
        checkout_base_url: impl AsRef<str>,
    ) -> Result<Self, RegionCheckoutError> {
        let api_base = self.api_base_url()?;
        let normalized_checkout =
            normalize_https_base_url(checkout_base_url.as_ref(), "checkout_base_url")?;
        Ok(Self::Custom {
            base_url: api_base,
            checkout_base_url: Some(normalized_checkout),
        })
    }

    /// Returns the canonical uppercase region identifier (`EGY`, `KSA`, `UAE`,
    /// `OMN`, `PAK`, or `CUSTOM`).
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Egypt => "EGY",
            Self::Ksa => "KSA",
            Self::Uae => "UAE",
            Self::Oman => "OMN",
            Self::Pakistan => "PAK",
            Self::Custom { .. } => "CUSTOM",
        }
    }

    /// Resolves and validates the HTTPS API base URL (without a trailing slash).
    ///
    /// Re-validates [`PaymobRegion::Custom`] even if constructed directly or
    /// deserialized from untrusted input.
    ///
    /// # Errors
    ///
    /// Returns a [`RegionCheckoutError`] if a [`PaymobRegion::Custom`] `base_url`
    /// fails TM-1 HTTPS validation.
    pub fn api_base_url(&self) -> Result<String, RegionCheckoutError> {
        match self {
            Self::Egypt => Ok(EGYPT_BASE_URL.to_owned()),
            Self::Ksa => Ok(KSA_BASE_URL.to_owned()),
            Self::Uae => Ok(UAE_BASE_URL.to_owned()),
            Self::Oman => Ok(OMAN_BASE_URL.to_owned()),
            Self::Pakistan => Ok(PAKISTAN_BASE_URL.to_owned()),
            Self::Custom { base_url, .. } => normalize_https_base_url(base_url, "base_url"),
        }
    }

    /// Resolves and validates the HTTPS checkout base URL (without a trailing slash).
    ///
    /// Uses `checkout_base_url` when configured on [`PaymobRegion::Custom`], and
    /// falls back to [`Self::api_base_url`] otherwise.
    ///
    /// # Errors
    ///
    /// Returns a [`RegionCheckoutError`] if a [`PaymobRegion::Custom`] URL fails
    /// TM-1 HTTPS validation.
    pub fn checkout_base_url(&self) -> Result<String, RegionCheckoutError> {
        if let Self::Custom {
            checkout_base_url: Some(override_url),
            ..
        } = self
        {
            return normalize_https_base_url(override_url, "checkout_base_url");
        }
        self.api_base_url()
    }

    /// Joins a relative API path onto [`Self::api_base_url`], preserving any
    /// trailing slash present in `path`.
    ///
    /// # Errors
    ///
    /// Returns a [`RegionCheckoutError`] if the region's API base URL is invalid.
    pub fn endpoint_url(&self, path: &str) -> Result<String, RegionCheckoutError> {
        let base = self.api_base_url()?;
        let trimmed = path.trim_start_matches('/');
        if trimmed.is_empty() {
            return Ok(base);
        }
        Ok(format!("{base}/{trimmed}"))
    }
}

impl FromStr for PaymobRegion {
    type Err = RegionCheckoutError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_code(s)
    }
}

/// Configuration bundle for rendering Paymob's embedded Pixel checkout widget.
///
/// Redacts `client_secret`, `pixel_checkout_url`, and `unified_checkout_url` as
/// `[REDACTED]` in [`fmt::Debug`] output to prevent credential leakage in logs (TM-4).
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::region_checkout::{PaymobRegion, PixelCheckoutConfig};
///
/// let cfg = PixelCheckoutConfig::new(
///     PaymobRegion::Egypt,
///     "egy_pk_live_abc",
///     "egy_csk_live_secret",
///     Some("https://eg.checkout.paymob.com"),
/// )?;
/// assert_eq!(cfg.checkout_base_url(), "https://eg.checkout.paymob.com");
/// assert_eq!(cfg.script_url(), "https://eg.checkout.paymob.com/pixel/main.js");
/// assert_eq!(cfg.public_key(), "egy_pk_live_abc");
/// assert_eq!(cfg.client_secret(), "egy_csk_live_secret");
/// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct PixelCheckoutConfig {
    region: PaymobRegion,
    checkout_base_url: String,
    script_url: String,
    pixel_checkout_url: String,
    unified_checkout_url: String,
    public_key: String,
    client_secret: String,
}

impl PixelCheckoutConfig {
    /// Creates a validated [`PixelCheckoutConfig`] for `region` and optional
    /// `checkout_base_url_override`.
    ///
    /// # Errors
    ///
    /// Returns a [`RegionCheckoutError`] if the region URL or override fails
    /// TM-1 HTTPS validation, or if `public_key` or `client_secret` is empty or
    /// whitespace.
    pub fn new(
        region: PaymobRegion,
        public_key: impl AsRef<str>,
        client_secret: impl AsRef<str>,
        checkout_base_url_override: Option<&str>,
    ) -> Result<Self, RegionCheckoutError> {
        let checkout_base = resolve_checkout_base(&region, checkout_base_url_override)?;
        let pk = validate_non_empty(public_key.as_ref(), "public_key")?;
        let cs = validate_non_empty(client_secret.as_ref(), "client_secret")?;
        let script_url = format!("{checkout_base}/pixel/main.js");
        let pixel_checkout_url = build_checkout_query_url(&checkout_base, "pixel", pk, cs)?;
        let unified_checkout_url =
            build_checkout_query_url(&checkout_base, "unifiedcheckout", pk, cs)?;
        Ok(Self {
            region,
            checkout_base_url: checkout_base,
            script_url,
            pixel_checkout_url,
            unified_checkout_url,
            public_key: pk.to_owned(),
            client_secret: cs.to_owned(),
        })
    }

    /// Returns the configured [`PaymobRegion`].
    #[must_use]
    pub const fn region(&self) -> &PaymobRegion {
        &self.region
    }

    /// Returns the resolved HTTPS checkout base URL (no trailing slash).
    #[must_use]
    pub fn checkout_base_url(&self) -> &str {
        &self.checkout_base_url
    }

    /// Returns the regional Paymob Pixel JavaScript bundle URL.
    #[must_use]
    pub fn script_url(&self) -> &str {
        &self.script_url
    }

    /// Returns the encoded Paymob Pixel checkout URL.
    #[must_use]
    pub fn pixel_checkout_url(&self) -> &str {
        &self.pixel_checkout_url
    }

    /// Returns the encoded Unified Checkout fallback URL for the same region.
    #[must_use]
    pub fn unified_checkout_url(&self) -> &str {
        &self.unified_checkout_url
    }

    /// Returns the validated public key.
    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// Returns the validated client secret.
    #[must_use]
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }
}

impl fmt::Debug for PixelCheckoutConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PixelCheckoutConfig")
            .field("region", &self.region)
            .field("checkout_base_url", &self.checkout_base_url)
            .field("script_url", &self.script_url)
            .field("pixel_checkout_url", &"[REDACTED]")
            .field("unified_checkout_url", &"[REDACTED]")
            .field("public_key", &self.public_key)
            .field("client_secret", &"[REDACTED]")
            .finish()
    }
}

/// Builds a regional Paymob Unified Checkout URL with URL-encoded query parameters:
/// `{checkout_base}/unifiedcheckout/?publicKey={encoded_pk}&clientSecret={encoded_cs}`.
///
/// When `checkout_base_url_override` is `Some`, it is validated against TM-1
/// HTTPS/SSRF rules and used in place of `region.checkout_base_url()`.
///
/// # Errors
///
/// Returns a [`RegionCheckoutError`] if the checkout host fails TM-1 validation
/// or if `public_key` or `client_secret` is empty or whitespace.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::region_checkout::{PaymobRegion, build_unified_checkout_url};
///
/// let url = build_unified_checkout_url(
///     &PaymobRegion::Oman,
///     "omn_pk_test_1",
///     "omn_csk_test_2",
///     None,
/// )?;
/// assert_eq!(
///     url,
///     "https://oman.paymob.com/unifiedcheckout/?publicKey=omn_pk_test_1&clientSecret=omn_csk_test_2"
/// );
/// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
/// ```
pub fn build_unified_checkout_url(
    region: &PaymobRegion,
    public_key: &str,
    client_secret: &str,
    checkout_base_url_override: Option<&str>,
) -> Result<String, RegionCheckoutError> {
    build_checkout_endpoint_url(
        region,
        "unifiedcheckout",
        public_key,
        client_secret,
        checkout_base_url_override,
    )
}

/// Builds a regional Paymob Pixel checkout URL with URL-encoded query parameters:
/// `{checkout_base}/pixel/?publicKey={encoded_pk}&clientSecret={encoded_cs}`.
///
/// When `checkout_base_url_override` is `Some`, it is validated against TM-1
/// HTTPS/SSRF rules and used in place of `region.checkout_base_url()`.
///
/// # Errors
///
/// Returns a [`RegionCheckoutError`] if the checkout host fails TM-1 validation
/// or if `public_key` or `client_secret` is empty or whitespace.
///
/// # Examples
///
/// ```
/// use some_paymob::alignment::region_checkout::{PaymobRegion, build_pixel_checkout_url};
///
/// let url = build_pixel_checkout_url(
///     &PaymobRegion::Pakistan,
///     "pak_pk_test_1",
///     "pak_csk_test_2",
///     None,
/// )?;
/// assert_eq!(
///     url,
///     "https://pakistan.paymob.com/pixel/?publicKey=pak_pk_test_1&clientSecret=pak_csk_test_2"
/// );
/// # Ok::<(), some_paymob::alignment::region_checkout::RegionCheckoutError>(())
/// ```
pub fn build_pixel_checkout_url(
    region: &PaymobRegion,
    public_key: &str,
    client_secret: &str,
    checkout_base_url_override: Option<&str>,
) -> Result<String, RegionCheckoutError> {
    build_checkout_endpoint_url(
        region,
        "pixel",
        public_key,
        client_secret,
        checkout_base_url_override,
    )
}

/// Resolves the checkout base URL, validates keys, and builds `{base}/{segment}/?...`.
fn build_checkout_endpoint_url(
    region: &PaymobRegion,
    segment: &str,
    public_key: &str,
    client_secret: &str,
    checkout_base_url_override: Option<&str>,
) -> Result<String, RegionCheckoutError> {
    let checkout_base = resolve_checkout_base(region, checkout_base_url_override)?;
    let pk = validate_non_empty(public_key, "public_key")?;
    let cs = validate_non_empty(client_secret, "client_secret")?;
    build_checkout_query_url(&checkout_base, segment, pk, cs)
}

/// Resolves the active checkout base URL from either an explicit override or the region.
fn resolve_checkout_base(
    region: &PaymobRegion,
    checkout_base_url_override: Option<&str>,
) -> Result<String, RegionCheckoutError> {
    if let Some(override_url) = checkout_base_url_override {
        return normalize_https_base_url(override_url, "checkout_base_url");
    }
    region.checkout_base_url()
}

/// Formats `{checkout_base}/{segment}/?publicKey=...&clientSecret=...` using [`Url`].
fn build_checkout_query_url(
    checkout_base: &str,
    segment: &str,
    public_key: &str,
    client_secret: &str,
) -> Result<String, RegionCheckoutError> {
    let raw = format!("{checkout_base}/{segment}/");
    let mut url = Url::parse(&raw).map_err(|err| RegionCheckoutError::InvalidUrl {
        field: "checkout_base_url",
        reason: err.to_string(),
    })?;
    url.query_pairs_mut()
        .append_pair("publicKey", public_key)
        .append_pair("clientSecret", client_secret);
    Ok(url.into())
}

/// Validates that `value` is non-empty after trimming whitespace.
fn validate_non_empty<'a>(
    value: &'a str,
    field: &'static str,
) -> Result<&'a str, RegionCheckoutError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(RegionCheckoutError::EmptyField { field });
    }
    Ok(trimmed)
}

/// Validates and normalizes an HTTPS base URL (no trailing slash) per TM-1.
fn normalize_https_base_url(raw: &str, field: &'static str) -> Result<String, RegionCheckoutError> {
    let parsed = parse_https_url(raw, field)?;
    reject_url_credentials(&parsed, field)?;
    reject_url_query_and_fragment(&parsed, field)?;
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

/// Parses a URL and enforces HTTPS scheme plus a non-empty host.
fn parse_https_url(raw: &str, field: &'static str) -> Result<Url, RegionCheckoutError> {
    let trimmed = raw.trim();
    if has_empty_https_authority(trimmed) {
        return Err(RegionCheckoutError::MissingHost { field });
    }
    let parsed = Url::parse(trimmed).map_err(|err| map_url_parse_error(err, field))?;
    if parsed.scheme() != "https" {
        return Err(RegionCheckoutError::InsecureScheme {
            field,
            scheme: parsed.scheme().to_owned(),
        });
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(RegionCheckoutError::MissingHost { field });
    }
    Ok(parsed)
}

/// Returns `true` when an HTTPS URL has an extra leading slash or backslash after `://`
/// (such as `https:///no-host`), preventing WHATWG slash-collapsing from promoting a path
/// segment into a host.
fn has_empty_https_authority(trimmed: &str) -> bool {
    let Some((scheme, rest)) = trimmed.split_once("://") else {
        return false;
    };
    scheme.eq_ignore_ascii_case("https") && rest.starts_with(['/', '\\'])
}

/// Maps a [`ParseError`] into [`RegionCheckoutError`], preserving [`RegionCheckoutError::MissingHost`].
fn map_url_parse_error(err: ParseError, field: &'static str) -> RegionCheckoutError {
    if err == ParseError::EmptyHost {
        return RegionCheckoutError::MissingHost { field };
    }
    RegionCheckoutError::InvalidUrl {
        field,
        reason: err.to_string(),
    }
}

/// Rejects embedded usernames or passwords in a base URL.
fn reject_url_credentials(parsed: &Url, field: &'static str) -> Result<(), RegionCheckoutError> {
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RegionCheckoutError::EmbeddedCredentials { field });
    }
    Ok(())
}

/// Rejects query strings and fragments in a base URL.
fn reject_url_query_and_fragment(
    parsed: &Url,
    field: &'static str,
) -> Result<(), RegionCheckoutError> {
    if parsed.query().is_some() {
        return Err(RegionCheckoutError::UnexpectedQuery { field });
    }
    if parsed.fragment().is_some() {
        return Err(RegionCheckoutError::UnexpectedFragment { field });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_9_1_1_builtin_regional_hosts_and_codes() {
        let cases = [
            (PaymobRegion::Egypt, "EGY", "https://accept.paymob.com"),
            (PaymobRegion::Ksa, "KSA", "https://ksa.paymob.com"),
            (PaymobRegion::Uae, "UAE", "https://uae.paymob.com"),
            (PaymobRegion::Oman, "OMN", "https://oman.paymob.com"),
            (PaymobRegion::Pakistan, "PAK", "https://pakistan.paymob.com"),
        ];
        for (region, expected_code, expected_host) in cases {
            assert_eq!(region.code(), expected_code);
            assert_eq!(region.api_base_url().unwrap(), expected_host);
            assert_eq!(region.checkout_base_url().unwrap(), expected_host);
            assert_eq!(
                region.endpoint_url("/v1/intention/").unwrap(),
                format!("{expected_host}/v1/intention/")
            );
        }
    }

    #[test]
    fn tc_9_1_1_from_code_and_from_str_lookup_table() {
        assert_eq!(PaymobRegion::from_code("eg").unwrap(), PaymobRegion::Egypt);
        assert_eq!(PaymobRegion::from_code("EGY").unwrap(), PaymobRegion::Egypt);
        assert_eq!(
            "  Egypt ".parse::<PaymobRegion>().unwrap(),
            PaymobRegion::Egypt
        );
        assert_eq!("ksa".parse::<PaymobRegion>().unwrap(), PaymobRegion::Ksa);
        assert_eq!("SA".parse::<PaymobRegion>().unwrap(), PaymobRegion::Ksa);
        assert_eq!(
            "saudi-arabia".parse::<PaymobRegion>().unwrap(),
            PaymobRegion::Ksa
        );
        assert_eq!("uae".parse::<PaymobRegion>().unwrap(), PaymobRegion::Uae);
        assert_eq!("ae".parse::<PaymobRegion>().unwrap(), PaymobRegion::Uae);
        assert_eq!("om".parse::<PaymobRegion>().unwrap(), PaymobRegion::Oman);
        assert_eq!("OMN".parse::<PaymobRegion>().unwrap(), PaymobRegion::Oman);
        assert_eq!(
            "pk".parse::<PaymobRegion>().unwrap(),
            PaymobRegion::Pakistan
        );
        assert_eq!(
            "pakistan".parse::<PaymobRegion>().unwrap(),
            PaymobRegion::Pakistan
        );
        let err = PaymobRegion::from_code("us").unwrap_err();
        assert_eq!(
            err,
            RegionCheckoutError::UnknownRegion {
                input: "us".to_owned(),
            }
        );
    }

    #[test]
    fn tc_9_1_1_egypt_checkout_base_url_override() {
        let url = build_unified_checkout_url(
            &PaymobRegion::Egypt,
            "egy_pk_test_abc",
            "egy_csk_test_xyz",
            Some("https://eg.checkout.paymob.com/"),
        )
        .unwrap();
        assert_eq!(
            url,
            "https://eg.checkout.paymob.com/unifiedcheckout/?publicKey=egy_pk_test_abc&clientSecret=egy_csk_test_xyz"
        );
        let eg_with_override = PaymobRegion::Egypt
            .with_checkout_base_url("https://eg.checkout.paymob.com")
            .unwrap();
        assert_eq!(
            eg_with_override.api_base_url().unwrap(),
            "https://accept.paymob.com"
        );
        assert_eq!(
            eg_with_override.checkout_base_url().unwrap(),
            "https://eg.checkout.paymob.com"
        );
        assert_eq!(eg_with_override.code(), "CUSTOM");
        let from_region = build_unified_checkout_url(
            &eg_with_override,
            "egy_pk_test_abc",
            "egy_csk_test_xyz",
            None,
        )
        .unwrap();
        assert_eq!(from_region, url);
    }

    #[test]
    fn tc_9_1_1_custom_region_and_pixel_builders() {
        let custom = PaymobRegion::custom_with_checkout(
            "https://api.custom.paymob.test/",
            "https://checkout.custom.paymob.test/",
        )
        .unwrap();
        assert_eq!(
            custom.api_base_url().unwrap(),
            "https://api.custom.paymob.test"
        );
        assert_eq!(
            custom.checkout_base_url().unwrap(),
            "https://checkout.custom.paymob.test"
        );
        let pixel_url =
            build_pixel_checkout_url(&custom, "custom_pk", "custom_secret", None).unwrap();
        assert_eq!(
            pixel_url,
            "https://checkout.custom.paymob.test/pixel/?publicKey=custom_pk&clientSecret=custom_secret"
        );
        let config =
            PixelCheckoutConfig::new(custom.clone(), "custom_pk", "custom_secret", None).unwrap();
        assert_eq!(config.region(), &custom);
        assert_eq!(
            config.checkout_base_url(),
            "https://checkout.custom.paymob.test"
        );
        assert_eq!(
            config.script_url(),
            "https://checkout.custom.paymob.test/pixel/main.js"
        );
        assert_eq!(config.pixel_checkout_url(), pixel_url);
        assert_eq!(
            config.unified_checkout_url(),
            "https://checkout.custom.paymob.test/unifiedcheckout/?publicKey=custom_pk&clientSecret=custom_secret"
        );
        assert_eq!(config.public_key(), "custom_pk");
        assert_eq!(config.client_secret(), "custom_secret");
    }

    #[test]
    fn tc_9_1_1_url_query_encoding() {
        let url = build_unified_checkout_url(
            &PaymobRegion::Ksa,
            "pk+test&a=b",
            "cs/secret?x=1#frag",
            None,
        )
        .unwrap();
        assert_eq!(
            url,
            "https://ksa.paymob.com/unifiedcheckout/?publicKey=pk%2Btest%26a%3Db&clientSecret=cs%2Fsecret%3Fx%3D1%23frag"
        );
    }

    #[test]
    fn tm_1_rejects_non_https_and_ssrf_vectors() {
        assert!(matches!(
            PaymobRegion::custom("http://accept.paymob.com"),
            Err(RegionCheckoutError::InsecureScheme {
                field: "base_url",
                ..
            })
        ));
        assert!(matches!(
            PaymobRegion::custom("ftp://accept.paymob.com"),
            Err(RegionCheckoutError::InsecureScheme {
                field: "base_url",
                ..
            })
        ));
        assert!(matches!(
            PaymobRegion::custom("javascript:alert(1)"),
            Err(RegionCheckoutError::InsecureScheme {
                field: "base_url",
                ..
            })
        ));
        assert!(matches!(
            PaymobRegion::custom("https:///no-host"),
            Err(RegionCheckoutError::MissingHost { field: "base_url" })
        ));
        assert!(matches!(
            PaymobRegion::custom("HTTPS:///no-host"),
            Err(RegionCheckoutError::MissingHost { field: "base_url" })
        ));
        assert!(matches!(
            PaymobRegion::custom("https://"),
            Err(RegionCheckoutError::MissingHost { field: "base_url" })
        ));
        assert!(matches!(
            PaymobRegion::custom("https://\\no-host"),
            Err(RegionCheckoutError::MissingHost { field: "base_url" })
        ));
        assert!(matches!(
            PaymobRegion::custom("https://user:pass@accept.paymob.com"),
            Err(RegionCheckoutError::EmbeddedCredentials { field: "base_url" })
        ));
        assert!(matches!(
            PaymobRegion::custom("https://user@accept.paymob.com"),
            Err(RegionCheckoutError::EmbeddedCredentials { field: "base_url" })
        ));
        assert!(matches!(
            PaymobRegion::custom("https://accept.paymob.com?redirect=evil"),
            Err(RegionCheckoutError::UnexpectedQuery { field: "base_url" })
        ));
        assert!(matches!(
            PaymobRegion::custom("https://accept.paymob.com#section"),
            Err(RegionCheckoutError::UnexpectedFragment { field: "base_url" })
        ));
        assert!(matches!(
            build_unified_checkout_url(
                &PaymobRegion::Egypt,
                "pk",
                "cs",
                Some("http://eg.checkout.paymob.com"),
            ),
            Err(RegionCheckoutError::InsecureScheme {
                field: "checkout_base_url",
                ..
            })
        ));
        assert!(matches!(
            build_unified_checkout_url(
                &PaymobRegion::Egypt,
                "pk",
                "cs",
                Some("https://admin:secret@eg.checkout.paymob.com"),
            ),
            Err(RegionCheckoutError::EmbeddedCredentials {
                field: "checkout_base_url",
            })
        ));
        assert!(matches!(
            build_unified_checkout_url(
                &PaymobRegion::Egypt,
                "pk",
                "cs",
                Some("https://eg.checkout.paymob.com?injected=1"),
            ),
            Err(RegionCheckoutError::UnexpectedQuery {
                field: "checkout_base_url",
            })
        ));
        assert!(matches!(
            build_unified_checkout_url(
                &PaymobRegion::Egypt,
                "pk",
                "cs",
                Some("https://eg.checkout.paymob.com#frag"),
            ),
            Err(RegionCheckoutError::UnexpectedFragment {
                field: "checkout_base_url",
            })
        ));
        let unvalidated = PaymobRegion::Custom {
            base_url: "http://169.254.169.254".to_owned(),
            checkout_base_url: None,
        };
        assert!(matches!(
            unvalidated.api_base_url(),
            Err(RegionCheckoutError::InsecureScheme { .. })
        ));
    }

    #[test]
    fn tm_1_rejects_empty_or_whitespace_credentials() {
        assert_eq!(
            build_unified_checkout_url(&PaymobRegion::Uae, "", "secret", None),
            Err(RegionCheckoutError::EmptyField {
                field: "public_key",
            })
        );
        assert_eq!(
            build_unified_checkout_url(&PaymobRegion::Uae, "   \t\n ", "secret", None),
            Err(RegionCheckoutError::EmptyField {
                field: "public_key",
            })
        );
        assert_eq!(
            build_unified_checkout_url(&PaymobRegion::Uae, "pk_123", "", None),
            Err(RegionCheckoutError::EmptyField {
                field: "client_secret",
            })
        );
        assert_eq!(
            build_pixel_checkout_url(&PaymobRegion::Uae, "pk_123", "   ", None),
            Err(RegionCheckoutError::EmptyField {
                field: "client_secret",
            })
        );
    }

    #[test]
    fn tm_4_pixel_config_debug_redacts_client_secret() {
        let secret = "egy_csk_live_super_secret_999";
        let config =
            PixelCheckoutConfig::new(PaymobRegion::Egypt, "egy_pk_live_123", secret, None).unwrap();
        let debug_output = format!("{config:?}");
        assert!(!debug_output.contains(secret));
        assert!(debug_output.contains("[REDACTED]"));
        assert!(debug_output.contains("egy_pk_live_123"));
        assert!(debug_output.contains("https://accept.paymob.com/pixel/main.js"));
    }
}
