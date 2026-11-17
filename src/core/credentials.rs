#![forbid(unsafe_code)]
//! Strongly-typed, memory-safe credential newtypes and prefix parser for Paymob.
//!
//! All secret-bearing types wrap [`secrecy::SecretString`], derive [`zeroize::ZeroizeOnDrop`],
//! and emit `"[REDACTED]"` in both [`std::fmt::Debug`] and [`std::fmt::Display`] so raw secrets
//! never leak into logs or panic traces.

use std::fmt;

use secrecy::{ExposeSecret, SecretString};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::core::error::PaymobError;
use crate::core::region::PaymobRegion;

/// Redacted placeholder emitted by all credential `Debug` and `Display` implementations.
const REDACTED: &str = "[REDACTED]";

/// Implements [`fmt::Debug`] and [`fmt::Display`] emitting `"[REDACTED]"` for secret types.
macro_rules! impl_redacted_fmt {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl fmt::Debug for $ty {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(REDACTED)
                }
            }

            impl fmt::Display for $ty {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str(REDACTED)
                }
            }
        )+
    };
}

/// Paymob operating environment inferred from credential prefixes or configured explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EnvironmentMode {
    /// Sandbox / test mode (`*_sk_test_*`, `*_pk_test_*`).
    Test,
    /// Production / live mode (`*_sk_live_*`, `*_pk_live_*`).
    Live,
}

impl EnvironmentMode {
    /// Returns `true` if this mode represents [`EnvironmentMode::Test`].
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::EnvironmentMode;
    ///
    /// assert!(EnvironmentMode::Test.is_test());
    /// assert!(!EnvironmentMode::Live.is_test());
    /// ```
    #[must_use]
    pub const fn is_test(self) -> bool {
        matches!(self, Self::Test)
    }

    /// Returns `true` if this mode represents [`EnvironmentMode::Live`].
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::EnvironmentMode;
    ///
    /// assert!(EnvironmentMode::Live.is_live());
    /// assert!(!EnvironmentMode::Test.is_live());
    /// ```
    #[must_use]
    pub const fn is_live(self) -> bool {
        matches!(self, Self::Live)
    }

    /// Returns the lowercase string identifier (`"test"` or `"live"`).
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::EnvironmentMode;
    ///
    /// assert_eq!(EnvironmentMode::Test.as_str(), "test");
    /// assert_eq!(EnvironmentMode::Live.as_str(), "live");
    /// ```
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Test => "test",
            Self::Live => "live",
        }
    }
}

impl fmt::Display for EnvironmentMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classification of a Paymob key prefix as either server-secret or client-public.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// Server-side secret key (`sk_*` or `<region>_sk_*`).
    Secret,
    /// Client-side publishable public key (`pk_*` or `<region>_pk_*`).
    Public,
}

/// Metadata inferred from a known Paymob key prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKeyPrefix {
    /// Whether the key is a server secret key or a publishable public key.
    pub kind: KeyKind,
    /// Environment mode (`Test` or `Live`) encoded in the prefix.
    pub mode: EnvironmentMode,
    /// Regional Paymob gateway encoded in the prefix, if present.
    pub region: Option<PaymobRegion>,
}

/// Static lookup table mapping known Paymob key prefixes to `(KeyKind, EnvironmentMode, Option<PaymobRegion>)`.
pub const KNOWN_PREFIXES: &[(&str, KeyKind, EnvironmentMode, Option<PaymobRegion>)] = &[
    (
        "egy_sk_test_",
        KeyKind::Secret,
        EnvironmentMode::Test,
        Some(PaymobRegion::Egypt),
    ),
    (
        "egy_sk_live_",
        KeyKind::Secret,
        EnvironmentMode::Live,
        Some(PaymobRegion::Egypt),
    ),
    (
        "egy_pk_test_",
        KeyKind::Public,
        EnvironmentMode::Test,
        Some(PaymobRegion::Egypt),
    ),
    (
        "egy_pk_live_",
        KeyKind::Public,
        EnvironmentMode::Live,
        Some(PaymobRegion::Egypt),
    ),
    (
        "ksa_sk_test_",
        KeyKind::Secret,
        EnvironmentMode::Test,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "ksa_sk_live_",
        KeyKind::Secret,
        EnvironmentMode::Live,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "ksa_pk_test_",
        KeyKind::Public,
        EnvironmentMode::Test,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "ksa_pk_live_",
        KeyKind::Public,
        EnvironmentMode::Live,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "sau_sk_test_",
        KeyKind::Secret,
        EnvironmentMode::Test,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "sau_sk_live_",
        KeyKind::Secret,
        EnvironmentMode::Live,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "sau_pk_test_",
        KeyKind::Public,
        EnvironmentMode::Test,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "sau_pk_live_",
        KeyKind::Public,
        EnvironmentMode::Live,
        Some(PaymobRegion::SaudiArabia),
    ),
    (
        "uae_sk_test_",
        KeyKind::Secret,
        EnvironmentMode::Test,
        Some(PaymobRegion::Uae),
    ),
    (
        "uae_sk_live_",
        KeyKind::Secret,
        EnvironmentMode::Live,
        Some(PaymobRegion::Uae),
    ),
    (
        "uae_pk_test_",
        KeyKind::Public,
        EnvironmentMode::Test,
        Some(PaymobRegion::Uae),
    ),
    (
        "uae_pk_live_",
        KeyKind::Public,
        EnvironmentMode::Live,
        Some(PaymobRegion::Uae),
    ),
    (
        "are_sk_test_",
        KeyKind::Secret,
        EnvironmentMode::Test,
        Some(PaymobRegion::Uae),
    ),
    (
        "are_sk_live_",
        KeyKind::Secret,
        EnvironmentMode::Live,
        Some(PaymobRegion::Uae),
    ),
    (
        "are_pk_test_",
        KeyKind::Public,
        EnvironmentMode::Test,
        Some(PaymobRegion::Uae),
    ),
    (
        "are_pk_live_",
        KeyKind::Public,
        EnvironmentMode::Live,
        Some(PaymobRegion::Uae),
    ),
    (
        "omn_sk_test_",
        KeyKind::Secret,
        EnvironmentMode::Test,
        Some(PaymobRegion::Oman),
    ),
    (
        "omn_sk_live_",
        KeyKind::Secret,
        EnvironmentMode::Live,
        Some(PaymobRegion::Oman),
    ),
    (
        "omn_pk_test_",
        KeyKind::Public,
        EnvironmentMode::Test,
        Some(PaymobRegion::Oman),
    ),
    (
        "omn_pk_live_",
        KeyKind::Public,
        EnvironmentMode::Live,
        Some(PaymobRegion::Oman),
    ),
    (
        "pak_sk_test_",
        KeyKind::Secret,
        EnvironmentMode::Test,
        Some(PaymobRegion::Pakistan),
    ),
    (
        "pak_sk_live_",
        KeyKind::Secret,
        EnvironmentMode::Live,
        Some(PaymobRegion::Pakistan),
    ),
    (
        "pak_pk_test_",
        KeyKind::Public,
        EnvironmentMode::Test,
        Some(PaymobRegion::Pakistan),
    ),
    (
        "pak_pk_live_",
        KeyKind::Public,
        EnvironmentMode::Live,
        Some(PaymobRegion::Pakistan),
    ),
    ("sk_test_", KeyKind::Secret, EnvironmentMode::Test, None),
    ("sk_live_", KeyKind::Secret, EnvironmentMode::Live, None),
    ("pk_test_", KeyKind::Public, EnvironmentMode::Test, None),
    ("pk_live_", KeyKind::Public, EnvironmentMode::Live, None),
];

/// Parses a Paymob key prefix using [`KNOWN_PREFIXES`] in `CC <= 3`.
///
/// Trims surrounding whitespace and normalizes ASCII casing before matching.
/// Returns `None` if `raw` does not start with any known regional or generic prefix.
///
/// # Examples
///
/// ```
/// use some_paymob::core::credentials::{parse_key_prefix, EnvironmentMode, KeyKind};
/// use some_paymob::core::region::PaymobRegion;
///
/// let parsed = parse_key_prefix("egy_sk_test_626xxx").expect("known prefix");
/// assert_eq!(parsed.kind, KeyKind::Secret);
/// assert_eq!(parsed.mode, EnvironmentMode::Test);
/// assert_eq!(parsed.region, Some(PaymobRegion::Egypt));
/// ```
#[must_use]
pub fn parse_key_prefix(raw: &str) -> Option<ParsedKeyPrefix> {
    let normalized = raw.trim().to_ascii_lowercase();
    KNOWN_PREFIXES
        .iter()
        .find(|(prefix, _, _, _)| normalized.starts_with(prefix))
        .map(|(_, kind, mode, region)| ParsedKeyPrefix {
            kind: *kind,
            mode: *mode,
            region: region.clone(),
        })
}

/// Candidate `.env` file paths searched (in order) when resolving a `$ENV_VARNAME`
/// or `${ENV_VARNAME}` secret reference that is not already set in the process environment.
pub const DEFAULT_DOTENV_PATHS: &[&str] = &[".env", ".env.local"];

/// Extracts the environment variable name if `trimmed` uses `$ENV_VARNAME` or
/// `${ENV_VARNAME}` syntax (`[A-Za-z_][A-Za-z0-9_]*`).
///
/// Returns `Ok(None)` when `trimmed` does not begin with `'$'` (treated as a literal secret).
/// Returns `Err(PaymobError::ValidationError)` when `trimmed` begins with `'$'` but the
/// variable name is empty, unclosed, or contains non-identifier characters.
///
/// # Examples
///
/// ```
/// use some_paymob::core::credentials::parse_env_secret_reference;
///
/// assert_eq!(parse_env_secret_reference("secret_key", "$PAYMOB_SECRET_KEY")?, Some("PAYMOB_SECRET_KEY"));
/// assert_eq!(parse_env_secret_reference("secret_key", "${PAYMOB_SECRET_KEY}")?, Some("PAYMOB_SECRET_KEY"));
/// assert_eq!(parse_env_secret_reference("secret_key", "egy_sk_test_literal")?, None);
/// assert!(parse_env_secret_reference("secret_key", "$").is_err());
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
pub fn parse_env_secret_reference<'a>(
    field: &'static str,
    trimmed: &'a str,
) -> Result<Option<&'a str>, PaymobError> {
    let Some(rest) = trimmed.strip_prefix('$') else {
        return Ok(None);
    };
    let candidate = extract_braced_or_bare_var(field, rest)?;
    if !is_valid_env_var_name(candidate) {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!(
                "{field} environment variable reference '{trimmed}' is invalid; expected $VAR_NAME or ${{VAR_NAME}}"
            ),
        });
    }
    Ok(Some(candidate))
}

fn extract_braced_or_bare_var<'a>(
    field: &'static str,
    rest: &'a str,
) -> Result<&'a str, PaymobError> {
    let Some(after_open) = rest.strip_prefix('{') else {
        return Ok(rest);
    };
    after_open
        .strip_suffix('}')
        .ok_or_else(|| PaymobError::ValidationError {
            field,
            reason: format!("{field} has unclosed '${{' in environment variable reference"),
        })
}

fn is_valid_env_var_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let valid_start = first.is_ascii_alphabetic() || first == '_';
    valid_start && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Parses a single line from a `.env` file and returns the unquoted value if the key matches `var_name`.
#[must_use]
pub fn parse_dotenv_line_value(line: &str, var_name: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let stripped = trimmed.strip_prefix("export ").map_or(trimmed, str::trim);
    let (key, raw_val) = stripped.split_once('=')?;
    if key.trim() != var_name {
        return None;
    }
    Some(unquote_dotenv_value(raw_val.trim()))
}

fn unquote_dotenv_value(raw: &str) -> String {
    if raw.len() >= 2
        && ((raw.starts_with('"') && raw.ends_with('"'))
            || (raw.starts_with('\'') && raw.ends_with('\'')))
    {
        return raw[1..raw.len() - 1].to_owned();
    }
    let without_comment = raw.split(" #").next().unwrap_or(raw).trim_end();
    without_comment.to_owned()
}

/// Searches `.env` content in memory for `var_name`, returning the last matching assignment.
#[must_use]
pub fn parse_dotenv_content(content: &str, var_name: &str) -> Option<String> {
    let mut found = None;
    for line in content.lines() {
        if let Some(val) = parse_dotenv_line_value(line, var_name) {
            found = Some(val);
        }
    }
    found
}

fn lookup_env_or_dotenv_files(var_name: &str) -> Option<String> {
    std::env::var(var_name)
        .ok()
        .filter(|val| !val.trim().is_empty())
        .or_else(|| {
            DEFAULT_DOTENV_PATHS
                .iter()
                .find_map(|p| read_dotenv_var(p, var_name))
        })
}

fn read_dotenv_var(path: &str, var_name: &str) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    parse_dotenv_content(&content, var_name).filter(|val| !val.trim().is_empty())
}

/// Resolves a secret string or `$ENV_VARNAME` / `${ENV_VARNAME}` reference using a custom lookup closure.
///
/// - If `raw` (after trimming) starts with `'$'`, parses the variable name via
///   [`parse_env_secret_reference`], queries `lookup(var_name)`, trims the resolved value,
///   rejects empty values, and wraps the result in [`SecretString`].
/// - Otherwise, trims `raw`, rejects empty values, and wraps it directly in [`SecretString`].
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] if `raw` is empty, if the `$ENV_VARNAME` syntax is
/// malformed, or if the referenced environment variable is not found or empty.
///
/// # Examples
///
/// ```
/// use secrecy::ExposeSecret;
/// use some_paymob::core::credentials::resolve_secret_or_env_with;
///
/// let resolved = resolve_secret_or_env_with("secret_key", "$MY_SK", |k| {
///     (k == "MY_SK").then(|| "egy_sk_test_from_env".to_owned())
/// })?;
/// assert_eq!(resolved.expose_secret(), "egy_sk_test_from_env");
///
/// let literal = resolve_secret_or_env_with("secret_key", "egy_sk_test_literal", |_| None)?;
/// assert_eq!(literal.expose_secret(), "egy_sk_test_literal");
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
pub fn resolve_secret_or_env_with<F>(
    field: &'static str,
    raw: impl Into<String>,
    lookup: F,
) -> Result<SecretString, PaymobError>
where
    F: FnOnce(&str) -> Option<String>,
{
    let value = Zeroizing::new(raw.into());
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(PaymobError::ValidationError {
            field,
            reason: format!("{field} must not be empty"),
        });
    }
    if let Some(var_name) = parse_env_secret_reference(field, trimmed)? {
        let resolved = Zeroizing::new(lookup(var_name).ok_or_else(|| {
            PaymobError::ValidationError {
                field,
                reason: format!(
                    "{field} references environment variable '{var_name}', which was not found in process environment or .env files"
                ),
            }
        })?);
        let resolved_trimmed = resolved.trim();
        if resolved_trimmed.is_empty() {
            return Err(PaymobError::ValidationError {
                field,
                reason: format!(
                    "{field} environment variable '{var_name}' resolved to an empty value"
                ),
            });
        }
        return Ok(SecretString::from(resolved_trimmed.to_owned()));
    }
    Ok(SecretString::from(trimmed.to_owned()))
}

/// Resolves a secret string or `$ENV_VARNAME` / `${ENV_VARNAME}` reference from the process
/// environment (`std::env::var`) with automatic fallback to `.env` and `.env.local` files.
///
/// Built-in reusable secret resolver used across [`SecretKey`], [`PublicKey`], [`ApiKey`],
/// [`HmacSecret`], [`PayoutsCredentials`], [`PartnerCredentials`],
/// [`PaymobWebhookEngine`](crate::webhooks::PaymobWebhookEngine), and resource token builders.
///
/// # Errors
///
/// Returns [`PaymobError::ValidationError`] if `raw` is empty, if the `$ENV_VARNAME` syntax is
/// malformed, or if the referenced variable is missing/empty in both the process environment
/// and `.env` files.
///
/// # Examples
///
/// ```
/// use secrecy::ExposeSecret;
/// use some_paymob::core::credentials::resolve_secret_or_env;
///
/// let direct = resolve_secret_or_env("api_key", "  direct_secret_123  ")?;
/// assert_eq!(direct.expose_secret(), "direct_secret_123");
/// # Ok::<(), some_paymob::core::error::PaymobError>(())
/// ```
pub fn resolve_secret_or_env(
    field: &'static str,
    raw: impl Into<String>,
) -> Result<SecretString, PaymobError> {
    resolve_secret_or_env_with(field, raw, lookup_env_or_dotenv_files)
}

/// Trims surrounding whitespace, resolves any `$ENV_VARNAME` / `${ENV_VARNAME}` reference,
/// validates non-emptiness, and wraps in [`SecretString`].
fn non_empty_secret(
    field: &'static str,
    raw: impl Into<String>,
) -> Result<SecretString, PaymobError> {
    resolve_secret_or_env(field, raw)
}

/// Checks whether a lowercase, trimmed key starts with `tag` (e.g., `"pk_"`)
/// or `<3-ascii-letters>_<tag>` (e.g., `"egy_pk_"`).
fn has_leading_key_tag(normalized: &str, tag: &str, region_tag: &str) -> bool {
    if normalized.starts_with(tag) {
        return true;
    }
    normalized.len() >= 3 + region_tag.len()
        && normalized.as_bytes()[..3]
            .iter()
            .all(u8::is_ascii_alphabetic)
        && normalized[3..].starts_with(region_tag)
}

/// Returns `true` if `raw` starts with a publishable public-key prefix (`pk_*` or `<cc>_pk_*`).
fn is_public_key_prefix(raw: &str) -> bool {
    let normalized = raw.trim().to_ascii_lowercase();
    matches!(parse_key_prefix(&normalized), Some(p) if p.kind == KeyKind::Public)
        || has_leading_key_tag(&normalized, "pk_", "_pk_")
}

/// Returns `true` if `raw` starts with a server secret-key prefix (`sk_*` or `<cc>_sk_*`).
fn is_secret_key_prefix(raw: &str) -> bool {
    let normalized = raw.trim().to_ascii_lowercase();
    matches!(parse_key_prefix(&normalized), Some(p) if p.kind == KeyKind::Secret)
        || has_leading_key_tag(&normalized, "sk_", "_sk_")
}

/// Server-side Paymob secret key (`sk_*` or `<region>_sk_*`) wrapped in [`SecretString`].
///
/// Rejects empty values and any publishable `pk_*` key at construction time.
///
/// # Compile-Time Key Role Separation
///
/// Passing a [`PublicKey`] where a [`SecretKey`] reference is expected fails at compile time:
///
/// ```compile_fail
/// use some_paymob::core::credentials::{PublicKey, SecretKey};
///
/// fn require_secret_key(_key: &SecretKey) {}
///
/// let pk = PublicKey::new("egy_pk_test_123").unwrap();
/// require_secret_key(&pk);
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey {
    inner: SecretString,
    #[zeroize(skip)]
    mode: EnvironmentMode,
    #[zeroize(skip)]
    region: Option<PaymobRegion>,
}

impl SecretKey {
    /// Constructs a validated [`SecretKey`], inferring [`EnvironmentMode`] and optional [`PaymobRegion`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `raw` is empty/whitespace or uses a `pk_*` prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::{EnvironmentMode, SecretKey};
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// let key = SecretKey::new("ksa_sk_live_abc123").expect("valid secret key");
    /// assert_eq!(key.mode(), EnvironmentMode::Live);
    /// assert_eq!(key.region(), Some(&PaymobRegion::SaudiArabia));
    /// assert_eq!(format!("{key:?}"), "[REDACTED]");
    /// ```
    pub fn new(raw: impl Into<String>) -> Result<Self, PaymobError> {
        let inner = non_empty_secret("secret_key", raw)?;
        let raw_str = inner.expose_secret();
        if is_public_key_prefix(raw_str) {
            return Err(PaymobError::ValidationError {
                field: "secret_key",
                reason: "public key (`pk_*`) cannot be used as a secret key".to_owned(),
            });
        }
        let (mode, region) =
            parse_key_prefix(raw_str).map_or((EnvironmentMode::Test, None), |p| (p.mode, p.region));
        Ok(Self {
            inner,
            mode,
            region,
        })
    }

    /// Returns the inferred [`EnvironmentMode`] (`Test` or `Live`).
    #[must_use]
    pub const fn mode(&self) -> EnvironmentMode {
        self.mode
    }

    /// Returns the inferred [`PaymobRegion`], if encoded in the key prefix.
    #[must_use]
    pub const fn region(&self) -> Option<&PaymobRegion> {
        self.region.as_ref()
    }

    /// Exposes the underlying secret string for authorized HTTP header injection.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }
}

/// Client-side publishable Paymob public key (`pk_*` or `<region>_pk_*`) wrapped in [`SecretString`].
///
/// Rejects empty values and any server `sk_*` key at construction time.
#[derive(Clone, ZeroizeOnDrop)]
pub struct PublicKey {
    inner: SecretString,
    #[zeroize(skip)]
    mode: EnvironmentMode,
    #[zeroize(skip)]
    region: Option<PaymobRegion>,
}

impl PublicKey {
    /// Constructs a validated [`PublicKey`], inferring [`EnvironmentMode`] and optional [`PaymobRegion`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `raw` is empty/whitespace or uses an `sk_*` prefix.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::{EnvironmentMode, PublicKey};
    /// use some_paymob::core::region::PaymobRegion;
    ///
    /// let key = PublicKey::new("egy_pk_live_999xxx").expect("valid public key");
    /// assert_eq!(key.mode(), EnvironmentMode::Live);
    /// assert_eq!(key.region(), Some(&PaymobRegion::Egypt));
    /// assert_eq!(format!("{key}"), "[REDACTED]");
    /// ```
    pub fn new(raw: impl Into<String>) -> Result<Self, PaymobError> {
        let inner = non_empty_secret("public_key", raw)?;
        let raw_str = inner.expose_secret();
        if is_secret_key_prefix(raw_str) {
            return Err(PaymobError::ValidationError {
                field: "public_key",
                reason: "secret key (`sk_*`) cannot be used as a public key".to_owned(),
            });
        }
        let (mode, region) =
            parse_key_prefix(raw_str).map_or((EnvironmentMode::Test, None), |p| (p.mode, p.region));
        Ok(Self {
            inner,
            mode,
            region,
        })
    }

    /// Returns the inferred [`EnvironmentMode`] (`Test` or `Live`).
    #[must_use]
    pub const fn mode(&self) -> EnvironmentMode {
        self.mode
    }

    /// Returns the inferred [`PaymobRegion`], if encoded in the key prefix.
    #[must_use]
    pub const fn region(&self) -> Option<&PaymobRegion> {
        self.region.as_ref()
    }

    /// Exposes the underlying public key string for checkout URL / Pixel initialization.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }
}

/// Paymob Accept API key used for Regime 2 JWT exchange (`POST /api/auth/tokens`).
#[derive(Clone, ZeroizeOnDrop)]
pub struct ApiKey {
    inner: SecretString,
}

impl ApiKey {
    /// Constructs a validated [`ApiKey`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `raw` is empty or whitespace-only.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::ApiKey;
    ///
    /// let api_key = ApiKey::new("ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5").unwrap();
    /// assert_eq!(format!("{api_key:?}"), "[REDACTED]");
    /// ```
    pub fn new(raw: impl Into<String>) -> Result<Self, PaymobError> {
        Ok(Self {
            inner: non_empty_secret("api_key", raw)?,
        })
    }

    /// Exposes the underlying API key string for JWT authentication requests.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }
}

/// Paymob HMAC-SHA512 webhook verification secret wrapped in [`SecretString`].
#[derive(Clone, ZeroizeOnDrop)]
pub struct HmacSecret {
    inner: SecretString,
}

impl HmacSecret {
    /// Constructs a validated [`HmacSecret`].
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `raw` is empty or whitespace-only.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::HmacSecret;
    ///
    /// let secret = HmacSecret::new("8E47539E8C8E1432A5C4").unwrap();
    /// assert_eq!(format!("{secret:?}"), "[REDACTED]");
    /// ```
    pub fn new(raw: impl Into<String>) -> Result<Self, PaymobError> {
        Ok(Self {
            inner: non_empty_secret("hmac_secret", raw)?,
        })
    }

    /// Exposes the underlying HMAC secret for constant-time signature verification.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.inner.expose_secret()
    }

    /// Returns a reference to the underlying [`SecretString`].
    #[must_use]
    #[allow(dead_code)]
    pub(crate) const fn as_secret_string(&self) -> &SecretString {
        &self.inner
    }
}

impl From<HmacSecret> for SecretString {
    fn from(secret: HmacSecret) -> Self {
        secret.inner.clone()
    }
}

/// Paymob Payouts OAuth2 credentials (Regime 3: HTTP Basic Auth + password grant).
#[derive(Clone, ZeroizeOnDrop)]
pub struct PayoutsCredentials {
    client_id: SecretString,
    client_secret: SecretString,
    username: SecretString,
    password: SecretString,
}

impl PayoutsCredentials {
    /// Constructs validated [`PayoutsCredentials`] for Paymob Payouts OAuth2 authentication.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if any credential field is empty or whitespace-only.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::PayoutsCredentials;
    ///
    /// let creds = PayoutsCredentials::new("cid_1", "csec_1", "user_1", "pass_1").unwrap();
    /// assert_eq!(format!("{creds:?}"), "[REDACTED]");
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, PaymobError> {
        Ok(Self {
            client_id: non_empty_secret("payouts_client_id", client_id)?,
            client_secret: non_empty_secret("payouts_client_secret", client_secret)?,
            username: non_empty_secret("payouts_username", username)?,
            password: non_empty_secret("payouts_password", password)?,
        })
    }

    /// Exposes the OAuth2 `client_id`.
    #[must_use]
    pub fn client_id(&self) -> &str {
        self.client_id.expose_secret()
    }

    /// Exposes the OAuth2 `client_secret`.
    #[must_use]
    pub fn client_secret(&self) -> &str {
        self.client_secret.expose_secret()
    }

    /// Exposes the Payouts `username`.
    #[must_use]
    pub fn username(&self) -> &str {
        self.username.expose_secret()
    }

    /// Exposes the Payouts `password`.
    #[must_use]
    pub fn password(&self) -> &str {
        self.password.expose_secret()
    }
}

/// Paymob Partner Onboarding delegated credentials (Regime 4).
#[derive(Clone, ZeroizeOnDrop)]
pub struct PartnerCredentials {
    api_key: SecretString,
    bearer_token: Option<SecretString>,
}

impl PartnerCredentials {
    /// Constructs [`PartnerCredentials`] with a partner API key.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if `api_key` is empty or whitespace-only.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::PartnerCredentials;
    ///
    /// let creds = PartnerCredentials::new("partner_api_key_123").unwrap();
    /// assert_eq!(format!("{creds:?}"), "[REDACTED]");
    /// assert!(creds.bearer_token().is_none());
    /// ```
    pub fn new(api_key: impl Into<String>) -> Result<Self, PaymobError> {
        Ok(Self {
            api_key: non_empty_secret("partner_api_key", api_key)?,
            bearer_token: None,
        })
    }

    /// Constructs [`PartnerCredentials`] with both a partner API key and a delegated bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`PaymobError::ValidationError`] if either `api_key` or `bearer_token` is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use some_paymob::core::credentials::PartnerCredentials;
    ///
    /// let creds = PartnerCredentials::with_bearer_token("partner_key", "bearer_tok").unwrap();
    /// assert_eq!(creds.bearer_token(), Some("bearer_tok"));
    /// assert_eq!(format!("{creds}"), "[REDACTED]");
    /// ```
    pub fn with_bearer_token(
        api_key: impl Into<String>,
        bearer_token: impl Into<String>,
    ) -> Result<Self, PaymobError> {
        Ok(Self {
            api_key: non_empty_secret("partner_api_key", api_key)?,
            bearer_token: Some(non_empty_secret("partner_bearer_token", bearer_token)?),
        })
    }

    /// Exposes the partner API key.
    #[must_use]
    pub fn api_key(&self) -> &str {
        self.api_key.expose_secret()
    }

    /// Exposes the optional delegated partner bearer token.
    #[must_use]
    pub fn bearer_token(&self) -> Option<&str> {
        self.bearer_token.as_ref().map(ExposeSecret::expose_secret)
    }
}

impl_redacted_fmt!(
    SecretKey,
    PublicKey,
    ApiKey,
    HmacSecret,
    PayoutsCredentials,
    PartnerCredentials,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_redacted<T: fmt::Debug + fmt::Display>(value: &T) {
        assert_eq!(
            (format!("{value:?}"), format!("{value}")),
            (REDACTED.to_owned(), REDACTED.to_owned())
        );
    }

    #[test]
    fn tc_1_1_2_prefix_parser_infers_region_and_mode() {
        let cases = [
            (
                "egy_sk_test_626xxx",
                KeyKind::Secret,
                EnvironmentMode::Test,
                Some(PaymobRegion::Egypt),
            ),
            (
                "sau_sk_live_abc",
                KeyKind::Secret,
                EnvironmentMode::Live,
                Some(PaymobRegion::SaudiArabia),
            ),
            (
                "are_pk_test_xyz",
                KeyKind::Public,
                EnvironmentMode::Test,
                Some(PaymobRegion::Uae),
            ),
            (
                "omn_sk_test_111",
                KeyKind::Secret,
                EnvironmentMode::Test,
                Some(PaymobRegion::Oman),
            ),
            (
                "pak_pk_live_222",
                KeyKind::Public,
                EnvironmentMode::Live,
                Some(PaymobRegion::Pakistan),
            ),
            (
                "sk_test_legacy",
                KeyKind::Secret,
                EnvironmentMode::Test,
                None,
            ),
            (
                "pk_live_legacy",
                KeyKind::Public,
                EnvironmentMode::Live,
                None,
            ),
        ];

        for (raw, expected_kind, expected_mode, expected_region) in cases {
            let parsed = parse_key_prefix(raw).expect("prefix should parse");
            assert_eq!(
                (parsed.kind, parsed.mode, parsed.region),
                (expected_kind, expected_mode, expected_region)
            );
        }

        assert!(parse_key_prefix("unknown_prefix_123").is_none());
    }

    #[test]
    fn tc_1_1_2_secret_key_accepts_valid_and_trims_whitespace() {
        let sk = SecretKey::new("  egy_sk_test_supersecret  ").expect("valid secret key");
        assert_eq!(
            (sk.mode(), sk.region(), sk.expose_secret()),
            (
                EnvironmentMode::Test,
                Some(&PaymobRegion::Egypt),
                "egy_sk_test_supersecret",
            )
        );
        assert_redacted(&sk);
    }

    #[test]
    fn tc_1_1_2_secret_key_rejects_empty_and_case_or_whitespace_pk_bypass() {
        for bad in [
            "",
            "   \t\n ",
            "  pk_test_123",
            "PK_TEST_123",
            "egy_pk_test_12345",
        ] {
            assert!(matches!(
                SecretKey::new(bad),
                Err(PaymobError::ValidationError {
                    field: "secret_key",
                    ..
                })
            ));
        }
        let valid_with_pk_substr =
            SecretKey::new("sk_live_abcd_pk_efgh").expect("substring _pk_ must not false-reject");
        assert_eq!(valid_with_pk_substr.mode(), EnvironmentMode::Live);
    }

    #[test]
    fn tc_1_1_2_public_key_accepts_valid_and_rejects_sk_bypass() {
        let pk = PublicKey::new("ksa_pk_live_publicval").expect("valid public key");
        assert_eq!(
            (pk.mode(), pk.region(), pk.expose_secret()),
            (
                EnvironmentMode::Live,
                Some(&PaymobRegion::SaudiArabia),
                "ksa_pk_live_publicval",
            )
        );
        assert_redacted(&pk);
    }

    #[test]
    fn tc_1_1_2_public_key_rejects_empty_and_sk_prefixes_without_substring_false_positive() {
        for bad in ["", "  sk_live_999", "SK_LIVE_999", "egy_sk_test_626xxx"] {
            assert!(matches!(
                PublicKey::new(bad),
                Err(PaymobError::ValidationError {
                    field: "public_key",
                    ..
                })
            ));
        }
        let valid_with_sk_substr =
            PublicKey::new("pk_live_abcd_sk_efgh").expect("substring _sk_ must not false-reject");
        assert_eq!(valid_with_sk_substr.mode(), EnvironmentMode::Live);
    }

    #[test]
    fn tc_1_1_2_api_key_and_hmac_secret_validation_and_redaction() {
        let api = ApiKey::new("  api_secret_value  ").expect("valid api key");
        assert_eq!(api.expose_secret(), "api_secret_value");
        assert_redacted(&api);
    }

    #[test]
    fn tc_1_1_2_api_key_and_hmac_secret_reject_empty() {
        assert!(matches!(
            ApiKey::new("  "),
            Err(PaymobError::ValidationError {
                field: "api_key",
                ..
            })
        ));
        assert!(matches!(
            HmacSecret::new(""),
            Err(PaymobError::ValidationError {
                field: "hmac_secret",
                ..
            })
        ));
    }

    #[test]
    fn tc_1_1_2_payouts_credentials_validation_and_redaction() {
        let payouts = PayoutsCredentials::new("cid", "csec", "usr", "pwd").expect("valid payouts");
        assert_eq!(
            (
                payouts.client_id(),
                payouts.client_secret(),
                payouts.username(),
                payouts.password()
            ),
            ("cid", "csec", "usr", "pwd")
        );
        assert_redacted(&payouts);
    }

    #[test]
    fn tc_1_1_2_payouts_credentials_reject_empty_fields() {
        for (cid, csec, usr, pwd, expected_field) in [
            ("", "csec", "usr", "pwd", "payouts_client_id"),
            ("cid", "", "usr", "pwd", "payouts_client_secret"),
            ("cid", "csec", " ", "pwd", "payouts_username"),
            ("cid", "csec", "usr", "", "payouts_password"),
        ] {
            let err = PayoutsCredentials::new(cid, csec, usr, pwd).expect_err("empty field");
            assert!(
                matches!(err, PaymobError::ValidationError { field, .. } if field == expected_field)
            );
        }
    }

    #[test]
    fn tc_1_1_2_partner_credentials_validation_and_redaction() {
        let partner =
            PartnerCredentials::with_bearer_token("p_key", "b_tok").expect("valid partner");
        assert_eq!(
            (partner.api_key(), partner.bearer_token()),
            ("p_key", Some("b_tok"))
        );
        assert_redacted(&partner);
    }

    #[test]
    fn tc_1_1_2_partner_credentials_reject_empty_inputs() {
        assert!(matches!(
            PartnerCredentials::new("   "),
            Err(PaymobError::ValidationError {
                field: "partner_api_key",
                ..
            })
        ));
        assert!(matches!(
            PartnerCredentials::with_bearer_token("p_key", ""),
            Err(PaymobError::ValidationError {
                field: "partner_bearer_token",
                ..
            })
        ));
    }

    #[test]
    fn tc_1_1_2_environment_mode_helpers() {
        assert_eq!(
            (
                EnvironmentMode::Test.is_test(),
                EnvironmentMode::Test.is_live(),
                EnvironmentMode::Test.as_str()
            ),
            (true, false, "test")
        );
        assert_eq!(
            (
                EnvironmentMode::Live.is_live(),
                EnvironmentMode::Live.is_test(),
                format!("{}", EnvironmentMode::Live)
            ),
            (true, false, "live".to_string())
        );
    }

    #[test]
    fn tc_env_secret_resolver_resolves_dollar_and_braced_syntax_and_dotenv() {
        let resolved = resolve_secret_or_env_with("secret_key", "$PAYMOB_TEST_SK", |k| {
            (k == "PAYMOB_TEST_SK").then(|| "  egy_sk_test_env_resolved_999  ".to_owned())
        })
        .expect("should resolve $VAR");
        assert_eq!(resolved.expose_secret(), "egy_sk_test_env_resolved_999");

        let braced = resolve_secret_or_env_with("hmac_secret", "${PAYMOB_TEST_HMAC}", |k| {
            (k == "PAYMOB_TEST_HMAC").then(|| "hmac_from_braced_env".to_owned())
        })
        .expect("should resolve ${VAR}");
        assert_eq!(braced.expose_secret(), "hmac_from_braced_env");

        let dotenv_sample = "
            # comment line
            OTHER_KEY=123
            export PAYMOB_DOTENV_SK=\"ksa_sk_live_from_dotenv\"
            SINGLE_QUOTED='omn_pk_test_single'
            INLINE_COMMENT=pak_sk_test_inline # trailing comment
        ";
        assert_eq!(
            parse_dotenv_content(dotenv_sample, "PAYMOB_DOTENV_SK").as_deref(),
            Some("ksa_sk_live_from_dotenv")
        );
        assert_eq!(
            parse_dotenv_content(dotenv_sample, "SINGLE_QUOTED").as_deref(),
            Some("omn_pk_test_single")
        );
        assert_eq!(
            parse_dotenv_content(dotenv_sample, "INLINE_COMMENT").as_deref(),
            Some("pak_sk_test_inline")
        );
        assert!(parse_dotenv_content(dotenv_sample, "MISSING_KEY").is_none());
    }

    #[test]
    fn tc_env_secret_resolver_rejects_malformed_missing_or_empty_env_vars() {
        for bad_syntax in [
            "$",
            "${}",
            "${UNCLOSED",
            "$123_INVALID",
            "$BAD-NAME",
            "$BAD SPACE",
        ] {
            let err = resolve_secret_or_env_with("secret_key", bad_syntax, |_| {
                Some("egy_sk_test_123".to_owned())
            })
            .expect_err("malformed $VAR syntax should fail");
            assert!(matches!(
                err,
                PaymobError::ValidationError {
                    field: "secret_key",
                    ..
                }
            ));
        }

        let missing_err =
            resolve_secret_or_env_with("api_key", "$DEFINITELY_MISSING_PAYMOB_VAR_XYZ", |_| None)
                .expect_err("missing env var must fail");
        assert!(matches!(
            missing_err,
            PaymobError::ValidationError {
                field: "api_key",
                ..
            }
        ));

        let empty_err =
            resolve_secret_or_env_with("hmac_secret", "$EMPTY_VAR", |_| Some("   ".to_owned()))
                .expect_err("empty resolved env var must fail");
        assert!(matches!(
            empty_err,
            PaymobError::ValidationError {
                field: "hmac_secret",
                ..
            }
        ));
    }
}
