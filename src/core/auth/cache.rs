#![forbid(unsafe_code)]
//! Lock-free single-flight token cache for 60-minute Paymob JWT and OAuth2 tokens.
//!
//! Reads execute lock-free against [`arc_swap::ArcSwapOption<CachedToken>`], while
//! refreshes are serialized through a single-flight [`tokio::sync::Mutex<()>`] with
//! double-checked locking to prevent thundering-herd token storms.

use arc_swap::ArcSwapOption;
use secrecy::{ExposeSecret, SecretString};
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use zeroize::ZeroizeOnDrop;

/// Default Paymob token time-to-live in seconds (60 minutes).
pub const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;

/// Proactive refresh margin in seconds before token expiration (60 seconds).
pub const PROACTIVE_REFRESH_MARGIN_SECS: u64 = 60;

const MAX_FALLBACK_TTL: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// Cached authentication token with automatic memory scrubbing on drop.
///
/// Both `access_token` and `refresh_token` are wrapped in [`SecretString`] and
/// zeroized when dropped via [`ZeroizeOnDrop`]. [`fmt::Debug`] always redacts
/// secret fields as `"[REDACTED]"`.
///
/// # Examples
///
/// ```
/// use secrecy::ExposeSecret;
/// use some_paymob::core::auth::cache::{CachedToken, DEFAULT_TOKEN_TTL_SECS};
///
/// let token = CachedToken::with_default_ttl("jwt-token", None);
/// assert_eq!(token.access_token.expose_secret(), "jwt-token");
/// assert!(!token.is_expired());
/// assert_eq!(DEFAULT_TOKEN_TTL_SECS, 3600);
/// ```
#[derive(Clone, ZeroizeOnDrop)]
pub struct CachedToken {
    /// Short-lived bearer or JSON-body access token.
    pub access_token: SecretString,
    /// Optional OAuth2 refresh token for renewal grants.
    pub refresh_token: Option<SecretString>,
    /// Monotonic expiration timestamp (excluded from zeroization).
    #[zeroize(skip)]
    pub expires_at: Instant,
}

impl CachedToken {
    /// Creates a [`CachedToken`] expiring after `ttl` from `Instant::now()`.
    #[must_use]
    pub fn new(
        access_token: impl Into<SecretString>,
        refresh_token: Option<SecretString>,
        ttl: Duration,
    ) -> Self {
        let now = Instant::now();
        let expires_at = now
            .checked_add(ttl)
            .or_else(|| now.checked_add(MAX_FALLBACK_TTL))
            .unwrap_or(now);
        Self {
            access_token: access_token.into(),
            refresh_token,
            expires_at,
        }
    }

    /// Creates a [`CachedToken`] using [`DEFAULT_TOKEN_TTL_SECS`] (3600s).
    #[must_use]
    pub fn with_default_ttl(
        access_token: impl Into<SecretString>,
        refresh_token: Option<SecretString>,
    ) -> Self {
        Self::new(
            access_token,
            refresh_token,
            Duration::from_secs(DEFAULT_TOKEN_TTL_SECS),
        )
    }

    /// Creates a [`CachedToken`] with an explicit monotonic `expires_at` instant.
    #[must_use]
    pub fn with_expires_at(
        access_token: impl Into<SecretString>,
        refresh_token: Option<SecretString>,
        expires_at: Instant,
    ) -> Self {
        Self {
            access_token: access_token.into(),
            refresh_token,
            expires_at,
        }
    }

    /// Returns `true` if `Instant::now()` has reached or passed `expires_at`.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    /// Returns `true` if remaining lifetime at `now` strictly exceeds `margin`.
    #[must_use]
    pub fn is_fresh_at(&self, now: Instant, margin: Duration) -> bool {
        self.expires_at.saturating_duration_since(now) > margin
    }

    /// Returns `true` if the token is expired or within `margin` of expiring.
    #[must_use]
    pub fn needs_refresh(&self, margin: Duration) -> bool {
        !self.is_fresh_at(Instant::now(), margin)
    }
}

impl fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CachedToken")
            .field("access_token", &"[REDACTED]")
            .field(
                "refresh_token",
                &self.refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Lock-free, single-flight cache for [`CachedToken`] instances.
///
/// Concurrent callers read cached tokens lock-free via [`ArcSwapOption`]. When
/// a token is missing, evicted, or within the proactive refresh margin, callers
/// coordinate through a [`tokio::sync::Mutex<()>`] using double-checked locking
/// so only one refresh future executes at a time.
///
/// # Examples
///
/// ```
/// use secrecy::ExposeSecret;
/// use some_paymob::core::auth::cache::{CachedToken, TokenCache};
///
/// let rt = tokio::runtime::Builder::new_current_thread()
///     .enable_time()
///     .build()
///     .unwrap();
///
/// rt.block_on(async {
///     let cache = TokenCache::new();
///     let token = cache
///         .get_or_refresh(|| async {
///             Ok::<_, std::convert::Infallible>(CachedToken::with_default_ttl("tok-1", None))
///         })
///         .await
///         .unwrap();
///     assert_eq!(token.access_token.expose_secret(), "tok-1");
/// });
/// ```
pub struct TokenCache {
    inner: ArcSwapOption<CachedToken>,
    refresh_lock: Mutex<()>,
    refresh_margin: Duration,
}

impl TokenCache {
    /// Creates an empty [`TokenCache`] with [`PROACTIVE_REFRESH_MARGIN_SECS`] (60s).
    #[must_use]
    pub fn new() -> Self {
        Self::with_refresh_margin(Duration::from_secs(PROACTIVE_REFRESH_MARGIN_SECS))
    }

    /// Creates an empty [`TokenCache`] with a custom proactive `refresh_margin`.
    #[must_use]
    pub fn with_refresh_margin(refresh_margin: Duration) -> Self {
        Self {
            inner: ArcSwapOption::empty(),
            refresh_lock: Mutex::new(()),
            refresh_margin,
        }
    }

    /// Performs a lock-free read and returns the token only if it is fresh.
    #[must_use]
    pub fn get_if_fresh(&self) -> Option<Arc<CachedToken>> {
        let now = Instant::now();
        self.inner
            .load_full()
            .filter(|token| token.is_fresh_at(now, self.refresh_margin))
    }

    /// Performs a lock-free read of the current cached token regardless of freshness.
    #[must_use]
    pub fn peek(&self) -> Option<Arc<CachedToken>> {
        self.inner.load_full()
    }

    /// Stores a new [`CachedToken`] atomically and returns a shared [`Arc`] handle.
    pub fn store(&self, token: CachedToken) -> Arc<CachedToken> {
        let arc = Arc::new(token);
        self.inner.store(Some(Arc::clone(&arc)));
        arc
    }

    /// Evicts the cached token (e.g., after an HTTP 401 invalidation response).
    pub fn evict(&self) {
        self.inner.store(None);
    }

    /// Evicts the cached token only if it still matches `stale_access_token`.
    ///
    /// Acquires `refresh_lock` before checking and clearing the cache so concurrent
    /// `401` retries do not evict a fresh token already stored by another task.
    pub async fn evict_if_matches(&self, stale_access_token: &SecretString) -> bool {
        let _guard = self.refresh_lock.lock().await;
        let Some(current) = self.inner.load_full() else {
            return false;
        };
        if current.access_token.expose_secret() == stale_access_token.expose_secret() {
            self.inner.store(None);
            return true;
        }
        false
    }

    /// Returns a fresh cached token lock-free or executes a single-flight refresh.
    ///
    /// Uses double-checked locking: if another task completes the refresh while
    /// waiting on `refresh_lock`, `refresh_fn` is not called again.
    pub async fn get_or_refresh<F, Fut, E>(&self, refresh_fn: F) -> Result<Arc<CachedToken>, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<CachedToken, E>>,
    {
        if let Some(token) = self.get_if_fresh() {
            return Ok(token);
        }

        let _guard = self.refresh_lock.lock().await;
        if let Some(token) = self.get_if_fresh() {
            return Ok(token);
        }

        let fresh = refresh_fn().await?;
        Ok(self.store(fresh))
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TokenCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenCache")
            .field("has_token", &self.inner.load().is_some())
            .field("refresh_margin", &self.refresh_margin)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn cached_token_default_ttl_and_constants() {
        assert_eq!(DEFAULT_TOKEN_TTL_SECS, 3600);
        assert_eq!(PROACTIVE_REFRESH_MARGIN_SECS, 60);
        assert_zeroize_on_drop::<CachedToken>();

        let token = CachedToken::with_default_ttl("jwt-abc", Some(SecretString::from("ref-xyz")));
        assert_eq!(token.access_token.expose_secret(), "jwt-abc");
        assert!(!token.is_expired());
        assert!(!token.needs_refresh(Duration::from_secs(PROACTIVE_REFRESH_MARGIN_SECS)));
    }

    #[test]
    fn cached_token_debug_redacts_secrets() {
        let with_refresh = CachedToken::with_default_ttl(
            "super-secret-jwt-value",
            Some(SecretString::from("super-secret-refresh-value")),
        );
        let debug_with = format!("{with_refresh:?}");
        assert!(!debug_with.contains("super-secret-jwt-value"));
        assert!(!debug_with.contains("super-secret-refresh-value"));
        assert!(debug_with.contains("[REDACTED]"));

        let without_refresh = CachedToken::with_default_ttl("another-secret-jwt", None);
        let debug_without = format!("{without_refresh:?}");
        assert!(!debug_without.contains("another-secret-jwt"));
        assert!(debug_without.contains("[REDACTED]"));
    }

    #[test]
    fn cached_token_freshness_boundary_and_zero_ttl() {
        let now = Instant::now();
        let margin = Duration::from_secs(PROACTIVE_REFRESH_MARGIN_SECS);

        let exact_margin = CachedToken::with_expires_at("tok", None, now + margin);
        assert!(!exact_margin.is_fresh_at(now, margin));

        let above_margin =
            CachedToken::with_expires_at("tok", None, now + margin + Duration::from_secs(1));
        assert!(above_margin.is_fresh_at(now, margin));

        let expired = CachedToken::with_expires_at(
            "tok",
            None,
            now.checked_sub(Duration::from_secs(5)).unwrap_or(now),
        );
        assert!(!expired.is_fresh_at(now, margin));
        assert!(expired.is_expired());

        let zero_ttl = CachedToken::new("tok", None, Duration::ZERO);
        assert!(zero_ttl.needs_refresh(margin));
    }

    #[test]
    fn token_cache_debug_does_not_leak_secrets() {
        let cache = TokenCache::new();
        cache.store(CachedToken::with_default_ttl("secret-cache-tok", None));

        let formatted = format!("{cache:?}");
        assert!(!formatted.contains("secret-cache-tok"));
        assert!(formatted.contains("has_token: true"));
    }

    #[tokio::test]
    async fn token_cache_lockfree_fast_path_hit() {
        let cache = TokenCache::new();
        cache.store(CachedToken::with_default_ttl("cached-jwt", None));

        let calls = AtomicUsize::new(0);
        let tok = cache
            .get_or_refresh(|| async {
                calls.fetch_add(1, Ordering::SeqCst);
                Err::<CachedToken, &str>("should not be called")
            })
            .await
            .expect("fast-path should return cached token");

        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(tok.access_token.expose_secret(), "cached-jwt");
    }

    #[tokio::test]
    async fn token_cache_proactive_refresh_within_margin() {
        let cache = TokenCache::new();
        let soon = Instant::now() + Duration::from_secs(30);
        cache.store(CachedToken::with_expires_at("expiring-jwt", None, soon));

        assert!(cache.get_if_fresh().is_none());

        let refreshed = cache
            .get_or_refresh(|| async {
                Ok::<_, &str>(CachedToken::with_default_ttl("fresh-jwt", None))
            })
            .await
            .expect("proactive refresh should succeed");

        assert_eq!(refreshed.access_token.expose_secret(), "fresh-jwt");
    }

    #[tokio::test]
    async fn token_cache_evict_forces_refresh_on_401() {
        let cache = TokenCache::new();
        cache.store(CachedToken::with_default_ttl("stale-401-jwt", None));
        assert!(cache.get_if_fresh().is_some());

        cache.evict();
        assert!(cache.get_if_fresh().is_none());
        assert!(cache.peek().is_none());

        let tok = cache
            .get_or_refresh(|| async {
                Ok::<_, &str>(CachedToken::with_default_ttl("recovered-jwt", None))
            })
            .await
            .expect("post-eviction refresh should succeed");

        assert_eq!(tok.access_token.expose_secret(), "recovered-jwt");
    }

    #[tokio::test]
    async fn token_cache_refresh_error_propagates_without_poisoning() {
        let cache = TokenCache::new();

        let err = cache
            .get_or_refresh(|| async { Err::<CachedToken, &str>("upstream 500") })
            .await
            .expect_err("error should propagate");
        assert_eq!(err, "upstream 500");
        assert!(cache.peek().is_none());

        let tok = cache
            .get_or_refresh(|| async {
                Ok::<_, &str>(CachedToken::with_default_ttl("ok-after-err", None))
            })
            .await
            .expect("subsequent refresh should succeed");
        assert_eq!(tok.access_token.expose_secret(), "ok-after-err");
    }

    #[tokio::test]
    async fn token_cache_50_concurrent_tasks_single_flight() {
        let cache = Arc::new(TokenCache::new());
        let refresh_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::with_capacity(50);

        for _ in 0..50 {
            let cache_ref = Arc::clone(&cache);
            let count_ref = Arc::clone(&refresh_count);
            handles.push(tokio::spawn(async move {
                cache_ref
                    .get_or_refresh(|| async move {
                        count_ref.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        Ok::<_, &str>(CachedToken::with_default_ttl("single-flight-jwt", None))
                    })
                    .await
            }));
        }

        for handle in handles {
            let tok = handle
                .await
                .expect("task should not panic")
                .expect("single-flight refresh should succeed");
            assert_eq!(tok.access_token.expose_secret(), "single-flight-jwt");
        }

        assert_eq!(refresh_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cached_token_duration_max_does_not_expire_immediately() {
        let now = Instant::now();
        let max_ttl = CachedToken::new("max-tok", None, Duration::MAX);
        assert!(!max_ttl.is_expired());
        assert!(max_ttl.is_fresh_at(now, Duration::from_secs(PROACTIVE_REFRESH_MARGIN_SECS)));
    }

    #[test]
    fn cached_token_zero_ttl_is_expired() {
        let zero_ttl = CachedToken::new("zero-tok", None, Duration::ZERO);
        assert!(zero_ttl.is_expired());
    }

    #[test]
    fn token_cache_with_zero_refresh_margin() {
        let cache = TokenCache::with_refresh_margin(Duration::ZERO);
        cache.store(CachedToken::new("short-tok", None, Duration::from_secs(5)));
        assert!(cache.get_if_fresh().is_some());
    }

    #[tokio::test]
    async fn token_cache_evict_if_matches_prevents_stale_eviction() {
        let cache = TokenCache::new();
        cache.store(CachedToken::with_default_ttl("fresh-tok", None));

        let evicted_mismatch = cache.evict_if_matches(&SecretString::from("stale-tok")).await;
        assert!(!evicted_mismatch);
        assert!(cache.peek().is_some());
    }

    #[tokio::test]
    async fn token_cache_evict_if_matches_clears_matching_token() {
        let cache = TokenCache::new();
        cache.store(CachedToken::with_default_ttl("stale-tok", None));

        let evicted_match = cache.evict_if_matches(&SecretString::from("stale-tok")).await;
        assert!(evicted_match);
        assert!(cache.peek().is_none());
    }
}
