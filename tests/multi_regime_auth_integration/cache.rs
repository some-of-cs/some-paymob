#![forbid(unsafe_code)]
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use secrecy::ExposeSecret;

use some_paymob::core::auth::cache::{
    CachedToken, DEFAULT_TOKEN_TTL_SECS, PROACTIVE_REFRESH_MARGIN_SECS, TokenCache,
};

struct CacheHarness {
    cache: Arc<TokenCache>,
    refresh_calls: Arc<AtomicUsize>,
}

impl CacheHarness {
    fn new() -> Self {
        Self {
            cache: Arc::new(TokenCache::new()),
            refresh_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn spawn_concurrent_reads(&self, count: usize, token: &'static str) -> Vec<String> {
        let mut handles = Vec::with_capacity(count);
        for _ in 0..count {
            let cache_ref = Arc::clone(&self.cache);
            let calls_ref = Arc::clone(&self.refresh_calls);
            handles.push(tokio::spawn(async move {
                let tok = cache_ref
                    .get_or_refresh(|| async move {
                        calls_ref.fetch_add(1, Ordering::SeqCst);
                        tokio::time::sleep(Duration::from_millis(15)).await;
                        Ok::<_, &str>(CachedToken::with_default_ttl(token, None))
                    })
                    .await
                    .expect("single-flight refresh");
                tok.access_token.expose_secret().to_owned()
            }));
        }

        let mut results = Vec::with_capacity(count);
        for handle in handles {
            results.push(handle.await.expect("task join"));
        }
        results
    }
}

#[test]
fn tc_1_2_2_cache_timing_constants() {
    assert_eq!(DEFAULT_TOKEN_TTL_SECS, 3600);
    assert_eq!(PROACTIVE_REFRESH_MARGIN_SECS, 60);
}

#[tokio::test]
async fn tc_1_2_2_token_cache_single_flight_50_tasks() {
    let harness = CacheHarness::new();
    let results = harness.spawn_concurrent_reads(50, "sf-jwt-1").await;

    assert!(results.iter().all(|tok| tok == "sf-jwt-1"));
    assert_eq!(harness.refresh_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn tc_1_2_2_token_cache_freshness_and_eviction() {
    let cache = TokenCache::new();
    cache.store(CachedToken::with_default_ttl("sf-jwt-1", None));

    let fast = cache.get_if_fresh().expect("cached token is fresh");
    assert_eq!(fast.access_token.expose_secret(), "sf-jwt-1");

    cache.evict();
    assert!(cache.get_if_fresh().is_none() && cache.peek().is_none());

    let after_evict = cache
        .get_or_refresh(|| async { Ok::<_, &str>(CachedToken::with_default_ttl("sf-jwt-2", None)) })
        .await
        .expect("post-eviction refresh");
    assert_eq!(after_evict.access_token.expose_secret(), "sf-jwt-2");
}

#[tokio::test]
async fn tc_1_2_2_token_cache_proactive_margin_and_error_recovery() {
    let cache = TokenCache::new();
    let soon = Instant::now() + Duration::from_secs(30);
    cache.store(CachedToken::with_expires_at("expiring-soon", None, soon));
    assert!(cache.get_if_fresh().is_none());

    let err = cache
        .get_or_refresh(|| async { Err::<CachedToken, &str>("upstream 503") })
        .await
        .expect_err("refresh failure propagates");
    assert_eq!(err, "upstream 503");

    let recovered = cache
        .get_or_refresh(|| async {
            Ok::<_, &str>(CachedToken::with_default_ttl("recovered-jwt", None))
        })
        .await
        .expect("cache is not poisoned after failed refresh");
    assert_eq!(recovered.access_token.expose_secret(), "recovered-jwt");
}
