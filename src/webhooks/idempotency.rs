//! Atomic webhook idempotency guard and thread-safe in-memory deduplicator.
//!
//! Provides [`IdempotentWebhookGuard`] for extracting deterministic
//! `(idempotency_key, correlation_id)` pairs across all Paymob webhook protocols
//! (Protocols A–E), [`WebhookIdempotencyStore`] for pluggable deduplication
//! backends, and [`InMemoryWebhookDeduplicator`] (aliased as
//! [`InMemoryWebhookIdempotencyStore`]) with bounded FIFO capacity, optional TTL
//! expiration, and [`InMemoryWebhookDeduplicator::process_with_rollback`].

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::verifier::{WebhookError, WebhookResult};

/// Default maximum number of `(idempotency_key, correlation_id)` entries retained
/// by [`InMemoryWebhookDeduplicator`] before FIFO eviction.
pub const DEFAULT_DEDUPLICATOR_CAPACITY: usize = 10_000;

/// Type alias for [`InMemoryWebhookDeduplicator`] following store naming conventions.
pub type InMemoryWebhookIdempotencyStore = InMemoryWebhookDeduplicator;

type DedupKey = (String, String);

/// Extracts a deterministic `(idempotency_key, correlation_id)` tuple from a
/// verified Paymob webhook payload for atomic deduplication.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::idempotency::{
///     IdempotentWebhookGuard, InMemoryWebhookDeduplicator,
/// };
///
/// struct SampleWebhook {
///     event_id: u64,
///     order_id: u64,
/// }
///
/// impl IdempotentWebhookGuard for SampleWebhook {
///     fn idempotency_tuple(&self) -> (String, String) {
///         (self.event_id.to_string(), self.order_id.to_string())
///     }
/// }
///
/// let deduplicator = InMemoryWebhookDeduplicator::new();
/// let event = SampleWebhook {
///     event_id: 192_036_465,
///     order_id: 217_503_754,
/// };
///
/// assert!(deduplicator.check_and_mark(&event));
/// assert!(!deduplicator.check_and_mark(&event));
/// assert_eq!(deduplicator.len(), 1);
/// ```
pub trait IdempotentWebhookGuard {
    /// Returns `(idempotency_key, correlation_id)` uniquely identifying this webhook delivery.
    fn idempotency_tuple(&self) -> (String, String);
}

impl IdempotentWebhookGuard for super::tx_models::TransactionProcessedEvent {
    fn idempotency_tuple(&self) -> (String, String) {
        (self.obj.id.to_string(), self.obj.order.id.to_string())
    }
}

impl IdempotentWebhookGuard for super::protocol_b_get::TransactionRedirectParams {
    fn idempotency_tuple(&self) -> (String, String) {
        (self.id.clone(), self.order_id.clone())
    }
}

impl IdempotentWebhookGuard for super::protocol_d_subscription::SubscriptionWebhookEvent {
    fn idempotency_tuple(&self) -> (String, String) {
        (
            self.paymob_request_id.clone(),
            self.subscription_data.id.to_string(),
        )
    }
}

impl IdempotentWebhookGuard for super::protocol_c_token::CardTokenWebhookEvent {
    fn idempotency_tuple(&self) -> (String, String) {
        (self.obj.id.to_string(), self.obj.order_id.clone())
    }
}

impl IdempotentWebhookGuard for super::protocol_e_payouts::DisbursementCallback {
    fn idempotency_tuple(&self) -> (String, String) {
        (self.transaction_id.clone(), self.transaction_id.clone())
    }
}

impl IdempotentWebhookGuard for super::protocol_e_payouts::TopupCallback {
    fn idempotency_tuple(&self) -> (String, String) {
        (self.topup_id.clone(), self.topup_id.clone())
    }
}

impl IdempotentWebhookGuard for super::dispatcher::WebhookEvent {
    fn idempotency_tuple(&self) -> (String, String) {
        match self {
            Self::TransactionProcessed(evt) => evt.idempotency_tuple(),
            Self::TransactionResponseRedirect(params) => params.idempotency_tuple(),
            Self::CardTokenSaved(evt) => evt.idempotency_tuple(),
            Self::SubscriptionLifecycle(evt) => evt.idempotency_tuple(),
            Self::PayoutDisbursement(evt) => evt.idempotency_tuple(),
            Self::PayoutTopup(evt) => evt.idempotency_tuple(),
        }
    }
}

/// Pluggable storage contract for atomic webhook delivery deduplication.
pub trait WebhookIdempotencyStore {
    /// Atomically checks whether `guard` has been seen and marks it as seen if new.
    fn check_and_mark(&self, guard: &impl IdempotentWebhookGuard) -> bool;

    /// Returns `true` if `guard` is currently recorded in the store without modifying state.
    fn contains(&self, guard: &impl IdempotentWebhookGuard) -> bool;

    /// Claims `guard` if unseen or returns [`WebhookError::DuplicateWebhookDelivery`].
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::DuplicateWebhookDelivery`] if the delivery tuple is already claimed.
    fn claim_or_reject(&self, guard: &impl IdempotentWebhookGuard) -> WebhookResult<()>;

    /// Removes `guard`'s idempotency tuple from the store (for example, on downstream handler failure).
    fn release(&self, guard: &impl IdempotentWebhookGuard) -> bool;

    /// Removes an explicit `(idempotency_key, correlation_id)` pair from the store.
    fn release_key(&self, idempotency_key: &str, correlation_id: &str) -> bool;

    /// Removes all recorded idempotency tuples from the store.
    fn clear(&self);

    /// Returns the number of active idempotency tuples currently recorded.
    fn len(&self) -> usize;

    /// Returns `true` if no active idempotency tuples are currently recorded.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

struct DeduplicatorState {
    entries: HashMap<DedupKey, Instant>,
    order: VecDeque<(DedupKey, Instant)>,
    max_capacity: usize,
    ttl: Option<Duration>,
}

impl DeduplicatorState {
    fn new(max_capacity: usize, ttl: Option<Duration>) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            max_capacity: max_capacity.max(1),
            ttl,
        }
    }

    fn is_front_expired(&self, now: Instant, ttl_dur: Duration) -> bool {
        self.order
            .front()
            .is_some_and(|(_, ts)| now.saturating_duration_since(*ts) >= ttl_dur)
    }

    fn pop_front_entry(&mut self) {
        if let Some((old_key, old_ts)) = self.order.pop_front() {
            if self.entries.get(&old_key) == Some(&old_ts) {
                self.entries.remove(&old_key);
            }
        }
    }

    fn evict_expired(&mut self, now: Instant) {
        let Some(ttl_dur) = self.ttl else { return };
        while self.is_front_expired(now, ttl_dur) {
            self.pop_front_entry();
        }
    }

    fn evict_oldest_while_full(&mut self) {
        while self.entries.len() >= self.max_capacity && !self.order.is_empty() {
            self.pop_front_entry();
        }
    }

    fn check_and_insert(&mut self, tuple: DedupKey) -> bool {
        let now = Instant::now();
        self.evict_expired(now);
        if self.entries.contains_key(&tuple) {
            return false;
        }
        self.evict_oldest_while_full();
        self.entries.insert(tuple.clone(), now);
        self.order.push_back((tuple, now));
        true
    }
}

/// Thread-safe in-memory webhook deduplicator with bounded FIFO capacity and optional TTL.
///
/// Intended for single-instance services, tests, and local replay protection.
/// Multi-instance production deployments should persist the `(idempotency_key, correlation_id)`
/// tuple from [`IdempotentWebhookGuard::idempotency_tuple`] in a shared transactional store
/// with a unique constraint.
///
/// # Examples
///
/// ```
/// use some_paymob::webhooks::idempotency::{
///     IdempotentWebhookGuard, InMemoryWebhookDeduplicator,
/// };
///
/// struct MockDelivery(&'static str, &'static str);
///
/// impl IdempotentWebhookGuard for MockDelivery {
///     fn idempotency_tuple(&self) -> (String, String) {
///         (self.0.to_owned(), self.1.to_owned())
///     }
/// }
///
/// let guard = InMemoryWebhookDeduplicator::new();
/// assert!(guard.is_empty());
/// assert!(guard.check_and_mark(&MockDelivery("tx_1", "ord_1")));
/// assert!(!guard.check_and_mark(&MockDelivery("tx_1", "ord_1")));
/// assert!(guard.check_and_mark(&MockDelivery("tx_2", "ord_1")));
/// assert_eq!(guard.len(), 2);
/// ```
pub struct InMemoryWebhookDeduplicator {
    state: Mutex<DeduplicatorState>,
    max_capacity: usize,
    ttl: Option<Duration>,
}

impl InMemoryWebhookDeduplicator {
    /// Creates an empty [`InMemoryWebhookDeduplicator`] with [`DEFAULT_DEDUPLICATOR_CAPACITY`]
    /// (`10,000` entries) and no TTL expiration.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(DeduplicatorState::new(DEFAULT_DEDUPLICATOR_CAPACITY, None)),
            max_capacity: DEFAULT_DEDUPLICATOR_CAPACITY,
            ttl: None,
        }
    }

    /// Creates an [`InMemoryWebhookDeduplicator`] with a bounded FIFO `max_capacity`
    /// (clamped to at least `1`).
    #[must_use]
    pub fn with_max_capacity(max_capacity: usize) -> Self {
        let clamped = max_capacity.max(1);
        Self {
            state: Mutex::new(DeduplicatorState::new(clamped, None)),
            max_capacity: clamped,
            ttl: None,
        }
    }

    /// Creates an [`InMemoryWebhookDeduplicator`] with [`DEFAULT_DEDUPLICATOR_CAPACITY`]
    /// and an entry time-to-live `ttl`.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            state: Mutex::new(DeduplicatorState::new(
                DEFAULT_DEDUPLICATOR_CAPACITY,
                Some(ttl),
            )),
            max_capacity: DEFAULT_DEDUPLICATOR_CAPACITY,
            ttl: Some(ttl),
        }
    }

    /// Creates an [`InMemoryWebhookDeduplicator`] with both a bounded FIFO `max_capacity`
    /// (clamped to at least `1`) and an entry time-to-live `ttl`.
    #[must_use]
    pub fn with_capacity_and_ttl(max_capacity: usize, ttl: Duration) -> Self {
        let clamped = max_capacity.max(1);
        Self {
            state: Mutex::new(DeduplicatorState::new(clamped, Some(ttl))),
            max_capacity: clamped,
            ttl: Some(ttl),
        }
    }

    /// Returns the configured maximum entry capacity before FIFO eviction.
    #[must_use]
    pub const fn max_capacity(&self) -> usize {
        self.max_capacity
    }

    /// Returns the configured entry time-to-live (`ttl`), if any.
    #[must_use]
    pub const fn ttl(&self) -> Option<Duration> {
        self.ttl
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, DeduplicatorState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Checks whether `guard`'s idempotency tuple has not been seen before and marks it as seen.
    ///
    /// Returns `true` if the event is newly seen (and has now been recorded), or `false` if it
    /// is a duplicate delivery.
    pub fn check_and_mark(&self, guard: &impl IdempotentWebhookGuard) -> bool {
        let tuple = guard.idempotency_tuple();
        let mut state = self.lock_state();
        state.check_and_insert(tuple)
    }

    /// Returns `true` if `guard`'s idempotency tuple is currently active in the deduplicator.
    #[must_use]
    pub fn contains(&self, guard: &impl IdempotentWebhookGuard) -> bool {
        let tuple = guard.idempotency_tuple();
        let now = Instant::now();
        let mut state = self.lock_state();
        state.evict_expired(now);
        state.entries.contains_key(&tuple)
    }

    /// Claims `guard`'s idempotency tuple if unseen, or returns
    /// [`WebhookError::DuplicateWebhookDelivery`] (`409 Conflict`) if already recorded.
    ///
    /// # Errors
    ///
    /// Returns [`WebhookError::DuplicateWebhookDelivery`] when the tuple has already been claimed.
    pub fn claim_or_reject(&self, guard: &impl IdempotentWebhookGuard) -> WebhookResult<()> {
        if self.check_and_mark(guard) {
            return Ok(());
        }
        let (idempotency_key, correlation_id) = guard.idempotency_tuple();
        Err(WebhookError::DuplicateWebhookDelivery {
            idempotency_key,
            correlation_id,
        })
    }

    /// Removes `guard`'s idempotency tuple from the store so a subsequent retry can be processed.
    ///
    /// Returns `true` if the tuple was present and removed.
    pub fn release(&self, guard: &impl IdempotentWebhookGuard) -> bool {
        let (key, corr) = guard.idempotency_tuple();
        self.release_key(&key, &corr)
    }

    /// Removes an explicit `(idempotency_key, correlation_id)` tuple from the store.
    ///
    /// Returns `true` if the tuple was present and removed.
    pub fn release_key(&self, idempotency_key: &str, correlation_id: &str) -> bool {
        let tuple = (idempotency_key.to_owned(), correlation_id.to_owned());
        let mut state = self.lock_state();
        state.entries.remove(&tuple).is_some()
    }

    /// Clears all recorded idempotency tuples from the deduplicator.
    pub fn clear(&self) {
        let mut state = self.lock_state();
        state.entries.clear();
        state.order.clear();
    }

    /// Executes `handler` at most once per unique `guard` tuple, automatically rolling back
    /// the idempotency claim if `handler` returns `Err`.
    ///
    /// - Returns `Ok(None)` immediately if `guard` has already been processed.
    /// - Returns `Ok(Some(output))` and retains the idempotency mark when `handler` succeeds.
    /// - Calls [`Self::release`] and propagates `Err(err)` when `handler` fails so Paymob
    ///   webhook retries are not permanently dropped.
    ///
    /// # Errors
    ///
    /// Returns any error `E` produced by `handler` after releasing the idempotency claim.
    pub fn process_with_rollback<G, T, E, F>(&self, guard: &G, handler: F) -> Result<Option<T>, E>
    where
        G: IdempotentWebhookGuard,
        F: FnOnce() -> Result<T, E>,
    {
        if !self.check_and_mark(guard) {
            return Ok(None);
        }
        match handler() {
            Ok(output) => Ok(Some(output)),
            Err(err) => {
                self.release(guard);
                Err(err)
            }
        }
    }

    /// Returns the number of distinct active `(idempotency_key, correlation_id)` tuples recorded.
    #[must_use]
    pub fn len(&self) -> usize {
        let now = Instant::now();
        let mut state = self.lock_state();
        state.evict_expired(now);
        state.entries.len()
    }

    /// Returns `true` if no active webhook deliveries are currently recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl WebhookIdempotencyStore for InMemoryWebhookDeduplicator {
    fn check_and_mark(&self, guard: &impl IdempotentWebhookGuard) -> bool {
        Self::check_and_mark(self, guard)
    }

    fn contains(&self, guard: &impl IdempotentWebhookGuard) -> bool {
        Self::contains(self, guard)
    }

    fn claim_or_reject(&self, guard: &impl IdempotentWebhookGuard) -> WebhookResult<()> {
        Self::claim_or_reject(self, guard)
    }

    fn release(&self, guard: &impl IdempotentWebhookGuard) -> bool {
        Self::release(self, guard)
    }

    fn release_key(&self, idempotency_key: &str, correlation_id: &str) -> bool {
        Self::release_key(self, idempotency_key, correlation_id)
    }

    fn clear(&self) {
        Self::clear(self);
    }

    fn len(&self) -> usize {
        Self::len(self)
    }
}

impl Default for InMemoryWebhookDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for InMemoryWebhookDeduplicator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InMemoryWebhookDeduplicator")
            .field("seen_count", &self.len())
            .field("max_capacity", &self.max_capacity)
            .field("ttl", &self.ttl)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[derive(Clone)]
    struct TestGuard {
        key: String,
        correlation: String,
    }

    impl TestGuard {
        fn new(key: &str, correlation: &str) -> Self {
            Self {
                key: key.to_owned(),
                correlation: correlation.to_owned(),
            }
        }
    }

    impl IdempotentWebhookGuard for TestGuard {
        fn idempotency_tuple(&self) -> (String, String) {
            (self.key.clone(), self.correlation.clone())
        }
    }

    #[test]
    fn check_and_mark_detects_first_and_duplicate_deliveries() {
        let dedup = InMemoryWebhookDeduplicator::new();
        assert!(dedup.is_empty());
        assert_eq!(dedup.max_capacity(), DEFAULT_DEDUPLICATOR_CAPACITY);

        let evt = TestGuard::new("192036465", "217503754");
        assert!(dedup.check_and_mark(&evt));
        assert!(dedup.contains(&evt) && !dedup.is_empty());
        assert!(!dedup.check_and_mark(&evt));
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn claim_or_reject_and_release_workflow() {
        let store = InMemoryWebhookIdempotencyStore::default();
        let evt = TestGuard::new("tx_500", "ord_600");
        assert_eq!(store.claim_or_reject(&evt), Ok(()));
        assert_eq!(
            store.claim_or_reject(&evt),
            Err(WebhookError::DuplicateWebhookDelivery {
                idempotency_key: "tx_500".into(),
                correlation_id: "ord_600".into(),
            })
        );
        assert!(store.release(&evt));
        assert!(!store.contains(&evt));
        assert_eq!(store.claim_or_reject(&evt), Ok(()));
    }

    #[test]
    fn process_with_rollback_releases_on_err_and_retains_on_ok() {
        let dedup = InMemoryWebhookDeduplicator::new();
        let evt = TestGuard::new("req_10", "sub_20");

        let failed: Result<Option<u32>, &str> =
            dedup.process_with_rollback(&evt, || Err("db timeout"));
        assert_eq!(failed, Err("db timeout"));
        assert!(!dedup.contains(&evt));

        let succeeded: Result<Option<u32>, &str> = dedup.process_with_rollback(&evt, || Ok(42));
        assert_eq!(succeeded, Ok(Some(42)));
        let duplicate: Result<Option<u32>, &str> = dedup.process_with_rollback(&evt, || Ok(99));
        assert_eq!(duplicate, Ok(None));
    }

    #[test]
    fn fifo_capacity_evicts_oldest_entries_when_full() {
        let dedup = InMemoryWebhookDeduplicator::with_max_capacity(2);
        let g1 = TestGuard::new("k1", "c1");
        let g2 = TestGuard::new("k2", "c2");
        let g3 = TestGuard::new("k3", "c3");

        assert!(dedup.check_and_mark(&g1));
        assert!(dedup.check_and_mark(&g2));
        assert!(dedup.check_and_mark(&g3));
        assert_eq!(dedup.len(), 2);
        assert!(!dedup.contains(&g1));
        assert!(dedup.contains(&g2) && dedup.contains(&g3));
    }

    #[test]
    fn ttl_expiration_evicts_expired_entries_and_clear_resets() {
        let dedup = InMemoryWebhookDeduplicator::with_capacity_and_ttl(10, Duration::ZERO);
        assert_eq!(dedup.ttl(), Some(Duration::ZERO));
        let evt = TestGuard::new("k_ttl", "c_ttl");
        assert!(dedup.check_and_mark(&evt));
        assert!(!dedup.contains(&evt));
        assert!(dedup.check_and_mark(&evt));

        let with_long_ttl = InMemoryWebhookDeduplicator::with_ttl(Duration::from_secs(60));
        with_long_ttl.check_and_mark(&evt);
        with_long_ttl.clear();
        assert!(with_long_ttl.is_empty());
    }

    #[test]
    fn concurrent_threads_deduplicate_atomically() {
        let dedup = Arc::new(InMemoryWebhookDeduplicator::new());
        let mut handles = Vec::with_capacity(8);
        for _ in 0..8 {
            let shared = Arc::clone(&dedup);
            handles.push(thread::spawn(move || {
                (0..16)
                    .filter(|idx| {
                        shared.check_and_mark(&TestGuard::new(
                            &format!("evt_{idx}"),
                            &format!("ord_{idx}"),
                        ))
                    })
                    .count()
            }));
        }
        let total_accepted: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!((total_accepted, dedup.len()), (16, 16));
    }

    #[test]
    fn poison_recovery_and_debug_output_work() {
        let dedup = Arc::new(InMemoryWebhookDeduplicator::new());
        let poisoned_ref = Arc::clone(&dedup);
        let _ = thread::spawn(move || {
            let _guard = poisoned_ref.state.lock().unwrap();
            panic!("intentional poison");
        })
        .join();

        assert!(dedup.check_and_mark(&TestGuard::new("tx_1", "ord_1")));
        let formatted = format!("{dedup:?}");
        assert!(formatted.contains("InMemoryWebhookDeduplicator"));
        assert!(formatted.contains("seen_count: 1"));
    }
}
