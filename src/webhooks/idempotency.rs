//! Atomic webhook idempotency guard and thread-safe in-memory deduplicator.
//!
//! Provides [`IdempotentWebhookGuard`] for extracting deterministic
//! `(idempotency_key, correlation_id)` pairs across all Paymob webhook protocols
//! (Protocols A–E), paired with [`InMemoryWebhookDeduplicator`] for thread-safe
//! replay protection.

use std::collections::HashSet;
use std::fmt;
use std::sync::Mutex;

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
            Self::TransactionResponseRedirect(params) => {
                (params.id.clone(), params.order_id.clone())
            }
            Self::CardTokenSaved(evt) => evt.idempotency_tuple(),
            Self::SubscriptionLifecycle(evt) => evt.idempotency_tuple(),
            Self::PayoutDisbursement(evt) => evt.idempotency_tuple(),
            Self::PayoutTopup(evt) => evt.idempotency_tuple(),
        }
    }
}

/// Thread-safe in-memory webhook deduplicator backed by a [`Mutex`]-guarded [`HashSet`].
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
    seen: Mutex<HashSet<(String, String)>>,
}

impl InMemoryWebhookDeduplicator {
    /// Creates an empty [`InMemoryWebhookDeduplicator`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// Checks whether `guard`'s idempotency tuple has not been seen before and marks it as seen.
    ///
    /// Returns `true` if the event is newly seen (and has now been recorded), or `false` if it
    /// is a duplicate delivery.
    pub fn check_and_mark(&self, guard: &impl IdempotentWebhookGuard) -> bool {
        let tuple = guard.idempotency_tuple();
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        seen.insert(tuple)
    }

    /// Returns the number of distinct `(idempotency_key, correlation_id)` tuples recorded so far.
    #[must_use]
    pub fn len(&self) -> usize {
        let seen = self
            .seen
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        seen.len()
    }

    /// Returns `true` if no webhook deliveries have been recorded yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        assert_eq!(dedup.len(), 0);

        let evt = TestGuard::new("192036465", "217503754");
        assert!(dedup.check_and_mark(&evt));
        assert!(!dedup.is_empty());
        assert_eq!(dedup.len(), 1);

        assert!(!dedup.check_and_mark(&evt));
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn distinct_key_or_correlation_tuples_are_tracked_independently() {
        let dedup = InMemoryWebhookDeduplicator::default();

        assert!(dedup.check_and_mark(&TestGuard::new("req_1", "sub_100")));
        assert!(dedup.check_and_mark(&TestGuard::new("req_2", "sub_100")));
        assert!(dedup.check_and_mark(&TestGuard::new("req_1", "sub_200")));
        assert!(!dedup.check_and_mark(&TestGuard::new("req_1", "sub_100")));
        assert_eq!(dedup.len(), 3);
    }

    #[test]
    fn empty_boundary_tuple_is_accepted_once() {
        let dedup = InMemoryWebhookDeduplicator::new();
        let empty = TestGuard::new("", "");

        assert!(dedup.check_and_mark(&empty));
        assert!(!dedup.check_and_mark(&empty));
        assert_eq!(dedup.len(), 1);
    }

    #[test]
    fn concurrent_threads_deduplicate_atomically() {
        let dedup = Arc::new(InMemoryWebhookDeduplicator::new());
        let event_count = 16;
        let thread_count = 8;

        let mut handles = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            let shared = Arc::clone(&dedup);
            handles.push(thread::spawn(move || {
                let mut accepted = 0usize;
                for idx in 0..event_count {
                    let evt = TestGuard::new(&format!("evt_{idx}"), &format!("ord_{idx}"));
                    if shared.check_and_mark(&evt) {
                        accepted += 1;
                    }
                }
                accepted
            }));
        }

        let total_accepted: usize = handles
            .into_iter()
            .map(|h| h.join().expect("worker thread should not panic"))
            .sum();

        assert_eq!(total_accepted, event_count);
        assert_eq!(dedup.len(), event_count);
    }

    #[test]
    fn debug_output_reports_count_without_panicking() {
        let dedup = InMemoryWebhookDeduplicator::new();
        dedup.check_and_mark(&TestGuard::new("tx_1", "ord_1"));
        let formatted = format!("{dedup:?}");
        assert!(formatted.contains("InMemoryWebhookDeduplicator"));
        assert!(formatted.contains("seen_count: 1"));
    }
}
