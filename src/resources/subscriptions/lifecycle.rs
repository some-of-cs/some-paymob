#![forbid(unsafe_code)]
//! Unit 4.3.2 stub — `SubscriptionsService`.

use crate::core::client::PaymobClient;

/// Service handle for subscription plans, lifecycle, card vault, and history (`US-4.2.0`, `US-4.3.0`).
#[derive(Debug, Clone)]
pub struct SubscriptionsService {
    client: PaymobClient,
}

impl SubscriptionsService {
    /// Creates a new [`SubscriptionsService`] bound to `client`.
    #[must_use]
    pub fn new(client: PaymobClient) -> Self {
        Self { client }
    }

    /// Returns a reference to the underlying [`PaymobClient`].
    #[must_use]
    pub fn client(&self) -> &PaymobClient {
        &self.client
    }
}
