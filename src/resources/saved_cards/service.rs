#![forbid(unsafe_code)]
//! Unit 4.1.3 stub — `SavedCardsService`.

use crate::core::client::PaymobClient;

/// Service handle for saved-card tokenization and headless payments (`US-4.1.0`).
#[derive(Debug, Clone)]
pub struct SavedCardsService {
    client: PaymobClient,
}

impl SavedCardsService {
    /// Creates a new [`SavedCardsService`] bound to `client`.
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
