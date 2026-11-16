#![forbid(unsafe_code)]
//! QuickLinks payment links service (`US-3.3.0/unit-1`).

use crate::core::client::PaymobClient;

/// Service handle for Paymob QuickLinks payment link creation and cancellation.
#[derive(Debug, Clone, Copy)]
pub struct QuickLinksService<'a> {
    client: &'a PaymobClient,
}

impl<'a> QuickLinksService<'a> {
    /// Creates a new [`QuickLinksService`] bound to `client`.
    #[must_use]
    pub(crate) const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }
}

impl PaymobClient {
    /// Returns the QuickLinks payment links service (`create`, `cancel`).
    #[must_use]
    pub const fn quicklinks(&self) -> QuickLinksService<'_> {
        QuickLinksService::new(self)
    }
}
