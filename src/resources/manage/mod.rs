#![forbid(unsafe_code)]
//! Payment lifecycle management service (`refund`, `void`, `capture`) for `US-3.1.0`.

pub mod models;
pub mod refund;
pub mod void_capture;

use crate::core::client::PaymobClient;

/// Service handle for Paymob payment lifecycle management operations.
#[derive(Debug, Clone, Copy)]
pub struct ManageService<'a> {
    client: &'a PaymobClient,
}

impl<'a> ManageService<'a> {
    /// Creates a new [`ManageService`] bound to `client`.
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
    /// Returns the payment lifecycle management service (`refund`, `void`, `capture`).
    #[must_use]
    pub const fn manage(&self) -> ManageService<'_> {
        ManageService::new(self)
    }
}
