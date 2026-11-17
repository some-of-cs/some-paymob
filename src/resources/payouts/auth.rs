#![forbid(unsafe_code)]
//! Payouts OAuth 2.0 token facade (`US-5.1.0/unit-1`).

use crate::core::client::PaymobClient;

/// Payouts OAuth 2.0 token service (`paymob.payouts().auth()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsAuthService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsAuthService<'a> {
    /// Creates a new [`PayoutsAuthService`] bound to `client`.
    #[must_use]
    pub const fn new(client: &'a PaymobClient) -> Self {
        Self { client }
    }

    /// Returns the underlying [`PaymobClient`].
    #[must_use]
    pub const fn client(&self) -> &'a PaymobClient {
        self.client
    }
}
