#![forbid(unsafe_code)]
//! Payouts topup requests (`US-5.2.0/unit-4`).

use crate::core::client::PaymobClient;

/// Payouts topup request service (`paymob.payouts().topups()`).
#[derive(Debug, Clone, Copy)]
pub struct PayoutsTopupsService<'a> {
    client: &'a PaymobClient,
}

impl<'a> PayoutsTopupsService<'a> {
    /// Creates a new [`PayoutsTopupsService`] bound to `client`.
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
