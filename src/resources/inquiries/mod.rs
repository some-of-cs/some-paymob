#![forbid(unsafe_code)]
//! Transaction, order, and saved card token inquiry service (`US-3.2.0`).

pub mod by_id;
pub mod by_order;
pub mod card_tokens;
pub mod order_inquiry;

use crate::core::client::PaymobClient;

/// Service handle for Paymob transaction, order, and saved card token inquiries.
#[derive(Debug, Clone, Copy)]
pub struct InquiriesService<'a> {
    client: &'a PaymobClient,
}

impl<'a> InquiriesService<'a> {
    /// Creates a new [`InquiriesService`] bound to `client`.
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
    /// Returns the transaction, order, and saved card token inquiry service.
    #[must_use]
    pub const fn inquiries(&self) -> InquiriesService<'_> {
        InquiriesService::new(self)
    }
}
