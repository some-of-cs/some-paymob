#![forbid(unsafe_code)]
//! Convenience prelude re-exporting the core `some-paymob` primitives (`US-1.3.0/unit-4`).
//!
//! Import all essential client, configuration, credential, region, auth,
//! HTTP transport, money, error, pagination, and webhook types with a single wildcard import:
//!
//! ```
//! use some_paymob::prelude::*;
//!
//! let query = PageQuery::new(1);
//! assert_eq!(query.to_query_string(), "?page=1");
//! ```

pub use crate::core::auth::AuthManager;
pub use crate::core::auth::cache::CachedToken;
pub use crate::core::auth::strategy::AuthStrategy;
pub use crate::core::client::PaymobClient;
pub use crate::core::config::{ClientConfig, ClientConfigBuilder};
pub use crate::core::credentials::{
    ApiKey, EnvironmentMode, HmacSecret, PartnerCredentials, PayoutsCredentials, PublicKey,
    SecretKey,
};
pub use crate::core::error::PaymobError;
pub use crate::core::http::{
    HttpClient, HttpClientConfig, HttpError, HttpRequest, HttpResponse, RetryPolicy,
};
pub use crate::core::pagination::{PageQuery, PaginatedResponse};
pub use crate::core::region::{PaymobRegion, RegionalEndpoints};
pub use crate::core::types::{Currency, MinorUnitAmount, validate_prefixed_id};
/// Re-exports all public saved-card tokenization and headless payment types.
#[cfg(feature = "saved-cards")]
pub use crate::resources::saved_cards::*;
/// Re-exports all public subscription plan, lifecycle, card vault, and history types.
#[cfg(feature = "subscriptions")]
pub use crate::resources::subscriptions::*;
/// Re-exports all public webhook verification types, traits, and helpers.
#[cfg(feature = "webhooks")]
pub use crate::webhooks::*;
