#![forbid(unsafe_code)]
//! Convenience prelude re-exporting the core `some-paymob` primitives (`US-1.3.0/unit-4`).
//!
//! Import all essential client, configuration, credential, region, auth,
//! HTTP transport, money, error, pagination, intentions, checkout, legacy-v2,
//! and webhook types with a single wildcard import:
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

/// Re-exports all public Unified Checkout, Pixel JS, and Affordability Widget types.
#[cfg(feature = "intentions")]
pub use crate::resources::checkout::{
    AffordabilityWidgetConfig, AffordabilityWidgetConfigBuilder, ApplePaySettings, CheckoutService,
    GooglePaySettings, PixelConfig, PixelConfigBuilder, PixelPaymentMethod,
};

/// Re-exports all public v1 Payment Intention request, response, and service types.
#[cfg(feature = "intentions")]
pub use crate::resources::intentions::{
    BillingData, BillingDataBuilder, ConfiguredPaymentMethod, CreateIntentionParams,
    CreateIntentionParamsBuilder, IntentionCustomer, IntentionDetail, IntentionItem,
    IntentionPaymentKey, IntentionResponse, IntentionsService, PaymentMethodInput,
    UpdateIntentionParams, UpdateIntentionParamsBuilder,
};

/// Re-exports all public Legacy Accept v2 3-step checkout types and helpers.
#[cfg(feature = "legacy-v2")]
pub use crate::resources::legacy::{
    AuthenticatedLegacyOrderRequest, CreateLegacyOrderParams, CreatePaymentKeyParams,
    DEFAULT_PAYMENT_KEY_EXPIRATION_SECS, LEGACY_ORDERS_PATH, LEGACY_PAYMENT_KEYS_PATH,
    LegacyBillingData, LegacyCheckoutParams, LegacyCheckoutSession, LegacyOrder, LegacyOrderItem,
    LegacyV2Service, PaymentKeyResponse, create_legacy_order, create_legacy_payment_key,
};

/// Re-exports all public webhook verification types, traits, and helpers.
#[cfg(feature = "webhooks")]
pub use crate::webhooks::*;
