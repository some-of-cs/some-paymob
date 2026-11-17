#![forbid(unsafe_code)]
//! Unified Checkout URL, Embedded Pixel JS config, and Affordability Widget builders.

pub mod affordability;
pub mod pixel;
pub mod unified;

pub use affordability::{AffordabilityWidgetConfig, AffordabilityWidgetConfigBuilder};
pub use pixel::{
    ApplePaySettings, GooglePaySettings, PixelConfig, PixelConfigBuilder, PixelPaymentMethod,
};
pub use unified::CheckoutService;
