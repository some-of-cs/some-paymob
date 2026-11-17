#![forbid(unsafe_code)]
//! v1 Payment Intention Create & Update API (`POST` & `PUT /v1/intention/`).

pub mod billing;
pub mod params;
pub mod response;
pub mod service;

pub use billing::{BillingData, BillingDataBuilder, IntentionCustomer, IntentionItem};
pub use params::{
    CreateIntentionParams, CreateIntentionParamsBuilder, PaymentMethodInput, UpdateIntentionParams,
    UpdateIntentionParamsBuilder,
};
pub use response::{
    ConfiguredPaymentMethod, IntentionDetail, IntentionPaymentKey, IntentionResponse,
};
pub use service::IntentionsService;
