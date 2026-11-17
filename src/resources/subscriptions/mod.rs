#![forbid(unsafe_code)]
//! Subscriptions & Recurring Billing engine (`US-4.2.0` & `US-4.3.0`).
//!
//! Pre-scaffolded module index for `feat/module-4-saved-cards-subscriptions`.

/// Unit 4.3.3: Subscription card vault management (`list`, `add_secondary`, `change_primary`, `delete_secondary`).
pub mod cards;
/// Unit 4.3.4: Subscription webhook registration and transaction history endpoints.
pub mod history;
/// Unit 4.3.2: [`SubscriptionsService`] lifecycle operations.
pub mod lifecycle;
/// Unit 4.3.1: Subscription record, state, list filter, and card vault models.
pub mod models;
/// Unit 4.2.1: Subscription plan frequency, plan type, and plan record models.
pub mod plan_models;
/// Unit 4.2.2: Subscription plan creation and update parameter builders.
pub mod plan_params;
/// Unit 4.2.3: Subscription plans CRUD and suspend/resume service.
pub mod plans_service;
/// Unit 4.3.5: Composite `refund_last_transaction` helper.
pub mod refund;

pub use lifecycle::SubscriptionsService;
pub use plans_service::SubscriptionPlansService;
