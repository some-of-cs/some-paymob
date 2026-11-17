#![forbid(unsafe_code)]
//! Subscriptions & Recurring Billing engine (`US-4.2.0` & `US-4.3.0`).

use reqwest::Method;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::core::client::{PaymobClient, build_bearer_json_request};
use crate::core::error::PaymobError;
use crate::core::http::HttpResponse;
use crate::core::types::validate_non_zero_u64;

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

pub use cards::{
    AddSecondaryCardParams, ChangePrimaryCardParams, DeleteSecondaryCardResponse,
    SubscriptionCardsService,
};
pub use history::{
    RegisterWebhookParams, SubscriptionHistoryService, SubscriptionTransaction,
    SubscriptionWebhookRegistration,
};
pub use lifecycle::{
    CreateSubscriptionParams, SubscriptionCardsAccessor, SubscriptionEnrollmentResponse,
    SubscriptionPlansAccessor, SubscriptionsService, UpdateSubscriptionParams,
};
pub use models::{
    KNOWN_SUBSCRIPTION_STATES, Subscription, SubscriptionListFilter, SubscriptionState,
};
pub use plan_models::{KNOWN_PLAN_FREQUENCIES, PlanFrequency, PlanType, SubscriptionPlan};
pub use plan_params::{
    CreateSubscriptionPlanParams, CreateSubscriptionPlanParamsBuilder, MAX_PLAN_NAME_LEN,
    UpdateSubscriptionPlanParams, UpdateSubscriptionPlanParamsBuilder,
};
pub use plans_service::SubscriptionPlansService;
pub use refund::{
    SubscriptionLastTransaction, SubscriptionRefundRequest, SubscriptionRefundResponse,
    prepare_refund_payload,
};

pub(crate) async fn execute_subscription_bearer_json<Req, Resp>(
    client: &PaymobClient,
    method: Method,
    path: &str,
    body: Option<&Req>,
) -> Result<Resp, PaymobError>
where
    Req: Serialize + ?Sized,
    Resp: DeserializeOwned,
{
    let url = client.accept_url(path)?;
    let response = client
        .execute_regime2_with_retry(
            || PaymobError::ValidationError {
                field: "api_key",
                reason: "Paymob API key is required for Regime 2 authentication".to_owned(),
            },
            |token| build_bearer_json_request(method.clone(), url.as_str(), token, body),
        )
        .await?;
    decode_subscription_response(response)
}

pub(crate) fn decode_subscription_response<Resp: DeserializeOwned>(
    response: HttpResponse,
) -> Result<Resp, PaymobError> {
    if !response.status.is_success() {
        return Err(PaymobError::from_http_response(&response));
    }
    Ok(response.json::<Resp>()?)
}

pub(crate) fn validate_positive_id(field: &'static str, id: u64) -> Result<(), PaymobError> {
    validate_non_zero_u64(field, id, "identifier must be greater than zero")
}
