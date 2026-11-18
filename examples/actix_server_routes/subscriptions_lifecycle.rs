#![forbid(unsafe_code)]
//! Service 8b: Subscriptions Lifecycle (Create, Retrieve, List, Update, Suspend, Resume, Cancel).

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::{Value, json};
use some_paymob::prelude::*;

use super::{ApiServerError, AppState, parse_currency};

#[derive(Debug, Deserialize)]
pub struct CreateSubPayload {
    pub subscription_plan_id: u64,
    pub amount_cents: u64,
    pub currency: String,
    pub payment_methods: Vec<u64>,
    pub billing_data: Option<Value>,
    pub special_reference: Option<String>,
    pub notification_url: Option<String>,
    pub redirection_url: Option<String>,
    pub extras: Option<Value>,
}

/// `POST /subscriptions` — Enrolls a customer in a subscription.
pub async fn create_subscription(
    state: web::Data<AppState>,
    body: web::Json<CreateSubPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let currency = parse_currency(&body.currency)?;
    let amount = MinorUnitAmount::new(body.amount_cents)?;
    let mut params = CreateSubscriptionParams::new(
        body.subscription_plan_id,
        amount,
        currency,
        body.payment_methods.clone(),
    );
    if let Some(bd) = &body.billing_data {
        params = params.with_billing_data(bd.clone());
    }
    if let Some(sr) = &body.special_reference {
        params = params.with_special_reference(sr);
    }
    if let Some(nu) = &body.notification_url {
        params = params.with_notification_url(nu);
    }
    if let Some(ru) = &body.redirection_url {
        params = params.with_redirection_url(ru);
    }
    if let Some(ex) = &body.extras {
        params = params.with_extras(ex.clone());
    }
    let resp = state.client.subscriptions().create(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "id": resp.id,
        "client_secret": "[REDACTED]",
        "intention_order_id": resp.intention_order_id,
        "status": resp.status,
        "subscription_plan_id": resp.subscription_plan_id,
    })))
}

fn sub_ok(sub: Subscription) -> Result<HttpResponse, ApiServerError> {
    Ok(HttpResponse::Ok().json(json!({
        "id": sub.id,
        "state": sub.state,
        "plan_id": sub.plan_id,
        "amount_cents": sub.amount_cents,
        "is_active": sub.is_active,
    })))
}

#[derive(Clone, Copy)]
enum SubAction {
    Retrieve,
    Suspend,
    Resume,
    Cancel,
}

async fn apply_sub_action(
    state: &web::Data<AppState>,
    sub_id: u64,
    action: SubAction,
) -> Result<HttpResponse, ApiServerError> {
    let svc = state.client.subscriptions();
    let sub = match action {
        SubAction::Retrieve => svc.retrieve(sub_id).await?,
        SubAction::Suspend => svc.suspend(sub_id).await?,
        SubAction::Resume => svc.resume(sub_id).await?,
        SubAction::Cancel => svc.cancel(sub_id).await?,
    };
    sub_ok(sub)
}

/// `GET /subscriptions/{sub_id}` — Retrieves a subscription by ID.
pub async fn get_subscription(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    apply_sub_action(&state, path.into_inner(), SubAction::Retrieve).await
}

#[derive(Debug, Deserialize)]
pub struct ListSubQuery {
    pub page: Option<u32>,
    pub state: Option<String>,
}

/// `GET /subscriptions` — Lists subscriptions.
pub async fn list_subscriptions(
    state: web::Data<AppState>,
    query: web::Query<ListSubQuery>,
) -> Result<HttpResponse, ApiServerError> {
    let mut filter = SubscriptionListFilter::default();
    if let Some(p) = query.page {
        filter.page = Some(p);
    }
    if let Some(s) = &query.state {
        filter.state = Some(s.clone());
    }
    let resp = state.client.subscriptions().list(&filter).await?;
    Ok(HttpResponse::Ok().json(json!({
        "count": resp.results.len(),
        "total": resp.count,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateSubPayload {
    pub amount_cents: Option<u64>,
    pub plan_id: Option<u64>,
    pub webhook_url: Option<String>,
    pub is_active: Option<bool>,
}

/// `PUT /subscriptions/{sub_id}` — Updates a subscription.
pub async fn update_subscription(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<UpdateSubPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut params = UpdateSubscriptionParams::new();
    if let Some(amt) = body.amount_cents {
        params = params.with_amount_cents(MinorUnitAmount::new(amt)?);
    }
    if let Some(pid) = body.plan_id {
        params = params.with_plan_id(pid);
    }
    if let Some(url) = &body.webhook_url {
        params = params.with_webhook_url(url);
    }
    if let Some(active) = body.is_active {
        params = params.with_is_active(active);
    }
    let sub = state
        .client
        .subscriptions()
        .update(path.into_inner(), &params)
        .await?;
    sub_ok(sub)
}

/// `POST /subscriptions/{sub_id}/suspend` — Suspends a subscription.
pub async fn suspend_subscription(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    apply_sub_action(&state, path.into_inner(), SubAction::Suspend).await
}

/// `POST /subscriptions/{sub_id}/resume` — Resumes a subscription.
pub async fn resume_subscription(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    apply_sub_action(&state, path.into_inner(), SubAction::Resume).await
}

/// `POST /subscriptions/{sub_id}/cancel` — Cancels a subscription.
pub async fn cancel_subscription(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    apply_sub_action(&state, path.into_inner(), SubAction::Cancel).await
}

/// Registers Service 8b routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/subscriptions", web::post().to(create_subscription))
        .route("/subscriptions", web::get().to(list_subscriptions))
        .route("/subscriptions/{sub_id}", web::get().to(get_subscription))
        .route(
            "/subscriptions/{sub_id}",
            web::put().to(update_subscription),
        )
        .route(
            "/subscriptions/{sub_id}/suspend",
            web::post().to(suspend_subscription),
        )
        .route(
            "/subscriptions/{sub_id}/resume",
            web::post().to(resume_subscription),
        )
        .route(
            "/subscriptions/{sub_id}/cancel",
            web::post().to(cancel_subscription),
        );
}
