#![forbid(unsafe_code)]
//! Service 8a: Subscription Plans CRUD & Lifecycle.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

fn parse_frequency(raw: &str) -> Result<PlanFrequency, ApiServerError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "weekly" => Ok(PlanFrequency::Weekly),
        "biweekly" | "bi_weekly" => Ok(PlanFrequency::BiWeekly),
        "monthly" => Ok(PlanFrequency::Monthly),
        "quarterly" => Ok(PlanFrequency::Quarterly),
        "yearly" => Ok(PlanFrequency::Yearly),
        _ => Err(PaymobError::ValidationError {
            field: "frequency",
            reason: "unsupported plan frequency".to_owned(),
        }
        .into()),
    }
}

#[derive(Debug, Deserialize)]
pub struct CreatePlanPayload {
    pub frequency: String,
    pub name: String,
    pub integration: u64,
    pub amount_cents: Option<u64>,
    pub webhook_url: Option<String>,
    pub reminder_days: Option<u16>,
    pub retrial_days: Option<u16>,
}

/// `POST /subscriptions/plans` — Creates a subscription plan.
pub async fn create_plan(
    state: web::Data<AppState>,
    body: web::Json<CreatePlanPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut b = CreateSubscriptionPlanParams::builder()
        .frequency(parse_frequency(&body.frequency)?)
        .name(&body.name)
        .integration(body.integration);
    if let Some(amt) = body.amount_cents {
        b = b.amount_cents(amt);
    }
    if let Some(u) = &body.webhook_url {
        b = b.webhook_url(u);
    }
    if let Some(d) = body.reminder_days {
        b = b.reminder_days(d);
    }
    if let Some(d) = body.retrial_days {
        b = b.retrial_days(d);
    }
    let params = b.build()?;
    let plan = state.client.subscriptions().plans().create(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "id": plan.id,
        "name": plan.name,
        "is_active": plan.is_active,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdatePlanPayload {
    pub name: Option<String>,
    pub amount_cents: Option<u64>,
    pub is_active: Option<bool>,
}

/// `PUT /subscriptions/plans/{plan_id}` — Updates a subscription plan.
pub async fn update_plan(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<UpdatePlanPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut b = UpdateSubscriptionPlanParams::builder();
    if let Some(n) = &body.name {
        b = b.name(n);
    }
    if let Some(amt) = body.amount_cents {
        b = b.amount_cents(amt);
    }
    if let Some(active) = body.is_active {
        b = b.is_active(active);
    }
    let params = b.build()?;
    let plan = state
        .client
        .subscriptions()
        .plans()
        .update(path.into_inner(), &params)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": plan.id,
        "name": plan.name,
        "is_active": plan.is_active,
    })))
}

#[derive(Debug, Deserialize)]
pub struct PageParams {
    pub page: Option<u32>,
}

/// `GET /subscriptions/plans` — Lists subscription plans.
pub async fn list_plans(
    state: web::Data<AppState>,
    query: web::Query<PageParams>,
) -> Result<HttpResponse, ApiServerError> {
    let page = PageQuery::new(query.page.unwrap_or(1));
    let resp = state.client.subscriptions().plans().list(page).await?;
    Ok(HttpResponse::Ok().json(json!({
        "count": resp.results.len(),
        "total": resp.count,
    })))
}

/// `POST /subscriptions/plans/{plan_id}/suspend` — Suspends a plan.
pub async fn suspend_plan(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let plan = state
        .client
        .subscriptions()
        .plans()
        .suspend(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(json!({ "id": plan.id, "is_active": plan.is_active })))
}

/// `POST /subscriptions/plans/{plan_id}/resume` — Resumes a plan.
pub async fn resume_plan(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let plan = state
        .client
        .subscriptions()
        .plans()
        .resume(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(json!({ "id": plan.id, "is_active": plan.is_active })))
}

/// Registers Service 8a routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/subscriptions/plans", web::post().to(create_plan))
        .route("/subscriptions/plans", web::get().to(list_plans))
        .route("/subscriptions/plans/{plan_id}", web::put().to(update_plan))
        .route(
            "/subscriptions/plans/{plan_id}/suspend",
            web::post().to(suspend_plan),
        )
        .route(
            "/subscriptions/{sub_id}/resume",
            web::post().to(resume_plan))
        );
}
