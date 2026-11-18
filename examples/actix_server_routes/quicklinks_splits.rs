#![forbid(unsafe_code)]
//! Service 6: QuickLinks & Marketplace Splits / Convenience Fees.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

#[derive(Debug, Deserialize)]
pub struct QuickLinkPayload {
    pub amount_cents: u64,
    pub currency: String,
    pub integrations: Vec<u64>,
    pub description: Option<String>,
}

/// `POST /quicklinks` — Creates a QuickLink payment URL.
pub async fn create_quicklink(
    state: web::Data<AppState>,
    body: web::Json<QuickLinkPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut params =
        CreateQuickLinkParams::new(body.amount_cents, &body.currency, body.integrations.clone());
    if let Some(desc) = &body.description {
        params = params.with_description(desc);
    }
    let resp = state.client.quicklinks().create(&params).await?;
    Ok(HttpResponse::Created().json(json!({
        "id": resp.id,
        "url": resp.url,
        "client_url": resp.client_url,
    })))
}

/// `POST /quicklinks/{link_id}/cancel` — Cancels an active QuickLink.
pub async fn cancel_quicklink(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> Result<HttpResponse, ApiServerError> {
    state.client.quicklinks().cancel(&path.into_inner()).await?;
    Ok(HttpResponse::Ok().json(json!({ "cancelled": true })))
}

#[derive(Debug, Deserialize)]
pub struct SplitRecipientInput {
    pub recipient_id: String,
    pub amount_cents: Option<u64>,
    pub percentage_bps: Option<u32>,
}

#[derive(Debug, Deserialize)]
pub struct SplitCardInput {
    pub amount_cents: u64,
    pub integration_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct SplitsQuotePayload {
    pub total_amount_cents: u64,
    pub recipients: Vec<SplitRecipientInput>,
    pub cards: Vec<SplitCardInput>,
    pub fixed_fee_cents: Option<u64>,
}

fn build_split_rule(r: &SplitRecipientInput) -> Result<SplitRecipientRule, ApiServerError> {
    match (r.amount_cents, r.percentage_bps) {
        (Some(amt), None) => Ok(SplitRecipientRule::fixed(&r.recipient_id, amt)),
        (None, Some(bps)) => Ok(SplitRecipientRule::percentage_bps(&r.recipient_id, bps)),
        _ => Err(PaymobError::ValidationError {
            field: "recipients",
            reason: "specify exactly one of amount_cents or percentage_bps".to_owned(),
        }
        .into()),
    }
}

/// `POST /splits/validate-and-quote` — Validates split rules, card portions, and convenience fees.
pub async fn splits_validate_and_quote(
    body: web::Json<SplitsQuotePayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut rules = Vec::with_capacity(body.recipients.len());
    for r in &body.recipients {
        rules.push(build_split_rule(r)?);
    }
    let split_desc = SplitDescription::new(rules)?;
    let cards: Vec<SplitCardPortion> = body
        .cards
        .iter()
        .map(|c| {
            let mut p = SplitCardPortion::new(c.amount_cents);
            if let Some(id) = c.integration_id {
                p = p.with_integration_id(id);
            }
            p
        })
        .collect();
    let card_cfg = SplitPaymentConfig::new(cards)?;
    card_cfg.validate_total(body.total_amount_cents)?;
    let fee_cfg = ConvenienceFeeConfig::new(FeeCalculationMode::FixedCents(body.fixed_fee_cents.unwrap_or(0)));
    let total_with_fee = fee_cfg.total_with_fee_cents(body.total_amount_cents)?;
    Ok(HttpResponse::Ok().json(json!({
        "recipients_count": split_desc.recipients.len(),
        "cards_count": card_cfg.cards.len(),
        "total_with_fee_cents": total_with_fee,
    })))
}

/// Registers Service 6 routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/quicklinks", web::post().to(create_quicklink))
        .route(
            "/quicklinks/{link_id}/cancel",
            web::post().to(cancel_quicklink),
        )
        .route(
            "/splits/validate-and-quote",
            web::post().to(splits_validate_and_quote),
        );
}
