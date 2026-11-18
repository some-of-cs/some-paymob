#![forbid(unsafe_code)]
//! Service 8c: Subscription Cards Vault, History & Composite Last-Transaction Refund.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;
use some_paymob::resources::subscriptions::models::SubscriptionTransaction;

use super::{ApiServerError, AppState};

fn sub_tx_ok(tx: &SubscriptionTransaction) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "id": tx.id,
        "amount_cents": tx.amount_cents,
        "success": tx.success,
        "is_refunded": tx.is_refunded,
    }))
}

/// `GET /subscriptions/{sub_id}/cards` â€” Lists cards attached to a subscription.
pub async fn list_cards(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let cards = state
        .client
        .subscriptions()
        .cards()
        .list(path.into_inner())
        .await?;
    Ok(HttpResponse::Ok().json(json!({ "count": cards.len(), "cards": cards })))
}

#[derive(Debug, Deserialize)]
pub struct AddSecondaryCardPayload {
    pub card_token: String,
    pub integration_id: Option<u64>,
    pub redirect_url: Option<String>,
}

/// `POST /subscriptions/{sub_id}/cards/secondary` â€” Adds a secondary card to a subscription.
pub async fn add_secondary_card(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<AddSecondaryCardPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let mut params = AddSecondaryCardParams::new(&body.card_token)?;
    if let Some(id) = body.integration_id {
        params = params.with_integration_id(id);
    }
    if let Some(url) = &body.redirect_url {
        params = params.with_redirect_url(url);
    }
    let card = state
        .client
        .subscriptions()
        .cards()
        .add_secondary(path.into_inner(), params)
        .await?;
    Ok(HttpResponse::Ok().json(card))
}

#[derive(Debug, Deserialize)]
pub struct ChangePrimaryCardPayload {
    pub card_id: u64,
}

/// `POST /subscriptions/{sub_id}/cards/primary` â€” Switches the primary subscription card.
pub async fn change_primary_card(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<ChangePrimaryCardPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let card = state
        .client
        .subscriptions()
        .cards()
        .change_primary(path.into_inner(), body.card_id)
        .await?;
    Ok(HttpResponse::Ok().json(card))
}

/// `DELETE /subscriptions/{sub_id}/cards/{card_id}` â€” Deletes a secondary card.
pub async fn delete_secondary_card(
    state: web::Data<AppState>,
    path: web::Path<(u64, u64)>,
) -> Result<HttpResponse, ApiServerError> {
    let (sub_id, card_id) = path.into_inner();
    let resp = state
        .client
        .subscriptions()
        .cards()
        .delete_secondary(sub_id, card_id)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "detail": resp.detail,
        "message": resp.message,
    })))
}

#[derive(Debug, Deserialize)]
pub struct RegisterWebhookPayload {
    pub webhook_url: String,
}

/// `POST /subscriptions/{sub_id}/webhook` â€” Registers a subscription webhook URL.
pub async fn register_webhook(
    state: web::Data<AppState>,
    path: web::Path<u64>,
    body: web::Json<RegisterWebhookPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let reg = state
        .client
        .subscriptions()
        .register_webhook(path.into_inner(), &body.webhook_url)
        .await?;
    Ok(HttpResponse::Ok().json(json!({
        "id": reg.id,
        "webhook_url": reg.webhook_url,
        "detail": reg.detail,
    })))
}

/// `GET /subscriptions/{sub_id}/last-transaction` â€” Fetches the latest subscription transaction.
pub async fn last_transaction(
    state: web::Data<AppState>,
    path: web::Path<u64>,
) -> Result<HttpResponse, ApiServerError> {
    let tx = state
        .client
        .subscriptions()
        .last_transaction(path.into_inner())ˆ˜]ØZ]ÎÂˆÚÊİX—İÛÚÊ	
JBŸB‚‹ËËÈÑUÜİXœØÜš\[ÛœËŞÜİX—ÚYKİ˜[œØXİ[ÛœØ8 %\İÈİXœØÜš\[Ûˆ˜[œØXİ[ÛœË‚œXˆ\Ş[˜È›ˆ\İİ˜[œØXİ[ÛœÊˆİ]NˆÙX‘]O\İ]O‹ˆ]ˆÙX”]M‹ŠHOˆ™\İ[™\ÜÛœÙK\TÙ\™\‘\œ›ÜˆÂˆ]ÈHİ]Bˆ˜ÛY[ˆœİXœØÜš\[ÛœÊ
Bˆ›\İİ˜[œØİ[ÛœÊ]š[×Ú[›™\Š
JBˆ˜]ØZ]ÎÂˆÚÊ™\ÜÛœÙN“ÚÊ
KšœÛÛŠœÛÛˆJÈ˜Ûİ[ˆË›[Š
HJJJBŸB‚ˆÖÙ\š]™JXYË\Ù\šX[^™JWBœXˆİXİ™Y[™\İ^[ØYÂˆXˆ[[İ[ØÙ[ÎˆÜ[ÛM‹ŸB‚‹ËËÈÔÕÜİXœØÜš\[ÛœËŞÜİX—ÚYKÜ™Y[™[\İ]˜[œØXİ[Û˜8 %™Y[™ÈH]\İİXœØÜš\[ÛˆÚ\™ÙK‚œXˆ\Ş[˜È›ˆ™Y[™Û\İİ˜[œØXİ[ÛŠˆİ]NˆÙX‘]O\İ]O‹ˆ]ˆÙX”]M‹ˆ›ÙNˆÙX’œÛÛ™Y[™\İ^[ØY‹ŠHOˆ™\İ[™\ÜÛœÙK\TÙ\™\‘\œ›ÜˆÂˆ]Hİ]Bˆ˜ÛY[ˆœİXœØÜš\[ÛœÊ
Bˆœ™Y[™Û\İİ˜[œØXİ[ÛŠ]š[×Ú[›™\Š
K›ÙK˜[[İ[ØÙ[ÊBˆ˜]ØZ]ÎÂˆÚÊİX—İÛÚÊ	
JBŸB‚‹ËËÈ™YÚ\İ\œÈÙ\šXÙHÈ›İ]\Ë‚œXˆ›ˆÛÛ™šYİ\™JÙ™Îˆ	›]]ÙX”Ù\šXÙPÛÛ™šYÊHÂˆÙ™Ëœ›İ]J‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKØØ\™È‹ÙX™Ù]

KÊ\İØØ\™ÊJBˆœ›İ]Jˆ‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKØØ\™ËÜÙXÛÛ™\H‹ˆÙXœÜİ

KÊYÜÙXÛÛ™\WØØ\™
Kˆ
Bˆœ›İ]Jˆ‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKØØ\™ËÜš[X\H‹ˆÙXœÜİ

KÊÚ[™ÙWÜš[X\WØØ\™
Kˆ
Bˆœ›İ]Jˆ‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKØØ\™ËŞØØ\™ÚYH‹ˆÙX™[]J
KÊ[]WÜÙXÛÛ™\WØØ\™
Kˆ
Bˆœ›İ]Jˆ‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKİÙXšÛÚÈ‹ˆÙXœÜİ

KÊ™YÚ\İ\—İÙXšÛÚÊKˆ
Bˆœ›İ]Jˆ‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKÛ\İ]˜[œØXİ[Ûˆ‹ˆÙX™Ù]

KÊ\İİ˜[œØXİ[ÛŠKˆ
Bˆœ›İ]Jˆ‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKİ˜[œØXİ[ÛœÈ‹ˆÙX™Ù]

KÊ\İİ˜[œØXİ[ÛœÊKˆ
Bˆœ›İ]Jˆ‹ÜİXœØÜš\[ÛœËŞÜİX—ÚYKÜ™Y[™[\İ]˜[œØXİ[Ûˆ‹ˆÙXœÜİ

KÊ™Y[™Û\İİ˜[œØXİ[ÛŠKˆ
NÂŸB