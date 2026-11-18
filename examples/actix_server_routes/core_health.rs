#![forbid(unsafe_code)]
//! Service 1: Health & SandboxGuard endpoints.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

/// `GET /health` â€” Service health probe.
pub async fn health_check(state: web::Data<AppState>) -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "status": "ok",
        "region": format!("{:?}", state.client.config().region()),
    }))
}

#[derive(Debug, Deserialize)]
pub struct SandboxCheckPayload {
    pub is_sandbox: bool,
    pub credential_age_days: u64,
    pub channel: String,
}

fn parse_sandbox_channel(raw: &str) -> Result<SandboxPaymentChannel, ApiServerError> {
    match raw.trim().to_ascii_uppercase().as_str() {
        "card" => Ok(SandboxPaymentChannel::Card),
        "wallet" => Ok(SandboxPaymentChannel::Wallet),
        "kiosk" => Ok(SandboxPaymentChannel::Kiosk),
        "bnpl" => Ok(SandboxPaymentChannel::Bnpl),
        _ => Err(PaymobError::ValidationError {
            field: "channel".to_owned(),
            rea|ÛÛˆ™^XİYÛ™HÙˆØ\™Ø[]Ú[ÜÚË›œ‹×ÛİÛ™Y

KˆBˆš[Ê
JKˆBŸB‚‹ËËÈÔÕÜØ[™›ŞØÚXÚØ8 %˜[Y]\ÈØ[™›ŞÜ™Y[X[YÙH[™Ú[›™[İ\Ü‚œXˆ\Ş[˜È›ˆØ[™›ŞØÚXÚÊˆ›ÙNˆÙX’œÛÛØ[™›ŞÚXÚÔ^[ØY‹ŠHOˆ™\İ[™\ÜÛœÙK\TÙ\™\‘\œ›ÜˆÂˆ]Ú[›™[H\œÙWÜØ[™›ŞØÚ[›™[
	˜›ÙK˜Ú[›™[
OÎÂˆ]™\ÜHØ[™›ŞİX\™˜ÚXÚ×ØÛÛœİ˜Z[Ê	”Ø[™›ŞÚXÚÔ™\]Y\İÂˆ\×ÜØ[™›Şˆ›ÙKš\×ÜØ[™›ŞˆÜ™Y[X[ØYÙWÙ^\Îˆ›ÙK˜Ü™Y[X[ØYÙWÙ^\ËˆÚ[›™[ˆJNÂˆYˆ]ÛÛYJš\œİÙ\œŠHH™\Ü™\œ›ÜœË™š\œİ

HÂˆ™]\›ˆ\œŠ\TÙ\™\‘\œ›Ü”Ø[™›Ş
š\œİÙ\œ‹˜ÛÛ™J
JJNÂˆBˆ]Ø\›š[™ÜÎˆ™XÏİš[™ÏˆH™\ÜØ\›š[™ÜËš]\Š
K›X\
Ôİš[™Î×Üİš[™ÊK˜ÛÛXİ

NÂˆÚÊ™\ÜÛœÙN“ÚÊ
KšœÛÛŠœÛÛˆJÂˆ›ÚÈˆ™\Üš\×ÛÚÊ
KˆØ\›š[™ÜÈˆØ\›š[™ÜËˆJJJBŸB‚‹ËËÈ™YÚ\İ\œÈÙ\šXÙHH›İ]\Ë‚œXˆ›ˆÛÛ™šYİ\™JÙ™Îˆ	›]]ÙX”Ù\šXÙPÛÛ™šYÊHÂˆÙ™Ëœ›İ]J‹ÚX[‹ÙX™Ù]

KÊX[ØÚXÚÊJBˆœ›İ]J‹ÜØ[™›ŞØÚXÚÈ‹ÙXœÜİ

KÊØ[™›ŞØÚXÚÊJNÂŸB