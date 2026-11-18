#![forbid(unsafe_code)]
//! Service 1: Health & SandboxGuard endpoints.

use actix_web::{HttpResponse, web};
use serde::Deserialize;
use serde_json::json;
use some_paymob::prelude::*;

use super::{ApiServerError, AppState};

/// `GET /health` — Service health probe.
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
    match raw.trim().to_ascii_lowercase().as_str() {
        "card" => Ok(SandboxPaymentChannel::Card),
        "wallet" => Ok(SandboxPaymentChannel::Wallet),
        "kiosk" => Ok(SandboxPaymentChannel::Kiosk),
        "bnpl" => Ok(SandboxPaymentChannel::Bnpl),
        _ => Err(PaymobError::ValidationError {
            field: "channel".to_owned(),
            reason: "expected one of: card, wallet, kiosk, bnpl".to_owned(),
        }
        .into()),
    }
}

/// `POST /sandbox/check` — Validates sandbox credential age and channel support.
pub async fn sandbox_check(
    body: web::Json<SandboxCheckPayload>,
) -> Result<HttpResponse, ApiServerError> {
    let channel = parse_sandbox_channel(&body.channel)?;
    let report = SandboxGuard::check_constraints(&SandboxCheckRequest {
        is_sandbox: body.is_sandbox,
        credential_age_days: body.credential_age_days,
        channel,
    });
    if let Some(first_err) = report.errors.first() {
        return Err(ApiServerError::Sandbox(first_err.clone()));
    }
    let warnings: Vec<String> = report.warnings.iter().map(ToString::to_string).collect();
    Ok(HttpResponse::Ok().json(json!({
        "ok": report.is_ok(),
        "warnings": warnings,
    })))
}

/// Registers Service 1 routes.
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health_check))
        .route("/sandbox/check", web::post().to(sandbox_check));
}
