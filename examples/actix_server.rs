#![forbid(unsafe_code)]
//! Reference Actix-Web HTTP Server demonstrating all 14 `some-paymob` services
//! and all 5 constant-time HMAC-SHA512 webhook verification protocols (`A`–`E`).

#[path = "actix_server_routes/mod.rs"]
pub mod routes;

pub use routes::{ApiServerError, AppState, MAX_JSON_PAYLOAD_BYTES};

use actix_web::web;

/// Configures the full Actix-Web service surface and bounded JSON extractor limit (4 MiB).
pub fn configure_app(cfg: &mut web::ServiceConfig) {
    cfg.app_data(web::JsonConfig::default().limit(MAX_JSON_PAYLOAD_BYTES));
    routes::configure_unit_1(cfg);
    routes::configure_unit_2(cfg);
    routes::configure_unit_3(cfg);
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    Ok(())
}
