#![forbid(unsafe_code)]
//! Axum reference server entrypoint combining Services 1–14 and Protocols A–E.
//!
//! Exposes [`build_router`] for integration tests and `main` for standalone execution.

use std::sync::Arc;

use some_paymob::prelude::{ClientConfig, PaymobClient};

#[path = "axum_server/routes_core.rs"]
pub mod routes_core;
#[path = "axum_server/routes_platform.rs"]
pub mod routes_platform;
#[path = "axum_server/routes_recurring.rs"]
pub mod routes_recurring;
#[path = "axum_server/state.rs"]
pub mod state;

pub use state::{ApiServerError, AppState};

/// Builds the complete Axum [`axum::Router`] merging core, recurring, and platform routes.
pub fn build_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .merge(routes_core::router())
        .merge(routes_recurring::router())
        .merge(routes_platform::router())
        .with_state(state)
}

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ClientConfig::from_env()?;
    let client = PaymobClient::new(config)?;
    let state = Arc::new(AppState::new(client));
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    Ok(())
}
