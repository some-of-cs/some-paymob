#![forbid(unsafe_code)]

#[path = "../examples/axum_server.rs"]
pub mod axum_server;

#[path = "axum_server_example_integration/common.rs"]
mod common;

#[path = "axum_server_example_integration/positive_and_boundaries.rs"]
mod positive_and_boundaries;

#[path = "axum_server_example_integration/negative_and_error_workflows.rs"]
mod negative_and_error_workflows;
