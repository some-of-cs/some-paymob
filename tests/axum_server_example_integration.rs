#![forbid(unsafe_code)]

#[path = "../examples/axum_server.rs"]
pub mod axum_server;

#[path = "axum_server_example_integration/common.rs"]
mod common;

#[path = "axum_server_example_integration/positive_e2e.rs"]
mod positive_e2e;

#[path = "axum_server_example_integration/boundary_conditions.rs"]
mod boundary_conditions;

#[path = "axum_server_example_integration/negative_and_error_workflows.rs"]
mod negative_and_error_workflows;
