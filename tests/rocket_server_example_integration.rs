#![forbid(unsafe_code)]
//! Full Edge/Error/Negative Integration Test Suite for `examples/rocket_server.rs`.

#[path = "../examples/rocket_server.rs"]
mod rocket_server;

#[path = "rocket_server_example_integration/negative_and_error_workflows.rs"]
mod negative_and_error_workflows;
#[path = "rocket_server_example_integration/positive_and_boundaries.rs"]
mod positive_and_boundaries;
