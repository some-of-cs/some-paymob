#![forbid(unsafe_code)]
//! Full Edge/Error/Negative Integration Test Suite for `examples/rocket_server.rs`.

#[path = "../examples/rocket_server.rs"]
mod rocket_server;

mod negative_and_error_workflows;
mod positive_and_boundaries;
