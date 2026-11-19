#![forbid(unsafe_code)]
//! Full Edge/Error/Negative Integration Test Suite for `examples/tonic_grpc_server.rs`.

#[path = "../examples/tonic_grpc_server.rs"]
#[allow(dead_code)]
mod tonic_grpc_server;

#[path = "tonic_grpc_server_example_integration/negative_and_error_workflows.rs"]
mod negative_and_error_workflows;
#[path = "tonic_grpc_server_example_integration/positive_and_boundaries.rs"]
mod positive_and_boundaries;
