#![forbid(unsafe_code)]
//! Unit 4: Positive E2E and boundary integration tests for `examples/tonic_grpc_server.rs`.

#[path = "boundary_conditions.rs"]
mod boundary_conditions;
#[path = "positive_e2e.rs"]
mod positive_e2e;
#[path = "positive_helpers.rs"]
mod positive_helpers;
#[path = "positive_mocks_core.rs"]
mod positive_mocks_core;
#[path = "positive_mocks_recurring.rs"]
mod positive_mocks_recurring;
