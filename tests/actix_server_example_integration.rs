#![forbid(unsafe_code)]
//! Exhaustive Integration Test Suite for `examples/actix_server.rs` (Units 4 & 5).
//!
//! Covers:
//! - Unit 4a: Positive E2E tests across all 14 services (`200 OK` / `201 Created`) and Protocols A–E.
//! - Unit 4b: Boundary condition tests (`amount` 0/1/`u64::MAX`, bulk 0/1/1000/1001, inquiry IDs 0/1/1000/1001,
//!   bank-transfer proof sizes 0/2,936,012/2,936,013 bytes, splits 0/1/3/4 cards & bps != 10,000,
//!   `SandboxGuard` credential age 24/25/30 days).
//! - Unit 5: Negative validation, security/redaction, MOTO CVC mismatch, tampered/malformed/duplicate
//!   webhooks (`400`/`401`/`409`), `429 Retry-After`, `422` over-refund & environment mismatch, and
//!   Regime 2 `401` JWT eviction & single-flight retry.

#[path = "../examples/actix_server.rs"]
pub mod actix_server;

#[path = "actix_server_tests/helpers.rs"]
pub mod helpers;
#[path = "actix_server_tests/unit4_boundaries.rs"]
pub mod unit4_boundaries;
#[path = "actix_server_tests/unit4_positive_e2e.rs"]
pub mod unit4_positive_e2e;
#[path = "actix_server_tests/unit5_negative_and_recovery.rs"]
pub mod unit5_negative_and_recovery;
