#![forbid(unsafe_code)]
//! Deterministic offline test vectors, multi-regime `wiremock` server, and sandbox constraint guards (`US-8.2.0`).
//!
//! Pre-scaffolded module index for `feat/module-8-adapter-test-utils`.
//! Each submodule is owned by an independent implementation unit.

/// Unit 8.2.2: Stateful `PaymobMockServer` simulating Accept Acquiring & Payouts hosts.
pub mod mock_server;
/// Unit 8.2.3: Sandbox diagnostic helpers for 30-day credential age, Kiosk/BNPL warnings, and Webhook Testing Tool payloads.
pub mod sandbox;
/// Unit 8.2.1: Verbatim official Paymob JSON payloads and HMAC-SHA512 test vectors.
pub mod vectors;
