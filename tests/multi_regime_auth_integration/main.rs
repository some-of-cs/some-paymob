#![forbid(unsafe_code)]
//! Integration tests for US-1.2.0 (4-Regime Auth Strategy, Lock-Free Cache, Accept JWT,
//! Payouts OAuth2, Partner Auth, and zero secret leakage in `Debug`).

mod accept_jwt;
mod cache;
mod common;
mod partner;
mod payouts_oauth;
mod strategy;
