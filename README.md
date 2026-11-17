# some-paymob

<div align="center">

> **Idiomatic, high-performance Rust SDK, Unified Intention & Payouts engine, and constant-time HMAC webhook verifier for the [Paymob API](https://developers.paymob.com/).**  
> Modeled after [`stripe-node`](https://github.com/stripe/stripe-node) & [`some-stripe`](https://github.com/some-of-cs/some-stripe) ergonomics • Built for the Rust 2024 edition • Core Egypt & MENA provider for [`some-payment`](https://github.com/some-of-cs/some-payment)

[![Crates.io](https://img.shields.io/crates/v/some-paymob.svg)](https://crates.io/crates/some-paymob)
[![Docs.rs](https://docs.rs/some-paymob/badge.svg)](https://docs.rs/some-paymob)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust: Edition 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://github.com/some-of-cs/some-paymob)
[![Ecosystem: some-payment](https://img.shields.io/badge/ecosystem-some--payment-8a2be2.svg)](https://github.com/some-of-cs/some-payment)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%99%A5-ff69b4.svg)](https://github.com/sponsors/maheraladdin)

[Why some-paymob?](#why-some-paymob) •
[Key Features](#key-features) •
[Feature Flags](#comprehensive-feature-flag-matrix) •
[Quick Start](#quick-start) •
[Webhook HMAC Security](#constant-time-hmac-webhook-verification-engine) •
[API Coverage](#complete-paymob-services--api-coverage) •
[some-payment Ecosystem](#cross-gateway-interoperability-with-some-payment) •
[Sponsors](#backers--corporate-sponsors)

</div>

---

## Why some-paymob?

Integrating [Paymob](https://developers.paymob.com/paymob-docs) across Egypt (`EGP`), Saudi Arabia (`SAR`), UAE (`AED`), Oman (`OMR`), and Pakistan (`PKR`) in high-concurrency Rust backend services involves distinct protocol complexities:

1. **Dual-Generation API Surface (Unified Intention API vs Legacy 3-Step Accept Flow)**: Modern [Paymob Create Intention (`/v1/intention/`)](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) authenticates via `Authorization: Token <sk_...>` and issues a `client_secret` for Unified Checkout and Pixel components, whereas legacy [Paymob Accept APIs](https://developers.paymob.com/paymob-docs/integration-paths/apis) require chaining Auth Token -> Order Registration -> Payment Key generation. `some-paymob` unifies both behind ergonomic [`stripe-node`](https://github.com/stripe/stripe-node)-style namespaces (`paymob.intentions()`, `paymob.checkout()`, `paymob.legacy_v2()`, `paymob.manage()`, `paymob.inquiries()`, `paymob.payouts()`).
2. **4-Regime Single-Flight Authentication & `$ENV_VARNAME` / `.env` Resolution**: Automatically routes Regime 1 (`Authorization: Token <secret_key>`), Regime 2 (`POST /api/auth/tokens` 60-minute JWT with single-flight `401` cache eviction & retry), Regime 3 (`POST /api/secure/o/token/` OAuth 2.0 `password` & `refresh_token` grants), and Regime 4 (Partner Bearer & API Key headers), while resolving `"$ENV_VARNAME"` references from process environment variables or `.env` files at runtime with `secrecy::SecretString` and `zeroize::ZeroizeOnDrop`.
3. **Multi-Shape HMAC-SHA512 Webhook Concatenation (Protocols A–E)**: [Paymob Webhook Callbacks & HMAC](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/overview) require lexicographical field extraction and concatenation across distinct callback shapes: [HMAC Transaction Callbacks](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-transaction-callback) (20 concatenated fields including nested `order.id` and `source_data.*`), Redirect Query Callbacks, [HMAC Card Token Callbacks](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens), [Subscription Callbacks](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback) (`"{trigger_type}for{subscription_data.id}"`), and Payout Disbursement/Topup Callbacks. `some-paymob` verifies all five protocols in strict constant time (`subtle::ConstantTimeEq`).
4. **Outbound Disbursements (`Paymob Send`)**: [Paymob Payouts](https://developers.paymob.com/paymob-docs/beyond-payments/payouts) (`/api/secure/disburse/`) uses separate OAuth2/Bearer token lifecycles and issuer codes (`vodafone`, `etisalat`, `orange`, `bank_wallet`, `bank_card`, `instant_bank`, `egyptian_post`), Aman cancellation, Bulk Disbursements, Budget/Transaction/Topup Inquiries, and Topup Requests (`<= 2.8 MB` proof guard).
5. **Native Multi-Gateway Composition**: Built as a core regional provider in [`some-payment`](https://github.com/some-of-cs/some-payment) alongside [`some-stripe`](https://github.com/some-of-cs/some-stripe) and [`some-moyasar`](https://github.com/some-of-cs/some-moyasar), implementing `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` plus the `PaymobExt` escape hatch.

---

## Key Features

- **Familiar [`stripe-node`](https://github.com/stripe/stripe-node) & [`some-stripe`](https://github.com/some-of-cs/some-stripe) Hierarchy**: Thread-safe `PaymobClient` (`Arc<PaymobCore>`) exposing `.intentions()`, `.checkout()`, `.legacy_v2()`, `.manage()`, `.inquiries()`, `.quicklinks()`, `.saved_cards()`, `.subscriptions()`, `.payouts()`, `.onboarding()`, and `.webhooks()`.
- **Zero-Float Minor-Unit Monetary Safety & `[REDACTED]` PII Hygiene**: Enforces `#![forbid(unsafe_code)]`, integer minor-unit monetary representations (`MinorUnitAmount(u64)` / `u64`), `SecretString` + `ZeroizeOnDrop` credential storage, and automatic `[REDACTED]` masking of keys, tokens, PANs, MSISDNs, emails, and national IDs in `Debug` and `Display`.
- **Unified Intention, Pixel & Affordability Widget Checkout**: Builders for [Create Intention (`POST /v1/intention/`)](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) and Update Intention (`PUT /v1/intention/`), Unified Checkout & Pixel JS configs (`ApplePaySettings`, `GooglePaySettings`), [Affordability Widget](https://developers.paymob.com/paymob-docs/developers/checkout-experiences/affordability-widget) `pre_selected_plan` installments, and [Split Payment & Convenience Fee](https://developers.paymob.com/paymob-docs/payments-and-features/core-features/split-features) engines.
- **Paymob Send (Payouts & Cash-In Engine)**: Instant disbursements via [`/api/secure/disburse/`](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin) across 7 issuers (`vodafone`, `etisalat`, `orange`, `bank_wallet`, `bank_card`, `instant_bank`, `egyptian_post`), Aman cancellation, Bulk Disbursements, and [Disbursement, Budget & Topup Inquiries](https://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires).
- **Constant-Time HMAC-SHA512 Verification Engine**: Zero-timing-attack verification (`subtle::ConstantTimeEq`) across [Transaction Processed Callbacks](https://developers.paymob.com/paymob-docs/manage-callback/transaction-callbacks), Redirect Callbacks, [Card Token Callbacks](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens), [Subscription Callbacks](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback), and [Payout Callbacks](https://developers.paymob.com/paymob-docs/developers/payouts-apis/payout-callbacks) with replay protection (`IdempotentWebhookGuard`).

---

## Comprehensive Feature Flag Matrix

| Feature Flag | Default | Dependencies Added | Included Modules, Services & Capabilities |
| :--- | :---: | :--- | :--- |
| `default` | **Yes** | `reqwest`, `serde`, `uuid`, `secrecy`, `thiserror`, `zeroize` | `core`, `webhooks`, `intentions`, `manage`, `inquiries`, `quicklinks`, `splits`, `saved-cards`, `subscriptions`, `payouts`, `onboarding`, `rustls-tls` |
| `core` | **Yes** | `reqwest`, `serde`, `secrecy`, `zeroize`, `arc-swap` | `PaymobClient`, 5-region URL router (`Egypt`, `SaudiArabia`, `Uae`, `Oman`, `Pakistan`, `Custom`), 4-regime `AuthManager`, `$ENV_VARNAME` / `.env` credential resolution, `MinorUnitAmount`, `Currency`, `PaymobError` |
| `webhooks` (`webhook-engine`) | **Yes** | `core`, `hmac`, `sha2`, `subtle`, `hex` | `PaymobWebhookEngine` — Constant-time HMAC-SHA512 verifier for Protocols A–E and `IdempotentWebhookGuard` |
| `intentions` | **Yes** | `core` | `client.intentions()`, `client.checkout()` — `POST`/`PUT /v1/intention/`, Unified Checkout, Pixel JS, and Affordability Widget builders |
| `legacy-v2` | No | `core` | `client.legacy_v2()` — Opt-in 3-step Legacy Accept v2 checkout (`auth_token` -> `order` -> `payment_key` -> `iframe`) |
| `manage` | **Yes** | `core` | `client.manage()` — Full/partial `refund`, `void`, and two-step Auth/`capture` |
| `inquiries` | **Yes** | `core` | `client.inquiries()` — Transaction inquiry by ID, by `order_id` / `merchant_order_id`, full order record, and saved card tokens |
| `quicklinks` | **Yes** | `core` | `client.quicklinks()` — Hosted payment link creation (`POST /api/ecommerce/payment-links`) and cancellation |
| `splits` | **Yes** | `core` | `resources::splits` — Marketplace `SplitRecipientRule`, 3-card `SplitPaymentConfig`, and integer basis-point `ConvenienceFeeConfig` |
| `saved-cards` (`tokens`) | **Yes** | `core` | `client.saved_cards()` — CIT/MIT saved-card charges, Mobile Wallet, Kiosk aggregator, and raw `POST /api/acceptance/payments/pay` |
| `subscriptions` | **Yes** | `core` | `client.subscriptions()` — Subscription plans CRUD, subscription lifecycle (`suspend`, `resume`, `cancel`), card vault, and `refund_last_transaction` |
| `payouts` | **Yes** | `core` | `client.payouts()` — Paymob Send OAuth 2.0 (`auth()`), 7-issuer Instant & Bulk Cashin (`cashin()`), Inquiries & User Budget (`inquiries()`), and Topups (`topups()`) |
| `onboarding` (`partner-onboarding`) | **Yes** | `core` | `client.onboarding()` — Partner login, API key provisioning, HMAC secret retrieval, merchant registration, onboarding flow schema, and `MerchantScopedClient` |
| `some-payments-adapter` (`some-payment-trait`) | No | `core`, `webhooks`, `intentions`, `manage`, `saved-cards`, `subscriptions`, `splits`, `payouts` | Implements `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, `PayoutProvider`, and `PaymobExt` escape hatch |
| `test-utils` | No | `core`, `webhooks`, `wiremock` | `PaymobMockServer` (Accept & Payouts offline harness), official HMAC test vectors, and `SandboxGuard` |
| `full` | No | All of the above | Enables every module, legacy flow, unified adapter, and test harness |

---

## Installation

### Standard Configuration

```toml
[dependencies]
some-paymob = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

### Full Enterprise Configuration (With Legacy v2, `some-payments` Adapter & Offline Test Harness)

```toml
[dependencies]
some-paymob = { version = "0.1.0", features = [
    "full",
    "some-payments-adapter",
    "test-utils"
] }
```

---

## Quick Start

### 1. Creating a Unified Checkout Intention (Cards, Mobile Wallets, Kiosk & ValU BNPL)

Using [Paymob's Create Intention API (`POST /v1/intention/`)](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) with integer minor-unit amounts (`MinorUnitAmount`) and `$ENV_VARNAME` / `.env` credential resolution:

```rust,no_run
use some_paymob::prelude::*;

#[tokio::main]
async fn main() -> Result<(), PaymobError> {
    // Supports direct keys or "$ENV_VARNAME" references resolved from process env or `.env`
    let config = ClientConfig::builder()
        .region(PaymobRegion::Egypt)
        .secret_key(SecretKey::new("$PAYMOB_SECRET_KEY")?)
        .public_key(PublicKey::new("$PAYMOB_PUBLIC_KEY")?)
        .build()?;
    let paymob = PaymobClient::new(config)?;

    let params = CreateIntentionParams::builder()
        .amount(MinorUnitAmount::new(250_000)) // 2,500.00 EGP in piasters (zero floats)
        .currency(Currency::EGP)
        .payment_methods(vec![
            PaymentMethodInput::IntegrationId(4097558),
            PaymentMethodInput::MethodName("card".to_owned()),
        ])
        .items(vec![IntentionItem::new(
            "Enterprise Annual License",
            MinorUnitAmount::new(250_000),
            1,
        )?])
        .billing_data(
            BillingData::builder()
                .first_name("Maher")
                .last_name("Mansour")
                .email("maher@example.com")
                .phone_number("+201012345678")
                .country("EG")
                .city("Mansoura")
                .build()?,
        )
        .special_reference("ORD-EG-2026-0091")
        .notification_url("https://api.example.com/webhooks/paymob")
        .redirection_url("https://app.example.com/checkout/complete")
        .build()?;

    let intention = paymob.intentions().create(params).await?;
    let checkout_url = paymob.checkout().unified_url(&intention.client_secret)?;
    println!("Redirect customer to Unified Checkout: {checkout_url}");
    Ok(())
}
```

### 2. Disbursing Instant Payouts via Paymob Send (`payouts` Feature)

Disburse funds directly to recipient mobile wallets or bank accounts via [Paymob Payouts (`/api/secure/disburse/`)](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin):

```rust,no_run
use some_paymob::prelude::*;

async fn disburse_wallet_payout(paymob: &PaymobClient) -> Result<(), PaymobError> {
    let params = MobileWalletCashinParams::new("01012345678", 150_000)
        .with_client_reference_id("PAYOUT-DRIVER-8841")
        .with_customer_bears_fees(false);

    let receipt = paymob.payouts().cashin().vodafone(params).await?;
    println!(
        "Disbursement transaction_id={} status={:?}",
        receipt.transaction_id, receipt.disbursement_status
    );
    Ok(())
}
```

---

## Constant-Time HMAC Webhook Verification Engine

Per [Paymob's HMAC Transaction Callback specification](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-transaction-callback), Paymob computes an `HMAC-SHA512` hex digest over 20 lexicographically ordered fields from `obj`. `some-paymob` extracts these fields and compares the 64-byte SHA-512 tag in strict constant time (`subtle::ConstantTimeEq`) across all 5 Paymob webhook protocols:

```rust,no_run
use some_paymob::prelude::*;

fn handle_paymob_webhook(
    raw_body: &str,
    query_hmac: Option<&str>,
    hmac_secret: &str,
) -> Result<(), WebhookError> {
    let engine = PaymobWebhookEngine::new(hmac_secret)?;

    match engine.construct_event(raw_body, query_hmac)? {
        WebhookEvent::TransactionProcessed(tx) => {
            if tx.obj.success && !tx.obj.pending {
                println!(
                    "Verified Paymob payment: tx_id={}, order_id={}, amount_cents={}",
                    tx.obj.id, tx.obj.order.id, tx.obj.amount_cents
                );
            }
        }
        WebhookEvent::CardTokenSaved(token) => {
            println!("Verified saved card token id={} masked={}", token.obj.id, token.obj.masked_pan);
        }
        WebhookEvent::SubscriptionLifecycle(sub) => {
            println!("Verified subscription update: sub_id={}", sub.subscription_data.id);
        }
        WebhookEvent::PayoutDisbursement(payout) => {
            println!("Verified payout callback: tx_id={}", payout.transaction_id);
        }
        _ => {}
    }
    Ok(())
}
```

---

## Complete Paymob Services & API Coverage

| Service Namespace | Accessor | Endpoints & Capabilities | Official Documentation |
| :--- | :--- | :--- | :--- |
| **Unified Intentions & Checkout** | `client.intentions()`, `client.checkout()` | `POST /v1/intention/`, `PUT /v1/intention/`, Unified Checkout & Pixel session builders, [Affordability Widget](https://developers.paymob.com/paymob-docs/developers/checkout-experiences/affordability-widget) plans | [Create Intention](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) |
| **Payment Lifecycle Management** | `client.manage()` | `POST /api/acceptance/void_refund/refund`, `POST /api/acceptance/void_refund/void`, `POST /api/acceptance/capture` | [Paymob Egypt Hub](https://developers.paymob.com/hub/egypt) |
| **Inquiries & QuickLinks** | `client.inquiries()`, `client.quicklinks()` | `GET /api/acceptance/transactions/{id}`, `POST /api/ecommerce/orders/transaction_inquiry`, `GET /api/ecommerce/orders/{id}`, `POST /api/acceptance/order_card_tokens`, `POST /api/ecommerce/payment-links` | [Transaction Inquiries](https://developers.paymob.com/hub/egypt) |
| **Saved Cards & CIT/MIT** | `client.saved_cards()` | `POST /api/acceptance/payments/pay` (`TOKEN`, `WALLET`, `AGGREGATOR` Kiosk, raw `source`) and `use_cvc_with_moto` validation | [HMAC Card Token Callback](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens) |
| **Subscriptions** | `client.subscriptions()` | Subscription plans CRUD, subscription lifecycle (`suspend`, `resume`, `cancel`), card vault, transaction history, and `refund_last_transaction` | [Subscription Callbacks](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback) |
| **Paymob Send (Payouts)** | `client.payouts()` | OAuth 2.0 (`POST /api/secure/o/token/`), 7-issuer Instant Cashin (`POST /api/secure/disburse/`), Aman Cancel, Bulk Disbursement, Budget/Tx/Topup Inquiries, Topup Requests | [Payouts Overview](https://developers.paymob.com/paymob-docs/beyond-payments/payouts) |
| **Partner Onboarding** | `client.onboarding()` | Partner Login, Partner API Key creation, Retrieve Partner HMAC Secret, Register Merchant, Onboarding Schema, Step Submission, `MerchantScopedClient` | [Partner Onboarding APIs](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) |
| **Webhook HMAC Engine** | `client.webhooks()` | Constant-time `HMAC-SHA512` verification for Protocols A–E and `IdempotentWebhookGuard` | [Webhook & HMAC Overview](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/overview) |

---

## Cross-Gateway Interoperability with `some-payment`

`some-paymob` is built to work standalone or as a composable gateway inside **[`some-payment`](https://github.com/some-of-cs/some-payment)** alongside **[`some-stripe`](https://github.com/some-of-cs/some-stripe)** and **[`some-moyasar`](https://github.com/some-of-cs/some-moyasar)**:

- **Country-Aware Payment Routing**: Automatically route `EG` customers to `some-paymob` (EGP Cards, Vodafone Cash, Fawry Kiosk, ValU BNPL), `SA` customers to [`some-moyasar`](https://github.com/some-of-cs/some-moyasar) (Mada, STC Pay, SADAD), and international customers to [`some-stripe`](https://github.com/some-of-cs/some-stripe).
- **Composable Cross-Gateway Capabilities**: Combine [`some-stripe`](https://github.com/some-of-cs/some-stripe) Identity (`stripe.identity().verification_sessions()`) for KYC verification with `some-paymob` for localized checkout collection (`paymob.intentions()`) and instant local wallet disbursements (`paymob.payouts()`).

---

## Backers & Corporate Sponsors

`some-paymob` (and the [`some-payment`](https://github.com/some-of-cs/some-payment) / [`some-stripe`](https://github.com/some-of-cs/some-stripe) ecosystem) is an independent, community-driven open-source project. If your business relies on this crate to process transactions or verify webhooks, corporate sponsorship directly finances continuous maintenance, zero-day security updates, and upcoming module expansion.

<div align="center">

[![Become a Sponsor](https://img.shields.io/badge/Become%20a%20Sponsor-%E2%99%A5-ea4aaa?style=for-the-badge)](https://github.com/sponsors/maheraladdin)

</div>

### Corporate Sponsorship Tiers & Benefits

| Tier | Monthly | Placement & Benefits |
| :--- | :--- | :--- |
| **🏆 Visionary** | $1,000 / mo | Large logo on `README.md`, website, and Docs.rs header • Prioritized GitHub issues • Dedicated quarterly roadmap review |
| **🥇 Gold Partner** | $500 / mo | Prominent logo on `README.md` • Prioritized PR reviews • Direct issue escalation |
| **🥈 Silver Backer** | $150 / mo | Company logo, link, and mention in `README.md` and release changelogs |
| **☕ Individual** | $10 – $50 / mo | Listed as a contributor and backer on GitHub |

### Sponsors & Backers Wall

<div align="center">

| 🏆 Visionary Sponsors | 🥇 Gold Partners | 🥈 Silver Backers | ☕ Individual Backers |
| :---: | :---: | :---: | :---: |
| *Your company logo here*<br>[Become a Visionary Sponsor](https://github.com/sponsors/maheraladdin) | *Your company logo here*<br>[Become a Gold Partner](https://github.com/sponsors/maheraladdin) | *Your company logo here*<br>[Become a Silver Backer](https://github.com/sponsors/maheraladdin) | [Join our Individual Backers](https://github.com/sponsors/maheraladdin) |

</div>

> [!TIP]
> **Need an Invoice or Procurement Documentation?**  
> We can issue formal VAT/sales-tax compliant invoices via Stripe Invoicing for corporate sponsors. Please contact [sponsors@someofcs.tech](mailto:sponsors@someofcs.tech).

---

## Contributing

We welcome community contributions! To ensure code quality and consistency:

1. Ensure all tests and doc-tests pass:
   ```bash
   cargo test
   ```
2. Ensure code compiles without warnings on the Rust 2024 edition:
   ```bash
   cargo clippy --all-targets -- -D warnings
   ```
3. Format all code according to standard `rustfmt`:
   ```bash
   cargo fmt --check
   ```

---

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).
