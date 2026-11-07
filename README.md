# some-paymob

<div align="center">

> **Idiomatic, high-performance Rust SDK, Unified Intention & Payouts engine, and constant-time HMAC webhook verifier for the [Paymob API](https://developers.paymob.com/).**  
> Modeled after [`stripe-node`](https://github.com/stripe/stripe-node) & [`some-stripe`](https://github.com/some-of-cs/some-stripe) ergonomics • Built for the Rust 2024 edition • Core Egypt & MENA provider for [`some-payment`](https://github.com/some-of-cs/some-payment)

[![Crates.io](https://img.shields.io/crates/v/some-paymob.svg)](https://crates.io/crates/some-paymob)
[![Docs.rs](https://docs.rs/some-paymob/badge.svg)](https://docs.rs/some-paymob)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust: Edition 2024](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://github.com/some-of-cs/some-paymob)
[![Ecosystem: some-payment](https://img.shields.io/badge/ecosystem-some--payment-8a2be2.svg)](https://github.com/some-of-cs/some-payment)
[![Sponsor](https://img.shields.io/badge/Sponsor-%E2%99%A5-ff69b4.svg)](https://github.com/sponsors/some-of-cs)

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

1. **Dual-Generation API Surface (Unified Intention API vs Legacy 3-Step Accept Flow)**: Modern [Paymob Create Intention (`/v1/intention/`)](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) authenticates via `Authorization: Token <sk_...>` and issues a `client_secret` for Unified Checkout and Pixel components, whereas legacy [Paymob Accept APIs](https://developers.paymob.com/paymob-docs/integration-paths/apis) require chaining Auth Token -> Order Registration -> Payment Key generation. `some-paymob` unifies both behind ergonomic [`stripe-node`](https://github.com/stripe/stripe-node)-style namespaces (`paymob.intentions()`, `paymob.transactions()`, `paymob.payouts()`).
2. **Multi-Shape HMAC-SHA512 Webhook Concatenation**: [Paymob Webhook Callbacks & HMAC](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/overview) require lexicographical field extraction and concatenation across three distinct callback shapes: [HMAC Transaction Callbacks](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-transaction-callback) (20 concatenated fields including nested `order.id` and `source_data.*`, with `hmac` in query params), [HMAC Card Token Callbacks](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens), and [Subscription Callbacks](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback) (where `hmac` is embedded inside the JSON body). `some-paymob` verifies all three in strict constant time.
3. **Outbound Disbursements (`Paymob Send`)**: [Paymob Payouts](https://developers.paymob.com/paymob-docs/beyond-payments/payouts) (`/api/secure/disburse/`) uses separate OAuth2/Bearer token lifecycles and issuer codes (`vodafone`, `etisalat`, `orange`, `aman`, `bank_wallet`, `bank_card`). `some-paymob` provides a strongly typed `client.payouts()` namespace with automated token refresh.
4. **Native Multi-Gateway Composition**: Built as a core regional provider in [`some-payment`](https://github.com/some-of-cs/some-payment) alongside [`some-stripe`](https://github.com/some-of-cs/some-stripe) and [`some-moyasar`](https://github.com/some-of-cs/some-moyasar), allowing applications to pair Stripe Identity KYC with Paymob EGP card/wallet/ValU collection and instant Vodafone Cash payouts.

---

## Key Features

- **Familiar [`stripe-node`](https://github.com/stripe/stripe-node) & [`some-stripe`](https://github.com/some-of-cs/some-stripe) Hierarchy**: Thread-safe `PaymobClient` (`Arc<PaymobConfig>`) exposing `.intentions()`, `.transactions()`, `.tokens()`, `.subscriptions()`, `.payouts()`, `.partner()`, and `.webhooks()`.
- **Unified Intention & Pixel Checkout**: First-class builder for [Create Intention (`POST /v1/intention/`)](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) and Update Intention (`PUT /v1/intention/`), supporting multi-integration IDs, [Affordability Widget](https://developers.paymob.com/paymob-docs/developers/checkout-experiences/affordability-widget) `pre_selected_plan` installments, and [Split Payment Features](https://developers.paymob.com/paymob-docs/payments-and-features/core-features/split-features).
- **Comprehensive Regional Payment Methods**: Cards (`MIGS`/`MPGS`, `Meza`, `Mada`, `OmanNet`), Mobile Wallets (`Vodafone Cash`, `e& money`, `Orange Cash`, `WE Pay`), Kiosk Reference Bills (`Fawry` / `Aman` / `Masary`), BNPL (`ValU`, `Sympl`, `Souhoola`, `Tabby`, `Tamara`), and [Apple Pay / Google Pay](https://developers.paymob.com/).
- **Paymob Send (Payouts & Cash-In Engine)**: Instant disbursements via [`/api/secure/disburse/`](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin) across [Vodafone Cash-In](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin), [Etisalat Cash](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/etisalat-cash), Bank Wallets, and Instant Bank transfers, plus [Disbursement Inquiries & Budget Checks](https://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires).
- **Constant-Time HMAC-SHA512 Verification Engine**: Zero-timing-attack verification (`subtle::ConstantTimeEq`) across [Transaction Processed Callbacks](https://developers.paymob.com/paymob-docs/manage-callback/transaction-callbacks), [Card Token Callbacks](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens), [Subscription Callbacks](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback), and [Payout Callbacks](https://developers.paymob.com/paymob-docs/developers/payouts-apis/payout-callbacks).

---

## Comprehensive Feature Flag Matrix

| Feature Flag | Default | Dependencies Added | Included Modules, Services & Capabilities |
| :--- | :---: | :--- | :--- |
| `default` | **Yes** | `reqwest`, `serde`, `uuid`, `secrecy`, `thiserror` | `core`, `intentions`, `transactions`, `webhook-engine`, `rustls-tls` ([Paymob Portal](https://developers.paymob.com/)) |
| `core` | **Yes** | `serde`, `serde_json`, `secrecy`, `chrono` | `PaymobClient`, region-aware base URL router (`egy`, `ksa`, `uae`, `omn`, `pak`), `SecretKey` (`egy_sk_...`), `PublicKey` (`egy_pk_...`), `PaymobError` ([Glossary](https://developers.paymob.com/paymob-docs/need-help/glossary)) |
| `intentions` | **Yes** | `core` | `client.intentions()` — [Create Intention (`POST /v1/intention/`)](https://developers.paymob.com/paymob-docs/intention-apis/create-intention), Update Intention (`PUT`), Unified Checkout & Pixel URL helpers |
| `transactions` | **Yes** | `core` | `client.transactions()` — Capture, Void, Refund, Transaction Inquiry, and [Split Features](https://developers.paymob.com/paymob-docs/payments-and-features/core-features/split-features) ([Egypt Hub](https://developers.paymob.com/hub/egypt)) |
| `webhook-engine` | **Yes** | `hmac`, `sha2`, `subtle`, `hex` | `PaymobHmacVerifier` — Constant-time HMAC-SHA512 verifier for [Transaction](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-transaction-callback), [Card Token](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens), and [Subscription](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback) webhooks |
| `tokens` | No | `core`, `transactions` | `client.tokens()` — Saved card tokenization and Customer-Initiated / Merchant-Initiated recurring MOTO charges ([Create Intention](https://developers.paymob.com/paymob-docs/intention-apis/create-intention)) |
| `subscriptions` | No | `core`, `tokens` | `client.subscriptions()` — Subscription plans, recurring billing lifecycles, and [Subscription HMAC Callbacks](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback) |
| `payouts` | No | `core` | `client.payouts()` — [Paymob Send Disbursements](https://developers.paymob.com/paymob-docs/beyond-payments/payouts) ([Vodafone Cash](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin), [Etisalat Cash](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/etisalat-cash), Bank Transfers) & [Inquiries](https://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires) |
| `partner-onboarding` | No | `core` | `client.partner()` — Partner Login, Partner API Key provisioning, Merchant Registration, and Partner HMAC Secret retrieval ([Partner APIs](https://developers.paymob.com/paymob-docs/intention-apis/create-intention)) |
| `some-payment-trait` | No | `some-payment-core` | Implements `PaymentCapability`, `PayoutCapability`, and `WebhookCapability` traits for [`some-payment`](https://github.com/some-of-cs/some-payment) |
| `full` | No | All of the above | Enables all Paymob Accept, Intention, Subscription, Payouts, Partner Onboarding, and [`some-payment`](https://github.com/some-of-cs/some-payment) modules |

---

## Installation

### Standard Configuration (Unified Intentions, Transactions & Webhook HMAC Engine)

```toml
[dependencies]
some-paymob = "0.1.0"
tokio = { version = "1", features = ["full"] }
```

### Full Enterprise Configuration (With Paymob Send Payouts, Subscriptions & `some-payment` Adapter)

```toml
[dependencies]
some-paymob = { version = "0.1.0", features = [
    "full",
    "payouts",
    "subscriptions",
    "some-payment-trait"
] }
```

---

## Quick Start

### 1. Creating a Unified Checkout Intention (Cards, Mobile Wallets, Kiosk & ValU BNPL)

Using [Paymob's Create Intention API (`POST /v1/intention/`)](https://developers.paymob.com/paymob-docs/intention-apis/create-intention):

```rust,no_run
use some_paymob::prelude::*;

#[tokio::main]
async fn main() -> Result<(), PaymobError> {
    // Region is automatically inferred from the secret key prefix (`egy_sk_...`, `ksa_sk_...`, `are_sk_...`)
    let paymob = PaymobClient::new("egy_sk_test_YOUR_SECRET_KEY")?;

    let intention = paymob
        .intentions()
        .create(&CreateIntentionParams {
            amount: 250_000, // 2,500.00 EGP in cents (piastres)
            currency: Currency::EGP,
            payment_methods: vec![
                PaymentMethodIntegration::Id(412345), // Online Card (MIGS/MPGS)
                PaymentMethodIntegration::Id(412346), // Mobile Wallets (Vodafone/Orange/e&)
                PaymentMethodIntegration::Id(412347), // ValU BNPL
            ],
            items: vec![IntentionItem {
                name: "Enterprise Annual License".into(),
                amount: 250_000,
                description: Some("Annual SaaS subscription".into()),
                quantity: 1,
            }],
            billing_data: BillingData {
                first_name: "Maher".into(),
                last_name: "Aladdin".into(),
                email: "maher@example.com".into(),
                phone_number: "+201012345678".into(),
                country: Some("EG".into()),
                city: Some("Mansoura".into()),
                ..Default::default()
            },
            special_reference: Some("ORD-EG-2026-0091".into()),
            notification_url: Some("https://api.example.com/webhooks/paymob".into()),
            redirection_url: Some("https://app.example.com/checkout/complete".into()),
            extras: None,
            pre_selected_plan: None,
        })
        .await?;

    println!(
        "Redirect to Unified Checkout: {}",
        paymob.intentions().unified_checkout_url("egy_pk_test_YOUR_PUBLIC_KEY", &intention.client_secret)
    );
    Ok(())
}
```

### 2. Disbursing Instant Payouts via Paymob Send (`payouts` Feature)

Disburse funds directly to recipient mobile wallets or bank accounts via [Paymob Payouts (`/api/secure/disburse/`)](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin):

```rust,no_run
use some_paymob::prelude::*;

async fn disburse_wallet_payout(paymob: &PaymobClient) -> Result<(), PaymobError> {
    let disbursement = paymob
        .payouts()
        .disburse(&CreateDisbursementParams {
            issuer: DisbursementIssuer::Vodafone,
            amount: 1500.00, // 1,500.00 EGP
            msisdn: Some("01012345678".into()),
            client_reference_id: Some("PAYOUT-DRIVER-8841".into()),
            bank_card_number: None,
            bank_code: None,
            full_name: None,
        })
        .await?;

    println!(
        "Disbursement transaction_id={} status={}",
        disbursement.transaction_id, disbursement.disbursement_status
    );
    Ok(())
}
```

---

## Constant-Time HMAC Webhook Verification Engine

Per [Paymob's HMAC Transaction Callback specification](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-transaction-callback), Paymob computes an `HMAC-SHA512` hex digest over 20 lexicographically ordered fields from `obj` (`amount_cents`, `created_at`, `currency`, `error_occured`, `has_parent_transaction`, `id`, `integration_id`, `is_3d_secure`, `is_auth`, `is_capture`, `is_refunded`, `is_standalone_payment`, `is_voided`, `order.id`, `owner`, `pending`, `source_data.pan`, `source_data.sub_type`, `source_data.type`, `success`). `some-paymob` extracts these fields without intermediate heap string concatenation and compares the 64-byte SHA-512 tag in strict constant time:

```rust
use some_paymob::webhook_engine::{PaymobHmacVerifier, PaymobWebhookPayload};

fn handle_paymob_webhook(raw_body: &[u8], query_hmac: Option<&str>, hmac_secret: &str) {
    let verifier = PaymobHmacVerifier::new(hmac_secret);

    // Automatically detects Transaction, CardToken, or Subscription callback shape
    match verifier.verify_and_construct(raw_body, query_hmac) {
        Ok(PaymobWebhookPayload::Transaction(tx)) => {
            if tx.success && !tx.pending {
                println!(
                    "Verified Paymob payment: tx_id={}, order_id={}, amount_cents={} {}",
                    tx.id, tx.order.id, tx.amount_cents, tx.currency
                );
            }
        }
        Ok(PaymobWebhookPayload::CardToken(token)) => {
            println!("Verified saved card token: {} (masked: {})", token.token, token.masked_pan);
        }
        Ok(PaymobWebhookPayload::Subscription(sub)) => {
            println!("Verified subscription lifecycle update: {:?}", sub);
        }
        Err(err) => {
            eprintln!("SECURITY ALERT: Rejected tampered Paymob webhook: {err}");
        }
    }
}
```

---

## Complete Paymob Services & API Coverage

| Service Namespace | Accessor | Endpoints & Capabilities | Official Documentation |
| :--- | :--- | :--- | :--- |
| **Unified Intentions** | `client.intentions()` | `POST /v1/intention/`, `PUT /v1/intention/`, Unified Checkout & Pixel session builders, [Affordability Widget](https://developers.paymob.com/paymob-docs/developers/checkout-experiences/affordability-widget) plans | [Create Intention](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) |
| **Transactions & Actions** | `client.transactions()` | Auth/Capture, Void, Refund, Transaction Inquiry by ID / `merchant_order_id`, and [Split Features](https://developers.paymob.com/paymob-docs/payments-and-features/core-features/split-features) | [Paymob Egypt Hub](https://developers.paymob.com/hub/egypt) |
| **Card Tokenization & CIT/MIT** | `client.tokens()` | Saved Card Token creation, Customer-Initiated Transactions (CIT), and recurring MOTO charges | [HMAC Card Token Callback](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/hmac/hmac-for-card-tokens) |
| **Subscriptions** | `client.subscriptions()` | Recurring billing plans, subscription state management, and body-embedded HMAC verification | [Subscription Callbacks](https://developers.paymob.com/paymob-docs/developers/subscription/hmac-calculation-for-subscription-callback) |
| **Paymob Send (Payouts)** | `client.payouts()` | `POST /api/secure/disburse/` ([Vodafone](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/vodafone-cashin), [Etisalat](https://developers.paymob.com/paymob-docs/developers/payouts-apis/cashin-api/etisalat-cash), Orange, Bank Card/Wallet), [Budget & Disbursement Inquiries](https://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires), [Payout Callbacks](https://developers.paymob.com/paymob-docs/developers/payouts-apis/payout-callbacks) | [Payouts Overview](https://developers.paymob.com/paymob-docs/beyond-payments/payouts) |
| **Partner Onboarding** | `client.partner()` | Partner Login, Partner API Key creation, Retrieve Partner HMAC Secret, Register Merchant, Submit Onboarding Step | [Partner Onboarding APIs](https://developers.paymob.com/paymob-docs/intention-apis/create-intention) |
| **Webhook HMAC Engine** | `client.webhooks()` | Constant-time `HMAC-SHA512` verification for Transaction Processed, Response Redirect, Card Token, and Subscription callbacks | [Webhook & HMAC Overview](https://developers.paymob.com/paymob-docs/developers/webhook-callbacks-and-hmac/overview) |

---

## Cross-Gateway Interoperability with `some-payment`

`some-paymob` is built to work standalone or as a composable gateway inside **[`some-payment`](https://github.com/some-of-cs/some-payment)** alongside **[`some-stripe`](https://github.com/some-of-cs/some-stripe)** and **[`some-moyasar`](https://github.com/some-of-cs/some-moyasar)**:

- **Country-Aware Payment Routing**: Automatically route `EG` customers to `some-paymob` (EGP Cards, Vodafone Cash, Fawry Kiosk, ValU BNPL), `SA` customers to [`some-moyasar`](https://github.com/some-of-cs/some-moyasar) (Mada, STC Pay, SADAD), and international customers to [`some-stripe`](https://github.com/some-of-cs/some-stripe).
- **Composable Cross-Gateway Capabilities**: Combine [`some-stripe`](https://github.com/some-of-cs/some-stripe) Identity (`stripe.identity().verification_sessions()`) for KYC verification with `some-paymob` for localized checkout collection (`paymob.intentions()`) and instant local wallet disbursements (`paymob.payouts()`).

---

## Backers & Corporate Sponsors

`some-paymob` (and the [`some-payment`](https://github.com/some-of-cs/some-payment) / [`some-stripe`](https://github.com/some-of-cs/some-stripe) ecosystem) is an independent, community-driven open-source project. If your business relies on this crate to process transactions or verify webhooks, corporate sponsorship directly finances continuous maintenance, zero-day security updates, and upcoming module expansion.

<div align="center">

[![Become a Sponsor](https://img.shields.io/badge/Become%20a%20Sponsor-%E2%99%A5-ea4aaa?style=for-the-badge)](https://github.com/sponsors/some-of-cs)

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
| *Your company logo here*<br>[Become a Visionary Sponsor](https://github.com/sponsors/some-of-cs) | *Your company logo here*<br>[Become a Gold Partner](https://github.com/sponsors/some-of-cs) | *Your company logo here*<br>[Become a Silver Backer](https://github.com/sponsors/some-of-cs) | [Join our Individual Backers](https://github.com/sponsors/some-of-cs) |

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
