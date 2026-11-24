# `some-paymob` — AI Agent Usage Guide

Rust microkernel SDK and constant-time HMAC-SHA512 webhook engine for Paymob (Egypt, KSA, UAE, Oman, Pakistan).

## Hard Invariants
- **Toolchain**: Rust edition `2024`, MSRV `1.85`, `#![forbid(unsafe_code)]`, `Send + Sync` (`Arc`-backed `PaymobClient`).
- **Money**: Integer minor units only via `MinorUnitAmount` (`u64`) — **never** `f32`/`f64`. `EGP`/`SAR`/`AED`/`PKR` = 2 decimals; `OMR` = 3 decimals (baisa).
- **Secrets**: `SecretKey`, `PublicKey`, `ApiKey`, `HmacSecret`, and `SecretString` redact to `[REDACTED]` in `Debug`/`Display` and zeroize on drop. Values starting with `$VAR` or `${VAR}` resolve from env/`.env`; prefix literal `$` secrets with `$$`.
- **Transport**: HTTPS + TLS 1.3 enforced on all non-loopback hosts; plaintext `http://` is permitted strictly on loopback (`127.0.0.0/8`, `::1`, `localhost`). Redirects are disabled (`Policy::none()`).

## Feature Flags (`Cargo.toml`)
| Feature | Enables | Notes |
| :--- | :--- | :--- |
| `default` | `core`, `webhooks`, `intentions`, `manage`, `inquiries`, `quicklinks`, `splits`, `saved-cards`, `subscriptions`, `payouts`, `onboarding`, `rustls-tls` | Batteries-included |
| `core` | `PaymobClient`, `ClientConfig`, `PaymobRegion`, 4-regime auth, `MinorUnitAmount`, `Currency`, `PaymobError` | Minimal base (`default-features = false`) |
| `webhooks` | `PaymobWebhookEngine` (Protocols A–E), `InMemoryWebhookDeduplicator` | Constant-time HMAC-SHA512 |
| `intentions` / `manage` / `inquiries` / `legacy-v2` | Unified Checkout Intentions, Refund/Void/Capture, Inquiries, Legacy v2 | Add as needed |
| `quicklinks` / `splits` / `saved-cards` / `subscriptions` | Payment Links, Marketplace Splits, CIT/MIT Tokenization, Subscriptions | Add as needed |
| `payouts` / `onboarding` / `some-payments-adapter` | Disbursements (OAuth2), Partner Onboarding, Unified Gateway Traits | Add as needed |
| `rustls-tls` / `native-tls` | TLS backend for `reqwest` | Pick one when `default-features = false` |

## 4 Authentication Regimes
| Regime | Mechanism | Configuration / Env Vars | Primary Endpoints |
| :--- | :--- | :--- | :--- |
| 1. Secret Key | `Authorization: Token <secret_key>` | Auto-loaded by `ClientConfig::from_env()`: `PAYMOB_SECRET_KEY`, `PAYMOB_PUBLIC_KEY` | `/v1/intention/`, `/v1/payment-links/`, Refunds/Voids/Captures, Saved Cards, Subscriptions |
| 2. Accept JWT | `POST /api/auth/tokens` (60m cached) | Auto-loaded by `ClientConfig::from_env()`: `PAYMOB_API_KEY` | Inquiries (`/api/ecommerce/orders/transaction_inquiry`), Legacy v2, some Manage calls |
| 3. Payouts OAuth2 | `POST /api/secure/o/token/` (Basic + password/refresh) | **Not** auto-loaded by `from_env()`; supply via `PayoutsCredentials` (supports `$VAR` resolution, e.g. `$PAYMOB_PAYOUTS_*`) | `/api/secure/disburse/`, Bulk Payouts, Budget/Topups |
| 4. Partner | Bearer or API Key + `Merchant-ID` | **Not** auto-loaded by `from_env()`; supply via `PartnerCredentials` (supports `$VAR` resolution, e.g. `$PAYMOB_PARTNER_*`) | Partner Onboarding (`/api/partner/...`) + `client.with_merchant(42)` |

## Minimal Copy-Paste Recipes

```rust
use some_paymob::prelude::*;

// 1. Client init (auto-infers region from key prefix if PAYMOB_REGION is omitted)
let client = PaymobClient::new(ClientConfig::from_env()?)?;
// Or explicit builder:
let cfg = ClientConfig::builder()
    .region(PaymobRegion::Egypt)
    .secret_key(SecretKey::new("$PAYMOB_SECRET_KEY")?)
    .public_key(PublicKey::new("$PAYMOB_PUBLIC_KEY")?)
    .hmac_secret(HmacSecret::new("$PAYMOB_HMAC_SECRET")?)
    .build()?;
let client = PaymobClient::new(cfg)?;

// 2. Intention + Unified Checkout URL
let params = CreateIntentionParams::builder()
    .amount(MinorUnitAmount::new(10_000)) // 100.00 EGP
    .currency(Currency::EGP)
    .payment_methods(vec![PaymentMethodInput::Id(4_097_558)])
    .billing_data(
        BillingData::builder()
            .phone_number("+201000000000")
            .first_name("Jane")
            .last_name("Doe")
            .email("jane@example.com")
            .build()?,
    )
    .build()?;
let intention = client.intentions().create(params).await?;
let checkout_url = client.checkout().unified_url(&intention.client_secret)?;

// 3. Refund / Void / Capture & Inquiries
client.manage().refund(RefundParams::new(tx_id, 5_000)).await?;
client.manage().void(VoidParams::new(tx_id)).await?;
client.manage().capture(CaptureParams::new(tx_id, 10_000)).await?;
let tx = client.inquiries().by_transaction_id(tx_id).await?;

// 4. Saved Cards (CIT/MIT), Subscriptions, Payouts, Partner, Unified Adapter
client.saved_cards().pay_with_token_mit(&MitPayParams::new(payment_key, card_token)?).await?;
client.subscriptions().plans().list(Some(1)).await?;
client.payouts().cashin().vodafone(MobileWalletCashinParams::new("01012345678", 5_000)).await?;
let scoped = client.with_merchant(42)?;
let session = client.create_payment_session(&unified_req).await?; // `some-payments-adapter`
```

## Webhook Verification & Replay Protection (`webhooks`)
```rust
use some_paymob::webhooks::{InMemoryWebhookDeduplicator, PaymobWebhookEngine, WebhookIdempotencyStore};

let engine = PaymobWebhookEngine::from_hmac_secret(&HmacSecret::new("$PAYMOB_HMAC_SECRET")?)
    .with_payouts_hmac_secret(&HmacSecret::new("$PAYMOB_PAYOUTS_HMAC_SECRET")?); // required (fail-closed) for Protocol E
let dedup = InMemoryWebhookDeduplicator::new();

// Protocols A, C, D, E (POST): auto-dispatch & constant-time verify
let event = engine.construct_event(raw_body, query_hmac.as_deref())?;
dedup.claim_or_reject(&event)?;

// Protocol B (GET redirect): ALWAYS pass raw query string to reject duplicate keys (HPP)
let redirect = engine.verify_transaction_get_query_str(raw_query)?;
```
- **Protocol D (Subscriptions)**: Paymob's HMAC authenticates **only** `(trigger_type, subscription_data.id)`. Always re-query `client.subscriptions()` for authoritative subscription state before mutating billing records.
- **Protocol E (Payouts)**: Fail-closed — `construct_event` / `verify_payout_*` reject unsigned callbacks when no payouts HMAC secret is configured.

## Error Handling & Top Rules
- `PaymobError`: Check `err.is_retryable()`, `err.is_auth_error()`, `err.status_code()`, `err.retry_after_secs()`.
- `WebhookError`: Return `err.suggested_http_status_code()` (`401` signature, `400` malformed, `409` duplicate, `500` config).
- **DO**: Use `MinorUnitAmount`, `verify_transaction_get_query_str`, `InMemoryWebhookDeduplicator` (or DB-backed `WebhookIdempotencyStore`), and clone `PaymobClient` across tasks.
- **DON'T**: Use floats for currency, call `.unwrap()` in production, trust unverified Protocol D body fields without API re-query, or pass untrusted `HashMap` query maps to `verify_transaction_get` without duplicate-key rejection.
