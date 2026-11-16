# `some-paymob` — User Story Specifications & Module Execution Prompts Index

Generated from [`docs/Paymob Rust SDK Architecture Research.md`](../Paymob%20Rust%20SDK%20Architecture%20Research.md) via the `spec-decomposition` skill (`some-divide-and-conquer`). Module, User Story, and Implementation Unit numbering is authoritative in [`docs/architecture/DECOMPOSITION_ROADMAP.md`](../architecture/DECOMPOSITION_ROADMAP.md).

- **8 Modules · 20 User Stories · 75 Parallel Implementation Units**
- **Strict Cross-Module Merge Order to `main`:** `Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`
- Every Module directory (`docs/user-stories/module-M-<slug>/`) contains:
  1. [`README.md`](./module-1-core-microkernel/README.md) — Module Overview, User Story & Unit Index Table, and a **Copy-Paste-Ready Module Execution Prompt**.
  2. Comprehensive 6-section User Story specifications (`us-M.S.0-<story-slug>.md`) covering Spec Kit Specifications (Narrative, Pre/Postconditions, Gherkin ACs, Traceability Matrix), Technical Implementation Plan (Invariants, Rust Schemas, Mermaid Sequence Diagram), Expected Folder Architecture, Implementation Units & Specialist Agent Roster, Security Gateway (STRIDE/OWASP ASVS, Cryptography, Global Compliance), and 6 Quality Validation Gates (`G0`, `G1`, `G2`, `G-Complexity`, `G-Docs`, `G-Review`).

---

## Module Index & Merge Order to `main`

| Merge Order | Module | Branch | Feature Flag(s) | Stories / Units | Module Execution Prompt |
| :---: | :--- | :--- | :--- | :---: | :--- |
| **1st** | **Module 1: Core Microkernel, Multi-Region Routing & 4-Regime Auth Engine** | `feat/module-1-core-microkernel` | `core` (implicit, always enabled), `rustls-tls` (default) | 3 stories · 13 units | [`module-1-core-microkernel/README.md`](./module-1-core-microkernel/README.md) |
| **3rd** | **Module 2: Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow** | `feat/module-2-intentions-checkout` | `intentions` (default enabled), `legacy-v2` (opt-in) | 3 stories · 10 units | [`module-2-intentions-checkout/README.md`](./module-2-intentions-checkout/README.md) |
| **4th** | **Module 3: Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models** | `feat/module-3-manage-inquiries-splits` | `manage`, `inquiries`, `quicklinks`, `splits` (and `transactions` alias) | 3 stories · 10 units | [`module-3-manage-inquiries-splits/README.md`](./module-3-manage-inquiries-splits/README.md) |
| **5th** | **Module 4: Saved Cards (CIT/MIT), Headless Payments & Subscriptions Recurring Billing Engine** | `feat/module-4-saved-cards-subscriptions` | `saved-cards` (alias `tokens`), `subscriptions` | 3 stories · 11 units | [`module-4-saved-cards-subscriptions/README.md`](./module-4-saved-cards-subscriptions/README.md) |
| **6th** | **Module 5: Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups** | `feat/module-5-payouts-cashin` | `payouts` | 2 stories · 8 units | [`module-5-payouts-cashin/README.md`](./module-5-payouts-cashin/README.md) |
| **7th** | **Module 6: Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping** | `feat/module-6-partner-onboarding` | `onboarding` (alias `partner-onboarding`) | 2 stories · 7 units | [`module-6-partner-onboarding/README.md`](./module-6-partner-onboarding/README.md) |
| **2nd** | **Module 7: Constant-Time Cryptographic Webhook Verification Engine (Protocols A–E & Idempotency Guard)** | `feat/module-7-webhooks-engine` | `webhooks` (alias `webhook-engine`, default enabled) | 2 stories · 10 units | [`module-7-webhooks-engine/README.md`](./module-7-webhooks-engine/README.md) |
| **8th** | **Module 8: some-payments Cross-Gateway Unified Adapter & Deterministic Test Harness** | `feat/module-8-adapter-test-utils` | `some-payments-adapter` (alias `some-payment-trait`), `test-utils`, `full` | 2 stories · 6 units | [`module-8-adapter-test-utils/README.md`](./module-8-adapter-test-utils/README.md) |

---

## Module 1 — Core Microkernel, Multi-Region Routing & 4-Regime Auth Engine (13 Units)

- **Module Execution Prompt:** [`module-1-core-microkernel/README.md`](./module-1-core-microkernel/README.md)
- **Branch:** `feat/module-1-core-microkernel` | **Merge Order Position:** 1st (Foundation Module — merges to `main` first; zero upstream module prerequisites; required by Modules 2–8)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-1.1.0` | Multi-Region Dual-Host Router, Credential Newtypes & ClientConfig | `2.55` | `4` | [`us-1.1.0-region-router-config.md`](./module-1-core-microkernel/us-1.1.0-region-router-config.md) |
| `US-1.2.0` | Zero-Race 4-Regime Authentication State Machine & Single-Flight Token Cache | `2.95` | `5` | [`us-1.2.0-multi-regime-auth.md`](./module-1-core-microkernel/us-1.2.0-multi-regime-auth.md) |
| `US-1.3.0` | HTTP Transport Pipeline, PaymobError Hierarchy, MinorUnitAmount & Prelude | `2.35` | `4` | [`us-1.3.0-http-error-primitives.md`](./module-1-core-microkernel/us-1.3.0-http-error-primitives.md) |

## Module 2 — Payment Intentions, Checkout Experiences & Legacy Accept v2 Flow (10 Units)

- **Module Execution Prompt:** [`module-2-intentions-checkout/README.md`](./module-2-intentions-checkout/README.md)
- **Branch:** `feat/module-2-intentions-checkout` | **Merge Order Position:** 3rd (Merges to `main` after Module 1 and Module 7; before Module 3, Module 4, Module 5, Module 6, and Module 8)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-2.1.0` | v1 Payment Intention Create & Update API (POST & PUT /v1/intention/) | `2.55` | `4` | [`us-2.1.0-intention-create-update.md`](./module-2-intentions-checkout/us-2.1.0-intention-create-update.md) |
| `US-2.2.0` | Unified Checkout URL, Embedded Pixel JS Config & Affordability Widget Builders | `2.00` | `3` | [`us-2.2.0-checkout-pixel-affordability.md`](./module-2-intentions-checkout/us-2.2.0-checkout-pixel-affordability.md) |
| `US-2.3.0` | Legacy Accept v2 3-Step Checkout Flow (Auth Token -> Order -> Payment Key -> Iframe) | `2.00` | `3` | [`us-2.3.0-legacy-v2-checkout.md`](./module-2-intentions-checkout/us-2.3.0-legacy-v2-checkout.md) |

## Module 3 — Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models (10 Units)

- **Module Execution Prompt:** [`module-3-manage-inquiries-splits/README.md`](./module-3-manage-inquiries-splits/README.md)
- **Branch:** `feat/module-3-manage-inquiries-splits` | **Merge Order Position:** 4th (Merges to `main` after Modules 1, 7, and 2; before Modules 4, 5, 6, and 8)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-3.1.0` | Payment Management — Full/Partial Refund, Unsettled Void & Auth/Capture | `2.00` | `3` | [`us-3.1.0-payment-refund-void-capture.md`](./module-3-manage-inquiries-splits/us-3.1.0-payment-refund-void-capture.md) |
| `US-3.2.0` | Transaction, Order & Saved Card Token Reconciliation Inquiries | `2.20` | `4` | [`us-3.2.0-transaction-order-inquiries.md`](./module-3-manage-inquiries-splits/us-3.2.0-transaction-order-inquiries.md) |
| `US-3.3.0` | QuickLinks Payment Links API, Marketplace Split Rules & Convenience Fee Engine | `2.00` | `3` | [`us-3.3.0-quicklinks-splits-fees.md`](./module-3-manage-inquiries-splits/us-3.3.0-quicklinks-splits-fees.md) |

## Module 4 — Saved Cards (CIT/MIT), Headless Payments & Subscriptions Recurring Billing Engine (11 Units)

- **Module Execution Prompt:** [`module-4-saved-cards-subscriptions/README.md`](./module-4-saved-cards-subscriptions/README.md)
- **Branch:** `feat/module-4-saved-cards-subscriptions` | **Merge Order Position:** 5th (Merges to `main` after Modules 1, 7, 2, and 3; before Modules 5, 6, and 8)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-4.1.0` | Saved Card Tokenization (CIT/MIT) & Headless Payments (MOTO, Mobile Wallet & Kiosk) | `2.00` | `3` | [`us-4.1.0-saved-cards-headless-pay.md`](./module-4-saved-cards-subscriptions/us-4.1.0-saved-cards-headless-pay.md) |
| `US-4.2.0` | Subscription Plans CRUD & Plan Lifecycle (POST/PUT/GET/Suspend/Resume) | `2.00` | `3` | [`us-4.2.0-subscription-plans.md`](./module-4-saved-cards-subscriptions/us-4.2.0-subscription-plans.md) |
| `US-4.3.0` | Subscription Lifecycle Actions, Card Vault Management, Transaction History & refund_last_transaction | `2.75` | `5` | [`us-4.3.0-subscription-lifecycle-cards-refunds.md`](./module-4-saved-cards-subscriptions/us-4.3.0-subscription-lifecycle-cards-refunds.md) |

## Module 5 — Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups (8 Units)

- **Module Execution Prompt:** [`module-5-payouts-cashin/README.md`](./module-5-payouts-cashin/README.md)
- **Branch:** `feat/module-5-payouts-cashin` | **Merge Order Position:** 6th (Merges to `main` after Modules 1, 7, 2, 3, and 4; before Modules 6 and 8)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-5.1.0` | Payouts OAuth 2.0 Token Facade & Instant Cashin Disbursements (7 Issuers + Aman Cancel) | `2.55` | `4` | [`us-5.1.0-payouts-oauth-instant-cashin.md`](./module-5-payouts-cashin/us-5.1.0-payouts-oauth-instant-cashin.md) |
| `US-5.2.0` | Bulk Disbursements, Payout Inquiries, User Budget & Topup Requests | `2.35` | `4` | [`us-5.2.0-payouts-bulk-inquiries-topups.md`](./module-5-payouts-cashin/us-5.2.0-payouts-bulk-inquiries-topups.md) |

## Module 6 — Partner Merchant Onboarding APIs & Multi-Tenant Client Scoping (7 Units)

- **Module Execution Prompt:** [`module-6-partner-onboarding/README.md`](./module-6-partner-onboarding/README.md)
- **Branch:** `feat/module-6-partner-onboarding` | **Merge Order Position:** 7th (Merges to `main` after Modules 1, 7, 2, 3, 4, and 5; before Module 8)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-6.1.0` | Partner Authentication, Partner API Key Provisioning & Partner HMAC Secret Retrieval | `2.00` | `3` | [`us-6.1.0-partner-auth-hmac.md`](./module-6-partner-onboarding/us-6.1.0-partner-auth-hmac.md) |
| `US-6.2.0` | Sub-Merchant Registration, Onboarding Flow Schema, Step Submission, Inquiry & with_merchant Scoping | `2.35` | `4` | [`us-6.2.0-merchant-onboarding-flow.md`](./module-6-partner-onboarding/us-6.2.0-merchant-onboarding-flow.md) |

## Module 7 — Constant-Time Cryptographic Webhook Verification Engine (Protocols A–E & Idempotency Guard) (10 Units)

- **Module Execution Prompt:** [`module-7-webhooks-engine/README.md`](./module-7-webhooks-engine/README.md)
- **Branch:** `feat/module-7-webhooks-engine` | **Merge Order Position:** 2nd (Merges to `main` immediately after Module 1; before Modules 2, 3, 4, 5, 6, and 8)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-7.1.0` | Constant-Time HMAC-SHA512 Core Verifier & Transaction Callbacks (Protocol A POST & Protocol B GET) | `2.95` | `5` | [`us-7.1.0-webhook-verifier-transaction-protocols.md`](./module-7-webhooks-engine/us-7.1.0-webhook-verifier-transaction-protocols.md) |
| `US-7.2.0` | Card Token (Protocol C), Subscription (Protocol D), Payouts (Protocol E), Auto-Dispatcher & IdempotentWebhookGuard | `2.75` | `5` | [`us-7.2.0-webhook-token-subscription-payout-idempotency.md`](./module-7-webhooks-engine/us-7.2.0-webhook-token-subscription-payout-idempotency.md) |

## Module 8 — some-payments Cross-Gateway Unified Adapter & Deterministic Test Harness (6 Units)

- **Module Execution Prompt:** [`module-8-adapter-test-utils/README.md`](./module-8-adapter-test-utils/README.md)
- **Branch:** `feat/module-8-adapter-test-utils` | **Merge Order Position:** 8th (Final Module — merges to `main` last after Modules 1, 7, 2, 3, 4, 5, and 6 have all merged to `main`)

| Story ID | Title | $S_{\text{story}}$ | Parallel Units ($K$) | Specification File |
| :--- | :--- | :---: | :---: | :--- |
| `US-8.1.0` | some-payments Unified Gateway Trait Implementations & PaymobExt Escape Hatch | `2.00` | `3` | [`us-8.1.0-some-payments-adapter.md`](./module-8-adapter-test-utils/us-8.1.0-some-payments-adapter.md) |
| `US-8.2.0` | Official Paymob Test Vector Suite, wiremock Multi-Regime Mock Server & Sandbox Constraint Harness | `2.00` | `3` | [`us-8.2.0-test-vectors-mock-harness.md`](./module-8-adapter-test-utils/us-8.2.0-test-vectors-mock-harness.md) |

