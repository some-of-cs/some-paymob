# User Story `US-8.1.0`: some-payments Unified Gateway Trait Implementations & PaymobExt Escape Hatch

- **Module**: `module-8` ([some-payments Cross-Gateway Unified Adapter & Deterministic Test Harness](./README.md))
- **Story Branch**: `feat/us-8.1.0-some-payments-adapter`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.00` $\to$ **`3` Parallel Implementation Units (`unit-1..3`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** Multi-Gateway FinTech Architect orchestrating `some-paymob`, `some-moyasar`, and `some-stripe` inside `some-payments`,  
> **I want** native implementations of `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` for `PaymobClient` plus a typed `ProviderExt::Paymob(PaymobExt)` escape hatch,  
> **So that** applications can route EGP/MENA checkouts, recurring subscriptions, and Vodafone Cash payouts through a single unified trait interface without losing access to Paymob-specific features like Affordability Widgets or Kiosk payments.

This User Story belongs to **Module 8 (some-payments Cross-Gateway Unified Adapter & Deterministic Test Harness)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `3` strictly disjoint, 100% parallel Implementation Units (`unit-1..3`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Modules 1 through 7 merged and feature flag `some-payments-adapter` (alias `some-payment-trait`) enabled.
- Cross-gateway unification table in [`docs/Paymob Rust SDK Architecture Research.md`](https://github.com/some-of-cs/some-paymob/blob/main/docs/Paymob%20Rust%20SDK%20Architecture%20Research.md) (lines 492–506) loaded.

#### 1.1.2 Postconditions
- `PaymobClient` implements `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider`.
- `ProviderExt::Paymob(PaymobExt)` exposes `pre_selected_plan`, `special_reference`, `split_description`, and Kiosk/Wallet execution without leaky abstractions.

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-8.1.0 — some-payments Unified Gateway Trait Implementations & PaymobExt Escape Hatch

  Scenario: AC-1 — Unified Payment Session, Capture, Refund & Void Mapping
    Given a multi-gateway orchestrator calling `PaymentProvider` trait methods on `PaymobClient`
    When `create_payment_session`, `capture_payment`, `refund_payment`, and `void_payment` are invoked
    Then they delegate zero-copy to `POST /v1/intention/` + `checkout().unified_url(...)`, `POST /api/acceptance/capture`, `POST /api/acceptance/void_refund/refund`, and `POST /api/acceptance/void_refund/void`

  Scenario: AC-2 — Unified Saved-Method MIT Charge, Webhook Verification & Subscription Refund
    Given a unified `charge_saved_method`, `verify_webhook`, or subscription refund request
    When the adapter traits execute
    Then `charge_saved_method` delegates to `POST /api/acceptance/payments/pay`, `verify_webhook` delegates to `PaymobWebhookEngine::construct_event`, and subscription refunds use `refund_last_transaction`

  Scenario: AC-3 — ProviderExt::Paymob Escape Hatch
    Given a request passing `ProviderExt::Paymob(PaymobExt { pre_selected_plan: Some(42), special_reference: Some("ORD-1".into()), .. })`
    When `create_payment_session` translates the request
    Then Paymob-specific fields wire directly into `CreateIntentionParams` without loss of type safety

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..3 of US-8.1.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-8.1.1` | `AC-1` | `unit-1` | Unit + Doc-Test | Validate `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` trait definitions and normalized request/response DTOs (`UnifiedPaymentSession`, `UnifiedRefundReceipt`, `UnifiedWebhookOutcome`, `UnifiedPayoutReceipt`) in `src/adapter/traits.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-8.1.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `impl PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` for `PaymobClient` mapping `create_payment_session`, `capture_payment`, `refund_payment`, `void_payment`, `charge_saved_method`, and `verify_webhook` in `src/adapter/some_payments.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-8.1.3` | `AC-3` | `unit-3` | Integration / Wire | Validate `PaymobExt` and `ProviderExt::Paymob(PaymobExt)` exposing `pre_selected_plan` (Affordability Widget), `special_reference`, `split_description`, and Kiosk/Mobile Wallet headless execution options in `src/adapter/ext.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-8.1.4` | `AC-4` | `unit-1..3` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **Zero-Copy Cross-Gateway Normalization**: Adapter methods borrow or move domain structs directly into `IntentionsService`, `ManageService`, `SavedCardsService`, `SubscriptionsService`, `PayoutsService`, and `PaymobWebhookEngine`.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaymobExt {
    pub pre_selected_plan: Option<u64>,
    pub special_reference: Option<String>,
    pub split_description: Option<Vec<crate::resources::splits::SplitRecipientRule>>,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/adapter/traits.rs)
    participant U2 as unit-2 (src/adapter/some_payments.rs)
    participant UK as unit-3 (src/adapter/ext.rs)
    participant Paymob as Paymob Gateway / Verifier

    Caller->>U1: Construct validated params / domain types
    U1->>U1: Enforce builder invariants, bounds & redaction rules
    Caller->>UK: Invoke service / engine entrypoint
    UK->>U2: Resolve auth regime / canonical payload encoding
    U2-->>UK: Return verified auth header/token or canonical digest input
    UK->>Paymob: Execute TLS 1.3 HTTP call or constant-time HMAC-SHA512 check
    Paymob-->>UK: Return wire payload / verification status
    UK-->>Caller: Return strongly-typed Result<T, PaymobError>
```

---

## 3. Expected Folder Architecture at the Project

All `3` Implementation Units in `US-8.1.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/adapter/traits.rs                   # Owned exclusively by unit-1 (feat/us-8.1.0/unit-1-unified-gateway-traits)
│   ├── src/adapter/some_payments.rs            # Owned exclusively by unit-2 (feat/us-8.1.0/unit-2-paymob-provider-impl)
│   ├── src/adapter/ext.rs                      # Owned exclusively by unit-3 (feat/us-8.1.0/unit-3-paymob-provider-ext)
└── tests/
    └── some_payments_adapter_integration.rs         # Executed by story-leader after unit-1..3 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `2` — 4 unified gateway traits (`PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, `PayoutProvider`) + `ProviderExt::Paymob(PaymobExt)` extension struct
- **$D_2$ (25% Artifact Volume)**: `2` — ~450 production LOC under `src/adapter/` (`#[cfg(feature = "some-payments-adapter")]`)
- **$D_3$ (20% Logic Complexity)**: `2` — Cross-gateway semantic normalization (`create_payment_session` -> `POST /v1/intention/` + `unified_url`, `refund_payment` -> `void_refund/refund` + subscription `last-transaction` refund, `charge_saved_method` -> `POST /api/acceptance/payments/pay`, idempotency key normalization)
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 3 independent files under `src/adapter/` (`traits.rs`, `some_payments.rs`, `ext.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(2) + 0.25(2) + 0.20(2) + 0.20(2) = \mathbf{2.00}$ $\to$ **`3` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..3`)

- **`unit-1` (`feat/us-8.1.0/unit-1-unified-gateway-traits`)**:
  - **Deliverable Scope**: `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` trait definitions and normalized request/response DTOs (`UnifiedPaymentSession`, `UnifiedRefundReceipt`, `UnifiedWebhookOutcome`, `UnifiedPayoutReceipt`)
  - **Owned Files**: `src/adapter/traits.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/adapter/traits.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-8.1.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-8.1.0/unit-2-paymob-provider-impl`)**:
  - **Deliverable Scope**: `impl PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` for `PaymobClient` mapping `create_payment_session`, `capture_payment`, `refund_payment`, `void_payment`, `charge_saved_method`, and `verify_webhook`
  - **Owned Files**: `src/adapter/some_payments.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/adapter/some_payments.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-8.1.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-8.1.0/unit-3-paymob-provider-ext`)**:
  - **Deliverable Scope**: `PaymobExt` and `ProviderExt::Paymob(PaymobExt)` exposing `pre_selected_plan` (Affordability Widget), `special_reference`, `split_description`, and Kiosk/Mobile Wallet headless execution options
  - **Owned Files**: `src/adapter/ext.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/adapter/ext.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-8.1.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-8.1.0/unit-1-unified-gateway-traits` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-8.1.0/unit-2-paymob-provider-impl` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-8.1.0/unit-3-paymob-provider-ext` | `api-tester` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-8.1.0-some-payments-adapter` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `src/adapter/mod.rs` and unified trait definitions on `feat/us-8.1.0-some-payments-adapter` before branching `unit-1..3`.
2. **Simultaneous Worktree Spawning**: All `3` units are provisioned in `.worktrees/feat-us-8.1.0-unit-1..3` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` into `feat/us-8.1.0-some-payments-adapter` via `gh pr merge <PR> --merge`.

---

## 5. Security Gateway (Powered by `security-audit` Skill)

### 5.1 Trust Boundaries & Security Actors
- **Security Actors**: Merchant backend services (`PaymobClient` callers), customer browsers/mobile apps (redirected via Unified Checkout / Pixel / Legacy Iframe), Paymob Acquiring & Payouts servers, and untrusted external webhook senders.
- **Trust Boundaries**:
  1. **Caller Input Boundary**: Untrusted builder inputs (phone numbers, amounts, frequencies, proof attachments, integration IDs) crossing into SDK request serializers.
  2. **Network Ingress / Deserialization Boundary**: Raw JSON/HTTP responses and incoming webhook payloads crossing into typed Rust domain models.
  3. **Credential & Telemetry Boundary**: Secret keys (`sk_*`), API keys, JWT/OAuth2 bearer tokens, saved card tokens, and HMAC secrets crossing into memory caches, HTTP headers, or diagnostic logs.

### 5.2 Threat Modeling & Abuse Matrix (STRIDE / OWASP ASVS)

| Threat ID | STRIDE Category | ASVS / CWE Ref | Attack Vector / Abuse Scenario | Impact | Required Mitigation & Code/Deliverable Control |
| :--- | :---: | :---: | :--- | :---: | :--- |
| `TM-1` | **S**poofing | ASVS V2 / CWE-287 | Wrong auth scheme (`Bearer` vs `Token`), expired 60-min JWT reuse, or forged webhook signature | Critical | Explicit `AuthStrategy` per endpoint, single-flight JWT/OAuth2 refresh, and constant-time `Hmac<Sha512>` + `subtle::ConstantTimeEq` verification |
| `TM-2` | **T**ampering | ASVS V5 / CWE-20 | Floating-point rounding manipulation, 100x currency unit errors, or tampered webhook query/body fields | Critical | `MinorUnitAmount(u64)` integer minor units (zero `f32`/`f64`), builder-time field validation, and fail-closed 20-key/8-key/body-HMAC verification |
| `TM-3` | **R**epudiation | ASVS V7 / CWE-778 | Duplicate transaction fulfillment on retried webhooks or unlogged state mutations | High | `IdempotentWebhookGuard` extracting `(obj.id, order.id)` and `(paymob_request_id, subscription_data.id)` + correlation logging |
| `TM-4` | **I**nformation Disclosure | ASVS V8 / CWE-200 | Secret key (`sk_*`), `client_secret`, JWT `auth_token`, or PAN/CVV leaked in `Debug` logs or panic traces | Critical | `secrecy::SecretString` + `ZeroizeOnDrop` on all credentials/tokens and custom `[REDACTED]` `Debug` implementations |
| `TM-5` | **D**enial of Service | ASVS V11 / CWE-400 | Thundering-herd token refresh storms on 1-hour JWT expiry or oversized (>2.8 MB) topup proof payloads | High | Lock-free `ArcSwapOption` + single-flight `tokio::sync::Mutex<()>` refresh guard, bounded timeouts, and `MAX_TOPUP_PROOF_BYTES` check |
| `TM-6` | **E**levation of Privilege | ASVS V4 / CWE-285 | Cross-merchant IDOR in Partner Onboarding (`with_merchant`) or mixing Test and Live integration IDs | Critical | Immutable `MerchantScopedClient` per `merchant_id` and strict `EnvironmentMode` (`Test` vs `Live`) parity enforcement |

### 5.3 Cryptography & Global Data Protection Controls (Worldwide Legal & Regulatory Compliance)
1. **Cryptographic Standards**:
   - **In Transit**: TLS 1.3 (`reqwest` with `rustls-tls`) enforced for all Accept Acquiring and Payouts connections.
   - **Signatures & Constant-Time MACs**: `HMAC-SHA512` (`hmac` + `sha2`) verified exclusively via branchless constant-time comparison (`subtle::ConstantTimeEq::ct_eq`); zero `SHA-1`/`MD5` or early-exit byte comparisons.
   - **Memory Hygiene**: All secret keys, API keys, JWTs, OAuth2 refresh tokens, card tokens, and HMAC secrets use `secrecy::SecretString` and `zeroize::ZeroizeOnDrop`.
2. **Global Multi-Jurisdictional Privacy & Financial Compliance**:
   - **PCI-DSS v4.0**: Raw PANs and CVVs are never stored or logged; card tokenization uses `masked_pan` (`xxxx-xxxx-xxxx-2346`) for display and `SecretString` for tokens; frontend checkout helpers accept only `PublicKey` (`pk_*`).
   - **MENA & Regional Central Bank Regulations (CBE Egypt, SAMA Saudi Arabia, CBUAE UAE, CBO Oman, SBP Pakistan)**: Regional host isolation via `PaymobRegion` ensures transaction and disbursement payloads remain routed to the designated sovereign regional gateway.
   - **GDPR / UK GDPR / CCPA / Egypt PDPL (Law No. 151 of 2020) / KSA PDPL**: Strict PII minimization and automatic `[REDACTED]` scrubbing of customer emails, phone numbers (`msisdn`), and bank account numbers in diagnostic traces.

### 5.4 Automated Security Verification Checklist (`security-audit` Skill)
- [ ] Applicable security playbooks reviewed (`WEB-PROTOCOL-AND-AUTH.md`, `MEMORY-SAFETY-AND-BINARY.md`, `SUPPLY-CHAIN-AND-RELEASE.md`).
- [ ] `#![forbid(unsafe_code)]` enforced at the crate root; all untrusted inputs validated for bounds, non-empty prefixes, and encoding prior to network dispatch.
- [ ] Zero secrets, API keys, JWTs, card tokens, or raw PII emitted in `Debug` formatting, logs, or error messages.
- [ ] Zero `f32`/`f64` floating-point types used for monetary amounts or fee calculations.

### 5.5 Security Gateway (Gate G2) Sign-Off Checklist
- [ ] **0 Critical / High / Medium** vulnerabilities in `security-audit` scan.
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-8.1.1..4`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-8.1.0-some-payments-adapter/unit-1..3`) and the parent Story PR (`feat/us-8.1.0-some-payments-adapter`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-8.1.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-8.1.1..4` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `3` units (`unit-1..3`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`
