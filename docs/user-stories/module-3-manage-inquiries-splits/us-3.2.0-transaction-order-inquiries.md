# User Story `US-3.2.0`: Transaction, Order & Saved Card Token Reconciliation Inquiries

- **Module**: `module-3` ([Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models](./README.md))
- **Story Branch**: `feat/us-3.2.0-transaction-order-inquiries`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.20` $\to$ **`4` Parallel Implementation Units (`unit-1..4`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** Financial Reconciliation Engineer verifying pending cash/kiosk orders or missed webhooks,  
> **I want** a complete `paymob.inquiries()` service covering transaction ID lookup, order/reference inquiry, order card-token discovery, and full order attempt history,  
> **So that** backend reconciliation jobs can deterministically audit settlement fees, VAT, reconciliation IDs, and saved card tokens whenever an asynchronous webhook callback is delayed.

This User Story belongs to **Module 3 (Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `4` strictly disjoint, 100% parallel Implementation Units (`unit-1..4`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Feature flag `inquiries` (or `transactions` / `full`) enabled.
- Paymob Inquiry specifications ([Transaction Inquiry](https://developers.paymob.com/paymob-docs/developers/transaction-inquiry-apis/transaction-inquiry), [By Order ID or Reference](https://developers.paymob.com/paymob-docs/developers/transaction-inquiry-apis/transaction-inquiry/by-order-id-or-reference), and [Card Token Inquiry](https://developers.paymob.com/paymob-docs/developers/transaction-inquiry-apis/card-token-inquiry)) loaded.

#### 1.1.2 Postconditions
- `by_transaction_id(tx_id)` executes `GET /api/acceptance/transactions/{transaction_id}` with `Authorization: Bearer <auth_token>`.
- `by_order_or_reference(params)` executes `POST /api/ecommerce/orders/transaction_inquiry` with JSON body `"auth_token"` and returns `InquiredTransaction` with full settlement/VAT/fee breakdown.
- `card_tokens_by_order(order_id)` executes `POST /api/acceptance/order_card_tokens` and returns `Vec<CardTokenEnvelope>` with `SecretString`-protected tokens.

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-3.2.0 — Transaction, Order & Saved Card Token Reconciliation Inquiries

  Scenario: AC-1 — Transaction Inquiry by ID (GET /api/acceptance/transactions/{id})
    Given a transaction ID `192036465`
    When `paymob.inquiries().by_transaction_id(192036465).await` is called
    Then the SDK attaches `Authorization: Bearer <auth_token>` and deserializes the `Transaction` record

  Scenario: AC-2 — Order or Special Reference Inquiry (POST /api/ecommerce/orders/transaction_inquiry)
    Given `TransactionInquiryParams` with `order_id: Some(212245716)` or `merchant_order_id: Some("order_estatestack_2026_001")`
    When `paymob.inquiries().by_order_or_reference(params).await` is executed
    Then the SDK injects `"auth_token"` into the JSON body and deserializes `InquiredTransaction` including `accept_fees_cents_int`, `vat_cents_int`, `settlement_amount_cents_int`, `is_settled`, `is_reconciled`, and `split_description`

  Scenario: AC-3 — Reject Empty Inquiry Parameters & Redact Saved Card Tokens
    Given a `TransactionInquiryParams` where both `order_id` and `merchant_order_id` are `None`
    When `by_order_or_reference` is called, and `card_tokens_by_order(523360093)` is formatted via `Debug`
    Then the empty inquiry is rejected locally with `PaymobError::ValidationError` and `CardTokenObject.token` prints `"[REDACTED]"`

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..4 of US-3.2.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-3.2.1` | `AC-1` | `unit-1` | Unit + Doc-Test | Validate `paymob.inquiries().by_transaction_id(tx_id)` (`GET /api/acceptance/transactions/{transaction_id}`) under Regime 2 `Authorization: Bearer <auth_token>` in `src/resources/inquiries/by_id.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-3.2.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `TransactionInquiryParams` (requiring at least one of `order_id` or `merchant_order_id` / `special_reference`), `InquiredTransaction` (`paid_at`, `fees`, `vat`, `accept_fees_cents_int`, `vat_cents_int`, `settlement_amount_cents_int`, `is_settled`, `is_reconciled`, `reconciliation_id`, `cogs`, `installment_info`, `split_description`, `is_split_payment`, `allow_cardless_refund`, `public_customer_fingerprint`), and `POST /api/ecommerce/orders/transaction_inquiry` in `src/resources/inquiries/by_order.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-3.2.3` | `AC-3` | `unit-3` | Unit + Doc-Test | Validate `CardTokenEnvelope` (`type: "TOKEN"`, `obj: CardTokenObject` with `token: SecretString`, `masked_pan`, `card_subtype`, `merchant_id`, `order_id`, `email`, `next_payment_intention`) and `paymob.inquiries().card_tokens_by_order(order_id)` (`POST /api/acceptance/order_card_tokens` with body `"auth_token"`) in `src/resources/inquiries/card_tokens.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-3.2.4` | `AC-3` | `unit-4` | Integration / Wire | Validate `OrderInquiryResponse` (order metadata + nested payment attempt transactions) and `paymob.inquiries().order(order_id)` (`GET /api/ecommerce/orders/{order_id}`) using Regime 2 `Bearer <auth_token>` in `src/resources/inquiries/order_inquiry.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-3.2.5` | `AC-4` | `unit-1..4` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **Non-Empty Inquiry Selector**: `TransactionInquiryParams` requires at least one of `order_id` or `merchant_order_id` (`special_reference`).
  - **Saved Card Token Redaction**: `CardTokenObject::token` is stored in `secrecy::SecretString` (`ZeroizeOnDrop`) while `masked_pan` (`xxxx-xxxx-xxxx-2346`) remains inspectable.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct TransactionInquiryParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merchant_order_id: Option<String>,
}

#[derive(Clone, Deserialize)]
pub struct CardTokenObject {
    pub id: u64,
    pub token: SecretString,
    pub masked_pan: String,
    pub merchant_id: u64,
    pub card_subtype: String,
    pub created_at: String,
    pub email: String,
    pub order_id: String,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/inquiries/by_id.rs)
    participant U2 as unit-2 (src/resources/inquiries/by_order.rs)
    participant UK as unit-4 (src/resources/inquiries/order_inquiry.rs)
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

All `4` Implementation Units in `US-3.2.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/inquiries/by_id.rs        # Owned exclusively by unit-1 (feat/us-3.2.0/unit-1-inquiry-by-tx-id)
│   ├── src/resources/inquiries/by_order.rs     # Owned exclusively by unit-2 (feat/us-3.2.0/unit-2-inquiry-by-order-ref)
│   ├── src/resources/inquiries/card_tokens.rs  # Owned exclusively by unit-3 (feat/us-3.2.0/unit-3-order-card-tokens)
│   ├── src/resources/inquiries/order_inquiry.rs # Owned exclusively by unit-4 (feat/us-3.2.0/unit-4-order-record-inquiry)
└── tests/
    └── transaction_order_inquiries_integration.rs         # Executed by story-leader after unit-1..4 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `2` — 4 inquiry endpoints: `by_transaction_id`, `by_order_or_reference`, `card_tokens_by_order`, and `order`
- **$D_2$ (25% Artifact Volume)**: `2` — ~540 production LOC across `src/resources/inquiries/`
- **$D_3$ (20% Logic Complexity)**: `3` — Dual Regime 2 authentication (`Bearer <auth_token>` header on GET endpoints vs. JSON body `"auth_token"` injection on POST inquiry endpoints), non-empty `order_id` or `merchant_order_id` invariant, and rich settlement/VAT/reconciliation deserialization
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 4 independent files under `src/resources/inquiries/` (`by_id.rs`, `by_order.rs`, `card_tokens.rs`, `order_inquiry.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(2) + 0.25(2) + 0.20(3) + 0.20(2) = \mathbf{2.20}$ $\to$ **`4` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..4`)

- **`unit-1` (`feat/us-3.2.0/unit-1-inquiry-by-tx-id`)**:
  - **Deliverable Scope**: `paymob.inquiries().by_transaction_id(tx_id)` (`GET /api/acceptance/transactions/{transaction_id}`) under Regime 2 `Authorization: Bearer <auth_token>`
  - **Owned Files**: `src/resources/inquiries/by_id.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/inquiries/by_id.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-3.2.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-3.2.0/unit-2-inquiry-by-order-ref`)**:
  - **Deliverable Scope**: `TransactionInquiryParams` (requiring at least one of `order_id` or `merchant_order_id` / `special_reference`), `InquiredTransaction` (`paid_at`, `fees`, `vat`, `accept_fees_cents_int`, `vat_cents_int`, `settlement_amount_cents_int`, `is_settled`, `is_reconciled`, `reconciliation_id`, `cogs`, `installment_info`, `split_description`, `is_split_payment`, `allow_cardless_refund`, `public_customer_fingerprint`), and `POST /api/ecommerce/orders/transaction_inquiry`
  - **Owned Files**: `src/resources/inquiries/by_order.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/inquiries/by_order.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-3.2.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-3.2.0/unit-3-order-card-tokens`)**:
  - **Deliverable Scope**: `CardTokenEnvelope` (`type: "TOKEN"`, `obj: CardTokenObject` with `token: SecretString`, `masked_pan`, `card_subtype`, `merchant_id`, `order_id`, `email`, `next_payment_intention`) and `paymob.inquiries().card_tokens_by_order(order_id)` (`POST /api/acceptance/order_card_tokens` with body `"auth_token"`)
  - **Owned Files**: `src/resources/inquiries/card_tokens.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/inquiries/card_tokens.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-3.2.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-4` (`feat/us-3.2.0/unit-4-order-record-inquiry`)**:
  - **Deliverable Scope**: `OrderInquiryResponse` (order metadata + nested payment attempt transactions) and `paymob.inquiries().order(order_id)` (`GET /api/ecommerce/orders/{order_id}`) using Regime 2 `Bearer <auth_token>`
  - **Owned Files**: `src/resources/inquiries/order_inquiry.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/inquiries/order_inquiry.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-3.2.4`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-3.2.0/unit-1-inquiry-by-tx-id` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-3.2.0/unit-2-inquiry-by-order-ref` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-3.2.0/unit-3-order-card-tokens` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-4` | `feat/us-3.2.0/unit-4-order-record-inquiry` | `api-tester` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-3.2.0-transaction-order-inquiries` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `src/resources/inquiries/mod.rs` and `InquiriesService` struct stub on `feat/us-3.2.0-transaction-order-inquiries` before branching `unit-1..4`.
2. **Simultaneous Worktree Spawning**: All `4` units are provisioned in `.worktrees/feat-us-3.2.0-unit-1..4` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` $\to$ `unit-4` into `feat/us-3.2.0-transaction-order-inquiries` via `gh pr merge <PR> --merge`.

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
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-3.2.1..5`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-3.2.0-transaction-order-inquiries/unit-1..4`) and the parent Story PR (`feat/us-3.2.0-transaction-order-inquiries`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-3.2.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-3.2.1..5` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `4` units (`unit-1..4`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`
