# User Story `US-3.3.0`: QuickLinks Payment Links API, Marketplace Split Rules & Convenience Fee Engine

- **Module**: `module-3` ([Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models](./README.md))
- **Story Branch**: `feat/us-3.3.0-quicklinks-splits-fees`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.00` $\to$ **`3` Parallel Implementation Units (`unit-1..3`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** Marketplace & SaaS Billing Engineer generating hosted payment links and multi-party settlements,  
> **I want** programmatic QuickLinks creation/cancellation (`paymob.quicklinks()`) alongside strongly-typed Split Amount, 3-Card Split Payment, and Convenience Fee models (`some_paymob::resources::splits`),  
> **So that** platforms can issue hosted payment URLs over SMS/WhatsApp, split single customer payments across multiple marketplace sellers or up to 3 customer cards, and compute compliant convenience fees without floating-point rounding errors.

This User Story belongs to **Module 3 (Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `3` strictly disjoint, 100% parallel Implementation Units (`unit-1..3`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Feature flags `quicklinks` and/or `splits` enabled.
- Paymob [QuickLinks Overview](https://developers.paymob.com/paymob-docs/developers/quicklink-apis/overview), [Payment Links OpenAPI](https://apis.io/apis/paymob/paymob-payment-links-api/), [Split Features](https://developers.paymob.com/paymob-docs/payments-and-features/core-features/split-features), and [Convenience Fee](https://developers.paymob.com/paymob-docs/payments-and-features/core-features/convenience-fee) specifications loaded.

#### 1.1.2 Postconditions
- `paymob.quicklinks().create(params)` (`POST /api/ecommerce/payment-links`) returns 201 `QuickLinkResponse` (`id`, `url`, `client_url`) and `.cancel(link_id)` (`POST /api/ecommerce/payment-links/cancel`) invalidates the link.
- `SplitDescription`, `SplitPaymentConfig` (up to 3 cards), and `ConvenienceFeeConfig` validate and serialize cleanly with zero floating-point arithmetic.

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-3.3.0 — QuickLinks Payment Links API, Marketplace Split Rules & Convenience Fee Engine

  Scenario: AC-1 — Create & Cancel QuickLink Payment Link
    Given valid `CreateQuickLinkParams` with `amount_cents: 150_000`, `currency: "EGP"`, and `integrations: vec![4097558]`
    When `paymob.quicklinks().create(params).await` and `.cancel(&resp.id).await` execute
    Then `POST /api/ecommerce/payment-links` returns 201 with `id`, `url`, and `client_url`, and `POST /api/ecommerce/payment-links/cancel` cancels the link

  Scenario: AC-2 — Multi-Card Split Payment Cap Enforcement (Max 3 Cards)
    Given a `SplitPaymentConfig` configured with 4 card portions
    When `SplitPaymentConfig::new(portions)` is called
    Then validation rejects the configuration with `PaymobError::ValidationError` because Paymob Split Payment supports at most 3 cards per transaction

  Scenario: AC-3 — Checked Integer Convenience Fee Calculation
    Given a `ConvenienceFeeConfig` with `Combination { bps: 250, fixed_cents: 300 }` (2.5% + 3.00 EGP) and `max_fee_cents: Some(5_000)`
    When `compute_fee_cents(300_000)` is evaluated
    Then the calculated fee (`7_800` piasters) is capped at `5_000` piasters using checked integer math

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..3 of US-3.3.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-3.3.1` | `AC-1` | `unit-1` | Unit + Doc-Test | Validate `CreateQuickLinkParams` (`amount_cents`, `currency`, `integrations: Vec<u64>`, optional `description`, `full_name`, `email`, `phone_number`, `redirection_url`), `QuickLinkResponse` (`id`, `url`, `client_url`), and `QuickLinksService` (`create` `POST /api/ecommerce/payment-links` & `cancel` `POST /api/ecommerce/payment-links/cancel` under Regime 2 `Bearer`) in `src/resources/quicklinks.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-3.3.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `SplitRecipientRule` and `SplitDescription` (multi-recipient marketplace settlement rules) plus `SplitPaymentConfig` (multi-card customer checkout enforcing `1 <= cards.len() <= 3`) in `src/resources/splits/models.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-3.3.3` | `AC-3` | `unit-3` | Unit + Doc-Test | Validate `ConvenienceFeeConfig`, `FeeCalculationMode` (`PercentageBps(u32)`, `FixedCents(u64)`, `Combination { bps: u32, fixed_cents: u64 }`), `max_fee_cents: Option<u64>`, `is_refundable: bool`, `CardFeeRule` (`Uniform`, `DebitVsCredit`, `BinRange`, `DomesticVsInternational`), and checked integer fee calculator in `src/resources/splits/convenience_fees.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-3.3.4` | `AC-4` | `unit-1..3` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **Maximum 3 Cards per Split Payment**: Paymob's Split Payment feature restricts customer checkout splitting to at most 3 cards (`1 <= portions.len() <= 3`).
  - **Basis-Points Integer Fee Math**: Percentage convenience fees use integer basis points (`10_000 bps = 100%`) and integer minor units (`u64`) with `max_fee_cents` clamping.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct CreateQuickLinkParams {
    pub amount_cents: u64,
    pub currency: String,
    pub integrations: Vec<u64>,
    pub description: Option<String>,
    pub full_name: Option<String>,
    pub email: Option<String>,
    pub phone_number: Option<String>,
    pub redirection_url: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct QuickLinkResponse {
    pub id: String,
    pub url: String,
    pub client_url: String,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/quicklinks.rs)
    participant U2 as unit-2 (src/resources/splits/models.rs)
    participant UK as unit-3 (src/resources/splits/convenience_fees.rs)
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

All `3` Implementation Units in `US-3.3.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/quicklinks.rs             # Owned exclusively by unit-1 (feat/us-3.3.0/unit-1-quicklinks-service)
│   ├── src/resources/splits/models.rs          # Owned exclusively by unit-2 (feat/us-3.3.0/unit-2-split-models)
│   ├── src/resources/splits/convenience_fees.rs # Owned exclusively by unit-3 (feat/us-3.3.0/unit-3-convenience-fees)
└── tests/
    └── quicklinks_splits_fees_integration.rs         # Executed by story-leader after unit-1..3 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `2` — 2 QuickLinks endpoints (`POST /api/ecommerce/payment-links`, `POST /api/ecommerce/payment-links/cancel`) + 3 Split/Fee domain models (`SplitDescription`, `SplitPaymentConfig`, `ConvenienceFeeConfig`)
- **$D_2$ (25% Artifact Volume)**: `2` — ~420 production LOC across `src/resources/quicklinks.rs` and `src/resources/splits/`
- **$D_3$ (20% Logic Complexity)**: `2` — Up-to-3-card split payment boundary validation, checked integer convenience fee calculation (`Percentage`, `FixedCents`, `Combination` with `max_fee_cents` cap), and card-level fee rule matching
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 3 independent files (`src/resources/quicklinks.rs`, `src/resources/splits/models.rs`, `src/resources/splits/convenience_fees.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(2) + 0.25(2) + 0.20(2) + 0.20(2) = \mathbf{2.00}$ $\to$ **`3` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..3`)

- **`unit-1` (`feat/us-3.3.0/unit-1-quicklinks-service`)**:
  - **Deliverable Scope**: `CreateQuickLinkParams` (`amount_cents`, `currency`, `integrations: Vec<u64>`, optional `description`, `full_name`, `email`, `phone_number`, `redirection_url`), `QuickLinkResponse` (`id`, `url`, `client_url`), and `QuickLinksService` (`create` `POST /api/ecommerce/payment-links` & `cancel` `POST /api/ecommerce/payment-links/cancel` under Regime 2 `Bearer`)
  - **Owned Files**: `src/resources/quicklinks.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/quicklinks.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-3.3.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-3.3.0/unit-2-split-models`)**:
  - **Deliverable Scope**: `SplitRecipientRule` and `SplitDescription` (multi-recipient marketplace settlement rules) plus `SplitPaymentConfig` (multi-card customer checkout enforcing `1 <= cards.len() <= 3`)
  - **Owned Files**: `src/resources/splits/models.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/splits/models.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-3.3.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-3.3.0/unit-3-convenience-fees`)**:
  - **Deliverable Scope**: `ConvenienceFeeConfig`, `FeeCalculationMode` (`PercentageBps(u32)`, `FixedCents(u64)`, `Combination { bps: u32, fixed_cents: u64 }`), `max_fee_cents: Option<u64>`, `is_refundable: bool`, `CardFeeRule` (`Uniform`, `DebitVsCredit`, `BinRange`, `DomesticVsInternational`), and checked integer fee calculator
  - **Owned Files**: `src/resources/splits/convenience_fees.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/splits/convenience_fees.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-3.3.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-3.3.0/unit-1-quicklinks-service` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-3.3.0/unit-2-split-models` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-3.3.0/unit-3-convenience-fees` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-3.3.0-quicklinks-splits-fees` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `src/resources/splits/mod.rs` and `src/resources/quicklinks.rs` stub exports on `feat/us-3.3.0-quicklinks-splits-fees` before branching `unit-1..3`.
2. **Simultaneous Worktree Spawning**: All `3` units are provisioned in `.worktrees/feat-us-3.3.0-unit-1..3` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` into `feat/us-3.3.0-quicklinks-splits-fees` via `gh pr merge <PR> --merge`.

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
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-3.3.1..4`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-3.3.0-quicklinks-splits-fees/unit-1..3`) and the parent Story PR (`feat/us-3.3.0-quicklinks-splits-fees`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-3.3.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-3.3.1..4` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `3` units (`unit-1..3`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`
