# User Story `US-5.2.0`: Bulk Disbursements, Payout Inquiries, User Budget & Topup Requests

- **Module**: `module-5` ([Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups](./README.md))
- **Story Branch**: `feat/us-5.2.0-payouts-bulk-inquiries-topups`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Story Decomposition Score ($S_{\text{story}}$)**: `2.35` $\to$ **`4` Parallel Implementation Units (`unit-1..4`)**

---

## 1. Spec Kit Specifications

### 1.1 User Story Narrative
> **As a** Treasury Operations Engineer managing payout budgets, bulk payroll runs, and balance topups,  
> **I want** strongly-typed methods for bulk disbursements (`cashin().bulk`), transaction/reference/budget/topup inquiries (`inquiries()`), and payout balance topups from Bank Transfers or Accept Balance (`topups()`),  
> **So that** treasury systems can monitor real-time Payouts budget balances, reconcile bulk disbursement batches, and fund payout accounts from Accept acquiring balances or bank transfers with client-side `2.8 MB` proof-size enforcement.

This User Story belongs to **Module 5 (Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups)** of [`some-paymob`](https://github.com/some-of-cs/some-paymob) as specified in [`docs/Paymob Rust SDK Architecture Research.md`](../../Paymob%20Rust%20SDK%20Architecture%20Research.md). It is decomposed into `4` strictly disjoint, 100% parallel Implementation Units (`unit-1..4`) that compile and verify independently inside isolated Git worktrees without inter-unit blocking.

#### 1.1.1 Preconditions
- Feature flag `payouts` enabled and `US-5.1.0` OAuth2/models available.
- Paymob Payouts Inquiry & Topup specifications ([User Budget Inquiry](https://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires/user-budget-inquiry), [Topup Inquiry](https://developers.paymob.com/paymob-docs/developers/payouts-apis/inquires/topup-inquiry), and [Topup Request – Accept Balance](https://developers.paymob.com/paymob-docs/developers/payouts-apis/topup/topup-request-accept-balance)) loaded.

#### 1.1.2 Postconditions
- `paymob.payouts().cashin().bulk(params)` dispatches `POST /disburse/api/v1/disburse/bulk_transaction/`.
- `paymob.payouts().inquiries()` provides `transactions`, `by_reference`, `user_budget` (`GET /api/secure/budget/inquire/`), and `topup` (`GET /api/secure/topup/inquire/`).
- `paymob.payouts().topups()` provides `from_bank_transfer` (enforcing `to_attach_proof <= 2.8 MB`) and `from_accept_balance` (`POST /api/secure/topup/request/`).

### 1.2 Acceptance Criteria (Gherkin Scenarios)

```gherkin
Feature: US-5.2.0 — Bulk Disbursements, Payout Inquiries, User Budget & Topup Requests

  Scenario: AC-1 — User Budget Inquiry & HTTP 429 Rate Limit Handling
    Given an authenticated Payouts client
    When `paymob.payouts().inquiries().user_budget().await` is executed
    Then `GET /api/secure/budget/inquire/` returns `UserBudgetResponse { current_budget: "Your current budget is 888.25 LE" }` (or maps HTTP 429 `{ status_description, status_code }` to `PaymobError::RateLimited`)

  Scenario: AC-2 — Bank Transfer Topup with 2.8 MB Proof Size Guard
    Given a `BankTransferTopupParams` where `to_attach_proof` exceeds `2.8 MB` (`2,936,012` bytes)
    When `paymob.payouts().topups().from_bank_transfer(params).await` is called
    Then validation rejects the oversized proof locally with `Err(PaymobError::ValidationError)` before uploading

  Scenario: AC-3 — Accept Balance Topup & Bulk Transaction Inquiries
    Given an `AcceptBalanceTopupParams` (`amount: 500`, `type: "from_accept_balance"`, `currency: "egyptian_pound"`, `username`)
    When `from_accept_balance` and `inquiries().by_reference` are invoked
    Then `POST /api/secure/topup/request/` returns `TopupRecord` (`status: "pending"`) and `inquire_by_reference` returns the batch status

  Scenario: AC-4 — Secret Redaction, Zero Float & Cyclomatic Complexity Compliance
    Given all public types and functions implemented across unit-1..4 of US-5.2.0
    When formatted via Debug/Display and analyzed by Gate G2 and Gate G-Complexity
    Then zero raw secrets, API keys, tokens, or PANs appear in Debug output (all emit "[REDACTED]")
    And every monetary value uses integer minor units (u64) with Cyclomatic Complexity CC <= 6 and nesting depth <= 2
```

### 1.3 Test Cases & Traceability Matrix

| Test Case ID | Mapped AC | Owning Unit | Test Level (Unit / Integration / Property / Security) | Description & Input Vector | Expected Result & Pass Threshold |
| :--- | :---: | :---: | :---: | :--- | :--- |
| `TC-5.2.1` | `AC-1` | `unit-1` | Unit + Doc-Test | Validate `BulkDisbursementParams`, `BulkDisbursementItem`, `BulkDisbursementResponse`, and `payouts().cashin().bulk(params)` (`POST /disburse/api/v1/disburse/bulk_transaction/`) under Regime 3 `Bearer <access_token>` in `src/resources/payouts/bulk.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.2.2` | `AC-2` | `unit-2` | Unit + Doc-Test | Validate `PayoutsInquiriesService` transaction lookup methods (`transactions(params)` covering `/api/secure/transaction/inquire/` and `/disburse/api/v1/bulk_transaction/inquire/` for banking & non-banking, plus `by_reference(params)` on `/disburse/api/v1/bulk_transaction/inquire_by_reference/`) in `src/resources/payouts/inquiries.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.2.3` | `AC-3` | `unit-3` | Unit + Doc-Test | Validate `payouts().inquiries().user_budget()` (`GET /api/secure/budget/inquire/` returning `UserBudgetResponse { current_budget }` and mapping HTTP 429 `{ status_description, status_code }` to `PaymobError::RateLimited`) and `payouts().inquiries().topup(params)` (`GET /api/secure/topup/inquire/`) in `src/resources/payouts/budget.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.2.4` | `AC-3` | `unit-4` | Integration / Wire | Validate `PayoutsTopupsService` (`from_bank_transfer(params)` enforcing `to_attach_proof.len() <= 2_936_012` bytes / 2.8 MB, and `from_accept_balance(params)` on `POST /api/secure/topup/request/` returning `TopupRecord` with redacted account numbers) in `src/resources/payouts/topups.rs` (positive, boundary, and malformed inputs) | 100% deterministic assertion pass; $\ge 90\%$ line & $\ge 85\%$ branch coverage |
| `TC-5.2.5` | `AC-4` | `unit-1..4` | Security / Property | Verify `[REDACTED]` `Debug` output, zero `f32`/`f64` floats, and `CC <= 6` across all units | 0 secret leaks in logs/panics; 0 Clippy warnings; all doctests pass |

---

## 2. Technical Implementation Plan

### 2.1 Domain Invariants & Storage Schema
- **Domain Invariants**:
  - **Strict 2.8 MB Proof Attachment Ceiling**: Paymob's `POST /api/secure/topup/request/` (`from_bank_transfer`) enforces a hard `2.8 MB` (`2,936,012` bytes) cap on `to_attach_proof`; checked before serialization.
  - **Bank Account Redaction**: `from_account_number` and `to_account_number` in `TopupRecord` are masked in `Debug` output.
- **Rust Type Definitions & Wire Protocol Schema**:

```rust
#![forbid(unsafe_code)]
use serde::{Deserialize, Serialize};

pub const MAX_TOPUP_PROOF_BYTES: usize = 2_936_012; // 2.8 MB

#[derive(Debug, Clone, Deserialize)]
pub struct UserBudgetResponse {
    pub current_budget: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AcceptBalanceTopupParams {
    pub amount: u64,
    #[serde(rename = "type")]
    pub transfer_type: &'static str, // "from_accept_balance"
    pub currency: String,
    pub username: String,
}
```

### 2.2 Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Caller as Rust Application Caller
    participant U1 as unit-1 (src/resources/payouts/bulk.rs)
    participant U2 as unit-2 (src/resources/payouts/inquiries.rs)
    participant UK as unit-4 (src/resources/payouts/topups.rs)
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

All `4` Implementation Units in `US-5.2.0` own **100% disjoint files** so they execute concurrently in isolated `.worktrees/` with zero merge conflicts:

```text
some-paymob/
├── Cargo.toml                                  # Seeded on Module/Story base branch
├── src/
│   ├── lib.rs                                  # Seeded on Module base branch
│   ├── src/resources/payouts/bulk.rs           # Owned exclusively by unit-1 (feat/us-5.2.0/unit-1-bulk-disbursement)
│   ├── src/resources/payouts/inquiries.rs      # Owned exclusively by unit-2 (feat/us-5.2.0/unit-2-payout-tx-inquiries)
│   ├── src/resources/payouts/budget.rs         # Owned exclusively by unit-3 (feat/us-5.2.0/unit-3-budget-and-topup-inquiry)
│   ├── src/resources/payouts/topups.rs         # Owned exclusively by unit-4 (feat/us-5.2.0/unit-4-topup-requests)
└── tests/
    └── payouts_bulk_inquiries_topups_integration.rs         # Executed by story-leader after unit-1..4 merge
```

---

## 4. Implementation Units in Detail & Specialist Agent Assignment

### 4.1 Story Decomposition Score ($S_{\text{story}}$) & Dynamic Unit Count ($K$)
- **$D_1$ (35% Functional Surface)**: `3` — 7 operations across 4 components: `cashin().bulk`, `inquiries().transactions` & `by_reference`, `inquiries().user_budget` & `topup`, and `topups().from_bank_transfer` & `from_accept_balance`
- **$D_2$ (25% Artifact Volume)**: `2` — ~520 production LOC across 4 files under `src/resources/payouts/`
- **$D_3$ (20% Logic Complexity)**: `2` — Pre-flight proof attachment size validation (`<= 2.8 MB` / `2,936,012` bytes) on `from_bank_transfer`, 429 rate-limit status mapping on `budget/inquire/`, and banking vs. non-banking bulk inquiry routing
- **$D_4$ (20% Orthogonal Boundaries)**: `2` — 4 independent files under `src/resources/payouts/` (`bulk.rs`, `inquiries.rs`, `budget.rs`, `topups.rs`)
- **Calculated Score**: $S_{\text{story}} = 0.35(3) + 0.25(2) + 0.20(2) + 0.20(2) = \mathbf{2.35}$ $\to$ **`4` Parallel Units**

### 4.2 Detailed Unit Specifications (`unit-1..4`)

- **`unit-1` (`feat/us-5.2.0/unit-1-bulk-disbursement`)**:
  - **Deliverable Scope**: `BulkDisbursementParams`, `BulkDisbursementItem`, `BulkDisbursementResponse`, and `payouts().cashin().bulk(params)` (`POST /disburse/api/v1/disburse/bulk_transaction/`) under Regime 3 `Bearer <access_token>`
  - **Owned Files**: `src/resources/payouts/bulk.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/bulk.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.2.1`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-2` (`feat/us-5.2.0/unit-2-payout-tx-inquiries`)**:
  - **Deliverable Scope**: `PayoutsInquiriesService` transaction lookup methods (`transactions(params)` covering `/api/secure/transaction/inquire/` and `/disburse/api/v1/bulk_transaction/inquire/` for banking & non-banking, plus `by_reference(params)` on `/disburse/api/v1/bulk_transaction/inquire_by_reference/`)
  - **Owned Files**: `src/resources/payouts/inquiries.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/inquiries.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.2.2`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-3` (`feat/us-5.2.0/unit-3-budget-and-topup-inquiry`)**:
  - **Deliverable Scope**: `payouts().inquiries().user_budget()` (`GET /api/secure/budget/inquire/` returning `UserBudgetResponse { current_budget }` and mapping HTTP 429 `{ status_description, status_code }` to `PaymobError::RateLimited`) and `payouts().inquiries().topup(params)` (`GET /api/secure/topup/inquire/`)
  - **Owned Files**: `src/resources/payouts/budget.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/budget.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.2.3`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)
- **`unit-4` (`feat/us-5.2.0/unit-4-topup-requests`)**:
  - **Deliverable Scope**: `PayoutsTopupsService` (`from_bank_transfer(params)` enforcing `to_attach_proof.len() <= 2_936_012` bytes / 2.8 MB, and `from_accept_balance(params)` on `POST /api/secure/topup/request/` returning `TopupRecord` with redacted account numbers)
  - **Owned Files**: `src/resources/payouts/topups.rs`
  - **Public Contract / Exports**: Public types, builders, and methods defined in `src/resources/payouts/topups.rs` re-exported via parent `mod.rs`
  - **Unit Verification & Target Complexity**: Colocated `#[cfg(test)] mod tests` + runnable rustdoc examples (`TC-5.2.4`), Max Cyclomatic Complexity $CC \le 6$ (cap $\le 10$, nesting $\le 2$)

### 4.3 Best-Fit Specialist Agents per Unit (`msitarzewski/agency-catalog` + Core Roster)

| Unit ID | Branch Name | Primary Implementer Agent(s) (`agency-catalog`) | Reviewing Council Agent(s) | Mandatory Skills Enforced |
| :--- | :--- | :--- | :--- | :--- |
| `unit-1` | `feat/us-5.2.0/unit-1-bulk-disbursement` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-2` | `feat/us-5.2.0/unit-2-payout-tx-inquiries` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-3` | `feat/us-5.2.0/unit-3-budget-and-topup-inquiry` | `backend-architect` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| `unit-4` | `feat/us-5.2.0/unit-4-topup-requests` | `api-tester` | `code-reviewer`, `security-engineer`, `api-tester` | `code-review-council`, `security-audit`, `cyclomatic-complexity` |
| **Story Remediation** | `patch/us-5.2.0-payouts-bulk-inquiries-topups` | `patch-implementer` + `backend-architect` | `code-reviewer-council-president` | Full 6-Gate Re-Verification |

### 4.4 Parallel Execution & Zero-Blocking Contract Seeding Plan
1. **Base Contract Seeding**: Commit `PayoutsInquiriesService` and `PayoutsTopupsService` struct stubs in `src/resources/payouts/mod.rs` on `feat/us-5.2.0-payouts-bulk-inquiries-topups` before branching `unit-1..4`.
2. **Simultaneous Worktree Spawning**: All `4` units are provisioned in `.worktrees/feat-us-5.2.0-unit-1..4` and spawned simultaneously in Wave 2.
3. **Ordered Cascading Merge Sequence**: `unit-1` $\to$ `unit-2` $\to$ `unit-3` $\to$ `unit-4` into `feat/us-5.2.0-payouts-bulk-inquiries-topups` via `gh pr merge <PR> --merge`.

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
- [ ] All STRIDE / ASVS threat mitigations (`TM-1..TM-6`) implemented and covered by security/negative tests in Section 1.3 (`TC-5.2.1..5`).
- [ ] Regional host partitioning, PCI-DSS token redaction, and `ZeroizeOnDrop` controls verified.
- [ ] Independent Security Reviewer agent sign-off posted to the GitHub PR conversation.

---

## 6. Validation Gates & Acceptance Sign-Off

Every Unit PR (`feat/us-5.2.0-payouts-bulk-inquiries-topups/unit-1..4`) and the parent Story PR (`feat/us-5.2.0-payouts-bulk-inquiries-topups`) MUST pass all 6 Quality Gates and post the evidence directly to the GitHub PR conversation before `gh pr merge`:

| Gate | Gate Name | Pass Criteria for `US-5.2.0` | Verification Command / Evidence | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Gate G0** | **Build, Lint & Format** | 0 errors, 0 warnings, 100% `rustfmt` & `clippy` compliance | `CARGO_BUILD_JOBS=1 cargo fmt --check && CARGO_BUILD_JOBS=1 cargo clippy --all-targets --all-features -- -D warnings` | `[ ]` |
| **Gate G1** | **Tests, Coverage & Traceability** | 100% of `AC-1..4` and `TC-5.2.1..5` passing ($\ge 90\%$ line, $\ge 85\%$ branch coverage) | `CARGO_BUILD_JOBS=1 cargo test --all-features` | `[ ]` |
| **Gate G2** | **Security Gateway (`security-audit`)** | All Section 5 STRIDE, constant-time crypto, and `[REDACTED]` checks pass (0 findings) | `security-audit` report on PR | `[ ]` |
| **Gate G-Complexity** | **Cyclomatic Complexity** | Every function $CC \le 6$ target ($CC \le 10$ ceiling, $CC > 15$ blocker, nesting $\le 2$) | `cyclomatic-complexity` table on PR | `[ ]` |
| **Gate G-Docs** | **Documentation & Examples** | 100% public symbols documented + runnable doc-tests + this spec synced | `CARGO_BUILD_JOBS=1 cargo test --doc --all-features` | `[ ]` |
| **Gate G-Review** | **Council President Sign-Off** | Independent Reviewing Council posts `GATE G-REVIEW APPROVED` on GitHub PR | `gh pr comment <PR>` | `[ ]` |

### Final Acceptance Sign-Off Block
- **Story Leader Verification**: All `4` units (`unit-1..4`) merged via cascading `gh pr merge`, story integration suite green, and zero unaddressed findings (or remediated via dedicated `patch-implementer` PRs).
- **Reviewing Council Verdict**: `PENDING` $\to$ `GATE G-REVIEW APPROVED`
