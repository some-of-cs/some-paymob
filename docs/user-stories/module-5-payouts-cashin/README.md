# Module `5`: Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups (`feat/module-5-payouts-cashin`)

- **Module Branch**: `feat/module-5-payouts-cashin`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `payouts`
- **User Stories**: `2` Stories (`US-5.1.0` .. `US-5.2.0`) | **Total Parallel Units**: `8` Units
- **Merge Order Position to `main`**: `6th (Merges to `main` after Modules 1, 7, 2, 3, and 4; before Modules 6 and 8)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements the complete 17-operation Paymob Send Payouts & Disbursement API (`src/resources/payouts/`) routed to the regional Payouts host (`https://payouts.paymobsolutions.com/`, `https://payouts.paymob.sa/`, `https://payouts-uae.paymobsolutions.com/`): OAuth 2.0 `password` and `refresh_token` grants (`POST /api/secure/o/token/`); Instant Cashin (`POST /api/secure/disburse/`) across `vodafone`, `etisalat`, `orange`, `bank_wallet`, `bank_card` (`salary | credit_card | prepaid_card | cash_transfer`), `instant_bank`, and `egyptian_post`, plus Aman cancellation (`POST /api/secure/transaction/aman/cancel/`); Bulk Disbursements (`POST /disburse/api/v1/disburse/bulk_transaction/`); Transaction, Reference, User Budget (`GET /api/secure/budget/inquire/`), and Topup Inquiries (`GET /api/secure/topup/inquire/`); and Topup Requests (`POST /api/secure/topup/request/`) from Bank Transfers (`<= 2.8 MB` proof attachment guard) and Accept Balance.

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-5.1.0` | [`us-5.1.0-payouts-oauth-instant-cashin.md`](./us-5.1.0-payouts-oauth-instant-cashin.md) — Payouts OAuth 2.0 Token Facade & Instant Cashin Disbursements (7 Issuers + Aman Cancel) | `2.55` | `4` | `src/resources/payouts/auth.rs`, `src/resources/payouts/models.rs`, `src/resources/payouts/wallet_cashin.rs`, `src/resources/payouts/bank_cashin.rs` |
| `US-5.2.0` | [`us-5.2.0-payouts-bulk-inquiries-topups.md`](./us-5.2.0-payouts-bulk-inquiries-topups.md) — Bulk Disbursements, Payout Inquiries, User Budget & Topup Requests | `2.35` | `4` | `src/resources/payouts/bulk.rs`, `src/resources/payouts/inquiries.rs`, `src/resources/payouts/budget.rs`, `src/resources/payouts/topups.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `5`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 5 (Paymob Send — Payouts OAuth2, Instant/Bulk Cashin, Inquiries & Topups) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-5-payouts-cashin` (base: `main`).
- Feature flags / Deliverable boundaries: `payouts`; ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-5-payouts-cashin/us-5.1.0-payouts-oauth-instant-cashin.md`
  2. `docs/user-stories/module-5-payouts-cashin/us-5.2.0-payouts-bulk-inquiries-topups.md`

### 2. Agent Roster, Roles & Skills (27 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-5-payouts-cashin/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-5-payouts-cashin` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (6 Agents = 2 Story Leaders + 2 Integration Verifiers + 2 Story Review Councils)**:
  - 2 `story-leader` agents (`US-5.1.0`..`US-5.2.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 2 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 2 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (16 Agents = 8 Unit Implementers + 8 Independent Unit Review Councils)**:
  - **US-5.1.0 (4 Units + 4 Reviewers)**:
    - Unit 1 (`feat/us-5.1.0/unit-1-payouts-auth-facade` -> `src/resources/payouts/auth.rs`): `PayoutsAuthService` (`payouts().auth().generate_token()`, `.refresh_token()`) wrapping `POST /api/secure/o/token/` (Basic Auth `{client_id}:{client_secret}` + form grants), returning `PayoutsTokenResponse` (`access_token: SecretString`, `refresh_token: SecretString`, `expires_in: 3600`, `scope`, `token_type`), and mapping `{"error": "invalid_grant"}` to `PaymobError::AuthenticationError` | Agent: `security-engineer`
    - Unit 2 (`feat/us-5.1.0/unit-2-disburse-models` -> `src/resources/payouts/models.rs`): `DisburseIssuer` enum (`Vodafone`, `Etisalat`, `Orange`, `BankWallet`, `BankCard`, `InstantBank`, `EgyptianPost` via static lookup slice `CC <= 3`), `BankTransactionType` (`Salary`, `CreditCard`, `PrepaidCard`, `CashTransfer`), `DisbursementResponse` (`transaction_id`, `msisdn`, `issuer`, `amount`, `full_name`, `disbursement_status`, `status_code`, `status_description`, `aman_cashing_details`, `created_at`, `updated_at`), and `AmanCashingDetails` | Agent: `backend-architect`
    - Unit 3 (`feat/us-5.1.0/unit-3-mobile-wallet-cashin` -> `src/resources/payouts/wallet_cashin.rs`): `PayoutsCashinService` mobile & bank wallet methods (`vodafone(params)`, `etisalat(params)`, `orange(params)`, `bank_wallet(params)`) dispatching `POST /api/secure/disburse/` with validated `msisdn`, `amount`, `client_reference_id`, and `customer_bears_fees` | Agent: `backend-architect`
    - Unit 4 (`feat/us-5.1.0/unit-4-bank-post-aman-cashin` -> `src/resources/payouts/bank_cashin.rs`): `PayoutsCashinService` bank & cash methods (`bank_card(params)` with redacted `bank_card_number`, `bank_code`, `bank_transaction_type`; `bank_instant(params)`; `egyptian_post(params)`; and `cancel_aman(params)` on `POST /api/secure/transaction/aman/cancel/`) | Agent: `api-tester`
  - **US-5.2.0 (4 Units + 4 Reviewers)**:
    - Unit 1 (`feat/us-5.2.0/unit-1-bulk-disbursement` -> `src/resources/payouts/bulk.rs`): `BulkDisbursementParams`, `BulkDisbursementItem`, `BulkDisbursementResponse`, and `payouts().cashin().bulk(params)` (`POST /disburse/api/v1/disburse/bulk_transaction/`) under Regime 3 `Bearer <access_token>` | Agent: `backend-architect`
    - Unit 2 (`feat/us-5.2.0/unit-2-payout-tx-inquiries` -> `src/resources/payouts/inquiries.rs`): `PayoutsInquiriesService` transaction lookup methods (`transactions(params)` covering `/api/secure/transaction/inquire/` and `/disburse/api/v1/bulk_transaction/inquire/` for banking & non-banking, plus `by_reference(params)` on `/disburse/api/v1/bulk_transaction/inquire_by_reference/`) | Agent: `backend-architect`
    - Unit 3 (`feat/us-5.2.0/unit-3-budget-and-topup-inquiry` -> `src/resources/payouts/budget.rs`): `payouts().inquiries().user_budget()` (`GET /api/secure/budget/inquire/` returning `UserBudgetResponse { current_budget }` and mapping HTTP 429 `{ status_description, status_code }` to `PaymobError::RateLimited`) and `payouts().inquiries().topup(params)` (`GET /api/secure/topup/inquire/`) | Agent: `backend-architect`
    - Unit 4 (`feat/us-5.2.0/unit-4-topup-requests` -> `src/resources/payouts/topups.rs`): `PayoutsTopupsService` (`from_bank_transfer(params)` enforcing `to_attach_proof.len() <= 2_936_012` bytes / 2.8 MB, and `from_accept_balance(params)` on `POST /api/secure/topup/request/` returning `TopupRecord` with redacted account numbers) | Agent: `api-tester`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `8` units on `feat/module-5-payouts-cashin` BEFORE branching `feat/us-5.1.0-payouts-oauth-instant-cashin`..`feat/us-5.2.0-payouts-bulk-inquiries-topups`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-5-payouts-cashin` from `main`, pre-scaffold index files + `8` empty unit stub files, and spawn all `2` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-5.1.0`..`US-5.2.0`) into `feat/module-5-payouts-cashin`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `2` Story PRs are `APPROVED` and merged sequentially into `feat/module-5-payouts-cashin`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `5` PR (`feat/module-5-payouts-cashin` -> `main`), post the Module Implementation Report, and run the independent Module `5` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `5` MUST be merged into `main` in position **`6th (Merges to `main` after Modules 1, 7, 2, 3, and 4; before Modules 6 and 8)`**—strictly AFTER `Module 1 (`feat/module-1-core-microkernel` — Regime 3 OAuth2 & `PaymobRegion` Payouts host routing)` have merged into `main` and BEFORE `Module 8`. Before merging the approved Module `5` PR into `main`, sync/rebase `feat/module-5-payouts-cashin` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `5`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```
