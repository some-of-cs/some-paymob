# Module `8`: some-payments Cross-Gateway Unified Adapter & Deterministic Test Harness (`feat/module-8-adapter-test-utils`)

- **Module Branch**: `feat/module-8-adapter-test-utils`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `some-payments-adapter` (alias `some-payment-trait`), `test-utils`, `full`
- **User Stories**: `2` Stories (`US-8.1.0` .. `US-8.2.0`) | **Total Parallel Units**: `6` Units
- **Merge Order Position to `main`**: `8th (Final Module — merges to `main` last after Modules 1, 7, 2, 3, 4, 5, and 6 have all merged to `main`)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements the northbound `some-payments` unified multi-gateway traits (`src/adapter/`) alongside the deterministic `wiremock` test harness and official Paymob test vector suite (`src/test_utils/`): implements `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` for `PaymobClient` with zero-copy type mapping and the `ProviderExt::Paymob(PaymobExt)` escape hatch (`pre_selected_plan`, `special_reference`, `split_description`, Kiosk/Wallet execution); embeds Paymob's verbatim official test vectors and a stateful `PaymobMockServer` simulating 1-hour JWT expiration (`401 {"detail": "incorrect credentials"}`) and Payouts `429 Too Many Requests`.

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-8.1.0` | [`us-8.1.0-some-payments-adapter.md`](./us-8.1.0-some-payments-adapter.md) — some-payments Unified Gateway Trait Implementations & PaymobExt Escape Hatch | `2.00` | `3` | `src/adapter/traits.rs`, `src/adapter/some_payments.rs`, `src/adapter/ext.rs` |
| `US-8.2.0` | [`us-8.2.0-test-vectors-mock-harness.md`](./us-8.2.0-test-vectors-mock-harness.md) — Official Paymob Test Vector Suite, wiremock Multi-Regime Mock Server & Sandbox Constraint Harness | `2.00` | `3` | `src/test_utils/vectors.rs`, `src/test_utils/mock_server.rs`, `src/test_utils/sandbox.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `8`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 8 (some-payments Cross-Gateway Unified Adapter & Deterministic Test Harness) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-8-adapter-test-utils` (base: `main`).
- Feature flags / Deliverable boundaries: `some-payments-adapter` (alias `some-payment-trait`), `test-utils`, `full`; ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-8-adapter-test-utils/us-8.1.0-some-payments-adapter.md`
  2. `docs/user-stories/module-8-adapter-test-utils/us-8.2.0-test-vectors-mock-harness.md`

### 2. Agent Roster, Roles & Skills (23 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-8-adapter-test-utils/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-8-adapter-test-utils` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (6 Agents = 2 Story Leaders + 2 Integration Verifiers + 2 Story Review Councils)**:
  - 2 `story-leader` agents (`US-8.1.0`..`US-8.2.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 2 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 2 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (12 Agents = 6 Unit Implementers + 6 Independent Unit Review Councils)**:
  - **US-8.1.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-8.1.0/unit-1-unified-gateway-traits` -> `src/adapter/traits.rs`): `PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` trait definitions and normalized request/response DTOs (`UnifiedPaymentSession`, `UnifiedRefundReceipt`, `UnifiedWebhookOutcome`, `UnifiedPayoutReceipt`) | Agent: `backend-architect`
    - Unit 2 (`feat/us-8.1.0/unit-2-paymob-provider-impl` -> `src/adapter/some_payments.rs`): `impl PaymentProvider`, `WebhookVerifier`, `SubscriptionProvider`, and `PayoutProvider` for `PaymobClient` mapping `create_payment_session`, `capture_payment`, `refund_payment`, `void_payment`, `charge_saved_method`, and `verify_webhook` | Agent: `backend-architect`
    - Unit 3 (`feat/us-8.1.0/unit-3-paymob-provider-ext` -> `src/adapter/ext.rs`): `PaymobExt` and `ProviderExt::Paymob(PaymobExt)` exposing `pre_selected_plan` (Affordability Widget), `special_reference`, `split_description`, and Kiosk/Mobile Wallet headless execution options | Agent: `api-tester`
  - **US-8.2.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-8.2.0/unit-1-official-test-vectors` -> `src/test_utils/vectors.rs`): Verbatim official Paymob JSON payloads and HMAC-SHA512 digests: Transaction Processed `192036465` (`fa8ac0b7...`), Transaction Response `316004`, Card Token `15978654` (`4c0480c8...`), and Subscription `1264` `"suspendedfor1264"` (`dd5b3018...`) | Agent: `api-tester`
    - Unit 2 (`feat/us-8.2.0/unit-2-multi-regime-mock-server` -> `src/test_utils/mock_server.rs`): `PaymobMockServer` responder simulating Accept Acquiring & Payouts hosts, programmable 1-hour JWT 401 expiry (`{"detail": "incorrect credentials"}`), and Payouts 429 (`{ status_description, status_code }`) responses | Agent: `api-tester`
    - Unit 3 (`feat/us-8.2.0/unit-3-sandbox-constraint-helpers` -> `src/test_utils/sandbox.rs`): Sandbox diagnostic helpers validating 30-day test credential age, flagging Kiosk/BNPL sandbox mode limitations, and generating signed payloads compatible with Paymob's Webhook Testing Tool | Agent: `api-tester`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `6` units on `feat/module-8-adapter-test-utils` BEFORE branching `feat/us-8.1.0-some-payments-adapter`..`feat/us-8.2.0-test-vectors-mock-harness`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-8-adapter-test-utils` from `main`, pre-scaffold index files + `6` empty unit stub files, and spawn all `2` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-8.1.0`..`US-8.2.0`) into `feat/module-8-adapter-test-utils`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `2` Story PRs are `APPROVED` and merged sequentially into `feat/module-8-adapter-test-utils`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `8` PR (`feat/module-8-adapter-test-utils` -> `main`), post the Module Implementation Report, and run the independent Module `8` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `8` MUST be merged into `main` in position **`8th (Final Module — merges to `main` last after Modules 1, 7, 2, 3, 4, 5, and 6 have all merged to `main`)`**—strictly AFTER `Modules 1, 7, 2, 3, 4, 5, and 6` have merged into `main` and BEFORE `None (Completes `v0.8.0` full SDK milestone)`. Before merging the approved Module `8` PR into `main`, sync/rebase `feat/module-8-adapter-test-utils` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `8`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```
