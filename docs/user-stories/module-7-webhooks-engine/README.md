# Module `7`: Constant-Time Cryptographic Webhook Verification Engine (Protocols A–E & Idempotency Guard) (`feat/module-7-webhooks-engine`)

- **Module Branch**: `feat/module-7-webhooks-engine`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `webhooks` (alias `webhook-engine`, default enabled)
- **User Stories**: `2` Stories (`US-7.1.0` .. `US-7.2.0`) | **Total Parallel Units**: `10` Units
- **Merge Order Position to `main`**: `2nd (Merges to `main` immediately after Module 1; before Modules 2, 3, 4, 5, 6, and 8)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements `some-paymob`'s fail-closed, constant-time `HMAC-SHA512` (`hmac` + `sha2` + `subtle::ConstantTimeEq`) webhook verification engine (`src/webhooks/`) across all 5 Paymob callback protocols: **Protocol A** (Transaction Processed POST JSON — 20 lexicographically sorted fields from `body.obj`, including `error_occured` with 1 `'r'`, verified against `?hmac=`), **Protocol B** (Transaction Response GET Query — 20 lexicographically sorted query keys with `order_id` / `order` fallback), **Protocol C** (Card Token POST JSON `{"type": "TOKEN", "obj": {...}}` — 8 lexicographical keys verified against `?hmac=`), **Protocol D** (Subscription Lifecycle POST JSON — `"{trigger_type}for{subscription_data.id}"` verified against body `"hmac"` across all 12 `SubscriptionTriggerType` variants including `"add_secondry_card"`), and **Protocol E** (Payouts Disbursement & Topup POST callbacks), plus the `IdempotentWebhookGuard` extracting `(obj.id, order.id)` and `(paymob_request_id, subscription_data.id)` for atomic database deduplication.

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-7.1.0` | [`us-7.1.0-webhook-verifier-transaction-protocols.md`](./us-7.1.0-webhook-verifier-transaction-protocols.md) — Constant-Time HMAC-SHA512 Core Verifier & Transaction Callbacks (Protocol A POST & Protocol B GET) | `2.95` | `5` | `src/webhooks/verifier.rs`, `src/webhooks/tx_models.rs`, `src/webhooks/canonical_tx.rs`, `src/webhooks/protocol_a_post.rs`, `src/webhooks/protocol_b_get.rs` |
| `US-7.2.0` | [`us-7.2.0-webhook-token-subscription-payout-idempotency.md`](./us-7.2.0-webhook-token-subscription-payout-idempotency.md) — Card Token (Protocol C), Subscription (Protocol D), Payouts (Protocol E), Auto-Dispatcher & IdempotentWebhookGuard | `2.75` | `5` | `src/webhooks/protocol_c_token.rs`, `src/webhooks/protocol_d_subscription.rs`, `src/webhooks/protocol_e_payouts.rs`, `src/webhooks/dispatcher.rs`, `src/webhooks/idempotency.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `7`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 7 (Constant-Time Cryptographic Webhook Verification Engine (Protocols A–E & Idempotency Guard)) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-7-webhooks-engine` (base: `main`).
- Feature flags / Deliverable boundaries: `webhooks` (alias `webhook-engine`, default enabled); ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-7-webhooks-engine/us-7.1.0-webhook-verifier-transaction-protocols.md`
  2. `docs/user-stories/module-7-webhooks-engine/us-7.2.0-webhook-token-subscription-payout-idempotency.md`

### 2. Agent Roster, Roles & Skills (31 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-7-webhooks-engine/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-7-webhooks-engine` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (6 Agents = 2 Story Leaders + 2 Integration Verifiers + 2 Story Review Councils)**:
  - 2 `story-leader` agents (`US-7.1.0`..`US-7.2.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 2 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 2 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (20 Agents = 10 Unit Implementers + 10 Independent Unit Review Councils)**:
  - **US-7.1.0 (5 Units + 5 Reviewers)**:
    - Unit 1 (`feat/us-7.1.0/unit-1-webhook-error-and-core` -> `src/webhooks/verifier.rs`): `WebhookError` enum (`MalformedSignatureHex`, `InvalidSecretKeyLength`, `SignatureMismatch`, `MissingQueryHmac`, `MissingBodyHmac`, `MissingRequiredField`, `InvalidJsonPayload`) and `PaymobWebhookEngine::verify_concatenated_str` computing `Hmac<Sha512>` and comparing digests via `subtle::ConstantTimeEq` | Agent: `security-engineer`
    - Unit 2 (`feat/us-7.1.0/unit-2-transaction-webhook-models` -> `src/webhooks/tx_models.rs`): `TransactionProcessedEvent`, `TransactionWebhookObj` (all 20 signed fields + `payment_key_claims`, `order`, `is_refunded`, `is_voided`, `is_captured`, `refunded_amount_cents`, `captured_amount`), and `TransactionSourceData` (`pan`, `sub_type`, `type`) | Agent: `backend-architect`
    - Unit 3 (`feat/us-7.1.0/unit-3-canonical-20key-builder` -> `src/webhooks/canonical_tx.rs`): Static `const TX_HMAC_KEYS: [&str; 20]` specification table and pre-sized `CanonicalTransactionConcatenator` (`CC <= 3`) formatting booleans as lowercase `"true"`/`"false"` without intermediate heap allocations | Agent: `security-engineer`
    - Unit 4 (`feat/us-7.1.0/unit-4-protocol-a-tx-post` -> `src/webhooks/protocol_a_post.rs`): Protocol A `verify_transaction_post(raw_body, query_hmac)` extracting the 20 lexicographical fields from `body.obj` (`amount_cents`, `created_at`, `currency`, `error_occured`, `has_parent_transaction`, `obj.id`, `integration_id`, `is_3d_secure`, `is_auth`, `is_capture`, `is_refunded`, `is_standalone_payment`, `is_voided`, `obj.order.id`, `owner`, `pending`, `source_data.pan`, `source_data.sub_type`, `source_data.type`, `success`) and verifying against Official Test Vector `192036465` (`fa8ac0b7...`) | Agent: `security-engineer`
    - Unit 5 (`feat/us-7.1.0/unit-5-protocol-b-tx-get` -> `src/webhooks/protocol_b_get.rs`): Protocol B `verify_transaction_get(query_params)` extracting the 20 query parameters with `params.get("order_id").or_else(|| params.get("order"))` fallback and verifying against Official Redirect Test Vector `316004` | Agent: `api-tester`
  - **US-7.2.0 (5 Units + 5 Reviewers)**:
    - Unit 1 (`feat/us-7.2.0/unit-1-protocol-c-card-token` -> `src/webhooks/protocol_c_token.rs`): Protocol C `CardTokenWebhookEvent` (`type: "TOKEN"`, `obj`) and 8-key lexicographical concatenator (`card_subtype`, `created_at`, `email`, `id`, `masked_pan`, `merchant_id`, `order_id`, `token`), verified against Official Test Vector `15978654` (`4c0480c8c5afdba5...`) | Agent: `security-engineer`
    - Unit 2 (`feat/us-7.2.0/unit-2-protocol-d-subscription` -> `src/webhooks/protocol_d_subscription.rs`): Protocol D `SubscriptionWebhookEvent`, 12-variant `SubscriptionTriggerType` enum backed by `const KNOWN_SUBSCRIPTION_TRIGGERS: &[(&str, SubscriptionTriggerType)]` (`CC <= 3`, preserving exact wire strings `"Subscription Created"`, `"add_secondry_card"`, `"Failed Overdue Transaction"`, etc.), and `"{trigger_type}for{subscription_data.id}"` body-`hmac` verifier tested against Official Test Vector `"suspendedfor1264"` (`dd5b3018888d9f98...`) | Agent: `security-engineer`
    - Unit 3 (`feat/us-7.2.0/unit-3-protocol-e-payouts` -> `src/webhooks/protocol_e_payouts.rs`): Protocol E `DisbursementCallback` (`bank_card`, `bank_wallet`, `instant_bank`) and `TopupCallback` (`Approved` | `Rejected`) models plus configurable Payouts account-wide HMAC verifier hook | Agent: `backend-architect`
    - Unit 4 (`feat/us-7.2.0/unit-4-webhook-event-dispatcher` -> `src/webhooks/dispatcher.rs`): `WebhookEvent` enum (`TransactionProcessed`, `TransactionResponseRedirect`, `CardTokenSaved`, `SubscriptionLifecycle`, `PayoutDisbursement`, `PayoutTopup`) and `PaymobWebhookEngine::construct_event(raw_body, query_hmac)` fail-closed auto-dispatcher | Agent: `security-engineer`
    - Unit 5 (`feat/us-7.2.0/unit-5-idempotent-webhook-guard` -> `src/webhooks/idempotency.rs`): `IdempotentWebhookGuard` trait extracting `(idempotency_key, order_correlation_id)` (`(obj.id.to_string(), obj.order.id.to_string())` for transactions and `(paymob_request_id, subscription_data.id.to_string())` for subscriptions) plus thread-safe `InMemoryWebhookDeduplicator` | Agent: `api-tester`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `10` units on `feat/module-7-webhooks-engine` BEFORE branching `feat/us-7.1.0-webhook-verifier-transaction-protocols`..`feat/us-7.2.0-webhook-token-subscription-payout-idempotency`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-7-webhooks-engine` from `main`, pre-scaffold index files + `10` empty unit stub files, and spawn all `2` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-7.1.0`..`US-7.2.0`) into `feat/module-7-webhooks-engine`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `2` Story PRs are `APPROVED` and merged sequentially into `feat/module-7-webhooks-engine`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `7` PR (`feat/module-7-webhooks-engine` -> `main`), post the Module Implementation Report, and run the independent Module `7` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `7` MUST be merged into `main` in position **`2nd (Merges to `main` immediately after Module 1; before Modules 2, 3, 4, 5, 6, and 8)`**—strictly AFTER `Module 1 (`feat/module-1-core-microkernel`)` have merged into `main` and BEFORE `Module 2, Module 3, Module 4, Module 5, Module 6, Module 8`. Before merging the approved Module `7` PR into `main`, sync/rebase `feat/module-7-webhooks-engine` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `7`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```
