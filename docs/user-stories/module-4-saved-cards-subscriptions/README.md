# Module `4`: Saved Cards (CIT/MIT), Headless Payments & Subscriptions Recurring Billing Engine (`feat/module-4-saved-cards-subscriptions`)

- **Module Branch**: `feat/module-4-saved-cards-subscriptions`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `saved-cards` (alias `tokens`), `subscriptions`
- **User Stories**: `3` Stories (`US-4.1.0` .. `US-4.3.0`) | **Total Parallel Units**: `11` Units
- **Merge Order Position to `main`**: `5th (Merges to `main` after Modules 1, 7, 2, and 3; before Modules 5, 6, and 8)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements saved card tokenization and headless payment execution (`src/resources/saved_cards/`) alongside the complete 18-operation Subscriptions & Recurring Billing engine (`src/resources/subscriptions/`): Customer-Initiated Transactions (CIT via Intention `card_tokens`), Merchant-Initiated Transactions (MIT off-session MOTO charges), Mobile Wallet direct charges (`Vodafone Cash`, `Orange Cash`, `e& money`), and Kiosk reference payments (`Fawry`, `Aman`, `Masary`) via `POST /api/acceptance/payments/pay`; Subscription Plan CRUD & lifecycle (`POST/PUT/GET/suspend/resume /api/acceptance/subscription-plans`); Subscription enrollment, state transitions (`suspend`, `resume`, `cancel`, `update`), multi-card management (`list`, `add_secondary`, `change_primary`, `delete_secondary`), webhook registration, transaction history (`last-transaction`, `transactions`), and the composite `refund_last_transaction(sub_id, Option<u64>)` helper.

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-4.1.0` | [`us-4.1.0-saved-cards-headless-pay.md`](./us-4.1.0-saved-cards-headless-pay.md) — Saved Card Tokenization (CIT/MIT) & Headless Payments (MOTO, Mobile Wallet & Kiosk) | `2.00` | `3` | `src/resources/saved_cards/sources.rs`, `src/resources/saved_cards/cit_mit.rs`, `src/resources/saved_cards/service.rs` |
| `US-4.2.0` | [`us-4.2.0-subscription-plans.md`](./us-4.2.0-subscription-plans.md) — Subscription Plans CRUD & Plan Lifecycle (POST/PUT/GET/Suspend/Resume) | `2.00` | `3` | `src/resources/subscriptions/plan_models.rs`, `src/resources/subscriptions/plan_params.rs`, `src/resources/subscriptions/plans_service.rs` |
| `US-4.3.0` | [`us-4.3.0-subscription-lifecycle-cards-refunds.md`](./us-4.3.0-subscription-lifecycle-cards-refunds.md) — Subscription Lifecycle Actions, Card Vault Management, Transaction History & refund_last_transaction | `2.75` | `5` | `src/resources/subscriptions/models.rs`, `src/resources/subscriptions/lifecycle.rs`, `src/resources/subscriptions/cards.rs`, `src/resources/subscriptions/history.rs`, `src/resources/subscriptions/refund.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `4`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 4 (Saved Cards (CIT/MIT), Headless Payments & Subscriptions Recurring Billing Engine) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-4-saved-cards-subscriptions` (base: `main`).
- Feature flags / Deliverable boundaries: `saved-cards` (alias `tokens`), `subscriptions`; ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-4-saved-cards-subscriptions/us-4.1.0-saved-cards-headless-pay.md`
  2. `docs/user-stories/module-4-saved-cards-subscriptions/us-4.2.0-subscription-plans.md`
  3. `docs/user-stories/module-4-saved-cards-subscriptions/us-4.3.0-subscription-lifecycle-cards-refunds.md`

### 2. Agent Roster, Roles & Skills (36 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-4-saved-cards-subscriptions/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-4-saved-cards-subscriptions` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (9 Agents = 3 Story Leaders + 3 Integration Verifiers + 3 Story Review Councils)**:
  - 3 `story-leader` agents (`US-4.1.0`..`US-4.3.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 3 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 3 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (22 Agents = 11 Unit Implementers + 11 Independent Unit Review Councils)**:
  - **US-4.1.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-4.1.0/unit-1-payment-sources` -> `src/resources/saved_cards/sources.rs`): `PaymentSource` enum (`SavedToken { identifier: SecretString, subtype: "TOKEN", cvn: Option<SecretString> }`, `MobileWallet { identifier: String, subtype: "WALLET" }`, `KioskAggregator { identifier: "AGGREGATOR", subtype: "AGGREGATOR" }`) with `[REDACTED]` `Debug` formatting | Agent: `security-engineer`
    - Unit 2 (`feat/us-4.1.0/unit-2-cit-mit-workflows` -> `src/resources/saved_cards/cit_mit.rs`): `CitCardTokenConfig` (wiring saved card tokens into `CreateIntentionParams::card_tokens`), `MitChargeParams` (`payment_token: SecretString`, `saved_token: SecretString`, `cvn: Option<SecretString>`), and `use_cvc_with_moto` validation guard | Agent: `backend-architect`
    - Unit 3 (`feat/us-4.1.0/unit-3-headless-pay-service` -> `src/resources/saved_cards/service.rs`): `SavedCardsService` (`pay_with_token_mit`, `pay_with_wallet`, `pay_with_kiosk`, `pay_raw`) executing `POST /api/acceptance/payments/pay` under Regime 2 `Bearer <auth_token>` and returning `HeadlessPayResponse` (`transaction`, `redirect_url`, `kiosk_bill_reference`) | Agent: `api-tester`
  - **US-4.2.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-4.2.0/unit-1-plan-models-frequency` -> `src/resources/subscriptions/plan_models.rs`): `PlanFrequency` enum (`Days7 = 7`, `Days15 = 15`, `Days30 = 30`, `Days60 = 60`, `Days90 = 90`, `Days180 = 180`, `Days360 = 360` mapped via static lookup table `CC <= 3`), `PlanType` (`Rent`), and `SubscriptionPlan` response struct | Agent: `backend-architect`
    - Unit 2 (`feat/us-4.2.0/unit-2-plan-params` -> `src/resources/subscriptions/plan_params.rs`): `CreateSubscriptionPlanParams` (enforcing `1 <= name.len() <= 200`, required `frequency: PlanFrequency`, required `integration: u64` MIGS MOTO ID, optional `webhook_url`, `reminder_days`, `retrial_days`, `plan_type`, `number_of_deductions`, `amount_cents`, `use_transaction_amount`, `is_active`, `fee`) and `UpdateSubscriptionPlanParams` | Agent: `backend-architect`
    - Unit 3 (`feat/us-4.2.0/unit-3-plans-service` -> `src/resources/subscriptions/plans_service.rs`): `SubscriptionPlansService` (`create` `POST /api/acceptance/subscription-plans`, `update` `PUT /api/acceptance/subscription-plans/{id}`, `list` `GET /api/acceptance/subscription-plans?page=N`, `suspend`, and `resume`) under Regime 2 `Bearer <auth_token>` | Agent: `api-tester`
  - **US-4.3.0 (5 Units + 5 Reviewers)**:
    - Unit 1 (`feat/us-4.3.0/unit-1-subscription-models` -> `src/resources/subscriptions/models.rs`): `Subscription` record (`id`, `plan_id`, `state`, `initial_transaction`, `amount_cents`, `starts_at`, `next_billing`, `reminder_date`, `ends_at`, `resumed_at`, `suspended_at`, `reactivated_at`, `created_at`), `SubscriptionState`, `SubscriptionListFilter` (`transaction`, `plan_id`, `state`), and `SubscriptionCard` (`id`, `card_data`, `token: SecretString`, `created_at`, `is_primary`, `masked_pan`, `failed_attempts`) | Agent: `backend-architect`
    - Unit 2 (`feat/us-4.3.0/unit-2-subscription-lifecycle` -> `src/resources/subscriptions/lifecycle.rs`): `SubscriptionsService` lifecycle methods (`create` via Intention 3DS enrollment, `retrieve(sub_id)` `GET /api/acceptance/subscriptions/{id}`, `list(filters)`, `update(sub_id, params)`, `suspend(sub_id)` `POST /api/acceptance/subscriptions/{id}/suspend`, `resume(sub_id)`, `cancel(sub_id)`) under Regime 2 `Bearer <auth_token>` | Agent: `backend-architect`
    - Unit 3 (`feat/us-4.3.0/unit-3-subscription-cards` -> `src/resources/subscriptions/cards.rs`): `SubscriptionCardsService` (`paymob.subscriptions().cards().list(sub_id)`, `.add_secondary(...)`, `.change_primary(sub_id, card_id)` `POST /api/acceptance/subscriptions/{id}/change-primary-card` with `{"card": card_id}`, and `.delete_secondary(sub_id, card_id)` `POST /api/acceptance/subscriptions/{id}/delete-card`) | Agent: `backend-architect`
    - Unit 4 (`feat/us-4.3.0/unit-4-subscription-history-webhook` -> `src/resources/subscriptions/history.rs`): `register_webhook(sub_id, url)`, `last_transaction(sub_id)` (`GET /api/acceptance/subscriptions/{id}/last-transaction` returning full `Transaction` with `api_source: "SUBSCRIPTION"`), and `list_transactions(sub_id)` (`GET /api/acceptance/subscriptions/{id}/transactions`) | Agent: `backend-architect`
    - Unit 5 (`feat/us-4.3.0/unit-5-subscription-refund-helper` -> `src/resources/subscriptions/refund.rs`): Composite `paymob.subscriptions().refund_last_transaction(sub_id, amount_cents: Option<u64>)` (`#[cfg(all(feature = "subscriptions", feature = "manage"))]`) fetching `last_transaction(sub_id)`, asserting `tx.success && !tx.is_refunded`, and delegating to `manage().refund(...)` for full or partial deduction amount | Agent: `api-tester`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `11` units on `feat/module-4-saved-cards-subscriptions` BEFORE branching `feat/us-4.1.0-saved-cards-headless-pay`..`feat/us-4.3.0-subscription-lifecycle-cards-refunds`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-4-saved-cards-subscriptions` from `main`, pre-scaffold index files + `11` empty unit stub files, and spawn all `3` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-4.1.0`..`US-4.3.0`) into `feat/module-4-saved-cards-subscriptions`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `3` Story PRs are `APPROVED` and merged sequentially into `feat/module-4-saved-cards-subscriptions`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `4` PR (`feat/module-4-saved-cards-subscriptions` -> `main`), post the Module Implementation Report, and run the independent Module `4` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `4` MUST be merged into `main` in position **`5th (Merges to `main` after Modules 1, 7, 2, and 3; before Modules 5, 6, and 8)`**—strictly AFTER `Module 1 (`feat/module-1-core-microkernel`), Module 7 (`feat/module-7-webhooks-engine`), Module 2 (`feat/module-2-intentions-checkout`), Module 3 (`feat/module-3-manage-inquiries-splits`)` have merged into `main` and BEFORE `Module 8`. Before merging the approved Module `4` PR into `main`, sync/rebase `feat/module-4-saved-cards-subscriptions` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `4`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```
