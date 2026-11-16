# Module `3`: Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models (`feat/module-3-manage-inquiries-splits`)

- **Module Branch**: `feat/module-3-manage-inquiries-splits`
- **Base Branch**: `main`
- **Field Profile**: `software` (`engineering,security,testing`)
- **Cargo Feature Flag(s)**: `manage`, `inquiries`, `quicklinks`, `splits` (and `transactions` alias)
- **User Stories**: `3` Stories (`US-3.1.0` .. `US-3.3.0`) | **Total Parallel Units**: `10` Units
- **Merge Order Position to `main`**: `4th (Merges to `main` after Modules 1, 7, and 2; before Modules 4, 5, 6, and 8)`

## 1. Module Overview & User Story / Implementation Unit Index

Implements post-authorization financial lifecycle operations (`src/resources/manage/`), reconciliation inquiries (`src/resources/inquiries/`), programmatic payment links (`src/resources/quicklinks/`), and marketplace split/convenience-fee models (`src/resources/splits/`): Refund (`POST /api/acceptance/void_refund/refund`), Void (`POST /api/acceptance/void_refund/void`), and Auth/Capture (`POST /api/acceptance/capture`); Transaction Inquiry by ID (`GET /api/acceptance/transactions/{id}`), Order/Reference Inquiry (`POST /api/ecommerce/orders/transaction_inquiry`), Order Card Tokens Inquiry (`POST /api/acceptance/order_card_tokens`), and Order Record Inquiry (`GET /api/ecommerce/orders/{id}`); QuickLinks create/cancel (`POST /api/ecommerce/payment-links`, `/cancel`); and Split Amount, Split Payment (up to 3 cards), and Convenience Fee configurations.

| Story ID | Title & Spec Link | $S_{\text{story}}$ Score | Parallel Units ($K$) | Owned Directory / Paths |
| :--- | :--- | :---: | :---: | :--- |
| `US-3.1.0` | [`us-3.1.0-payment-refund-void-capture.md`](./us-3.1.0-payment-refund-void-capture.md) — Payment Management — Full/Partial Refund, Unsettled Void & Auth/Capture | `2.00` | `3` | `src/resources/manage/models.rs`, `src/resources/manage/refund.rs`, `src/resources/manage/void_capture.rs` |
| `US-3.2.0` | [`us-3.2.0-transaction-order-inquiries.md`](./us-3.2.0-transaction-order-inquiries.md) — Transaction, Order & Saved Card Token Reconciliation Inquiries | `2.20` | `4` | `src/resources/inquiries/by_id.rs`, `src/resources/inquiries/by_order.rs`, `src/resources/inquiries/card_tokens.rs`, `src/resources/inquiries/order_inquiry.rs` |
| `US-3.3.0` | [`us-3.3.0-quicklinks-splits-fees.md`](./us-3.3.0-quicklinks-splits-fees.md) — QuickLinks Payment Links API, Marketplace Split Rules & Convenience Fee Engine | `2.00` | `3` | `src/resources/quicklinks.rs`, `src/resources/splits/models.rs`, `src/resources/splits/convenience_fees.rs` |

---

## 2. Copy-Paste Module Execution Prompt

Copy and paste the prompt block below directly into your AI agent session to execute **Module `3`** end-to-end using the `some-divide-and-conquer` multi-agent workflow:

```text
Execute Module 3 (Payment Lifecycle Management, Transaction Inquiries, QuickLinks & Split Models) on https://github.com/some-of-cs/some-paymob (base: main) using the some-divide-and-conquer plugin in full parallel mode.

### 1. Architecture, Scope & Feature/Deliverable Contract
- Module branch: `feat/module-3-manage-inquiries-splits` (base: `main`).
- Feature flags / Deliverable boundaries: `manage`, `inquiries`, `quicklinks`, `splits` (and `transactions` alias); ensure standalone `core` and default feature builds (`cargo check`, `cargo check --no-default-features`, `cargo check --all-features`) remain 100% green.
- Specifications to implement 100% (every Acceptance Criterion `AC-*` and Test Case `TC-*`):
  1. `docs/user-stories/module-3-manage-inquiries-splits/us-3.1.0-payment-refund-void-capture.md`
  2. `docs/user-stories/module-3-manage-inquiries-splits/us-3.2.0-transaction-order-inquiries.md`
  3. `docs/user-stories/module-3-manage-inquiries-splits/us-3.3.0-quicklinks-splits-fees.md`

### 2. Agent Roster, Roles & Skills (34 Total Agents)
- **Shared Infrastructure Agents (3)**:
  - `git-workflow-master` (1): Exclusive owner of `.worktrees/`, branches, PR creation, and ordered cascading merges.
  - `github-projects-kanban` (1): Syncs `.agents/checkpoints/module-3-manage-inquiries-splits/checkpoint.json` and PR conversation reports.
  - `quota-sentinel` (1): Monitors rate limits and flushes state on HTTP 429 / 1% remaining quota.
- **Tier 1 — Module Level (2 Agents)**:
  - `module-leader` (1) on `feat/module-3-manage-inquiries-splits` (3-minute watchdog `*/3 * * * *`). NEVER spawns Unit Implementers directly and NEVER edits code/deliverables directly.
  - Independent `code-review-council` + `code-reviewer-council-president` (1) for the Module PR.
- **Tier 2 — Story Level (9 Agents = 3 Story Leaders + 3 Integration Verifiers + 3 Story Review Councils)**:
  - 3 `story-leader` agents (`US-3.1.0`..`US-3.3.0`, 1-minute watchdog `* * * * *`). NEVER edits code/deliverables directly.
  - 3 integration/API tester agents (`testing-api-tester`) for story-level verification.
  - 3 independent `code-review-council` subagents (1 per Story PR).
- **Tier 3 — Unit Level (20 Agents = 10 Unit Implementers + 10 Independent Unit Review Councils)**:
  - **US-3.1.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-3.1.0/unit-1-transaction-models` -> `src/resources/manage/models.rs`): `Transaction` and child transaction response structs (`id`, `pending`, `amount_cents`, `success`, `is_auth`, `is_capture`, `is_void`, `is_refund`, `is_voided`, `is_refunded`, `is_captured`, `parent_transaction`, `refunded_amount_cents`, `captured_amount`, `integration_id`, `currency`, `source_data`, `order`, `created_at`) | Agent: `backend-architect`
    - Unit 2 (`feat/us-3.1.0/unit-2-refund-operation` -> `src/resources/manage/refund.rs`): `RefundParams` (`transaction_id: u64`, `amount_cents: u64`), `paymob.manage().refund(params)` (`POST /api/acceptance/void_refund/refund`), and parser mapping HTTP 400 `"Requested Refund Amount is greater than the maximum refund amount permissible..."` to `PaymobError::RefundExceedsPermissibleAmount` | Agent: `backend-architect`
    - Unit 3 (`feat/us-3.1.0/unit-3-void-and-capture` -> `src/resources/manage/void_capture.rs`): `VoidParams` (`transaction_id: u64`), `CaptureParams` (`transaction_id: u64`, `amount_cents: u64`), `paymob.manage().void(params)` (`POST /api/acceptance/void_refund/void`), and `paymob.manage().capture(params)` (`POST /api/acceptance/capture`) with configurable Regime 1 Token / Regime 2 Bearer auth | Agent: `api-tester`
  - **US-3.2.0 (4 Units + 4 Reviewers)**:
    - Unit 1 (`feat/us-3.2.0/unit-1-inquiry-by-tx-id` -> `src/resources/inquiries/by_id.rs`): `paymob.inquiries().by_transaction_id(tx_id)` (`GET /api/acceptance/transactions/{transaction_id}`) under Regime 2 `Authorization: Bearer <auth_token>` | Agent: `backend-architect`
    - Unit 2 (`feat/us-3.2.0/unit-2-inquiry-by-order-ref` -> `src/resources/inquiries/by_order.rs`): `TransactionInquiryParams` (requiring at least one of `order_id` or `merchant_order_id` / `special_reference`), `InquiredTransaction` (`paid_at`, `fees`, `vat`, `accept_fees_cents_int`, `vat_cents_int`, `settlement_amount_cents_int`, `is_settled`, `is_reconciled`, `reconciliation_id`, `cogs`, `installment_info`, `split_description`, `is_split_payment`, `allow_cardless_refund`, `public_customer_fingerprint`), and `POST /api/ecommerce/orders/transaction_inquiry` | Agent: `backend-architect`
    - Unit 3 (`feat/us-3.2.0/unit-3-order-card-tokens` -> `src/resources/inquiries/card_tokens.rs`): `CardTokenEnvelope` (`type: "TOKEN"`, `obj: CardTokenObject` with `token: SecretString`, `masked_pan`, `card_subtype`, `merchant_id`, `order_id`, `email`, `next_payment_intention`) and `paymob.inquiries().card_tokens_by_order(order_id)` (`POST /api/acceptance/order_card_tokens` with body `"auth_token"`) | Agent: `backend-architect`
    - Unit 4 (`feat/us-3.2.0/unit-4-order-record-inquiry` -> `src/resources/inquiries/order_inquiry.rs`): `OrderInquiryResponse` (order metadata + nested payment attempt transactions) and `paymob.inquiries().order(order_id)` (`GET /api/ecommerce/orders/{order_id}`) using Regime 2 `Bearer <auth_token>` | Agent: `api-tester`
  - **US-3.3.0 (3 Units + 3 Reviewers)**:
    - Unit 1 (`feat/us-3.3.0/unit-1-quicklinks-service` -> `src/resources/quicklinks.rs`): `CreateQuickLinkParams` (`amount_cents`, `currency`, `integrations: Vec<u64>`, optional `description`, `full_name`, `email`, `phone_number`, `redirection_url`), `QuickLinkResponse` (`id`, `url`, `client_url`), and `QuickLinksService` (`create` `POST /api/ecommerce/payment-links` & `cancel` `POST /api/ecommerce/payment-links/cancel` under Regime 2 `Bearer`) | Agent: `backend-architect`
    - Unit 2 (`feat/us-3.3.0/unit-2-split-models` -> `src/resources/splits/models.rs`): `SplitRecipientRule` and `SplitDescription` (multi-recipient marketplace settlement rules) plus `SplitPaymentConfig` (multi-card customer checkout enforcing `1 <= cards.len() <= 3`) | Agent: `backend-architect`
    - Unit 3 (`feat/us-3.3.0/unit-3-convenience-fees` -> `src/resources/splits/convenience_fees.rs`): `ConvenienceFeeConfig`, `FeeCalculationMode` (`PercentageBps(u32)`, `FixedCents(u64)`, `Combination { bps: u32, fixed_cents: u64 }`), `max_fee_cents: Option<u64>`, `is_refundable: bool`, `CardFeeRule` (`Uniform`, `DebitVsCredit`, `BinRange`, `DomesticVsInternational`), and checked integer fee calculator | Agent: `backend-architect`
- **On-Demand Remediation Agent**: `patch-implementer` (spawned by any Story Leader or Module Leader whenever a Review Council, CodeScene, or CodeRabbit check flags any issue).
- **Skills Loaded**: `divide-and-conquer-orchestrator`, `preflight-git-gh`, `git-workflow-master`, `github-projects-kanban`, `quota-sentinel`, `security-audit`, `code-review-council`, `code-reviewer-council-president`, `cyclomatic-complexity`, `patch-implementer`.

### 3. Mandatory Anti-Regression Rules (Hard Invariants)
1. **Zero Shared-Index (`mod.rs` / `lib.rs`) Clobbering Across Stories & Units**: In Wave 1, `module-leader` MUST pre-scaffold all module index files (`src/lib.rs`, `mod.rs`, `Cargo.toml`) and empty stub files for all `10` units on `feat/module-3-manage-inquiries-splits` BEFORE branching `feat/us-3.1.0-payment-refund-void-capture`..`feat/us-3.3.0-quicklinks-splits-fees`. Story and Unit branches MUST NOT delete sibling declarations.
2. **Never Self-Review or Merge Before Independent Subagent Approval**: Every Unit PR, Story PR, Patch PR, and Module PR MUST receive a structured Implementation Report comment AND an independent `code-review-council` subagent review (`event="COMMENT"` when using a single GitHub account to avoid self-approval API errors). If ANY gate or automated PR comment (CodeScene / CodeRabbit) flags an issue, iterate on the Unit branch or spawn `patch-implementer` at the Story/Module tier and re-run the Reviewer subagent until `Gate G-Review: Approved` with 0 issues.
3. **Plain UTF-8 Commits Only**: When committing files via GitHub API / MCP tools (`GITHUB_COMMIT_MULTIPLE_FILES`), ALWAYS pass plain-text UTF-8 strings with `encoding: "utf-8"` (never pre-encode Base64, preventing binary corruption).
4. **Static Lookup Tables for Multi-Branch Mapping (`CC <= 6`, Nesting `<= 2`)**: Any enum or dispatcher with >5 variants mapping to/from strings MUST use a static `const KNOWN_*: &[(&str, Self)]` lookup table or declarative map so cyclomatic complexity stays `CC <= 3` (never write a 10+ arm `match`/`switch` that fails `G-Complexity`).
5. **Security, Bounds & Secret Hygiene (`G2` & `G-Law`)**: Enforce domain bounds during deserialization, require non-empty suffixes on prefixed IDs, redact all secrets/tokens/PII (`[REDACTED]`) in `Debug`/logs, zeroize intermediate credential buffers (`ZeroizeOnDrop`), verify all webhooks in constant time (`subtle::ConstantTimeEq`), and use checked integer math for monetary values (`MinorUnitAmount(u64)`, zero `f32`/`f64` floats).
6. **Complete Documentation, Runnable Doc-Tests & Compile-Fail Guards (`G-Docs` & `G1`)**: Every public symbol/interface MUST include doc comments, runnable doc-tests, and negative/compile-time guards where applicable.
7. **Memory-Safe Verification Execution**: Run build, lint, format, test, and doc-test commands sequentially (e.g., `CARGO_BUILD_JOBS=1` in memory-constrained sandboxes) so linking never OOMs.

### 4. Step-by-Step Execution & Strict Merge-Order Constraint into `main`
- **Step 1 (Gate 0 & Wave 1 Scaffolding)**: Run `preflight-git-gh`, start `quota-sentinel`, create `feat/module-3-manage-inquiries-splits` from `main`, pre-scaffold index files + `10` empty unit stub files, and spawn all `3` `story-leader` subagents in parallel.
- **Step 2 (Wave 2 Parallel Unit Loop)**: Each `story-leader` spawns its `K` Unit Implementers in parallel. Each Unit Implementer implements its owned file + unit tests + doc-tests, verifies build/lint/format, opens its Unit PR, posts its Implementation Report comment, and loops with its dedicated Unit Review Council subagent until `APPROVED`.
- **Step 3 (Wave 3 Ordered Cascading Unit Merges & Story Review Loop)**: Merge Unit PRs `1 -> 2 -> ... -> K` one by one per story (rebasing/updating each next Unit PR onto the updated story branch). Then open each Story PR (`US-3.1.0`..`US-3.3.0`) into `feat/module-3-manage-inquiries-splits`, post the Story Implementation Report, run the independent Story Review Council subagent, and spawn `patch-implementer` if any issue is flagged until all `3` Story PRs are `APPROVED` and merged sequentially into `feat/module-3-manage-inquiries-splits`.
- **Step 4 (Wave 4 Module PR, Whole-Module Audit & Strict `main` Merge Order)**:
  - Open the Module `3` PR (`feat/module-3-manage-inquiries-splits` -> `main`), post the Module Implementation Report, and run the independent Module `3` Review Council subagent (+ `patch-implementer` loop if needed) until `GATE G-REVIEW APPROVED` with 0 issues.
  - **STRICT MERGE ORDER CONSTRAINT TO `main` (`Module 1 -> Module 7 -> Module 2 -> Module 3 -> Module 4 -> Module 5 -> Module 6 -> Module 8`)**: Module `3` MUST be merged into `main` in position **`4th (Merges to `main` after Modules 1, 7, and 2; before Modules 4, 5, 6, and 8)`**—strictly AFTER `Module 1 (`feat/module-1-core-microkernel`), Module 7 (`feat/module-7-webhooks-engine`), Module 2 (`feat/module-2-intentions-checkout`)` have merged into `main` and BEFORE `Module 4, Module 6, Module 8`. Before merging the approved Module `3` PR into `main`, sync/rebase `feat/module-3-manage-inquiries-splits` onto the latest `main` branch so shared manifests (`Cargo.toml`) and top-level exports (`src/lib.rs`, `src/prelude.rs`) preserve all previously merged modules alongside Module `3`, re-run the full verification suite (`cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-features`, `cargo test --doc`), and then merge into `main`.
```
