# AGENTS.md - Crumbs Modular Monolith

## Crate Roles & Boundaries

| Crate | Role | Dependencies Allowed |
|---|---|---|
| `crumbs` | **Core Library**: Business logic, orchestration, shared types. | Internal crates only (`crumbs-storage`, `crumbs-indexer`, etc.). |
| `crumbs-storage` | **Shared Kernel**: Traits, entities, errors. **NO I/O, NO SQL.** | `thiserror`, `serde`, `uuid`, `async-trait`, `futures-core`. |
| `crumbs-storage-ladybug` | **Infrastructure**: Implements `crumbs-storage` traits over LadybugDB. | `crumbs-storage`, `lbug`, async/concurrency glue needed for that adapter. |
| `crumbs-llama` | **Model Runtime Adapter**: Local llama.cpp hosting, batching, tokenizer/model glue, and model-facing contracts for embeddings, reranking, and generation. **NO search/index/domain policy.** | `llama-cpp`, tokenizer/model-loading deps, async/runtime deps required for local inference hosting. |
| `crumbs-history` | **Module**: Git history traversal, filtering, and cochange accumulation. | `crumbs-storage`, `gix`, `regex`, supporting async/runtime deps. |
| `crumbs-indexer` | **Module**: Indexing logic. | `crumbs-storage`, `niblits`, `seasoning`, `crumbs-symbol-graph`, `crumbs-llama`. |
| `crumbs-search` | **Module**: Search logic and query-side embedding/reranking orchestration. **Builds on `crumbs-indexer` for shared indexing/search pipeline helpers such as FTS tokenization.** | `crumbs-storage`, `crumbs-indexer`, `niblits`, `seasoning`, `crumbs-llama`. |
| `crumbs-symbol-graph` | **Module**: Pure symbol graph build/resolve logic. | `crumbs-storage`, pure helper deps only. |
| `crumbs-workspace` | **Module**: Workspace detection/parsing. | `crumbs-storage` (if needed). |
| `crumbs-workspace-hack` | **Build-only**: `cargo-hakari` workspace feature unification crate. | Special exception: may appear as a direct dependency only because `cargo-hakari` manages it; do not add code-level imports or business logic here. |
| `crumbs-cli` | **Face**: CLI interface, including CLI-owned config loading/parsing and clap/confique integration. | `crumbs` |

### Topology Architecture (Current)

- There is **no** `crumbs-topology` crate anymore.
- `crumbs-storage` owns topology model types and the `TopologyRepository` trait.
- `crumbs-storage-ladybug` implements topology queries over Ladybug.
- `crumbs/src/topology/` owns topology facade orchestration, diffing, and refactor planning. Snapshot file I/O stays in `crumbs-cli`; `crumbs` only loads the live snapshot needed for diffing.

### Dependency Rules (STRICT)
1. **Core is Central**: All interface crates depend **only** on `crumbs`.
2. **Modules NEVER depend on Storage Infrastructure**: `crumbs-indexer` / `crumbs-search` / `crumbs-history` / `crumbs-symbol-graph` / `crumbs-workspace` must **NOT** depend on `crumbs-storage-ladybug`. They depend on `crumbs-storage` (traits) and get impls injected. `crumbs-indexer` and `crumbs-search` may also depend on `crumbs-llama`. `crumbs-search` may also depend on `crumbs-indexer` because search builds on indexer-owned indexing/search pipeline helpers.
3. **Shared Kernel is Pure**: `crumbs-storage` must **NEVER** import `sqlc`, `deadpool`, `tokio`, or `axum`. Shared-kernel traits may use `async-trait`, and shared-kernel stream signatures may use `futures-core::Stream`.
4. **No Undocumented Horizontal Module Imports**: horizontal module imports are forbidden unless explicitly documented in this file. Current explicit exception: `crumbs-search -> crumbs-indexer` is allowed because search builds on indexer-owned indexing/search pipeline helpers such as FTS tokenization. Other module-to-module imports should still flow through shared crates or `crumbs`.
5. **`crumbs-llama` stays model-facing, not business-facing**: `crumbs-llama` may own llama.cpp hosting, batching, tokenizer/model preparation, and model request/response contracts. It must **NOT** absorb indexing policy, search policy, ranking heuristics, query expansion policy, workspace logic, or other domain/business orchestration from `crumbs`, `crumbs-indexer`, or `crumbs-search`.
6. **`crumbs-workspace-hack` is a build-only exception**: direct dependencies on `crumbs-workspace-hack` are allowed only when managed by `cargo-hakari` for feature unification. No crate may use it as a source of runtime logic, shared domain APIs, or architectural coupling.

## Non-negotiable Rules

### No Optionality / No Fallbacks
- **Never introduce optionality to "make it pass/work".** Do not add silent defaults, degrade required behavior to `Option`, return early with `Ok(())`, swallow errors, or otherwise mask missing configuration/state.
- **Never weaken tests to go green.** Do not "skip" by returning success early, loosen assertions, add broad retries/timeouts, or ignore errors unless explicitly instructed.
- **Never add gating/ignores without explicit instruction.** No `#[ignore]`, feature flags, env-var gates, or conditional compilation to hide failing tests or behavior changes unless the user explicitly asks for it.

### Boundary Streaming (Non-negotiable)
- **No explicit sequence numbers.** We use ordered IDs (UUIDv7) for ordering:
  - Stream/event contracts must **not** introduce a separate `seq` field; order/resume must be expressed via the relevant ordered ID.
- **External data must stream until the first real sink/owner boundary.** Any code reading from a database (FalkorDB / Redis / Postgres / etc.) must stay streaming until it reaches an intentional sink.
  - Valid sinks include: a database/file/response write sink, or an owning in-memory model whose job is to materialize the data for further local analysis.
  - Example: `TopologyRepository::get_current_snapshot()` materializing `TopologySnapshotData` for topology export/diff is a valid sink.
  - **Explicit exception**: loading existing file hashes for indexing may materialize into an in-memory map because that set is treated as bounded for this repository.
  - **Explicit topology exception**: the accepted `topology-storage-queries` design intentionally materializes `TopologyRepository::get_current_snapshot()` plus bounded/algorithmic topology results such as `strongly_connected_components()`, `cycle_components()`, `feature_volumes()`, and `dependency_paths()`. Do **not** flag those as streaming violations by default. `pagerank_scores()` and `star_neighbors()` are still expected to stream.
- **No `Vec<T>` for unbounded external results before the sink.** Do not add storage/facade/transport APIs that return `Vec<T>` for unbounded or user-controlled external result sets (e.g., messages, turns, history, search results) before handoff to a real sink/owner boundary.
- **Paging must still stream.** Paging must return a `Stream` of items with a cursor/limit, not allocate a full page into a `Vec` by default.
- **End-to-end streaming to the sink.** Routes and facades must preserve streaming end-to-end until the data reaches the intended sink/owner boundary; do not buffer external streams into memory early unless the result is provably small and bounded.
- **After the sink, do not fake streaming.** Once data has intentionally entered an owning in-memory sink/model, graph-local or model-local bulk APIs are allowed. Review those paths for redundant clones, copies, and re-collects instead of forcing fake streaming ceremony.

### Mise Environment
> **CRITICAL: Do not ever try to fix `mise` environment related issues. Escalate to the user immediately.**

### Linting & Code Quality
- **Fix, Don't Suppress**: You **MUST** address all lint errors and warnings by fixing the code.
- **No `allow` Attributes**: **NEVER** use `#![allow(...)]` or `#[allow(...)]` to suppress warnings.
- **Strict Mode**: The project is compiled with `-D warnings`. If it doesn't compile cleanly, it's broken.

## Data Flow & Validation Strategy

> **CRITICAL: Validate ONCE. Do not repeat validation logic across layers.**

### 1. Interfaces (Transport Layer)
- **Responsibility**: Parse raw input (CLI args, JS objects, Python dicts).
- **Validation**: **Syntactic only**. (e.g., "Is this valid JSON?", "Is this field missing?").
- **Normalization**: Convert native types to `crumbs` types.
- **❌ SIN**: Do not check business rules (e.g., "does this user exist?") in the Interface.

### 2. Core (`crumbs`) (Domain Layer)
- **Responsibility**: Enforce business invariants and normalize data.
- **Validation**: **Semantic validation**. (e.g., "Is this email unique?", "Is the date in the future?").
- **Normalization**: **ALL**. Convert raw strings to Value Objects, trim whitespace, lowercase emails, etc.
- **❌ SIN**: Do not return `Option` or silent failures. Return `Result<T, DomainError>`.

### 3. Internal Storage/Infra
- **Responsibility**: Persistence.
- **Validation**: **NONE**. Trust the Core.
- **Normalization**: **NONE**. Store exactly what the Core gives.

### Example
```rust
// ❌ BAD: Validation repeated in Interface and Core
// Interface
if req.email.is_empty() { return Err("Email required"); }
if !req.email.contains('@') { return Err("Invalid email"); }
crumbs::create(req.email).await?;

// Core
if email.is_empty() { return Err(DomainError::InvalidEmail); } // Redundant!

// ✅ GOOD: Validation only in Core
// Interface
crumbs::create(req.email).await?; // Just pass it

// Core
pub async fn create(raw_email: String) -> Result<User, DomainError> {
    let email = Email::new(raw_email)?; // Validates & Normalizes (e.g. lowercase)
    // ...
}
```

## Configuration

- **Owner**: Configuration file/env loading, parsing, merge precedence, and `clap`/`confique` integration are a **`crumbs-cli` concern**.
- **Scope**: `crumbs-cli` is the **only** crate that owns this config system. Do **not** reimplement file/env config loading in `crumbs` or any future non-CLI face.
- **Core boundary**: `crumbs` consumes typed settings/builders/requests. It does **not** own config file I/O, `confique`, or `clap` integration.
- **CLI expansion rule**: Additional CLI entrypoints should become subcommands of `crumbs-cli`, not separate binaries with their own config loaders.

## Coding Standards

- **Builders**: Use `typed-builder` for request and configuration types in `crumbs` to ensure safe construction and clear APIs.
- **Error Handling**:
  - Each crate that defines a local error boundary must expose exactly one `Error` type and one `Result<T>` alias at the crate root (`lib.rs` or the binary root).
  - Do **not** define module-local `Result` aliases or duplicate error enums in child modules.
  - Child modules must import the crate-root `Error` and `Result`.
  - Storage implementations in `crumbs-storage-ladybug` use the `crumbs-storage` error/result boundary directly; they do not introduce a separate storage-domain error type.
  - `crumbs` defines its own error types using `thiserror`.
  - Interface crates map these errors to their specific error formats.
  - Use `eyre::Result` for top-level orchestration in interfaces.
- **Simplicity**: Avoid over-engineering. Do not introduce complex architectural patterns (e.g., Hexagonal, Ports & Adapters) unless absolutely necessary. Focus on practical decoupling.
- **Naming Conventions**:
  - **Rust**: `snake_case` for variables/functions, `PascalCase` for types, `snake_case` for files.
  - **TypeScript**: `camelCase` for variables/functions, `PascalCase` for types, `camelCase` for files.
- **Testing**: Unit tests for logic belong in `crumbs`. Interface crates should focus on integration/binding tests.

## Development Workflow (Mise)

**ALWAYS** use `mise` tasks for development. Only run direct toolchain commands if no `mise` wrapper exists.

**NEVER** run "targeted" tests, the cost is not the test it's the compilation of the modules.
**NEVER** run `cargo test`, it is not a win, it has the opposite outcome.

| Task | Description |
|---|---|
| `mise format` | Quick checks for this codebase (format + lint). |
| `mise test` | All tests (Rust `nextest`). |
| `mise run --force test` | Force a fresh full test run (bypass cache). |

**IMPORTANT**: After changes, **ALWAYS** run:
1. `mise format`
2. If Rust code was modified: `mise run --force test`

## Agent Guidelines

- **Do not** move logic from `crumbs` to interface crates.
- **Do not** move CLI config loading/parsing out of `crumbs-cli`, and do not duplicate it in other faces.
- **Do not** add dependencies from `crumbs` to interface crates.
- **Do not** create intermediate crates unless explicitly requested.
- **Do** keep `crumbs` as the central hub for domain logic and shared types.
- **Do** ensure interface crates act as thin wrappers that normalize data and call `crumbs`.
- **When adding a feature**: Implement the logic and types in `crumbs` first, then update the relevant interface crate to expose it.

## Before Committing Checklist

- [ ] `mise format` passes
- [ ] `mise run --force test` passes
- [ ] **No `allow` attributes**: All lint warnings fixed, not suppressed
- [ ] No `.unwrap()` or `.expect()` in production paths
- [ ] No `.collect()` on potentially large external datasets before a real sink/owner boundary
- [ ] No `seq` fields in stream/event contracts (use UUIDv7)
- [ ] No `Vec<T>` for unbounded external results before a real sink/owner boundary
- [ ] **Validation**: No redundant checks in Interfaces or Storage
- [ ] **Normalization**: Happens in Core, not in Interface
- [ ] All public items have doc comments
- [ ] No debug `println!` or `dbg!` statements
- [ ] No hardcoded credentials
- [ ] **Dependency Check**: Interfaces depend ONLY on `crumbs`
- [ ] **Dependency Check**: Modules do NOT depend on storage infra crates
- [ ] **Dependency Check**: `crumbs-llama` contains NO search/index/domain business logic
- [ ] **Dependency Check**: `crumbs-storage` has NO I/O dependencies
