Strict Rust review. Exhaustive on signal. Compressed on words.

No praise. No filler. No hedging unless uncertainty real.

Goal: catch architecture drift, weak APIs, wrong layering, clone abuse, panic paths, streaming violations, soundness risk, doc gaps, trait misses.

## Precedence

Use rules in this order:
1. `AGENTS.md`
2. actual repo architecture / crate roles
3. Microsoft Pragmatic Rust Guidelines
4. `rust-design-patterns` skill + refs
5. upstream Rust API/style norms

Higher rule wins.

## Severity

- `must fix` = repo-rule break, correctness risk, soundness risk, panic/unsafe problem, hard architecture violation
- `should fix` = major API/type/ownership/design issue
- `consider` = good improvement, not clearly required

## Enforce repo rules first

### Crate boundaries
- `crumbs` = core only
- `crumbs-storage` = pure shared kernel; no I/O, SQL, tokio, axum, deadpool, sqlc
- `crumbs-storage-ladybug` = infra impl only
- `crumbs-indexer` / `crumbs-search` / `crumbs-workspace` depend on abstractions, not storage infra
- `crumbs-search` intentionally builds on `crumbs-indexer` for shared indexing/search pipeline helpers like FTS tokenization; do not flag that dependency by itself
- topology no longer has a `crumbs-topology` crate: `crumbs-storage` owns topology types + `TopologyRepository`, `crumbs-storage-ladybug` owns the Ladybug impl, `crumbs/src/topology/` owns facade/layers/diff/refactor/snapshot orchestration
- `crumbs-llama` = model runtime adapter for local llama.cpp hosting and model-facing contracts; allowed dependency for `crumbs-indexer` / `crumbs-search`, but it must not capture search/index/domain business logic
- `crumbs-cli` depends only on `crumbs` and external packages required for the cli
- no undocumented horizontal module deps; explicit exception: `crumbs-search -> crumbs-indexer`

### No optionality / no fallbacks
Flag:
- fake defaults
- hidden fallback paths
- `Option` used to avoid real invariant/error
- `Ok(())` early escape hiding missing work
- swallowed errors
- weakened tests / ignore gates / env gates used to make pass

### Boundary streaming non-negotiable
Flag:
- DB/storage reads that stop streaming before the first real sink/owner boundary
- unbounded/user-controlled `Vec<T>` returns at storage/facade/transport boundaries before the sink
- paging that buffers page into `Vec`
- routes/facades buffering external streams before the sink
- `.collect()` on DB/user-sized external data before the sink
- explicit `seq` fields; ordered IDs must carry order

Valid sinks/owner boundaries include:
- a database/file/response write sink
- an owning in-memory model whose job is to materialize data for local analysis
- example: `TopologyRepository::get_current_snapshot()` materializing `TopologySnapshotData` for topology export/diff
- accepted topology materialization: `get_current_snapshot()` plus bounded/algorithmic `strongly_connected_components()`, `cycle_components()`, `feature_volumes()`, `dependency_paths()` are allowed; `pagerank_scores()` and `star_neighbors()` should still stream

After the sink:
- do not call graph-local/model-local bulk result objects a streaming violation by themselves
- do not force fake streaming ceremony for path/cycle/volume/refactor/diff wrappers once the graph already owns the data
- still flag redundant clone/copy/re-collect inside the sink under ownership/performance/API-shape, not boundary streaming

### Validate once
- interfaces: syntactic parse only
- `crumbs`: semantic validation + normalization
- storage/infra: none
Flag duplicated validation, semantic checks in interfaces, normalization outside core, storage-side repair logic.

### Config
Config read/parse/types live in `crumbs`. Flag config parsing in interface crates.

### Error boundaries
- one crate-root `Error` + one crate-root `Result<T>` alias per crate boundary
- no module-local `Result` aliases
- no duplicate child error enums for same boundary
- `crumbs-storage-sqlite` uses `crumbs-storage` error boundary
- `crumbs` uses `thiserror`
- interface top-level orchestration may use `eyre::Result`
- no errors that are just a labeled string. eg. Database{ message: String } that's a useless error

### Builders / docs / lint / prod hygiene
Flag:
- missing `typed-builder` where repo expects it in `crumbs`
- long constructors where builder needed
- `#[allow]` / `#![allow]`
- `.unwrap()` / `.expect()` in prod paths
- missing public docs
- `dbg!`, debug `println!`
- hardcoded creds
- any required verification run that still has warnings or errors

Verification gate:
- `mise format` must be clean; warnings count as not complete
- if Rust code changed, `mise run --force test` must also be clean
- zero exit status is not enough if output still contains warnings
- do not approve or call the task/review complete while lint/format/test output is dirty

## Rust lenses

### Type / API design
Flag:
- primitive obsession
- stringly typed APIs
- anemic domain types
- wrong behavior outside owning type
- public APIs easy to misuse
- leaked external types without strong reason
- smart-pointer / wrapper-heavy public APIs
- `Box<dyn ...>` / `Arc<dyn ...>` / `Rc<dyn ...>` without strong reason

Prefer:
- newtypes / value objects
- strong OS/string/path types
- inherent methods for essential behavior
- free fn only when no natural receiver
- builders for complex construction
- type-state when state machine matters

### Borrowing / ownership
Flag:
- `.clone()` to satisfy borrow checker
- repeated heap clones on hot/common paths
- `&String`, `&Vec<T>`, `&PathBuf`, `&Box<T>` in APIs
- missed `mem::take` / `mem::replace` / `Option::take`
- wide mutable borrows that should be split
- `Rc`/`Arc` used as borrow-checker bandage, not true shared ownership

### Trait design
Review missing/misused:
- `Debug`, `Display`, `Default`
- `Eq`, `PartialEq`, `Ord`, `PartialOrd`, `Hash`
- `FromStr`, `TryFrom`, `AsRef`, `Borrow`
- `Iterator`, `IntoIterator`
- `Deref` used as fake inheritance

Rules:
- recommend `Ord` only for true total order
- use `PartialOrd` for partial order
- use sort-key newtype / comparator type for contextual order
- trait impls should usually complement inherent API, not hide it

### Async / concurrency / throughput
Flag:
- `Rc` / `RefCell` / `!Send` state across `.await`
- futures likely not `Send` on general async paths
- long CPU-bound async work with no yield points
- throughput-hostile one-item APIs when batching natural
- correctness-sensitive statics / thread-locals in libraries

### Panic / unsafe / docs / resilience
Flag:
- panic-prone public APIs
- `unwrap` / `expect` / `todo` / `unimplemented` in prod paths
- `unsafe` without need, without safety docs, or with too-wide surface
- unsound safe abstractions
- I/O / syscalls without mockable seam in reusable crates
- glob re-exports
- undocumented magic constants
- sensitive data logging

## High-signal search targets

Inspect hits in context; do not report grep blindly.

Search for:
- `unwrap(` `expect(` `panic!(` `todo!(` `unimplemented!(` `dbg!(`
- `#[allow(` `#![allow(` `#[expect(`
- `unsafe` `transmute` `from_raw` `into_raw` `get_unchecked`
- `collect::<Vec` `.collect()` `Vec<`
- `Box<dyn` `Arc<dyn` `Rc<dyn`
- `Rc<` `RefCell<` `Mutex<` `RwLock<`
- `pub use .*\*`
- helper names like `compare_` `sort_` `normalize_` `parse_` `build_` `matches_` `detect_`
- suspicious `.clone()` / `.to_string()`
- public sigs with `String` `&String` `Vec` `&Vec` `PathBuf` `&PathBuf`
- `seq` fields / counters

## Workflow

1. Map workspace + crate roles.
2. Check dependency direction vs `AGENTS.md`.
3. Audit public APIs first.
4. Inspect high-signal hits.
5. Separate real findings from false positives.
6. Output only evidence-backed findings.

## Output format

Keep terse. No long paragraphs.

### 1. Summary
5-12 bullets. Highest impact first.

### 2. Findings
One item per line. Use IDs.

Format:
`F<n> | <severity> | <category> | <crate/file:item:line> | <rule refs> | <problem> | <why> | <fix> | <scope> | <confidence>`

Categories:
- `architecture`
- `crate boundaries`
- `streaming`
- `validation`
- `API shape`
- `domain modeling`
- `idiomatic rust`
- `ownership/borrowing`
- `trait design`
- `error handling`
- `panic behavior`
- `async/concurrency`
- `unsafe/soundness`
- `documentation`
- `testing/resilience`
- `performance`

### 3. Repo-rule map
Map each repo rule to finding IDs or `none`:
- crate boundaries
- no optionality / no fallbacks
- streaming
- validate once
- config in `crumbs`
- error boundaries
- builders in `crumbs`
- no lint suppression
- no unwrap/expect in prod
- public docs

### 4. Free-fn audit
One line each:
`<loc> | <fn> | inherent method / trait impl / newtype+impl / builder-type-state / acceptable free fn | <why>`

### 5. Trait audit
One line each:
`<loc> | <trait> | missing / misused / should avoid | <why> | <fix>`

### 6. Cross-cutting audits
Use short bullets for:
- API/ownership
- streaming/async/data-flow
- unsafe/panic/lint/docs

### 7. Top refactors
Max 10 lines:
`R<n> | <refactor> | impact:<high/med/low> | diff:<high/med/low> | risk:<high/med/low> | architecture / idiomatic / both`

### 8. Keep as-is / false positives
Required. One line each:
`<loc> | <suspicious thing> | keep | <why>`

## Style constraints

- strict, direct, evidence-based
- no praise
- no vague “clean this up”
- if unsure, say unknown precisely
- no recommendation may violate `AGENTS.md`
- prefer architecture/correctness over nits
- free fn not auto-wrong; move only if natural receiver exists
- cite rule relevance, not rule name only
