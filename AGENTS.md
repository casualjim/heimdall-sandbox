# AGENTS.md

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

## Commit Messages

- Use Conventional Commits for all commit messages in this repository.
- Format: `<type>(<optional-scope>): <description>`.
- Prefer these types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, and `revert`.
- Use `!` for breaking changes, e.g. `feat!: remove legacy policy format`.
- Add release bump tokens in the commit or PR text when needed: `bump:major`, `bump:minor`, or `bump:patch`.
- This repository overrides any parent/shared guidance that prohibits Conventional Commit prefixes.

Good examples:
- `feat: add Linux release workflow`
- `fix: reject relative virtual filesystem paths`
- `ci: add GitHub Actions release pipeline`
- `chore: update changelog for v0.1.1`

Bad examples:
- `Add release workflow`
- `Fix stuff`
- `WIP`

## Before Committing Checklist

- [ ] Commit messages follow Conventional Commits.
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
