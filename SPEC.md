# SPEC

## §G GOAL
Heimdall runs untrusted commands cross-platform with policy-driven filesystem/network/env/proc/agent isolation plus local OpenAI privacy-filter setup/redaction.

## §C CONSTRAINTS
- Rust 2024 Cargo workspace; release version from `workspace.package.version`.
- Public binary/package name: `heimdall-sandbox`; MIT; repo `https://github.com/casualjim/heimdall-sandbox`.
- Linux isolation uses `bwrap` + namespaces; macOS isolation uses `/usr/bin/sandbox-exec` + Seatbelt SBPL.
- Runtime selector default `platform`: Linux → `bwrap`; macOS → Seatbelt.
- MicroVM runtime uses microsandbox Rust SDK; `msb` + runtime bundle ! preinstalled.
- MicroVM hosts: Linux KVM + `aarch64-apple-darwin`; unsupported hosts fail closed.
- MicroVM exec ephemeral attached only; detached/reuse/snapshots/volumes/resource knobs ⊥ phase one.
- MicroVM parity strict; unsupported Heimdall policy semantic → error, no fallback.
- Release targets: `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `aarch64-apple-darwin`.
- Linux arm64 privacy-filter WebGPU ⊥; CPU provider only unless upstream ONNX Runtime/Dawn artifact exists.
- Direct exec argv only; Heimdall ⊥ shell-parse command strings.
- JSON policy fields closed; unknown top-level/nested fields reject.
- `enabled=false` policy unsupported; fail closed.
- Process hardening ! run before sandbox exec; dangerous loader/allocator env vars stripped.
- Privacy-filter runtime loads cache only; explicit `setup` downloads model assets.
- Default privacy-filter model: `openai/privacy-filter` revision `7ffa9a043d54d1be65afb281eddf0ffbe629385b`.
- WebGPU Dawn sidecar ! live beside installed binary where platform uses WebGPU.
- cargo-dist owns release archives/installers; custom jobs publish crates.io/npm/Homebrew.

## §I INTERFACES
- cmd: `heimdall-sandbox exec [--policy POLICY|-] [--runtime platform|microvm] [--cwd PATH] [--allow-env KEY...] [--deny-env KEY...] [--stdio inherit|piped] [--no-proc] -- ARGV...`
- cmd: `heimdall-sandbox policy schema` → JSON Schema stdout.
- cmd: `heimdall-sandbox policy validate POLICY|-` → exit 0 valid, exit 2 invalid.
- cmd: `heimdall-sandbox setup [--force] [--cache-dir PATH] [--variant q4|q4f16|quantized|fp16|full] [--revision REV]`.
- cmd: `heimdall-sandbox privacy-filter redact [TEXT_OR_FILE] [--cache-dir PATH] [--variant q4|q4f16|quantized|fp16|full] [--revision REV] [--execution-provider cpu|web-gpu]`.
- cmd: `heimdall-sandbox injection-guard setup [--force] [--cache-dir PATH] [--revision REV] [--execution-provider cpu|web-gpu]`.
- cmd: `heimdall-sandbox injection-guard scan [TEXT_OR_FILE] [--cache-dir PATH] [--revision REV] [--execution-provider cpu|web-gpu]` → stdout JSON `{flagged,max_margin,threshold,spans,redacted}`, exit 0 flagged or not.
- cmd: hidden `heimdall-sandbox __heimdall-inner-exec --cwd PATH [--stdio inherit|piped] -- ARGV...` Linux reentry.
- policy: JSON fields `cwd`, `command`, `runtime`, `enabled`, `network`, `proc`, `filesystem`, `env`, `stdio`, `sshAgent`, `gpgAgent`, `ageAgent`.
- policy: `runtime: "platform"|"microvm"`; omitted → `platform`; CLI `--runtime` overrides policy runtime.
- policy: `network: "host"|"none"`; `proc: "default"|"none"`; `stdio: "inherit"|"piped"`.
- policy: `env.allow`, `env.deny`; CLI allow/deny mutually exclusive, policy allow+deny accepted with deny override.
- policy: `filesystem.deny`, `filesystem.writable`, `filesystem.virtual` absolute path → content map.
- file: `.heimdall-deny` cwd-local deny fragment appended after JSON deny patterns.
- file: `.heimdall-write` cwd-local writable fragment appended after JSON writable patterns.
- env: `PATH` discovers `bwrap`; child env filtered by `--allow-env`/`--deny-env` or policy env.
- env: `PATH`/microsandbox install discovers `msb` + `libkrunfw`; Heimdall exec ⊥ auto-download runtime bundle.
- env: `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, `AGE_AUTH_SOCK`, `GOPASS_AGE_AGENT_SOCK` used only when matching policy agent flag true.
- env: `LD_*` stripped on Linux-like Unix; `DYLD_*`, `MallocStackLogging*`, `MallocLogFile*` stripped on macOS.
- env: Hugging Face cache/API env vars via `hf_hub::Cache::from_env()`/`ApiBuilder::from_env()` ?
- rust: `heimdall_core::{ExecRequest, Executor, RuntimeMode, EnvPolicy, StdioPolicy, NetworkMode, ProcMode, FilesystemPolicy, AgentPolicy}`.
- rust: `heimdall_privacy_filter::{PrivacyFilterConfig, PrivacyFilterRuntime, redact_text, redact_captured_text, setup_privacy_filter}`.
- rust: `heimdall_injection_guard::{InjectionGuardConfig, InjectionGuardRuntime, InjectionScan, setup_injection_guard}`.
- rust: `heimdall_model_runtime::{source::ModelSource, session::{OnnxSession, ExecutionProvider}, windows::plan_token_windows}`.
- cargo crates: `heimdall-process-hardening`, `heimdall-sandbox-policy`, `heimdall-linux-sandbox`, `heimdall-macos-sandbox`, `heimdall-microvm-sandbox`, `heimdall-core`, `heimdall-model-runtime`, `heimdall-injection-guard`, `heimdall-privacy-filter`, `heimdall-sandbox`.
- npm: `@casualjim/heimdall-sandbox` delegates to optional platform packages `linux-x64`, `linux-arm64`, `darwin-arm64`.
- ci: `.github/workflows/ci.yml` runs `mise format` + `mise run --force test` on Ubuntu/macOS.
- release: `dist-workspace.toml`, `.github/workflows/release*.yml`, `scripts/package-webgpu-dawn.sh`, publish scripts.

## §V INVARIANTS
V9: ∀ exec request → empty argv ∨ invalid cwd → exit `2`, child ⊥ spawn
V10: child normal exit code preserved; Unix signal `n` → exit `128+n`
V11: direct exec default env → allowlist ∅; `--deny-env` → blocklist; `--allow-env` ∧ `--deny-env` ⊥
V12: policy input ! JSON object; unknown top-level/nested fields reject; schema `additionalProperties=false`
V13: `exec --policy` ∧ direct exec flags/argv/stdio/no-proc/env args → error; `--runtime` exception allowed
V14: policy defaults: `network=host`, `proc=default`, `stdio=inherit`; `enabled=false` → error
V15: isolation needed ⇔ `network=none` ∨ filesystem policy non-empty ∨ agent socket opt-in
V16: unsupported OS isolation → fail closed; Linux isolation missing executable `bwrap` → fail before child
V17: Linux bwrap plan ! `--die-with-parent`, `--unshare-user`, `--unshare-pid`; `network=none` adds `--unshare-net`; `proc=none` skips `/proc`
V18: macOS plan ! `/usr/bin/sandbox-exec` + generated SBPL; `network=none` blocks loopback/host network by policy
V19: filesystem patterns follow gitignore order; `.heimdall-*` fragments append after JSON; parent dirs ⊥ discovered
V20: deny/writable conflicts resolved by ordered literal specificity; indeterminate restored path → error
V21: protected control paths `.git`, `.agents`, `.pi`, `.heimdall-*` ⊥ writable even broad cwd writable grant
V22: missing deny under writable parent gets guard mount/policy; cleanup failure after successful child → error
V23: `filesystem.virtual` targets ! absolute; Linux materializes read-only content; Seatbelt prevents writes without host mutation
V24: agent sockets opt-in only; missing/relative sockets ignored; discovered socket dirs readable; exact socket access bypasses deny collision
V25: dangerous env vars stripped before child; agent env values appended only when matching agent flag true
V26: `SIGHUP`/`SIGINT`/`SIGQUIT`/`SIGTERM` forwarded to child/process group/bwrap payload; Linux child dies when parent dies
V27: privacy setup downloads/validates required config/tokenizer/tokenizer_config/viterbi/ONNX/sidecars per variant
V28: privacy runtime load ⊥ download; missing cached asset → `NotReady` with "run `heimdall-sandbox setup`" guidance
V29: privacy runtime disabled config → error; config serde unknown fields reject; default revision length = 40 hex chars
V30: ONNX session inputs exactly `attention_mask`,`input_ids`; output `logits` or single tensor; class count ! 33; label 0 ! `O`
V31: token window plan covers long input with overlap + forward progress; byte offsets stay UTF-8 boundaries
V32: redaction merges overlapping/touching spans, skips invalid/non-boundary spans, preserves `raw_for_user` locally
V33: release archives/npm platform packages include `libwebgpu_dawn` sidecar where WebGPU exists; Linux arm64 skips sidecar
V34: CI main/PR ! run `mise format` then `mise run --force test` on Linux and macOS
V35: runtime precedence: CLI `--runtime` > policy `runtime` > `platform`
V36: `platform` runtime maps Linux → `bwrap`, macOS → Seatbelt; `microvm` maps microsandbox SDK
V37: `microvm` host requires Linux KVM ∨ `aarch64-apple-darwin`; missing host/deps → fail before child
V38: `microvm` exec creates ephemeral attached sandbox, runs argv, preserves exit, calls `stop_and_wait()`
V39: `microvm` ! preserve V15,V19,V20,V21,V22,V23,V24,V25 semantics; unsupported mapping → error; fallback ⊥
V40: Heimdall exec ⊥ download/install microsandbox runtime; setup external to exec path
V41: injection guard runtime load ⊥ download; missing cached asset → `NotReady`; ONNX inputs exactly `attention_mask`,`input_ids`; output `margin` ! present
V42: injection scan flattens whitespace, scores ≤510-token windows (+BOS/EOS, one window per ORT call), flags window iff `margin ≥ thresholds.json margin_threshold`; flagged spans map back to original UTF-8 boundaries, merged
V43: `heimdall-model-runtime` owns HF download/cache lookup, ORT init/session, token windowing; model crates ⊥ depend on `ort`/`hf-hub` directly

## §T TASKS
id|status|task|cites
T10|x|sync README with actual CLI/env defaults, policy fields, privacy-filter cmds, crate count|I.cmd,I.policy,V11,V12,V27
T11|x|sync registry docs + `scripts/validate-cargo-packages.sh` with `heimdall-privacy-filter` crate|I.cargo,V33
T12|x|add CLI/integration coverage for `sshAgent`/`gpgAgent`/`ageAgent` success paths on Linux/macOS|I.policy,V15,V24
T13|x|document Hugging Face env/cache/auth behavior from `hf_hub::*::from_env()` or force explicit `--cache-dir`?|I.env,V27,V28
T14|x|decide/document policy `env.allow` + `env.deny` semantics; code uses deny override while CLI forbids mix|I.policy,V11
T15|x|confirm Seatbelt `filesystem.virtual` contract vs README replace-file claim|I.policy,V23
T16|x|review backend-unavailable early-return integration tests; decide explicit skip policy or infra requirement|V16,V18,V34
T17|x|document signal forwarding and process-hardening guarantees for operators|V25,V26,I.cmd
T18|.|add runtime enum/schema + CLI `--runtime`; thread policy/CLI precedence|I.cmd,I.policy,V12,V35
T19|.|thread runtime through `PolicyDocument` → `ExecRequest` → executor dispatch|I.rust,V35,V36
T20|.|add `heimdall-microvm-sandbox` backend using microsandbox Rust SDK|I.cargo,V36,V38
T21|.|add microVM host/dependency preflight for Linux KVM + Apple Silicon macOS|V37,V40
T22|.|map FS/network/proc/agent policy to microVM strict parity or fail closed|V15,V19,V20,V21,V22,V23,V24,V39
T23|.|add microVM tests for schema, CLI precedence, dispatch, preflight, no fallback|V12,V34,V35,V37,V39
T24|.|sync README/SPEC docs for runtime field, CLI flag, microsandbox deps, host matrix|I.cmd,I.policy,V36,V37,V40
T25|x|extract `heimdall-model-runtime`; add `heimdall-injection-guard` (Galvanize-3, ort only) + `injection-guard setup|scan` CLI|I.cmd,I.rust,I.cargo,V41,V42,V43

## §B BUGS
id|date|cause|fix
