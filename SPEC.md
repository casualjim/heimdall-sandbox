# SPEC

## §G GOAL
Heimdall runs untrusted commands cross-platform with policy-driven filesystem/network/env/proc/agent isolation plus local OpenAI privacy-filter setup/redaction.

## §C CONSTRAINTS
- Rust 2024 Cargo workspace; release version from `workspace.package.version`.
- Public binary/package name: `heimdall-sandbox`; MIT; repo `https://github.com/casualjim/heimdall-sandbox`.
- Linux isolation uses `bwrap` + namespaces; macOS isolation uses `/usr/bin/sandbox-exec` + Seatbelt SBPL.
- Runtime selector default `platform`: Linux → `bwrap`; macOS → Seatbelt.
- MicroVM runtime uses boxlite crate (embedded, `include_bytes!`); build-time curl fetch `boxlite-runtime-v{ver}-{target}.tar.gz` from `github.com/boxlite-ai/boxlite/releases` (R1); offline build ⊥; no host preinstall; `libkrunfw` dlopen'd at runtime via `LD_LIBRARY_PATH=<box>/bin`.
- MicroVM hosts: Linux KVM + `aarch64-apple-darwin`; unsupported hosts fail closed; macOS HVF boot test ⊥ unignored on GitHub-hosted CI (R2).
- MicroVM exec ephemeral attached only; detached/reuse/snapshots/volumes/resource knobs ⊥ phase one; ephemeral box auto-cleans on heimdall exit via Keepalive watchdog (R8, no daemon); warm sessions deferred (cross-process reuse needs long-lived keepalive-holder/daemon or detach+reaper; R7).
- MicroVM policy surface shrinks to boxlite native knobs; dropped fields (`snapshot`, `pullPolicy`, rlimits beyond boxlite 5, guest `hostname`/`shell`/`init`, `SecretHostPattern::Any`) reject; no fallback.
- MicroVM stdout/stderr = boxlite `Stream<Item=String>`, lossy `U+FFFD` on non-UTF-8 (R3); binary stdout regression acknowledged.
- MicroVM exec ! tokio multi_thread runtime (boxlite `tokio::spawn` watcher/guest_connect/drain).
- MicroVM secrets = boxlite `Secret{name,hosts,placeholder,value}`; placeholder→value substitution host-gated exact+wildcard (R5); `SecretHostPattern::Any` ⊥.
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
- cmd: hidden `heimdall-sandbox __heimdall-inner-exec --cwd PATH [--stdio inherit|piped] -- ARGV...` Linux reentry.
- policy: JSON fields `cwd`, `command`, `runtime`, `image`, `enabled`, `network`, `proc`, `filesystem`, `env`, `stdio`, `sshAgent`, `gpgAgent`, `ageAgent`.
- policy: `runtime: "platform"|"microvm"`; omitted → `platform`; CLI `--runtime` overrides policy runtime.
- policy: `image` non-empty string required when effective runtime `microvm`; `platform` + `image` → error.
- policy: `secrets` = `[{name, placeholder, value, hosts[exact|wildcard]}]` (boxlite `Secret`; placeholder→value MITM substitution host-gated; `SecretHostPattern::Any` ⊥).
- policy: `image.snapshot`, `image.pullPolicy`, rlimits beyond `max_open_files`/`max_file_size`/`max_processes`/`max_memory`/`max_cpu_time`, `guest.hostname`/`shell`/`init` ⊥ (reject).
- policy: `network: "host"|"none"`; `proc: "default"|"none"`; `stdio: "inherit"|"piped"`.
- policy: `env.allow`, `env.deny`; CLI allow/deny mutually exclusive, policy allow+deny accepted with deny override.
- policy: `filesystem.deny`, `filesystem.writable`, `filesystem.virtual` absolute path → content map.
- file: `.heimdall-deny` cwd-local deny fragment appended after JSON deny patterns.
- file: `.heimdall-write` cwd-local writable fragment appended after JSON writable patterns.
- env: `PATH` discovers `bwrap`; child env filtered by `--allow-env`/`--deny-env` or policy env.
- env: `SSH_AUTH_SOCK`, `GPG_AGENT_INFO`, `AGE_AUTH_SOCK`, `GOPASS_AGE_AGENT_SOCK` used only when matching policy agent flag true.
- env: `LD_*` stripped on Linux-like Unix; `DYLD_*`, `MallocStackLogging*`, `MallocLogFile*` stripped on macOS.
- env: Hugging Face cache/API env vars via `hf_hub::Cache::from_env()`/`ApiBuilder::from_env()` ?
- rust: `heimdall_core::{ExecRequest, Executor, RuntimeMode, EnvPolicy, StdioPolicy, NetworkMode, ProcMode, FilesystemPolicy, AgentPolicy}`.
- rust: `heimdall_privacy_filter::{PrivacyFilterConfig, PrivacyFilterRuntime, redact_text, redact_captured_text, setup_privacy_filter}`.
- cargo crates: `heimdall-process-hardening`, `heimdall-sandbox-policy`, `heimdall-linux-sandbox`, `heimdall-macos-sandbox`, `heimdall-microvm-sandbox`, `heimdall-core`, `heimdall-privacy-filter`, `heimdall-sandbox`.
- npm: `@casualjim/heimdall-sandbox` delegates to optional platform packages `linux-x64`, `linux-arm64`, `darwin-arm64`.
- ci: `.github/workflows/ci.yml` runs `mise format` + `mise run --force test` on Ubuntu/macOS.
- release: `dist-workspace.toml`, `.github/workflows/release*.yml`, `scripts/package-webgpu-dawn.sh`, publish scripts.

## §R RESEARCH
id|topic|finding|src
R1|boxlite v0.9.7 runtime assets|tarballs published darwin-arm64/linux-x64-gnu/linux-arm64-gnu + .sha256; build.rs `download()` URL matches → crates.io build-time fetch works for 3 heimdall targets|api.github.com/repos/boxlite-ai/boxlite/releases/tags/v0.9.7
R2|GH Actions macOS arm64 HVF|nested-virt ⊥ macos-14/15/26 arm64 GitHub-hosted; #13505 closed 2026-01-08 not-planned; `kern.hv_support` empty → unignored HVF boot test ⊥ on GitHub-hosted macOS|github.com/actions/runner-images/issues/13505
R3|boxlite stdout stream|`Execution::stdout()/stderr()` → `Stream<Item=String>`; `Utf8StreamDecoder` chunk-granular + lossy `U+FFFD` on non-UTF-8 → binary stdout corrupted, ⊥ preserved, ⊥ error|src/boxlite/src/portal/interfaces/exec.rs:536-572, src/guest/src/service/exec/exec_handle.rs
R4|boxlite `stop()` blocking|`stop()` (box_impl.rs:599-746) awaits guest shutdown (≤10s timeout) then synchronous `remove_box(id,false)` (disk/db/lock) before return; idempotent; `auto_remove=true` ⇒ full teardown blocks until done; ⊥ early-return; ephemeral exec-once safe|src/boxlite/src/litebox/box_impl.rs:599-746
R5|boxlite secret host-gating|secret substitution host-gated @ connection level: `forked_tcp.go:188-198` MITM engages only when `secretMatcher.Matches(hostname)`; `secrets=SecretsForHost(hostname)` (matched only); `substituteHeaders` replaces placeholder→value for those (mitm.go:166, mitm_proxy.go:48); non-matched hosts ⊥ MITM → secret never sent → parity w/ microsandbox `allow_host`/`allow_host_pattern`|src/deps/libgvproxy-sys/gvproxy-bridge/forked_tcp.go:188-198, mitm.go:166-185
R6|boxlite pause/resume (embedded API)|embedded `LiteBox` API (mod.rs:80-192) ⊥ pause/resume/unpause/suspend method; `auto_pause` is a REST sweeper policy (rt_impl.rs:1615-1619 local returns Unsupported), ⊥ a local embedded call; internal `with_quiesce_async` SIGSTOP+FIFREEZE is snapshot/clone-only. cleanup is via keepalive watchdog (R8), ⊥ pause/resume|src/boxlite/src/litebox/mod.rs:80-192, runtime/rt_impl.rs:1615-1619, box_impl.rs:1152
R7|boxlite BoxInfo activity|`BoxInfo.last_updated` = last state-change ⊥ last-exec; `list_info`/`get`/`remove(force)` exist; reaper ⊥ use `last_updated` (reaps active warm box) → sessions need heimdall registry w/ last-activity|src/boxlite/src/runtime/types.rs:311-357
R8|boxlite embedded cleanup (keepalive)|embedded model cleanup = Keepalive watchdog pipe: non-detached (default) box → shim polls read-end; parent death/drop keepalive → POLLHUP → shim graceful shutdown (defense-in-depth if `stop()` ⊥ called); `detach=true` disables watchdog (box outlives parent). keepalive flows spawn→`SpawnedShim`→`ShimHandler`(shim.rs:39)→LiveState→BoxImpl→LiteBox; dropping LiteBox/process exit drops keepalive|src/boxlite/src/vmm/controller/watchdog.rs, spawn.rs:21-67,136, shim.rs:26-57

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
V36: `platform` runtime maps Linux → `bwrap`, macOS → Seatbelt; `microvm` maps boxlite crate (embedded)
V37: `microvm` host requires Linux KVM ∨ `aarch64-apple-darwin`; missing host/KVM → fail before child; macOS HVF boot test ⊥ unignored on GitHub-hosted CI (R2)
V38: `microvm` exec creates ephemeral attached box, runs argv, preserves exit, calls `LiteBox::stop()` (`auto_remove=true`); stop() blocks until disk/lock cleanup (R4)
V39: `microvm` policy surface = boxlite native knobs; dropped fields reject; preserve V15,V19,V20,V21,V22,V23,V24,V25 where mappable; fallback ⊥
V40: MicroVM runtime embedded via boxlite `include_bytes!`; build-time fetch from GitHub releases (R1); exec ⊥ host preinstall
V41: effective `microvm` runtime requires policy `image`; effective `platform` runtime rejects `image`
V42: `microvm` stdout/stderr forward live chunk-granular via boxlite `Stream<Item=String>`; lossy `U+FFFD` on non-UTF-8 (R3)
V43: `microvm` exec ! tokio multi_thread runtime (⊥ `current_thread`; boxlite `tokio::spawn`)
V44: `microvm` secrets = boxlite `Secret{name,hosts,placeholder,value}`; placeholder→value gated by hosts exact+wildcard (R5); `SecretHostPattern::Any` ⊥
V45: `microvm` CI live boot test unignored Linux KVM only; macOS HVF ⊥ on GitHub-hosted (R2)
V46: boxlite runtime binaries embedded (`include_bytes!`); extracted to `~/.local/share/boxlite/runtimes/v{VER}-{HASH}/`; `libkrunfw` dlopen via `LD_LIBRARY_PATH=<box>/bin`; no host preinstall
V47: warm sessions deferred — non-detached keepalive dies with each ephemeral heimdall exec process (R8) → cross-process reuse needs long-lived keepalive-holder (daemon) or detach+reaper; `BoxInfo.last_updated`=state-change ⊥ last-exec (R7)
V48: `microvm` ephemeral box auto-cleans on heimdall process exit via boxlite Keepalive watchdog (POLLHUP → shim graceful shutdown); defense-in-depth if `stop()` ⊥ called (R8); `detach=false` default

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
T18|x|add runtime enum/schema + CLI `--runtime`; thread policy/CLI precedence|I.cmd,I.policy,V12,V35,V41
T19|x|thread runtime through `PolicyDocument` → `ExecRequest` → executor dispatch|I.rust,V35,V36,V41
T20|x|add `heimdall-microvm-sandbox` backend using microsandbox Rust SDK|I.cargo,V36,V38,V41
T21|x|add microVM host/dependency preflight for Linux KVM + Apple Silicon macOS|V37,V40
T22|x|map FS/network/proc/agent policy to microVM strict parity or fail closed|V15,V19,V20,V21,V22,V23,V24,V39,V41
T23|x|add microVM tests for schema, CLI precedence, dispatch, preflight, no fallback|V12,V34,V35,V37,V39,V41
T24|x|sync README/SPEC docs for runtime field, CLI flag, microsandbox deps, host matrix|I.cmd,I.policy,V36,V37,V40
T25|x|swap microsandbox→boxlite in `heimdall-microvm-sandbox` Cargo.toml; rewrite `request.rs` to drive `BoxliteRuntime`/`LiteBox`/`BoxCommand`|V36,V40,V46
T26|x|switch microvm exec tokio runtime `current_thread`→`multi_thread`|V43
T27|x|shrink `MicrovmPolicy` to boxlite native knobs; drop `snapshot`/`pullPolicy`/11-rlimits/`hostname`/`shell`/`init`/`SecretHostPattern::Any`; reject dropped fields|V39,V41
T28|x|map secrets → boxlite `Secret{name,hosts,placeholder,value}`; policy schema + `request.rs`|V44
T29|.|live chunk stdout/stderr forwarding from boxlite `Stream<Item=String>` (concurrent drain); document lossy `U+FFFD` binary regression|V42
T30|.|CI: unignored boxlite boot test Linux KVM; macOS HVF self-hosted/manual or dropped; remove `msb`/`libkrunfw` preflight|V37,V45
T31|.|remove `microsandbox` crate + `preflight.rs` `msb`/`libkrunfw` resolution; V40 invert|V40,V46
T32|.|deferred: warm sessions (detach+reattach-by-id) — needs heimdall session registry + reaper (lazy reap-on-exec or systemd-timer/launchd)|R6,R7

## §B BUGS
id|date|cause|fix
