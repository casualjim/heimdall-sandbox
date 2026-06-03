# Heimdall

A cross-platform process sandbox runtime written in Rust. Heimdall executes untrusted commands with configurable filesystem, network, and environment isolation — using [bubblewrap](https://github.com/containers/bubblewrap) and Linux namespaces on Linux, and [Seatbelt](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) on macOS.

## Features

- **Cross-platform isolation** — bubblewrap on Linux, Seatbelt on macOS
- **Filesystem isolation** — deny patterns, writable overlays, and virtual file injection using gitignore-style globs
- **Network isolation** — disable host networking inside the sandbox
- **Environment filtering** — allowlist by default, or blocklist with explicit deny rules
- **Process hardening** — disable ptrace attachment, zero core file limits, and strip dangerous loader/allocator environment variables
- **Signal forwarding** — forward `SIGHUP`, `SIGINT`, `SIGQUIT`, and `SIGTERM` to child processes; Linux bubblewrap payloads also die when Heimdall dies
- **`/proc` control** — mount or hide `/proc` inside the sandbox (Linux)
- **Agent socket opt-in** — expose SSH, GnuPG, and age agent sockets only when policy fields request them
- **Fragment files** — `.heimdall-deny` and `.heimdall-write` files in your project root for local policy overrides
- **Protected targets** — `.git`, `.agents`, `.pi`, and `.heimdall-*` paths are automatically write-protected
- **JSON policy documents** — declarative sandbox configuration with closed fields and schema validation
- **stdio control** — inherit or pipe child process I/O
- **Local privacy filter** — explicit setup plus cached ONNX redaction runtime for `openai/privacy-filter`

## Installation

Homebrew (macOS and Linux):

```sh
brew install casualjim/homebrew-taps/heimdall-sandbox
```

Shell installer:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/casualjim/heimdall-sandbox/releases/latest/download/heimdall-sandbox-installer.sh | sh
```

npm (macOS Apple Silicon, Linux x64, and Linux arm64):

```sh
npm install -g @casualjim/heimdall-sandbox
```

Linux arm64 remains a supported sandbox/package target, but Linux arm64 releases are built without WebGPU. The privacy-filter WebGPU execution provider currently depends on upstream ONNX Runtime/Dawn prebuilt artifacts that are not available for Linux arm64, so Linux arm64 uses the CPU execution provider unless a source-built or vendored Linux arm64 WebGPU runtime is added.

Cargo registry:

```sh
cargo install heimdall-sandbox
```

Cargo installs only the executable. On platforms where Heimdall links the ONNX Runtime WebGPU provider, the installed binary also needs the Dawn sidecar library (`libwebgpu_dawn.dylib` on macOS, `libwebgpu_dawn.so` on Linux) next to the executable or in another runtime linker search path. Prefer Homebrew, the shell installer, or npm for WebGPU-capable installs; those release packages are built with cargo-dist and include the sidecar library.

If a Cargo-installed binary fails with a missing `libwebgpu_dawn` error, copy the library from the build output next to the installed executable, for example on macOS:

```sh
cp target/release/libwebgpu_dawn.dylib ~/.cargo/bin/
```

## Quick start

Run a command inside the sandbox:

```sh
heimdall-sandbox exec -- printf "hello"
```

You should see `hello` printed to your terminal. The sandbox used your current directory and inherited stdio. Parent environment variables are not inherited unless you allowlist them or choose blocklist mode.

Now restrict the environment so only `PATH` reaches the child:

```sh
heimdall-sandbox exec --allow-env PATH -- env
```

Notice that most variables are gone. This is allowlist mode: only explicitly named keys pass through.

## How to ...

### Restrict environment variables

Allowlist mode (only pass listed vars):

```sh
heimdall-sandbox exec --allow-env PATH --allow-env HOME -- env
```

Blocklist mode (pass everything except listed vars):

```sh
heimdall-sandbox exec --deny-env SECRET_TOKEN -- env
```

`--allow-env` and `--deny-env` are mutually exclusive.

### Disable networking

Pass a JSON policy document via stdin:

```sh
heimdall-sandbox exec --policy - <<'EOF'
{
  "network": "none",
  "command": ["curl", "https://example.com"]
}
EOF
```

The child will fail because the network is unreachable inside the sandbox.

### Hide files and inject virtual ones

Filesystem policies use gitignore-style glob patterns. This example hides `.env` files, marks `src/` as writable, and injects a virtual `/etc/passwd` file. Linux materialises virtual files as read-only sandbox content. macOS Seatbelt cannot materialise replacement bytes; it enforces read/write policy around existing host paths and prevents writes to virtual targets without mutating the host:

```sh
heimdall-sandbox exec --policy - <<'EOF'
{
  "command": ["cat", "/etc/passwd"],
  "filesystem": {
    "deny": ["**/.env*", "!**/.env.example"],
    "writable": ["src/**"],
    "virtual": {
      "/etc/passwd": "nobody:x:65534:65534:Nobody:/nonexistent:/usr/sbin/nologin\n"
    }
  }
}
EOF
```

### Override policies locally with fragment files

Place a `.heimdall-deny` or `.heimdall-write` file in your working directory to extend the policy without changing the JSON document. Patterns in these files are appended after the JSON patterns, so negations can selectively re-allow denied paths:

```sh
# .heimdall-deny — deny all dotfiles except .env.example
.env*
!.env.example
```

Fragment files are discovered automatically — no CLI flag needed.

### Validate or inspect a policy document

Validate a policy file before running it:

```sh
heimdall-sandbox policy validate policy.json
```

Print the JSON schema to author policies with editor support:

```sh
heimdall-sandbox policy schema
```

### Set up and run the privacy filter

Download required model assets explicitly before redaction:

```sh
heimdall-sandbox setup --variant q4
```

Setup downloads `config.json`, `tokenizer.json`, `tokenizer_config.json`, `viterbi_calibration.json`, the selected ONNX model, and required ONNX sidecars for the chosen variant. Defaults use `openai/privacy-filter` revision `7ffa9a043d54d1be65afb281eddf0ffbe629385b` and the `q4` variant.

Redact text after setup:

```sh
heimdall-sandbox privacy-filter redact "alice@example.com"
```

You can pass text, a file path, or stdin. The runtime only loads cached files; it does not download missing assets. If cache entries are missing, run `heimdall-sandbox setup` first. Use `--cache-dir PATH` to force a cache root for setup and redaction, or rely on Hugging Face defaults from `hf_hub::Cache::from_env()` and `hf_hub::api::sync::ApiBuilder::from_env()`. Those defaults use `HF_HOME/hub` when `HF_HOME` is set, otherwise the user cache directory at `.cache/huggingface/hub`; `HF_ENDPOINT` overrides the download endpoint. Authentication comes from the Hugging Face token file beside the cache (`HF_HOME/token`, or the default Hugging Face token path), such as one written by `huggingface-cli login`.

`--execution-provider cpu` is the default. `--execution-provider web-gpu` requires a platform build with the Dawn sidecar library next to the installed binary. Linux arm64 packages use CPU only.

### Operator guarantees

Heimdall applies process hardening before sandbox execution. On Linux it disables dumpability with `prctl(PR_SET_DUMPABLE, 0)` and sets core dump limits to zero; on macOS it uses `ptrace(PT_DENY_ATTACH)` and sets core dump limits to zero. Linux-like Unix builds strip `LD_*`; macOS strips `DYLD_*`, `MallocStackLogging*`, and `MallocLogFile*`.

Signal handling forwards `SIGHUP`, `SIGINT`, `SIGQUIT`, and `SIGTERM` to the child. Direct execution targets the child process. macOS Seatbelt execution targets the child process group. Linux bubblewrap execution targets discovered payload descendants, and `--die-with-parent` plus Linux parent-death signalling terminates the payload when Heimdall exits.

### Test backend requirements

Integration tests that exercise real isolation require platform backends: `bwrap` on Linux and `/usr/bin/sandbox-exec` on macOS. Backend-specific tests return early when that backend is unavailable; CI must provide the backend to cover the corresponding invariants. Unit tests for policy and plan generation still run without those binaries.

## Policy document reference

| Field | Type | Description |
|---|---|---|
| `command` | `string[]` | **Required.** Command argv to execute. |
| `cwd` | `string` | Working directory (defaults to current directory). |
| `stdio` | `"inherit" \| "piped"` | Child I/O handling (default: `inherit`). |
| `network` | `"host" \| "none"` | Network mode (default: `host`). |
| `proc` | `"default" \| "none"` | `/proc` mount policy (default: `default`). |
| `env.allow` | `string[]` | Environment variable allowlist. |
| `env.deny` | `string[]` | Environment variable blocklist. With no `env.allow`, policy uses blocklist mode. With `env.allow`, deny entries override allowed values at runtime. CLI `--allow-env` and `--deny-env` remain mutually exclusive. |
| `filesystem.deny` | `string[]` | Gitignore-style patterns for paths to hide from the child. |
| `filesystem.writable` | `string[]` | Patterns for paths the child may write to. |
| `filesystem.virtual` | `object` | Absolute path → content map. Linux exposes read-only virtual content; macOS Seatbelt write-denies matching targets without host mutation. |
| `enabled` | `boolean` | Optional compatibility field. `true` is accepted; `false` is rejected fail-closed. |
| `sshAgent` | `boolean` | When `true`, expose existing absolute `SSH_AUTH_SOCK` to an isolated child. |
| `gpgAgent` | `boolean` | When `true`, expose existing absolute GnuPG sockets from `GPG_AGENT_INFO` and `gpgconf --list-dirs`. |
| `ageAgent` | `boolean` | When `true`, expose existing absolute `AGE_AUTH_SOCK` and `GOPASS_AGE_AGENT_SOCK`. |

## How it works

Heimdall is a Cargo workspace with seven crates:

| Crate | Role |
|---|---|
| `heimdall-sandbox` | CLI binary — argument parsing, policy loading, entry point. |
| `heimdall-core` | Core runtime — execution orchestration, environment filtering, signal handling. |
| `heimdall-sandbox-policy` | Shared policy types and filesystem policy materialization (used by both platform crates). |
| `heimdall-linux-sandbox` | Linux isolation — bubblewrap planning, namespace configuration. |
| `heimdall-macos-sandbox` | macOS isolation — Seatbelt policy generation, sandbox-exec invocation. |
| `heimdall-process-hardening` | Process hardening — ptrace protection, core dump disabling, dangerous environment stripping. |
| `heimdall-privacy-filter` | Privacy-filter setup, cached ONNX runtime loading, and redaction. |

## Requirements

- Linux (x86_64, aarch64) — filesystem and network isolation require bubblewrap and user namespaces
- macOS (Apple Silicon) — filesystem and network isolation use the built-in Seatbelt sandbox
- Rust 2024 edition (1.85+) for building from source

## License

[MIT](LICENSE)
