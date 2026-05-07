# Heimdall

A cross-platform process sandbox runtime written in Rust. Heimdall executes untrusted commands with configurable filesystem, network, and environment isolation — using [bubblewrap](https://github.com/containers/bubblewrap) and Linux namespaces on Linux, and [Seatbelt](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) on macOS.

## Features

- **Cross-platform isolation** — bubblewrap on Linux, Seatbelt on macOS
- **Filesystem isolation** — deny patterns, writable overlays, and virtual file injection using gitignore-style globs
- **Network isolation** — disable host networking inside the sandbox
- **Environment filtering** — allowlist or blocklist parent environment variables
- **Process hardening** — disable ptrace attachment, zero core file limits
- **`/proc` control** — mount or hide `/proc` inside the sandbox (Linux)
- **Fragment files** — `.heimdall-deny` and `.heimdall-write` files in your project root for local policy overrides
- **Protected targets** — `.git`, `.agents`, `.pi`, and `.heimdall-*` paths are automatically write-protected
- **JSON policy documents** — declarative sandbox configuration with schema validation
- **stdio control** — inherit or pipe child process I/O

## Installation

Homebrew (macOS and Linux):

```sh
brew install casualjim/homebrew-taps/heimdall-sandbox
```

Shell installer:

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/casualjim/heimdall-sandbox/releases/latest/download/heimdall-sandbox-installer.sh | sh
```

From source:

```sh
cargo install heimdall-sandbox
```

## Quick start

Run a command inside the sandbox:

```sh
heimdall-sandbox exec -- printf "hello"
```

You should see `hello` printed to your terminal. The sandbox inherited your current directory, environment, and stdio — nothing was isolated yet.

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

Filesystem policies use gitignore-style glob patterns. This example hides `.env` files, marks `src/` as writable, and replaces `/etc/passwd` with a virtual file:

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

## Policy document reference

| Field | Type | Description |
|---|---|---|
| `command` | `string[]` | **Required.** Command argv to execute. |
| `cwd` | `string` | Working directory (defaults to current directory). |
| `stdio` | `"inherit" \| "piped"` | Child I/O handling (default: `inherit`). |
| `network` | `"host" \| "none"` | Network mode (default: `host`). |
| `proc` | `"default" \| "none"` | `/proc` mount policy (default: `default`). |
| `env.allow` | `string[]` | Environment variable allowlist. |
| `env.deny` | `string[]` | Environment variable blocklist (mutually exclusive with `allow`). |
| `filesystem.deny` | `string[]` | Gitignore-style patterns for paths to hide from the child. |
| `filesystem.writable` | `string[]` | Patterns for paths the child may write to. |
| `filesystem.virtual` | `object` | Absolute path → content map injected as read-only files. |

## How it works

Heimdall is a Cargo workspace with four crates:

| Crate | Role |
|---|---|
| `heimdall-sandbox` | CLI binary — argument parsing, policy loading, entry point. |
| `heimdall-core` | Core runtime — execution orchestration, environment filtering, signal handling. |
| `heimdall-sandbox-policy` | Shared policy types and filesystem policy materialization (used by both platform crates). |
| `heimdall-linux-sandbox` | Linux isolation — bubblewrap planning, namespace configuration. |
| `heimdall-macos-sandbox` | macOS isolation — Seatbelt policy generation, sandbox-exec invocation. |
| `heimdall-process-hardening` | Process hardening — ptrace protection, core dump disabling. |

## Requirements

- Linux (x86_64, aarch64) — filesystem and network isolation require bubblewrap and user namespaces
- macOS (Apple Silicon) — filesystem and network isolation use the built-in Seatbelt sandbox
- Rust 2024 edition (1.85+) for building from source

## License

[MIT](LICENSE)
