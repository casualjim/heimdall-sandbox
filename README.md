# Heimdall

A Linux process sandbox runtime written in Rust. Heimdall executes untrusted commands with configurable filesystem, network, and environment isolation using Linux namespaces and [bubblewrap](https://github.com/containers/bubblewrap).

## Features

- **Filesystem isolation** — deny patterns, writable overlays, and virtual file injection using gitignore-style globs
- **Network isolation** — disable host networking inside the sandbox
- **Environment filtering** — allowlist or blocklist parent environment variables
- **Process hardening** — disable ptrace attachment, zero core file limits
- **`/proc` control** — mount or hide `/proc` inside the sandbox
- **JSON policy documents** — declarative sandbox configuration with schema validation
- **stdio control** — inherit or pipe child process I/O

## Installation

```sh
cargo install heimdall-sandbox
```

## Usage

### Run a command in the sandbox

```sh
heimdall-sandbox exec -- printf "hello"
```

### Restrict environment variables

Allowlist mode (only pass listed vars):

```sh
heimdall-sandbox exec --allow-env PATH --allow-env HOME -- env
```

Blocklist mode (pass everything except listed vars):

```sh
heimdall-sandbox exec --deny-env SECRET_TOKEN -- env
```

### Disable networking

```sh
heimdall-sandbox exec --policy - <<'EOF'
{
  "network": "none",
  "command": ["curl", "https://example.com"]
}
EOF
```

### Filesystem policy with virtual files

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

### Validate a policy document

```sh
heimdall-sandbox policy validate policy.json
```

### Print the JSON schema

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

## Architecture

Heimdall is a Cargo workspace with four crates:

| Crate | Role |
|---|---|
| `heimdall-sandbox` | CLI binary — argument parsing, policy loading, entry point. |
| `heimdall-core` | Core runtime — execution orchestration, environment filtering, signal handling. |
| `heimdall-linux-sandbox` | Linux isolation — bubblewrap planning, filesystem policy materialization. |
| `heimdall-process-hardening` | Process hardening — ptrace protection, core dump disabling. |

## Requirements

- Linux (filesystem and network isolation require bubblewrap and user namespaces)
- Rust 2024 edition (1.85+)

## License

[MIT](LICENSE)
