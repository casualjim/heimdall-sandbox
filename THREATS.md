# THREAT TABLE — secret material reaching model context

Enumerate first. Mitigate second. Mitigations are scoped to a lifecycle stage;
a mitigation at the wrong stage is not coverage.

Failure = credential or sensitive material rendered into the agent's context.
Not exfiltration. Threat actor = non-malicious but persistent agent that routes
around friction, escalating to less observable channels when blocked.

## §L LIFECYCLE STAGES

| id | stage | what happens | who controls it |
|----|-------|--------------|-----------------|
| S1 | provision | credential exists somewhere the agent can reach | host config, env, cluster RBAC |
| S2 | intent | agent constructs the command / API request | judge on outbound request |
| S3 | execution | command runs — locally, or remotely in a system the agent controls | sandbox, RBAC |
| S4 | return | output travels back toward the harness | network chokepoint (MITM) |
| S5 | ingestion | bytes become model context | harness tool-result hook |
| S6 | persistence | transcripts, corpora, memory files, provider logs | scrubbing, rotation |

Key property: **S3 may occur outside any boundary you own.** A pod, a CI job, an
SSH session. For those vectors S1/S2/S4 are the only reachable stages.

## §M MITIGATIONS

Mechanism only. Implementation is UNCHOSEN — see §Y. Do not let a candidate's
existence decide the design.

| id | mitigation | stage | mechanism |
|----|-----------|-------|-----------|
| M1 | placeholder substitution | S1+S4 | agent holds a placeholder; real value swapped in at egress to an allowed host |
| M2 | egress allowlist | S4 | outbound connections restricted to named hosts, per-secret |
| M3 | TLS interception | S4 | terminate + re-encrypt so S4 mitigations can see plaintext |
| M4 | endpoint response redaction | S4 | URL-pattern match → redact structured fields (`.data`, `.stringData`) |
| M5 | shape scan on response | S4 | secret-pattern detectors over response bodies. ceiling = shapeless secrets |
| M6 | PII scan on response | S4 | PII model over response bodies. different threat class from credentials |
| M7 | outbound intent judge | S2 | classify request before it executes — shell command, pod spec, exec cmd |
| M8 | tool-result redaction | S5 | harness hook rewrites tool result before the model sees it |
| M9 | agent sockets | S1 | real key stays host-side; agent gets a socket that performs the operation |
| M10 | environment segregation | S1 | agent credentials point at an environment holding no real secrets |
| M11 | process/fs hardening | S3 | restrict filesystem and exec for the agent process |
| M12 | hardware isolation | S3 | VM boundary around the agent |
| M13 | corpus scrub + rotate | S6 | redact persisted transcripts, gate on verification, rotate what leaked |
| M14 | reaction mining | S6 | mine transcripts for human reactions to leaks |
| M15 | auth-terminating protocol proxy | S1+S4 | proxy speaks the wire protocol through auth, re-authenticates upstream with the real credential, forwards after. agent's connection string points at the proxy; real host + credential never in its env |

### M15 detail

Challenge-response auth (postgres SCRAM-SHA-256, mysql `caching_sha2`, mongo SCRAM)
means a placeholder cannot be string-swapped in flight — the client derives a proof
FROM the password, so a swapped string yields a wrong proof. ∴ terminate, don't rewrite:

1. client authenticates to the proxy (trust, or against the placeholder)
2. proxy runs its own auth exchange upstream with the real credential
3. after `AuthenticationOk`, bridge bytes

pgbouncer's auth-passthrough model. Redis `AUTH` is a plain command ∴ straight
substitution works there.

Two properties that matter:

- **⊥ transparent interception needed.** The proxy IS the endpoint. No `HTTPS_PROXY`
  cooperation, no netns, no VM ∴ M15 does NOT inherit §G.G3. Works identically on macOS.
- **Terminating ⇒ result sets visible in clear.** `DataRow` messages are parsed ∴ M5+M6
  apply to query results, which is the only coverage T14 has.

! fail CLOSED on unrecognized protocol version or auth method. A blind forward is a
silent bypass, and silent bypasses are the ones never discovered.

### M1/M2 constraint — per-session scoping

One shared network stack ⇒ one policy for every session inside it. Project A's session
gets project B's egress rights and placeholders. ∴ any M1/M2 implementation ! scope
policy per session:

- each session gets its own source address inside the boundary
- interception layer resolves session → secret set + allowlist by source address

Cheap to design in, expensive to retrofit. Applies to shared-VM designs (one long-lived
VM, sessions spawned into it) and to any multi-session host proxy.

## §Y IMPLEMENTATION CANDIDATES — none chosen

| mitigation | candidates | notes |
|-----------|-----------|-------|
| M1,M2,M3 | standalone intercepting proxy (own, or mitmproxy) · heimdall extension · boxlite (`Secrets`/`AllowNet`/`CACertPEM`, built) · microsandbox (built) · exec-time injection wrapper, no interception at all | proxy-layer work is OS-independent and needs no VM. VM only adds enforcement against a guest actively evading — not this threat actor |
| M4,M5,M6 | wherever M3 lands | M4 is ~50 LOC in any of them |
| M7 | — | undecided; this is the only place a learned model is still in question |
| M8 | pi / codex / opencode extension | not available in Claude Code |
| M9,M11 | heimdall (Seatbelt + bubblewrap + agent sockets, built, cross-platform) | |
| M12 | boxlite · microsandbox · Tart (macOS guests) · none | Linux guests only except Tart. Optional for this threat actor |
| M13 | cft-extract `--redact` + membership gate | partial today |
| M15 | heimdall (already discussed there) · standalone per-protocol proxy | ⊥ needs VM or netns — the proxy IS the endpoint ∴ macOS parity |

## §T THREAT VECTORS

| id | vector | example | S3 location | mitigations | coverage |
|----|--------|---------|-------------|-------------|----------|
| T1 | direct credential file read | `cat ~/.aws/credentials` | local | M1, M7, M8 | ✓ |
| T2 | obfuscated file read | `sh -c 'cat .env'`, `base64 .env`, `python3 -c` | local | M1, M7(parse), M8 | ✓ |
| T3 | environment dump | `env`, `printenv`, `/proc/self/environ`, `set` | local | M1, M8 | ✓ |
| T4 | secret-manager CLI | `gopass show`, `vault kv get`, `op read` | local+remote | M1, M4, M7 | ~ |
| T5 | cloud secret manager | `aws secretsmanager get-secret-value` | remote HTTP | M4 (endpoint), M5 | ✓ |
| T6 | k8s secret, direct | `kubectl get secret -o yaml` | remote HTTP | M4 (endpoint) | ✓ |
| T7 | **k8s secret, indirect** | `kubectl run dbg -- sh -c 'env'` then `kubectl logs dbg` | **inside cluster** | M7 (pod spec), M5 | **✗ shapeless** |
| T8 | other remote execution | `docker run`, `ssh host 'env'`, CI job, lambda | **remote host** | M5, M7 | **✗ shapeless** |
| T9 | non-HTTP protocol creds | `psql "postgres://u:pw@…"`, redis, mongo URI | local+remote | M15 | ✓ per protocol implemented |
| T10 | local crypto with real key | `sops -d`, `age -d`, `gpg --decrypt` | local | M9 | ~ |
| T11 | secret in unexpected output | token in error message, CI log, build output | anywhere | M5, M6 | ~ shape only |
| T12 | secret at rest in repo | committed `.env`, `tfstate`, inline password in config | local | M1 (if enumerated), M13 | ~ |
| T13 | agent re-reads own artifact | agent writes secret to a file, reads it later | local | M8 | ~ |
| T14 | PII / customer data | `psql` query returning customer rows | remote | M15 → M6 | ~ needs M15 to see `DataRow` |
| T15 | secrets already in transcripts | historical leaks in session corpora | — | M13, M14 | ~ |

## §G GAPS — ranked

| rank | gap | why it is hard | direction |
|------|-----|----------------|-----------|
| G1 | **T7/T8 shapeless secrets via remote execution** | S3 is outside every boundary you own; output arrives as anonymous text on a non-secret endpoint (`/pods/*/log`) | M7 at pod-spec creation — structured JSON, far more tractable than shell. M5 as backstop with a known ceiling. |
| G2 | **T9 per-protocol coverage** | M15 solves the class, but each protocol needs its own auth flow implemented; auth methods drift across versions. ssh ∉ scope — M9 agent forwarding covers it | implement postgres first (highest use), fail closed on unknown version |
| G3 | **macOS enforcement of S4** | no network namespaces; no lightweight macOS sandbox. M1-M6 all need traffic forced through the interception point. Linux: netns (`bwrap --unshare-net`) enforces it. macOS: only cooperative `HTTPS_PROXY`, or pf-by-uid / NetworkExtension (root, heavyweight) | accept cooperative + **enumerate which tools honor proxy env**; silent bypass is the failure mode, so absence of alerts is not coverage |
| G4 | **T10 local crypto** | placeholder key cannot decrypt | M9 agent sockets |
| G5 | **Claude Code** | no tool-result interception → M8 unavailable | M4 at network layer still applies |

## §P PRINCIPLES ESTABLISHED

- P1: **Friction causes escalation to less observable channels.** Blocking `kubectl get secret` produces a debug pod whose output arrives as anonymous log text. Prefer redaction over blocking wherever the fallback path is unobservable.
- P2: **Shape-based detection has a ceiling; source-based does not** — but source-based requires the source be enumerable, which fails for T7/T8 where the source is arbitrary remote code.
- P3: **Enumeration beats recognition.** Substituting your own known credentials (finite, static) beats detecting any credential read (unbounded, adversarial). Applies wherever the credential is one you provisioned.
- P4: **The system cannot report its own blind spots.** M14 reaction mining is the only feedback channel for vectors not in this table.
- P5: This table is incomplete. Every prior architecture in this project broke on an unenumerated vector.
