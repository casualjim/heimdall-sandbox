---
date: 2026-05-07T12:26:16-0700
author: Ivan Porto Carrero
commit: 25817b4
branch: main
repository: heimdall-sandbox
topic: "Linux eBPF-only controlled egress instead of dual-legged proxy"
confidence: medium
complexity: high
status: ready
tags: [solutions, linux, ebpf, sandbox-networking]
last_updated: 2026-05-07T12:26:16-0700
last_updated_by: Ivan Porto Carrero
---

# Solution Analysis: Linux eBPF-only controlled egress instead of dual-legged proxy

**Date**: 2026-05-07T12:26:16-0700
**Author**: Ivan Porto Carrero
**Commit**: 25817b4
**Branch**: main
**Repository**: heimdall-sandbox

## Research Question

Instead of the planned dual-legged TCP↔UDS/socat-style managed proxy in `SANDBOX-PLAN.md`, can Linux controlled outbound networking be done purely with eBPF?

## Summary

**Problem**: The plan currently reserves future controlled outbound networking for a managed proxy bridge, but that adds userspace relay/process complexity.
**Recommended**: Cgroup-BPF connect gate - it is the strongest Linux-only fit for kernel-enforced per-sandbox L3/L4 allow/deny, but it is not a full HTTP/SOCKS proxy replacement.
**Effort**: High (10-15 days for a production-quality restricted-network mode with privileged tests)
**Confidence**: Medium

## Problem Statement

**Requirements:**
- Explore replacing the planned dual-legged proxy/socat bridge with Linux eBPF.
- Preserve sandbox safety: fail closed, do not weaken existing `network: "none"`, and keep enforcement scoped to the sandbox process tree.
- Be explicit about whether eBPF can replace proxy semantics, not just packet filtering.
- Fit the current Rust workspace and Linux bubblewrap architecture.

**Constraints:**
- Current policy model has only `NetworkMode::Host` and `NetworkMode::None` (`crates/heimdall-sandbox-policy/src/lib.rs:105`).
- Current Linux network denial is bubblewrap `--unshare-net`, emitted for `NetworkMode::None` (`crates/heimdall-linux-sandbox/src/plan.rs:226`).
- Current CLI/policy JSON accepts only `"host"`/`"none"` for network and rejects unknown fields (`crates/heimdall-sandbox/src/lib.rs:152`, `crates/heimdall-sandbox/src/lib.rs:305`).
- Linux eBPF/cgroup attachment requires kernel support, cgroup v2 lifecycle, and privileged capabilities such as `CAP_BPF`, `CAP_NET_ADMIN`, or broader privileges depending on kernel/distro.
- macOS remains Seatbelt-based; Linux-only restricted networking must not silently become full access on macOS.

**Success criteria:**
- A chosen option defines a concrete Linux implementation path.
- Existing `network: "none"` remains deny-all via bwrap net namespace isolation.
- Any new restricted egress mode triggers sandbox isolation and fails closed if BPF/cgroup setup fails.
- The design distinguishes L3/L4 policy from HTTP/SOCKS proxy features.

## Current State

**Existing implementation:**
- Platform dispatch routes isolation requests to Linux bubblewrap or macOS Seatbelt (`crates/heimdall-core/src/executor.rs:34`).
- `ExecRequest::needs_isolation()` currently isolates only for `NetworkMode::None` or non-empty filesystem policy (`crates/heimdall-core/src/request.rs:124`).
- Linux bwrap planning adds namespace flags, including `--unshare-net` only when `NetworkMode::None` (`crates/heimdall-linux-sandbox/src/plan.rs:226`).
- The managed proxy is future design text only: Phase 4 lists "Managed proxy routing" and sketches TCP↔UDS bridge plus proxy env rewrite (`SANDBOX-PLAN.md:407`, `SANDBOX-PLAN.md:577`).

**Relevant patterns:**
- Platform-specific dependency split: Linux and macOS sandbox crates are conditionally used by core (`crates/heimdall-core/Cargo.toml:6`).
- Low-level Linux process hardening exists via `prctl` (`crates/heimdall-process-hardening/src/lib.rs:56`).
- bwrap behavior is planned in a structured argument builder with unit tests for `--unshare-net` (`crates/heimdall-linux-sandbox/src/plan.rs:363`).
- Integration tests already skip unavailable bwrap (`crates/heimdall-sandbox/tests/exec.rs:10`), which is a precedent for prerequisite-gated tests, but not enough for privileged BPF validation.

**Integration points:**
- `crates/heimdall-sandbox-policy/src/lib.rs:105` - add a restricted Linux network mode/policy shape.
- `crates/heimdall-sandbox/src/lib.rs:152` - extend JSON parsing/schema for restricted egress fields.
- `crates/heimdall-core/src/request.rs:124` - ensure restricted egress triggers isolation.
- `crates/heimdall-core/src/executor.rs:127` - interpose Linux cgroup/BPF lifecycle around bwrap spawn.
- `crates/heimdall-linux-sandbox/src/plan.rs:226` - keep `network:none` semantics separate from a new restricted mode.
- `.github/workflows/ci.yml:13` - CI currently lacks privileged BPF/cgroup setup.

## Solution Options

### Option 1: Cgroup-BPF connect gate

**How it works:**
Attach `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` programs to a dedicated sandbox cgroup using `BPF_CGROUP_INET4_CONNECT`, `BPF_CGROUP_INET6_CONNECT`, and UDP sendmsg hooks. The BPF program checks destination IP/port/protocol against maps populated by the Rust loader and returns allow/deny before the socket connect/send proceeds.

**Pros:**
- Best per-sandbox scoping: each sandbox process tree can be moved into its own cgroup.
- Strongest fit for the actual enforcement goal if the requirement is L3/L4 allow/deny, not proxy protocol behavior.
- Mature kernel primitive: cgroup sock_addr hooks are documented kernel/libbpf attach types.
- Smaller blast radius than TC/veth because it does not require owning routes, veth pairs, qdiscs, or NAT.

**Cons:**
- Does not implement HTTP/SOCKS semantics: no CONNECT, auth, proxy DNS, headers, TLS visibility, per-URL policy, or request logging.
- Requires cgroup lifecycle and privileged BPF loading/attachment.
- Current repo has no cgroup/eBPF precedent or BPF loader dependencies.
- DNS and UDP policy require extra hooks and tests; DNS hostname intent is not visible at TCP connect time.

**Complexity:** High (~10-15 days)
- Files to create: 2-4 (~600-1,200 lines) for Linux cgroup/BPF loader, BPF program artifact, policy maps, tests.
- Files to modify: 6-9 (~400-800 lines) across policy, CLI schema, core request/executor, Linux sandbox, CI/docs.
- Risk level: Medium-high.

### Option 2: Cgroup-BPF connect rewrite

**How it works:**
Use the same cgroup sock_addr hooks, but rewrite outbound destination IP/port to an approved local or host endpoint. This can avoid a dual-legged socat bridge for some transparent L4 routing cases, while a host-side service handles the ultimate egress.

**Pros:**
- Can remove part of the planned bridge by doing transparent L4 destination rewriting in the kernel.
- Per-sandbox cgroup scoping is still strong.
- Reuses the same likely BPF/control-plane foundation as the connect gate.

**Cons:**
- Still needs an endpoint/service if traffic must leave the host; eBPF cannot synthesize SOCKS or HTTP proxy conversations.
- Conflicts with the current `--unshare-net` model unless a new reachable controlled-network mode is introduced.
- DNS/TLS behavior is subtle: the app resolves the original host, but the kernel rewrites the connect target.
- Higher behavioral verification cost than allow/deny because rewrite correctness must be proven for IPv4/IPv6, TCP/UDP, checksums, loopback, and failure modes.

**Complexity:** High (~12-18 days)
- Files to create: 3-5 (~800-1,500 lines).
- Files to modify: 7-10 (~500-900 lines).
- Risk level: High.

### Option 3: TC/veth egress policy

**How it works:**
Create a network namespace for each sandbox, connect it to the host through a veth pair, and attach tc eBPF programs at the veth boundary. The BPF datapath can drop, mark, account, redirect, or rewrite packets using interface-level metadata.

**Pros:**
- Strong L3/L4 packet-path control at a clear sandbox boundary.
- Mature pattern in container networking; netns/veth/tc are well-known Linux primitives.
- Can support richer packet accounting and NAT-like steering than connect hooks.

**Cons:**
- Highest integration cost: must own netns/veth creation, IP addressing, routes, qdiscs, cleanup, and privileged setup.
- Not naturally per process unless every sandbox gets dedicated netns/veth plumbing.
- More race-prone with current bwrap lifecycle because bwrap currently owns namespace creation.
- Still does not implement HTTP/SOCKS proxy semantics.

**Complexity:** High (~15-25 days)
- Files to create: 4-7 (~1,200-2,000 lines).
- Files to modify: 8-12 (~700-1,200 lines).
- Risk level: High.

### Option 4: sk_lookup + sockmap/sk_msg L4 dispatch

**How it works:**
Attach `BPF_PROG_TYPE_SK_LOOKUP` to a network namespace and use sockmap/sockhash plus `sk_msg`/`sk_skb` programs to assign local traffic to sockets or redirect socket data among managed sockets.

**Pros:**
- Real kernel-native socket steering path.
- Useful for local L4 dispatch, socket load balancing, and socket-to-socket redirection patterns.
- Upstream kernel docs and production precedents exist in systems like Cilium.

**Cons:**
- Niche fit for outbound sandbox egress: `sk_lookup` is mainly local delivery socket selection, not arbitrary outbound connect policy.
- Requires managed sockets inserted into maps, increasing lifecycle complexity.
- Poor replacement for the planned proxy bridge unless the problem is narrowed to local socket dispatch.
- Still no HTTP/SOCKS semantics.

**Complexity:** High (~12-20 days)
- Files to create: 4-6 (~900-1,600 lines).
- Files to modify: 7-10 (~500-900 lines).
- Risk level: High.

## Comparison

| Criteria | Connect gate | Connect rewrite | TC/veth policy | sk_lookup/sockmap |
|----------|--------------|-----------------|----------------|-------------------|
| Complexity | High | High | High+ | High |
| Codebase fit | Medium-low | Medium-low | Low | Low |
| Risk | Medium-high | High | High | High |
| L3/L4 enforcement | High | High | High | Medium |
| Proxy semantic replacement | No | No | No | No |
| Verification cost | High | High+ | High+ | High+ |
| Operational prerequisites | cgroup v2 + BPF caps | cgroup v2 + BPF/network caps + endpoint | netns/veth/tc + BPF/network caps | netns + BPF/socket-map caps |

## Recommendation

**Selected:** Option 1 — Cgroup-BPF connect gate

**Rationale:**
- It is the only option that directly matches per-sandbox outbound allow/deny with a bounded Linux kernel surface: cgroup membership plus socket-address hooks.
- It avoids the biggest operational burden of TC/veth: no per-sandbox routes, veth pairs, qdiscs, or NAT ownership.
- It has the clearest fail-closed story: if the cgroup/BPF hook cannot be installed before spawn, return sandbox misconfiguration instead of running unsandboxed.
- Current managed proxy routing is not implemented yet (`SANDBOX-PLAN.md:407`, `SANDBOX-PLAN.md:577`), so choosing this now mostly changes design direction rather than deleting code.

**Why not alternatives:**
- Option 2: useful only if transparent L4 rewrite is required, but it still needs a userspace endpoint and does not remove proxy semantics. It is a second phase after allow/deny is proven.
- Option 3: technically powerful, but it turns the sandbox binary into a mini container networking stack. That is too much integration and verification cost for the current goal.
- Option 4: socket dispatch is the wrong primary primitive for arbitrary outbound egress; it is better suited to local load balancing or managed socket redirection.

**Trade-offs:**
- Accepting no HTTP/SOCKS semantics in exchange for a much simpler kernel-enforced L3/L4 restricted mode.
- Accepting Linux-only privileged operation in exchange for stronger OS-level egress control.
- Keeping a future userspace proxy option available if application-layer policy becomes required.

**Implementation approach:**
1. Add a new Linux restricted-network policy shape, separate from `host` and `none`.
2. Extend `needs_isolation()` so restricted egress always routes through the sandbox path.
3. Add Linux cgroup lifecycle: create per-sandbox cgroup, move the bwrap child/process tree into it before user command execution, clean up on all exits.
4. Add a cgroup sock_addr BPF program and loader using a Rust-friendly path such as Aya or libbpf-rs.
5. Store allow/deny rules in BPF maps keyed by address family, CIDR/IP, port, and protocol.
6. Fail closed on missing kernel support, missing privileges, BPF verifier failure, cgroup write failure, or attach failure.
7. Keep `network: "none"` as bwrap `--unshare-net`; do not reinterpret it as BPF filtering.
8. Add privileged/manual tests first; add CI only if a privileged runner is available.

**Integration points:**
- `crates/heimdall-sandbox-policy/src/lib.rs:105` - add restricted network policy types.
- `crates/heimdall-sandbox/src/lib.rs:152` - extend CLI JSON parsing and schema.
- `crates/heimdall-core/src/request.rs:124` - make restricted networking require isolation.
- `crates/heimdall-core/src/executor.rs:127` - add Linux setup/cleanup lifecycle around bwrap spawn.
- `crates/heimdall-linux-sandbox/src/plan.rs:226` - preserve existing bwrap net namespace behavior for deny-all mode.
- `.github/workflows/ci.yml:13` - decide whether privileged eBPF tests can run in CI or remain manual/self-hosted.

**Patterns to follow:**
- Platform dispatch through `heimdall-core` (`crates/heimdall-core/src/executor.rs:34`).
- Fail-closed sandbox misconfiguration handling (`crates/heimdall-core/src/error.rs:75`).
- Linux unit tests that assert generated bwrap arguments (`crates/heimdall-linux-sandbox/src/plan.rs:363`).
- Existing prerequisite-gated integration tests as a model, with stronger manual coverage for privileged BPF (`crates/heimdall-sandbox/tests/exec.rs:10`).

**Risks:**
- **Proxy expectation mismatch**: users may expect HTTP/SOCKS features. Mitigation: name the mode restricted L3/L4 egress, not proxy.
- **Privilege friction**: CAP_BPF/CAP_NET_ADMIN/root may not be available. Mitigation: fail closed with clear exit code 2 and document prerequisites.
- **Kernel variability**: helper availability and verifier behavior vary. Mitigation: runtime feature detection plus a tested kernel support matrix.
- **Setup race**: child could connect before attach. Mitigation: attach before user command exec, likely through the existing inner re-entry stage or a pre-exec synchronization barrier.
- **MacOS semantic drift**: restricted mode must not become full access on macOS. Mitigation: explicitly reject unsupported modes on non-Linux platforms.

## Scope Boundaries

- Build a Linux-only restricted L3/L4 egress mode.
- Do not replace `network: "none"`; keep it as deny-all via bwrap network namespace isolation.
- Do not claim HTTP/SOCKS proxy replacement unless a userspace proxy remains in the design.
- Do not add packet-path TC/veth ownership unless connect hooks prove insufficient.
- Do not add shell/exfiltration AST policy as part of this networking change.

## Testing Strategy

**Unit tests:**
- Parse restricted network policy and reject unknown/invalid fields.
- Ensure restricted network mode triggers `needs_isolation()`.
- Ensure macOS/non-Linux rejects Linux-only restricted mode instead of allowing full network.
- Validate BPF map key construction for IPv4, IPv6, TCP, UDP, ports, and CIDRs.
- Validate setup errors map to sandbox misconfiguration exit code 2.

**Integration tests:**
- Allowed TCP connect succeeds to an approved endpoint.
- Denied TCP connect fails to an unapproved endpoint.
- IPv6 allow/deny behaves consistently.
- UDP/DNS behavior is explicitly controlled or explicitly unsupported.
- Forked child processes inherit cgroup policy.
- Existing `network: "none"` still produces bwrap net isolation and cannot connect outward.
- Missing BPF capability, missing cgroup v2, verifier rejection, and attach failure fail closed.
- Cleanup removes cgroups/BPF links/maps after success, error, signal, and parent death.

**Manual verification:**
- [ ] Run on a known supported kernel with cgroup v2 and required capabilities.
- [ ] Inspect loaded programs/maps with `bpftool` during a sandbox run.
- [ ] Verify denied destinations do not receive SYN packets.
- [ ] Verify concurrent sandboxes with different policies do not cross-contaminate.
- [ ] Verify setup failure does not execute the user command unsandboxed.

## Open Questions

**Resolved during research:**
- Can pure eBPF replace HTTP/SOCKS proxy semantics? No. eBPF candidates can enforce or redirect L3/L4 traffic, but cannot implement CONNECT negotiation, proxy auth, HTTP headers, per-URL policy, TLS-aware routing, or SOCKS domain semantics by themselves.
- Is the planned proxy already implemented? No. It appears as future design text in Phase 4 (`SANDBOX-PLAN.md:407`, `SANDBOX-PLAN.md:577`).
- Which eBPF primitive fits per-sandbox allow/deny best? Cgroup sock_addr connect hooks fit best because they attach per cgroup and run at socket connect/sendmsg time.

**Requires user input:**
- Is L3/L4 allow/deny enough, or must the system preserve HTTP/SOCKS proxy semantics?
- Is requiring root/CAP_BPF/CAP_NET_ADMIN or a privileged helper acceptable for Linux users?
- Should destination policy be IP/CIDR-only, or should DNS/hostname policy be in scope?
- Should restricted egress be a future mode after `host`/`none`, or replace the planned proxy Phase 4 item entirely?

**Blockers:**
- No implementation blocker for a design phase if the target is L3/L4 allow/deny.
- Full pure-eBPF proxy replacement is blocked by layer mismatch: proxy semantics are application-layer behavior.

## References

- `SANDBOX-PLAN.md:577` - Planned managed proxy routing design.
- `crates/heimdall-sandbox-policy/src/lib.rs:105` - Current network enum shape.
- `crates/heimdall-linux-sandbox/src/plan.rs:226` - Current Linux bwrap network namespace behavior.
- `crates/heimdall-core/src/request.rs:124` - Current isolation trigger logic.
- Linux cgroup sock_addr docs: <https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_CGROUP_SOCK_ADDR/>
- Linux libbpf program type docs: <https://docs.kernel.org/bpf/libbpf/program_types.html>
- Linux cgroup docs: <https://docs.kernel.org/admin-guide/cgroup-v2.html>
- Linux capabilities docs: <https://man7.org/linux/man-pages/man7/capabilities.7.html>
- Linux network namespaces docs: <https://man7.org/linux/man-pages/man7/network_namespaces.7.html>
- Linux veth docs: <https://man7.org/linux/man-pages/man4/veth.4.html>
- Linux tc-bpf docs: <https://man7.org/linux/man-pages/man8/tc-bpf.8.html>
- Linux sk_lookup docs: <https://docs.kernel.org/bpf/prog_sk_lookup.html>
- Linux sockmap docs: <https://docs.kernel.org/bpf/map_sockmap.html>
- SOCKS v5 RFC: <https://www.rfc-editor.org/rfc/rfc1928.txt>
- HTTP semantics RFC: <https://www.rfc-editor.org/rfc/rfc9110.html>
