# Security Policy

idryx is a security product, so its own trust boundaries matter. This document
states the threat model, the design invariants that bound idryx's blast radius,
and how to report a vulnerability.

## Reporting a vulnerability

Please report security issues privately, not in public issues or PRs:

- Open a **GitHub private security advisory**:
  <https://github.com/TAIPANBOX/idryx/security/advisories/new>

Include the affected version/commit, a description, and a minimal reproduction.
We aim to acknowledge within a few days and to fix high-severity issues before
any public disclosure. There is no bug-bounty program; we credit reporters in the
advisory unless you prefer otherwise.

## Design invariants

These are load-bearing security properties. A change that breaks one is a bug.

1. **Read-only against the cloud and IdP.** idryx observes; it never mutates the
   IdP, cloud provider, or any monitored system. Remediation is delivered as
   Terraform artifacts and (optionally) a pull request -- never `terraform apply`.
   Apply stays with the operator and their CI. The `ebpf-capture` sensor (see
   below) is the one place idryx asks for elevated privilege at all, and even
   there it only ever reads kernel-exposed connection metadata -- it cannot
   mutate the host it runs on either.
2. **Detection is deterministic.** Detectors are statistics and rules over the
   graph. No LLM is ever in the detection path; LLMs may only ever be an
   interface layer (NL queries, explanations).
3. **Inputs are untrusted.** Every connector input -- IdP logs, IAM dumps, agent
   and MCP inventories, egress logs -- is attacker-influenced data. Fields that
   flow to a sink (a filename, a shell/`gh` argument, HTML/JS, SQL) must be
   neutralised for that sink's context.

## Threat model

### Trust boundaries

| Boundary | Untrusted side | Defense |
| --- | --- | --- |
| Connector ingest | log/inventory JSON (identity IDs, policy names, hosts) | parsed into a typed model; never `eval`'d or shelled |
| Dashboard (`serve`) | identity IDs etc. rendered into HTML/JS | client-rendered from JSON APIs; `esc()` for HTML, `escJS()` for JS-string-in-attribute contexts |
| JSON API | same fields returned to clients | `encoding/json` (data, not markup) |
| Remediation artifacts (`--out`, `--open-pr`) | identity IDs used as filenames | `SanitizeName` whitelists `[A-Za-z0-9._-]`; collisions de-duplicated; no path traversal |
| Enforcement (`--open-pr`) | identity/policy names as `git`/`gh` arguments | executed via `exec.CommandContext` with an argument slice -- **no shell**, so no command injection; a preflight verifies a clean git work tree and authenticated `gh` before any branch is created |
| Postgres (`--db`, `--save-db`) | event/identity/remediation rows | parameterized queries only (pgx); no string-concatenated SQL |
| eBPF sensor (`ebpf-capture`) | raw kernel tracepoint data (pid, process name, destination ip:port) | fixed-size ring buffer records validated by exact byte length before parsing; malformed/short records are skipped, never trusted as control data; the eBPF program itself only ever reads, never writes, kernel or process memory |

### eBPF network sensor (`ebpf-capture`)

`internal/ebpfcapture` is idryx's one privileged, host-level connector -- every
other connector reads logs/inventory a caller already has; this one asks to run
as root (or with `CAP_BPF`+`CAP_PERFMON`) on a real Linux host so it can attach
a small BPF program to the `sys_enter_connect` tracepoint and observe outbound
`connect()` calls directly from the kernel. That is a materially different
trust posture from the rest of idryx, so it gets its own explicit callout
rather than folding into the table above:

- **Scope of what it reads.** Only the arguments of `connect()` calls already
  visible to any process on the host with tracing permissions: the calling
  PID, its `comm` (short process name), and the destination `AF_INET`
  address/port. It never reads packet payloads, never terminates or inspects
  TLS, and captures no data after the connection is established (`Bytes` is
  always `0` in its output -- see `internal/ebpfcapture/flow.go`).
- **The BPF program is load-only, not enforcement.** `connect.c`'s
  `on_connect` handler only copies fields into a ring buffer; it never
  returns a non-zero verdict that could block or alter the syscall. A kernel
  new enough to reject the program's BTF/CO-RE relocations, or a missing
  `/sys/kernel/btf/vmlinux`, fails the whole sensor loudly at startup -- see
  `Run`'s error wrapping in `capture_linux.go` -- it never fails silently into
  a partially-working state.
- **`comm` is a process-supplied, not kernel-verified, identity.** Any process
  can rename itself (`PR_SET_NAME`/`prctl`), including immediately before or
  after the `connect()` call this sensor observes. The resulting
  `proc:<comm>`-prefixed graph identity (see `ebpfcapture.Identity` and the
  `unmanaged_egress` detector) is intentionally coarse and stated as such: it
  answers "was a connection with this reported process name observed here,"
  not "which specific governed agent made this call." A host already
  compromised enough to run an evasive agent could rename that process to
  dodge or spoof attribution -- the sensor's honest job is only to catch
  network activity with **no** attribution at all (no IAM, agent-event, or
  Passport record whatsoever), which is a real gap it closes regardless of
  this limitation, not a claim that it resolves identity reliably under an
  adversarial host.
- **JA3/JA4 TLS fingerprinting is out of scope permanently, not for this
  version.** It would require reading the ClientHello, which is reading what
  the application wrote into its socket, and that contradicts all three clauses
  above: payloads, TLS inspection, and data after the connection is
  established. A ClientHello is plaintext, so nothing would be decrypted, but
  the promise is not about encryption; it is about this sensor not looking
  inside data at all. Decided 2026-08-09: the promise stands and the
  fingerprint does not happen.
- **DNS-tunnel detection is also out of scope permanently**, decided
  2026-08-09, and the reasoning corrects something this file said until that
  day. It was listed as deferred "which does not need to read a payload", and
  that was wrong. A DNS tunnel encodes its data in the QUERY NAME
  (`k7fq2b3x.dGVzdA.tunnel.example.com`), which lives in the body of the DNS
  request. This sensor sees that a process connected to a resolver and nothing
  else: measured on the live capture above, every DNS flow rendered as
  `172.31.0.2:53`. Distinguishing a tunnel from ordinary browsing needs the
  name, the name is a payload, and that is the same wall JA3/JA4 met.

  A second limit would remain even if the first were solved, and it is worth
  recording because it is not obvious: most DNS goes over UDP with no
  `connect()` at all. The live capture saw `systemd-resolve` only because
  systemd connects its socket. A process resolving names any other way is
  invisible to this sensor entirely, so a volume-based approximation would be
  silent on an unknown share of real traffic while looking like coverage.

- **Still deferred, and this one is a deferral rather than a decision.**
  Corroborating a claimed identity: resolving a process to a governed identity
  is partly built (agent-passport SPEC 3.3, read as a *claim*), and what
  remains is checking a claim against the graph rather than believing it. That
  needs no payload and no new hook.

  Beaconing shipped on 2026-08-09 and is no longer on this list. It works from
  connection timing alone, taken from the kernel's own clock, which is what
  made it possible inside the promise above.
  This version mirrors what TokenFuse's own `crates/radar` sensor ships
  today, not the originally-specced full scope.
- **CI builds it, never loads it, and that gap is closed by hand.** The
  `ebpf (build)` job regenerates `vmlinux.h` from the runner's own BTF and
  rebuilds the sensor on every push, so `connect.c` drifting out of sync with
  the committed bindings (`internal/ebpfcapture/bpf_bpfel.go`/`bpf_bpfeb.go`)
  fails CI. It never attaches the program or reads a packet: that needs a
  BTF-enabled kernel and root, which a hosted runner may not reliably provide.

  So a green CI says the sensor COMPILES against a kernel's types. It says
  nothing about whether the kernel accepts the program or whether the program
  observes anything, and those are the claims this sensor is bought for.

  **Live capture, 2026-08-09**, on a disposable AWS instance (Linux
  6.17.0-1019-aws, BTF present, 7,005,299 bytes), 45 seconds, root:

  | property | result |
  |---|---|
  | program loaded and observed | 28 flows captured |
  | IPv6 | `[2606:4700:4700::1111]:443`, bracketed |
  | cgroup | 25 of 28 flows carried `@cg`; a process started under `systemd-run --scope` landed in its own cgroup, distinct from its parent shell's |
  | self-declared identity | `claimed:agent://acme.example/support/live-bot`, 3 flows, from `AGENT_PASSPORT_ID` on a live process |
  | provider resolution | `api.openai.com:443` rather than a bare address |
  | sub-second precision | all 28 timestamps carried a fraction |
  | out-of-scope traffic | *"not reported -- 29 connect(s) over other address families (AF_UNIX, netlink, ...), 0 unreadable sockaddr(s)"* |

  That last row is the one nothing but a live kernel can establish: 29 AF_UNIX
  connections were counted and deliberately not reported, which is invariant 4
  doing its job on real traffic rather than in a fixture.

  Feeding the capture through `idryx detect` produced 7 alerts, including
  `claimed_agent_unknown` (critical: a process declared an identity no Passport
  in the graph names, and reached a model API), `shadow_ai`, four
  `unmanaged_egress`, and `beaconing`:

  > *5 connections to 93.184.216.34:80 on a regular cadence: every 5s, varying
  > by 0%. A heartbeat, not work; identify what schedules it.*

  Worth recording precisely because it disagreed with the operator: the beacon
  was generated with `sleep 3`, and the detector measured 5s. Both are right.
  `sleep 3` plus the connection itself is a five-second period, and the
  detector reported the traffic rather than the intention behind it.

### What idryx deliberately does NOT defend against

- **The contents of generated Terraform.** Remediation `.tf` is a human-readable
  proposed diff, not a drop-in file: a human is expected to review it, fold the
  change into their own configuration, and apply through their own plan/apply
  workflow. idryx does not execute it; an operator who applies unreviewed
  generated IaC owns that risk.
- **Credentials and access for the connectors themselves.** idryx reads whatever
  logs/inventory you feed it; securing those exports and any cloud read
  credentials is the operator's responsibility.
- **The Postgres instance.** idryx uses the DSN you provide; database access
  control and network exposure are out of scope.
- **`idryx serve` as a public endpoint.** The dashboard is read-only and has no
  authentication; run it behind your own auth/network controls, not on the open
  internet.

## Supported versions

idryx is pre-1.0; only `main` is supported. Fixes land on `main` and are not
backported.

## Verifying a build

Every change must pass the full gate before merge: `gofmt -l .` clean,
`go vet ./...`, `staticcheck ./...` (zero findings), and `go test ./...`. CI also
runs `go test -race` and the Postgres-backed integration tests. See
[`AGENTS.md`](AGENTS.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).
