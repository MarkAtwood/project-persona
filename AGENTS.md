# Agent Instructions

This project uses **bd** (beads) for issue tracking. Run `bd prime` for full workflow context.

## Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

## Non-Interactive Shell Commands

**ALWAYS use non-interactive flags** with file operations to avoid hanging on confirmation prompts.

Shell commands like `cp`, `mv`, and `rm` may be aliased to include `-i` (interactive) mode on some systems, causing the agent to hang indefinitely waiting for y/n input.

**Use these forms instead:**
```bash
# Force overwrite without prompting
cp -f source dest           # NOT: cp source dest
mv -f source dest           # NOT: mv source dest
rm -f file                  # NOT: rm file

# For recursive operations
rm -rf directory            # NOT: rm -r directory
cp -rf source dest          # NOT: cp -r source dest
```

**Other commands that may prompt:**
- `scp` - use `-o BatchMode=yes` for non-interactive
- `ssh` - use `-o BatchMode=yes` to fail instead of prompting
- `apt-get` - use `-y` flag
- `brew` - use `HOMEBREW_NO_AUTO_UPDATE=1` env var

## Project Context

hired is a **user-session daemon** that federates heterogeneous human-identity sources behind the standard SPIFFE Workload API socket. It is "SPIRE for humans": a local daemon that answers "who is the person at this workstation and how confident are we they are physically present?" CLI is `hire`, daemon is `hired`. No new wire protocol -- consumers call `FetchJWTSVID` / `FetchX509SVIDs` on the local socket and get standard SPIFFE SVIDs. Any SPIFFE-aware client works unmodified.

Read `~/PROJECT/SPEC-HIRE.md` before making design changes -- it is the authoritative spec.

## Before Writing Code

For any task touching more than 3 files or requiring more than a few steps:
1. File a Beads epic and break it into issues
2. Write a plan and get approval before touching code
3. Work through issues one at a time, using parallel subagents within each issue

## Crate Boundaries

| Crate | What belongs here |
|---|---|
| `hired` | Daemon binary: socket listener, startup, signal handling, systemd/launchd integration |
| `hire` | CLI binary: `hire whoami`, `hire enumerate`, `hire fetch-jwt`, etc. |
| `hire-core` | Shared types: SPIFFE ID schema, assurance levels (`iaa1`/`iaa2`/`iaa3`), presence model (`none`/`session`/`software`/`hardware`), trust domain model |
| `hire-attestors` | Attestor plugin trait (`enumerate` -> candidates, `prove` -> evidence, `freshness`) + implementations: tailscale, ssh-agent, oidc, gpg, did:key, unix account, plus fido2 behind `--features fido2`. piv and goa are placeholder modules that never activate; there is no secure-enclave and no windows-hello module |
| `hire-grpc` | SPIFFE Workload API gRPC server: `FetchX509SVIDs`, `FetchX509Bundles`, `FetchJWTSVID`, `FetchJWTBundles`, `ValidateJWTSVID` |

**No gRPC outside `hire-grpc`. No platform-specific attestation outside `hire-attestors`. No `unsafe`.**

## Key Design Decisions

**Standard SPIFFE Workload API.** The gRPC service implements the upstream SPIFFE proto definitions (`spiffe.api.agent.v1`). No custom wire protocol. Any SPIFFE client library (go-spiffe, rust-spiffe, java-spiffe, py-spiffe) works against hired unmodified.

**Per-consumer pseudonymity.** The default SPIFFE ID exposed to a consumer is an HKDF-derived pseudonym: `spiffe://{trust-domain}/pseudonym/{hkdf-id}`. There is no `for/{consumer-app-id}` tail. Consumers get identifiers that cannot be correlated across apps without explicit user consent, stable for the lifetime of the running daemon. Derivation uses `HKDF-SHA256(ikm=pseudonym_key || root_spiffe_uri, salt=trust_domain, info=consumer_app_id)`, where `pseudonym_key` is 32 random bytes generated at start and never persisted. Keyed on the consumer application only, never on the JWT `aud`.

**Attestor plugin architecture.** Each identity source is a plugin implementing three methods: `enumerate()` discovers candidate identities, `prove(candidate, challenge)` produces evidence, `freshness(candidate)` checks liveness. A candidate carries no assurance and no presence level; both are derived from the evidence by `Claim::derive`, which is the only constructor for a `Claim`. `prove()` defaults to declining, so an attestor that cannot verify anything contributes no level and the daemon declines rather than asserting. `Claim` lives in `hire-attestors/src/claim.rs` and not in `lib.rs`: private fields on a crate-root struct stay writable from every attestor module, so moving it back would silently remove the guarantee. Plugins are loaded at startup based on platform availability. Missing sources are logged and skipped, never fatal.

**Consumer authentication via OS process attestation.** Once per connection, at accept, hired attests the calling process from its Unix socket credentials and hashes its main executable: `/proc/{pid}/exe` on Linux, `proc_pidpath` on macOS. (`GetNamedPipeClientProcessId` on Windows is unimplemented.) The consumer's verified identity drives pseudonym derivation, and a peer that cannot be attested is refused.

**No persistent storage.** hired is a normalizer, not a vault. Any data it caches is wiped on session end. It holds no secrets that are not already held by the underlying identity source.

**Cryptography via ring and rustls.** TLS on the gRPC socket via `rustls`. SVID signing (X.509, JWT, ECDSA P-256/P-384) and HKDF derivation via `ring`. Algorithm primitives via RustCrypto crates as needed.

## Code Conventions

- Rust, edition 2021
- `#[non_exhaustive]` on all public enums
- Types from `jmap-chat-types` / `jmap-types` are constructed via serde (`serde_json::from_value` pattern) -- do NOT add `new()` constructors to upstream types
- Error handling: `thiserror` for library crates (`hire-core`, `hire-attestors`, `hire-grpc`), `anyhow` for binaries (`hired`, `hire`)
- Async runtime: `tokio`
- gRPC framework: `tonic`
- Tests: `cargo test`, no external test harnesses
- Platform-specific code behind `#[cfg]` feature flags, not runtime detection

## Quality Gate (run before every commit)

```bash
cargo fmt --all
cargo clippy --all-features -- -D warnings
cargo test
```

All three must pass clean. If `cargo fmt` changes files, stage and include those changes in the commit.

## Test Integrity

**Never cheat on tests.** No exceptions.

- Failing test -> fix the code, not the test
- Never hardcode a value derived from running the code under test
- Never mock an attestor or socket call just to make the test green unless the test is explicitly a unit test of a higher layer
- If a fix is out of scope, escalate rather than papering over it

**Auth rejection must be tested.** For every authorized path, there must be a test that an unattested or wrong-identity consumer is rejected.

## Related Projects

| Project | Location | Relationship |
|---|---|---|
| kith | `~/PROJECT/kith/` | First consumer of hired. kithd replaces Tailscale WhoIs with `FetchJWTSVID` on the hire socket. |
| moot | `~/PROJECT/moot/` | Second JMAP Chat implementation (Python). Future hired consumer. |
| jmap-chat-types | crates.io | Mark's crate. Shared JMAP Chat wire types. |
| jmap-types | crates.io | Mark's crate. Base JMAP types. |
| SPEC-HIRE.md | `~/PROJECT/SPEC-HIRE.md` | Authoritative design spec for hired. |

## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` for full workflow context.

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work atomically
bd close <id>         # Complete work
bd dolt push          # Push beads data to remote
```

**Beads is the only task and planning tool.** Do NOT use:
- TodoWrite / markdown TODO lists
- Scratchpad or audit files (`audit-*.md`, `plan-scratch.md`, or any similar throwaway planning file)
- MEMORY.md or any other markdown file as a knowledge store

The only permitted markdown planning artifact is a crate's `PLAN.md`, which is a permanent
design document checked into the repo -- not a scratchpad. Use `bd remember` for persistent
knowledge and `bd create` for all task tracking.
