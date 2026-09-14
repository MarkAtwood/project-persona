<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# personad -- Human Identity Agent

A user-session daemon that federates heterogeneous human-identity sources behind the standard SPIFFE Workload API socket. Applications call `FetchJWTSVID` on a local socket and receive a verifiable credential without caring whether identity came from Tailscale, FIDO2, PIV, OIDC, SSH agent, GPG, or DID. No new wire protocol -- just the CNCF-standard SPIFFE Workload API, extended to answer "who is the human at this keyboard, and are they present right now?"

## Why

There is no standard local API for "who is this human." Every application invents its own answer from whichever signals it happens to have access to -- the OS login session, a browser cookie, a Tailscale node, a cached OIDC token -- without a common format, provenance model, or consumer authentication discipline.

SPIFFE/SPIRE solved exactly this problem for workloads, and solved it well enough to graduate in the CNCF. Nobody did it for people. The adjacent systems each cover a slice and stop: SPIRE is explicitly scoped to "what process is this," Kerberos handles one identity source with no presence model, `pam-fido2` proves a human is present but not who they are beyond a Unix UID, WebAuthn is browser-only and gives every relying party an unlinked credential, and the platform SSO stacks are locked to one OS apiece.

The gap is a daemon answering **"who is the human at this keyboard, and are they present right now?"** over an API that already exists. `personad` aims to be that -- SPIRE's shape, pointed at the desk instead of the cluster. The full comparison table is in [SPEC-HIA.md](SPEC-HIA.md#prior-art-and-why-nothing-existing-solves-this).

## Status

**Early implementation. Do not deploy this.** The daemon builds, serves the SPIFFE
Workload API over a Unix socket, and issues signed JWT-SVIDs -- but it currently
*asserts* identity claims rather than verifying them, so the assurance and presence
guarantees described below are design intent, not present behaviour.

Concretely, as of this writing:

| Area | State |
|---|---|
| SPIFFE Workload API over gRPC/UDS | works -- covered by an end-to-end test |
| JWT-SVID issuance, ephemeral in-memory CA | works |
| Attestor registry, startup probing, `enumerate()` | works for most sources |
| CLI (`whoami`, `enumerate`, `fetch-jwt`, ...) | works |
| `prove()` -- cryptographic proof of possession | **not implemented in any attestor** |
| Identity assurance levels | **asserted, not established** -- see below |
| Presence levels | **not enforced correctly** -- the gate is bypassable |
| Per-audience pseudonyms | implemented and test-vector verified, but **not wired into issuance** |
| Consumer attestation (`SO_PEERCRED`) | implemented but **never invoked** |
| Trust bundle / `ValidateJWTSVID` | **unusable** -- publishes an empty JWKS |
| X.509-SVID, browser HTTPS gateway | stubs |

The load-bearing problem is structural rather than a list of bugs: `enumerate()`
returns the same `Claim` type that `prove()` was meant to produce, so a cheap
discovery call can hand back an assurance level nothing ever established. A
connected FIDO2 key currently yields `iaa3` plus hardware presence without anyone
touching it. Fixing that by construction -- making the unproven state
unrepresentable rather than merely discouraged -- is tracked as its own piece of
work, and the individual defects hang off it.

Issues are tracked in-repo with [beads](https://github.com/gastownhall/beads)
under `.beads/`.

## Key Concepts

Design intent. See [Status](#status) for what is actually implemented today.

- **SPIFFE Workload API** -- the daemon implements the standard gRPC Workload API (`FetchJWTSVID`, `FetchX509SVIDs`, `FetchJWTBundles`, `FetchX509Bundles`, `ValidateJWTSVID`). Any SPIFFE-aware consumer (envoy, ghostunnel, go-spiffe, rust-spiffe) works unmodified.
- **Per-audience pseudonymity** -- each consumer application is meant to receive a stable HKDF-derived pseudonym rather than the user's root identity, so cross-consumer linkage requires explicit consent. The derivation exists and is verified against externally computed vectors; it is not yet wired into issuance, and today every caller receives the root identity.
- **Identity assurance levels** -- `iaa1` (self-asserted: SSH key, GPG, DID), `iaa2` (IdP-verified: Tailscale OIDC, GNOME Online Accounts), `iaa3` (hardware-bound + IdP-verified: FIDO2, PIV, Windows Hello).
- **Presence levels** -- `none`, `session` (screen unlocked at login), `software` (TOTP/password re-entry), `hardware` (FIDO2 touch, Windows Hello, TouchID, PIV PIN -- timestamped, hardware-backed).
- **Attestor plugins** -- each identity source implements `enumerate()`, `prove()`, `freshness()`. Sources are probed at startup; missing sources are skipped, never fatal.

## Architecture

```
persona (CLI)  -->  personad (daemon)  -->  identity sources
                        |
                  SPIFFE Workload API
                  (gRPC unix socket)
                        |
                   consumer apps
```

- **Daemon:** `personad` -- runs as a user-session service (no root required)
- **CLI:** `persona` -- `whoami`, `enumerate`, `fetch-jwt`, `enroll app`, `delegate`, etc.
- **Socket (Linux):** `/run/user/{uid}/persona/workload.sock`
- **Socket (macOS):** `$TMPDIR/persona/workload.sock`
- **Socket (Windows):** `\\.\pipe\persona-workload-{sid}`
- **Browser bridge:** localhost HTTPS gateway on `127.0.0.1:2443` + native messaging host

The daemon implements the SPIFFE Workload API as-is. No new protocol is invented.

Consumer authentication is designed to use OS-level process attestation (`SO_PEERCRED` on Linux, `SecCodeCopyGuestWithAttributes` on macOS, EXE signing on Windows) to identify calling applications and derive per-consumer pseudonyms. The Linux path is implemented but is not yet called from the issuance path, so callers are currently not distinguished.

## Identity Sources

Day-one attestor plugins. The assurance and presence columns are the **target** for
each source once `prove()` exists; they are not what the daemon can currently
substantiate. See [Status](#status).

| Source | Assurance | Presence | Platforms |
|---|---|---|---|
| Tailscale | iaa2 | none | Linux, macOS, Windows |
| FIDO2 (libfido2) | iaa3 | hardware | Linux, macOS, Windows |
| PIV / smartcard | iaa3 | hardware (with PIN) | cross-platform |
| Windows Hello | iaa3 | hardware | Windows |
| Secure Enclave (TouchID) | iaa3 | hardware | macOS |
| GNOME Online Accounts | iaa2 | session | Linux (GNOME) |
| OIDC cached | iaa2/iaa1 | session | cross-platform |
| SSH agent | iaa1 | none | cross-platform |
| GPG | iaa1 | none | cross-platform |
| DID (did:key, did:web) | iaa1/iaa2 | none | cross-platform |

## Platform Support

The consumer-facing API is identical on every platform -- the SPIFFE Workload API gRPC socket. Per-platform work is entirely in the attestor plugins.

| Platform | Service manager | Notes |
|---|---|---|
| Linux (systemd) | `persona.service` (user unit) | Full source support |
| Linux (non-systemd) | Init script or user session | Socket at `/tmp/persona-{uid}/workload.sock` |
| macOS | LaunchAgent | TouchID via CryptoTokenKit |
| Windows | User-mode service | Windows Hello, named pipe transport |
| FreeBSD / OpenBSD | User session | SSH agent, GPG, Kerberos, PIV, FIDO2 |
| Containers | Bind-mount host socket | Inherits host identity |
| WSL2 | Native or bridged from Windows | AF_UNIX interop or native Tailscale |

Implementation is a single Rust binary with `#[cfg]` feature flags per platform.

## Installation

> The shipped systemd units do not currently work together: `personad.socket`
> declares socket activation, but the daemon binds its own socket at the same path
> and removes it on shutdown, and `personad.service` has no dependency on the socket
> unit. Run the binary directly until that is fixed.

### systemd (Linux)

```bash
# Build and install
cargo install --path personad

# Install user systemd units
persona install-service

# Enable and start
systemctl --user enable --now personad

# Verify
persona whoami
```

## Documents

- [SPEC-HIA.md](SPEC-HIA.md) -- normative specification: SPIFFE ID schema, trust domains, assurance levels, prior art
- [DESIGN.md](DESIGN.md) -- technical design and architecture
- [PRFAQ.md](PRFAQ.md) -- press release and anticipated questions

## License

Two licenses apply, by file type:

- **Code** — Apache-2.0. All Rust sources, `Cargo.toml` manifests, build scripts,
  protobuf definitions, and service/config files. See [LICENSE](LICENSE).
  Each crate carries `license = "Apache-2.0"` in its manifest.
- **Documentation** — CC-BY-4.0. `SPEC-HIA.md`, `DESIGN.md`, `PRFAQ.md` and this
  README. See [LICENSE-CC-BY-4.0](LICENSE-CC-BY-4.0). Each carries an SPDX
  identifier on its first line.

`AGENTS.md` and `CLAUDE.md` are agent tooling instructions and fall under Apache-2.0
with the code.
