<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# personad -- Human Identity Agent

A user-session daemon that puts many human-identity sources behind one socket: the standard SPIFFE Workload API. Applications call `FetchJWTSVID` and get a verifiable credential, whether the identity came from Tailscale, FIDO2, PIV, OIDC, SSH agent, GPG, or DID. No new wire protocol.

## Why

There is no standard local API for "who is this human." Every application invents its own answer from whatever signals it can reach: the OS login session, a browser cookie, a Tailscale node, a cached OIDC token. No common format, no provenance, no consumer authentication.

SPIFFE/SPIRE solved this for workloads and graduated in the CNCF. Nobody did it for people. The nearby systems each stop short:

| System | Stops at |
|---|---|
| SPIRE | "what process is this," not who runs it |
| Kerberos | one identity source, no presence model |
| pam-fido2 | proves a human is present, not which human |
| WebAuthn | browser only; every relying party gets an unlinked credential |
| Windows SSPI, macOS ASAuth | one OS each |

`personad` answers "who is the human at this keyboard, and are they present right now?" over the SPIFFE Workload API, which already exists and has clients. The longer argument is in [MOTIVATIONS.md](MOTIVATIONS.md); the full comparison table is in [SPEC-HIA.md](SPEC-HIA.md#prior-art-and-why-nothing-existing-solves-this).

## Status

**Early implementation. Do not deploy this.** The daemon builds, serves the SPIFFE
Workload API over a Unix socket, and issues signed JWT-SVIDs. It does not verify the
identity claims it signs. Treat the assurance and presence levels below as targets.

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

The cause is structural. `enumerate()` returns the same `Claim` type `prove()`
produces, so a discovery call can return an assurance level nothing established. A
FIDO2 key that is merely plugged in yields `iaa3` and hardware presence, claiming a
touch that never happened. The fix is to make the unproven state impossible to
construct, tracked as one item with the individual defects under it.

Issues are tracked in-repo with [beads](https://github.com/gastownhall/beads) under
`.beads/`.

## Key Concepts

What the daemon is for. See [Status](#status) for what runs today.

- **SPIFFE Workload API** -- the daemon implements the standard gRPC Workload API (`FetchJWTSVID`, `FetchX509SVIDs`, `FetchJWTBundles`, `FetchX509Bundles`, `ValidateJWTSVID`). Any SPIFFE-aware consumer (envoy, ghostunnel, go-spiffe, rust-spiffe) works unmodified.
- **Per-audience pseudonymity** -- each consumer gets a stable HKDF-derived pseudonym instead of the user's root identity, so linking one user across consumers takes explicit consent. The derivation is written and checked against external test vectors, but issuance never calls it. Today every caller gets the root identity.
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
- **Socket (Linux):** `$XDG_RUNTIME_DIR/persona/workload.sock`, normally `/run/user/{uid}/persona/workload.sock`
- **Socket (macOS):** `<darwin-user-temp>/persona/workload.sock`, the per-user temp directory launchd also exports as `$TMPDIR`
- **Socket (Windows):** `\\.\pipe\persona-workload-{sid}`
- **Socket (fallback):** `/tmp/persona-{uid}/workload.sock` when the platform supplies no runtime directory
- **Browser bridge:** localhost HTTPS gateway on `127.0.0.1:2443` + native messaging host

The daemon implements the SPIFFE Workload API as-is. No new protocol is invented.

Consumer authentication uses OS-level process attestation (`SO_PEERCRED` on Linux, `SecCodeCopyGuestWithAttributes` on macOS, EXE signing on Windows) to identify calling applications and derive per-consumer pseudonyms. The Linux path is written but never called, so callers are not distinguished today.

## Identity Sources

Day-one attestor plugins. The assurance and presence columns are targets for once
`prove()` exists, not what the daemon substantiates today. See [Status](#status).

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
| Linux (systemd) | `personad.service` (user unit) | Full source support |
| Linux (non-systemd) | Init script or user session | Socket at `$XDG_RUNTIME_DIR/persona/workload.sock`, or `/tmp/persona-{uid}/workload.sock` if that is unset |
| macOS | LaunchAgent | TouchID via CryptoTokenKit |
| Windows | User-mode service | Windows Hello, named pipe transport |
| FreeBSD / OpenBSD | User session | SSH agent, GPG, Kerberos, PIV, FIDO2 |
| Containers | Bind-mount host socket | Inherits host identity |
| WSL2 | Native or bridged from Windows | AF_UNIX interop or native Tailscale |

Implementation is a single Rust binary with `#[cfg]` feature flags per platform.

## Installation

> `personad.service` starts the daemon, which binds its own socket. There is no
> socket-activation unit: the daemon does not read `LISTEN_FDS` yet, so a `.socket`
> unit would hand it a listener it ignores.

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

- [MOTIVATIONS.md](MOTIVATIONS.md) -- why this needs to exist at all
- [SPEC-HIA.md](SPEC-HIA.md) -- normative specification: SPIFFE ID schema, trust domains, assurance levels, prior art
- [DESIGN.md](DESIGN.md) -- technical design and architecture
- [PRFAQ.md](PRFAQ.md) -- press release and anticipated questions

## License

Two licenses apply, by file type:

- **Code** — Apache-2.0. All Rust sources, `Cargo.toml` manifests, build scripts,
  protobuf definitions, and service/config files. See [LICENSE](LICENSE).
  Each crate carries `license = "Apache-2.0"` in its manifest.
- **Documentation** — CC-BY-4.0. `MOTIVATIONS.md`, `SPEC-HIA.md`, `DESIGN.md`,
  `PRFAQ.md` and this README. See [LICENSE-CC-BY-4.0](LICENSE-CC-BY-4.0). Each carries an SPDX
  identifier on its first line.

`AGENTS.md` and `CLAUDE.md` are agent tooling instructions and fall under Apache-2.0
with the code.
