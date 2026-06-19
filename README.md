# personad -- Human Identity Agent

A user-session daemon that federates heterogeneous human-identity sources behind the standard SPIFFE Workload API socket. Applications call `FetchJWTSVID` on a local socket and receive a verifiable credential without caring whether identity came from Tailscale, FIDO2, PIV, OIDC, SSH agent, GPG, or DID. No new wire protocol -- just the CNCF-standard SPIFFE Workload API, extended to answer "who is the human at this keyboard, and are they present right now?"

## Why

There is no standard local API for "who is this human." Every application invents its own answer from whichever signals it happens to have access to -- the OS login session, a browser cookie, a Tailscale node, a cached OIDC token -- without a common format, provenance model, or consumer authentication discipline. SPIFFE/SPIRE solved this for workloads. `personad` solves it for humans.

## Key Concepts

- **SPIFFE Workload API** -- the daemon implements the standard gRPC Workload API (`FetchJWTSVID`, `FetchX509SVIDs`, `FetchJWTBundles`, `FetchX509Bundles`, `ValidateJWTSVID`). Any SPIFFE-aware consumer (envoy, ghostunnel, go-spiffe, rust-spiffe) works unmodified.
- **Per-audience pseudonymity** -- each consumer application receives a stable HKDF-derived pseudonym, not the user's root identity. Cross-consumer linkage requires explicit user consent.
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

The daemon implements the SPIFFE Workload API as-is. No new protocol is invented. Consumer authentication uses OS-level process attestation (`SO_PEERCRED` on Linux, `SecCodeCopyGuestWithAttributes` on macOS, EXE signing on Windows) to identify calling applications and derive per-consumer pseudonyms.

## Identity Sources

Day-one attestor plugins:

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

## Status

Design phase. See DESIGN.md for the full technical design.

## License

TBD

## Links

- [DESIGN.md](DESIGN.md) -- full technical design document
- [PRFAQ.md](PRFAQ.md) -- press release and FAQ
