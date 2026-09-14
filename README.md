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
| Attestor registry, startup probing, `enumerate()` | works for most sources; returns candidates, not claims |
| CLI (`whoami`, `enumerate`, `fetch-jwt`, ...) | works |
| `prove()` -- cryptographic proof of possession | **not implemented in any attestor** -- so no SVID is issued on any platform |
| Identity assurance levels | derived from evidence -- see below |
| Presence levels | enforced across every audience, and unknown requirements are refused rather than ignored |
| Per-consumer pseudonyms | wired into issuance -- every caller receives a pseudonym, never the root identity |
| Consumer attestation | attested once per connection; a caller that cannot be attested is refused |
| Trust bundle / `ValidateJWTSVID` | works -- publishes a real JWKS, and validation reads only that bundle; an external verifier holding the bundle and nothing else is part of the test suite |
| X.509-SVID, browser HTTPS gateway | stubs |

The cause was structural. `enumerate()` returned the same `Claim` type `prove()`
produces, so a discovery call could return an assurance level nothing established. A
FIDO2 key that was merely plugged in yielded `iaa3` and hardware presence, claiming a
touch that never happened.

`enumerate()` now returns a `Candidate`, which carries no assurance and no presence.
A `Claim` has private fields and one constructor, `Claim::derive(candidate, evidence)`,
whose signature takes no level: the tier is read off the evidence variants. No evidence
means no claim, so the daemon declines instead of asserting. Because no attestor
implements `prove()` yet, that is what happens everywhere today -- `personad` finds
candidates, cannot prove any of them, and answers `UNAUTHENTICATED` with
`no identity claims available`. The first prover to land will be ssh-agent
`SSH2_AGENTC_SIGN_REQUEST`, which earns the floor tier.

Issues are tracked in-repo with [beads](https://github.com/gastownhall/beads) under
`.beads/`.

## Key Concepts

What the daemon is for. See [Status](#status) for what runs today.

- **SPIFFE Workload API** -- the daemon implements the standard gRPC Workload API (`FetchJWTSVID`, `FetchX509SVIDs`, `FetchJWTBundles`, `FetchX509Bundles`, `ValidateJWTSVID`). Any SPIFFE-aware consumer (envoy, ghostunnel, go-spiffe, rust-spiffe) works unmodified.
- **Per-consumer pseudonymity** -- each consumer gets an HKDF-derived pseudonym instead of the user's root identity, so linking one user across consumers takes explicit consent. The pseudonym is stable for the lifetime of the running daemon: the key is generated at start and never persisted, so pseudonyms rotate when personad restarts, as the ephemeral signing key already does. Keyed on the calling application, never on the audience -- one consumer gets one pseudonym across every audience it requests.
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

Consumer authentication uses OS-level process attestation to identify calling applications and derive per-consumer pseudonyms. The peer's credentials are read when the connection is accepted, and the consumer is the SHA-256 of its main executable -- `/proc/{pid}/exe` on Linux, `proc_pidpath` on macOS. A caller that cannot be attested receives no SVID; there is no unattested fallback, because a pid-keyed identity changes on every launch and a uid-keyed one is shared by everything the user runs. Richer signing identities (`SecCodeCopyGuestWithAttributes` on macOS, EXE signing on Windows) are not implemented.

This buys unlinkability against honest-but-curious consumers. It is not authentication against a local adversary: a malicious same-uid process can exec the victim's binary, and pids are reusable. It also makes the *identifier* unlinkable, not the whole token -- `persona_ext` still carries `root_trust_domain`, `sources`, `auth_methods` and a raw-second `attested_at`, which two colluding consumers served in the same window can still join on.

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

# Install the user unit
persona install-service

# Enable and start
systemctl --user enable --now personad

# Verify
persona whoami
```

Logs go to the journal: `journalctl --user -u personad -f`.

### launchd (macOS)

```bash
cargo install --path personad
persona install-service
launchctl load ~/Library/LaunchAgents/personad.plist
persona whoami
```

`launchd/personad.plist` in this repo is a template, not a working file. launchd
expands nothing -- no `~`, no `$HOME`, no systemd-style specifiers -- so
`persona install-service` substitutes your home directory and writes the result.
Copying the template into place unedited will not work.

Logs go to `~/Library/Logs/personad.log`.

Redirection is required rather than a convenience. An agent with no
`StandardOutPath` has its output discarded: on macOS 26.6.2 a test agent ran to
completion and produced no unified-log entries for anything it printed. `~/Library`
is mode 0700, so the file is unreadable by other local users even though launchd
creates it 0644.

Do not move it to `/tmp`. The daemon logs SPIFFE IDs, attestor sources and assurance
levels, and a predictable name in a world-writable directory can be pre-created by
another local user.

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
