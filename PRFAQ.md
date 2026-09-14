<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# PRFAQ: personad — SPIFFE Identity for Humans

---

## Press Release

### personad Brings Zero Trust Identity to the Developer Desktop

**A user-session daemon that federates human identity sources behind the SPIFFE Workload API — the first FIPS-validated SPIRE-compatible agent.**

**Seattle, WA — June 13, 2026** — Today marks the release of personad, an open-source identity daemon that answers a question no existing tool addresses: "Who is the human at this keyboard, how confident are we, and is someone physically present right now?" personad federates heterogeneous identity sources — Tailscale, FIDO2, PIV smartcards, OIDC, SSH agent, GPG, and DIDs — behind the standard SPIFFE Workload API socket. Applications call `FetchJWTSVID` on a local Unix socket and receive a signed, short-lived identity credential. They never need to know which identity source backed the assertion.

Every desktop application that needs to know who the user is currently invents its own answer. A chat app reads Tailscale WhoIs. A terminal reads SSH keys. A browser extension reads a cached OIDC token. Each uses a different format, a different trust model, and a different level of assurance. personad eliminates this fragmentation by presenting all identity sources through SPIFFE — a CNCF standard already deployed in every major service mesh for workload identity. The API is not new; the attestation sources are. Any SPIFFE-aware consumer (Envoy, ghostunnel, spiffe-helper, or any application using go-spiffe, rust-spiffe, java-spiffe) works against personad without modification.

personad introduces three capabilities absent from every existing identity tool: per-consumer pseudonymity, hardware presence attestation, and multi-source federation. Each consumer application receives a stable but opaque pseudonym derived from the (app-identity, root-identity) pair — the Apple Sign-In-with-Apple model lifted into SPIFFE ID paths. Consumers cannot correlate identities across applications without explicit user consent. Hardware presence is attested via FIDO2 touch, Windows Hello, TouchID, or PIV PIN, with timestamped claims that decay on a fixed TTL. Identity sources from different trust domains — a work IdP, a personal DID, a Tailscale tailnet — coexist without conflation.

"SPIFFE solved workload identity. The same API shape solves human identity — same trust model, same consumer libraries, different attestation sources," said Mark Atwood, project lead. "personad is the identity leaf of a Zero Trust desktop stack. Every enforcement point downstream — SSH bouncer, mail gateway, sudo PAM module — depends on a standard local API that answers 'who is this human.' Without it, each one invents its own answer at varying quality."

The project runs on Linux (systemd and non-systemd), macOS, Windows, FreeBSD, and WSL2, with platform-specific attestor plugins that activate based on what hardware and software are available at startup. The first production consumer is kith, a Tailnet-native JMAP Chat system that uses personad to authenticate peers across trust domains without hardcoding any single identity provider.

---

## External FAQ

### How is personad different from SPIRE?

SPIRE answers "what process is this running in what context." personad answers "what human is at this keyboard and are they physically present." SPIRE attests workloads via kernel, container, and orchestrator signals. personad attests humans via Tailscale, FIDO2, PIV, OIDC, SSH agent, GPG, and DIDs. Both expose the same SPIFFE Workload API. They are complementary: a host can run both SPIRE (for service identity) and personad (for human identity), and applications consume both through identical client libraries.

### What identity sources does personad support?

Day-one sources: Tailscale (LocalAPI), Windows Hello (TPM-backed), macOS Secure Enclave (TouchID/FaceID), FIDO2 (USB/NFC via libfido2), PIV/CAC smartcards (PKCS#11), GNOME Online Accounts (DBus), cached OIDC tokens (gcloud, az, OS keychain), SSH agent, GPG agent, and DIDs (did:key, did:web, did:ipfs). Day-two sources include AWS SSO, gcloud, Azure CLI, Bitwarden, and Kerberos. personad probes for available sources at startup and activates what it finds. Missing sources are logged and skipped, never fatal.

### Do I need Tailscale to use personad?

No. Tailscale is one identity source among many. personad works with any combination of supported sources. A machine with only an SSH agent and a FIDO2 key produces valid SVIDs at assurance levels iaa1 (SSH, self-asserted) and iaa3 (FIDO2, hardware-bound). Tailscale provides iaa2-level identity (IdP-verified via Google/GitHub/OIDC) and is the most common source for tailnet-connected machines, but it is not required.

### What platforms does personad support?

Linux (systemd: Fedora, RHEL, Ubuntu, Debian; non-systemd: Gentoo, Void, Alpine), macOS, Windows, FreeBSD, OpenBSD, NetBSD, WSL2, and containers (via bind-mounted host socket). The consumer API is identical on every platform — applications call `FetchJWTSVID` on the SPIFFE Workload API socket and get back a signed credential regardless of which platform-specific attestor plugins produced it. A single Rust binary compiles per target with `#[cfg]` feature flags.

### How does per-consumer pseudonymity work?

By default, each consumer application receives a stable opaque pseudonym, not the user's root identity. The pseudonym is derived deterministically via HKDF-SHA256 from the (daemon pseudonym key, root identity, trust domain, consumer app identity) tuple. App A and App B each get a different identifier for the same user. Neither can derive the other's identifier, because the key is secret and never leaves the daemon. It is also never persisted, so pseudonyms are stable for the lifetime of the running daemon rather than across restarts. Cross-consumer linkage requires explicit user consent via `persona enroll`. This is the Apple Sign-In-with-Apple model applied at the OS level, not the browser level.

### Can I use personad without the full Zero Trust stack?

Yes. personad is useful standalone. Any application that calls the SPIFFE Workload API gets signed identity credentials. You do not need the SSH bouncer, the ZT control plane, or the IMAP gateway to benefit from personad. Those components consume personad's SVIDs, but personad produces them independently. A developer who installs personad on their laptop immediately gets `persona whoami`, `persona fetch-jwt`, and `persona prove` — useful for scripting, CLI authentication, and local development against SPIFFE-aware services.

---

## Internal FAQ

### Why SPIFFE and not a custom protocol?

SPIFFE is a CNCF standard with gRPC proto definitions, client libraries in Go, Java, Python, and Rust, and production deployment in every major service mesh. By implementing the standard Workload API, personad inherits the entire ecosystem. Any SPIFFE-aware consumer works unmodified. Any objection to the API is an objection to a CNCF standard, not to this project. A custom protocol would require writing client libraries, convincing every consumer to adopt them, and defending every design decision from scratch. SPIFFE makes all of that someone else's solved problem.

### Why Rust?

Two reasons. First, personad is a security-critical daemon running in user session scope on every developer workstation — memory safety is non-negotiable. Second, Rust compiles to a single static binary per platform with no runtime dependency, which simplifies distribution across Linux, macOS, Windows, and BSDs.

### How long will this take to build?

personad itself is 5-7 weeks of focused work. The full ZT desktop stack (SSH bouncer, control plane, IMAP gateway, sudo PAM module, device posture agent, Bitwarden integration) is 20-28 weeks total. personad must ship first because every downstream component depends on it. After personad and the minimal ZT control plane are stable, the SSH bouncer, IMAP gateway, and device posture agent can be developed concurrently.

### What is the hardest technical risk?

Consumer attestation — reliably identifying which application is calling the socket. On macOS, code signing and bundle IDs provide strong attestation. On Windows, EXE signing certificates and MSIX Package Family Names work. On Linux, the story is weaker: `SO_PEERCRED` gives pid/uid, `/proc/{pid}/exe` gives the binary path, and AppArmor/SELinux labels or Flatpak/Snap app IDs provide additional signal, but a native Linux binary without confinement is harder to attest reliably. The pseudonymity model degrades gracefully — a poorly-attested consumer gets a pseudonym keyed off its binary hash, which changes on every update — but the UX for re-enrolling apps after updates needs careful design.

### Why build personad before the SSH bouncer?

The SSH bouncer needs to validate identity credentials. Without personad, the bouncer would need to implement its own identity federation, presence attestation, and credential issuance — duplicating everything personad does. Building personad first means the SSH bouncer (and every other enforcement point) calls `FetchJWTSVID` on the persona socket and gets a signed credential. The bouncer validates the credential against the SPIFFE trust bundle. One identity daemon, many consumers. The alternative — each enforcement point implementing its own identity stack — is the fragmentation personad exists to eliminate.

### What if the SPIFFE community rejects the human-identity proposal?

personad ships regardless. The proposal is a two-page discussion document circulated to the SPIFFE TSC, not a gate on implementation. personad implements the existing SPIFFE Workload API without modifications — no spec changes are required. The proposal asks the community to acknowledge human identity as a valid use case and to consider desktop attestation selectors (binary hash, bundle ID, Flatpak app ID) alongside existing workload selectors. If the TSC says no, personad continues as a conformant but unofficial SPIFFE agent. The API compatibility means consumers work either way. Community endorsement would accelerate adoption; its absence does not block shipping.

---

> **What is a PRFAQ?** A PRFAQ (Press Release / FAQ) is an Amazon-originated product planning technique. It starts with a fictional press release written as if the product has already launched successfully, forcing clarity on customer benefit and desired outcome. The FAQ section then anticipates hard internal and external questions. Writing the press release first ensures the team aligns on what success looks like before committing to implementation.
