<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# SPEC-HIRE: Human Identity Runtime Environment (hired)

**Status:** Draft
**Last updated:** 2026-09-14

> This document absorbed `DESIGN.md`, which had been a reworded copy of the same
> content. Sections describing delivery — the Zero Trust stack components, the build
> order, the coverage map — are context rather than normative requirements, and would
> be dropped from any version submitted to a standards body.

---

## Problem

SPIFFE/SPIRE solves workload identity: a daemon on the host that attests "this process is service X running in context Y" and issues short-lived cryptographic credentials. Applications call the Workload API on a local socket and get an SVID. No passwords, no long-lived secrets, no out-of-band enrollment.

There is no equivalent for human users.

The question "who is the person operating this workstation, and how confident are we that they are physically present right now?" has no standard local API answer. Every application invents its own answer from whichever signals it happens to have access to — the OS login session, a browser cookie, a Tailscale node, a cached OIDC token — without a common format, provenance model, or consumer authentication discipline.

**SPIFFE/SPIRE for humans** is the missing piece: a user-session daemon that federates heterogeneous human-identity sources behind the existing SPIFFE Workload API socket. Apps stop caring whether the user's identity comes from Tailscale, Windows Hello, a work IdP, a DID, or a PIV smartcard. They call `FetchJWTSVID` on the local socket, they get a verifiable credential, and they can reason about provenance and assurance without knowing anything about the source.

### Why SPIFFE is the right shape (not just an analogy)

Every SPIFFE component maps directly to something the human-identity problem already needs:

| SPIFFE concept | Human identity meaning |
|---|---|
| Trust domain | Identity source (tailnet, work IdP, personal DID, ...) |
| SPIFFE ID URI | Structured, provenance-carrying identifier |
| Workload API socket | Single local socket for all consumers |
| X.509-SVID | mTLS identity (walk into a service mesh) |
| JWT-SVID | HTTP bearer (OIDC-shaped, works with any RP) |
| Workload attestation | App attestation: who is asking, and what is it allowed to see |
| Trust bundle distribution | How federated trust roots are published |
| SVID rotation | Short-lived assertions, automatic refresh |

Nothing in this design requires changes to the SPIFFE spec. The SPIFFE Workload API is implemented as-is; only the attestor plugins are new.

This is a deliberate strategic choice. By presenting the standard SPIFFE Workload API — a CNCF standard with gRPC proto definitions, client libraries in Go/Java/Python/Rust, and production deployment in every major service mesh — `hired` inherits the entire SPIFFE ecosystem. Any SPIFFE-aware consumer works unmodified, and a platform that wants a different answer can implement the same API itself.

---

## Daemon: `hired`

**CLI:** `hire`
**Socket (Linux):** `$XDG_RUNTIME_DIR/hire/workload.sock`, normally `/run/user/{uid}/hire/workload.sock` (gRPC, SPIFFE Workload API)
**Socket (macOS):** `<darwin-user-temp>/hire/workload.sock`, the per-user temp directory launchd also exports as `$TMPDIR`
**Socket (Windows):** Named pipe `\\.\pipe\hire-workload-{sid}`
**Localhost HTTP gateway:** `127.0.0.1:2443` (for browser native-messaging bridge)
**User systemd unit (Linux):** `hired.service`
**LaunchAgent (macOS):** `hired` (`~/Library/LaunchAgents/hired.plist`)
**Windows user-mode service:** `HireIdentityAgent`

Storage: nothing persistent that isn't already persistent in the underlying source. `hired` is a normaliser, not a vault. Any data it caches is wiped on session end.

Network: `hired` may make outbound network connections. Several sources are defined by network resolution and have no local substitute: `did:web` resolves a DID document over HTTPS, verifying an OIDC token means fetching the issuer's JWKS, and SPIFFE Federation syncs trust bundles between hosts. Where a source can reach its data through a local daemon that already does the fetching it still should -- the Tailscale attestor speaks the LocalAPI over `/var/run/tailscale/tailscaled.sock` rather than calling the coordination server itself -- but that is an efficiency, not a boundary. A name `hired` resolves generally arrives from local input it does not control, so it is untrusted input and is treated as such.

---

## SPIFFE ID Schema for Human Identity

### Provenance in the URI

SPIFFE IDs encode the identity source in the path, making provenance explicit and machine-readable:

```
spiffe://{trust-domain}/user/{sub}/via/{source}
```

Examples:
```
spiffe://example.com/user/mark/via/google-workspace
spiffe://tailscale/user/mark@example.com/node/heft
spiffe://personal.atwood/identity/mark/attested-by/onlykey
spiffe://example.com/user/mark/via/piv-smartcard
```

A consumer that accepts `spiffe://example.com/**` is trusting the example.com trust domain (backed by example.com's Google Workspace). A consumer that additionally accepts `spiffe://tailscale/**` is widening its trust to include Tailscale-network identity. Each trust domain is independent.

### Pseudonymous IDs (per-consumer)

The default SPIFFE ID exposed to a consumer is **not** the root identity. It is a stable opaque pseudonym derived deterministically from the (consumer-app-identity, root-identity) pair:

```
spiffe://{trust-domain}/pseudonym/{hkdf-derived-opaque-id}
```

There is deliberately no `for/{consumer-app-id}` tail. The opaque id is already per-consumer, so the tail would tell the consumer only what it already knows, while telling every relying party the token is shown to which application asked for it.

The consumer gets a stable identifier that it can correlate with this user, but cannot correlate with any other consumer's identifier. Linkability across consumers requires explicit user consent. This is Apple's Sign-In-with-Apple model lifted into the SPIFFE ID path.

Stability is for the lifetime of the running daemon, not across restarts: the pseudonym key is generated at start and never persisted, so a consumer cannot recognise the same user after hired restarts. The ephemeral ES256 signing key already invalidates every issued SVID on restart. Unlinkability is the privacy guarantee and it survives a restart; cross-restart stability is a consumer convenience and does not. Persisting the key needs somewhere to persist it, and nothing here writes to disk until enrollment is implemented.

The derivation is keyed on the consumer application only, never on the JWT `aud`. One consumer therefore gets one pseudonym across every audience it ever requests.

The pseudonym is derived via HKDF:
```
pseudonym = HKDF-SHA256(
    ikm  = pseudonym_key || root_spiffe_uri,
    salt = trust_domain,
    info = consumer_selector_key
)
```

`pseudonym_key` is 32 random bytes generated at daemon start and never persisted.
It is the reason this is pseudonymity rather than obfuscation: every other input is
public, and HKDF over public inputs lets any consumer recompute every other
consumer's pseudonym offline. Because the key is ephemeral, pseudonyms are stable
for the life of a daemon process and change across restarts.

The pseudonym is keyed on the consumer, not the audience. One consumer receives the
same pseudonym for every audience it requests.

Correlation that remains. The `attested_at` change made this worse, not better. On a single-identity
daemon `root_trust_domain`, `sources` and `auth_methods` are constants shared by
every consumer, so a colluding pair can link on those alone. `attested_at` is
now derived from the observation rather than from the request clock, which means
two consumers served from one observation receive a byte-identical value that
stays constant for the whole presence window, rather than two different integers
a second apart. That is a stronger and longer-lived join key than before, and it
is published deliberately: withholding it would leave a consumer unable to judge
freshness for itself and forced to trust a TTL it cannot check. Whole seconds is
the floor: a JWT consumer has no use for sub-second resolution, and every extra
bit of precision is another bit two colluding consumers can join on.
`present_until` is `attested_at` plus a public constant, so it adds no bits of
its own. Two colluding consumers still cannot recover the root
identity. Narrowing the three unconditional fields is tracked separately.

Every `FetchJWTSVID` call derives the calling consumer's pseudonym. A consumer that cannot be attested is refused outright rather than served a weaker identity. A consumer with elevated scope (granted by the user at enrollment) can request the full-provenance ID; that path is not implemented and is gated on enrollment.

---

## Trust Domain Model

Each identity source on the desktop publishes into a different trust domain. `hired` maintains a trust bundle for each:

| Trust domain | Backing authority | Verification |
|---|---|---|
| `tailscale` | Tailscale coordination server | Tailscale LocalAPI `Status`; node keypair |
| `{org}.com` | Org's OIDC/SAML IdP | OIDC ID token; JWKS from IdP |
| `personal.{user}` | User's DID document | `did:key`, `did:ipfs`, or `did:web` resolution |
| `piv.{issuer}` | PIV/CAC certificate chain | Certificate path validation to issuing CA |
| `ssh.local` | SSH agent (locally trusted) | Agent-signed challenge; weak assurance |
| `pgp.local` | GPG key | Signed challenge; assurance depends on key custody |

SPIFFE Federation handles cross-domain trust bundle distribution for any of these that need to be accepted by remote relying parties.

---

## Sources (Attestor Plugins)

Each source implements a plugin interface: `enumerate()`, `prove(candidate, challenge)`, `freshness(candidate)`. `enumerate()` returns candidates, which carry no assurance and no presence; those come only from the evidence `prove()` returns. Sources are loaded at startup based on what is available on the platform.

### Day-One Sources

**tailscale**
- Method: LocalAPI on `/var/run/tailscale/tailscaled.sock`
- Returns: `UserProfile.LoginName` (email), display name, node name, tailnet
- Assurance: `iaa2` — verified by Tailscale's IdP (Google/GitHub/OIDC)
- Presence: none (network identity, not physical presence)
- Notes: tailscaled must be running; automatic re-attest on `tailscale status` change

**windows-hello** (Windows)
- Method: `Windows.Security.Credentials.KeyCredentialManager`
- Returns: TPM-backed attestation that the user authenticated with Hello (PIN or biometric) and when
- Assurance: `iaa3`, presence: `hardware`
- Notes: presence expires on configurable TTL; re-challenge triggers Hello prompt

**secure-enclave** (macOS)
- Method: `LocalAuthentication` + `CryptoTokenKit`; TouchID or Face ID as platform FIDO2 authenticator
- Returns: Secure Enclave-backed assertion with timestamp
- Assurance: `iaa3`, presence: `hardware`

**fido2** (Linux, cross-platform)
- Method: `libfido2`; USB/NFC hardware authenticator
- Returns: authenticator data including UP bit, timestamp
- Assurance: `iaa3`, presence: `hardware`
- Notes: UP bit proves physical touch; UV bit (biometric on the key itself) optionally required

**piv-smartcard** (cross-platform)
- Method: PKCS#11 via standard slot; PIV/CAC/YubiKey PIV application
- Returns: X.509 certificate (may include UPN, email, DOD EDIPI); signed challenge
- Assurance: `iaa3` if card is hardware-bound and PIN is required; presence depends on PIN mode

**gnome-online-accounts** (Linux/GNOME)
- Method: DBus `org.gnome.OnlineAccounts`
- Returns: Google/Microsoft/Nextcloud OIDC tokens for the primary GNOME account
- Assurance: `iaa2`; presence: `session` (token may be stale)

**oidc-cached**
- Method: OIDC ID token from OS keychain (stored by prior browser login, `gcloud`, `az`, etc.)
- Returns: `sub`, `email`, `iss`, `exp` from cached token
- Assurance: `iaa2` if token is non-expired; `iaa1` if expired (identity only, unverified freshness)
- Notes: staleness is explicit in the claim; the token is not refreshed on behalf of the consumer

**ssh-agent**
- Method: SSH agent protocol via `SSH_AUTH_SOCK`; sign a challenge with each key in the agent
- Returns: public key fingerprint; signed challenge
- Assurance: `iaa1` (self-asserted; key custody is assumed)
- Notes: useful for developer tooling that trusts SSH keys

**gpg**
- Method: `gpg-agent` via its socket; sign a challenge with the primary key
- Returns: fingerprint, UID(s), signed challenge
- Assurance: `iaa1` (self-asserted)

**did-self** (`did:key`, `did:ipfs`, `did:web`)
- Method: resolve DID document; sign challenge with controlled key
- Returns: DID, verification method, signed assertion
- Assurance: `iaa1` for `did:key` (self-issued); `iaa2` for `did:web` if the DID document is hosted under a domain the user controls

**unix-account** (Linux, macOS, BSD)
- Method: `getuid()` for the account, `getpwuid_r` for its name; no agent, no socket, no network
- Returns: uid, username
- Assurance: `iaa1` (self-asserted; the kernel names the account a process runs under, and nothing checks who holds it)
- Presence: none (an account is not a seat — a uid says a process is running, not that a human is logged in)
- Notes: available whenever the operating system is, so this is the one source that never degrades away and a Unix box always issues. The consumer gets the answer `getuid()` would have given it, plus provenance, a pseudonym and audience binding; a consumer that reads "holds a credential" as "is authenticated" gets a weaker answer than it did when the daemon declined, and has to read the assurance field instead. It publishes into `ssh.local` rather than a domain of its own, because `hired` seeds no bundle for a domain the table above does not list and an unseeded domain fails `ValidateJWTSVID`.

### Day-Two Sources

**aws-sso** — active `aws sso login` session in `~/.aws/sso/cache`
**gcloud** — `gcloud auth print-identity-token` for the active account
**az** — `az account get-access-token` for the active subscription
**bitwarden** — unlocked Bitwarden vault's identity item (requires Bitwarden CLI unlock)
**kerberos** — valid TGT from `klist`; Kerberos principal as identity claim

### Explicitly Out of Scope (v1)

Browser cookie jars — per-origin OIDC session extraction from a live browser. High privacy sensitivity; enumeration model is not well-defined. Deferred to v2; bridge via native messaging instead.

---

## Consumer Authentication (App Attestation)

If any process in the user session can call the socket without identification, then malware can enumerate the user's identities. The solution is per-consumer pseudonymity keyed off verified app identity.

On each `FetchJWTSVID` or `FetchX509SVID` call, `hired` attests the calling process and derives the pseudonym for that consumer. The user never sees a global identifier leave the daemon; each consumer gets its own.

| Platform | Attestation mechanism | Consumer ID |
|---|---|---|
| Linux | `SO_PEERCRED` (uid/pid) → `/proc/{pid}/exe` → binary hash → AppArmor/SELinux label → Flatpak/Snap app ID | Binary hash or app ID |
| macOS | `getpeereid` + `LOCAL_PEEREPID` (uid/pid) → `proc_pidpath` → binary hash | Binary hash |
| macOS (planned) | `LOCAL_PEERTOKEN` → `audit_token_t` → `SecCodeCopyGuestWithAttributes` → signing identity | Bundle ID + Team ID |
| Windows | `GetNamedPipeClientProcessId` → EXE signing certificate → MSIX Package Family Name | Package Family Name or EXE signer |
| Browser (native messaging) | Chrome/Firefox native messaging — origin-bound; the declaring manifest extension specifies allowed origins | Extension ID + origin |

The SPIFFE selector model (`unix:uid`, `unix:path`, `unix:sha256`, `k8s:ns`, ...) is extended with desktop selectors:

```
binary_sha256:abc123...
macos:bundle_id:com.notion.Notion
macos:team_id:ABCD1234
flatpak:app:com.obsidian.Obsidian
snap:name:obsidian
msix:publisher:CN=Notion...
chrome_extension:id:abc123...
```

These selectors drive the SPIFFE Server-style workload registration. The user runs `hire enroll app` to interactively authorize a new consumer app.

---

## Browser Bridge

Browsers cannot connect to a Unix socket from JavaScript. Three strategies, in deployment order:

**1. Native messaging host (ship first)**
A small native binary registered with Chrome/Firefox as a native messaging host. The extension (or a manifest-declared web origin) communicates with the binary via stdin/stdout; the binary forwards to the `hired` socket. The native messaging host is the consumer from `hired`'s perspective; the extension/origin is the consumer from the pseudonymity perspective (mapped via `chrome_extension:id` selector).

**2. Localhost HTTPS gateway (127.0.0.1:2443)**
`hired` binds a localhost HTTPS server with a self-signed cert installed in the user trust store at first run. Consumers are identified by the `Origin` header, which is verified against an allowlist managed by `hire enroll origin`. This works without a browser extension but requires the user to approve the cert once.

**3. FedCM IdP registration (future)**
Register `hired` as a FedCM identity provider. The browser handles the trust UI; web pages call the FedCM API without a custom extension. Timeline: months to years, depending on how fast FedCM standardises.

---

## API

`hired` implements the SPIFFE Workload API (gRPC, proto definitions from `github.com/spiffe/spiffe/proto/spiffe/workload`):

- `FetchX509SVIDs` — streaming; returns X.509-SVIDs, refreshes before expiry
- `FetchX509Bundles` — trust bundles for all active trust domains
- `FetchJWTSVID` — returns JWT-SVID for a given audience; triggers presence challenge if `hire_require_presence` is set in the audience claim
- `FetchJWTBundles` — JWKS endpoints for all trust domains
- `ValidateJWTSVID` — validates a JWT-SVID against the trust bundle

No new wire protocol is invented. Any SPIFFE-aware consumer (envoy, ghostunnel, spiffe-helper, go-spiffe, rust-spiffe, java-spiffe) works against `hired` out of the box.

### Presence extension

The `audience` string in `FetchJWTSVID` carries optional structured extensions:

```
audience = "https://example.com?hire_require_presence=hardware"
```

A request may carry several audiences, each with its own extensions. The request
is gated on the strictest `hire_require_presence` named by any of them, so an
audience naming no requirement can never relax one another audience named. The
issued token's `aud` claim carries the audience URLs with `hire_` parameters
removed.

The `hire_` query-parameter namespace is reserved and closed: a `hire_`
parameter `hired` does not implement is rejected with `INVALID_ARGUMENT`
rather than ignored.

`hire_max_age=<seconds>` bounds the age of the observation behind the claim.
A claim is served only if its observation is *strictly younger* than the bound,
so `hire_max_age=0` accepts nothing; a non-integer, negative or overflowing
value is `INVALID_ARGUMENT`, never a default. A repeat within one audience takes
the smallest, and across audiences the daemon takes the smallest any of them
names — for an age bound the strictest is the least, the mirror of
`hire_require_presence` and its strictest-wins maximum. Because the bound is
folded with a minimum and an audience naming no bound contributes nothing, no
audience an attacker appends can relax a bound another audience named.

Independently of any caller bound, `hired` applies a fixed daemon-wide
presence TTL of 300 seconds to the observation. Past it the claim asserts no
presence at all, so it stops satisfying `hire_require_presence` — the decay
runs through the ordinary presence gate rather than through a second refusal
path.

If presence requirements are not met, `hired` triggers a presence challenge (FIDO2 touch prompt, Hello dialog, etc.) before issuing the SVID. If the challenge cannot be satisfied within the timeout, the RPC returns `UNAUTHENTICATED`.

### CLI (hire)

```
hire whoami                           # print current identity summary
hire enumerate                        # list all candidate identities with source and SPIFFE ID
hire disclose --audience X            # show which claims would be disclosed to audience X
hire fetch-jwt --audience X           # fetch JWT-SVID for audience X (calls FetchJWTSVID)
hire fetch-x509                       # fetch X.509-SVID bundle (calls FetchX509SVIDs)
hire prove --audience X --challenge N # produce signed assertion for nonce N
hire watch                            # stream claim add/remove/refresh events
hire enroll app                       # authorize a new consumer app
hire enroll origin URL                # authorize a browser origin
hire log                              # view audit log of disclosures and prove calls
hire trust-bundle add spiffe://x/     # import a remote trust bundle
```

---

## HVID Extension (Human Verifiable Identity Document)

The JWT-SVID payload carries standard SPIFFE claims plus a `hire` extension object:

```json
{
  "sub": "spiffe://example.com/pseudonym/3f1a7b...",
  "aud": ["https://example.com"],
  "exp": 1746000000,
  "iat": 1745999700,
  "spiffe_id": "spiffe://example.com/pseudonym/3f1a7b...",
  "hire": {
    "root_trust_domain": "example.com",
    "sources": ["tailscale", "piv-smartcard"],
    "identity_assurance": "iaa3",
    "presence": {
      "present": true,
      "attested_by": "fido2_up",
      "attested_at": 1745999640,
      "present_until": 1745999940
    },
    "auth_methods": ["tailscale_oidc", "fido2_up"]
  }
}
```

The `hire` extension is non-standard but ignorable by consumers that do not understand it. The `sub`/`aud`/`exp`/`spiffe_id` fields are standard SPIFFE JWT-SVID fields.

---

## Assurance Levels

### Identity assurance (`identity_assurance`)

| Level | Meaning |
|---|---|
| `iaa1` | Self-asserted (SSH key, GPG key, did:key, local username) |
| `iaa2` | IdP-verified (Tailscale OIDC, GNOME Online Accounts, cached OIDC token) |
| `iaa3` | Hardware-bound + IdP-verified (Tailscale + FIDO2, PIV smartcard, Windows Hello) |

### Presence assurance (`presence_level`)

| Level | Meaning |
|---|---|
| `none` | No presence assertion |
| `session` | Screen was unlocked by the user at session start; no recent confirmation |
| `software` | Software authenticator (TOTP, password re-entry); weak recency |
| `hardware` | FIDO2 UP, Windows Hello, TouchID/Face ID, PIV PIN — timestamped, hardware-backed |

---

## SPIFFE Community Proposal

Before code, this design should be circulated to the SPIFFE TSC as a two-page discussion document: "Personal SVID — extending SPIFFE Workload API to human identity on the desktop." The SPIFFE community scoped the project to workloads as a deployable beachhead, not because they thought workloads were the only use case. The desktop agent is the natural completion.

Sections of that proposal:
1. Trust domain model for heterogeneous human identity sources
2. Attestor plugin list (maps to existing SPIRE server attestor API)
3. Per-RP pseudonymity via deterministic SPIFFE ID derivation
4. App-attestation selectors per OS
5. Browser bridge (native messaging, FedCM roadmap)

Contacts: Evan Gilman (original SPIFFE/SPIRE author), SPIFFE Technical Steering Committee, CNCF TAG Security.

---

## Position in the Zero Trust Desktop Stack

`hired` is the **identity leaf** of a Zero Trust desktop framework — roughly 20–25% of the total system. It is the necessary foundation: every other component depends on having a standard local API that answers "who is this human and are they present." Without `hired`, each enforcement point invents its own identity answer at varying quality.

The full ZT desktop stack has six distinct layers. `hired` owns one of them.

```
┌──────────────────────────────────────────────────────────────────┐
│  External Services                                               │
│  (SaaS, 3P apps, external email — reached via password manager)  │
└──────────────────────────────────────────────────────────────────┘
                              ▲
┌──────────────────────────────────────────────────────────────────┐
│  Enforcement Points                                              │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────┐  ┌──────────┐  │
│  │ SSH Bouncer │  │ IMAP/SMTP GW │  │ API      │  │ ZT sudo  │  │
│  │             │  │              │  │ Proxy    │  │ PAM      │  │
│  └──────┬──────┘  └──────┬───────┘  └────┬─────┘  └────┬─────┘  │
└─────────┼────────────────┼───────────────┼──────────────┼────────┘
          │                │               │              │
          └────────────────┴───────────────┴──────────────┘
                                    │ validate grant / cert
┌──────────────────────────────────────────────────────────────────┐
│  ZT Control Plane                                                │
│  (OPA policy engine + credential minting + audit log)            │
│                                                                  │
│  input: hired JWT-SVID + device posture                       │
│  output: delegation grants, SSH certs, OAuth tokens, mTLS certs  │
└──────────────────────────┬───────────────────────────────────────┘
                           │ FetchJWTSVID
┌──────────────────────────▼───────────────────────────────────────┐
│  hired  (this spec)                                           │
│  SPIFFE Workload API — human identity + presence                 │
└──────────────────────────┬───────────────────────────────────────┘
                           │ identity + presence sources
         ┌─────────────────┼──────────────────────┐
    Tailscale         FIDO2 / Hello           SSH agent
    OIDC/IdP          TouchID / PIV           GPG / DID / GOA
┌──────────────────────────────────────────────────────────────────┐
│  Device Posture Agent                                            │
│  (separate input to ZT control plane — not part of hired)     │
│  disk encryption, patch level, MDM enrollment, binary integrity  │
└──────────────────────────────────────────────────────────────────┘
┌──────────────────────────────────────────────────────────────────┐
│  Desktop Login (PAM / Windows Credential Provider)               │
│  NIST SP 800-63B r4 + FIDO2-rooted; hired starts at login     │
└──────────────────────────────────────────────────────────────────┘
```

### Coverage Map

| ZT Primitive | Who owns it | State |
|---|---|---|
| Human identity + presence | `hired` | **this spec** |
| Workload identity | SPIFFE/SPIRE | exists |
| Policy engine | OPA | exists |
| Credential minting (SSH CA, delegation broker) | ZT control plane | **gap — to build** |
| SSH bouncer | SSH enforcement point | **gap — to build; hardest piece** |
| IMAP/SMTP gateway | Mail enforcement point | **gap — to build** |
| API proxy (HTTP/gRPC) | Envoy + OPA ext-authz | mostly exists; integration needed |
| ZT sudo | PAM module | **gap — to build** |
| Device posture | partial (various MDM tools) | **gap — no clean open-source** |
| Password manager (external sites) | Bitwarden (open source) | exists; ZT integration needed |
| Desktop login (FIDO2-rooted) | PAM config + FIDO2 PAM module | mostly exists; policy config needed |

---

### Component 1: ZT Control Plane

The policy decision point sitting above `hired`. It consumes the `hired` JWT-SVID plus a device posture report and evaluates them against OPA policy to determine what credentials the user may receive.

**Inputs:**
- `hired` JWT-SVID (identity + presence assurance + auth methods)
- Device posture report (patch level, disk encryption state, MDM enrollment, binary integrity)
- Resource request (what the user or delegated software is trying to access)

**Outputs:**
- Signed delegation grants (for IMAP, SMTP, database, API access)
- Short-lived SSH certificates
- Short-lived OAuth2 tokens (for internal applications)
- Short-lived mTLS client certificates (for service mesh access)

**What exists:** OPA is the policy engine and is production-grade. The gap is the credential-minting glue layer: a small service that accepts `(hired SVID + device posture + resource request)`, evaluates against OPA, and calls the appropriate CA or token issuer. This is the smallest of the missing components — probably 2–3 weeks of Rust work.

**OPA policy example:**
```rego
allow_ssh_cert {
    input.identity.presence_level == "hardware"
    input.identity.identity_assurance == "iaa2"
    input.device.disk_encrypted == true
    input.device.patch_age_days < 30
    input.resource.host_group == "engineering"
}
```

---

### Component 2: SSH Bouncer

**This is the hardest and most important gap.** SSH is where most Zero Trust deployments stop enforcing anything. The network perimeter moves, the SSH keys stay static on disk, and nothing about the user's presence is checked at connection time. There is no open-source ZT SSH solution that is FIDO2-rooted, presence-enforced, and policy-driven per connection.

The architecture:
```
User workstation
    ↓ SSH (with ephemeral cert signed by ZT CA)
SSH Bouncer (policy enforcement point)
    ↓ validates cert against ZT trust bundle
    ↓ calls OPA: is this cert + user + target + time allowed?
    ↓ enforces command allowlist
    ↓ records session
Target host
    ↓ accepts cert from ZT SSH CA only; direct SSH disabled
```

**What the bouncer must do:**
- Terminate SSH (speak the SSH wire protocol as both client and server)
- Validate the ephemeral cert against the ZT CA trust bundle
- Call OPA per connection (not per network location)
- Enforce scope from the cert: which principals, which hosts, which commands
- Reject connections whose cert has expired (10-minute TTL means staleness is bounded)
- Record sessions: keystrokes, commands, timing, identity binding
- Refuse any SSH connection not carrying a valid ZT-issued cert

**Why FIDO2 presence matters for SSH specifically:** SSH is dangerous because it enables unattended lateral movement. A static SSH key can be used by malware silently. An ephemeral cert whose issuance required FIDO2 touch proves a human was at the keyboard at session initiation. Malware cannot touch a hardware key, so it cannot get a cert, so it cannot SSH.

**Scope:**
- Command-level enforcement: `hire delegate ssh --commands "git,make,kubectl"` produces a cert whose extensions encode the allowed command set. The bouncer enforces this, not just logs it.
- `sudo` escalation on the target can require a new cert with elevated scope — another FIDO2 touch.
- CI/CD service accounts use SPIFFE workload SVIDs (not `hired`) — separate identity, separate cert path, no FIDO2 required, but also no human-presence claim.

**Build complexity:** similar to `hired`. A distinct Rust project, 4–6 weeks. The SSH wire protocol is the hardest part; `thrussh` or `russh` crate provides a base.

---

### Component 3: IMAP/SMTP Gateway

Covered in detail in the Delegated Access section. The gateway speaks real IMAP and SMTP, validates `hired`-issued delegation grants (grant + client key + scope + TTL), and enforces send-as identity on SMTP.

**Key constraint:** unmodified open-source IMAP/SMTP clients (`mutt`, `notmuch`, `isync`, `msmtp`) must work against the gateway without modification. The gateway is a transparent protocol proxy from the client's perspective.

**Build complexity:** 3–4 weeks. Dovecot plugin path is the fastest; standalone Rust proxy is cleaner but more work.

---

### Component 4: ZT sudo PAM Module

A PAM module that, instead of asking for a password on `sudo`, calls `hired` requiring `hardware` presence (`hire_require_presence=hardware`). If presence is satisfied, `sudo` proceeds. If not, it triggers a FIDO2 touch challenge.

Policy (from OPA, via the ZT control plane) determines which commands require hardware presence and which allow a stale session-level presence claim.

```
$ sudo systemctl restart nginx
[hire] touch your security key... ✓
[sudo] running as root: systemctl restart nginx
```

**Build complexity:** 1–2 weeks. The PAM module interface is small; the complexity is in wiring the async FIDO2 challenge into a synchronous PAM flow (blocking call with timeout).

---

### Component 5: Device Posture Agent

A separate daemon (not `hired`) that reports device health to the ZT control plane:
- Disk encryption state (LUKS/FileVault/BitLocker)
- Patch currency (days since last security update)
- MDM enrollment status
- Running process integrity (optional)
- Hardware security capability (TPM present, Secure Boot enabled)

The ZT control plane combines the device posture report with the `hired` SVID when evaluating policy. A user with `iaa3` identity but an unpatched device may be denied high-privilege credentials.

**What exists:** various MDM agents, Osquery. The gap is a clean open-source device posture agent that speaks a standard format to the ZT control plane and does not require a vendor MDM subscription. This is 2–3 weeks of Rust work but requires per-platform implementation (Linux, macOS, Windows each have different APIs for encryption state, patch level, etc.).

---

### Component 6: Password Manager Integration (External Sites)

The policy requires that external site authentication uses the company-managed password manager (Bitwarden) integrated with the ZT framework. In practice this means:

- Bitwarden CLI authenticates using `hired` (`hire fetch-jwt --audience bitwarden.example.com`) rather than a master password
- Bitwarden populates credentials into the browser
- External sites use Passkey > FIDO2 > TOTP > password (in that preference order)
- The ZT control plane can see which external services are being accessed (via Bitwarden audit log integration) for policy enforcement

Bitwarden is open source (AGPL); the integration is a Bitwarden CLI plugin / SDK extension, not a fork. The `hired` JWT-SVID acts as the Bitwarden vault unlock credential.

**Build complexity:** 1–2 weeks for the Bitwarden CLI plugin. The main work is Bitwarden's SDK API for custom unlock mechanisms.

---

### Build Order

`hired` is the right starting point because every other component depends on it. After that, priority by impact and dependency:

1. **`hired`** (this spec) — 5–7 weeks — foundation; nothing else works without it
2. **SSH Bouncer** — 4–6 weeks — highest security impact; the gap nobody else is filling; the "is this ZT real?" test
3. **ZT Control Plane (minimal)** — 2–3 weeks — ties `hired` + OPA + SSH CA together; enables delegation grants
4. **IMAP/SMTP Gateway** — 3–4 weeks — enables the delegated-access use case; unblocks engineers
5. **ZT sudo PAM module** — 1–2 weeks — high visibility, low effort; engineers notice immediately
6. **Device Posture Agent** — 2–3 weeks — required for full policy; can stub with static "posture ok" initially
7. **Bitwarden integration** — 1–2 weeks — completes the external-site policy requirement

Total: roughly 20–28 weeks of focused Rust work (one person). Parallelizable once `hired` and the ZT control plane are stable: SSH bouncer, IMAP gateway, and device posture can be developed concurrently.

### What Does Not Need to Be Built

**Policy engine** — OPA exists, is production-grade, and is the right choice. Write Rego policies, do not write a policy engine.

**Workload identity** — SPIFFE/SPIRE exists. `hired` federates with it via SPIFFE trust bundles; no replacement needed.

**API proxy** — Envoy with OPA ext-authz covers HTTP/gRPC enforcement. Write the OPA policy, not a new proxy.

**Desktop login** — FIDO2 PAM modules exist (`pam-u2f`, `pam-fido2`). The work is configuration and policy, not new software. `hired` starts as a user session service launched at login, after FIDO2 PAM has already authenticated the desktop session.

**Password manager** — Bitwarden exists and is open source. The work is integration, not replacement.

---

## Delegated Access

The hardest integration case is software that the user has authorized to act on their behalf, but which cannot itself perform FIDO2 authentication — and must not require it for every operation. The canonical examples are IMAP/SMTP clients: `mutt`, `notmuch`, `offlineimap`, `isync`, `fetchmail`, `msmtp`.

These tools need real protocol access (RFC-compliant IMAP and SMTP, not a webmail approximation), must send mail as the user's actual identity, and must work unattended in the background. They cannot be required to touch a FIDO2 key on every mail poll.

If engineers cannot run `isync` against it, they will route around the framework, and the framework will protect nothing.

### The Delegation Grant

When the user authenticates to the ZT control plane (with FIDO2 hardware presence), they can create a **delegation grant** that authorizes a specific software instance to act on their behalf within a defined scope.

A delegation grant is a signed, short-lived cryptographic object:

```json
{
  "version": "1",
  "grant_id": "dg-abc123",
  "issued_at": "2026-04-28T14:00:00Z",
  "expires_at": "2026-04-28T22:00:00Z",

  "grantor": {
    "spiffe_id": "spiffe://example.com/user/mark/via/tailscale",
    "presence_at_issuance": "hardware",
    "presence_attested_at": "2026-04-28T13:59:44Z"
  },

  "grantee": {
    "kind": "software",
    "software_id": "isync@alice-laptop",
    "public_key": "ecdsa-p256:abc123..."
  },

  "scope": {
    "protocol": "imap",
    "mailbox": "mark@example.com",
    "permissions": ["read", "flag", "expunge"],
    "folders": ["INBOX", "Sent", "Drafts"],
    "smtp_send_as": "mark@example.com",
    "smtp_scope": "internal"
  },

  "issuer": "zt-control.example.com",
  "signature": "..."
}
```

**Key properties:**
- The grant is bound to the grantee's **public key** — not a bearer token. Stealing the grant without the corresponding private key does nothing.
- Scope is explicit: which protocol, which mailbox, which permissions, which folders, whether SMTP send-as is permitted and to what scope.
- The grant carries the **presence level at issuance** — downstream systems can decide whether `hardware` presence at delegation time is sufficient for the operation.
- TTL is hours (for mail access), not months. Re-issuance requires another FIDO2 touch.

### Software Identity

The delegated software generates its own keypair at enrollment time. The private key lives in the local filesystem (or SSH agent, or OS keychain) and never leaves the machine. The public key is bound into the delegation grant.

From the software's perspective: "I have a keypair and a grant document. When I need to authenticate, I present both and sign a challenge with my private key."

No passwords are embedded. No reusable tokens are stored. Stealing the config directory without the private key yields nothing.

### ZT IMAP/SMTP Gateway

The enforcement point is a protocol gateway that speaks real IMAP and SMTP but validates delegation grants rather than passwords.

```
mutt / isync
     ↓ real IMAP (TLS)
ZT IMAP/SMTP Gateway
     ↓ validates: grant + client key + scope + TTL
Mail server (Dovecot / Postfix)
```

On connection, the gateway receives a SASL exchange carrying:
1. The delegation grant (signed by ZT control plane)
2. A challenge response signed by the grantee's private key

The gateway verifies both against the ZT trust bundle. If valid, it proxies the IMAP/SMTP session with scope enforcement applied.

From the IMAP client's perspective, this is a normal IMAP server. No client modifications are required.

### SMTP Send-As Enforcement

The gateway enforces that SMTP `MAIL FROM` matches the delegated identity. It prohibits arbitrary `From:` header values. It optionally:
- Applies DKIM signing per the human identity
- Stamps internal headers with identity metadata
- Rate-limits based on grant scope (`smtp_scope: internal` blocks external recipients)

This prevents the classic failure mode where delegated software credentials leak and are used to send spam or impersonate others.

### Presence Gates Delegation, Not Operations

The user must be FIDO2-present to **mint or renew** a delegation grant. Individual IMAP polls and SMTP sends within the grant's TTL do not require re-presence.

High-risk SMTP operations can require a fresh delegation grant with a narrower scope:
```
smtp_scope: external   # requires separate grant with explicit approval
smtp_scope: bulk       # requires separate grant with rate-limit annotation
```

This mirrors the SSH cert pattern: presence at cert issuance, not presence per command.

### The Same Pattern for SSH

The SSH cert flow is identical in structure:

```json
{
  "grantee": { "kind": "ssh-session", "public_key": "ed25519:..." },
  "scope": {
    "protocol": "ssh",
    "principals": ["mark"],
    "hosts": ["*.example.com"],
    "commands": ["*"],   // or a restricted allowlist
    "ttl_seconds": 600
  },
  "grantor": { "presence_at_issuance": "hardware", ... }
}
```

The SSH bouncer validates this grant on connection, re-evaluates per OPA policy, and refuses any connection whose grant has expired or whose scope does not cover the requested target.

FIDO2 touch at session initiation; the short-lived cert carries the presence claim forward; the bouncer enforces scope. 
### `hire delegate` CLI

```
hire delegate imap \
  --mailbox mark@example.com \
  --grantee isync \
  --permissions read,flag,expunge \
  --folders INBOX,Sent \
  --smtp-send-as mark@example.com \
  --smtp-scope internal \
  --ttl 8h
```

This triggers a FIDO2 touch prompt, then writes the signed delegation grant to the grantee's config path (or to a location `isync` is configured to read from).

```
hire delegate ssh \
  --principals mark \
  --hosts "*.example.com" \
  --ttl 10m
```

```
hire delegate list            # show active delegation grants
hire delegate revoke dg-abc123  # immediately revoke a grant
```

---

## Platform Support

The consumer API is **identical on every platform** — the SPIFFE Workload API gRPC socket. An application calls `FetchJWTSVID`, gets back a signed identity document. It does not care whether that identity came from Tailscale WhoIs on Linux, Windows Hello on Windows, TouchID on macOS, or a ServiceAccount token in Kubernetes.

The per-platform work is entirely in the attestor plugins — the "how do I discover identity on this OS" layer. The consumer-facing API, the pseudonymity model, the presence levels, the trust domain schema — all platform-independent.

Implementation: a single Rust binary with `#[cfg]` feature flags per platform, compiling to a static binary on each target. The SPIFFE gRPC socket is the universal interface. Applications write to the socket API once and run everywhere.

This table is the **design**. Sources are marked *(not implemented)* where no
attestor exists today; everything unmarked is active in a default build. The
distinction matters because a platform's entry describes what `hired` is
meant to federate, not what it currently federates.

| Platform | Identity sources | Presence sources | Socket |
|---|---|---|---|
| Linux (systemd: Fedora, RHEL, Ubuntu, Debian) | Tailscale, OIDC cached, SSH agent, GPG, `did:key`, Unix account; GNOME Online Accounts *(not implemented)*, KDE Wallet *(not implemented)*, PIV *(not implemented)*, Kerberos *(not implemented)*, `did:web` *(not implemented)* | libfido2 (USB/NFC) behind `--features fido2`; PAM *(not implemented)* | `$XDG_RUNTIME_DIR/hire/workload.sock`, normally `/run/user/{uid}/hire/workload.sock` (user systemd unit) |
| Linux (non-systemd: Gentoo, Void, Alpine) | Same as above minus GNOME/KDE-specific sources | libfido2 behind `--features fido2` | `$XDG_RUNTIME_DIR/hire/workload.sock`, or `/tmp/hire-{uid}/workload.sock` if that is unset (started via init script or user session) |
| macOS | OIDC cached, SSH agent, GPG, `did:key`, Unix account; Keychain *(not implemented)*, PIV *(not implemented)*; Tailscale *(not implemented here — the attestor probes `/var/run/tailscale/tailscaled.sock`, which the macOS client does not create)* | TouchID (CryptoTokenKit) *(not implemented)*; libfido2 behind `--features fido2` | `<darwin-user-temp>/hire/workload.sock` (LaunchAgent) |
| Windows | *(not implemented — `hired` does not run on Windows; the named-pipe transport is the gate.)* Designed: Tailscale, WAM (Web Account Manager), OIDC cached, SSH agent, PIV | Windows Hello, WebAuthn API, libfido2 — all *(not implemented)* | `\\.\pipe\hire-workload-{sid}` (user-mode service) *(not implemented)* |
| FreeBSD / OpenBSD / NetBSD | SSH agent, GPG, `did:key`, OIDC cached, Unix account; Kerberos *(not implemented)*, PIV *(not implemented)* | libfido2 behind `--features fido2` | `$XDG_RUNTIME_DIR/hire/workload.sock`, or `/tmp/hire-{uid}/workload.sock` if that is unset |
| Kubernetes | ServiceAccount projected token, node attestation via kubelet — all *(not implemented)* | none (workload identity, not human) | Projected volume socket (SPIFFE CSI driver pattern) *(not implemented)* |
| Container (Docker / Podman) | Host `hired` socket bind-mounted into container — needs no code, so this works today | Inherited from host | Bind-mount host socket to `/run/hire/workload.sock` |
| WSL2 | Native Linux `hired` works as on any Linux; `AF_UNIX` interop with a Windows `hired` *(not implemented)* | Host Windows Hello via named-pipe bridge *(not implemented)*; libfido2 native behind `--features fido2` | `/run/user/{uid}/hire/workload.sock` (native); the bridged Windows pipe *(not implemented)* |

### Platform detection and graceful degradation

`hired` probes available identity sources at startup and activates only those present on the current platform. A minimal deployment (SSH agent only) works everywhere; a rich deployment (Tailscale + FIDO2 + OIDC) uses whatever the platform offers. Missing sources are logged and skipped, never fatal.

The Unix account source is the floor: it needs only a running process, so no Unix platform probes to nothing. The rich case is still partly design — PIV has no working `is_available()`, and FIDO2 is compiled out unless `--features fido2` is set.

The startup probe order:
1. Tailscale socket (`/var/run/tailscale/tailscaled.sock` or platform equivalent)
2. FIDO2 devices (`libfido2` enumeration)
3. PIV/smartcard slots (PKCS#11 enumeration)
4. Platform keychain (Keychain / Credential Manager / Secret Service)
5. OIDC token cache (`~/.config/gcloud/`, `~/.azure/`, OS keychain)
6. SSH agent (`SSH_AUTH_SOCK`)
7. GPG agent (gpgconf socket)
8. Kerberos (`KRB5CCNAME` or default ccache)
9. Platform-specific: GNOME Online Accounts (DBus), KDE Wallet (DBus), WAM (COM)

The Unix account source is absent from that list because there is nothing to probe: it is available whenever the kernel is. It is appended after every probed source, and that position is load-bearing. The daemon keeps the first claim it sees at the winning tier, so a source that always produces `iaa1` evidence placed any earlier would take the slot from an SSH key or a hardware touch at the same tier and re-home every pseudonym derived from it.

---

## Prior Art

| System | What it does | What it doesn't do |
|---|---|---|
| **SPIRE Agent** | Workload identity via attestation + SVID issuance | Human identity. Explicitly scoped to "what process is this," not "what human is here." No presence, no FIDO2, no desktop identity sources. Go, no FIPS path. |
| **Kerberos / GSSAPI** | Cryptographic proof of identity from a KDC | Single identity source only. No multi-source federation, no presence model, no per-consumer pseudonyms, no hardware attestation. |
| **macOS Keychain / Windows Credential Manager** | Platform-specific identity and credential store | No cross-platform API, no SPIFFE, no presence model, no pseudonymity. Applications must code to each platform separately. |
| **pam-u2f / pam-fido2** | FIDO2 at the PAM authentication layer | Answers "is a human present" but not "who are they" beyond Unix UID. No daemon, no API for applications, no identity metadata. |
| **Hashicorp Vault Agent** | Injects secrets and short-lived certs into workloads | Closer to SPIRE than hired. No human identity, no presence, no desktop integration. |
| **ssh-agent** | Holds keys, signs challenges on demand via socket API | No identity metadata, no presence, no multi-source federation. But it is the closest UX analog — a daemon that applications talk to over a socket for cryptographic operations. |
| **1Password / Bitwarden CLI** | Password storage and credential population | Password managers, not identity providers. No SPIFFE, no attestation model, no presence levels. |
| **Platform SSO (Windows SSPI, macOS ASAuth)** | OS-level single sign-on for platform-native apps | Platform-locked. No cross-platform API. SSPI is Windows-only, ASAuth is macOS-only. No presence model beyond "session exists." |
| **WebAuthn / Passkeys** | FIDO2-based authentication to web services | Browser-only. No local daemon API. No identity federation — each relying party gets an independent credential. |

The gap: **nobody built "SPIRE but for the human at the keyboard."** The SPIFFE community scoped the project to workloads as a deployable beachhead, not because they thought workloads were the only use case. The desktop agent is the natural completion — same API, same trust model, different attestation sources.

---

## Relationship to SPEC-UIL

`uild` (Unified Identity Layer) is a **server-side** auth normalization daemon. It normalizes incoming OAuth2/OIDC/SAML/WebAuthn requests from clients.

`hired` is a **client-side** identity assertion daemon. It aggregates local identity sources into outgoing SPIFFE SVIDs.

They are complementary:
- A server running `uild` can accept HVIDs (JWT-SVIDs from `hired`) as one of its input token types
- A `hired`-issued JWT-SVID carries `hire.presence` which maps to `uild`'s `auth_strength: hardware_key | biometric`
- The SPIFFE trust bundle from `hired` acts as the JWKS endpoint that `uild` uses to verify the token

Mapping from `hired` `identity_assurance` to `uild` `identity_assurance`:
```
iaa1 → iaa1
iaa2 → iaa2
iaa3 → iaa3
```

Mapping from `hired` `presence_level` to `uild` `auth_strength`:
```
none     → password
session  → password
software → mfa
hardware → hardware_key | biometric
```

---

## First Consumer: kith

kith (Tailnet-native JMAP Chat) is the first application designed to consume `hired`. Today kith hardcodes Tailscale WhoIs as its sole identity source. With `hired`:

1. kithd replaces `tailscale.LocalClient.WhoIs(ctx, remoteAddr)` with `FetchJWTSVID` on the hire socket
2. The JWT-SVID's `spiffe_id` becomes the `Identity.user_id`
3. The `hire.presence` claim enables presence-gated features (e.g., broadcast mentions could require `hardware` presence)
4. kith's pluggable identity provider trait (`kith-core::IdentityProvider`) implements the hire socket as its canonical backend, with Tailscale WhoIs as a fallback when `hired` is absent
5. Federation between kith instances across different trust domains uses SPIFFE trust bundle federation — no custom trust negotiation needed

This also means kith works without Tailscale: on a machine with `hired` and any identity source (OIDC, PIV, Kerberos), kith can authenticate peers via the hire socket over any transport (DNS+mTLS, Tor, local network).

---

## Open Questions

1. **Pseudonymity model**: HKDF-derived pseudonyms give per-consumer isolation. But what if the user wants to link their identity across two specific apps (e.g., their password manager and their SSH client)? Need an explicit user-consent flow for cross-consumer linkage.

2. **Multi-user workstations**: one `hired` per login session (scoped to the session's Unix UID) is the v1 answer. Fast-user-switching requires each session's daemon to hold separate key material. Verify that the socket path scheme enforces this.

3. **Daemon privilege for FIDO2**: USB FIDO2 access on Linux requires either `udev` rules (60-fido.rules) or a privileged helper. The daemon should run as the user and rely on `udev` rules for hardware access. Installation should set up the rules.

4. **Presence challenge UX**: when a consumer requests `hardware` presence and none is available, who owns the prompt? A `hired`-owned tray notification or polkit dialog is cleanest — it avoids requiring every consumer to build its own FIDO2 touch UI.

5. **Presence decay** — *implemented*: `present_until` is a fixed 300-second TTL measured from the observation the claim rests on, not from the clock at request time, so re-requesting cannot extend it. Nothing a caller does extends the window; soft presence signals do not exist and could not extend a hardware-presence claim if they did. What remains open is whether the TTL should be per-attestor rather than daemon-wide.

6. **Cross-machine presence propagation**: if Alice's `kithd` sends a message, can Bob's `kithd` verify that Alice was hardware-present at send time? Options: (a) include a signed HVID attachment in the message envelope; (b) Alice's `hired` issues a per-message presence assertion. The SPIFFE JWT-SVID shape already handles this — the JWT is the signed assertion, the audience is the message ID.

7. **Trust bundle sync**: the user's `hired` on their laptop and `hired` on their server need to share trust bundles if the server is running SPIFFE-aware services. SPIFFE Federation handles this; the question is what the bootstrap looks like for a personal deployment (probably: tailscale + a well-known path under the user's `did:web`).

8. **SASL mechanism for delegation grants**: the IMAP/SMTP gateway needs a SASL mechanism that accepts (delegation-grant, challenge-signature). Options: (a) a custom `GSSAPI`-shaped mechanism registered with IANA; (b) repurpose `OAUTHBEARER` with a non-bearer signed credential; (c) use the existing `EXTERNAL` mechanism with mTLS where the client cert is derived from the delegation grant. Option (c) requires the gateway to issue a short-lived client cert from the grant, which Dovecot/Postfix can validate via `ssl_cert_verifier`. This is the path of least resistance for compatibility with unmodified IMAP clients.

9. **Delegation grant revocation propagation**: if the user revokes a delegation grant (`hire delegate revoke`), gateways that have cached the grant must be notified. Options: (a) short TTL makes revocation eventual (gaps up to TTL); (b) gateway polls a revocation endpoint; (c) push notification via SPIFFE-authenticated webhook. A 15-minute TTL on delegation grants makes option (a) acceptable for most cases; SSH certs should use ≤10 minute TTL for the same reason.
