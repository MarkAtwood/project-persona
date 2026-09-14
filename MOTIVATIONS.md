<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Why personad exists

Count the things on your laptop that already know who you are.

The SSH agent holds your keys and will sign a challenge on request. GPG has your
fingerprint and your web of trust. The browser has passkeys. Tailscale knows your
tailnet identity, verified through Google or GitHub. `gcloud` has a cached OIDC
token, and so do `az` and `aws`. The OS has a login session, unlocked by a password
or a fingerprint. There is probably a FIDO2 key in a USB port right now, and it will
prove a human touched it within the last few seconds.

Seven or eight independent, working answers to "who is this person."

Now name the call an application makes to ask.

There isn't one. Every application that needs to know who you are builds its own
answer from whichever of those signals it happens to be able to reach. A chat client
shells out to `tailscale whois`. A CLI tool reads `~/.config/gcloud`. A terminal
multiplexer trusts the Unix UID and stops there. An internal web app sets a cookie
and hopes. Each picks a different source, gets a different level of confidence, and
has no way to say which it got.

## Nobody can tell you how sure they are

The formats differ, which is annoying. The missing part is worse: none of these
answers carries its own provenance.

A Unix UID and a FIDO2 touch are not the same claim. One says a process is running
under an account that was logged into at some point today, possibly by someone who
walked away an hour ago. The other says a specific human physically touched a
specific piece of hardware within a specific number of seconds. Both arrive at the
application as "the user is alice," and the application has no way to tell them
apart, because there is no vocabulary in which to say it.

So every application either treats a cached token as though someone were sitting
there, or it re-prompts constantly and gets trained out of by its own users. Both
failures come from the same missing thing: no way to ask how strong the answer is,
and no way for the answer to say.

The same goes the other direction. Nothing tells the application whether a human is
present *right now*, as opposed to having been present when the laptop was unlocked
this morning. Presence is not a property of a session. It decays.

## Why it stayed missing

Each of those existing pieces was built for one consumer. `ssh-agent` exists because
`ssh` needed it. GPG's agent exists because GPG needed it. They are narrow because
narrow was correct: a general local identity daemon only pays for itself once several
independent programs want the same answer, and until recently they didn't.

That changed. A Zero Trust desktop has an SSH bouncer, a mail gateway, a `sudo` PAM
module, a device posture agent, and a browser bridge, and every one of them needs to
know who the human is and how confident to be. Build identity federation separately
into each and you have written it five times, five different ways, with five sets of
bugs. That is the fragmentation this project exists to remove, and it only became
worth removing once the consumers showed up.

## The API already exists

The interesting part is that the hard design work is done, by someone else, for a
different audience.

SPIFFE solved this exact problem for workloads. A local socket, a standard gRPC
API, short-lived signed credentials, an attestation model that keeps the trust
decision out of the application. It graduated in the CNCF. Envoy speaks it. So do
ghostunnel, `spiffe-helper`, and the client libraries in Go, Java, Python and Rust.
The specification and the ecosystem are finished and deployed.

The SPIFFE community scoped the project to workloads because workloads were a
tractable beachhead, not because human identity was judged out of bounds. The
`FetchJWTSVID` call does not care what kind of thing is being identified. Point the
same API at a desk instead of a cluster, swap kernel and container attestors for
FIDO2 and PIV and Tailscale, and the shape fits without modification.

So `personad` invents no protocol. Any objection to the API is an objection to a
CNCF standard. Everything new is in the attestation sources and in two ideas SPIFFE
did not need for workloads:

**Assurance, stated out loud.** A credential says which source produced it and how
strong that source is, so an application can require a hardware-backed identity for
one operation and accept a cached token for another. The application never learns
which vendor was involved.

**Per-consumer pseudonyms.** Each consumer receives an identifier derived from
its own identity plus yours, not your root identity. Two applications cannot work
out that they are talking to the same person. This is the Sign-in-with-Apple idea
moved down from the browser to the operating system, where it covers every
application rather than the ones that chose a particular login button.

## Where this actually is

None of the above is finished. The daemon serves the SPIFFE Workload API and issues
signed credentials, but it currently asserts identity claims rather than establishing
them: `prove()` is unimplemented across every attestor, and a FIDO2 key that is only
plugged in will produce a credential claiming a touch that never happened. Pseudonym
derivation is written and tested but not yet connected to issuance.

This document argues for what the daemon is for. [README.md](README.md) records what
runs today, and the gap between the two is large. Read both.

## Further reading

- [README.md](README.md) — overview, current implementation state, installation
- [SPEC-HIA.md](SPEC-HIA.md) — normative specification, SPIFFE ID schema, trust
  domain model, and a full comparison against Kerberos, SPIRE, WebAuthn, platform
  SSO and the rest
- [PRFAQ.md](PRFAQ.md) — the launch framing and anticipated objections
- [DESIGN.md](DESIGN.md) — architecture and technical design
