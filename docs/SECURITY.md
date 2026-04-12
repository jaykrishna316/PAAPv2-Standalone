# PAAP v2 Security Notes (Gotchas + Upgrade Path)

This document calls out common pitfalls that reviewers will flag and provides an upgrade path from this repository’s **reference suites** to a standardized, production-ready suite.

## 1) Cryptographic suite: understand what the reference code is (and is not)

This repository currently includes two suites:

- `PAAPv2-DEMO-RAW-RSA-2048-SHA256`: **textbook RSA** operations over integers (blind `m`, compute `s = m^d mod n`, verify `m == s^e mod n`). This is for demo/readability and is **not** a standardized signature scheme.
- `PAAPv2-OPRF-MODP14-SHA256`: an **OPRF-style** blind exponentiation construction over a standard MODP group (client blinds a hash-to-group element, issuer evaluates, client unblinds to a token output).

Both suites are sufficient for **demonstrating the PAAP v2 flow** (blind issuance + redemption + nullifiers), but neither should be treated as a final, “settled” production cryptographic construction without review.

If you publish PAAP v2 publicly, expect cryptography reviewers to ask for a standardized blind signature suite.

## 2) Upgrade path (recommended)

### Phase A — Make the spec suite-driven (now)

- Specify a mandatory `suite` identifier (e.g., `PAAPv2-RSABSSA-SHA384-PSS-2048`).
- Domain-separate nullifiers by including `suite`, `keyId`, and `context` (survey/app scope).

### Phase B — Implement a standardized blind signature suite (recommended)

Adopt **RSA Blind Signatures** per **RFC 9474** (Blind RSA with PSS encoding), instead of signing raw integers.

This suite provides a well-defined `Blind/BlindSign/Finalize/Verify` interface and eliminates “raw RSA” objections. citeturn0search8

### Phase C — Consider Privacy Pass / VOPRF (optional, longer-term)

For some products, a VOPRF/Privacy Pass-style issuance model may provide a more modern foundation than RSA blind signatures. This is a larger change and should be evaluated with a clear threat model and interop requirements.

Important nuance for reviewers: the OPRF-style suite in this repo is **inspired** by that ecosystem, but it is not a drop-in implementation of an RFC VOPRF suite.

## 3) Nullifier domain separation (important)

If the nullifier is computed as `SHA256(C)` only, you should still domain-separate it to avoid accidental cross-context collisions and to ensure nullifiers are scoped to the intended service/survey/app.

Recommended:

- `N = SHA256("paapv2" || suite || keyId || contextId || C)`

Where `contextId` is an application-defined scope (e.g., surveyId).

## 4) Timing correlation is out of scope for protocol crypto

PAAP v2 does not prevent a powerful network observer (or corporate proxy logs) from correlating “who acted when.”

If you want “extreme anonymity,” pair PAAP v2 with:
- an anonymity layer (relay/Tor)
- optional batching/jitter at the gateway

Make this explicit as a non-goal in public-facing docs.

## 5) Issuance code theft and denial-of-participation

Issuance codes are high-value secrets:
- If stolen, an attacker can redeem first (eligibility theft).
- If guessed/brute-forced, an attacker can burn codes (denial).

Mitigations:
- high-entropy issuance codes (CSPRNG)
- short expiry
- rate limiting keyed by hashed issuance code
- re-issue process

## 6) Key rotation and multi-key verification

Production deployments need rules for:
- publishing the issuer public key (and key identifiers)
- rotating keys safely without breaking in-flight issuance
- accepting multiple `keyId`s during a transition window

## 7) Logging and data minimization

Most “anonymity failures” happen due to operational mistakes:
- logging request bodies
- storing issuance codes or credentials in plain text
- joining capability tokens to user identity

PAAP v2 integrators should maintain a strict “do not log secrets” policy and audit their infra logs.
