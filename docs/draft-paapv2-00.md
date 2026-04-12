# draft-paapv2-00

## Title

PAAP v2: Blind-Issued Eligibility Credentials with Nullifiers

## Status

This document is an internal/public draft intended to be stable enough for third-party implementation. It is not an IETF submission.

## Abstract

PAAP v2 defines an anonymous authorization protocol for “eligible-only, one-time” actions (e.g., survey submission) without identity-based authentication. The protocol provides:
- per-user eligibility (issuance constrained by an issuer)
- unlinkability between issuance and redemption (via blind issuance)
- one-time use enforcement (via nullifiers / spend list)
- minimal stored artifacts (hashed-at-rest and no identity binding)

## Security Properties (informal)

When instantiated with a secure cryptographic suite and deployed with appropriate operational controls, PAAP v2 is intended to provide:
- **Eligibility**: only eligible users can obtain a credential.
- **One-time use**: a credential can be redeemed once (double-spend prevention via nullifiers).
- **Unlinkability (issuance→redemption)**: the issuer should not be able to link which issued credential was redeemed (blind issuance).
- **No identity binding at the service**: the service can verify eligibility and enforce one-time use without storing identity-to-action links.

## Non-Goals

PAAP v2 does not, by itself:
- prevent **timing correlation** by network observers
- protect against compromised client devices (malware, screenshots, keyloggers)
- protect secrets if implementers log request bodies or store raw issuance codes
- guarantee anonymity of released analytics/output (this is an application-layer problem)

## Terminology

- **Issuer**: the system that decides who is eligible (e.g., HR/admin/SSO gate).
- **Client**: the end user who wants to perform the action anonymously.
- **Service**: the anonymous application backend (e.g., survey service).
- **Issuance Code**: a one-time eligibility secret distributed per user to trigger blind issuance.
- **Context ID**: application scope for credentials (e.g., `surveyId`).
- **Credential**: suite-specific proof of issuance, redeemed once.
- **Nullifier (N)**: a scoped hash derived from a credential commitment; stored to prevent re-use without revealing identity.

## Threat Model (non-exhaustive)

PAAP v2 aims to prevent linking a user identity to a redeemed credential or submission, under the following assumptions:
- the service database may be exposed
- application logs may be exposed (best-effort minimization is recommended)
- the issuer can know which identities were issued eligibility (but should not be able to link issuance to redemption)

PAAP v2 does not, by itself, prevent timing correlation by a network observer; deployments should use an anonymity layer and/or batching if “extreme anonymity” is required.

## Protocol Overview

### Phase 0: Issuer parameters discovery

The service exposes issuer parameters for client blinding:
- `keyId`
- issuer public key (e.g., RSA JWK fields `n` and `e`)

### Phase 1: Issuance code distribution

The issuer distributes one issuance code per eligible user out-of-band.
Issuance codes MUST be single-use and SHOULD expire quickly.

### Phase 2: Blind issuance

1. Client generates a per-credential secret (suite-specific).
2. Client blinds it to produce `B`.
3. Client sends `(issuanceCode, B)` to the service issuance endpoint.
4. Service validates `issuanceCode` and returns `E_blind` (blind evaluation).
5. Client unblinds `E_blind` to obtain `E`.

### Phase 3: Redemption

Client sends a suite-specific credential to the service, scoped to a `contextId`.
Service verifies the credential and checks the nullifier spend list:
- compute scoped nullifier `N = SHA256("paapv2" || suite || keyId || contextId || commitment)`
- reject if `N` already exists
- otherwise, record `N` and issue a one-time capability token (e.g., submission token)

### Phase 4: Action

Client performs the one-time action using the capability token. The token MUST be consumed on use.

## Message Formats (JSON)

### Issuer discovery
- Response (generic): `{ suiteId, keyId, ...suiteParams }`
- RSA-blind-signature suite params: `{ publicJwk: { kty: \"RSA\", n, e } }`
- OPRF suite params: `{ group: { id, primeHex, generatorHex, elementBytes }, publicKeyHex }`

### Blind issue request
- Request (generic): `{ issuanceCode: string, blinded: hexString }`
- Response (generic): `{ suiteId: string, keyId: string, evaluated: hexString }`

### Redemption request
- Request (generic): `{ contextId: string, credential: { keyId?: string, ...suiteCredential } }`
- RSA suite credential: `{ commitment: hex32bytes, signature: hexString }`
- OPRF suite credential: `{ tokenInput: hex32bytes, tokenOutput: hexString }`
- Response: `{ submissionToken: string, expiresAt: isoDate }`

## Security Considerations

- **Do not distribute issuance codes via URLs** (referrers, analytics, screenshots).
- **Minimize logs** for the issuance/redemption endpoints.
- **Rate limit** issuance attempts to reduce brute force.
- **Enforce k-threshold output controls** to prevent small-cohort de-anonymization.
- Consider deploying an anonymity layer (Tor/relay) for high-assurance unlinkability at the network layer.

## Cryptographic Suites (IMPORTANT)

PAAP v2 is a protocol and MUST be instantiated with a cryptographic suite.

This repository’s reference code includes:
- a **demo-only** “raw RSA over integers” blind-signature construction (for readability)
- an **OPRF-style** blind exponentiation suite over a standard MODP group (a stepping stone toward VOPRF-style issuance)

For production use, implementers SHOULD adopt a standardized blind signature construction, such as **RSA Blind Signatures (RFC 9474)**. citeturn0search8

## IANA Considerations

This document has no IANA actions.
