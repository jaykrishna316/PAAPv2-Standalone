# PAAP v2 Public Protocol Package (Repository Layout)

This repository contains a protocol spec + reference packages intended for reuse outside of any single application.

PAAP v2 is an **anonymous authorization** protocol: it enforces **eligible-only, one-time** actions (like anonymous survey submission) without identity-based login.

## What it gives you (advantages)

- **Eligibility without identity**: users can prove they’re allowed to act without revealing who they are.
- **One-time use**: prevents double-submission via a **nullifier/spend list**.
- **Unlinkability**: issuance is **blind**, so the issuer cannot later link which credential was redeemed.
- **Minimal stored artifacts**: you can avoid storing raw eligibility secrets or identity-to-action links.

## What you store vs what you do not store

Recommended defaults:
- You **store**:
  - a hashed-at-rest, single-use **issuance code** record (or equivalent issuance gate)
  - a **nullifier** (spent marker) per redeemed credential
  - a short-lived, single-use **capability token** (e.g., submission token)
- You **do not store**:
  - raw issuance codes
  - identity-to-credential mapping
  - credential contents attached to the user identity

## “Company segregation” (who learns what)

PAAP v2 separates roles:
- The **Issuer** (e.g., “the company’s eligibility system”) can know which identities were issued eligibility.
- The **Service** (the anonymous app) verifies credentials and enforces one-time use, but does not need to learn identity.

Blind issuance is the key: it prevents the issuer from recognizing which issued credential was later redeemed.

## Quickstart (one command demo)

Run a local demo server with a tiny browser UI (no install step; uses Node built-ins):

```bash
node examples/paapv2-demo/server.js
```

Then open the printed URL (default `http://localhost:4040`) and paste one of the issuance codes printed in the console.

The demo exercises the 3 protocol endpoints:
- `GET /issuer`
- `POST /issue`
- `POST /redeem`

## Plug-and-play (Express)

Use the ready-to-mount Express router:
- `packages/paapv2-express`

It exposes the same 3 endpoints:
- `GET /issuer`
- `POST /issue`
- `POST /redeem`

In a production integration, you should replace the default in-memory stores with:
- a persistent issuance-code store (single-use + expiry)
- a persistent nullifier store (unique constraint; scoped nullifiers)
- a capability token store (single-use + TTL)

## Suites

This repo supports multiple cryptographic suites via `suiteId`:
- `PAAPv2-OPRF-MODP14-SHA256` (default): OPRF-style blind issuance with `{ tokenInput, tokenOutput }` credentials.
- `PAAPv2-DEMO-RAW-RSA-2048-SHA256`: demo-only RSA blind signature flow with `{ commitment, signature }` credentials.

## Spec
- Draft (IETF-style): `protocol/paapv2/draft-paapv2-00.md`
- Conformance checklist: `protocol/paapv2/CONFORMANCE.md`
- Security notes + upgrade path: `protocol/paapv2/SECURITY.md`

## Reference implementations
- Server (Node/CommonJS): `packages/paapv2-server`
- Browser (ES module): `packages/paapv2-browser`
- Express router (ready-to-mount): `packages/paapv2-express`

## Test vectors
- `packages/paapv2-server/test-vectors/v1.json`

## Notes

This is security-sensitive code. If you intend to use PAAP v2 in production, plan for a cryptography review and a clear threat model (especially around network timing correlation).
