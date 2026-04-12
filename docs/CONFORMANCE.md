# PAAP v2 Conformance Checklist

Use this checklist to validate independent implementations of PAAP v2 (server or client).

## Issuer discovery
- [ ] Exposes `suiteId` and `keyId`
- [ ] Exposes suite parameters needed by clients (RSA JWK for RSA; group params for OPRF)
- [ ] Uses stable `keyId` for the lifetime of a credential issuance window

## Issuance codes
- [ ] Issuance codes are single-use
- [ ] Issuance codes expire (recommended ≤ 7 days)
- [ ] Issuance codes are stored hashed-at-rest (never store raw values)
- [ ] Issuance endpoint is rate-limited

## Client secret material
- [ ] Client generates a fresh, high-entropy per-credential secret
- [ ] Client binds credentials to a `contextId` (e.g., `surveyId`) per the chosen suite

## Blind issuance
- [ ] Client blinds using suite parameters (RSA or OPRF group)
- [ ] Server performs blind evaluation without learning the client secret
- [ ] Client unblinds evaluation to obtain a redeemable credential

## Redemption
- [ ] Server verifies suite credential (RSA signature or OPRF token output)
- [ ] Server computes a scoped nullifier (domain-separated by suite/keyId/context) and stores it
- [ ] Redemption rejects if nullifier already exists (double-spend prevention)
- [ ] Server issues a one-time capability token

## Capability token
- [ ] Token is single-use and consumed on submit
- [ ] Token is stored hashed-at-rest
- [ ] Token expires (recommended ≤ 24h)

## Logging / privacy
- [ ] No raw issuance codes or credentials are logged
- [ ] No identity-to-response linking fields are stored with answers
- [ ] Output is gated by thresholds (avoid small cohort leakage)
