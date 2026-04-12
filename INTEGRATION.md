# PAAP v2 Integration Guide

This guide helps developers integrate PAAP v2 (Privacy-Preserving Anonymous Authorization Protocol) into their applications. The protocol enables anonymous eligibility verification without requiring user identity login.

## Quick Start for Coding Agents

If you're an AI coding agent, read this section to understand how to integrate PAAP v2:

### Core Components

1. **Server-side** (`protocol-server`): Handles issuance and redemption
2. **Client-side** (`protocol-browser`): Handles blinding and verification in browser
3. **Demo server** (`demo/server.js`): Reference implementation

### Integration Steps

1. Install protocol server: `npm install ../protocol-server`
2. Add `/issuer`, `/issue`, `/redeem` endpoints to your server
3. Import browser SDK in your frontend: `import { generateTokenInputHex, oprfBlindModp14, oprfUnblindModp14, oprfDeriveCommitmentHex } from './paapv2-browser.js'`
4. Follow the flow: Fetch issuer → Blind → Issue → Redeem

See detailed steps below.

---

## Table of Contents

- [Protocol Overview](#protocol-overview)
- [Architecture](#architecture)
- [Server Integration](#server-integration)
- [Client Integration](#client-integration)
- [Complete Flow](#complete-flow)
- [Security Considerations](#security-considerations)
- [Cryptographic Suites](#cryptographic-suites)
- [Example Implementations](#example-implementations)

---

## Protocol Overview

PAAP v2 provides anonymous authorization through:

1. **Blind Issuance**: Server signs user's credential without seeing it
2. **Nullifier Scoping**: Prevents double-spending per context
3. **No Identity Storage**: Server only stores nullifiers, not user data

### Use Cases

- Anonymous surveys
- One-time voting
- Limited access without accounts
- Privacy-preserving authentication

---

## Architecture

```
┌─────────────┐
│   Browser   │ (Client SDK)
│  (Blind)    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Your      │ (Your Server + PAAP Server)
│   Server    │
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Database  │ (Only stores nullifiers)
└─────────────┘
```

---

## Server Integration

### Step 1: Install Protocol Server

```bash
npm install ../protocol-server
```

Or add to your `package.json`:

```json
{
  "dependencies": {
    "paapv2-protocol": "../protocol-server"
  }
}
```

### Step 2: Configure Suite

Set environment variable in your server:

```bash
export PAAPV2_SUITE=PAAPv2-OPRF-MODP14-SHA256
# For production:
export PAAPV2_SUITE=PAAPv2-RFC9474-RSA-2048-PSS-SHA256
```

### Step 3: Add Endpoints

Add these three endpoints to your server:

```javascript
const paap = require('paapv2-protocol');

// GET /issuer - Returns public parameters
app.get('/issuer', (req, res) => {
  try {
    const issuerInfo = paap.getIssuerInfo();
    res.json(issuerInfo);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /issue - Issues blind signature
app.post('/issue', async (req, res) => {
  try {
    const { issuanceCode, blinded } = req.body;
    
    // Validate issuance code (your business logic)
    if (!isValidIssuanceCode(issuanceCode)) {
      return res.status(401).json({ error: 'Invalid issuance code' });
    }
    
    const { suiteId } = paap.getIssuerInfo();
    let result;
    
    if (suiteId === paap.SUITES.OPRF_MODP14_SHA256) {
      const { keyId, evaluatedElementHex } = paap.oprfEvaluateBlinded({ blindedElementHex: blinded });
      result = { suiteId, keyId, evaluated: evaluatedElementHex };
    } else if (suiteId === paap.SUITES.RFC9474_RSA_2048_PSS_SHA256) {
      // RFC 9474 implementation
      const keyManager = paap.getKeyManager();
      const currentKey = keyManager.getCurrentKey();
      const { blindedSignatureHex } = paap.rfc9474BlindSign(blinded, currentKey.privateKey);
      result = { suiteId, keyId: currentKey.keyId, evaluated: blindedSignatureHex };
    }
    
    res.status(201).json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /redeem - Redeems credential for token
app.post('/redeem', async (req, res) => {
  try {
    const { contextId, credential } = req.body;
    
    // Validate contextId
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(contextId)) {
      return res.status(400).json({ error: 'Invalid contextId' });
    }
    
    const { suiteId } = paap.getIssuerInfo();
    let commitmentHex;
    
    if (suiteId === paap.SUITES.OPRF_MODP14_SHA256) {
      const ok = paap.oprfVerifyToken({
        tokenInputHex: credential.tokenInput,
        tokenOutputHex: credential.tokenOutput,
        contextId,
        suiteId,
        keyId: credential.keyId
      });
      
      if (!ok) {
        return res.status(401).json({ error: 'Invalid credential' });
      }
      
      commitmentHex = paap.oprfDeriveCommitmentHexFromTokenOutput({
        tokenOutputHex: credential.tokenOutput,
        contextId,
        suiteId,
        keyId: credential.keyId
      });
    } else if (suiteId === paap.SUITES.RFC9474_RSA_2048_PSS_SHA256) {
      // RFC 9474 verification
      const keyManager = paap.getKeyManager();
      const key = keyManager.getKey(credential.keyId);
      const ok = paap.rfc9474Verify(credential.message, credential.signature, key.publicKey);
      
      if (!ok) {
        return res.status(401).json({ error: 'Invalid credential' });
      }
      
      commitmentHex = require('crypto').createHash('sha256').update(credential.message).digest('hex');
    }
    
    // Check if nullifier already spent (your database)
    if (await isNullifierSpent(commitmentHex, contextId)) {
      return res.status(409).json({ error: 'Credential already redeemed' });
    }
    
    // Store nullifier (your database)
    await storeNullifier(commitmentHex, contextId);
    
    // Generate submission token
    const submissionToken = generateUUID();
    
    res.json({
      submissionToken,
      expiresAt: new Date(Date.now() + 3600000).toISOString() // 1 hour
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Step 4: Database Schema

You need to store nullifiers to prevent double-spending:

```sql
CREATE TABLE nullifiers (
  id SERIAL PRIMARY KEY,
  commitment_hex VARCHAR(64) NOT NULL,
  context_id VARCHAR(64) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(commitment_hex, context_id)
);
```

---

## Client Integration

### Step 1: Copy Browser SDK

Copy `protocol-browser/src/index.js` to your frontend project, or install it:

```bash
npm install ../protocol-browser
```

### Step 2: Import Functions

```javascript
import {
  generateTokenInputHex,
  oprfBlindModp14,
  oprfUnblindModp14,
  oprfDeriveCommitmentHex
} from './paapv2-browser.js';
```

### Step 3: Implement Flow

```javascript
// 1. Fetch issuer info
const issuerResp = await fetch('/issuer');
const issuer = await issuerResp.json();

// 2. Blind the token
const tokenInput = generateTokenInputHex();
const { blindedElementHex, blindFactorInvHex } = await oprfBlindModp14({
  tokenInputHex: tokenInput,
  contextId: 'my-survey-id',
  issuer
});

// 3. Request blind signature
const issueResp = await fetch('/issue', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    issuanceCode: 'your-issuance-code',
    blinded: blindedElementHex
  })
});
const issued = await issueResp.json();

// 4. Unblind signature
const { tokenOutputHex } = await oprfUnblindModp14({
  evaluatedElementHex: issued.evaluated,
  blindFactorInvHex,
  issuer
});

// 5. Redeem credential
const redeemResp = await fetch('/redeem', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    contextId: 'my-survey-id',
    credential: {
      keyId: issued.keyId,
      tokenInput,
      tokenOutput: tokenOutputHex
    }
  })
});
const redeemed = await redeemResp.json();

// 6. Use submission token
console.log('Submission token:', redeemed.submissionToken);
```

---

## Complete Flow

```
1. Client → Server: GET /issuer
   Server → Client: { suiteId, keyId, publicKeyHex, group }
   
2. Client: Generate tokenInput, blind it
   Client → Server: POST /issue { issuanceCode, blinded }
   Server → Client: { suiteId, keyId, evaluated }
   
3. Client: Unblind signature to get tokenOutput
   Client → Server: POST /redeem { contextId, credential }
   Server: Verify credential, store nullifier
   Server → Client: { submissionToken, expiresAt }
   
4. Client: Use submission token for your application
```

---

## Security Considerations

### Required

1. **Validate issuance codes**: Don't accept arbitrary codes
2. **Store nullifiers**: Prevent double-spending
3. **Use HTTPS**: Protect protocol messages in transit
4. **Context ID validation**: Restrict to alphanumeric + hyphens/underscores

### Recommended

1. **Rate limiting**: Prevent abuse of issuance endpoint
2. **Key rotation**: Use RFC 9474 with key rotation for production
3. **Audit logging**: Track protocol events without storing user data
4. **CORS configuration**: Restrict to your frontend domain

### Never Do

1. Store IP addresses or user agents linked to protocol events
2. Log issuance codes with user identifiers
3. Share issuance codes in URLs
4. Use demo suite (DEMO_RAW_RSA) in production

---

## Cryptographic Suites

### OPRF-MODP14-SHA256 (Demo)

- **Use case**: Development and testing
- **Security**: VOPRF-inspired over MODP14 group
- **Pros**: Simple, no key rotation needed
- **Cons**: Not standardized, less studied

### RFC9474-RSA-2048-PSS-SHA256 (Production)

- **Use case**: Production deployments
- **Security**: Standardized Blind RSA with PSS padding
- **Pros**: RFC standard, well-audited, supports key rotation
- **Cons**: More complex, requires key management

**Recommendation**: Use OPRF for development, RFC 9474 for production.

---

## JWT Token Enhancement (Optional)

The protocol uses simple UUIDs for submission tokens by default, but JWT can be added for additional features like built-in expiration and metadata. Privacy guarantees remain unchanged.

### Why JWT is Optional

- **Privacy**: Blind signatures and nullifiers provide privacy - token format doesn't affect this
- **Functionality**: JWT adds convenience (expiration, claims) but isn't required for core protocol
- **Decision**: Use JWT if you need standard token format or expiration handling

### Implementation

#### Step 1: Install JWT library

```bash
npm install jsonwebtoken
```

#### Step 2: Modify /redeem endpoint

```javascript
const jwt = require('jsonwebtoken');

// In your /redeem endpoint:
const submissionToken = jwt.sign(
  { 
    contextId,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600 // 1 hour expiration
  },
  process.env.JWT_SECRET || 'your-secret-key'
);
```

#### Step 3: Verify JWT in your application

```javascript
const jwt = require('jsonwebtoken');

// When using the submission token:
try {
  const decoded = jwt.verify(submissionToken, process.env.JWT_SECRET);
  console.log('Valid token for context:', decoded.contextId);
} catch (err) {
  console.error('Invalid token:', err.message);
}
```

### JWT vs UUID Comparison

| Feature | UUID | JWT |
|---------|------|-----|
| Privacy | ✓ | ✓ (same) |
| Expiration | Manual | Built-in (exp claim) |
| Metadata | None | Custom claims |
| Size | 36 chars | ~200 chars |
| Standardization | None | RFC 7519 |
| Verification | Simple | Requires secret |

### Example JWT Payload

```json
{
  "contextId": "survey-123",
  "iat": 1744713600,
  "exp": 1744717200
}
```

**Note**: Never include user-identifiable information in JWT claims. The protocol's privacy depends on the blind signature, not the token format.

---

## Example Implementations

### Express.js Server

See `demo/server.js` for a complete reference implementation.

### React Frontend

```javascript
import { useState } from 'react';
import {
  generateTokenInputHex,
  oprfBlindModp14,
  oprfUnblindModp14
} from './paapv2-browser.js';

function PAAPv2Flow() {
  const [token, setToken] = useState(null);
  
  const handleIssueAndRedeem = async () => {
    // Fetch issuer
    const issuer = await fetch('/issuer').then(r => r.json());
    
    // Blind
    const tokenInput = generateTokenInputHex();
    const { blindedElementHex, blindFactorInvHex } = await oprfBlindModp14({
      tokenInputHex: tokenInput,
      contextId: 'survey-123',
      issuer
    });
    
    // Issue
    const issued = await fetch('/issue', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ issuanceCode: 'code-123', blinded: blindedElementHex })
    }).then(r => r.json());
    
    // Unblind
    const { tokenOutputHex } = await oprfUnblindModp14({
      evaluatedElementHex: issued.evaluated,
      blindFactorInvHex,
      issuer
    });
    
    // Redeem
    const redeemed = await fetch('/redeem', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contextId: 'survey-123',
        credential: { keyId: issued.keyId, tokenInput, tokenOutput: tokenOutputHex }
      })
    }).then(r => r.json());
    
    setToken(redeemed.submissionToken);
  };
  
  return (
    <div>
      <button onClick={handleIssueAndRedeem}>Get Anonymous Token</button>
      {token && <p>Token: {token}</p>}
    </div>
  );
}
```

---

## Troubleshooting

### "Invalid credential" error

- Check that the client and server are using the same suite
- Verify the contextId matches between issue and redeem
- Ensure the keyId is valid

### "Credential already redeemed" error

- This is expected if the same credential is used twice
- Each credential can only be redeemed once per contextId

### Browser SDK not loading

- Ensure the file is served with correct MIME type (`text/javascript`)
- Check that imports use the correct path

---

## Support

- **Demo**: http://localhost:4040
- **Protocol Source**: `protocol-server/src/index.js`
- **Browser SDK**: `protocol-browser/src/index.js`
- **Demo Implementation**: `demo/server.js`

---

## License

MIT
