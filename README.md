# PAAP v2 Standalone

A standalone implementation of the Privacy-Preserving Anonymous Authorization Protocol (PAAP v2) with a demo UI.

## Project Structure

```
PAAPv2-Standalone/
├── demo/                  # Demo UI and server
│   ├── server.js         # Demo server with PAAP endpoints
│   └── static/
│       └── index.html    # Demo UI
├── protocol-server/      # Server-side protocol implementation
│   └── src/
├── protocol-browser/     # Browser SDK for client-side operations
│   └── src/
└── docs/                 # Protocol documentation
```

## Quick Start

1. Navigate to the project directory:
```bash
cd /Users/jayichapurapu/Desktop/PAAPv2-Standalone
```

2. Start the demo server:
```bash
npm start
```

3. Open your browser to:
```
http://localhost:4040
```

4. Use the demo issuance code `demo-code` to test the flow.

## Protocol Endpoints

The demo server implements the following endpoints:

- `GET /issuer` - Returns issuer public key and cryptographic suite parameters
- `POST /issue` - Blind issuance endpoint (takes issuance code + blinded element)
- `POST /redeem` - Redeem credential for a one-time capability token
- `GET /health` - Health check endpoint

## How It Works

1. **Fetch Issuer**: Client learns the suite + public parameters to blind in-browser
2. **Blind Issue**: Client sends issuance code + blinded element. Server never sees the secret
3. **Redeem**: Client redeems once to receive a one-time capability token

## Privacy Features

- No identity-to-credential mapping stored
- No IP/User-Agent in database by protocol design
- Scoped nullifiers (contextId like surveyId)
- Single-use redemption via nullifier tracking (production deployment)
- Blind issuance prevents issuer from learning the secret

## Security Improvements

The demo server includes several security hardening measures:

- **Rate Limiting**: 100 requests per minute per IP to prevent DoS attacks
- **Request Size Limits**: 1MB max request body to prevent memory exhaustion
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
- **CORS Configuration**: Proper CORS headers for cross-origin requests
- **Request Timeout**: 30-second timeout to prevent slowloris attacks
- **Input Validation**: Strict validation for contextId and other inputs
- **Graceful Shutdown**: Proper handling of SIGTERM/SIGINT signals
- **Health Check**: `/health` endpoint for monitoring
- **Configuration Validation**: Validation of PORT and PAAPV2_SUITE environment variables

**Note**: This is a **stateless demo implementation** designed for simplicity and demonstration purposes. It uses a single demo code (`demo-code`) and generates random submission tokens without tracking issuance codes or nullifiers in memory.

This implementation is suitable for production demo/concept showcase purposes. For real-world production deployments with actual credential issuance to users, you would need:
- HTTPS/TLS encryption
- RFC 9474 Blind RSA signature scheme (instead of demo-only textbook RSA)
- Comprehensive logging and auditing
- Optional: Persistent storage for issuance codes and spent nullifiers (if you need to prevent code reuse and double-spending in a real deployment)

See `docs/SECURITY.md` for detailed security considerations and production upgrade path.

## Cryptographic Suites

The implementation supports three suites:

- `PAAPv2-DEMO-RAW-RSA-2048-SHA256`: Textbook RSA for demo/readability (not production-ready)
- `PAAPv2-OPRF-MODP14-SHA256`: OPRF-style blind exponentiation over MODP group
- `PAAPv2-RFC9474-RSA-2048-PSS-SHA256`: RFC 9474 Blind RSA with PSS encoding (production-ready standardized suite)

### Using RFC 9474 Suite

To use the RFC 9474 Blind RSA suite (recommended for production):

```bash
PAAPV2_SUITE=PAAPv2-RFC9474-RSA-2048-PSS-SHA256 npm start
```

The RFC 9474 suite includes:
- Standardized blind signature scheme per RFC 9474
- Automatic key management with rotation support
- Multi-key support during rotation windows
- Comprehensive audit logging

### Key Rotation

The RFC 9474 suite supports key rotation via the admin endpoint:

```bash
curl -X POST http://localhost:4040/admin/rotate-key
```

This creates a new key while keeping the old key active during a configurable rotation window (default 7 days).

## Documentation

See the `docs/` folder for:
- Protocol specification
- Security considerations
- Conformance requirements
- Upgrade path to standardized suites

## Using in a New Project

To integrate PAAP v2 into your own project:

1. Copy the `protocol-server/` folder to your backend
2. Copy the `protocol-browser/` folder to your frontend
3. Import and use the functions as shown in the demo server and UI

### Server-side example:
```javascript
const paap = require('./protocol-server/src/index');

// Get issuer info
const issuer = paap.getIssuerInfo();

// Evaluate blinded element
const { keyId, evaluatedElementHex } = paap.oprfEvaluateBlinded({ blindedElementHex: blinded });

// Compute nullifier
const nullifier = paap.computeNullifierHexScoped({ commitmentHex, contextId, keyId, suiteId });
```

### Client-side example:
```javascript
import { generateTokenInputHex, oprfBlindModp14, oprfUnblindModp14 } from './protocol-browser/src/index.js';

// Generate secret
const tokenInput = generateTokenInputHex();

// Blind
const { blindedElementHex, blindFactorInvHex } = await oprfBlindModp14({ tokenInputHex: tokenInput, contextId: surveyId, issuer });

// Unblind
const { tokenOutputHex } = await oprfUnblindModp14({ evaluatedElementHex: evaluated, blindFactorInvHex, issuer });
```

## License

MIT
