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

4. Use one of the demo issuance codes printed in the terminal to test the flow.

## Protocol Endpoints

The demo server implements three core PAAP v2 endpoints:

- `GET /issuer` - Returns issuer public key and cryptographic suite parameters
- `POST /issue` - Blind issuance endpoint (takes issuance code + blinded element)
- `POST /redeem` - Redeem credential for a one-time capability token

## How It Works

1. **Fetch Issuer**: Client learns the suite + public parameters to blind in-browser
2. **Blind Issue**: Client sends issuance code + blinded element. Server never sees the secret
3. **Redeem**: Client redeems once to receive a one-time capability token

## Privacy Features

- No identity-to-credential mapping stored
- No IP/User-Agent in database by protocol design
- Scoped nullifiers (contextId like surveyId)
- Single-use redemption via nullifier tracking
- Blind issuance prevents issuer from learning the secret

## Cryptographic Suites

The implementation supports two suites:

- `PAAPv2-DEMO-RAW-RSA-2048-SHA256`: Textbook RSA for demo/readability
- `PAAPv2-OPRF-MODP14-SHA256`: OPRF-style blind exponentiation over MODP group

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
