// Lambda Handler for PAAP v2
// This file should be at the root of the deployment package

const serverless = require('serverless-http');
const express = require('express');
const path = require('path');

const paap = require('../protocol-server/src/index');

const app = express();
app.use(express.json());

// Middleware for CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

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
    
    // Validate input
    if (!issuanceCode || !blinded) {
      return res.status(400).json({ error: 'Missing issuanceCode or blinded' });
    }
    
    const { suiteId } = paap.getIssuerInfo();
    let result;
    
    if (suiteId === paap.SUITES.OPRF_MODP14_SHA256) {
      const { keyId, evaluatedElementHex } = paap.oprfEvaluateBlinded({ blindedElementHex: blinded });
      result = { suiteId, keyId, evaluated: evaluatedElementHex };
    } else if (suiteId === paap.SUITES.RFC9474_RSA_2048_PSS_SHA256) {
      const keyManager = paap.getKeyManager();
      if (!keyManager) {
        return res.status(500).json({ error: 'Key manager not initialized' });
      }
      const currentKey = keyManager.getCurrentKey();
      const { blindedSignatureHex } = paap.rfc9474BlindSign(blinded, currentKey.privateKey);
      result = { suiteId, keyId: currentKey.keyId, evaluated: blindedSignatureHex };
    } else {
      return res.status(500).json({ error: 'Unsupported suite' });
    }
    
    res.status(201).json(result);
  } catch (err) {
    console.error('Issue error:', err);
    res.status(500).json({ error: err.message });
  }
});

// POST /redeem - Redeems credential for token
app.post('/redeem', async (req, res) => {
  try {
    const { contextId, credential } = req.body;
    
    // Validate input
    if (!contextId || !credential) {
      return res.status(400).json({ error: 'Missing contextId or credential' });
    }
    
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
      const keyManager = paap.getKeyManager();
      if (!keyManager) {
        return res.status(500).json({ error: 'Key manager not initialized' });
      }
      const key = keyManager.getKey(credential.keyId);
      if (!key) {
        return res.status(401).json({ error: 'Invalid keyId' });
      }
      const ok = paap.rfc9474Verify(credential.message, credential.signature, key.publicKey);
      
      if (!ok) {
        return res.status(401).json({ error: 'Invalid credential' });
      }
      
      commitmentHex = require('crypto').createHash('sha256').update(credential.message).digest('hex');
    }
    
    // Note: In production, you would check/store nullifiers in a database
    // For demo, we'll just generate a token
    const submissionToken = generateUUID();
    
    res.json({
      submissionToken,
      expiresAt: new Date(Date.now() + 3600000).toISOString()
    });
  } catch (err) {
    console.error('Redeem error:', err);
    res.status(500).json({ error: err.message });
  }
});

// GET / - Serve static HTML (for demo)
app.get('/', (req, res) => {
  // For Lambda, you might want to serve static files from S3 instead
  res.json({ 
    message: 'PAAP v2 API',
    endpoints: ['/issuer', '/issue', '/redeem'],
    documentation: 'See INTEGRATION.md'
  });
});

// Helper function to generate UUID
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// Export for serverless-http
module.exports.handler = serverless(app);
