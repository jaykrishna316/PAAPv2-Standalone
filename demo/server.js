const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const paap = require('../protocol-server/src/index');

const PORT = process.env.PORT || 4040;
const PAAPV2_SUITE = process.env.PAAPV2_SUITE || 'PAAPv2-OPRF-MODP14-SHA256';

const VALID_SUITES = [
  'PAAPv2-DEMO-RAW-RSA-2048-SHA256',
  'PAAPv2-OPRF-MODP14-SHA256',
  'PAAPv2-RFC9474-RSA-2048-PSS-SHA256'
];
const configuredSuite = process.env.PAAPV2_SUITE;
if (configuredSuite && !VALID_SUITES.includes(configuredSuite)) {
  console.error(`Invalid PAAPV2_SUITE: ${configuredSuite}. Must be one of: ${VALID_SUITES.join(', ')}`);
  process.exit(1);
}

// Initialize audit logger
const logger = paap.getAuditLogger({
  logLevel: process.env.LOG_LEVEL || 'info',
  logToFile: process.env.LOG_TO_FILE !== 'false',
  enableConsole: process.env.ENABLE_CONSOLE_LOG !== 'false'
});

// Initialize key manager (for RFC 9474 suite)
let keyManager = null;
if (paap.getSuiteId() === paap.SUITES.RFC9474_RSA_2048_PSS_SHA256) {
  keyManager = paap.getKeyManager();
  // Initialize with a key if none exists
  if (!keyManager.getCurrentKey()) {
    keyManager.createNewKey();
  }
}

// Stateless demo: No issuance codes or nullifiers tracked in memory
// For demo purposes, we accept any non-empty issuance code and return random tokens
const DEMO_ISSUANCE_CODE = 'demo-code'; // Simplified demo: single known code

function json(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': body.length
  });
  res.end(body);
}

function readJson(req, maxSize = 1 * 1024 * 1024) { // 1MB limit
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > maxSize) {
        req.destroy();
        reject(new Error('Request body too large'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve(raw ? JSON.parse(raw) : {});
      } catch (e) {
        reject(e);
      }
    });
  });
}

function serveFile(res, filePath, contentType) {
  const buf = fs.readFileSync(filePath);
  res.writeHead(200, { 'Content-Type': contentType, 'Content-Length': buf.length });
  res.end(buf);
}

// Input validation
function validateContextId(contextId) {
  if (!contextId || typeof contextId !== 'string') {
    return false;
  }
  // Allow alphanumeric, hyphens, underscores, max 64 chars
  return /^[a-zA-Z0-9_-]{1,64}$/.test(contextId);
}

// Simple in-memory rate limiting (per IP)
const rateLimitMap = new Map(); // IP -> { count, resetTime }
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 100; // 100 requests per minute per IP

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  
  if (!record || now > record.resetTime) {
    rateLimitMap.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }
  
  if (record.count >= RATE_LIMIT_MAX) {
    logger.logRateLimitExceeded(ip, 'unknown');
    return false;
  }
  
  record.count++;
  return true;
}

// eslint-disable-next-line no-console
console.log('\nPAAP v2 demo running (stateless mode).');
// eslint-disable-next-line no-console
console.log(`Open: http://localhost:${PORT}`);
// eslint-disable-next-line no-console
console.log('Demo issuance code: demo-code');
logger.logServerStart(PORT, paap.getSuiteId());

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const clientIp = req.socket.remoteAddress || 'unknown';

    // Rate limiting check
    if (!checkRateLimit(clientIp)) {
      return json(res, 429, { error: 'Too many requests' });
    }

    // Add security headers
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';");

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle preflight requests
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Static demo UI
    if (req.method === 'GET' && url.pathname === '/') {
      return serveFile(res, path.join(__dirname, 'static', 'index.html'), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/sdk/paapv2-browser.js') {
      return serveFile(res, path.join(__dirname, '..', 'protocol-browser', 'src', 'index.js'), 'text/javascript; charset=utf-8');
    }

    // GET /issuer
    if (req.method === 'GET' && url.pathname === '/issuer') {
      logger.logIssuerRequest(clientIp, paap.getSuiteId());
      return json(res, 200, paap.getIssuerInfo());
    }

    // GET /health
    if (req.method === 'GET' && url.pathname === '/health') {
      return json(res, 200, { status: 'ok', timestamp: new Date().toISOString() });
    }

    // POST /admin/rotate-key (admin endpoint for key rotation)
    if (req.method === 'POST' && url.pathname === '/admin/rotate-key') {
      if (!keyManager) {
        return json(res, 400, { error: 'Key rotation only available with RFC 9474 suite' });
      }
      try {
        const result = keyManager.rotateKey();
        logger.logKeyRotation(result.oldKey.keyId, result.newKey.keyId);
        return json(res, 200, { 
          message: 'Key rotated successfully',
          oldKeyId: result.oldKey.keyId,
          newKeyId: result.newKey.keyId
        });
      } catch (error) {
        logger.error('key_rotation_failed', { error: error.message });
        return json(res, 500, { error: 'Key rotation failed' });
      }
    }

    // POST /issue { issuanceCode, blinded }
    if (req.method === 'POST' && url.pathname === '/issue') {
      const body = await readJson(req);
      const { issuanceCode } = body;
      const blinded = body.blinded || body.blindedElement || body.blindedCommitment;
      const contextId = body.contextId || body.surveyId || 'demo-survey';

      if (!issuanceCode || !blinded) {
        logger.logIssuanceFailure(clientIp, contextId, paap.getSuiteId(), 'Missing required fields');
        return json(res, 400, { error: 'issuanceCode and blinded are required' });
      }

      logger.logIssuanceRequest(clientIp, contextId, paap.getSuiteId());

      // Stateless demo: accept any non-empty issuance code
      if (issuanceCode !== DEMO_ISSUANCE_CODE) {
        logger.logIssuanceFailure(clientIp, contextId, paap.getSuiteId(), 'Invalid issuance code');
        return json(res, 401, { error: 'Invalid issuance code' });
      }

      const { suiteId } = paap.getIssuerInfo();
      let result;

      if (suiteId === paap.SUITES.RFC9474_RSA_2048_PSS_SHA256) {
        // RFC 9474 Blind RSA
        if (!keyManager) {
          logger.logIssuanceFailure(clientIp, contextId, suiteId, 'Key manager not initialized');
          return json(res, 500, { error: 'Key manager not initialized' });
        }
        const currentKey = keyManager.getCurrentKey();
        const { blindedSignatureHex } = paap.rfc9474BlindSign(blinded, currentKey.privateKey);
        result = { suiteId, keyId: currentKey.keyId, evaluated: blindedSignatureHex };
      } else if (suiteId === paap.SUITES.OPRF_MODP14_SHA256) {
        const { keyId, evaluatedElementHex } = paap.oprfEvaluateBlinded({ blindedElementHex: blinded });
        result = { suiteId, keyId, evaluated: evaluatedElementHex };
      } else if (suiteId === paap.SUITES.DEMO_RAW_RSA_2048_SHA256) {
        const { keyId, blindSignatureHex } = paap.signBlinded(blinded);
        result = { suiteId, keyId, evaluated: blindSignatureHex };
      } else {
        logger.logIssuanceFailure(clientIp, contextId, suiteId, 'Unsupported suite');
        return json(res, 500, { error: 'Unsupported suite' });
      }

      logger.logIssuanceSuccess(clientIp, contextId, suiteId, result.keyId);
      return json(res, 201, result);
    }

    // POST /redeem { contextId, credential: { ... } }
    if (req.method === 'POST' && url.pathname === '/redeem') {
      const body = await readJson(req);
      const { suiteId } = paap.getIssuerInfo();
      const contextId = body.contextId || body.surveyId || 'demo-survey';

      // Validate contextId
      if (!validateContextId(contextId)) {
        logger.logRedeemFailure(clientIp, contextId, suiteId, null, 'Invalid contextId');
        return json(res, 400, { error: 'Invalid contextId. Must be 1-64 alphanumeric characters, hyphens, or underscores' });
      }

      logger.logRedeemRequest(clientIp, contextId, suiteId, 'unknown');

      const credential = body.credential || {};

      let commitmentHex;
      let expectedKeyId;

      if (suiteId === paap.SUITES.OPRF_MODP14_SHA256) {
        if (!credential.tokenInput || !credential.tokenOutput) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, null, 'Missing required fields');
          return json(res, 400, { error: 'credential.tokenInput and credential.tokenOutput are required' });
        }
        expectedKeyId = credential.keyId || paap.getOprfKeyMaterialModp14().keyId;
        const ok = paap.oprfVerifyToken({
          tokenInputHex: credential.tokenInput,
          tokenOutputHex: credential.tokenOutput,
          contextId,
          suiteId: paap.getSuiteId(),
          keyId: expectedKeyId
        });
        if (!ok) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, expectedKeyId, 'Invalid credential');
          return json(res, 401, { error: 'Invalid credential' });
        }
        commitmentHex = paap.oprfDeriveCommitmentHexFromTokenOutput({
          tokenOutputHex: credential.tokenOutput,
          contextId,
          suiteId: paap.getSuiteId(),
          keyId: expectedKeyId
        });
      } else if (suiteId === paap.SUITES.RFC9474_RSA_2048_PSS_SHA256) {
        // RFC 9474 verification
        if (!credential.signature || !credential.message) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, null, 'Missing required fields');
          return json(res, 400, { error: 'credential.signature and credential.message are required' });
        }
        expectedKeyId = credential.keyId || (keyManager ? keyManager.getCurrentKey().keyId : null);
        logger.logRedeemRequest(clientIp, contextId, suiteId, expectedKeyId || 'unknown');
        
        if (!expectedKeyId || !keyManager) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, null, 'Key manager not initialized');
          return json(res, 500, { error: 'Key manager not initialized' });
        }
        const key = keyManager.getKey(expectedKeyId);
        if (!key) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, expectedKeyId, 'Invalid keyId');
          return json(res, 401, { error: 'Invalid keyId' });
        }
        
        try {
          // Use the PEM directly from key data
          const publicKeyPem = key.publicKey;
          const ok = paap.rfc9474Verify(credential.message, credential.signature, publicKeyPem);
          if (!ok) {
            logger.logRedeemFailure(clientIp, contextId, suiteId, expectedKeyId, 'Invalid credential');
            return json(res, 401, { error: 'Invalid credential' });
          }
          commitmentHex = crypto.createHash('sha256').update(credential.message).digest('hex');
        } catch (err) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, expectedKeyId, err.message);
          return json(res, 500, { error: 'Verification failed: ' + err.message });
        }
      } else {
        if (!credential.commitment || !credential.signature) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, null, 'Missing required fields');
          return json(res, 400, { error: 'credential.commitment and credential.signature are required' });
        }
        expectedKeyId = credential.keyId || paap.getRsaParams().keyId;
        const ok = paap.verifyCommitmentSignature(credential.commitment, credential.signature, expectedKeyId);
        if (!ok) {
          logger.logRedeemFailure(clientIp, contextId, suiteId, expectedKeyId, 'Invalid credential');
          return json(res, 401, { error: 'Invalid credential' });
        }
        commitmentHex = credential.commitment;
      }

      // Stateless demo: skip nullifier tracking, just return random token
      // In production, you would track nullifiers to prevent double-spending
      const nullifier = paap.computeNullifierHexScoped({
        commitmentHex,
        contextId,
        keyId: expectedKeyId,
        suiteId: paap.getSuiteId()
      });

      logger.logRedeemSuccess(clientIp, contextId, suiteId, expectedKeyId);

      // Demo capability token (single-use not enforced in stateless demo)
      return json(res, 201, {
        submissionToken: crypto.randomUUID(),
        expiresAt: new Date(Date.now() + 3600_000).toISOString(),
        nullifier: nullifier // Include for demo visibility
      });
    }

    // Not found
    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error('Request error:', e);
    return json(res, 500, { error: 'Internal server error' });
  }
});

// Set request timeout (30 seconds)
server.timeout = 30000;
server.headersTimeout = 30000;

// Graceful shutdown handling
const shutdown = (signal) => {
  console.log(`\n${signal} received, shutting down gracefully...`);
  logger.logServerShutdown();
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });

  // Force shutdown after 10 seconds
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

server.on('error', (err) => {
  // In some sandboxed environments, binding a port is not permitted.
  // eslint-disable-next-line no-console
  console.error(`\nFailed to listen on port ${PORT}:`, err?.message || err);
  // eslint-disable-next-line no-console
  console.error('If you are running inside a restricted sandbox, run this demo locally on your machine.');
  process.exit(1);
});

server.listen(PORT, '127.0.0.1', () => {
  // eslint-disable-next-line no-console
  console.log(`Server listening on http://127.0.0.1:${PORT}`);
});
