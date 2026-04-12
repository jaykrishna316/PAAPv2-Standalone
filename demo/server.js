const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const paap = require('../protocol-server/src/index');

const PORT = Number(process.env.PORT || 4040);

const issuanceCodes = new Map(); // sha256(code) -> { used, expiresAt }
const spentNullifiers = new Set(); // `${keyId}:${nullifier}`

function sha256hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function json(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': body.length
  });
  res.end(body);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
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

function mintIssuanceCodes(count = 3, ttlMs = 7 * 24 * 60 * 60 * 1000) {
  const expiresAt = Date.now() + ttlMs;
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = crypto.randomUUID();
    issuanceCodes.set(sha256hex(code), { used: false, expiresAt });
    codes.push(code);
  }
  return { codes, expiresAt: new Date(expiresAt).toISOString() };
}

// For demo: pre-mint a small set and print them.
const pre = mintIssuanceCodes(5);
// eslint-disable-next-line no-console
console.log('\nPAAP v2 demo running.');
// eslint-disable-next-line no-console
console.log(`Open: http://localhost:${PORT}`);
// eslint-disable-next-line no-console
console.log('Demo issuance codes (one-time):');
pre.codes.forEach((c) => console.log('  -', c));

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host}`);

    // Static demo UI
    if (req.method === 'GET' && url.pathname === '/') {
      return serveFile(res, path.join(__dirname, 'static', 'index.html'), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && url.pathname === '/sdk/paapv2-browser.js') {
      return serveFile(res, path.join(__dirname, '..', 'protocol-browser', 'src', 'index.js'), 'text/javascript; charset=utf-8');
    }

    // GET /issuer
    if (req.method === 'GET' && url.pathname === '/issuer') {
      return json(res, 200, paap.getIssuerInfo());
    }

    // POST /issue { issuanceCode, blinded }
    if (req.method === 'POST' && url.pathname === '/issue') {
      const body = await readJson(req);
      const { issuanceCode } = body;
      const blinded = body.blinded || body.blindedElement || body.blindedCommitment;
      if (!issuanceCode || !blinded) {
        return json(res, 400, { error: 'issuanceCode and blinded are required' });
      }
      const k = sha256hex(issuanceCode);
      const entry = issuanceCodes.get(k);
      if (!entry || entry.used || entry.expiresAt <= Date.now()) {
        return json(res, 401, { error: 'Invalid or already-used issuance code' });
      }
      entry.used = true;
      issuanceCodes.set(k, entry);

      const { suiteId } = paap.getIssuerInfo();
      if (suiteId === paap.SUITES.OPRF_MODP14_SHA256) {
        const { keyId, evaluatedElementHex } = paap.oprfEvaluateBlinded({ blindedElementHex: blinded });
        return json(res, 201, { suiteId, keyId, evaluated: evaluatedElementHex });
      }
      // Fallback: keep the demo runnable even if env forces the RSA demo suite.
      if (suiteId === paap.SUITES.DEMO_RAW_RSA_2048_SHA256) {
        const { keyId, blindSignatureHex } = paap.signBlinded(blinded);
        return json(res, 201, { suiteId, keyId, evaluated: blindSignatureHex });
      }
      return json(res, 500, { error: 'Unsupported suite' });
    }

    // POST /redeem { contextId, credential: { ... } }
    if (req.method === 'POST' && url.pathname === '/redeem') {
      const body = await readJson(req);
      const { suiteId } = paap.getIssuerInfo();
      const contextId = body.contextId || body.surveyId || 'demo-survey';
      const credential = body.credential || {};

      let commitmentHex;
      let expectedKeyId;

      if (suiteId === paap.SUITES.OPRF_MODP14_SHA256) {
        if (!credential.tokenInput || !credential.tokenOutput) {
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
        if (!ok) return json(res, 401, { error: 'Invalid credential' });
        commitmentHex = paap.oprfDeriveCommitmentHexFromTokenOutput({
          tokenOutputHex: credential.tokenOutput,
          contextId,
          suiteId: paap.getSuiteId(),
          keyId: expectedKeyId
        });
      } else {
        if (!credential.commitment || !credential.signature) {
          return json(res, 400, { error: 'credential.commitment and credential.signature are required' });
        }
        expectedKeyId = credential.keyId || paap.getRsaParams().keyId;
        const ok = paap.verifyCommitmentSignature(credential.commitment, credential.signature, expectedKeyId);
        if (!ok) return json(res, 401, { error: 'Invalid credential' });
        commitmentHex = credential.commitment;
      }

      const nullifier = paap.computeNullifierHexScoped({
        commitmentHex,
        contextId,
        keyId: expectedKeyId,
        suiteId: paap.getSuiteId()
      });
      const spentKey = `${expectedKeyId}:${nullifier}`;
      if (spentNullifiers.has(spentKey)) return json(res, 409, { error: 'Credential already redeemed' });
      spentNullifiers.add(spentKey);

      // Demo capability token (single-use not modeled in this minimal demo)
      return json(res, 201, { submissionToken: crypto.randomUUID(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
    }

    // Not found
    return json(res, 404, { error: 'Not found' });
  } catch (e) {
    return json(res, 500, { error: 'Internal server error' });
  }
});

server.on('error', (err) => {
  // In some sandboxed environments, binding a port is not permitted.
  // eslint-disable-next-line no-console
  console.error(`\nFailed to listen on port ${PORT}:`, err?.message || err);
  // eslint-disable-next-line no-console
  console.error('If you are running inside a restricted sandbox, run this demo locally on your machine.');
  process.exit(1);
});

server.listen(PORT, '127.0.0.1');
