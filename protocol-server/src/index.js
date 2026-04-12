const crypto = require('crypto');
const { getIssuerKeyMaterial } = require('./issuerKeys');
const { base64UrlToBigInt, bigIntToHex, hexToBigInt, modPow } = require('./bigint');
const { getModp14 } = require('./modp14');
const oprf = require('./oprfModp14');
const { getOprfKeyMaterialModp14 } = require('./oprfKeys');

const SUITES = {
  // Demo-only suite. See protocol/paapv2/SECURITY.md for the production upgrade path.
  DEMO_RAW_RSA_2048_SHA256: 'PAAPv2-DEMO-RAW-RSA-2048-SHA256',
  // VOPRF-inspired OPRF suite over a standard MODP group.
  OPRF_MODP14_SHA256: 'PAAPv2-OPRF-MODP14-SHA256'
};

function getRsaParams() {
  const { keyId, privateJwk, publicJwk } = getIssuerKeyMaterial();
  const n = base64UrlToBigInt(publicJwk.n);
  const e = base64UrlToBigInt(publicJwk.e);
  const d = base64UrlToBigInt(privateJwk.d);
  return { keyId, n, e, d, publicJwk: { kty: 'RSA', n: publicJwk.n, e: publicJwk.e } };
}

function getSuiteId() {
  return process.env.PAAPV2_SUITE || SUITES.OPRF_MODP14_SHA256;
}

function normalizeCommitmentHex(commitmentHex) {
  if (typeof commitmentHex !== 'string') throw new Error('commitment must be hex string');
  const normalized = commitmentHex.startsWith('0x') ? commitmentHex.slice(2) : commitmentHex;
  if (!/^[0-9a-fA-F]+$/.test(normalized)) throw new Error('commitment must be hex');
  if (normalized.length !== 64) throw new Error('commitment must be 32 bytes hex (64 chars)');
  return normalized.toLowerCase();
}

function normalizeSignatureHex(signatureHex) {
  if (typeof signatureHex !== 'string') throw new Error('signature must be hex string');
  const normalized = signatureHex.startsWith('0x') ? signatureHex.slice(2) : signatureHex;
  if (!/^[0-9a-fA-F]+$/.test(normalized)) throw new Error('signature must be hex');
  return normalized.toLowerCase();
}

function signBlinded(blindedHex) {
  const { keyId, n, d } = getRsaParams();
  const blinded = hexToBigInt(blindedHex);
  if (blinded <= 0n || blinded >= n) throw new Error('blinded value out of range');
  const sig = modPow(blinded, d, n);
  return { keyId, blindSignatureHex: bigIntToHex(sig) };
}

function verifyCommitmentSignature(commitmentHex, signatureHex, expectedKeyId) {
  const { keyId, n, e } = getRsaParams();
  if (expectedKeyId && expectedKeyId !== keyId) return false;

  const commitment = hexToBigInt(normalizeCommitmentHex(commitmentHex));
  const sig = hexToBigInt(normalizeSignatureHex(signatureHex));
  if (sig <= 0n || sig >= n) return false;

  const recovered = modPow(sig, e, n);
  return recovered === commitment;
}

function computeNullifierHex(commitmentHex) {
  const normalized = normalizeCommitmentHex(commitmentHex);
  return crypto.createHash('sha256').update(Buffer.from(normalized, 'hex')).digest('hex');
}

function computeNullifierHexScoped({ commitmentHex, contextId, keyId, suiteId }) {
  if (!contextId) throw new Error('contextId is required');
  if (!keyId) throw new Error('keyId is required');
  const normalized = normalizeCommitmentHex(commitmentHex);
  const suite = suiteId || getSuiteId();
  const material = `paapv2|${suite}|${keyId}|${contextId}|` + normalized;
  return crypto.createHash('sha256').update(material, 'utf8').digest('hex');
}

module.exports = {
  SUITES,
  getRsaParams,
  getSuiteId,
  normalizeCommitmentHex,
  normalizeSignatureHex,
  signBlinded,
  verifyCommitmentSignature,
  computeNullifierHex,
  computeNullifierHexScoped,

  // OPRF (MODP14) suite exports
  getModp14,
  getOprfKeyMaterialModp14,
  oprfBlind: oprf.blind,
  oprfEvaluateBlinded: oprf.evaluateBlinded,
  oprfUnblind: oprf.unblind,
  oprfVerifyToken: oprf.verifyToken,
  oprfComputeTokenOutput: oprf.computeTokenOutput,
  oprfDeriveCommitmentHexFromTokenOutput: oprf.deriveCommitmentHexFromTokenOutput,

  /**
   * Suite-aware public issuer info for `/issuer`.
   */
  getIssuerInfo() {
    const suiteId = getSuiteId();
    if (suiteId === SUITES.DEMO_RAW_RSA_2048_SHA256) {
      const { keyId, publicJwk } = getRsaParams();
      return { suiteId, keyId, publicJwk };
    }
    if (suiteId === SUITES.OPRF_MODP14_SHA256) {
      const { keyId, publicKeyHex } = getOprfKeyMaterialModp14();
      const group = getModp14();
      return {
        suiteId,
        keyId,
        group: { id: group.id, primeHex: group.primeHex, generatorHex: group.generatorHex, elementBytes: group.elementBytes },
        publicKeyHex
      };
    }
    throw new Error(`Unsupported suiteId: ${suiteId}`);
  }
};
