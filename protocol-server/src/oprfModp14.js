const crypto = require('crypto');
const { hexToBigInt, modPow, modInv } = require('./bigint');
const { getModp14 } = require('./modp14');
const { getOprfKeyMaterialModp14 } = require('./oprfKeys');

function normalizeHex(hex, { bytes, label }) {
  if (typeof hex !== 'string') throw new Error(`${label} must be a hex string`);
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]+$/.test(normalized)) throw new Error(`${label} must be hex`);
  if (bytes != null && normalized.length !== bytes * 2) throw new Error(`${label} must be ${bytes} bytes hex`);
  return normalized.toLowerCase();
}

function sha256HexUtf8(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest('hex');
}

function sha256HexBytes(buf) {
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function hashToGroupElement({ tokenInputHex, contextId, suiteId, keyId }) {
  const { p } = getModp14();
  const input = normalizeHex(tokenInputHex, { bytes: 32, label: 'tokenInput' });
  if (!contextId) throw new Error('contextId is required');
  if (!suiteId) throw new Error('suiteId is required');
  if (!keyId) throw new Error('keyId is required');

  // Map-to-subgroup: interpret hash as integer h, then square to land in quadratic residues (order q).
  // Retry with a counter if we hit a degenerate point (0 or 1).
  for (let ctr = 0; ctr < 8; ctr += 1) {
    const material = `paapv2|oprf|${suiteId}|${keyId}|${contextId}|${ctr}|` + input;
    const h = hexToBigInt(sha256HexUtf8(material)) % p;
    const u = (h * h) % p;
    if (u !== 0n && u !== 1n) return u;
  }
  throw new Error('Failed to hash to group element');
}

function normalizeElementHex(elementHex) {
  const { p, elementBytes, bigIntToFixedHex } = getModp14();
  const normalized = normalizeHex(elementHex, { bytes: null, label: 'group element' });
  const bi = hexToBigInt(normalized);
  if (bi <= 1n || bi >= p) throw new Error('group element out of range');
  return bigIntToFixedHex(bi, elementBytes);
}

function randomBlindScalar() {
  const { q } = getModp14();
  while (true) {
    const rnd = BigInt('0x' + crypto.randomBytes(64).toString('hex')) % q;
    if (rnd > 1n) return rnd;
  }
}

function blind({ tokenInputHex, contextId, suiteId, keyId, blindScalarHex }) {
  const { p, q, elementBytes, bigIntToFixedHex } = getModp14();
  const u = hashToGroupElement({ tokenInputHex, contextId, suiteId, keyId });
  const b = blindScalarHex
    ? (hexToBigInt(normalizeHex(blindScalarHex, { bytes: 32, label: 'blindScalar' })) % q)
    : randomBlindScalar();
  if (b <= 1n) throw new Error('blindScalar must be > 1 mod q');
  const bInv = modInv(b, q);
  const blinded = modPow(u, b, p);
  return {
    blindedElementHex: bigIntToFixedHex(blinded, elementBytes),
    // These are exponents mod q; they can be up to ~2048 bits, so encode at group element width.
    blindFactorHex: bigIntToFixedHex(b, elementBytes),
    blindFactorInvHex: bigIntToFixedHex(bInv, elementBytes)
  };
}

function evaluateBlinded({ blindedElementHex }) {
  const { p, elementBytes, bigIntToFixedHex } = getModp14();
  const { keyId, k } = getOprfKeyMaterialModp14();
  const blinded = hexToBigInt(normalizeElementHex(blindedElementHex));
  const evaluated = modPow(blinded, k, p);
  return { keyId, evaluatedElementHex: bigIntToFixedHex(evaluated, elementBytes) };
}

function unblind({ evaluatedElementHex, blindFactorInvHex }) {
  const { p, q, elementBytes, bigIntToFixedHex } = getModp14();
  const evaluated = hexToBigInt(normalizeElementHex(evaluatedElementHex));
  const inv = hexToBigInt(normalizeHex(blindFactorInvHex, { bytes: null, label: 'blindFactorInv' })) % q;
  if (inv <= 1n) throw new Error('blindFactorInv out of range');
  const unblinded = modPow(evaluated, inv, p);
  return { tokenOutputHex: bigIntToFixedHex(unblinded, elementBytes) };
}

function computeTokenOutput({ tokenInputHex, contextId, suiteId, keyId }) {
  const { p, elementBytes, bigIntToFixedHex } = getModp14();
  const { k } = getOprfKeyMaterialModp14();
  const u = hashToGroupElement({ tokenInputHex, contextId, suiteId, keyId });
  const out = modPow(u, k, p);
  return bigIntToFixedHex(out, elementBytes);
}

function verifyToken({ tokenInputHex, tokenOutputHex, contextId, suiteId, keyId }) {
  const expected = computeTokenOutput({ tokenInputHex, contextId, suiteId, keyId });
  const provided = normalizeElementHex(tokenOutputHex);
  return timingSafeEqualHex(expected, provided);
}

function timingSafeEqualHex(aHex, bHex) {
  const a = Buffer.from(aHex, 'hex');
  const b = Buffer.from(bHex, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

function deriveCommitmentHexFromTokenOutput({ tokenOutputHex, contextId, suiteId, keyId }) {
  if (!contextId) throw new Error('contextId is required');
  if (!suiteId) throw new Error('suiteId is required');
  if (!keyId) throw new Error('keyId is required');
  const out = Buffer.from(normalizeElementHex(tokenOutputHex), 'hex');
  const material = Buffer.concat([
    Buffer.from(`paapv2|commitment|${suiteId}|${keyId}|${contextId}|`, 'utf8'),
    out
  ]);
  return sha256HexBytes(material);
}

module.exports = {
  blind,
  evaluateBlinded,
  unblind,
  verifyToken,
  computeTokenOutput,
  deriveCommitmentHexFromTokenOutput,
  normalizeElementHex
};
