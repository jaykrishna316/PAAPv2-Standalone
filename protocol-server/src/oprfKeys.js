const crypto = require('crypto');
const { hexToBigInt, bigIntToHex } = require('./bigint');
const { getModp14 } = require('./modp14');

function getIssuerKeyId() {
  return process.env.ISSUER_KEY_ID || 'v1';
}

function normalizeScalarHex(hex) {
  if (typeof hex !== 'string' || hex.length === 0) throw new Error('Invalid scalar hex');
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]+$/.test(normalized)) throw new Error('Invalid scalar hex');
  return normalized.toLowerCase();
}

function randomScalarBelow(modulus) {
  // 2048-bit modulus => 256 bytes is a reasonable draw.
  while (true) {
    const rnd = BigInt('0x' + crypto.randomBytes(256).toString('hex')) % modulus;
    if (rnd > 1n) return rnd;
  }
}

let cached = null;

function getOprfKeyMaterialModp14() {
  if (cached) return cached;

  const { q, g, p, bigIntToFixedHex, elementBytes } = getModp14();
  const keyId = getIssuerKeyId();

  // Production should set a stable secret. Demo can fall back to ephemeral.
  const env = process.env.ISSUER_OPRF_MODP14_K_HEX || process.env.ISSUER_OPRF_K_HEX;
  const k = env ? (hexToBigInt(normalizeScalarHex(env)) % q) : randomScalarBelow(q);
  if (k <= 1n) throw new Error('Issuer OPRF key must be > 1 mod q');

  const publicKey = crypto.createHash('sha256') // not used for crypto; just a stable keyId-like fingerprint
    .update(bigIntToHex(k), 'utf8')
    .digest('hex')
    .slice(0, 12);

  // Expose g^k as a public point-like element for diagnostics (not used by current verifier path).
  const y = modPowCompat(g, k, p);
  const publicKeyHex = bigIntToFixedHex(y, elementBytes);

  cached = { keyId, k, publicKeyHex, publicKeyFingerprint: publicKey };
  return cached;
}

function modPowCompat(base, exponent, modulus) {
  // Avoid circular require: bigint.js depends on nothing, but keep this local tiny helper.
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
}

module.exports = {
  getOprfKeyMaterialModp14
};

