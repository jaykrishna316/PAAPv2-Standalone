const hexToBigInt = (hex) => {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  return BigInt('0x' + normalized);
};

const bigIntToHex = (value) => {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = '0' + hex;
  return hex;
};

const base64UrlToBigInt = (b64url) => {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b64url.length + 3) % 4);
  const bytes = Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  let hex = '';
  bytes.forEach((b) => {
    hex += b.toString(16).padStart(2, '0');
  });
  return BigInt('0x' + hex);
};

const modPow = (base, exponent, modulus) => {
  if (modulus === 0n) throw new Error('modPow: modulus is 0');
  let result = 1n;
  let b = base % modulus;
  let e = exponent;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % modulus;
    e >>= 1n;
    b = (b * b) % modulus;
  }
  return result;
};

const egcd = (a, b) => {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return { g: oldR, x: oldS };
};

const modInv = (a, modulus) => {
  const { g, x } = egcd((a % modulus + modulus) % modulus, modulus);
  if (g !== 1n && g !== -1n) throw new Error('modInv: inverse does not exist');
  return (x % modulus + modulus) % modulus;
};

const getRandomBytes = (len) => {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
};

const bytesToHex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');

const randomBigIntBelow = (modulus) => {
  const hexLen = modulus.toString(16).length;
  const byteLen = Math.ceil(hexLen / 2);
  const rnd = getRandomBytes(byteLen);
  const r = BigInt('0x' + bytesToHex(rnd));
  return r % modulus;
};

export const generateCommitmentHex = () => bytesToHex(getRandomBytes(32));

export const blindCommitment = async (commitmentHex, publicJwk) => {
  if (!publicJwk?.n || !publicJwk?.e) throw new Error('Missing issuer public key');
  const n = base64UrlToBigInt(publicJwk.n);
  const e = base64UrlToBigInt(publicJwk.e);

  const C = hexToBigInt(commitmentHex);
  if (C <= 0n || C >= n) throw new Error('Commitment out of range');

  let r;
  while (true) {
    r = randomBigIntBelow(n);
    if (r <= 1n) continue;
    try {
      modInv(r, n);
      break;
    } catch {
      // retry
    }
  }

  const rPowE = modPow(r, e, n);
  const blinded = (C * rPowE) % n;

  return {
    blindedCommitmentHex: bigIntToHex(blinded),
    unblindFactorHex: bigIntToHex(r)
  };
};

export const unblindSignature = async (blindSignatureHex, unblindFactorHex, publicJwk) => {
  if (!publicJwk?.n) throw new Error('Missing issuer public key');
  const n = base64UrlToBigInt(publicJwk.n);
  const r = hexToBigInt(unblindFactorHex);
  const rinv = modInv(r, n);
  const Sblind = hexToBigInt(blindSignatureHex);
  const S = (Sblind * rinv) % n;
  return bigIntToHex(S);
};

// -----------------------------
// OPRF (MODP14) client helpers
// -----------------------------

const normalizeHex = (hex, { bytes, label }) => {
  if (typeof hex !== 'string') throw new Error(`${label} must be a hex string`);
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (!/^[0-9a-fA-F]+$/.test(normalized)) throw new Error(`${label} must be hex`);
  if (bytes != null && normalized.length !== bytes * 2) throw new Error(`${label} must be ${bytes} bytes hex`);
  return normalized.toLowerCase();
};

const padHexToBytes = (hex, bytes) => {
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  return normalized.padStart(bytes * 2, '0');
};

const bigIntToFixedHex = (value, bytes) => padHexToBytes(bigIntToHex(value), bytes);

const sha256HexUtf8 = async (s) => {
  const data = new TextEncoder().encode(s);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(digest));
};

const sha256HexBytes = async (bytes) => {
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(digest));
};

export const generateTokenInputHex = () => bytesToHex(getRandomBytes(32));

export const oprfBlindModp14 = async ({ tokenInputHex, contextId, issuer, blindScalarHex }) => {
  const suiteId = issuer?.suiteId;
  const keyId = issuer?.keyId;
  const group = issuer?.group;
  if (!suiteId || !keyId || !group?.primeHex || !group?.generatorHex) throw new Error('Missing issuer OPRF parameters');
  if (!contextId) throw new Error('contextId is required');

  const p = hexToBigInt(normalizeHex(group.primeHex, { bytes: null, label: 'primeHex' }));
  const q = (p - 1n) / 2n;
  const elementBytes = group.elementBytes || Math.ceil(group.primeHex.length / 2);

  const input = normalizeHex(tokenInputHex, { bytes: 32, label: 'tokenInput' });

  let u = null;
  for (let ctr = 0; ctr < 8; ctr += 1) {
    const material = `paapv2|oprf|${suiteId}|${keyId}|${contextId}|${ctr}|` + input;
    const h = hexToBigInt(await sha256HexUtf8(material)) % p;
    const candidate = (h * h) % p;
    if (candidate !== 0n && candidate !== 1n) {
      u = candidate;
      break;
    }
  }
  if (u == null) throw new Error('Failed to hash to group element');

  let b;
  if (blindScalarHex) {
    b = hexToBigInt(normalizeHex(blindScalarHex, { bytes: 32, label: 'blindScalar' })) % q;
    if (b <= 1n) throw new Error('blindScalar must be > 1 mod q');
  } else {
    while (true) {
      b = BigInt('0x' + bytesToHex(getRandomBytes(64))) % q;
      if (b > 1n) break;
    }
  }
  const bInv = modInv(b, q);

  const blinded = modPow(u, b, p);
  return {
    blindedElementHex: bigIntToFixedHex(blinded, elementBytes),
    blindFactorInvHex: bigIntToFixedHex(bInv, elementBytes)
  };
};

export const oprfUnblindModp14 = async ({ evaluatedElementHex, blindFactorInvHex, issuer }) => {
  const group = issuer?.group;
  if (!group?.primeHex) throw new Error('Missing issuer OPRF parameters');
  const p = hexToBigInt(normalizeHex(group.primeHex, { bytes: null, label: 'primeHex' }));
  const q = (p - 1n) / 2n;
  const elementBytes = group.elementBytes || Math.ceil(group.primeHex.length / 2);

  const evaluated = hexToBigInt(normalizeHex(evaluatedElementHex, { bytes: null, label: 'evaluatedElement' }));
  if (evaluated <= 1n || evaluated >= p) throw new Error('evaluatedElement out of range');

  const inv = hexToBigInt(normalizeHex(blindFactorInvHex, { bytes: null, label: 'blindFactorInv' })) % q;
  if (inv <= 1n) throw new Error('blindFactorInv out of range');
  const unblinded = modPow(evaluated, inv, p);
  return { tokenOutputHex: bigIntToFixedHex(unblinded, elementBytes) };
};

export const oprfDeriveCommitmentHex = async ({ tokenOutputHex, contextId, issuer }) => {
  const suiteId = issuer?.suiteId;
  const keyId = issuer?.keyId;
  const group = issuer?.group;
  if (!suiteId || !keyId || !group?.elementBytes) throw new Error('Missing issuer metadata');
  if (!contextId) throw new Error('contextId is required');

  const outHex = padHexToBytes(normalizeHex(tokenOutputHex, { bytes: null, label: 'tokenOutput' }), group.elementBytes);
  const outBytes = Uint8Array.from(outHex.match(/.{1,2}/g).map((b) => parseInt(b, 16)));
  const prefix = new TextEncoder().encode(`paapv2|commitment|${suiteId}|${keyId}|${contextId}|`);
  const material = new Uint8Array(prefix.length + outBytes.length);
  material.set(prefix, 0);
  material.set(outBytes, prefix.length);
  return sha256HexBytes(material);
};
