function hexToBigInt(hex) {
  if (typeof hex !== 'string' || hex.length === 0) throw new Error('Invalid hex');
  const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
  return BigInt('0x' + normalized);
}

function bigIntToHex(value) {
  let hex = value.toString(16);
  if (hex.length % 2 === 1) hex = '0' + hex;
  return hex;
}

function base64UrlToBigInt(b64url) {
  const padded = b64url.replace(/-/g, '+').replace(/_/g, '/')
    + '==='.slice((b64url.length + 3) % 4);
  const buf = Buffer.from(padded, 'base64');
  return BigInt('0x' + buf.toString('hex'));
}

function modPow(base, exponent, modulus) {
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
}

function egcd(a, b) {
  let oldR = a;
  let r = b;
  let oldS = 1n;
  let s = 0n;
  let oldT = 0n;
  let t = 1n;

  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
    [oldT, t] = [t, oldT - q * t];
  }

  return { g: oldR, x: oldS, y: oldT };
}

function modInv(a, modulus) {
  const { g, x } = egcd((a % modulus + modulus) % modulus, modulus);
  if (g !== 1n && g !== -1n) throw new Error('modInv: inverse does not exist');
  return (x % modulus + modulus) % modulus;
}

module.exports = {
  hexToBigInt,
  bigIntToHex,
  base64UrlToBigInt,
  modPow,
  modInv
};
