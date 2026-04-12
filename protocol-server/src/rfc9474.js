const crypto = require('crypto');
const { hexToBigInt, bigIntToHex, base64UrlToBigInt } = require('./bigint');

/**
 * RFC 9474 Blind RSA with PSS Encoding
 * Implements standardized blind signature scheme
 */

function generateKeyPair(bits = 2048) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  return { privateKey, publicKey };
}

function getJwkFromPem(pem) {
  const key = pem.startsWith('-----BEGIN PUBLIC KEY') 
    ? crypto.createPublicKey(pem)
    : crypto.createPrivateKey(pem);
  return key.export({ format: 'jwk' });
}

function blindingFactor(modulus) {
  // Generate a random blinding factor r such that 1 < r < n and gcd(r, n) = 1
  const n = BigInt(modulus);
  while (true) {
    const r = BigInt('0x' + crypto.randomBytes(256).toString('hex')) % n;
    if (r > 1n) {
      // Simple check: try to compute inverse
      try {
        const inv = modInverse(r, n);
        if (inv !== null) return r;
      } catch (e) {
        continue;
      }
    }
  }
}

function modInverse(a, m) {
  // Extended Euclidean algorithm
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];

  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }

  if (old_r > 1n) return null; // Not invertible

  return old_s % m;
}

function modPow(base, exponent, modulus) {
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

function encodeMessageEMSAPSS(message, emLen, saltLength = 32) {
  // EMSA-PSS encoding as per RFC 8017
  const hLen = 32; // SHA-256
  const sLen = saltLength;

  if (emLen < hLen + sLen + 2) {
    throw new Error('Encoding error');
  }

  // Generate random salt
  const salt = crypto.randomBytes(sLen);

  // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt
  const mHash = crypto.createHash('sha256').update(message).digest();
  const mPrime = Buffer.concat([Buffer.alloc(8), mHash, salt]);

  // H = Hash(M')
  const h = crypto.createHash('sha256').update(mPrime).digest();

  // PS = string of (emLen - sLen - hLen - 2) zero bytes
  const ps = Buffer.alloc(emLen - sLen - hLen - 2, 0);

  // DB = PS || 0x01 || salt
  const db = Buffer.concat([ps, Buffer.from([0x01]), salt]);

  // DBMask = MGF(H, emLen - hLen - 1)
  const dbMask = mgf1(h, emLen - hLen - 1);

  // MaskedDB = DB xor DBMask
  const maskedDb = Buffer.alloc(db.length);
  for (let i = 0; i < db.length; i++) {
    maskedDb[i] = db[i] ^ dbMask[i];
  }

  // Set leftmost bits to zero
  const leftmostBits = 8 * emLen - emLen * 8;
  maskedDb[0] &= 0xFF >>> (8 + leftmostBits - emLen * 8);

  // EM = MaskedDB || H || 0xbc
  const em = Buffer.concat([maskedDb, h, Buffer.from([0xbc])]);

  return em;
}

function mgf1(seed, maskLen) {
  // MGF1 as per RFC 8017
  const hLen = 32;
  const T = Buffer.alloc(0);
  const counterMax = Math.ceil(maskLen / hLen);

  for (let counter = 0; counter < counterMax; counter++) {
    const C = Buffer.alloc(4);
    C.writeUInt32BE(counter, 0);
    const hash = crypto.createHash('sha256').update(Buffer.concat([seed, C])).digest();
    const T = Buffer.concat([T, hash]);
  }

  return T.slice(0, maskLen);
}

/**
 * Blind operation - client side
 * Takes a message and returns blinded message and blinding factor
 */
function blind(message, publicKeyPem) {
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const jwk = publicKey.export({ format: 'jwk' });
  const n = base64UrlToBigInt(jwk.n);
  const e = base64UrlToBigInt(jwk.e);

  // Convert message to buffer if string
  const msgBuffer = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;

  // Encode with EMSA-PSS
  const k = (n.toString(2).length + 7) >> 3; // Length in bytes
  const em = encodeMessageEMSAPSS(msgBuffer, k);

  // Convert EM to integer
  const m = BigInt('0x' + em.toString('hex'));

  // Generate blinding factor
  const r = blindingFactor(n);

  // Compute blinded message: m' = m * r^e mod n
  const rE = modPow(r, e, n);
  const blinded = (m * rE) % n;

  return {
    blindedMessageHex: bigIntToHex(blinded),
    blindingFactorHex: bigIntToHex(r)
  };
}

/**
 * BlindSign operation - server side
 * Takes blinded message and signs it
 */
function blindSign(blindedMessageHex, privateKeyPem) {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const jwk = privateKey.export({ format: 'jwk' });
  const n = base64UrlToBigInt(jwk.n);
  const d = base64UrlToBigInt(jwk.d);

  const blinded = hexToBigInt(blindedMessageHex);

  // Compute blinded signature: s' = (m')^d mod n
  const blindedSignature = modPow(blinded, d, n);

  return {
    blindedSignatureHex: bigIntToHex(blindedSignature)
  };
}

/**
 * Finalize operation - client side
 * Takes blinded signature and blinding factor, returns final signature
 */
function finalize(blindedSignatureHex, blindingFactorHex, publicKeyPem) {
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const jwk = publicKey.export({ format: 'jwk' });
  const n = base64UrlToBigInt(jwk.n);
  const e = base64UrlToBigInt(jwk.e);

  const blindedSig = hexToBigInt(blindedSignatureHex);
  const r = hexToBigInt(blindingFactorHex);

  // Compute r inverse
  const rInv = modInverse(r, n);
  if (rInv === null) {
    throw new Error('Cannot compute modular inverse');
  }

  // Compute final signature: s = s' * r^(-1) mod n
  const signature = (blindedSig * rInv) % n;

  return {
    signatureHex: bigIntToHex(signature)
  };
}

/**
 * Verify operation
 * Takes message and signature, returns true if valid
 */
function verify(message, signatureHex, publicKeyPem) {
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const jwk = publicKey.export({ format: 'jwk' });
  const n = base64UrlToBigInt(jwk.n);
  const e = base64UrlToBigInt(jwk.e);

  // Convert message to buffer if string
  const msgBuffer = typeof message === 'string' ? Buffer.from(message, 'utf8') : message;

  // Encode with EMSA-PSS
  const k = (n.toString(2).length + 7) >> 3;
  const em = encodeMessageEMSAPSS(msgBuffer, k);
  const m = BigInt('0x' + em.toString('hex'));

  const signature = hexToBigInt(signatureHex);

  // Verify: m == s^e mod n
  const recovered = modPow(signature, e, n);

  return recovered === m;
}

/**
 * Convert JWK to PEM format using Node.js crypto
 */
function getPemFromJwk(jwk) {
  if (!jwk || !jwk.n || !jwk.e) {
    throw new Error('Invalid JWK');
  }
  
  // Use Node.js crypto to create proper PEM from JWK
  const publicKeyObject = crypto.createPublicKey({
    format: 'jwk',
    key: jwk
  });
  
  return publicKeyObject.export({
    type: 'spki',
    format: 'pem'
  });
}

module.exports = {
  generateKeyPair,
  getJwkFromPem,
  getPemFromJwk,
  blind,
  blindSign,
  finalize,
  verify
};
