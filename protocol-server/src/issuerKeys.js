const crypto = require('crypto');

function getIssuerKeyId() {
  return process.env.ISSUER_KEY_ID || 'v1';
}

function loadIssuerPrivateKeyPem() {
  const fs = require('fs');
  const path = require('path');
  
  const keyPath = process.env.ISSUER_RSA_PRIVATE_KEY_PATH || 
    path.join(__dirname, '../../../backend/private_key.pem');
  
  try {
    const pem = fs.readFileSync(keyPath, 'utf8');
    if (!pem) {
      throw new Error('RSA private key file is empty');
    }
    return pem.trim();
  } catch (error) {
    throw new Error(`Failed to load RSA private key from ${keyPath}: ${error.message}`);
  }
}

let cached = null;

function getIssuerKeyMaterial() {
  if (cached) return cached;

  const keyId = getIssuerKeyId();
  const privateKeyPem = loadIssuerPrivateKeyPem();

  const privateKeyObj = crypto.createPrivateKey(privateKeyPem);
  const publicKeyObj = crypto.createPublicKey(privateKeyObj);

  const privateJwk = privateKeyObj.export({ format: 'jwk' });
  const publicJwk = publicKeyObj.export({ format: 'jwk' });

  cached = { keyId, privateKeyPem, privateJwk, publicJwk };
  return cached;
}

module.exports = {
  getIssuerKeyMaterial
};

