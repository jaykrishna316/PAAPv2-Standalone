const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { getAuditLogger } = require('./auditLogger');

/**
 * Key rotation mechanism with multi-key support
 * Supports multiple active keys during rotation window
 */

class KeyManager {
  constructor(options = {}) {
    this.keysDir = options.keysDir || path.join(process.cwd(), 'keys');
    this.currentKeyId = options.currentKeyId || 'v1';
    this.rotationWindowDays = options.rotationWindowDays || 7;
    this.keys = new Map();
    this.logger = getAuditLogger();
    
    this.ensureKeysDirectory();
    this.loadKeys();
  }

  ensureKeysDirectory() {
    if (!fs.existsSync(this.keysDir)) {
      fs.mkdirSync(this.keysDir, { recursive: true });
    }
  }

  generateKeyId() {
    const timestamp = Date.now();
    return `key-${timestamp}`;
  }

  generateKeyPair(keyId) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
      },
      privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
      }
    });

    return {
      keyId,
      privateKey,
      publicKey,
      createdAt: new Date().toISOString(),
      status: 'active'
    };
  }

  saveKey(keyData) {
    const privateKeyPath = path.join(this.keysDir, `${keyData.keyId}-private.pem`);
    const publicKeyPath = path.join(this.keysDir, `${keyData.keyId}-public.pem`);
    const metadataPath = path.join(this.keysDir, `${keyData.keyId}-metadata.json`);

    fs.writeFileSync(privateKeyPath, keyData.privateKey);
    fs.writeFileSync(publicKeyPath, keyData.publicKey);
    fs.writeFileSync(metadataPath, JSON.stringify({
      keyId: keyData.keyId,
      createdAt: keyData.createdAt,
      status: keyData.status,
      rotationWindowEnds: keyData.rotationWindowEnds
    }, null, 2));
  }

  loadKeys() {
    try {
      const files = fs.readdirSync(this.keysDir);
      const metadataFiles = files.filter(f => f.endsWith('-metadata.json'));

      for (const metadataFile of metadataFiles) {
        const metadataPath = path.join(this.keysDir, metadataFile);
        const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
        const privateKeyPath = path.join(this.keysDir, `${metadata.keyId}-private.pem`);
        const publicKeyPath = path.join(this.keysDir, `${metadata.keyId}-public.pem`);

        if (fs.existsSync(privateKeyPath) && fs.existsSync(publicKeyPath)) {
          this.keys.set(metadata.keyId, {
            ...metadata,
            privateKey: fs.readFileSync(privateKeyPath, 'utf8'),
            publicKey: fs.readFileSync(publicKeyPath, 'utf8')
          });
        }
      }
    } catch (error) {
      this.logger.warn('key_load_error', { error: error.message });
    }
  }

  getCurrentKey() {
    return this.keys.get(this.currentKeyId);
  }

  getKey(keyId) {
    return this.keys.get(keyId);
  }

  getAllActiveKeys() {
    const activeKeys = [];
    const now = new Date();

    for (const [keyId, keyData] of this.keys) {
      if (keyData.status === 'active') {
        activeKeys.push(keyData);
      }
      
      // Include keys in rotation window
      if (keyData.rotationWindowEnds) {
        const windowEnd = new Date(keyData.rotationWindowEnds);
        if (now < windowEnd) {
          activeKeys.push(keyData);
        }
      }
    }

    return activeKeys;
  }

  createNewKey() {
    const newKeyId = this.generateKeyId();
    const keyPair = this.generateKeyPair(newKeyId);
    this.keys.set(newKeyId, keyPair);
    this.currentKeyId = newKeyId; // Set as current key
    this.saveKey(keyPair);
    this.logger.info('key_created', { keyId: newKeyId });
    return keyPair;
  }

  rotateKey() {
    const currentKey = this.getCurrentKey();
    if (!currentKey) {
      throw new Error('No current key found');
    }

    const newKey = this.createNewKey();
    
    // Set rotation window for old key
    const rotationWindowEnd = new Date();
    rotationWindowEnd.setDate(rotationWindowEnd.getDate() + this.rotationWindowDays);
    
    currentKey.rotationWindowEnds = rotationWindowEnd.toISOString();
    this.saveKey(currentKey);

    // Update current key ID
    this.currentKeyId = newKey.keyId;
    
    this.logger.logKeyRotation(currentKey.keyId, newKey.keyId);
    
    return {
      oldKey: currentKey,
      newKey
    };
  }

  verifyKeyId(keyId) {
    const activeKeys = this.getAllActiveKeys();
    return activeKeys.some(key => key.keyId === keyId);
  }

  getPublicKeyJwk(keyId) {
    const key = this.getKey(keyId);
    if (!key) {
      return null;
    }

    const publicKey = crypto.createPublicKey(key.publicKey);
    return publicKey.export({ format: 'jwk' });
  }

  getAllPublicKeys() {
    const publicKeys = [];
    
    for (const [keyId, keyData] of this.keys) {
      if (keyData.status === 'active' || keyData.rotationWindowEnds) {
        publicKeys.push({
          keyId,
          publicKeyJwk: this.getPublicKeyJwk(keyId),
          createdAt: keyData.createdAt,
          status: keyData.status,
          rotationWindowEnds: keyData.rotationWindowEnds
        });
      }
    }

    return publicKeys;
  }

  revokeKey(keyId) {
    const key = this.getKey(keyId);
    if (!key) {
      throw new Error('Key not found');
    }

    key.status = 'revoked';
    this.saveKey(key);
    this.logger.warn('key_revoked', { keyId });
  }

  cleanupOldKeys(daysOld = 30) {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    let cleanedCount = 0;

    for (const [keyId, keyData] of this.keys) {
      const createdDate = new Date(keyData.createdAt);
      
      if (keyData.status === 'revoked' && createdDate < cutoffDate) {
        // Delete key files
        const privateKeyPath = path.join(this.keysDir, `${keyId}-private.pem`);
        const publicKeyPath = path.join(this.keysDir, `${keyId}-public.pem`);
        const metadataPath = path.join(this.keysDir, `${keyId}-metadata.json`);

        fs.unlinkSync(privateKeyPath);
        fs.unlinkSync(publicKeyPath);
        fs.unlinkSync(metadataPath);

        this.keys.delete(keyId);
        cleanedCount++;
      }
    }

    this.logger.info('key_cleanup', { cleanedCount });
    return cleanedCount;
  }
}

// Singleton instance
let keyManagerInstance = null;

function getKeyManager(options) {
  if (!keyManagerInstance) {
    keyManagerInstance = new KeyManager(options);
  }
  return keyManagerInstance;
}

module.exports = {
  KeyManager,
  getKeyManager
};
