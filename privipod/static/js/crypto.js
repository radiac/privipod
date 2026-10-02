class PrivipodCrypto {
  static async generateKeyPair() {
    return await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["encrypt", "decrypt"]
    );
  }

  static async exportKey(key) {
    return await crypto.subtle.exportKey("jwk", key);
  }

  static async importPublicKey(jwk) {
    return await crypto.subtle.importKey(
      "jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["encrypt"]
    );
  }

  static async importPrivateKey(jwk) {
    return await crypto.subtle.importKey(
      "jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]
    );
  }

  static base64ToBuffer(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0)).buffer;
  }

  static bufferToBase64(buffer) {
    return btoa(Array.from(new Uint8Array(buffer), b => String.fromCharCode(b)).join(''));
  }

  static async encrypt(data, publicKey) {
    const aesKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const dataBuffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const encryptedData = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, dataBuffer);
    const aesKeyData = await crypto.subtle.exportKey("raw", aesKey);
    const encryptedKey = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, aesKeyData);
    return {
      encryptedKey: PrivipodCrypto.bufferToBase64(encryptedKey),
      encryptedData: PrivipodCrypto.bufferToBase64(encryptedData),
      iv: PrivipodCrypto.bufferToBase64(iv),
    };
  }

  static async decrypt(encrypted, privateKey) {
    const aesKeyData = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" }, privateKey, PrivipodCrypto.base64ToBuffer(encrypted.encryptedKey)
    );
    const aesKey = await crypto.subtle.importKey(
      "raw", aesKeyData, { name: "AES-GCM", length: 256 }, false, ["decrypt"]
    );
    return await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: PrivipodCrypto.base64ToBuffer(encrypted.iv) },
      aesKey,
      PrivipodCrypto.base64ToBuffer(encrypted.encryptedData)
    );
  }

  // Challenge to prove the user has the key
  static async createChallenge(publicKey) {
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const ciphertext = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, publicKey, nonce);
    const hash = await crypto.subtle.digest("SHA-256", nonce);
    return {
      ciphertext: PrivipodCrypto.bufferToBase64(ciphertext),
      token: PrivipodCrypto.bytesToHex(new Uint8Array(hash)),
    };
  }

  // Decrypt a challenge with the private key and return hashed nonce.
  static async answerChallenge(ciphertextBase64, privateKey) {
    const nonce = await crypto.subtle.decrypt(
      { name: "RSA-OAEP" }, privateKey, PrivipodCrypto.base64ToBuffer(ciphertextBase64)
    );
    const hash = await crypto.subtle.digest("SHA-256", nonce);
    return PrivipodCrypto.bytesToHex(new Uint8Array(hash));
  }

  static async _pbkdf2KeyMaterial(code) {
    return await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(code), { name: "PBKDF2" }, false, ["deriveBits", "deriveKey"]
    );
  }

  // Derive AES-GCM wrapping key from access code + salt buffer
  static async deriveWrappingKey(code, saltBuffer) {
    const material = await PrivipodCrypto._pbkdf2KeyMaterial(code);
    return await crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: saltBuffer, iterations: 600000, hash: "SHA-256" },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  // Derive 32-byte verification token from access code + salt buffer; returns hex string
  static async deriveVerificationToken(code, saltBuffer) {
    const material = await PrivipodCrypto._pbkdf2KeyMaterial(code);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: saltBuffer, iterations: 600000, hash: "SHA-256" },
      material,
      256
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // Random salt as Uint8Array (16 bytes)
  static randomSalt() {
    return crypto.getRandomValues(new Uint8Array(16));
  }

  static bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  static hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }

  // Wrap a private key JWK with an AES-GCM wrapping key; returns JSON blob string
  static async wrapPrivateKey(privateKeyJwk, wrappingKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(privateKeyJwk));
    const wrapped = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, wrappingKey, data);
    return {
      wrapped: PrivipodCrypto.bufferToBase64(wrapped),
      iv: PrivipodCrypto.bufferToBase64(iv),
    };
  }

  // Unwrap a wrapped private key blob; returns private key JWK object
  static async unwrapPrivateKey(blobObj, wrappingKey) {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: PrivipodCrypto.base64ToBuffer(blobObj.iv) },
      wrappingKey,
      PrivipodCrypto.base64ToBuffer(blobObj.wrapped)
    );
    return JSON.parse(new TextDecoder().decode(decrypted));
  }

  // Pod private key localStorage (keyed by pod hash)
  static storeKey(hash, jwkObj) {
    localStorage.setItem(`privipod_key_${hash}`, JSON.stringify(jwkObj));
  }

  static getStoredKey(hash) {
    const str = localStorage.getItem(`privipod_key_${hash}`);
    return str ? JSON.parse(str) : null;
  }

  static removeKey(hash) {
    localStorage.removeItem(`privipod_key_${hash}`);
  }

  static cleanupStoredKeys(activePodHashes) {
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i);
      if (key && key.startsWith('privipod_key_')) {
        const hash = key.slice('privipod_key_'.length);
        if (!activePodHashes.has(hash)) localStorage.removeItem(key);
      }
    }
  }

  // Identity key localStorage
  static storeIdentityKey(jwkObj) {
    localStorage.setItem('privipod_identity_key', JSON.stringify(jwkObj));
  }

  static getStoredIdentityKey() {
    const str = localStorage.getItem('privipod_identity_key');
    return str ? JSON.parse(str) : null;
  }

  static removeIdentityKey() {
    localStorage.removeItem('privipod_identity_key');
  }

  // Access code sessionStorage (per pod hash or 'identity')
  static storeAccessCode(scope, code) {
    sessionStorage.setItem(`privipod_code_${scope}`, code);
  }

  static getStoredAccessCode(scope) {
    return sessionStorage.getItem(`privipod_code_${scope}`);
  }

  static removeAccessCode(scope) {
    sessionStorage.removeItem(`privipod_code_${scope}`);
  }
}
