class PrivipodKeys {
  static exportKeyFile(hash) {
    const jwkObj = PrivipodCrypto.getStoredKey(hash);
    if (!jwkObj) { PrivipodUI.showToast('No key found in this browser.', 'warning'); return; }
    PrivipodUI.downloadJwkFile(jwkObj, `privipod-key-${hash}.json`);
  }

  static exportIdentityKeyFile() {
    const jwkObj = PrivipodCrypto.getStoredIdentityKey();
    if (!jwkObj) { PrivipodUI.showToast('No identity key found in this browser.', 'warning'); return; }
    PrivipodUI.downloadJwkFile(jwkObj, 'privipod-identity-key.json');
  }

  static async storeIdentityKeyOnServer(privateJwk, code) {
    const salt = PrivipodCrypto.randomSalt();
    const wrappingKey = await PrivipodCrypto.deriveWrappingKey(code, salt);
    const blob = await PrivipodCrypto.wrapPrivateKey(privateJwk, wrappingKey);

    const fd = new FormData();
    fd.append('encrypted_identity_private_key', JSON.stringify(blob));
    fd.append('identity_key_salt', PrivipodCrypto.bytesToHex(salt));
    const resp = await fetch('/identity/setup/', {
      method: 'POST',
      headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
      credentials: 'same-origin',
      body: fd,
    });
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      throw new Error(data.error || 'Server error');
    }
  }

  // Retrieve and decrypt identity private key; returns privateKey CryptoKey or null
  static async retrieveIdentityKey(conf) {
    // Try localStorage first
    const storedJwk = PrivipodCrypto.getStoredIdentityKey();
    if (storedJwk) {
      try { return await PrivipodCrypto.importPrivateKey(storedJwk); } catch { }
    }

    // Try server
    const resp = await fetch('/identity/get-key/', { credentials: 'same-origin' });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (!data.encrypted_private_key) return null;

    // Try stored access code
    const storedCode = PrivipodCrypto.getStoredAccessCode('identity');
    if (storedCode) {
      try {
        const key = await PrivipodKeys.decryptIdentityKey(data, storedCode);
        if (key) return key;
      } catch { }
    }

    return null;  // caller must prompt for access code
  }

  static async decryptIdentityKey(serverData, code) {
    const salt = PrivipodCrypto.hexToBytes(serverData.salt);
    const wrappingKey = await PrivipodCrypto.deriveWrappingKey(code, salt);
    const blob = JSON.parse(serverData.encrypted_private_key);
    const jwk = await PrivipodCrypto.unwrapPrivateKey(blob, wrappingKey);
    PrivipodCrypto.storeIdentityKey(jwk);
    PrivipodCrypto.storeAccessCode('identity', code);
    return await PrivipodCrypto.importPrivateKey(jwk);
  }

  static async storeReceivePodKey(podHash, privateJwk, code) {
    // Salt derived from pod hash (deterministic - no need to store)
    const saltBuf = await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(podHash + ":encrypt")
    );
    const wrappingKey = await PrivipodCrypto.deriveWrappingKey(code, saltBuf);
    const blob = await PrivipodCrypto.wrapPrivateKey(privateJwk, wrappingKey);

    const fd = new FormData();
    fd.append('encrypted_private_key', JSON.stringify(blob));
    const resp = await fetch(`/pod/r-${podHash}/store-key/`, {
      method: 'POST',
      headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
      credentials: 'same-origin',
      body: fd,
    });
    if (!resp.ok) throw new Error((await resp.json()).error || 'Unknown error');
  }

  static async retrieveReceivePodKey(podHash, code) {
    const resp = await fetch(`/pod/r-${podHash}/get-key/`, { credentials: 'same-origin' });
    if (!resp.ok) throw new Error('Failed to retrieve key from server');
    const data = await resp.json();
    if (!data.encrypted_private_key) throw new Error('No key stored on server');

    const saltBuf = await crypto.subtle.digest(
      "SHA-256", new TextEncoder().encode(podHash + ":encrypt")
    );
    const wrappingKey = await PrivipodCrypto.deriveWrappingKey(code, saltBuf);
    const blob = JSON.parse(data.encrypted_private_key);
    const jwk = await PrivipodCrypto.unwrapPrivateKey(blob, wrappingKey);
    PrivipodCrypto.storeKey(podHash, jwk);
    PrivipodCrypto.storeAccessCode(podHash, code);
    return await PrivipodCrypto.importPrivateKey(jwk);
  }

  static async storeSendPodKey(podHash, privateJwk, code) {
    // Salts derived from hash - deterministic, same as what the recipient will derive
    const salt1Buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(podHash + ':verify'));
    const salt2Buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(podHash + ':encrypt'));

    const [token, wrappingKey] = await Promise.all([
      PrivipodCrypto.deriveVerificationToken(code, salt1Buf),
      PrivipodCrypto.deriveWrappingKey(code, salt2Buf),
    ]);
    const blob = await PrivipodCrypto.wrapPrivateKey(privateJwk, wrappingKey);

    const fd = new FormData();
    fd.append('verification_token', token);
    fd.append('encrypted_private_key', JSON.stringify(blob));
    const resp = await fetch(`/pod/s-${podHash}/store-key/`, {
      method: 'POST',
      headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
      credentials: 'same-origin',
      body: fd,
    });
    if (!resp.ok) throw new Error((await resp.json()).error || 'Unknown error');
  }
}
