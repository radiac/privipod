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
}


class PrivipodUI {

  static copyToClipboard(text, msg) {
    navigator.clipboard.writeText(text)
      .then(() => alert(msg || 'Copied!'))
      .catch(() => alert('Failed to copy to clipboard'));
  }

  static copyUrl(url) {
    this.copyToClipboard(url, 'Pod URL copied to clipboard!');
  }

  static async renderSecret(display, decrypted, secretType, privateKey, encryptedFilenameData) {
    display.innerHTML = '';
    if (secretType === 'text') {
      const text = new TextDecoder().decode(decrypted);
      const ta = document.createElement('textarea');
      ta.readOnly = true;
      ta.style.cssText = 'width:100%; min-height:150px; margin-top:10px;';
      ta.value = text;
      display.appendChild(ta);
      const btn = document.createElement('button');
      btn.style.marginTop = '10px';
      btn.textContent = 'Copy to Clipboard';
      btn.onclick = () => PrivipodUI.copyToClipboard(text, 'Copied to clipboard!');
      display.appendChild(btn);
    } else {
      let filename = 'file';
      if (encryptedFilenameData) {
        try {
          const fnBytes = await PrivipodCrypto.decrypt(encryptedFilenameData, privateKey);
          filename = new TextDecoder().decode(fnBytes);
        } catch (fnErr) {
          console.error('Filename decryption failed:', fnErr);
        }
      }
      const blob = new Blob([decrypted]);
      const url = URL.createObjectURL(blob);
      const p = document.createElement('p');
      const strong = document.createElement('strong');
      strong.textContent = 'File: ';
      p.appendChild(strong);
      p.appendChild(document.createTextNode(filename));
      display.appendChild(p);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.className = 'button';
      a.textContent = 'Download File';
      display.appendChild(a);
    }
  }

  static exportKeyFile(hash) {
    const jwkObj = PrivipodCrypto.getStoredKey(hash);
    if (!jwkObj) { alert('No key found in this browser.'); return; }
    const blob = new Blob([JSON.stringify(jwkObj)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `privipod-key-${hash}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  static initCreatePod(podHash) {
    let keyPair = null;
    PrivipodCrypto.generateKeyPair()
      .then(kp => { keyPair = kp; })
      .catch(err => { console.error('Key generation failed:', err); });

    document.getElementById('createPodForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!keyPair) { alert('Key generation not ready yet, please try again.'); return; }
      try {
        document.querySelector('input[name="public_key"]').value =
          JSON.stringify(await PrivipodCrypto.exportKey(keyPair.publicKey));
        PrivipodCrypto.storeKey(podHash, await PrivipodCrypto.exportKey(keyPair.privateKey));
        e.target.submit();
      } catch (err) {
        alert(`Error preparing pod: ${err.message}`);
      }
    });
  }

  static async initOwnerPending(podHash, selfDestruct) {
    const display = document.getElementById('secretDisplay');
    const storedJwk = PrivipodCrypto.getStoredKey(podHash);
    if (!storedJwk || selfDestruct) {
      setTimeout(() => location.reload(), 30000);
      return;
    }
    const privateKey = await PrivipodCrypto.importPrivateKey(storedJwk);

    const pollForSecret = async () => {
      try {
        const resp = await fetch(`/pod/${podHash}/status/`, { credentials: 'same-origin' });
        if (!resp.ok) return;
        const data = await resp.json();
        if (data.status !== 'sent') return;
        clearInterval(pollInterval);
        const decrypted = await PrivipodCrypto.decrypt(data.encrypted_secret, privateKey);
        await PrivipodUI.renderSecret(display, decrypted, data.secret_type, privateKey, data.encrypted_filename || null);
        display.style.display = 'block';
      } catch (err) {
        console.error('Poll error:', err);
      }
    };

    const pollInterval = setInterval(pollForSecret, 1000);
    setTimeout(() => { clearInterval(pollInterval); location.reload(); }, 30000);
  }

  static async initOwnerSent(podHash, selfDestruct) {
    const secretType = document.getElementById('pod-secret-type').dataset.type;
    const encryptedSecret = JSON.parse(document.getElementById('encrypted-secret-data').textContent);
    const encFilenameEl = document.getElementById('encrypted-filename-data');
    const display = document.getElementById('secretDisplay');
    const keyRecovery = document.getElementById('keyRecovery');
    const keyActions = document.getElementById('keyActions');

    const showError = (msg) => {
      display.innerHTML = '';
      const p = document.createElement('p');
      p.className = 'message error';
      p.textContent = msg;
      display.appendChild(p);
    };

    const decryptAndDisplay = async (privateKey) => {
      const decrypted = await PrivipodCrypto.decrypt(encryptedSecret, privateKey);
      const encryptedFilename = encFilenameEl ? JSON.parse(encFilenameEl.textContent) : null;
      await PrivipodUI.renderSecret(display, decrypted, secretType, privateKey, encryptedFilename);
      keyRecovery.style.display = 'none';
      if (selfDestruct) {
        PrivipodCrypto.removeKey(podHash);
      } else {
        keyActions.style.display = 'block';
      }
    };

    const storedJwk = PrivipodCrypto.getStoredKey(podHash);
    if (storedJwk) {
      try {
        await decryptAndDisplay(await PrivipodCrypto.importPrivateKey(storedJwk));
      } catch {
        display.innerHTML = '';
        keyRecovery.style.display = 'block';
      }
    } else {
      display.innerHTML = '';
      keyRecovery.style.display = 'block';
    }

    document.getElementById('importKeyFile').addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      try {
        const jwkObj = JSON.parse(await file.text());
        const privateKey = await PrivipodCrypto.importPrivateKey(jwkObj);
        await decryptAndDisplay(privateKey);
        PrivipodCrypto.storeKey(podHash, jwkObj);
      } catch (err) {
        showError(`Decryption failed: ${err.message}`);
      }
    });
  }

  static async initSendForm() {
    const jwk = JSON.parse(document.getElementById('public-key-data').textContent);
    const cachedPublicKey = await PrivipodCrypto.importPublicKey(jwk);

    document.querySelectorAll('input[name="input_type"]').forEach(radio => {
      radio.addEventListener('change', (e) => {
        document.getElementById('textInput').style.display = e.target.value === 'text' ? 'block' : 'none';
        document.getElementById('fileInput').style.display = e.target.value === 'file' ? 'block' : 'none';
      });
    });

    document.getElementById('sendForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const inputType = document.querySelector('input[name="input_type"]:checked').value;
      let data;
      if (inputType === 'text') {
        data = document.getElementById('secretText').value;
        if (!data) { alert('Please enter some text'); return; }
        document.querySelector('input[name="secret_type"]').value = 'text';
      } else {
        const fileInput = document.getElementById('secretFile');
        if (!fileInput.files.length) { alert('Please select a file'); return; }
        const file = fileInput.files[0];
        data = await file.arrayBuffer();
        document.querySelector('input[name="secret_type"]').value = 'file';
        const encryptedFilename = await PrivipodCrypto.encrypt(file.name, cachedPublicKey);
        document.querySelector('input[name="encrypted_filename"]').value = JSON.stringify(encryptedFilename);
      }
      try {
        e.target.classList.add('loading');
        const encrypted = await PrivipodCrypto.encrypt(data, cachedPublicKey);
        document.querySelector('input[name="encrypted_data"]').value = JSON.stringify(encrypted);
        e.target.submit();
      } catch (err) {
        e.target.classList.remove('loading');
        alert(`Encryption failed: ${err.message}`);
      }
    });
  }
}
