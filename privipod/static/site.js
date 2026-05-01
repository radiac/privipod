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

  static showToast(msg, type = 'info', duration = 5000) {
    let container = document.getElementById('ppToastContainer');
    if (!container) {
      container = document.createElement('div');
      container.id = 'ppToastContainer';
      container.className = 'toast-container';
      document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = `message toast ${type}`;
    toast.textContent = msg;
    toast.onclick = () => toast.remove();
    container.appendChild(toast);
    if (duration > 0) setTimeout(() => toast.remove(), duration);
    return toast;
  }

  static formatTimeUntil(isoString) {
    const diff = new Date(isoString) - Date.now();
    if (diff <= 0) return 'expired';
    const totalMinutes = Math.floor(diff / 60000);
    const days = Math.floor(totalMinutes / 1440);
    const hours = Math.floor((totalMinutes % 1440) / 60);
    const minutes = totalMinutes % 60;
    if (days > 0) return `in ${days}d ${hours}h`;
    if (hours > 0) return `in ${hours}h ${minutes}m`;
    return `in ${minutes}m`;
  }

  static initDeadlines() {
    document.querySelectorAll('time[data-deadline]').forEach(el => {
      el.title = el.dataset.deadline;
      el.textContent = PrivipodUI.formatTimeUntil(el.dataset.deadline);
    });
  }

  static copyToClipboard(text, msg) {
    navigator.clipboard.writeText(text)
      .then(() => PrivipodUI.showToast(msg || 'Copied!', 'success', 3000))
      .catch(() => PrivipodUI.showToast('Failed to copy to clipboard', 'error'));
  }

  static copyUrl(url) {
    PrivipodUI.copyToClipboard(url, 'Pod URL copied to clipboard!');
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

  static getCsrfToken() {
    return document.cookie.split(';')
      .map(c => c.trim())
      .find(c => c.startsWith('csrftoken='))
      ?.split('=')[1] ?? '';
  }

  static exportKeyFile(hash) {
    const jwkObj = PrivipodCrypto.getStoredKey(hash);
    if (!jwkObj) { PrivipodUI.showToast('No key found in this browser.', 'warning'); return; }
    const blob = new Blob([JSON.stringify(jwkObj)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `privipod-key-${hash}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  static initDashboard() {
    const podHashes = new Set(
      Array.from(document.querySelectorAll('tr[data-pod-hash]')).map(tr => tr.dataset.podHash)
    );
    PrivipodCrypto.cleanupStoredKeys(podHashes);
    PrivipodUI.initDeadlines();
  }

  static initCreatePod() {
    const form = document.getElementById('createPodForm');
    let keyPair = null;
    PrivipodCrypto.generateKeyPair()
      .then(kp => { keyPair = kp; })
      .catch(err => { console.error('Key generation failed:', err); });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!keyPair) { PrivipodUI.showToast('Key generation not ready yet, please try again.', 'warning'); return; }
      try {
        e.target.classList.add('loading');
        document.querySelector('input[name="public_key"]').value =
          JSON.stringify(await PrivipodCrypto.exportKey(keyPair.publicKey));
        // Hash not yet known; park private key until initOwnerPending picks it up
        sessionStorage.setItem('privipod_pending_key',
          JSON.stringify(await PrivipodCrypto.exportKey(keyPair.privateKey)));
        e.target.submit();
      } catch (err) {
        e.target.classList.remove('loading');
        PrivipodUI.showToast(`Error preparing pod: ${err.message}`, 'error');
      }
    });
  }

  static initOwnerPending() {
    const { podHash } = document.getElementById('pp-data').dataset;

    // Transfer private key parked by initCreatePod into persistent localStorage
    const pendingKey = sessionStorage.getItem('privipod_pending_key');
    if (pendingKey) {
      PrivipodCrypto.storeKey(podHash, JSON.parse(pendingKey));
      sessionStorage.removeItem('privipod_pending_key');
    }

    const pollForSecret = async () => {
      try {
        const resp = await fetch(`/pod/${podHash}/status/`, { credentials: 'same-origin' });
        if (!resp.ok) return;
        const data = await resp.json();
        if (data.status !== 'sent') return;
        location.reload();
      } catch (err) {
        console.error('Poll error:', err);
      }
    };

    const pollInterval = setInterval(pollForSecret, 1000);
    setTimeout(() => { clearInterval(pollInterval); location.reload(); }, 30000);
  }

  static async initOwnerSent() {
    const { podHash, selfDestruct } = document.getElementById('pp-data').dataset;
    const isSelfDestruct = selfDestruct === 'true';

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
      if (isSelfDestruct) {
        PrivipodCrypto.removeKey(podHash);
        fetch(`/pod/${podHash}/confirm-read/`, {
          method: 'POST',
          headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
          credentials: 'same-origin',
        }).catch(err => console.error('confirm-read failed:', err));
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

    const secretText = document.getElementById('secretText');
    const expandTextarea = () => {
      secretText.style.height = 'auto';
      secretText.style.height = secretText.scrollHeight + 'px';
    };
    secretText.addEventListener('input', expandTextarea);
    expandTextarea();

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
        data = secretText.value;
        if (!data) {
          PrivipodUI.showToast('Please enter some text', 'warning');
          secretText.focus();
          return;
        }
        document.querySelector('input[name="secret_type"]').value = 'text';
      } else {
        const fileInput = document.getElementById('secretFile');
        if (!fileInput.files.length) {
          PrivipodUI.showToast('Please select a file', 'warning');
          fileInput.focus();
          return;
        }
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
        PrivipodUI.showToast(`Encryption failed: ${err.message}`, 'error');
      }
    });
  }

  static async initPodView() {
    if (document.getElementById('pp-owner-pending')) {
      PrivipodUI.initOwnerPending();
    }
    if (document.getElementById('pp-owner-sent')) {
      await PrivipodUI.initOwnerSent();
    }
    if (document.getElementById('sendForm')) {
      await PrivipodUI.initSendForm();
    }
    PrivipodUI.initDeadlines();
  }
}


document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('#pp-messages li').forEach(li => {
    PrivipodUI.showToast(li.textContent.trim(), li.dataset.type);
  });

  document.querySelectorAll('[data-copy-url]').forEach(btn => {
    btn.addEventListener('click', () => PrivipodUI.copyUrl(btn.dataset.copyUrl));
  });
  document.querySelectorAll('[data-export-key]').forEach(btn => {
    btn.addEventListener('click', () => PrivipodUI.exportKeyFile(btn.dataset.exportKey));
  });
  document.querySelectorAll('[data-action="reload"]').forEach(btn => {
    btn.addEventListener('click', () => location.reload());
  });
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', (e) => {
      if (!confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  const body = document.body;
  if (body.classList.contains('page-dashboard')) {
    PrivipodUI.initDashboard();
  } else if (body.classList.contains('page-pod-create')) {
    PrivipodUI.initCreatePod();
  } else if (body.classList.contains('page-pod-view')) {
    PrivipodUI.initPodView();
  }
});
