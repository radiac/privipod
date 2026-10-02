
class PrivipodReceive {
  static initCreate() {
    const form = document.getElementById('createPodForm');
    const keyPairPromise = PrivipodCrypto.generateKeyPair();

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      try {
        e.target.classList.add('loading');
        const keyPair = await keyPairPromise;
        document.querySelector('input[name="public_key"]').value =
          JSON.stringify(await PrivipodCrypto.exportKey(keyPair.publicKey));
        sessionStorage.setItem('privipod_pending_key',
          JSON.stringify(await PrivipodCrypto.exportKey(keyPair.privateKey)));
        PrivipodUI.deadlinesToUtc(e.target);
        e.target.submit();
      } catch (err) {
        e.target.classList.remove('loading');
        PrivipodUI.showToast(`Error preparing pod: ${err.message}`, 'error');
      }
    });
  }

  static initOwnerPending() {
    const conf = JSON.parse(document.getElementById('pp-conf').textContent);
    const { podHash } = conf;

    // Transfer private key parked by initCreatePod into persistent localStorage
    const pendingKey = sessionStorage.getItem('privipod_pending_key');
    if (pendingKey) {
      PrivipodCrypto.storeKey(podHash, JSON.parse(pendingKey));
      sessionStorage.removeItem('privipod_pending_key');
    }

    PrivipodReceive.initKeyManage(podHash);
    PrivipodUI.pollStatus(`/pod/r-${podHash}/status/`, 'pending');
  }

  static initKeyManage(podHash) {
    const box = document.getElementById('keyManage');
    if (!box || !PrivipodCrypto.getStoredKey(podHash)) return;
    box.hidden = false;

    const storeKeyForm = document.getElementById('storeKeyForm');
    const storeKeyCode = document.getElementById('storeKeyCode');
    const storeKeyBtn = document.getElementById('storeKeyBtn');
    const storeKeySuccess = document.getElementById('storeKeySuccess');
    if (!storeKeyBtn) return;

    storeKeyBtn.addEventListener('click', async () => {
      const code = storeKeyCode.value.trim();
      if (!code) { PrivipodUI.showToast('Enter an access code first.', 'warning'); return; }
      const privateJwk = PrivipodCrypto.getStoredKey(podHash);
      if (!privateJwk) { PrivipodUI.showToast('Private key not found in this browser.', 'error'); return; }
      try {
        storeKeyBtn.disabled = true;
        await PrivipodKeys.storeReceivePodKey(podHash, privateJwk, code);
        PrivipodCrypto.storeAccessCode(podHash, code);
        storeKeyForm.remove();
        storeKeySuccess.hidden = false;
      } catch (err) {
        storeKeyBtn.disabled = false;
        PrivipodUI.showToast(`Failed to store key: ${err.message}`, 'error');
      }
    });
  }

  static async initOwnerReceived() {
    const conf = JSON.parse(document.getElementById('pp-conf').textContent);
    const { podHash, selfDestruct, hasServerKey } = conf;
    const isSelfDestruct = selfDestruct === true || selfDestruct === 'true';

    const secretType = document.getElementById('pod-secret-type').dataset.type;
    const encryptedSecret = JSON.parse(document.getElementById('encrypted-secret-data').textContent);
    const encFilenameEl = document.getElementById('encrypted-filename-data');
    const display = document.getElementById('secretDisplay');
    const keyRecovery = document.getElementById('keyRecovery');

    const showError = (msg) => {
      display.innerHTML = '';
      const p = document.createElement('p');
      p.className = 'message error';
      p.textContent = msg;
      display.appendChild(p);
    };

    // Pass jwk when the key came from a file, to keep it once it has proved to work
    const decryptAndDisplay = async (privateKey, jwk = null) => {
      const decrypted = await PrivipodCrypto.decrypt(encryptedSecret, privateKey);
      const encryptedFilename = encFilenameEl ? JSON.parse(encFilenameEl.textContent) : null;
      await PrivipodUI.renderSecret(
        display, decrypted, secretType, privateKey, encryptedFilename,
        document.getElementById('secretActions'),
      );
      keyRecovery.style.display = 'none';
      try {
        await fetch(`/pod/r-${podHash}/confirm-read/`, {
          method: 'POST',
          headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
          credentials: 'same-origin',
        });
      } catch (err) {
        console.error('confirm-read failed:', err);
      }
      if (isSelfDestruct) {
        PrivipodCrypto.removeKey(podHash);
      } else {
        if (jwk) PrivipodCrypto.storeKey(podHash, jwk);
        PrivipodReceive.initKeyManage(podHash);
      }
    };

    // Try localStorage first
    const storedJwk = PrivipodCrypto.getStoredKey(podHash);
    if (storedJwk) {
      try {
        await decryptAndDisplay(await PrivipodCrypto.importPrivateKey(storedJwk));
        return;
      } catch {
        // Fall through to key recovery
      }
    }

    // No key in localStorage - show recovery UI
    display.innerHTML = '';
    keyRecovery.style.display = 'block';

    // Server key retrieval
    const retrieveBtn = document.getElementById('retrieveKeyBtn');
    const retrieveCode = document.getElementById('retrieveKeyCode');
    const retrieveError = document.getElementById('retrieveKeyError');

    if (retrieveBtn) {
      // Try stored access code silently first
      const storedCode = PrivipodCrypto.getStoredAccessCode(podHash);
      if (storedCode && hasServerKey) {
        try {
          const privateKey = await PrivipodKeys.retrieveReceivePodKey(podHash, storedCode);
          await decryptAndDisplay(privateKey);
          return;
        } catch {
          // Stored code failed - prompt user
        }
      }

      retrieveBtn.addEventListener('click', async () => {
        const code = retrieveCode.value.trim();
        if (!code) { PrivipodUI.showToast('Enter your access code.', 'warning'); return; }
        try {
          retrieveBtn.disabled = true;
          if (retrieveError) retrieveError.hidden = true;
          const privateKey = await PrivipodKeys.retrieveReceivePodKey(podHash, code);
          await decryptAndDisplay(privateKey);
        } catch (err) {
          retrieveBtn.disabled = false;
          if (retrieveError) {
            retrieveError.textContent = `Failed: ${err.message}`;
            retrieveError.hidden = false;
          }
        }
      });
    }

    // Key file import
    document.getElementById('importKeyFile')?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      try {
        const jwkObj = JSON.parse(await file.text());
        const privateKey = await PrivipodCrypto.importPrivateKey(jwkObj);
        await decryptAndDisplay(privateKey, jwkObj);
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
      const submitBtn = e.target.querySelector('[type="submit"]');
      if (submitBtn) submitBtn.disabled = true;
      const inputType = document.querySelector('input[name="input_type"]:checked').value;
      let data;
      if (inputType === 'text') {
        data = secretText.value;
        if (!data) {
          PrivipodUI.showToast('Please enter some text', 'warning');
          if (submitBtn) submitBtn.disabled = false;
          return;
        }
        document.querySelector('input[name="secret_type"]').value = 'text';
      } else {
        const fileInput = document.getElementById('secretFile');
        if (!fileInput.files.length) {
          PrivipodUI.showToast('Please select a file', 'warning');
          if (submitBtn) submitBtn.disabled = false;
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
        if (submitBtn) submitBtn.disabled = false;
        PrivipodUI.showToast(`Encryption failed: ${err.message}`, 'error');
      }
    });
  }

  static async initView() {
    if (document.getElementById('pp-owner-pending')) {
      PrivipodReceive.initOwnerPending();
    }
    if (document.getElementById('pp-owner-received')) {
      await PrivipodReceive.initOwnerReceived();
    }
    if (document.getElementById('sendForm')) {
      await PrivipodReceive.initSendForm();
    }
    PrivipodUI.initDeadlines();
  }
}
