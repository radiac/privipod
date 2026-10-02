class PrivipodSend {
  static async initCreate() {
    const conf = JSON.parse(document.getElementById('pp-conf').textContent);
    const { allowServerKeys, podHash } = conf;

    const recipientSelect = document.getElementById('id_recipient_username');
    const recipientKeyStatus = document.getElementById('recipientKeyStatus');
    const anonSection = document.getElementById('anonAccessCodeSection')
      || document.getElementById('anonKeyfileSection');
    const secretText = document.getElementById('secretText');
    if (secretText) {
      const expand = () => { secretText.style.height = 'auto'; secretText.style.height = secretText.scrollHeight + 'px'; };
      secretText.addEventListener('input', expand);
      expand();
    }

    document.querySelectorAll('input[name="input_type"]').forEach(radio => {
      radio.addEventListener('change', (e) => {
        document.getElementById('textInput').style.display = e.target.value === 'text' ? 'block' : 'none';
        document.getElementById('fileInput').style.display = e.target.value === 'file' ? 'block' : 'none';
      });
    });

    // Generate anon keypair once on load - hash is fixed, no need to regenerate on recipient change
    const anonKeyPair = await PrivipodCrypto.generateKeyPair();
    let recipientPublicKey = null;

    const updateRecipient = async () => {
      const username = recipientSelect.value;
      recipientPublicKey = null;
      recipientSelect.disabled = true;

      if (!username) {
        if (anonSection) anonSection.hidden = false;
        if (recipientKeyStatus) recipientKeyStatus.hidden = true;
        recipientSelect.disabled = false;
      } else {
        if (anonSection) anonSection.hidden = true;
        if (recipientKeyStatus) {
          recipientKeyStatus.hidden = false;
          recipientKeyStatus.textContent = 'Fetching recipient key…';
          recipientKeyStatus.className = '';
        }
        try {
          const resp = await fetch(`/user/${encodeURIComponent(username)}/public-key/`, {
            credentials: 'same-origin',
          });
          if (!resp.ok) throw new Error('User has no identity key set up');
          const data = await resp.json();
          recipientPublicKey = await PrivipodCrypto.importPublicKey(data.public_key);
          if (recipientKeyStatus) {
            recipientKeyStatus.textContent = `Ready - will encrypt with ${username}'s key`;
            recipientKeyStatus.className = 'message success';
          }
        } catch (err) {
          recipientPublicKey = null;
          if (recipientKeyStatus) {
            recipientKeyStatus.textContent = `Cannot send: ${err.message}`;
            recipientKeyStatus.className = 'message error';
          }
        } finally {
          recipientSelect.disabled = false;
        }
      }
    };

    if (recipientSelect) {
      recipientSelect.addEventListener('change', updateRecipient);
      await updateRecipient();
    }

    document.getElementById('sendPodForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const submitBtn = document.getElementById('sendPodSubmit');
      if (submitBtn) submitBtn.disabled = true;

      const username = recipientSelect ? recipientSelect.value : '';
      const isAnon = !username;

      if (!isAnon && !recipientPublicKey) {
        PrivipodUI.showToast('Recipient key not available - cannot encrypt.', 'error');
        if (submitBtn) submitBtn.disabled = false;
        return;
      }

      // For anon pods with server keys, require and wrap the access code now
      if (isAnon && allowServerKeys) {
        const code = document.getElementById('sendCreateAccessCode')?.value.trim();
        if (!code) {
          PrivipodUI.showToast('Enter an access code for the recipient.', 'warning');
          if (submitBtn) submitBtn.disabled = false;
          return;
        }
        try {
          const privateJwk = await PrivipodCrypto.exportKey(anonKeyPair.privateKey);
          const salt1 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(podHash + ':verify'));
          const salt2 = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(podHash + ':encrypt'));
          const [token, wrappingKey] = await Promise.all([
            PrivipodCrypto.deriveVerificationToken(code, salt1),
            PrivipodCrypto.deriveWrappingKey(code, salt2),
          ]);
          const blob = await PrivipodCrypto.wrapPrivateKey(privateJwk, wrappingKey);
          document.querySelector('input[name="encrypted_private_key"]').value = JSON.stringify(blob);
          document.querySelector('input[name="verification_token"]').value = token;
        } catch (err) {
          PrivipodUI.showToast(`Key wrapping failed: ${err.message}`, 'error');
          if (submitBtn) submitBtn.disabled = false;
          return;
        }
      } else if (isAnon && !allowServerKeys) {
        // No server-side key storage available
        try {
          const privateJwk = await PrivipodCrypto.exportKey(anonKeyPair.privateKey);
          PrivipodUI.downloadJwkFile(privateJwk, `privipod-key-${podHash}.json`);
          const { ciphertext, token } = await PrivipodCrypto.createChallenge(anonKeyPair.publicKey);
          document.querySelector('input[name="read_challenge"]').value = JSON.stringify({ ciphertext });
          document.querySelector('input[name="verification_token"]').value = token;
        } catch (err) {
          PrivipodUI.showToast(`Key export failed: ${err.message}`, 'error');
          if (submitBtn) submitBtn.disabled = false;
          return;
        }
      }

      const publicKeyForEncrypt = isAnon ? anonKeyPair.publicKey : recipientPublicKey;
      const inputType = document.querySelector('input[name="input_type"]:checked').value;
      let data;

      if (inputType === 'text') {
        data = document.getElementById('secretText').value;
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
        const encFn = await PrivipodCrypto.encrypt(file.name, publicKeyForEncrypt);
        document.querySelector('input[name="encrypted_filename"]').value = JSON.stringify(encFn);
      }

      try {
        e.target.classList.add('loading');
        const encrypted = await PrivipodCrypto.encrypt(data, publicKeyForEncrypt);
        document.querySelector('input[name="encrypted_secret"]').value = JSON.stringify(encrypted);
        PrivipodUI.deadlinesToUtc(e.target);
        e.target.submit();
      } catch (err) {
        e.target.classList.remove('loading');
        if (submitBtn) submitBtn.disabled = false;
        PrivipodUI.showToast(`Error: ${err.message}`, 'error');
      }
    });
  }

  static async initView() {
    const conf = JSON.parse(document.getElementById('pp-conf').textContent);
    PrivipodUI.initDeadlines();

    if (conf.isOwner) {
      const storeBtn = document.getElementById('storeKeyBtn');
      if (storeBtn) {
        storeBtn.addEventListener('click', async () => {
          const fileInput = document.getElementById('storeKeyFile');
          const code = document.getElementById('storeKeyCode')?.value.trim();
          const successEl = document.getElementById('storeKeySuccess');
          if (!fileInput || !fileInput.files.length) {
            PrivipodUI.showToast('Select the key file you downloaded when creating this pod.', 'warning');
            return;
          }
          if (!code) {
            PrivipodUI.showToast('Enter an access code for the recipient.', 'warning');
            return;
          }
          storeBtn.disabled = true;
          try {
            const jwk = JSON.parse(await fileInput.files[0].text());
            await PrivipodKeys.storeSendPodKey(conf.podHash, jwk, code);
            if (successEl) successEl.hidden = false;
          } catch (err) {
            PrivipodUI.showToast(`Failed to store key: ${err.message}`, 'error');
          } finally {
            storeBtn.disabled = false;
          }
        });
      }

      if (conf.isPending) {
        PrivipodUI.pollStatus(`/pod/s-${conf.podHash}/status/`, 'pending');
      }
      return;
    }

    // Recipient view
    if (!conf.isAnon) {
      await PrivipodSend.initRecipientAuth(conf);
    } else if (conf.hasServerKey) {
      await PrivipodSend.initRecipientAnon(conf);
    } else {
      await PrivipodSend.initRecipientAnonKeyImport(conf);
    }
  }

  static async initRecipientAuth(conf) {
    const { podHash, selfDestruct, secretType } = conf;
    const encryptedSecretEl = document.getElementById('encrypted-secret-data');
    const encFilenameEl = document.getElementById('encrypted-filename-data');
    const display = document.getElementById('secretDisplay');
    const identitySection = document.getElementById('identityKeySection');
    const decryptingEl = document.getElementById('identityKeyDecrypting');
    const codePromptEl = document.getElementById('identityKeyCodePrompt');
    const codeInput = document.getElementById('identityAccessCode');
    const codeSubmit = document.getElementById('identityAccessCodeSubmit');
    const keyError = document.getElementById('identityKeyError');
    const importPromptEl = document.getElementById('identityKeyImportPrompt');
    const importFileEl = document.getElementById('importIdentityKeyFile');

    if (!encryptedSecretEl) return;
    const encryptedSecret = JSON.parse(encryptedSecretEl.textContent);
    const encryptedFilename = encFilenameEl ? JSON.parse(encFilenameEl.textContent) : null;

    const decryptAndShow = async (privateKey) => {
      const decrypted = await PrivipodCrypto.decrypt(encryptedSecret, privateKey);
      if (display) {
        display.hidden = false;
        await PrivipodUI.renderSecret(display, decrypted, secretType, privateKey, encryptedFilename);
      }
      if (identitySection) identitySection.hidden = true;
      await fetch(`/pod/s-${podHash}/confirm-read/`, {
        method: 'POST',
        headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
        credentials: 'same-origin',
      }).catch(() => { });
    };

    // Try to retrieve key automatically
    try {
      const privateKey = await PrivipodKeys.retrieveIdentityKey(conf);
      if (privateKey) {
        await decryptAndShow(privateKey);
        return;
      }
    } catch { }

    // Need user input
    if (decryptingEl) decryptingEl.hidden = true;

    // Try server encrypted key
    const serverResp = await fetch('/identity/get-key/', { credentials: 'same-origin' });
    const serverData = serverResp.ok ? await serverResp.json() : null;

    if (serverData && serverData.encrypted_private_key) {
      if (codePromptEl) codePromptEl.hidden = false;
      codeSubmit?.addEventListener('click', async () => {
        const code = codeInput?.value.trim();
        if (!code) return;
        try {
          codeSubmit.disabled = true;
          const privateKey = await PrivipodKeys.decryptIdentityKey(serverData, code);
          await decryptAndShow(privateKey);
        } catch (err) {
          codeSubmit.disabled = false;
          if (keyError) { keyError.textContent = 'Wrong access code.'; keyError.hidden = false; }
        }
      });
    } else {
      if (importPromptEl) importPromptEl.hidden = false;
    }

    importFileEl?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      try {
        const jwk = JSON.parse(await file.text());
        const privateKey = await PrivipodCrypto.importPrivateKey(jwk);
        PrivipodCrypto.storeIdentityKey(jwk);
        await decryptAndShow(privateKey);
      } catch (err) {
        if (keyError) { keyError.textContent = `Failed: ${err.message}`; keyError.hidden = false; }
      }
    });
  }

  static async initRecipientAnon(conf) {
    const { podHash, secretType } = conf;
    const display = document.getElementById('secretDisplay');
    const codeInput = document.getElementById('accessCode');
    const codeSubmit = document.getElementById('accessCodeSubmit');
    const codeError = document.getElementById('accessCodeError');

    const decryptAndShow = async (privateKey, encryptedSecret, encryptedFilename, token = null) => {
      const decrypted = await PrivipodCrypto.decrypt(encryptedSecret, privateKey);
      if (display) {
        display.hidden = false;
        await PrivipodUI.renderSecret(display, decrypted, secretType, privateKey, encryptedFilename);
      }
      document.getElementById('accessCodeSection')?.remove();
      const fd = new FormData();
      if (token) fd.append('verification_token', token);
      await fetch(`/pod/s-${podHash}/confirm-read/`, {
        method: 'POST',
        headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
        credentials: 'same-origin',
        body: fd,
      }).catch(() => { });
    };

    codeInput?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); codeSubmit?.click(); }
    });

    codeSubmit?.addEventListener('click', async () => {
      const code = codeInput?.value.trim();
      if (!code) { PrivipodUI.showToast('Enter your access code.', 'warning'); return; }

      try {
        codeSubmit.disabled = true;
        if (codeError) codeError.hidden = true;

        // Salts are derived from the pod hash - deterministic, same as the sender used
        const salt1Buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(podHash + ':verify'));
        const token = await PrivipodCrypto.deriveVerificationToken(code, salt1Buf);

        const fd = new FormData();
        fd.append('verification_token', token);
        const resp = await fetch(`/pod/s-${podHash}/verify/`, {
          method: 'POST',
          headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
          credentials: 'same-origin',
          body: fd,
        });
        const result = await resp.json();

        if (!resp.ok) {
          if (result.error?.includes('locked')) {
            const section = document.getElementById('accessCodeSection');
            if (section) {
              section.innerHTML = '<div class="message error"><strong>Pod locked</strong> - too many failed access attempts. Ask the sender to unlock it before trying again.</div>';
            }
            return;
          }
          codeSubmit.disabled = false;
          const msg = result.remaining !== undefined
            ? `Wrong access code. ${result.remaining} attempt(s) remaining.`
            : (result.error || 'Wrong access code.');
          if (codeError) { codeError.textContent = msg; codeError.hidden = false; }
          if (codeInput) { codeInput.value = ''; codeInput.focus(); }
          return;
        }

        // Derive wrapping key from code + hash-derived salt2
        const salt2Buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(podHash + ':encrypt'));
        const wrappingKey = await PrivipodCrypto.deriveWrappingKey(code, salt2Buf);
        const encPrivBlob = JSON.parse(result.encrypted_private_key);
        const privateJwk = await PrivipodCrypto.unwrapPrivateKey(encPrivBlob, wrappingKey);
        const privateKey = await PrivipodCrypto.importPrivateKey(privateJwk);

        PrivipodCrypto.storeAccessCode(podHash, code);
        await decryptAndShow(privateKey, result.encrypted_secret, result.encrypted_filename || null, token);

      } catch (err) {
        codeSubmit.disabled = false;
        if (codeError) { codeError.textContent = `Error: ${err.message}`; codeError.hidden = false; }
      }
    });
  }

  static async initRecipientAnonKeyImport(conf) {
    const { podHash, selfDestruct, secretType } = conf;
    const encryptedSecretEl = document.getElementById('encrypted-secret-data');
    const encFilenameEl = document.getElementById('encrypted-filename-data');
    const challengeEl = document.getElementById('read-challenge-data');
    const display = document.getElementById('secretDisplay');
    const importFileEl = document.getElementById('importKeyFile');

    if (!encryptedSecretEl || !importFileEl) return;
    const encryptedSecret = JSON.parse(encryptedSecretEl.textContent);
    const encryptedFilename = encFilenameEl ? JSON.parse(encFilenameEl.textContent) : null;
    const readChallenge = challengeEl ? JSON.parse(challengeEl.textContent) : null;

    importFileEl.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      try {
        const jwk = JSON.parse(await file.text());
        const privateKey = await PrivipodCrypto.importPrivateKey(jwk);
        const decrypted = await PrivipodCrypto.decrypt(encryptedSecret, privateKey);
        if (display) {
          display.hidden = false;
          await PrivipodUI.renderSecret(display, decrypted, secretType, privateKey, encryptedFilename);
        }
        const fd = new FormData();
        if (readChallenge) {
          const token = await PrivipodCrypto.answerChallenge(readChallenge.ciphertext, privateKey);
          fd.append('verification_token', token);
        }
        await fetch(`/pod/s-${podHash}/confirm-read/`, {
          method: 'POST',
          headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
          credentials: 'same-origin',
          body: fd,
        }).catch(() => { });
      } catch (err) {
        PrivipodUI.showToast(`Decryption failed: ${err.message}`, 'error');
      }
    });
  }
}
