class PrivipodAccount {
  static async initManageKeys() {
    const conf = JSON.parse(document.getElementById('pp-conf').textContent);
    const { allowServerKeys, hasServerPrivateKey, hasIdentityKey } = conf;

    if (!hasIdentityKey) {
      // No identity key yet - generate one then reload so the server gets the new key
      const banner = document.getElementById('identity-key-banner');
      if (banner) await PrivipodAccount.initIdentityKeySetup(banner);
      if (PrivipodCrypto.getStoredIdentityKey()) location.reload();
      return;
    }

    // Identity key
    const hasIdentityInBrowser = !!PrivipodCrypto.getStoredIdentityKey();
    const browserStatusEl = document.getElementById('identity-browser-status');
    if (browserStatusEl) browserStatusEl.textContent = hasIdentityInBrowser ? '✓ In browser' : '✗ Not in browser';

    const browserActionsEl = document.getElementById('identity-browser-key-actions');
    if (browserActionsEl) {
      if (hasIdentityInBrowser) {
        const btn = document.createElement('button');
        btn.className = 'button secondary';
        btn.textContent = 'Download key file';
        btn.onclick = () => PrivipodKeys.exportIdentityKeyFile();
        browserActionsEl.appendChild(btn);
      } else {
        const label = document.createElement('label');
        label.htmlFor = 'importIdentityKeyFile';
        label.textContent = 'Restore from key file: ';
        const input = document.createElement('input');
        input.type = 'file';
        input.id = 'importIdentityKeyFile';
        input.accept = '.json';
        input.addEventListener('change', async (e) => {
          const file = e.target.files[0];
          if (!file) return;
          try {
            const jwk = JSON.parse(await file.text());
            await PrivipodCrypto.importPrivateKey(jwk);
            PrivipodCrypto.storeIdentityKey(jwk);
            location.reload();
          } catch (err) {
            PrivipodUI.showToast(`Failed to import key: ${err.message}`, 'error');
          }
        });
        label.appendChild(input);
        browserActionsEl.appendChild(label);
      }
    }

    const serverActionsEl = document.getElementById('identity-server-key-actions');
    if (serverActionsEl) {
      if (hasServerPrivateKey) {
        const btn = document.createElement('button');
        btn.className = 'button danger';
        btn.textContent = 'Remove from server';
        btn.onclick = async () => {
          if (!confirm('Remove your private key from the server? It will remain in this browser only.')) return;
          const resp = await fetch('/identity/remove-private-key/', {
            method: 'POST',
            headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
            credentials: 'same-origin',
          });
          if (resp.ok) {
            location.reload();
          } else {
            PrivipodUI.showToast('Failed to remove key.', 'error');
          }
        };
        serverActionsEl.appendChild(btn);
      }
      if (!hasIdentityInBrowser && !hasServerPrivateKey) {
        const warn = document.createElement('p');
        warn.className = 'message warning';
        warn.textContent = 'Private key not found in browser or server. Others can still send you secrets (your public key is on the server), but you cannot decrypt them until the private key is recovered or a new key is generated.';
        serverActionsEl.appendChild(warn);
      }
      if (hasIdentityInBrowser && !hasServerPrivateKey && allowServerKeys) {
        serverActionsEl.appendChild(PrivipodAccount._buildAccessCodeForm('Save to server', async (code) => {
          const privateJwk = PrivipodCrypto.getStoredIdentityKey();
          if (!privateJwk) throw new Error('No private key in browser');
          await PrivipodKeys.storeIdentityKeyOnServer(privateJwk, code);
        }));
      }
      if (!hasIdentityInBrowser && hasServerPrivateKey) {
        serverActionsEl.appendChild(PrivipodAccount._buildAccessCodeForm('Load from server', async (code) => {
          const resp = await fetch('/identity/get-key/', { credentials: 'same-origin' });
          if (!resp.ok) throw new Error('Failed to fetch key from server');
          const data = await resp.json();
          if (!data.encrypted_private_key) throw new Error('No key stored on server');
          await PrivipodKeys.decryptIdentityKey(data, code);
        }));
      }
    }

    // Regenerate identity key
    const regenBtn = document.getElementById('regenerateIdentityKeyBtn');
    if (regenBtn) {
      regenBtn.onclick = async () => {
        const { pendingRecipientCount } = conf;
        let confirmMsg = 'Regenerate your identity key? This cannot be undone.';
        if (pendingRecipientCount > 0) {
          confirmMsg = `Warning: ${pendingRecipientCount} pending secret${pendingRecipientCount === 1 ? '' : 's'} sent to you will become permanently unreadable.\n\n` + confirmMsg;
        }
        if (!confirm(confirmMsg)) return;
        try {
          regenBtn.disabled = true;
          const keyPair = await PrivipodCrypto.generateKeyPair();
          const publicJwk = await PrivipodCrypto.exportKey(keyPair.publicKey);
          const privateJwk = await PrivipodCrypto.exportKey(keyPair.privateKey);

          const fd = new FormData();
          fd.append('identity_public_key', JSON.stringify(publicJwk));
          const resp = await fetch('/identity/setup/', {
            method: 'POST',
            headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
            credentials: 'same-origin',
            body: fd,
          });
          if (!resp.ok) throw new Error('Failed to update public key on server');

          // Server's public key has changed
          PrivipodCrypto.storeIdentityKey(privateJwk);

          if (hasServerPrivateKey) {
            try {
              const removeResp = await fetch('/identity/remove-private-key/', {
                method: 'POST',
                headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
                credentials: 'same-origin',
              });
              if (!removeResp.ok) throw new Error('bad status');
            } catch {
              // Old key is now stale
              sessionStorage.setItem('privipod_pending_toast', JSON.stringify({
                msg: 'Identity key regenerated, but the old key could not be removed from the server - remove it manually from Manage Keys.',
                type: 'warning',
              }));
            }
          }

          location.reload();
        } catch (err) {
          regenBtn.disabled = false;
          PrivipodUI.showToast(`Regeneration failed: ${err.message}`, 'error');
        }
      };
    }

    // Pod keys table
    document.querySelectorAll('#pod-keys-table tbody tr[data-pod-hash]').forEach(row => {
      const hash = row.dataset.podHash;
      const hasServerKey = row.dataset.hasServerKey === 'true';
      const hasBrowserKey = !!PrivipodCrypto.getStoredKey(hash);

      const browserCell = row.querySelector('.browser-key-status');
      if (browserCell) browserCell.textContent = hasBrowserKey ? '✓' : '✗';

      const actionsCell = row.querySelector('.pod-key-actions');
      if (!actionsCell) return;

      if (hasBrowserKey && !hasServerKey && allowServerKeys) {
        actionsCell.appendChild(PrivipodAccount._buildAccessCodeForm('Save to server', async (code) => {
          const privateJwk = PrivipodCrypto.getStoredKey(hash);
          if (!privateJwk) throw new Error('Key not found in browser');
          await PrivipodKeys.storeReceivePodKey(hash, privateJwk, code);
        }));
      }
      if (!hasBrowserKey && hasServerKey) {
        actionsCell.appendChild(PrivipodAccount._buildAccessCodeForm('Load from server', async (code) => {
          await PrivipodKeys.retrieveReceivePodKey(hash, code);
        }));
      }
      if (hasServerKey) {
        const btn = document.createElement('button');
        btn.className = 'button danger';
        btn.textContent = 'Remove from server';
        btn.onclick = async () => {
          if (!confirm('Remove this pod key from the server?')) return;
          const resp = await fetch(`/pod/r-${hash}/remove-key/`, {
            method: 'POST',
            headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
            credentials: 'same-origin',
          });
          if (resp.ok) {
            row.dataset.hasServerKey = 'false';
            const serverCell = row.querySelector('.server-key-status');
            if (serverCell) serverCell.textContent = '✗';
            btn.remove();
            PrivipodUI.showToast('Key removed from server.', 'success');
            if (hasBrowserKey && allowServerKeys) {
              actionsCell.appendChild(PrivipodAccount._buildAccessCodeForm('Save to server', async (code) => {
                const privateJwk = PrivipodCrypto.getStoredKey(hash);
                if (!privateJwk) throw new Error('Key not found in browser');
                await PrivipodKeys.storeReceivePodKey(hash, privateJwk, code);
              }));
            }
          } else {
            PrivipodUI.showToast('Failed to remove key.', 'error');
          }
        };
        actionsCell.appendChild(btn);
      }
    });
  }

  static _buildAccessCodeForm(buttonText, actionFn) {
    const div = document.createElement('div');
    div.className = 'key-action-form';

    const input = document.createElement('input');
    input.type = 'password';
    input.placeholder = 'Access code';
    input.autocomplete = 'off';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'button secondary';
    btn.textContent = buttonText;

    const errEl = document.createElement('span');
    errEl.className = 'message error';
    errEl.hidden = true;

    btn.onclick = async () => {
      const code = input.value.trim();
      if (!code) { PrivipodUI.showToast('Enter an access code first.', 'warning'); return; }
      try {
        btn.disabled = true;
        btn.textContent = '…';
        errEl.hidden = true;
        await actionFn(code);
        if (buttonText.toLowerCase().includes('load')) {
          sessionStorage.setItem('privipod_pending_toast', JSON.stringify({ msg: 'Loaded from server.', type: 'success' }));
        }
        location.reload();
      } catch (err) {
        btn.disabled = false;
        btn.textContent = buttonText;
        errEl.textContent = `Failed to decode key - incorrect password`;
        errEl.hidden = false;
      }
    };

    div.appendChild(input);
    div.appendChild(btn);
    div.appendChild(errEl);
    return div;
  }


  static async initDashboard() {
    const podHashes = new Set(
      Array.from(document.querySelectorAll('[data-pod-hash]')).map(el => el.dataset.podHash)
    );
    PrivipodCrypto.cleanupStoredKeys(podHashes);
    PrivipodUI.initDeadlines();

    const conf = JSON.parse(document.getElementById('pp-conf').textContent);
    if (conf.hasIdentityKey && !PrivipodCrypto.getStoredIdentityKey()) {
      const warning = document.getElementById('identity-key-missing-warning');
      if (warning) warning.hidden = false;
    }

    const banner = document.getElementById('identity-key-banner');
    if (banner) await PrivipodAccount.initIdentityKeySetup(banner);
  }

  static async initIdentityKeySetup(banner) {
    const conf = JSON.parse(document.getElementById('pp-conf').textContent);
    const closeBtn = document.getElementById('identityKeyBannerClose');
    const contentEl = document.getElementById('identity-key-banner-content');

    if (closeBtn) {
      closeBtn.addEventListener('click', async () => {
        banner.hidden = true;
        try {
          await fetch('/identity/dismiss-banner/', {
            method: 'POST',
            headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
            credentials: 'same-origin',
          });
        } catch (err) {
          console.error('Failed to dismiss identity key banner:', err);
        }
      });
    }

    if (conf.hasIdentityKey) {
      if (PrivipodCrypto.getStoredIdentityKey()) {
        banner.hidden = false;
        if (closeBtn) closeBtn.hidden = false;
      }
      return;
    }

    const generatingEl = document.getElementById('identity-key-generating');
    try {
      const keyPair = await PrivipodCrypto.generateKeyPair();
      const publicJwk = await PrivipodCrypto.exportKey(keyPair.publicKey);
      const privateJwk = await PrivipodCrypto.exportKey(keyPair.privateKey);

      const fd = new FormData();
      fd.append('identity_public_key', JSON.stringify(publicJwk));
      const resp = await fetch('/identity/setup/', {
        method: 'POST',
        headers: { 'X-CSRFToken': PrivipodUI.getCsrfToken() },
        credentials: 'same-origin',
        body: fd,
      });
      if (!resp.ok) throw new Error('Failed to save identity key');

      PrivipodCrypto.storeIdentityKey(privateJwk);

      if (contentEl) {
        contentEl.innerHTML = '';
        const p = document.createElement('p');
        p.appendChild(document.createTextNode("Your identity key has been generated. You'll want to copy this somewhere. "));
        const a = document.createElement('a');
        a.href = conf.manageKeysUrl;
        a.textContent = 'Manage keys';
        p.appendChild(a);
        contentEl.appendChild(p);
      }
      if (closeBtn) closeBtn.hidden = false;
    } catch (err) {
      console.error('Identity key setup failed:', err);
      if (generatingEl) generatingEl.textContent = 'Failed to generate identity key.';
    }
  }
}
