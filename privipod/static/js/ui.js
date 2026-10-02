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

  // datetime-local inputs have no timezone, but the server works in UTC
  static initDeadlineInputs() {
    document.querySelectorAll('input[type="datetime-local"]').forEach(input => {
      const raw = input.getAttribute('value');
      if (!raw || !/(Z|[+-]\d\d:\d\d)$/.test(raw)) return;
      const date = new Date(raw);
      if (isNaN(date)) return;
      const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
      input.value = local.toISOString().slice(0, 16);
    });
  }

  static deadlinesToUtc(form) {
    form.querySelectorAll('input[type="datetime-local"]').forEach(input => {
      if (!input.value || !input.name) return;
      const hidden = document.createElement('input');
      hidden.type = 'hidden';
      hidden.name = input.name;
      hidden.value = new Date(input.value).toISOString();
      input.removeAttribute('name');
      form.appendChild(hidden);
    });
  }

  static pollStatus(url, initial) {
    const start = Date.now();
    let timer = null;
    let inFlight = false;
    const delay = () => Math.min(10, 1 + Math.floor((Date.now() - start) / 30000)) * 1000;
    const schedule = () => {
      if (!document.hidden && timer === null && !inFlight) timer = setTimeout(poll, delay());
    };
    const poll = async () => {
      timer = null;
      inFlight = true;
      try {
        const resp = await fetch(url, { credentials: 'same-origin' });
        if (resp.status === 404) { location.reload(); return; }
        if (resp.redirected) { location.reload(); return; }
        if (resp.ok) {
          const data = await resp.json();
          if (data.status !== initial) { location.reload(); return; }
        }
      } catch (err) {
        console.error('Poll error:', err);
      } finally {
        inFlight = false;
      }
      schedule();
    };
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        clearTimeout(timer);
        timer = null;
      } else if (timer === null && !inFlight) {
        poll();
      }
    });
    schedule();
  }

  static copyToClipboard(text, msg) {
    navigator.clipboard.writeText(text)
      .then(() => PrivipodUI.showToast(msg || 'Copied!', 'success', 3000))
      .catch(() => PrivipodUI.showToast('Failed to copy to clipboard', 'error'));
  }

  static copyUrl(url) {
    PrivipodUI.copyToClipboard(url, 'Pod URL copied to clipboard!');
  }

  // Show a decrypted secret in `display`
  static async renderSecret(display, decrypted, secretType, privateKey, encryptedFilenameData, actions = null) {
    display.innerHTML = '';
    const addAction = (el) => {
      if (actions) {
        actions.prepend(el);
      } else {
        el.style.marginTop = '10px';
        display.appendChild(el);
      }
    };
    if (secretType === 'text') {
      const text = new TextDecoder().decode(decrypted);
      const ta = document.createElement('textarea');
      ta.readOnly = true;
      ta.style.cssText = 'width:100%; min-height:150px; margin-top:10px;';
      ta.value = text;
      display.appendChild(ta);
      const btn = document.createElement('button');
      btn.textContent = 'Copy to Clipboard';
      btn.onclick = () => PrivipodUI.copyToClipboard(text, 'Copied to clipboard!');
      addAction(btn);
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
      addAction(a);
    }
  }

  static getCsrfToken() {
    return document.cookie.split(';')
      .map(c => c.trim())
      .find(c => c.startsWith('csrftoken='))
      ?.split('=')[1] ?? '';
  }

  static downloadJwkFile(jwkObj, filename) {
    const blob = new Blob([JSON.stringify(jwkObj)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }
}
