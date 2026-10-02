document.addEventListener('DOMContentLoaded', () => {
  document.querySelectorAll('#pp-messages li').forEach(li => {
    PrivipodUI.showToast(li.textContent.trim(), li.dataset.type);
  });
  const pendingToast = sessionStorage.getItem('privipod_pending_toast');
  if (pendingToast) {
    sessionStorage.removeItem('privipod_pending_toast');
    try {
      const { msg, type } = JSON.parse(pendingToast);
      PrivipodUI.showToast(msg, type);
    } catch (_) { }
  }

  document.querySelectorAll('[data-copy-url]').forEach(btn => {
    btn.addEventListener('click', () => PrivipodUI.copyUrl(btn.dataset.copyUrl));
  });
  document.querySelectorAll('[data-export-key]').forEach(btn => {
    btn.addEventListener('click', () => PrivipodKeys.exportKeyFile(btn.dataset.exportKey));
  });
  document.querySelectorAll('form[data-confirm]').forEach(form => {
    form.addEventListener('submit', (e) => {
      if (!confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  PrivipodUI.initDeadlineInputs();

  const body = document.body;
  let init = null;
  if (body.classList.contains('page-dashboard')) {
    init = PrivipodAccount.initDashboard();
  } else if (body.classList.contains('page-pod-create')) {
    init = PrivipodReceive.initCreate();
  } else if (body.classList.contains('page-pod-view')) {
    init = PrivipodReceive.initView();
  } else if (body.classList.contains('page-send-create')) {
    init = PrivipodSend.initCreate();
  } else if (body.classList.contains('page-send-view')) {
    init = PrivipodSend.initView();
  } else if (body.classList.contains('page-manage-keys')) {
    init = PrivipodAccount.initManageKeys();
  }

  // Flag when the page's JS is set up and ready for input - used by e2e tests
  Promise.resolve(init)
    .catch(err => console.error('Page init failed:', err))
    .finally(() => { document.documentElement.dataset.ppReady = 'true'; });
});
