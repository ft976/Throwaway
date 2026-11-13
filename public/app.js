'use strict';

(function () {
  const STORAGE_KEY = 'throwaway_inbox_v1';
  const POLL_INTERVAL_SEC = 5;
  const BACKOFF_INTERVAL_SEC = 15;
  const WARNING_THRESHOLD_MS = 120000;
  const BASE_TITLE = 'Throwaway — Disposable Temporary Email';

  const USERNAME_REGEX = /^[a-z0-9](?:[a-z0-9._-]{1,28})[a-z0-9]$/;
  const RESERVED_USERNAMES = new Set([
    'admin',
    'administrator',
    'root',
    'postmaster',
    'abuse',
    'hostmaster',
    'webmaster',
    'support',
    'noreply',
    'no-reply',
    'security',
    'info',
    'mail',
  ]);

  const els = {
    addressInput: document.getElementById('address-input'),
    copyBtn: document.getElementById('copy-btn'),
    refreshBtn: document.getElementById('refresh-btn'),
    refreshIcon: document.getElementById('refresh-icon'),
    changeBtn: document.getElementById('change-btn'),
    deleteAddressBtn: document.getElementById('delete-address-btn'),
    extendBtn: document.getElementById('extend-btn'),
    expiryText: document.getElementById('expiry-text'),
    expiryProgress: document.getElementById('expiry-progress'),
    pollText: document.getElementById('poll-text'),
    noticeBanner: document.getElementById('notice-banner'),
    liveAnnouncer: document.getElementById('live-announcer'),
    notifyBtn: document.getElementById('notify-btn'),
    inboxSection: document.getElementById('inbox-section'),
    inboxCount: document.getElementById('inbox-count'),
    emptyState: document.getElementById('empty-state'),
    messageList: document.getElementById('message-list'),
    messageView: document.getElementById('message-view'),
    backBtn: document.getElementById('back-btn'),
    deleteMsgBtn: document.getElementById('delete-msg-btn'),
    msgSubject: document.getElementById('msg-subject'),
    msgFrom: document.getElementById('msg-from'),
    msgDate: document.getElementById('msg-date'),
    msgAttachments: document.getElementById('msg-attachments'),
    attachmentsList: document.getElementById('attachments-list'),
    modeHtmlBtn: document.getElementById('mode-html-btn'),
    modeTextBtn: document.getElementById('mode-text-btn'),
    imageGuard: document.getElementById('image-guard'),
    loadImagesBtn: document.getElementById('load-images-btn'),
    messageIframe: document.getElementById('message-iframe'),
    messagePlain: document.getElementById('message-plain'),
    changeDialog: document.getElementById('change-dialog'),
    changeForm: document.getElementById('change-form'),
    changeCloseBtn: document.getElementById('change-close-btn'),
    changeCancelBtn: document.getElementById('change-cancel-btn'),
    usernameInput: document.getElementById('username-input'),
    domainSelect: document.getElementById('domain-select'),
    changeError: document.getElementById('change-error'),
    randomNameBtn: document.getElementById('random-name-btn'),
    changeSubmitBtn: document.getElementById('change-submit-btn'),
    deleteDialog: document.getElementById('delete-dialog'),
    deleteForm: document.getElementById('delete-form'),
    deleteCloseBtn: document.getElementById('delete-close-btn'),
    deleteCancelBtn: document.getElementById('delete-cancel-btn'),
    deleteConfirmBtn: document.getElementById('delete-confirm-btn'),
    abuseLink: document.getElementById('abuse-link'),
    inboxTokenInput: document.getElementById('inbox-token-input'),
    toggleTokenBtn: document.getElementById('toggle-token-btn'),
    copyTokenBtn: document.getElementById('copy-token-btn'),
    rotateTokenBtn: document.getElementById('rotate-token-btn'),
    apiCurlPreview: document.getElementById('api-curl-preview'),
    copyCurlBtn: document.getElementById('copy-curl-btn'),
    apiKeyForm: document.getElementById('api-key-form'),
    apiKeyLabel: document.getElementById('api-key-label'),
    createKeyBtn: document.getElementById('create-key-btn'),
    apiKeyResult: document.getElementById('api-key-result'),
    apiKeyOutput: document.getElementById('api-key-output'),
    copyKeyBtn: document.getElementById('copy-key-btn'),
    revokeKeyBtn: document.getElementById('revoke-key-btn'),
    apiKeyMeta: document.getElementById('api-key-meta'),
  };

  const state = {
    inbox: null, // { address, token, expiresAt, ttlMs }
    domains: [],
    messages: [],
    knownIds: new Set(),
    etag: null,
    activeMessage: null,
    viewerMode: 'html',
    imagesLoaded: false,
    pollRemainingSec: POLL_INTERVAL_SEC,
    pollDelaySec: POLL_INTERVAL_SEC,
    isFetching: false,
    notificationsEnabled: false,
    copyTimer: null,
    tokenRevealed: false,
    activeApiKey: null,
    lastPollAt: 0,
  };

  const WINDOW_NAME_PREFIX = 'THROWAWAY_STATE:';

  function saveInboxToStorage(inbox, messages = state.messages) {
    if (!inbox) {
      try { window.localStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
      try { window.sessionStorage.removeItem(STORAGE_KEY); } catch { /* ignore */ }
      try {
        if (typeof window.name === 'string' && window.name.startsWith(WINDOW_NAME_PREFIX)) {
          window.name = '';
        }
      } catch { /* ignore */ }
      return;
    }

    const serialized = JSON.stringify({
      address: inbox.address,
      token: inbox.token,
      expiresAt: inbox.expiresAt,
      ttlMs: inbox.ttlMs,
      messages: Array.isArray(messages) ? messages.slice(0, 50) : [],
    });

    try { window.localStorage.setItem(STORAGE_KEY, serialized); } catch { /* ignore */ }
    try { window.sessionStorage.setItem(STORAGE_KEY, serialized); } catch { /* ignore */ }
    try { window.name = WINDOW_NAME_PREFIX + serialized; } catch { /* ignore */ }
  }

  function loadInboxFromStorage() {
    const candidates = [];
    try {
      const ls = window.localStorage.getItem(STORAGE_KEY);
      if (ls) candidates.push(ls);
    } catch { /* ignore */ }
    try {
      const ss = window.sessionStorage.getItem(STORAGE_KEY);
      if (ss) candidates.push(ss);
    } catch { /* ignore */ }
    try {
      if (typeof window.name === 'string' && window.name.startsWith(WINDOW_NAME_PREFIX)) {
        candidates.push(window.name.slice(WINDOW_NAME_PREFIX.length));
      }
    } catch { /* ignore */ }

    for (const raw of candidates) {
      try {
        const parsed = JSON.parse(raw);
        if (parsed && parsed.address && parsed.token && parsed.expiresAt && parsed.expiresAt > Date.now()) {
          return parsed;
        }
      } catch {
        // Try next storage fallback
      }
    }
    return null;
  }

  function showNotice(message, isError = false) {
    if (!message) {
      els.noticeBanner.hidden = true;
      els.noticeBanner.textContent = '';
      els.noticeBanner.classList.remove('is-error');
      return;
    }
    els.noticeBanner.textContent = message;
    els.noticeBanner.classList.toggle('is-error', isError);
    els.noticeBanner.hidden = false;
  }

  function announce(text) {
    els.liveAnnouncer.textContent = '';
    window.setTimeout(() => {
      els.liveAnnouncer.textContent = text;
    }, 50);
  }

  function validateUsernameClient(raw) {
    const username = String(raw || '').trim().toLowerCase();
    if (!username) {
      return { valid: false, error: 'Enter a username or click Random.' };
    }
    if (username.length < 3 || username.length > 30) {
      return { valid: false, error: 'Username must be 3 to 30 characters.' };
    }
    if (username.includes('..')) {
      return { valid: false, error: 'Username cannot contain consecutive dots.' };
    }
    if (!USERNAME_REGEX.test(username)) {
      return {
        valid: false,
        error: 'Use only a-z, 0-9, dots, underscores, or hyphens; start and end with a letter or number.',
      };
    }
    if (RESERVED_USERNAMES.has(username)) {
      return { valid: false, error: 'This username is reserved and cannot be used.' };
    }
    return { valid: true, username };
  }

  function generateRandomUsername(length = 10) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    let out = '';
    for (let i = 0; i < length; i += 1) {
      out += alphabet[bytes[i] % alphabet.length];
    }
    return out;
  }

  function formatCountdown(ms) {
    const totalSec = Math.max(0, Math.ceil(ms / 1000));
    const minutes = Math.floor(totalSec / 60);
    const seconds = totalSec % 60;
    return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')} left`;
  }

  function formatShortDate(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  function formatFullDate(iso) {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return '';
    return d.toLocaleString([], {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  }

  function formatBytes(bytes) {
    const num = Number(bytes) || 0;
    if (num < 1024) return `${num} B`;
    if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
    return `${(num / (1024 * 1024)).toFixed(1)} MB`;
  }

  function updateTabTitle() {
    const unreadCount = state.messages.filter((m) => !m.read).length;
    if (document.hidden && unreadCount > 0) {
      document.title = `(${unreadCount}) Throwaway`;
    } else {
      document.title = BASE_TITLE;
    }
  }

  function updateExpiryUI() {
    if (!state.inbox) {
      els.expiryText.textContent = '--:-- left';
      els.expiryProgress.style.transform = 'scaleX(0)';
      return;
    }

    const remainingMs = Math.max(0, state.inbox.expiresAt - Date.now());
    const totalMs = state.inbox.ttlMs || 60 * 60 * 1000;
    const ratio = Math.max(0, Math.min(1, remainingMs / totalMs));
    const isWarning = remainingMs <= WARNING_THRESHOLD_MS;

    els.expiryText.textContent = formatCountdown(remainingMs);
    els.expiryText.classList.toggle('is-warning', isWarning);
    els.expiryProgress.classList.toggle('is-warning', isWarning);
    els.expiryProgress.style.transform = `scaleX(${ratio})`;
  }

  function buildCurlCommand(includeSecret) {
    if (!state.inbox) return '';
    const origin = window.location.origin;
    const tokenPart = includeSecret ? state.inbox.token : '<INBOX_BEARER_TOKEN>';
    return `curl -sS -H "Authorization: Bearer ${tokenPart}" "${origin}/api/v1/inbox/${encodeURIComponent(state.inbox.address)}"`;
  }

  function updateApiSecretsUI() {
    if (!els.inboxTokenInput || !els.apiCurlPreview) return;
    if (!state.inbox) {
      els.inboxTokenInput.value = '';
      els.apiCurlPreview.textContent = '';
      return;
    }
    els.inboxTokenInput.type = state.tokenRevealed ? 'text' : 'password';
    els.inboxTokenInput.value = state.inbox.token;
    if (els.toggleTokenBtn) {
      els.toggleTokenBtn.textContent = state.tokenRevealed ? 'Hide' : 'Show';
    }
    els.apiCurlPreview.textContent = buildCurlCommand(state.tokenRevealed);
  }

  function updatePollUI() {
    if (document.hidden) {
      els.pollText.textContent = 'Paused while tab is hidden';
      return;
    }
    if (state.isFetching) {
      els.pollText.textContent = 'Checking for mail...';
      return;
    }
    els.pollText.textContent = `Checking in ${state.pollRemainingSec}s`;
  }

  function renderInboxList(newlyArrivedIds = new Set()) {
    const count = state.messages.length;
    els.inboxCount.textContent = count === 1 ? '1 message' : `${count} messages`;

    if (count === 0) {
      els.emptyState.hidden = false;
      els.messageList.hidden = true;
      els.messageList.textContent = '';
      updateTabTitle();
      return;
    }

    els.emptyState.hidden = true;
    els.messageList.hidden = false;
    els.messageList.textContent = '';

    const fragment = document.createDocumentFragment();
    for (const msg of state.messages) {
      const li = document.createElement('li');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'inbox-row';
      if (!msg.read) btn.classList.add('is-unread');
      if (newlyArrivedIds.has(msg.id)) btn.classList.add('is-new');
      btn.dataset.messageId = msg.id;

      const senderEl = document.createElement('span');
      senderEl.className = 'row-sender';
      senderEl.textContent = msg.fromName ? `${msg.fromName} <${msg.from}>` : msg.from;

      const mainEl = document.createElement('span');
      mainEl.className = 'row-main';

      const subjectLine = document.createElement('span');
      subjectLine.className = 'row-subject-line';

      const subjectEl = document.createElement('span');
      subjectEl.className = 'row-subject';
      subjectEl.textContent = msg.subject || '(No subject)';
      subjectLine.appendChild(subjectEl);

      if (msg.hasAttachments) {
        const attEl = document.createElement('span');
        attEl.className = 'row-attachment';
        attEl.textContent = 'Attachment';
        subjectLine.appendChild(attEl);
      }

      const snippetEl = document.createElement('span');
      snippetEl.className = 'row-snippet';
      snippetEl.textContent = msg.snippet || '';
      snippetEl.style.display = 'block';

      mainEl.appendChild(subjectLine);
      mainEl.appendChild(snippetEl);

      const dateEl = document.createElement('span');
      dateEl.className = 'row-date';
      dateEl.textContent = formatShortDate(msg.date);

      btn.appendChild(senderEl);
      btn.appendChild(mainEl);
      btn.appendChild(dateEl);

      btn.addEventListener('click', () => {
        openMessage(msg.id);
      });

      li.appendChild(btn);
      fragment.appendChild(li);
    }

    els.messageList.appendChild(fragment);
    updateTabTitle();
  }

  function buildBlockedImageDataUri(altText) {
    const label = String(altText || 'Remote image blocked').slice(0, 32).replace(/[<>&"']/g, '');
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="220" height="36" viewBox="0 0 220 36"><rect width="220" height="36" rx="4" fill="#f3f4f6" stroke="#d1d5db"/><text x="12" y="22" font-family="sans-serif" font-size="12" fill="#4b5563">[Blocked image: ${label}]</text></svg>`;
    return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
  }

  function buildSandboxedSrcdoc(sanitizedHtml, allowImages) {
    const parser = new window.DOMParser();
    const doc = parser.parseFromString(sanitizedHtml || '', 'text/html');

    const images = doc.querySelectorAll('img[data-src]');
    images.forEach((img) => {
      const rawSrc = img.getAttribute('data-src') || '';
      if (allowImages) {
        if (/^https?:\/\//i.test(rawSrc.trim())) {
          img.setAttribute('src', rawSrc.trim());
        }
        img.removeAttribute('data-src');
      } else {
        img.setAttribute('src', buildBlockedImageDataUri(img.getAttribute('alt')));
      }
    });

    const csp = allowImages
      ? "default-src 'none'; img-src https:; style-src 'unsafe-inline'"
      : "default-src 'none'; img-src data:; style-src 'unsafe-inline'";

    const bodyHtml = doc.body ? doc.body.innerHTML : '';

    return [
      '<!DOCTYPE html>',
      '<html><head><meta charset="UTF-8">',
      '<base target="_blank">',
      `<meta http-equiv="Content-Security-Policy" content="${csp}">`,
      '</head><body>',
      bodyHtml,
      '</body></html>',
    ].join('');
  }

  function hasBlockedImages(html) {
    if (!html) return false;
    const parser = new window.DOMParser();
    const doc = parser.parseFromString(html, 'text/html');
    return doc.querySelectorAll('img[data-src]').length > 0;
  }

  function renderActiveMessageBody() {
    const msg = state.activeMessage;
    if (!msg) return;

    const hasHtml = Boolean(msg.html && msg.html.trim());
    els.modeHtmlBtn.disabled = !hasHtml;

    if (state.viewerMode === 'html' && hasHtml) {
      els.modeHtmlBtn.classList.add('is-active');
      els.modeHtmlBtn.setAttribute('aria-pressed', 'true');
      els.modeTextBtn.classList.remove('is-active');
      els.modeTextBtn.setAttribute('aria-pressed', 'false');

      els.messageIframe.hidden = false;
      els.messagePlain.hidden = true;
      els.messageIframe.srcdoc = buildSandboxedSrcdoc(msg.html, state.imagesLoaded);

      const blocked = hasBlockedImages(msg.html) && !state.imagesLoaded;
      els.imageGuard.hidden = !blocked;
    } else {
      els.modeTextBtn.classList.add('is-active');
      els.modeTextBtn.setAttribute('aria-pressed', 'true');
      els.modeHtmlBtn.classList.remove('is-active');
      els.modeHtmlBtn.setAttribute('aria-pressed', 'false');

      els.messageIframe.hidden = true;
      els.messagePlain.hidden = false;
      els.imageGuard.hidden = true;
      els.messagePlain.textContent = msg.text || '(No plain text content)';
    }
  }

  function showInboxView() {
    state.activeMessage = null;
    els.messageView.hidden = true;
    els.inboxSection.hidden = false;
    els.messageIframe.srcdoc = '';
  }

  function showMessageView(msg) {
    state.activeMessage = msg;
    state.imagesLoaded = false;
    state.viewerMode = msg.html && msg.html.trim() ? 'html' : 'text';

    els.msgSubject.textContent = msg.subject || '(No subject)';
    els.msgFrom.textContent = msg.fromName ? `${msg.fromName} <${msg.from}>` : msg.from;
    els.msgDate.textContent = formatFullDate(msg.date);
    els.msgDate.dateTime = msg.date || '';

    const attachments = Array.isArray(msg.attachments) ? msg.attachments : [];
    els.attachmentsList.textContent = '';
    if (attachments.length > 0) {
      els.msgAttachments.hidden = false;
      for (const att of attachments) {
        const li = document.createElement('li');
        li.textContent = `${att.filename} (${formatBytes(att.size)}, not stored)`;
        els.attachmentsList.appendChild(li);
      }
    } else {
      els.msgAttachments.hidden = true;
    }

    els.inboxSection.hidden = true;
    els.messageView.hidden = false;
    renderActiveMessageBody();
  }

  async function apiRequest(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (options.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }
    if (state.inbox && state.inbox.token && options.auth !== false) {
      headers.set('Authorization', `Bearer ${state.inbox.token}`);
    }

    const res = await window.fetch(path, {
      method: options.method || 'GET',
      headers,
      body: options.body,
      cache: 'no-store',
    });
    return res;
  }

  async function loadDomainsAndMeta() {
    try {
      const [domRes, metaRes] = await Promise.all([
        window.fetch('/api/domains', { cache: 'no-store' }),
        window.fetch('/api/meta', { cache: 'no-store' }),
      ]);

      let domains = [];
      let ownDomains = [];

      if (metaRes.ok) {
        const meta = await metaRes.json();
        if (Array.isArray(meta.domains)) domains = meta.domains;
        if (Array.isArray(meta.ownDomains)) ownDomains = meta.ownDomains;
        if (meta.abuseEmail && els.abuseLink) {
          els.abuseLink.textContent = meta.abuseEmail;
          els.abuseLink.href = `mailto:${meta.abuseEmail}`;
        }
      }

      if (domRes.ok) {
        const data = await domRes.json();
        if (Array.isArray(data.domains) && data.domains.length > 0) {
          domains = data.domains;
        }
      }

      state.domains = domains;
      els.domainSelect.textContent = '';

      const ownSet = new Set(ownDomains);
      const serverList = domains.filter((d) => ownSet.has(d));
      const publicList = domains.filter((d) => !ownSet.has(d));

      if (serverList.length > 0 && publicList.length > 0) {
        const ownGroup = document.createElement('optgroup');
        ownGroup.label = 'Your Server';
        for (const d of serverList) {
          const opt = document.createElement('option');
          opt.value = d;
          opt.textContent = d;
          ownGroup.appendChild(opt);
        }

        const pubGroup = document.createElement('optgroup');
        pubGroup.label = 'Public Mail APIs';
        for (const d of publicList) {
          const opt = document.createElement('option');
          opt.value = d;
          opt.textContent = d;
          pubGroup.appendChild(opt);
        }

        els.domainSelect.appendChild(ownGroup);
        els.domainSelect.appendChild(pubGroup);
      } else {
        for (const d of domains) {
          const opt = document.createElement('option');
          opt.value = d;
          opt.textContent = d;
          els.domainSelect.appendChild(opt);
        }
      }
    } catch {
      // Non-fatal metadata load failure
    }
  }

  async function createNewRandomInbox(noticeMessage = '') {
    showMessageViewIfNeededReset();
    const res = await window.fetch('/api/inbox', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
      cache: 'no-store',
    });

    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      showNotice(errData.error || 'Unable to create a temporary address.', true);
      return;
    }

    const created = await res.json();
    state.inbox = created;
    state.messages = [];
    state.knownIds = new Set();
    state.etag = null;
    state.pollDelaySec = POLL_INTERVAL_SEC;
    state.pollRemainingSec = POLL_INTERVAL_SEC;
    saveInboxToStorage(created);

    els.addressInput.value = created.address;
    state.tokenRevealed = false;
    updateExpiryUI();
    updateApiSecretsUI();
    renderInboxList();
    if (noticeMessage) {
      showNotice(noticeMessage, false);
    } else {
      showNotice('');
    }
  }

  function showMessageViewIfNeededReset() {
    if (state.activeMessage) {
      showInboxView();
    }
  }

  function maybeNotifyNewMail(newMsgs) {
    if (!newMsgs.length) return;
    const first = newMsgs[0];
    const sender = first.fromName || first.from;
    announce(`${newMsgs.length} new message${newMsgs.length > 1 ? 's' : ''} from ${sender}`);

    if (
      state.notificationsEnabled &&
      document.hidden &&
      'Notification' in window &&
      window.Notification.permission === 'granted'
    ) {
      try {
        const n = new window.Notification(`New email from ${sender}`, {
          body: first.subject || '(No subject)',
        });
        n.onclick = () => {
          window.focus();
          n.close();
        };
      } catch {
        // Ignore notification errors
      }
    }
  }

  async function pollInbox({ manual = false } = {}) {
    if (!state.inbox || state.isFetching) return;

    state.isFetching = true;
    state.lastPollAt = Date.now();
    els.refreshIcon.classList.add('is-spinning');
    updatePollUI();

    try {
      const headers = {};
      if (state.etag) {
        headers['If-None-Match'] = state.etag;
      }

      const res = await apiRequest(`/api/inbox/${encodeURIComponent(state.inbox.address)}`, {
        headers,
      });

      if (res.status === 304) {
        state.pollDelaySec = POLL_INTERVAL_SEC;
        state.pollRemainingSec = state.pollDelaySec;
        return;
      }

      if (res.status === 404) {
        saveInboxToStorage(null);
        await createNewRandomInbox('Your previous address expired. A new address has been issued.');
        return;
      }

      if (!res.ok) {
        state.pollDelaySec = BACKOFF_INTERVAL_SEC;
        state.pollRemainingSec = state.pollDelaySec;
        if (manual) {
          showNotice('Could not refresh inbox right now. Retrying shortly.', true);
        }
        return;
      }

      const etag = res.headers.get('ETag');
      if (etag) state.etag = etag;

      const data = await res.json();
      state.inbox.expiresAt = data.expiresAt;
      if (data.ttlMs) state.inbox.ttlMs = Math.max(state.inbox.ttlMs || 0, data.ttlMs);
      saveInboxToStorage(state.inbox);

      const incoming = Array.isArray(data.messages) ? data.messages : [];
      const newMsgs = [];
      const newlyArrivedIds = new Set();

      if (state.knownIds.size > 0 || state.messages.length > 0 || manual) {
        for (const msg of incoming) {
          if (!state.knownIds.has(msg.id)) {
            newMsgs.push(msg);
            newlyArrivedIds.add(msg.id);
          }
        }
      }

      state.knownIds = new Set(incoming.map((m) => m.id));
      state.messages = incoming;
      state.pollDelaySec = POLL_INTERVAL_SEC;
      state.pollRemainingSec = POLL_INTERVAL_SEC;

      saveInboxToStorage(state.inbox, incoming);
      updateExpiryUI();
      renderInboxList(newlyArrivedIds);
      maybeNotifyNewMail(newMsgs);
    } catch {
      state.pollDelaySec = BACKOFF_INTERVAL_SEC;
      state.pollRemainingSec = state.pollDelaySec;
    } finally {
      state.isFetching = false;
      els.refreshIcon.classList.remove('is-spinning');
      updatePollUI();
    }
  }

  async function openMessage(id) {
    if (!state.inbox) return;
    try {
      const res = await apiRequest(
        `/api/inbox/${encodeURIComponent(state.inbox.address)}/messages/${encodeURIComponent(id)}`
      );
      if (res.status === 404) {
        await pollInbox({ manual: true });
        return;
      }
      if (!res.ok) {
        showNotice('Failed to load message.', true);
        return;
      }
      const fullMsg = await res.json();
      const listMatch = state.messages.find((m) => m.id === id);
      if (listMatch) {
        listMatch.read = true;
        state.etag = null;
        saveInboxToStorage(state.inbox, state.messages);
        renderInboxList();
      }
      showMessageView(fullMsg);
    } catch {
      showNotice('Failed to load message.', true);
    }
  }

  async function copyAddress() {
    if (!state.inbox) return;
    const text = state.inbox.address;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        els.addressInput.select();
        document.execCommand('copy');
      }
    } catch {
      els.addressInput.select();
      try {
        document.execCommand('copy');
      } catch {
        // Ignore fallback failure
      }
    }

    els.copyBtn.textContent = 'Copied';
    els.copyBtn.classList.add('is-copied');
    announce('Email address copied to clipboard');

    if (state.copyTimer) window.clearTimeout(state.copyTimer);
    state.copyTimer = window.setTimeout(() => {
      els.copyBtn.textContent = 'Copy';
      els.copyBtn.classList.remove('is-copied');
    }, 1500);
  }

  async function extendInboxTimer() {
    if (!state.inbox) return;
    els.extendBtn.disabled = true;
    try {
      const res = await apiRequest(`/api/inbox/${encodeURIComponent(state.inbox.address)}/extend`, {
        method: 'POST',
      });
      if (res.status === 404) {
        await createNewRandomInbox('Your previous address expired. A new address has been issued.');
        return;
      }
      if (!res.ok) {
        showNotice('Unable to extend timer right now.', true);
        return;
      }
      const data = await res.json();
      state.inbox.expiresAt = data.expiresAt;
      state.inbox.ttlMs = data.ttlMs;
      state.etag = null;
      saveInboxToStorage(state.inbox);
      updateExpiryUI();
      announce('Inbox timer extended');
    } catch {
      showNotice('Unable to extend timer right now.', true);
    } finally {
      els.extendBtn.disabled = false;
    }
  }

  function openChangeDialog() {
    els.changeError.hidden = true;
    els.changeError.textContent = '';
    els.usernameInput.value = '';
    if (state.inbox && state.domains.length > 0) {
      const currentDomain = state.inbox.address.split('@')[1];
      if (state.domains.includes(currentDomain)) {
        els.domainSelect.value = currentDomain;
      }
    }
    els.changeDialog.showModal();
    els.usernameInput.focus();
  }

  async function handleChangeSubmit(event) {
    event.preventDefault();
    const rawUser = els.usernameInput.value.trim();
    const domain = els.domainSelect.value;

    let bodyPayload;
    if (rawUser) {
      const check = validateUsernameClient(rawUser);
      if (!check.valid) {
        els.changeError.textContent = check.error;
        els.changeError.hidden = false;
        return;
      }
      bodyPayload = { username: check.username, domain };
    } else {
      bodyPayload = { domain };
    }

    els.changeError.hidden = true;
    els.changeSubmitBtn.disabled = true;

    const previousInbox = state.inbox;

    try {
      const res = await window.fetch('/api/inbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyPayload),
        cache: 'no-store',
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        els.changeError.textContent = data.error || 'Could not change address.';
        els.changeError.hidden = false;
        return;
      }

      if (previousInbox) {
        window.fetch(`/api/inbox/${encodeURIComponent(previousInbox.address)}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${previousInbox.token}` },
          cache: 'no-store',
        }).catch(() => {});
      }

      state.inbox = data;
      state.messages = [];
      state.knownIds = new Set();
      state.etag = null;
      state.pollDelaySec = POLL_INTERVAL_SEC;
      state.pollRemainingSec = POLL_INTERVAL_SEC;
      saveInboxToStorage(data);

      els.addressInput.value = data.address;
      state.tokenRevealed = false;
      showMessageViewIfNeededReset();
      updateExpiryUI();
      updateApiSecretsUI();
      renderInboxList();
      showNotice('');
      els.changeDialog.close();
      announce(`Address changed to ${data.address}`);
    } catch {
      els.changeError.textContent = 'Network error. Please try again.';
      els.changeError.hidden = false;
    } finally {
      els.changeSubmitBtn.disabled = false;
    }
  }

  async function handleDeleteAddress(event) {
    event.preventDefault();
    els.deleteConfirmBtn.disabled = true;
    const previousInbox = state.inbox;

    try {
      if (previousInbox) {
        await window.fetch(`/api/inbox/${encodeURIComponent(previousInbox.address)}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${previousInbox.token}` },
          cache: 'no-store',
        }).catch(() => {});
      }
      saveInboxToStorage(null);
      els.deleteDialog.close();
      await createNewRandomInbox('Previous inbox deleted. A fresh address is ready.');
    } finally {
      els.deleteConfirmBtn.disabled = false;
    }
  }

  async function handleDeleteActiveMessage() {
    if (!state.inbox || !state.activeMessage) return;
    const msgId = state.activeMessage.id;
    els.deleteMsgBtn.disabled = true;
    try {
      const res = await apiRequest(
        `/api/inbox/${encodeURIComponent(state.inbox.address)}/messages/${encodeURIComponent(msgId)}`,
        { method: 'DELETE' }
      );
      if (res.status === 404) {
        showInboxView();
        await pollInbox();
        return;
      }
      state.messages = state.messages.filter((m) => m.id !== msgId);
      state.knownIds.delete(msgId);
      state.etag = null;
      showInboxView();
      renderInboxList();
      announce('Message deleted');
    } catch {
      showNotice('Could not delete message.', true);
    } finally {
      els.deleteMsgBtn.disabled = false;
    }
  }

  function updateNotificationButton() {
    if (!('Notification' in window)) {
      els.notifyBtn.hidden = true;
      return;
    }
    if (window.Notification.permission === 'granted' && state.notificationsEnabled) {
      els.notifyBtn.textContent = 'Notifications on';
    } else {
      els.notifyBtn.textContent = 'Enable notifications';
    }
  }

  async function toggleNotifications() {
    if (!('Notification' in window)) return;
    if (window.Notification.permission === 'granted') {
      state.notificationsEnabled = !state.notificationsEnabled;
      updateNotificationButton();
      return;
    }
    if (window.Notification.permission === 'denied') {
      showNotice('Browser notifications are blocked in your site permissions.', false);
      updateNotificationButton();
      return;
    }
    try {
      const result = await window.Notification.requestPermission();
      state.notificationsEnabled = result === 'granted';
      updateNotificationButton();
    } catch {
      // Ignore permission dialog errors
    }
  }

  async function copyTextWithFeedback(text, buttonEl, originalLabel, copiedLabel = 'Copied') {
    if (!text) return;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      }
    } catch {
      // Ignore clipboard permission errors
    }
    if (!buttonEl) return;
    buttonEl.textContent = copiedLabel;
    window.setTimeout(() => {
      buttonEl.textContent = originalLabel;
    }, 1500);
  }

  async function handleRotateInboxToken() {
    if (!state.inbox || !els.rotateTokenBtn) return;
    els.rotateTokenBtn.disabled = true;
    try {
      const res = await apiRequest(
        `/api/v1/inbox/${encodeURIComponent(state.inbox.address)}/rotate-token`,
        { method: 'POST' }
      );
      if (res.status === 404) {
        await createNewRandomInbox('Your previous address expired. A new address has been issued.');
        return;
      }
      if (!res.ok) {
        showNotice('Unable to rotate inbox token right now.', true);
        return;
      }
      const rotated = await res.json();
      state.inbox.token = rotated.token;
      state.inbox.expiresAt = rotated.expiresAt;
      saveInboxToStorage(state.inbox);
      updateApiSecretsUI();
      showNotice('Inbox secret token rotated. Previous tokens are now invalid.', false);
      announce('Inbox secret token rotated');
    } catch {
      showNotice('Unable to rotate inbox token right now.', true);
    } finally {
      els.rotateTokenBtn.disabled = false;
    }
  }

  async function handleCreateApiKey(event) {
    event.preventDefault();
    if (!els.createKeyBtn) return;
    els.createKeyBtn.disabled = true;
    const label = els.apiKeyLabel ? els.apiKeyLabel.value.trim() : 'default';

    try {
      const res = await window.fetch('/api/v1/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label || 'default' }),
        cache: 'no-store',
      });
      if (!res.ok) {
        showNotice('Could not create API key right now.', true);
        return;
      }
      const created = await res.json();
      state.activeApiKey = created.apiKey;
      els.apiKeyOutput.value = created.apiKey;
      els.apiKeyMeta.textContent = `Label: ${created.label} · Expires ${formatFullDate(new Date(created.expiresAt).toISOString())}`;
      els.apiKeyResult.hidden = false;
      announce('Developer API key generated');
    } catch {
      showNotice('Could not create API key right now.', true);
    } finally {
      els.createKeyBtn.disabled = false;
    }
  }

  async function handleRevokeApiKey() {
    if (!state.activeApiKey || !els.revokeKeyBtn) return;
    els.revokeKeyBtn.disabled = true;
    try {
      await window.fetch('/api/v1/keys/me', {
        method: 'DELETE',
        headers: { 'X-API-Key': state.activeApiKey },
        cache: 'no-store',
      });
      state.activeApiKey = null;
      els.apiKeyOutput.value = '';
      els.apiKeyMeta.textContent = '';
      els.apiKeyResult.hidden = true;
      showNotice('Developer API key revoked.', false);
      announce('Developer API key revoked');
    } catch {
      showNotice('Could not revoke API key right now.', true);
    } finally {
      els.revokeKeyBtn.disabled = false;
    }
  }

  function bindEvents() {
    els.copyBtn.addEventListener('click', copyAddress);
    els.refreshBtn.addEventListener('click', () => {
      state.pollRemainingSec = state.pollDelaySec;
      pollInbox({ manual: true });
    });
    els.extendBtn.addEventListener('click', extendInboxTimer);
    els.changeBtn.addEventListener('click', openChangeDialog);
    els.deleteAddressBtn.addEventListener('click', () => els.deleteDialog.showModal());

    els.changeCloseBtn.addEventListener('click', () => els.changeDialog.close());
    els.changeCancelBtn.addEventListener('click', () => els.changeDialog.close());
    els.changeForm.addEventListener('submit', handleChangeSubmit);
    els.randomNameBtn.addEventListener('click', () => {
      els.usernameInput.value = generateRandomUsername(10);
      els.changeError.hidden = true;
      els.changeError.textContent = '';
    });
    els.usernameInput.addEventListener('input', () => {
      if (!els.usernameInput.value.trim()) {
        els.changeError.hidden = true;
        els.changeError.textContent = '';
        return;
      }
      const check = validateUsernameClient(els.usernameInput.value);
      if (!check.valid) {
        els.changeError.textContent = check.error;
        els.changeError.hidden = false;
      } else {
        els.changeError.hidden = true;
        els.changeError.textContent = '';
      }
    });

    els.deleteCloseBtn.addEventListener('click', () => els.deleteDialog.close());
    els.deleteCancelBtn.addEventListener('click', () => els.deleteDialog.close());
    els.deleteForm.addEventListener('submit', handleDeleteAddress);

    els.backBtn.addEventListener('click', showInboxView);
    els.deleteMsgBtn.addEventListener('click', handleDeleteActiveMessage);
    els.modeHtmlBtn.addEventListener('click', () => {
      state.viewerMode = 'html';
      renderActiveMessageBody();
    });
    els.modeTextBtn.addEventListener('click', () => {
      state.viewerMode = 'text';
      renderActiveMessageBody();
    });
    els.loadImagesBtn.addEventListener('click', () => {
      state.imagesLoaded = true;
      renderActiveMessageBody();
    });

    els.notifyBtn.addEventListener('click', toggleNotifications);

    if (els.toggleTokenBtn) {
      els.toggleTokenBtn.addEventListener('click', () => {
        state.tokenRevealed = !state.tokenRevealed;
        updateApiSecretsUI();
      });
    }
    if (els.copyTokenBtn) {
      els.copyTokenBtn.addEventListener('click', () => {
        if (state.inbox) {
          copyTextWithFeedback(state.inbox.token, els.copyTokenBtn, 'Copy');
        }
      });
    }
    if (els.rotateTokenBtn) {
      els.rotateTokenBtn.addEventListener('click', handleRotateInboxToken);
    }
    if (els.copyCurlBtn) {
      els.copyCurlBtn.addEventListener('click', () => {
        copyTextWithFeedback(buildCurlCommand(true), els.copyCurlBtn, 'Copy cURL');
      });
    }
    if (els.apiKeyForm) {
      els.apiKeyForm.addEventListener('submit', handleCreateApiKey);
    }
    if (els.copyKeyBtn) {
      els.copyKeyBtn.addEventListener('click', () => {
        copyTextWithFeedback(state.activeApiKey, els.copyKeyBtn, 'Copy');
      });
    }
    if (els.revokeKeyBtn) {
      els.revokeKeyBtn.addEventListener('click', handleRevokeApiKey);
    }

    document.addEventListener('visibilitychange', () => {
      updateTabTitle();
      updatePollUI();
      if (!document.hidden && state.inbox) {
        state.pollRemainingSec = state.pollDelaySec;
        pollInbox();
      }
    });

    window.addEventListener('focus', () => {
      if (state.inbox && Date.now() - state.lastPollAt > 2000) {
        state.pollRemainingSec = state.pollDelaySec;
        pollInbox();
      }
    });

    document.addEventListener('pointerdown', () => {
      if (state.inbox && !state.isFetching && Date.now() - state.lastPollAt > 2000) {
        state.pollRemainingSec = state.pollDelaySec;
        pollInbox();
      }
    }, { passive: true });
  }

  function startTimers() {
    window.setInterval(() => {
      updateExpiryUI();

      if (state.inbox && state.inbox.expiresAt <= Date.now()) {
        saveInboxToStorage(null);
        createNewRandomInbox('Your previous address expired. A new address has been issued.');
        return;
      }

      if (!document.hidden && !state.isFetching && state.inbox) {
        state.pollRemainingSec -= 1;
        if (state.pollRemainingSec <= 0) {
          state.pollRemainingSec = state.pollDelaySec;
          pollInbox();
        }
      }
      updatePollUI();
    }, 1000);
  }

  async function init() {
    bindEvents();
    updateNotificationButton();

    const saved = loadInboxFromStorage();
    if (saved) {
      state.inbox = {
        address: saved.address,
        token: saved.token,
        expiresAt: saved.expiresAt,
        ttlMs: saved.ttlMs,
      };
      state.messages = Array.isArray(saved.messages) ? saved.messages : [];
      state.knownIds = new Set(state.messages.map((m) => m.id));
      els.addressInput.value = saved.address;
      updateExpiryUI();
      updateApiSecretsUI();
      renderInboxList();

      await loadDomainsAndMeta();

      try {
        const res = await apiRequest(`/api/inbox/${encodeURIComponent(saved.address)}`);
        if (res.ok) {
          const etag = res.headers.get('ETag');
          if (etag) state.etag = etag;
          const data = await res.json();
          state.inbox.expiresAt = data.expiresAt;
          if (data.ttlMs) state.inbox.ttlMs = Math.max(state.inbox.ttlMs || 0, data.ttlMs);
          state.messages = Array.isArray(data.messages) ? data.messages : [];
          state.knownIds = new Set(state.messages.map((m) => m.id));
          saveInboxToStorage(state.inbox, state.messages);
          updateExpiryUI();
          updateApiSecretsUI();
          renderInboxList();
        } else if (res.status === 404) {
          saveInboxToStorage(null);
          await createNewRandomInbox('Your previous address expired. A new address has been issued.');
        } else {
          showNotice('Could not reach server to sync right now. Showing saved inbox and retrying...', false);
        }
      } catch {
        showNotice('Network unavailable while refreshing. Showing saved inbox and retrying...', false);
      }
    } else {
      await loadDomainsAndMeta();
      await createNewRandomInbox();
    }

    startTimers();
  }

  init();
})();
