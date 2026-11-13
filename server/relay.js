'use strict';

const crypto = require('node:crypto');
const sanitizeHtml = require('sanitize-html');
const { normalizeAddress, generateRandomUsername } = require('./validate');

const MAIL_TM_BASE = 'https://api.mail.tm';
const TEMPMAIL_LOL_BASE = 'https://api.tempmail.lol/v2';
const GUERRILLA_BASE = 'https://api.guerrillamail.com/ajax.php';

const GUERRILLA_DOMAINS = [
  'guerrillamail.com',
  'sharklasers.com',
  'guerrillamailblock.com',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamail.biz',
  'grr.la',
  'spam4.me',
];

const DEFAULT_TIMEOUT_MS = 7000;
const DOMAIN_CACHE_TTL_MS = 5 * 60 * 1000;
const PROBE_CACHE_TTL_MS = 15 * 60 * 1000;

function parseFromHeader(rawFrom) {
  const str = String(rawFrom || '').trim();
  if (!str) {
    return { from: 'unknown@unknown', fromName: '' };
  }
  const angleMatch = /^(.*)<([^>]+)>$/.exec(str);
  if (angleMatch) {
    const name = angleMatch[1].trim().replace(/^["']|["']$/g, '');
    const addr = normalizeAddress(angleMatch[2]) || 'unknown@unknown';
    return { from: addr, fromName: name };
  }
  return { from: normalizeAddress(str) || 'unknown@unknown', fromName: '' };
}

function stripTagsToText(htmlOrText) {
  return sanitizeHtml(String(htmlOrText || ''), {
    allowedTags: [],
    allowedAttributes: {},
  })
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function createPublicMailRelay({ fetchImpl = globalThis.fetch } = {}) {
  let cachedMailTmDomains = [];
  let mailTmCachedAt = 0;

  let cachedTempmailLolDomains = [];
  let tempmailLolCachedAt = 0;

  let guerrillaReachable = false;
  let guerrillaCachedAt = 0;

  let inFlightDomainsPromise = null;

  async function requestJson(url, options = {}) {
    const res = await fetchImpl(url, {
      ...options,
      signal: options.signal || AbortSignal.timeout(DEFAULT_TIMEOUT_MS),
    });
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = null;
    }
    return { status: res.status, ok: res.ok, data, text };
  }

  async function fetchMailTmDomains({ force = false } = {}) {
    if (!force && cachedMailTmDomains.length > 0 && Date.now() - mailTmCachedAt < DOMAIN_CACHE_TTL_MS) {
      return cachedMailTmDomains;
    }
    try {
      const res = await requestJson(`${MAIL_TM_BASE}/domains`);
      if (res.ok && res.data && Array.isArray(res.data['hydra:member'])) {
        const list = res.data['hydra:member']
          .filter((item) => item && item.domain && item.isActive !== false && !item.isPrivate)
          .map((item) => String(item.domain).trim().toLowerCase())
          .filter(Boolean);
        if (list.length > 0) {
          cachedMailTmDomains = Array.from(new Set(list));
          mailTmCachedAt = Date.now();
          return cachedMailTmDomains;
        }
      }
    } catch {
      // Fallback to cached domains if available
    }
    return cachedMailTmDomains;
  }

  async function fetchTempmailLolDomains({ force = false } = {}) {
    if (!force && tempmailLolCachedAt > 0 && Date.now() - tempmailLolCachedAt < PROBE_CACHE_TTL_MS) {
      return cachedTempmailLolDomains;
    }
    try {
      const res = await requestJson(`${TEMPMAIL_LOL_BASE}/inbox/create`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      tempmailLolCachedAt = Date.now();
      if (res.ok && res.data && typeof res.data.address === 'string' && res.data.address.includes('@')) {
        const domain = normalizeAddress(res.data.address.split('@')[1]);
        if (domain) {
          cachedTempmailLolDomains = [domain];
          return cachedTempmailLolDomains;
        }
      }
    } catch {
      // Keep previous cached domain if probe fails
    }
    return cachedTempmailLolDomains;
  }

  async function checkGuerrillaAvailability({ force = false } = {}) {
    if (!force && guerrillaCachedAt > 0 && Date.now() - guerrillaCachedAt < PROBE_CACHE_TTL_MS) {
      return guerrillaReachable;
    }
    try {
      const res = await requestJson(`${GUERRILLA_BASE}?f=get_email_address&lang=en`);
      guerrillaCachedAt = Date.now();
      guerrillaReachable = Boolean(res.ok && res.data && res.data.sid_token && res.data.email_addr);
    } catch {
      guerrillaReachable = false;
    }
    return guerrillaReachable;
  }

  async function fetchPublicDomains({ force = false } = {}) {
    if (!force && inFlightDomainsPromise) {
      return inFlightDomainsPromise;
    }

    const job = (async () => {
      const [mailTmResult, tempmailLolResult, guerrillaResult] = await Promise.allSettled([
        fetchMailTmDomains({ force }),
        fetchTempmailLolDomains({ force }),
        checkGuerrillaAvailability({ force }),
      ]);

      const mailTmDomains = mailTmResult.status === 'fulfilled' ? mailTmResult.value : [];
      const tempmailDomains = tempmailLolResult.status === 'fulfilled' ? tempmailLolResult.value : [];
      const hasGuerrilla = guerrillaResult.status === 'fulfilled' && guerrillaResult.value;

      const combined = [
        ...mailTmDomains,
        ...tempmailDomains,
        ...(hasGuerrilla ? GUERRILLA_DOMAINS : []),
      ];

      return Array.from(new Set(combined));
    })();

    if (!force) {
      inFlightDomainsPromise = job;
    }
    try {
      return await job;
    } finally {
      if (inFlightDomainsPromise === job) {
        inFlightDomainsPromise = null;
      }
    }
  }

  async function createMailTmAccount(address) {
    const password = `Tw_${crypto.randomBytes(18).toString('base64url')}`;
    const acc = await requestJson(`${MAIL_TM_BASE}/accounts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, password }),
    });

    if (acc.status === 422) {
      const err = new Error('That email address is already in use.');
      err.statusCode = 409;
      throw err;
    }
    if (!acc.ok || !acc.data || !acc.data.address) {
      const err = new Error('Upstream mail.tm account creation failed.');
      err.statusCode = 502;
      throw err;
    }

    const tok = await requestJson(`${MAIL_TM_BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address, password }),
    });
    if (!tok.ok || !tok.data || !tok.data.token) {
      const err = new Error('Upstream mail.tm token creation failed.');
      err.statusCode = 502;
      throw err;
    }

    return {
      address: normalizeAddress(acc.data.address),
      upstream: {
        provider: 'mail.tm',
        accountId: acc.data.id,
        address: normalizeAddress(acc.data.address),
        password,
        jwt: tok.data.token,
      },
    };
  }

  async function createGuerrillaInbox({ username, domain } = {}) {
    const cleanDomain = normalizeAddress(domain) || GUERRILLA_DOMAINS[0];
    const requestedUser = username || generateRandomUsername(10);
    const url = `${GUERRILLA_BASE}?f=set_email_user&email_user=${encodeURIComponent(requestedUser)}&lang=en&domain=${encodeURIComponent(cleanDomain)}`;
    const res = await requestJson(url);

    if (!res.ok || !res.data || !res.data.sid_token || !res.data.email_addr) {
      const err = new Error('Upstream Guerrilla Mail inbox creation failed.');
      err.statusCode = 502;
      throw err;
    }

    const returnedLocal = String(res.data.email_addr).split('@')[0];
    const effectiveAddress = normalizeAddress(`${returnedLocal || requestedUser}@${cleanDomain}`);

    return {
      address: effectiveAddress,
      upstream: {
        provider: 'guerrilla',
        sidToken: String(res.data.sid_token),
        emailAddr: effectiveAddress,
      },
    };
  }

  async function createTempmailLolInbox({ prefix, domain } = {}) {
    const payload = {};
    if (prefix) payload.prefix = prefix;
    if (domain) payload.domain = domain;
    const res = await requestJson(`${TEMPMAIL_LOL_BASE}/inbox/create`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok || !res.data || !res.data.address || !res.data.token) {
      const err = new Error('Upstream tempmail.lol inbox creation failed.');
      err.statusCode = 502;
      throw err;
    }
    return {
      address: normalizeAddress(res.data.address),
      upstream: {
        provider: 'tempmail.lol',
        upstreamToken: String(res.data.token),
      },
    };
  }

  async function provisionPublicInbox({ username, domain } = {}) {
    const [mailTmDomains, tempmailDomains, hasGuerrilla] = await Promise.all([
      fetchMailTmDomains(),
      fetchTempmailLolDomains(),
      checkGuerrillaAvailability(),
    ]);

    const cleanDomain = domain ? normalizeAddress(domain) : '';

    if (cleanDomain) {
      if (mailTmDomains.includes(cleanDomain)) {
        if (username) {
          return createMailTmAccount(`${username}@${cleanDomain}`);
        }
        for (let i = 0; i < 3; i += 1) {
          const candidate = `${generateRandomUsername(10)}@${cleanDomain}`;
          try {
            return await createMailTmAccount(candidate);
          } catch (err) {
            if (err.statusCode !== 409) break;
          }
        }
        return null;
      }

      if (GUERRILLA_DOMAINS.includes(cleanDomain)) {
        return createGuerrillaInbox({ username, domain: cleanDomain });
      }

      if (tempmailDomains.includes(cleanDomain)) {
        return createTempmailLolInbox({ prefix: username, domain: cleanDomain });
      }

      return null;
    }

    if (username) {
      if (mailTmDomains.length > 0) {
        try {
          return await createMailTmAccount(`${username}@${mailTmDomains[0]}`);
        } catch (err) {
          if (err.statusCode === 409) throw err;
        }
      }
      if (hasGuerrilla) {
        try {
          return await createGuerrillaInbox({ username, domain: GUERRILLA_DOMAINS[0] });
        } catch {
          // Try tempmail.lol next
        }
      }
      try {
        return await createTempmailLolInbox({ prefix: username });
      } catch {
        return null;
      }
    }

    if (mailTmDomains.length > 0) {
      const chosenDomain = mailTmDomains[crypto.randomInt(0, mailTmDomains.length)];
      for (let i = 0; i < 3; i += 1) {
        const candidate = `${generateRandomUsername(10)}@${chosenDomain}`;
        try {
          return await createMailTmAccount(candidate);
        } catch (err) {
          if (err.statusCode !== 409) break;
        }
      }
    }

    if (hasGuerrilla) {
      try {
        return await createGuerrillaInbox({ domain: GUERRILLA_DOMAINS[0] });
      } catch {
        // Fallback to tempmail.lol
      }
    }

    try {
      return await createTempmailLolInbox();
    } catch {
      return null;
    }
  }

  async function refreshMailTmToken(upstream) {
    if (!upstream || !upstream.address || !upstream.password) return '';
    const tok = await requestJson(`${MAIL_TM_BASE}/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: upstream.address, password: upstream.password }),
    });
    if (tok.ok && tok.data && tok.data.token) {
      return String(tok.data.token);
    }
    return '';
  }

  async function fetchMailTmMessages(upstream, seenSet) {
    let jwt = upstream.jwt;
    let listRes = await requestJson(`${MAIL_TM_BASE}/messages`, {
      headers: { Authorization: `Bearer ${jwt}` },
    });

    if (listRes.status === 401) {
      const refreshed = await refreshMailTmToken(upstream);
      if (refreshed) {
        jwt = refreshed;
        listRes = await requestJson(`${MAIL_TM_BASE}/messages`, {
          headers: { Authorization: `Bearer ${jwt}` },
        });
      }
    }

    if (!listRes.ok || !listRes.data || !Array.isArray(listRes.data['hydra:member'])) {
      return { messages: [], refreshedJwt: jwt !== upstream.jwt ? jwt : '' };
    }

    const items = listRes.data['hydra:member'];
    const newMessages = [];

    for (const summary of items) {
      if (!summary || !summary.id) continue;
      const extId = `mailtm:${summary.id}`;
      if (seenSet.has(extId)) continue;

      const detailRes = await requestJson(`${MAIL_TM_BASE}/messages/${encodeURIComponent(summary.id)}`, {
        headers: { Authorization: `Bearer ${jwt}` },
      });
      if (!detailRes.ok || !detailRes.data) continue;
      const full = detailRes.data;

      const rawHtml = Array.isArray(full.html)
        ? full.html.join('\n')
        : (typeof full.html === 'string' ? full.html : '');
      const text = typeof full.text === 'string' ? full.text : String(full.intro || '');
      const fromObj = full.from && typeof full.from === 'object' ? full.from : {};

      newMessages.push({
        externalId: extId,
        from: normalizeAddress(fromObj.address || 'unknown@unknown') || 'unknown@unknown',
        fromName: String(fromObj.name || ''),
        subject: String(full.subject || '(No subject)'),
        date: full.createdAt ? new Date(full.createdAt).toISOString() : new Date().toISOString(),
        text,
        rawHtml,
        attachments: Array.isArray(full.attachments)
          ? full.attachments.map((att) => ({
            filename: String((att && att.filename) || 'attachment'),
            size: Number((att && att.size) || 0),
            contentType: String((att && att.contentType) || 'application/octet-stream'),
          }))
          : [],
      });
    }

    // Oldest first so saveMessage LPUSH puts newest first
    newMessages.reverse();
    return { messages: newMessages, refreshedJwt: jwt !== upstream.jwt ? jwt : '' };
  }

  async function fetchGuerrillaMessages(upstream, seenSet) {
    if (!upstream || !upstream.sidToken) {
      return { messages: [], refreshedJwt: '' };
    }
    const checkUrl = `${GUERRILLA_BASE}?f=check_email&seq=0&sid_token=${encodeURIComponent(upstream.sidToken)}`;
    const listRes = await requestJson(checkUrl);
    if (!listRes.ok || !listRes.data || !Array.isArray(listRes.data.list)) {
      return { messages: [], refreshedJwt: '' };
    }

    const newMessages = [];
    for (const summary of listRes.data.list) {
      if (!summary || !summary.mail_id) continue;
      // Skip default Guerrilla Mail promo welcome item
      if (String(summary.mail_id) === '1' && Number(summary.mail_timestamp || 0) === 0) {
        continue;
      }

      const extId = `guerrilla:${summary.mail_id}`;
      if (seenSet.has(extId)) continue;

      const fetchUrl = `${GUERRILLA_BASE}?f=fetch_email&email_id=${encodeURIComponent(summary.mail_id)}&sid_token=${encodeURIComponent(upstream.sidToken)}`;
      const detailRes = await requestJson(fetchUrl);
      if (!detailRes.ok || !detailRes.data) continue;
      const full = detailRes.data;

      const bodyStr = typeof full.mail_body === 'string' ? full.mail_body : String(summary.mail_excerpt || '');
      const looksHtml = /<[a-z][\s\S]*>/i.test(bodyStr);
      const rawHtml = looksHtml ? bodyStr : '';
      const text = looksHtml ? stripTagsToText(bodyStr) : bodyStr;
      const parsedFrom = parseFromHeader(full.mail_from || summary.mail_from);

      const tsSec = Number(full.mail_timestamp || summary.mail_timestamp);
      const dateIso = Number.isFinite(tsSec) && tsSec > 0
        ? new Date(tsSec * 1000).toISOString()
        : new Date().toISOString();

      newMessages.push({
        externalId: extId,
        from: parsedFrom.from,
        fromName: parsedFrom.fromName,
        subject: String(full.mail_subject || summary.mail_subject || '(No subject)'),
        date: dateIso,
        text,
        rawHtml,
        attachments: [],
      });
    }

    newMessages.reverse();
    return { messages: newMessages, refreshedJwt: '' };
  }

  async function fetchTempmailLolMessages(upstream, seenSet) {
    if (!upstream || !upstream.upstreamToken) {
      return { messages: [], refreshedJwt: '' };
    }
    const res = await requestJson(
      `${TEMPMAIL_LOL_BASE}/inbox?token=${encodeURIComponent(upstream.upstreamToken)}`
    );
    if (!res.ok || !res.data || !Array.isArray(res.data.emails)) {
      return { messages: [], refreshedJwt: '' };
    }

    const newMessages = [];
    for (const em of res.data.emails) {
      if (!em || typeof em !== 'object') continue;
      const sigInput = `${em.from || ''}|${em.subject || ''}|${em.date || ''}|${String(em.body || '').slice(0, 200)}`;
      const extId = `tmlol:${crypto.createHash('sha256').update(sigInput).digest('hex').slice(0, 24)}`;
      if (seenSet.has(extId)) continue;

      const parsedFrom = parseFromHeader(em.from);
      let dateIso = new Date().toISOString();
      if (em.date) {
        const d = new Date(em.date);
        if (!Number.isNaN(d.getTime())) dateIso = d.toISOString();
      }

      newMessages.push({
        externalId: extId,
        from: parsedFrom.from,
        fromName: parsedFrom.fromName,
        subject: String(em.subject || '(No subject)'),
        date: dateIso,
        text: String(em.body || ''),
        rawHtml: typeof em.html === 'string' ? em.html : '',
        attachments: [],
      });
    }

    return { messages: newMessages, refreshedJwt: '' };
  }

  async function fetchUpstreamMessages(upstream, seenExternalIds = []) {
    if (!upstream || !upstream.provider) {
      return { messages: [], refreshedJwt: '' };
    }
    const seenSet = new Set(Array.isArray(seenExternalIds) ? seenExternalIds : []);
    try {
      if (upstream.provider === 'mail.tm') {
        return await fetchMailTmMessages(upstream, seenSet);
      }
      if (upstream.provider === 'guerrilla') {
        return await fetchGuerrillaMessages(upstream, seenSet);
      }
      if (upstream.provider === 'tempmail.lol') {
        return await fetchTempmailLolMessages(upstream, seenSet);
      }
    } catch {
      // Non-fatal upstream poll error
    }
    return { messages: [], refreshedJwt: '' };
  }

  async function deleteUpstreamInbox(upstream) {
    if (!upstream) return;
    try {
      if (upstream.provider === 'mail.tm' && upstream.accountId && upstream.jwt) {
        await fetchImpl(`${MAIL_TM_BASE}/accounts/${encodeURIComponent(upstream.accountId)}`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${upstream.jwt}` },
          signal: AbortSignal.timeout(3000),
        });
      } else if (upstream.provider === 'guerrilla' && upstream.sidToken) {
        await fetchImpl(`${GUERRILLA_BASE}?f=forget_me&sid_token=${encodeURIComponent(upstream.sidToken)}`, {
          signal: AbortSignal.timeout(3000),
        });
      }
    } catch {
      // Ignore upstream cleanup errors
    }
  }

  return {
    fetchPublicDomains,
    provisionPublicInbox,
    fetchUpstreamMessages,
    deleteUpstreamInbox,
  };
}

module.exports = {
  createPublicMailRelay,
  parseFromHeader,
  GUERRILLA_DOMAINS,
};
