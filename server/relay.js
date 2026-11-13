'use strict';

const crypto = require('node:crypto');
const sanitizeHtml = require('sanitize-html');
const { simpleParser } = require('mailparser');
const { normalizeAddress, generateRandomUsername } = require('./validate');

const MAIL_TM_BASE = 'https://api.mail.tm';
const TEMPMAIL_LOL_BASE = 'https://api.tempmail.lol/v2';
const GUERRILLA_BASE = 'https://api.guerrillamail.com/ajax.php';
const INBOXES_BASE = 'https://inboxes.com/api/v2';
const TEMPMAIL_PLUS_BASE = 'https://tempmail.plus/api';
const MAILDROP_GRAPHQL = 'https://api.maildrop.cc/graphql';

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

const TEMPMAIL_PLUS_DOMAINS = [
  'mailto.plus',
  'fexpost.com',
  'fexbox.org',
  'mailbox.in.ua',
  'rover.info',
  'chitthi.in',
  'merepost.com',
];

const MAILDROP_DOMAINS = ['maildrop.cc'];

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

  let cachedInboxesDomains = [];
  let inboxesCachedAt = 0;

  let tempmailPlusReachable = false;
  let tempmailPlusCachedAt = 0;

  let maildropReachable = false;
  let maildropCachedAt = 0;

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

  async function fetchInboxesDomains({ force = false } = {}) {
    if (!force && cachedInboxesDomains.length > 0 && Date.now() - inboxesCachedAt < DOMAIN_CACHE_TTL_MS) {
      return cachedInboxesDomains;
    }
    try {
      const res = await requestJson(`${INBOXES_BASE}/domain`);
      if (res.ok && res.data && Array.isArray(res.data.domains)) {
        const list = res.data.domains
          .map((item) => normalizeAddress(item && item.qdn))
          .filter(Boolean);
        if (list.length > 0) {
          cachedInboxesDomains = Array.from(new Set(list));
          inboxesCachedAt = Date.now();
          return cachedInboxesDomains;
        }
      }
    } catch {
      // Fallback to cached domains if available
    }
    return cachedInboxesDomains;
  }

  async function checkTempmailPlusAvailability({ force = false } = {}) {
    if (!force && tempmailPlusCachedAt > 0 && Date.now() - tempmailPlusCachedAt < PROBE_CACHE_TTL_MS) {
      return tempmailPlusReachable;
    }
    try {
      const res = await requestJson(`${TEMPMAIL_PLUS_BASE}/mails?email=twprobe%40mailto.plus&limit=1&epin=`);
      tempmailPlusCachedAt = Date.now();
      tempmailPlusReachable = Boolean(res.ok && res.data && res.data.result === true);
    } catch {
      tempmailPlusReachable = false;
    }
    return tempmailPlusReachable;
  }

  async function checkMaildropAvailability({ force = false } = {}) {
    if (!force && maildropCachedAt > 0 && Date.now() - maildropCachedAt < PROBE_CACHE_TTL_MS) {
      return maildropReachable;
    }
    try {
      const res = await requestJson(MAILDROP_GRAPHQL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: 'query { inbox(mailbox:"twprobe") { id } }' }),
      });
      maildropCachedAt = Date.now();
      maildropReachable = Boolean(res.ok && res.data && res.data.data && Array.isArray(res.data.data.inbox));
    } catch {
      maildropReachable = false;
    }
    return maildropReachable;
  }

  async function fetchPublicDomains({ force = false } = {}) {
    if (!force && inFlightDomainsPromise) {
      return inFlightDomainsPromise;
    }

    const job = (async () => {
      const [
        mailTmResult,
        tempmailLolResult,
        guerrillaResult,
        inboxesResult,
        tempmailPlusResult,
        maildropResult,
      ] = await Promise.allSettled([
        fetchMailTmDomains({ force }),
        fetchTempmailLolDomains({ force }),
        checkGuerrillaAvailability({ force }),
        fetchInboxesDomains({ force }),
        checkTempmailPlusAvailability({ force }),
        checkMaildropAvailability({ force }),
      ]);

      const mailTmDomains = mailTmResult.status === 'fulfilled' ? mailTmResult.value : [];
      const tempmailDomains = tempmailLolResult.status === 'fulfilled' ? tempmailLolResult.value : [];
      const hasGuerrilla = guerrillaResult.status === 'fulfilled' && guerrillaResult.value;
      const inboxesDomains = inboxesResult.status === 'fulfilled' ? inboxesResult.value : [];
      const hasTempmailPlus = tempmailPlusResult.status === 'fulfilled' && tempmailPlusResult.value;
      const hasMaildrop = maildropResult.status === 'fulfilled' && maildropResult.value;

      const combined = [
        ...mailTmDomains,
        ...tempmailDomains,
        ...(hasGuerrilla ? GUERRILLA_DOMAINS : []),
        ...inboxesDomains,
        ...(hasTempmailPlus ? TEMPMAIL_PLUS_DOMAINS : []),
        ...(hasMaildrop ? MAILDROP_DOMAINS : []),
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

  function createInboxesInbox({ username, domain }) {
    const effectiveUser = username || generateRandomUsername(10);
    const address = normalizeAddress(`${effectiveUser}@${domain}`);
    return {
      address,
      upstream: {
        provider: 'inboxes.com',
        address,
      },
    };
  }

  function createTempmailPlusInbox({ username, domain }) {
    const effectiveUser = username || generateRandomUsername(10);
    const address = normalizeAddress(`${effectiveUser}@${domain}`);
    return {
      address,
      upstream: {
        provider: 'tempmail.plus',
        address,
      },
    };
  }

  function createMaildropInbox({ username }) {
    const mailbox = username || generateRandomUsername(10);
    const address = normalizeAddress(`${mailbox}@maildrop.cc`);
    return {
      address,
      upstream: {
        provider: 'maildrop.cc',
        mailbox,
        address,
      },
    };
  }

  async function provisionPublicInbox({ username, domain } = {}) {
    const [
      mailTmDomains,
      tempmailDomains,
      hasGuerrilla,
      inboxesDomains,
      hasTempmailPlus,
      hasMaildrop,
    ] = await Promise.all([
      fetchMailTmDomains(),
      fetchTempmailLolDomains(),
      checkGuerrillaAvailability(),
      fetchInboxesDomains(),
      checkTempmailPlusAvailability(),
      checkMaildropAvailability(),
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

      if (inboxesDomains.includes(cleanDomain)) {
        return createInboxesInbox({ username, domain: cleanDomain });
      }

      if (TEMPMAIL_PLUS_DOMAINS.includes(cleanDomain)) {
        return createTempmailPlusInbox({ username, domain: cleanDomain });
      }

      if (MAILDROP_DOMAINS.includes(cleanDomain)) {
        return createMaildropInbox({ username });
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
      if (inboxesDomains.length > 0) {
        return createInboxesInbox({ username, domain: inboxesDomains[0] });
      }
      if (hasTempmailPlus) {
        return createTempmailPlusInbox({ username, domain: TEMPMAIL_PLUS_DOMAINS[0] });
      }
      if (hasMaildrop) {
        return createMaildropInbox({ username });
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

    if (inboxesDomains.length > 0) {
      const chosen = inboxesDomains[crypto.randomInt(0, inboxesDomains.length)];
      return createInboxesInbox({ domain: chosen });
    }

    if (hasTempmailPlus) {
      return createTempmailPlusInbox({ domain: TEMPMAIL_PLUS_DOMAINS[0] });
    }

    if (hasMaildrop) {
      return createMaildropInbox({});
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
      const text = typeof full.text === 'string'
        ? full.text
        : (rawHtml ? stripTagsToText(rawHtml) : String(full.intro || ''));
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

      const rawHtml = typeof em.html === 'string' ? em.html : '';
      const text = em.body ? String(em.body) : (rawHtml ? stripTagsToText(rawHtml) : '');

      newMessages.push({
        externalId: extId,
        from: parsedFrom.from,
        fromName: parsedFrom.fromName,
        subject: String(em.subject || '(No subject)'),
        date: dateIso,
        text,
        rawHtml,
        attachments: [],
      });
    }

    return { messages: newMessages, refreshedJwt: '' };
  }

  async function fetchInboxesMessages(upstream, seenSet) {
    if (!upstream || !upstream.address) {
      return { messages: [], refreshedJwt: '' };
    }
    const listRes = await requestJson(`${INBOXES_BASE}/inbox/${encodeURIComponent(upstream.address)}`);
    if (!listRes.ok || !listRes.data || !Array.isArray(listRes.data.msgs)) {
      return { messages: [], refreshedJwt: '' };
    }

    const newMessages = [];
    for (const summary of listRes.data.msgs) {
      if (!summary || !summary.uid) continue;
      const extId = `inboxes:${summary.uid}`;
      if (seenSet.has(extId)) continue;

      const detailRes = await requestJson(`${INBOXES_BASE}/message/${encodeURIComponent(summary.uid)}`);
      if (!detailRes.ok || !detailRes.data) continue;
      const full = detailRes.data;

      const parsedFrom = parseFromHeader(full.ff || full.f || summary.f);
      const rawHtml = typeof full.html === 'string' ? full.html : '';
      const text = typeof full.text === 'string' && full.text.trim()
        ? full.text
        : (rawHtml ? stripTagsToText(rawHtml) : '');
      const dateStr = full.cr || summary.cr;
      const parsedDate = dateStr ? new Date(dateStr) : null;
      const dateIso = parsedDate && !Number.isNaN(parsedDate.getTime())
        ? parsedDate.toISOString()
        : new Date().toISOString();

      newMessages.push({
        externalId: extId,
        from: parsedFrom.from,
        fromName: parsedFrom.fromName,
        subject: String(full.s || summary.s || '(No subject)'),
        date: dateIso,
        text,
        rawHtml,
        attachments: Array.isArray(full.at)
          ? full.at.map((att) => ({
            filename: String((att && (att.filename || att.name)) || 'attachment'),
            size: Number((att && att.size) || 0),
            contentType: String((att && (att.contentType || att.type)) || 'application/octet-stream'),
          }))
          : [],
      });
    }

    newMessages.reverse();
    return { messages: newMessages, refreshedJwt: '' };
  }

  async function fetchTempmailPlusMessages(upstream, seenSet) {
    if (!upstream || !upstream.address) {
      return { messages: [], refreshedJwt: '' };
    }
    const listRes = await requestJson(
      `${TEMPMAIL_PLUS_BASE}/mails?email=${encodeURIComponent(upstream.address)}&limit=20&epin=`
    );
    if (!listRes.ok || !listRes.data || !Array.isArray(listRes.data.mail_list)) {
      return { messages: [], refreshedJwt: '' };
    }

    const newMessages = [];
    for (const summary of listRes.data.mail_list) {
      if (!summary || !summary.mail_id) continue;
      const extId = `tmplus:${summary.mail_id}`;
      if (seenSet.has(extId)) continue;

      const detailRes = await requestJson(
        `${TEMPMAIL_PLUS_BASE}/mails/${encodeURIComponent(summary.mail_id)}?email=${encodeURIComponent(upstream.address)}&epin=`
      );
      if (!detailRes.ok || !detailRes.data || detailRes.data.result === false) continue;
      const full = detailRes.data;

      const rawHtml = typeof full.html === 'string' ? full.html : '';
      const text = typeof full.text === 'string' && full.text
        ? full.text
        : (rawHtml ? stripTagsToText(rawHtml) : '');
      const fromAddr = normalizeAddress(full.from_mail || summary.from_mail || full.from) || 'unknown@unknown';
      const fromName = String(full.from_name || summary.from_name || '');
      const parsedDate = full.date ? new Date(full.date) : null;
      const dateIso = parsedDate && !Number.isNaN(parsedDate.getTime())
        ? parsedDate.toISOString()
        : new Date().toISOString();

      newMessages.push({
        externalId: extId,
        from: fromAddr,
        fromName,
        subject: String(full.subject || summary.subject || '(No subject)'),
        date: dateIso,
        text,
        rawHtml,
        attachments: Array.isArray(full.attachments)
          ? full.attachments.map((att) => ({
            filename: String((att && (att.name || att.filename)) || 'attachment'),
            size: Number((att && att.size) || 0),
            contentType: String((att && (att.contentType || att.type)) || 'application/octet-stream'),
          }))
          : [],
      });
    }

    newMessages.reverse();
    return { messages: newMessages, refreshedJwt: '' };
  }

  async function fetchMaildropMessages(upstream, seenSet) {
    if (!upstream || !upstream.mailbox) {
      return { messages: [], refreshedJwt: '' };
    }
    const mailbox = upstream.mailbox;
    const listRes = await requestJson(MAILDROP_GRAPHQL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: 'query($m: String!) { inbox(mailbox: $m) { id headerfrom subject date } }',
        variables: { m: mailbox },
      }),
    });
    const list = listRes.data && listRes.data.data && Array.isArray(listRes.data.data.inbox)
      ? listRes.data.data.inbox
      : null;
    if (!listRes.ok || !list) {
      return { messages: [], refreshedJwt: '' };
    }

    const newMessages = [];
    for (const summary of list) {
      if (!summary || !summary.id) continue;
      const extId = `maildrop:${summary.id}`;
      if (seenSet.has(extId)) continue;

      const detailRes = await requestJson(MAILDROP_GRAPHQL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: 'query($m: String!, $id: String!) { message(mailbox: $m, id: $id) { id headerfrom mailfrom subject date data html } }',
          variables: { m: mailbox, id: summary.id },
        }),
      });
      const full = detailRes.data && detailRes.data.data && detailRes.data.data.message;
      if (!detailRes.ok || !full) continue;

      let parsedFrom = parseFromHeader(full.headerfrom || summary.headerfrom || full.mailfrom);
      let subject = String(full.subject || summary.subject || '(No subject)');
      let rawHtml = typeof full.html === 'string' ? full.html : '';
      let text = '';
      let attachments = [];
      let dateIso = new Date().toISOString();
      if (full.date || summary.date) {
        const d = new Date(full.date || summary.date);
        if (!Number.isNaN(d.getTime())) dateIso = d.toISOString();
      }

      if (typeof full.data === 'string' && full.data.trim()) {
        try {
          const parsedMime = await simpleParser(full.data);
          const fromEntry = parsedMime.from && Array.isArray(parsedMime.from.value) && parsedMime.from.value[0];
          if (fromEntry && fromEntry.address) {
            parsedFrom = {
              from: normalizeAddress(fromEntry.address) || parsedFrom.from,
              fromName: String(fromEntry.name || parsedFrom.fromName || ''),
            };
          }
          if (parsedMime.subject) subject = String(parsedMime.subject).trim();
          if (typeof parsedMime.html === 'string' && parsedMime.html) rawHtml = parsedMime.html;
          if (parsedMime.text) text = String(parsedMime.text);
          if (Array.isArray(parsedMime.attachments)) {
            attachments = parsedMime.attachments.map((att) => ({
              filename: String(att.filename || 'attachment'),
              size: Number(att.size || (att.content ? att.content.length : 0)),
              contentType: String(att.contentType || 'application/octet-stream'),
            }));
          }
        } catch {
          // Fallback to metadata + rawHtml below
        }
      }

      if (!text) {
        text = rawHtml ? stripTagsToText(rawHtml) : '';
      }

      newMessages.push({
        externalId: extId,
        from: parsedFrom.from,
        fromName: parsedFrom.fromName,
        subject,
        date: dateIso,
        text,
        rawHtml,
        attachments,
      });
    }

    newMessages.reverse();
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
      if (upstream.provider === 'inboxes.com') {
        return await fetchInboxesMessages(upstream, seenSet);
      }
      if (upstream.provider === 'tempmail.plus') {
        return await fetchTempmailPlusMessages(upstream, seenSet);
      }
      if (upstream.provider === 'maildrop.cc') {
        return await fetchMaildropMessages(upstream, seenSet);
      }
    } catch {
      // Non-fatal upstream poll error
    }
    return { messages: [], refreshedJwt: '' };
  }

  async function sendTempmailPlusMail({ from, to, subject, text }) {
    const res = await requestJson(`${TEMPMAIL_PLUS_BASE}/mails/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        email: normalizeAddress(from),
        to: normalizeAddress(to),
        subject: String(subject || '(No subject)'),
        text: String(text || ''),
      }),
    });

    if (!res.ok || !res.data || res.data.result !== true) {
      const msg = (res.data && res.data.err && res.data.err.msg) || 'Public tempmail.plus send failed.';
      const err = new Error(msg);
      err.statusCode = 502;
      throw err;
    }

    return { delivered: true, transport: 'tempmail.plus', to: normalizeAddress(to) };
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
    sendTempmailPlusMail,
    deleteUpstreamInbox,
  };
}

module.exports = {
  createPublicMailRelay,
  parseFromHeader,
  GUERRILLA_DOMAINS,
  TEMPMAIL_PLUS_DOMAINS,
  MAILDROP_DOMAINS,
};
