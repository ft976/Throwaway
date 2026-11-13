'use strict';

const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const {
  normalizeAddress,
  validateUsername,
  validateDomain,
  validateAddressSyntax,
  generateRandomUsername,
} = require('./validate');
const { sanitizeEmailHtml, createSnippet } = require('./sanitize');
const { createPublicMailRelay } = require('./relay');

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function verifyToken(providedToken, expectedHashHex) {
  if (typeof providedToken !== 'string' || !providedToken || typeof expectedHashHex !== 'string') {
    return false;
  }
  const providedBuf = crypto.createHash('sha256').update(providedToken).digest();
  let expectedBuf;
  try {
    expectedBuf = Buffer.from(expectedHashHex, 'hex');
  } catch {
    return false;
  }
  if (providedBuf.length !== expectedBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(providedBuf, expectedBuf);
}

function verifySharedSecret(providedSecret, expectedSecret) {
  if (
    typeof providedSecret !== 'string' ||
    typeof expectedSecret !== 'string' ||
    !providedSecret ||
    !expectedSecret
  ) {
    return false;
  }
  const a = crypto.createHash('sha256').update(providedSecret).digest();
  const b = crypto.createHash('sha256').update(expectedSecret).digest();
  return crypto.timingSafeEqual(a, b);
}

function inboxKey(address) {
  return `inbox:${address}`;
}

function msgsListKey(address) {
  return `inbox:${address}:msgs`;
}

function messageKey(address, id) {
  return `msg:${address}:${id}`;
}

function apiKeyRedisKey(keyHash) {
  return `apikey:${keyHash}`;
}

function createStore(redis, config, { relay: injectedRelay } = {}) {
  const events = new EventEmitter();
  events.setMaxListeners(0);

  const relay = injectedRelay !== undefined
    ? injectedRelay
    : (config.publicMailRelay === 'off' ? null : createPublicMailRelay());

  const lastSyncAt = new Map();
  const inFlightSync = new Map();

  function subscribeInbox(address, listener) {
    const channel = `inbox:${normalizeAddress(address)}`;
    events.on(channel, listener);
    return () => {
      events.off(channel, listener);
    };
  }

  function emitInboxEvent(address, type, payload) {
    const channel = `inbox:${normalizeAddress(address)}`;
    events.emit(channel, { type, payload });
  }

  const nonLocalConfigured = config.domains.filter((d) => !d.endsWith('.local'));
  const hasRealConfiguredDomain = nonLocalConfigured.length > 0;

  async function getDomains() {
    if (!relay) {
      return [...config.domains];
    }
    const publicDomains = await relay.fetchPublicDomains();
    if (hasRealConfiguredDomain) {
      return Array.from(new Set([...config.domains, ...publicDomains]));
    }
    if (config.publicMailRelay === 'on') {
      return Array.from(new Set([...config.domains, ...publicDomains]));
    }
    if (publicDomains.length > 0) {
      return Array.from(new Set([...publicDomains, ...nonLocalConfigured]));
    }
    return [...config.domains];
  }

  async function createInbox({ username, domain } = {}) {
    const ttlMs = config.inboxTtlMs;
    const hasUsername = username !== undefined && username !== null && String(username).trim() !== '';
    const hasDomain = domain !== undefined && domain !== null && String(domain).trim() !== '';

    let cleanUsername;
    if (hasUsername) {
      const userCheck = validateUsername(username);
      if (!userCheck.valid) {
        const err = new Error(userCheck.error);
        err.statusCode = 400;
        throw err;
      }
      cleanUsername = userCheck.username;
    }

    const publicDomains = relay ? await relay.fetchPublicDomains() : [];
    const allowedDomains = Array.from(new Set([...config.domains, ...publicDomains]));

    let cleanDomain;
    if (hasDomain) {
      const domainCheck = validateDomain(domain, allowedDomains);
      if (!domainCheck.valid) {
        const err = new Error(domainCheck.error);
        err.statusCode = 400;
        throw err;
      }
      cleanDomain = domainCheck.domain;
    }

    const targetIsOwnServerDomain = Boolean(
      (cleanDomain && config.domains.includes(cleanDomain))
      || (!cleanDomain && hasRealConfiguredDomain)
    );

    if (relay && !targetIsOwnServerDomain) {
      const provisioned = await relay.provisionPublicInbox({
        username: cleanUsername,
        domain: cleanDomain,
      });

      if (provisioned && provisioned.address) {
        const address = provisioned.address;
        const token = crypto.randomBytes(32).toString('base64url');
        const now = Date.now();
        const expiresAt = now + ttlMs;
        const payload = JSON.stringify({
          tokenHash: hashToken(token),
          createdAt: now,
          expiresAt,
          upstream: provisioned.upstream,
          seenExternalIds: [],
        });

        const created = await redis.set(inboxKey(address), payload, 'NX', 'PX', ttlMs);
        if (created !== null) {
          return {
            address,
            token,
            expiresAt,
            ttlMs,
            provider: provisioned.upstream.provider,
          };
        }
      }

      if (cleanDomain && !config.domains.includes(cleanDomain)) {
        const err = new Error(`Public mail domain "${cleanDomain}" is temporarily unavailable. Please choose another domain.`);
        err.statusCode = 502;
        throw err;
      }
    }

    const targetDomain = cleanDomain
      || (hasUsername ? config.domains[0] : config.domains[crypto.randomInt(0, config.domains.length)]);

    let companionUpstream = undefined;
    if (relay && targetIsOwnServerDomain) {
      try {
        const provisioned = await relay.provisionPublicInbox({
          username: cleanUsername,
        });
        if (provisioned && provisioned.upstream) {
          companionUpstream = provisioned.upstream;
        }
      } catch {
        // Non-fatal upstream mirror fallback
      }
    }

    if (cleanUsername) {
      const address = `${cleanUsername}@${targetDomain}`;
      const token = crypto.randomBytes(32).toString('base64url');
      const now = Date.now();
      const expiresAt = now + ttlMs;
      const payload = JSON.stringify({
        tokenHash: hashToken(token),
        createdAt: now,
        expiresAt,
        upstream: companionUpstream,
        seenExternalIds: [],
      });

      const created = await redis.set(inboxKey(address), payload, 'NX', 'PX', ttlMs);
      if (created === null) {
        const err = new Error('That email address is already in use.');
        err.statusCode = 409;
        throw err;
      }

      return { address, token, expiresAt, ttlMs, provider: 'local' };
    }

    for (let attempt = 0; attempt < 15; attempt += 1) {
      const candidateUser = generateRandomUsername(10);
      const address = `${candidateUser}@${targetDomain}`;
      const token = crypto.randomBytes(32).toString('base64url');
      const now = Date.now();
      const expiresAt = now + ttlMs;
      const payload = JSON.stringify({
        tokenHash: hashToken(token),
        createdAt: now,
        expiresAt,
        upstream: companionUpstream,
        seenExternalIds: [],
      });

      const created = await redis.set(inboxKey(address), payload, 'NX', 'PX', ttlMs);
      if (created !== null) {
        return { address, token, expiresAt, ttlMs, provider: 'local' };
      }
    }

    const err = new Error('Could not allocate a unique email address. Please try again.');
    err.statusCode = 503;
    throw err;
  }

  async function getAuthorizedInbox(rawAddress, token) {
    const addrCheck = validateAddressSyntax(rawAddress);
    if (!addrCheck.valid) {
      return null;
    }
    const address = addrCheck.address;
    const raw = await redis.get(inboxKey(address));
    if (!raw) {
      return null;
    }

    let inbox;
    try {
      inbox = JSON.parse(raw);
    } catch {
      return null;
    }

    if (!inbox || typeof inbox.expiresAt !== 'number' || inbox.expiresAt <= Date.now()) {
      return null;
    }

    if (!verifyToken(token, inbox.tokenHash)) {
      return null;
    }

    return { address, inbox };
  }

  async function rotateInboxToken(rawAddress, token) {
    const auth = await getAuthorizedInbox(rawAddress, token);
    if (!auth) {
      return null;
    }
    const { address, inbox } = auth;
    const newToken = crypto.randomBytes(32).toString('base64url');
    const updatedInbox = {
      ...inbox,
      tokenHash: hashToken(newToken),
    };

    const pipe = redis.pipeline();
    pipe.set(inboxKey(address), JSON.stringify(updatedInbox));
    pipe.pexpireat(inboxKey(address), inbox.expiresAt);
    await pipe.exec();

    return {
      address,
      token: newToken,
      expiresAt: inbox.expiresAt,
      ttlMs: Math.max(0, inbox.expiresAt - Date.now()),
    };
  }

  async function inboxExists(rawAddress) {
    const addrCheck = validateAddressSyntax(rawAddress);
    if (!addrCheck.valid) {
      return false;
    }
    const raw = await redis.get(inboxKey(addrCheck.address));
    if (!raw) {
      return false;
    }
    try {
      const parsed = JSON.parse(raw);
      return Boolean(parsed && typeof parsed.expiresAt === 'number' && parsed.expiresAt > Date.now());
    } catch {
      return false;
    }
  }

  async function saveMessage(rawAddress, messageInput) {
    const address = normalizeAddress(rawAddress);
    const rawInbox = await redis.get(inboxKey(address));
    if (!rawInbox) {
      return false;
    }

    let inbox;
    try {
      inbox = JSON.parse(rawInbox);
    } catch {
      return false;
    }

    if (!inbox || typeof inbox.expiresAt !== 'number' || inbox.expiresAt <= Date.now()) {
      return false;
    }

    const id = crypto.randomUUID();
    const message = {
      id,
      from: String(messageInput.from || 'unknown@unknown').toLowerCase(),
      fromName: String(messageInput.fromName || ''),
      subject: String(messageInput.subject || '(No subject)'),
      date: String(messageInput.date || new Date().toISOString()),
      text: String(messageInput.text || ''),
      html: String(messageInput.html || ''),
      snippet: String(messageInput.snippet || ''),
      attachments: Array.isArray(messageInput.attachments) ? messageInput.attachments : [],
      read: false,
    };

    const listKey = msgsListKey(address);
    const msgKey = messageKey(address, id);
    const expiresAt = inbox.expiresAt;

    const existingOverflowIds = await redis.lrange(listKey, config.maxMessages - 1, -1);

    const pipe = redis.pipeline();
    pipe.set(msgKey, JSON.stringify(message));
    pipe.pexpireat(msgKey, expiresAt);
    pipe.lpush(listKey, id);
    pipe.ltrim(listKey, 0, config.maxMessages - 1);
    pipe.pexpireat(listKey, expiresAt);
    pipe.pexpireat(inboxKey(address), expiresAt);

    if (existingOverflowIds.length > 0) {
      for (const oldId of existingOverflowIds) {
        pipe.del(messageKey(address, oldId));
      }
    }

    await pipe.exec();

    emitInboxEvent(address, 'message', {
      id: message.id,
      from: message.from,
      fromName: message.fromName,
      subject: message.subject,
      date: message.date,
      snippet: message.snippet,
      hasAttachments: message.attachments.length > 0,
      read: false,
    });

    return true;
  }

  async function syncUpstreamMessages(address, { force = false } = {}) {
    if (!relay) return;
    const normAddr = normalizeAddress(address);
    if (!force) {
      const prev = lastSyncAt.get(normAddr) || 0;
      if (Date.now() - prev < 2000) return;
    }

    if (inFlightSync.has(normAddr)) {
      return inFlightSync.get(normAddr);
    }

    const job = (async () => {
      try {
        lastSyncAt.set(normAddr, Date.now());
        const rawInbox = await redis.get(inboxKey(normAddr));
        if (!rawInbox) return;
        let inbox;
        try {
          inbox = JSON.parse(rawInbox);
        } catch {
          return;
        }
        if (!inbox || !inbox.upstream || inbox.expiresAt <= Date.now()) return;

        const seen = Array.isArray(inbox.seenExternalIds) ? inbox.seenExternalIds : [];
        const { messages, refreshedJwt } = await relay.fetchUpstreamMessages(inbox.upstream, seen);
        let modified = false;

        if (refreshedJwt) {
          inbox.upstream.jwt = refreshedJwt;
          modified = true;
        }

        const seenSet = new Set(seen);
        for (const msg of messages) {
          if (msg.externalId && seenSet.has(msg.externalId)) continue;
          const html = msg.rawHtml ? sanitizeEmailHtml(msg.rawHtml) : '';
          const snippet = createSnippet(msg.text, msg.rawHtml);
          const saved = await saveMessage(normAddr, {
            from: msg.from,
            fromName: msg.fromName,
            subject: msg.subject,
            date: msg.date,
            text: msg.text,
            html,
            snippet,
            attachments: msg.attachments || [],
          });
          if (saved && msg.externalId) {
            seenSet.add(msg.externalId);
            modified = true;
          }
        }

        if (modified) {
          const latestRaw = await redis.get(inboxKey(normAddr));
          if (latestRaw) {
            const latestInbox = JSON.parse(latestRaw);
            latestInbox.upstream = inbox.upstream;
            latestInbox.seenExternalIds = Array.from(seenSet).slice(-200);
            const pipe = redis.pipeline();
            pipe.set(inboxKey(normAddr), JSON.stringify(latestInbox));
            pipe.pexpireat(inboxKey(normAddr), latestInbox.expiresAt);
            await pipe.exec();
          }
        }
      } catch {
        // Non-fatal upstream sync error
      } finally {
        inFlightSync.delete(normAddr);
      }
    })();

    inFlightSync.set(normAddr, job);
    return job;
  }

  async function listMessages(rawAddress, token) {
    const auth = await getAuthorizedInbox(rawAddress, token);
    if (!auth) {
      return null;
    }
    const { address, inbox } = auth;
    if (inbox.upstream && relay) {
      await syncUpstreamMessages(address);
    }
    const freshRaw = await redis.get(inboxKey(address));
    const currentInbox = freshRaw ? JSON.parse(freshRaw) : inbox;
    const ids = await redis.lrange(msgsListKey(address), 0, config.maxMessages - 1);

    const messages = [];
    if (ids.length > 0) {
      const keys = ids.map((id) => messageKey(address, id));
      const rawMessages = await redis.mget(...keys);
      for (const rawMsg of rawMessages) {
        if (!rawMsg) continue;
        try {
          const msg = JSON.parse(rawMsg);
          messages.push({
            id: msg.id,
            from: msg.from,
            fromName: msg.fromName,
            subject: msg.subject,
            date: msg.date,
            snippet: msg.snippet,
            hasAttachments: Array.isArray(msg.attachments) && msg.attachments.length > 0,
            read: Boolean(msg.read),
          });
        } catch {
          // Ignore malformed entry
        }
      }
    }

    return {
      address,
      expiresAt: currentInbox.expiresAt,
      ttlMs: Math.max(0, currentInbox.expiresAt - Date.now()),
      provider: currentInbox.upstream ? currentInbox.upstream.provider : 'local',
      messages,
    };
  }

  async function getMessage(rawAddress, id, token) {
    const auth = await getAuthorizedInbox(rawAddress, token);
    if (!auth) {
      return { notFound: true };
    }
    if (!id || typeof id !== 'string') {
      return { notFound: true };
    }
    const { address, inbox } = auth;
    const msgKey = messageKey(address, id);
    const rawMsg = await redis.get(msgKey);
    if (!rawMsg) {
      return { notFound: true };
    }

    let message;
    try {
      message = JSON.parse(rawMsg);
    } catch {
      return { notFound: true };
    }

    if (!message.read) {
      message.read = true;
      const pipe = redis.pipeline();
      pipe.set(msgKey, JSON.stringify(message));
      pipe.pexpireat(msgKey, inbox.expiresAt);
      await pipe.exec();
    }

    return { notFound: false, message };
  }

  async function deleteMessage(rawAddress, id, token) {
    const auth = await getAuthorizedInbox(rawAddress, token);
    if (!auth) {
      return { notFound: true };
    }
    if (!id || typeof id !== 'string') {
      return { notFound: true };
    }
    const { address } = auth;
    const deleted = await redis.del(messageKey(address, id));
    await redis.lrem(msgsListKey(address), 0, id);
    if (deleted === 0) {
      return { notFound: true };
    }
    return { notFound: false };
  }

  async function extendInbox(rawAddress, token) {
    const auth = await getAuthorizedInbox(rawAddress, token);
    if (!auth) {
      return null;
    }
    const { address, inbox } = auth;
    const newExpiresAt = Date.now() + config.inboxTtlMs;
    const updatedInbox = {
      ...inbox,
      expiresAt: newExpiresAt,
    };

    const listKey = msgsListKey(address);
    const ids = await redis.lrange(listKey, 0, config.maxMessages - 1);

    const pipe = redis.pipeline();
    pipe.set(inboxKey(address), JSON.stringify(updatedInbox));
    pipe.pexpireat(inboxKey(address), newExpiresAt);
    pipe.pexpireat(listKey, newExpiresAt);
    for (const id of ids) {
      pipe.pexpireat(messageKey(address, id), newExpiresAt);
    }
    await pipe.exec();

    return {
      expiresAt: newExpiresAt,
      ttlMs: config.inboxTtlMs,
    };
  }

  async function deleteInbox(rawAddress, token) {
    const auth = await getAuthorizedInbox(rawAddress, token);
    if (!auth) {
      return false;
    }
    const { address, inbox } = auth;
    const listKey = msgsListKey(address);
    const ids = await redis.lrange(listKey, 0, config.maxMessages - 1);
    const keysToDelete = [
      inboxKey(address),
      listKey,
      ...ids.map((id) => messageKey(address, id)),
    ];
    if (keysToDelete.length > 0) {
      await redis.del(...keysToDelete);
    }
    lastSyncAt.delete(address);
    emitInboxEvent(address, 'deleted', { address });
    if (inbox && inbox.upstream && relay) {
      relay.deleteUpstreamInbox(inbox.upstream).catch(() => {});
    }
    return true;
  }

  async function createApiKey({ label = 'default' } = {}) {
    const cleanLabel = String(label || 'default').trim().slice(0, 64) || 'default';
    const keyId = crypto.randomUUID();
    const apiKey = `tw_live_${crypto.randomBytes(24).toString('base64url')}`;
    const keyHash = hashToken(apiKey);
    const now = Date.now();
    const ttlMs = config.apiKeyTtlMs || 30 * 24 * 60 * 60 * 1000;
    const expiresAt = now + ttlMs;

    const record = JSON.stringify({
      keyId,
      label: cleanLabel,
      keyHash,
      createdAt: now,
      expiresAt,
    });

    const pipe = redis.pipeline();
    pipe.set(apiKeyRedisKey(keyHash), record);
    pipe.pexpireat(apiKeyRedisKey(keyHash), expiresAt);
    await pipe.exec();

    return {
      keyId,
      apiKey,
      label: cleanLabel,
      createdAt: new Date(now).toISOString(),
      expiresAt,
    };
  }

  async function verifyApiKey(rawApiKey) {
    if (typeof rawApiKey !== 'string' || !rawApiKey.startsWith('tw_live_')) {
      return null;
    }
    const keyHash = hashToken(rawApiKey);
    const raw = await redis.get(apiKeyRedisKey(keyHash));
    if (!raw) {
      return null;
    }
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return null;
    }
    if (!parsed || typeof parsed.expiresAt !== 'number' || parsed.expiresAt <= Date.now()) {
      return null;
    }
    if (!verifyToken(rawApiKey, parsed.keyHash)) {
      return null;
    }
    return {
      keyId: parsed.keyId,
      label: parsed.label,
      createdAt: parsed.createdAt,
      expiresAt: parsed.expiresAt,
    };
  }

  async function revokeApiKey(rawApiKey) {
    if (typeof rawApiKey !== 'string' || !rawApiKey.startsWith('tw_live_')) {
      return false;
    }
    const keyHash = hashToken(rawApiKey);
    const deleted = await redis.del(apiKeyRedisKey(keyHash));
    return deleted > 0;
  }

  return {
    getDomains,
    createInbox,
    getAuthorizedInbox,
    rotateInboxToken,
    inboxExists,
    saveMessage,
    syncUpstreamMessages,
    listMessages,
    getMessage,
    deleteMessage,
    extendInbox,
    deleteInbox,
    subscribeInbox,
    createApiKey,
    verifyApiKey,
    revokeApiKey,
    relay,
  };
}

module.exports = {
  createStore,
  hashToken,
  verifyToken,
  verifySharedSecret,
};
