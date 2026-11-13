'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const { rateLimit } = require('express-rate-limit');
const { simpleParser } = require('mailparser');
const { normalizeAddress, validateAddressSyntax } = require('./validate');
const { sanitizeEmailHtml, createSnippet } = require('./sanitize');
const { verifySharedSecret } = require('./store');
const { verifySmtpConnectivity, sendInternalSmtpMail, sendOutboundEmail, stripHtmlToText } = require('./smtp');

class RedisRateLimitStore {
  constructor(redis, prefix) {
    this.redis = redis;
    this.prefix = prefix;
    this.windowMs = 60000;
  }

  init(options) {
    this.windowMs = options.windowMs;
  }

  async increment(key) {
    const fullKey = `${this.prefix}${key}`;
    const totalHits = await this.redis.incr(fullKey);
    let pttl = await this.redis.pttl(fullKey);
    if (totalHits === 1 || pttl < 0) {
      await this.redis.pexpire(fullKey, this.windowMs);
      pttl = this.windowMs;
    }
    return {
      totalHits,
      resetTime: new Date(Date.now() + Math.max(0, pttl)),
    };
  }

  async decrement(key) {
    const fullKey = `${this.prefix}${key}`;
    const current = await this.redis.get(fullKey);
    if (current !== null) {
      const next = Math.max(0, Number(current) - 1);
      const pttl = await this.redis.pttl(fullKey);
      if (next === 0) {
        await this.redis.del(fullKey);
      } else if (pttl > 0) {
        await this.redis.set(fullKey, String(next), 'PX', pttl);
      }
    }
  }

  async resetKey(key) {
    await this.redis.del(`${this.prefix}${key}`);
  }
}

function createLimiter({ redis, prefix, windowMs, max, keyMax }) {
  return rateLimit({
    windowMs,
    max: (req) => (req.apiKey && keyMax ? keyMax : max),
    keyGenerator: (req) => (req.apiKey ? `key:${req.apiKey.keyId}` : `ip:${req.ip || 'unknown'}`),
    standardHeaders: true,
    legacyHeaders: false,
    validate: { trustProxy: false, keyGeneratorIpFallback: false },
    store: redis ? new RedisRateLimitStore(redis, prefix) : undefined,
    handler: (req, res) => {
      const resetTime = req.rateLimit && req.rateLimit.resetTime;
      const retryAfterSec = resetTime
        ? Math.max(1, Math.ceil((new Date(resetTime).getTime() - Date.now()) / 1000))
        : Math.max(1, Math.ceil(windowMs / 1000));
      res.set('Retry-After', String(retryAfterSec));
      res.status(429).json({ error: 'Too many requests. Please try again later.' });
    },
  });
}

function extractBearerToken(req) {
  const auth = req.get('authorization');
  if (!auth || typeof auth !== 'string') return '';
  const match = /^Bearer\s+(.+)$/i.exec(auth.trim());
  return match ? match[1].trim() : '';
}

function computeInboxEtag(data) {
  const summary = `${data.address}|${data.expiresAt}|${data.messages
    .map((m) => `${m.id}:${m.read ? '1' : '0'}`)
    .join(',')}`;
  const hash = crypto.createHash('sha256').update(summary).digest('base64url').slice(0, 24);
  return `"${hash}"`;
}

function buildOpenApiSpec(config) {
  return {
    openapi: '3.0.3',
    info: {
      title: 'Throwaway Public & Secrets API',
      version: '1.0.0',
      description: 'Public disposable email API with Bearer inbox tokens, developer API keys, SSE real-time mail stream, inbound webhook delivery, and admin status.',
    },
    servers: [{ url: '/api/v1' }, { url: '/api' }],
    components: {
      securitySchemes: {
        InboxBearer: { type: 'http', scheme: 'bearer' },
        ApiKeyAuth: { type: 'apiKey', in: 'header', name: 'X-API-Key' },
        WebhookSecret: { type: 'apiKey', in: 'header', name: 'X-Webhook-Secret' },
        AdminBearer: { type: 'http', scheme: 'bearer' },
      },
    },
    paths: {
      '/health': {
        get: {
          summary: 'Check Redis and internal SMTP server readiness',
          responses: { 200: { description: 'Backend ready' }, 503: { description: 'Service unavailable' } },
        },
      },
      '/domains': {
        get: {
          summary: 'List active receiving domains',
          responses: { 200: { description: 'List of domains' } },
        },
      },
      '/domains/status': {
        get: {
          summary: 'Check SMTP readiness and public MX DNS status for own-server domains',
          responses: { 200: { description: 'Domain delivery status' } },
        },
      },
      '/inbox': {
        post: {
          summary: 'Create a random or custom disposable inbox',
          responses: { 201: { description: 'Created inbox with one-time Bearer secret token' } },
        },
      },
      '/inbox/{address}': {
        get: {
          summary: 'List inbox messages (supports ETag / If-None-Match)',
          security: [{ InboxBearer: [] }],
          responses: { 200: { description: 'Inbox summary and messages' }, 304: { description: 'Not Modified' }, 404: { description: 'Not Found' } },
        },
        delete: {
          summary: 'Delete inbox and all stored messages',
          security: [{ InboxBearer: [] }],
          responses: { 204: { description: 'Deleted' }, 404: { description: 'Not Found' } },
        },
      },
      '/inbox/{address}/stream': {
        get: {
          summary: 'Subscribe to real-time incoming mail notifications via Server-Sent Events (SSE)',
          security: [{ InboxBearer: [] }],
          responses: { 200: { description: 'SSE event stream' }, 404: { description: 'Not Found' } },
        },
      },
      '/inbox/{address}/extend': {
        post: {
          summary: `Reset inbox expiry timer (+${config.inboxTtlMinutes} minutes)`,
          security: [{ InboxBearer: [] }],
          responses: { 200: { description: 'Updated expiry timestamp' }, 404: { description: 'Not Found' } },
        },
      },
      '/inbox/{address}/test-email': {
        post: {
          summary: 'Send a live test email through the internal SMTP server to an own-server inbox',
          security: [{ InboxBearer: [] }],
          responses: { 202: { description: 'Test email delivered over SMTP' }, 400: { description: 'Unsupported inbox' }, 404: { description: 'Not Found' } },
        },
      },
      '/inbox/{address}/send': {
        post: {
          summary: 'Send an email from the active disposable inbox to a local or external recipient',
          security: [{ InboxBearer: [] }],
          responses: {
            202: { description: 'Email accepted for delivery' },
            400: { description: 'Invalid recipient or empty body' },
            404: { description: 'Inbox or local recipient not found' },
            502: { description: 'Upstream mail transport error' },
          },
        },
      },
      '/inbox/{address}/rotate-token': {
        post: {
          summary: 'Rotate the secret Bearer token for an inbox',
          security: [{ InboxBearer: [] }],
          responses: { 200: { description: 'New secret token issued' }, 404: { description: 'Not Found' } },
        },
      },
      '/inbox/{address}/messages/{id}': {
        get: {
          summary: 'Read a full sanitized message and mark it read',
          security: [{ InboxBearer: [] }],
          responses: { 200: { description: 'Full message JSON' }, 404: { description: 'Not Found' } },
        },
        delete: {
          summary: 'Delete a single message',
          security: [{ InboxBearer: [] }],
          responses: { 204: { description: 'Deleted' }, 404: { description: 'Not Found' } },
        },
      },
      '/keys': {
        post: {
          summary: 'Generate a scoped developer API key for elevated rate limits',
          responses: { 201: { description: 'API key issued once' } },
        },
      },
      '/keys/me': {
        get: {
          summary: 'Inspect metadata for the caller X-API-Key',
          security: [{ ApiKeyAuth: [] }],
          responses: { 200: { description: 'API key metadata' }, 401: { description: 'Unauthorized' } },
        },
        delete: {
          summary: 'Revoke the caller X-API-Key',
          security: [{ ApiKeyAuth: [] }],
          responses: { 204: { description: 'Revoked' }, 401: { description: 'Unauthorized' } },
        },
      },
      '/inbound/email': {
        post: {
          summary: 'Deliver an email over HTTPS (Cloudflare Email Workers / HTTP mail relay)',
          security: [{ WebhookSecret: [] }],
          responses: { 202: { description: 'Delivered to inbox' }, 401: { description: 'Unauthorized' }, 404: { description: 'Mailbox not found' } },
        },
      },
      '/admin/status': {
        get: {
          summary: 'Server and Redis status (requires ADMIN_SECRET)',
          security: [{ AdminBearer: [] }],
          responses: { 200: { description: 'Runtime health status' }, 404: { description: 'Not Found' } },
        },
      },
    },
  };
}

function createApp({
  config,
  redis,
  store,
  smtpServer = null,
  checkSmtpHealth = null,
  resolveMx = null,
  createTransport = null,
  rateLimits = {},
}) {
  const app = express();
  const mxCache = new Map();
  const MX_CACHE_TTL_MS = 60 * 1000;

  async function checkRedisHealth() {
    try {
      const pong = await redis.ping();
      return pong === 'PONG'
        ? { ok: true }
        : { ok: false, error: 'Unexpected Redis PING response.' };
    } catch (err) {
      return { ok: false, error: err && err.message ? err.message : 'Redis ping failed.' };
    }
  }

  async function checkSmtpStatus() {
    if (typeof checkSmtpHealth === 'function') {
      return checkSmtpHealth();
    }
    return verifySmtpConnectivity(smtpServer);
  }

  async function runReadinessChecks() {
    const [redisResult, smtpResult] = await Promise.all([
      checkRedisHealth(),
      checkSmtpStatus(),
    ]);
    return {
      ok: Boolean(redisResult.ok && smtpResult.ok),
      redis: redisResult,
      smtp: smtpResult,
    };
  }

  async function inspectDomainMx(domain) {
    if (domain.endsWith('.local')) {
      return {
        domain,
        mxStatus: 'local',
        mxRecords: [],
        readyForExternalMail: false,
      };
    }

    const cached = mxCache.get(domain);
    if (cached && Date.now() - cached.checkedAt < MX_CACHE_TTL_MS) {
      return cached.value;
    }

    const mxResolver = typeof resolveMx === 'function'
      ? resolveMx
      : (d) => dns.promises.resolveMx(d);

    let timer;
    try {
      const records = await Promise.race([
        mxResolver(domain),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('ETIMEOUT')), 3000);
          if (timer.unref) timer.unref();
        }),
      ]);

      const list = Array.isArray(records) ? records : [];
      const validExchanges = list
        .map((r) => String((r && r.exchange) || '').trim())
        .filter((ex) => ex && ex !== '.');

      let value;
      if (validExchanges.length > 0) {
        value = {
          domain,
          mxStatus: 'ok',
          mxRecords: validExchanges,
          readyForExternalMail: true,
        };
      } else if (list.length > 0) {
        value = {
          domain,
          mxStatus: 'null-mx',
          mxRecords: [],
          readyForExternalMail: false,
        };
      } else {
        value = {
          domain,
          mxStatus: 'missing',
          mxRecords: [],
          readyForExternalMail: false,
        };
      }

      mxCache.set(domain, { checkedAt: Date.now(), value });
      return value;
    } catch (err) {
      const code = err && (err.code || err.message);
      const mxStatus = code === 'ENODATA' || code === 'ENOTFOUND' ? 'missing' : 'unknown';
      const value = {
        domain,
        mxStatus,
        mxRecords: [],
        readyForExternalMail: false,
      };
      mxCache.set(domain, { checkedAt: Date.now(), value });
      return value;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  app.set('trust proxy', config.trustProxy);
  app.disable('x-powered-by');

  app.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          'default-src': ["'self'"],
          'frame-src': ["'self'", 'about:', 'blob:'],
          'style-src': ["'self'"],
          'script-src': ["'self'"],
          'img-src': ["'self'", 'data:', 'https:'],
          'connect-src': ["'self'"],
          'object-src': ["'none'"],
          'base-uri': ["'self'"],
          'form-action': ["'self'"],
        },
      },
      frameguard: { action: 'sameorigin' },
    })
  );

  app.use(compression({
    filter: (req, res) => {
      if (req.path.endsWith('/stream') || req.get('accept') === 'text/event-stream') {
        return false;
      }
      return compression.filter(req, res);
    },
  }));

  if (Array.isArray(config.corsOrigins) && config.corsOrigins.length > 0) {
    app.use(['/api', '/api/v1'], (req, res, next) => {
      const origin = req.get('origin');
      if (origin && (config.corsOrigins.includes('*') || config.corsOrigins.includes(origin))) {
        res.set('Access-Control-Allow-Origin', config.corsOrigins.includes('*') ? '*' : origin);
        res.set('Vary', 'Origin');
        res.set('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
        res.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Webhook-Secret, If-None-Match');
        if (req.method === 'OPTIONS') {
          return res.status(204).end();
        }
      }
      return next();
    });
  }

  const smallJsonParser = express.json({ limit: '2kb' });
  const composeJsonParser = express.json({ limit: '128kb' });
  const inboundJsonParser = express.json({ limit: config.maxMessageBytes });

  const jsonErrorHandler = (err, _req, res, next) => {
    if (err && (err.type === 'entity.parse.failed' || err.type === 'entity.too.large' || err instanceof SyntaxError)) {
      res.set('Cache-Control', 'no-store');
      const status = err.type === 'entity.too.large' ? 413 : 400;
      return res.status(status).json({
        error: err.type === 'entity.too.large' ? 'Request payload too large.' : 'Invalid JSON payload.',
      });
    }
    return next(err);
  };

  const createInboxLimiter = createLimiter({
    redis,
    prefix: 'rl:create:',
    windowMs: rateLimits.createWindowMs || 60 * 60 * 1000,
    max: rateLimits.createMax || 20,
    keyMax: rateLimits.createKeyMax || 120,
  });

  const readInboxLimiter = createLimiter({
    redis,
    prefix: 'rl:read:',
    windowMs: rateLimits.readWindowMs || 60 * 1000,
    max: rateLimits.readMax || 120,
    keyMax: rateLimits.readKeyMax || 600,
  });

  const otherApiLimiter = createLimiter({
    redis,
    prefix: 'rl:other:',
    windowMs: rateLimits.otherWindowMs || 60 * 1000,
    max: rateLimits.otherMax || 60,
    keyMax: rateLimits.otherKeyMax || 300,
  });

  const keyCreateLimiter = createLimiter({
    redis,
    prefix: 'rl:keys:',
    windowMs: rateLimits.keyWindowMs || 60 * 60 * 1000,
    max: rateLimits.keyMax || 10,
  });

  app.use(['/api', '/healthz'], (_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });

  app.get('/healthz', async (_req, res) => {
    const checks = await runReadinessChecks();
    if (checks.ok) {
      return res.status(200).type('text/plain').send('ok');
    }
    return res.status(503).type('text/plain').send('error');
  });

  async function optionalApiKeyAuth(req, res, next) {
    const rawKey = req.get('x-api-key');
    if (!rawKey) {
      return next();
    }
    try {
      const keyMeta = await store.verifyApiKey(rawKey.trim());
      if (!keyMeta) {
        return res.status(401).json({ error: 'Invalid or expired API key.' });
      }
      req.apiKey = keyMeta;
      req.rawApiKey = rawKey.trim();
      return next();
    } catch {
      return res.status(500).json({ error: 'API key verification failed.' });
    }
  }

  function requireApiKeyAuth(req, res, next) {
    if (!req.apiKey) {
      return res.status(401).json({ error: 'X-API-Key header is required.' });
    }
    return next();
  }

  function requireInboxAuth(req, res, next) {
    const rawAddress = normalizeAddress(req.params.address);
    const addrCheck = validateAddressSyntax(rawAddress);
    const token = extractBearerToken(req) || String(req.get('x-inbox-token') || '').trim();

    if (!addrCheck.valid || !token) {
      return res.status(404).json({ error: 'Inbox not found.' });
    }

    req.inboxAddress = addrCheck.address;
    req.inboxToken = token;
    return next();
  }

  const apiRouter = express.Router();
  apiRouter.use(optionalApiKeyAuth);

  // Inbound HTTP mail webhook (large payload parser)
  apiRouter.post('/inbound/email', inboundJsonParser, jsonErrorHandler, async (req, res) => {
    if (!config.inboundWebhookSecret) {
      return res.status(503).json({ error: 'Inbound webhook is not configured on this server.' });
    }

    const providedSecret = String(req.get('x-webhook-secret') || extractBearerToken(req) || '').trim();
    if (!verifySharedSecret(providedSecret, config.inboundWebhookSecret)) {
      return res.status(401).json({ error: 'Invalid webhook secret.' });
    }

    const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
    if (!body) {
      return res.status(400).json({ error: 'Invalid inbound payload.' });
    }

    try {
      let recipients = [];
      if (Array.isArray(body.to)) {
        recipients = body.to.map((r) => normalizeAddress(String(r || ''))).filter(Boolean);
      } else if (typeof body.to === 'string') {
        recipients = body.to.split(',').map((r) => normalizeAddress(r)).filter(Boolean);
      }

      let messagePayload = null;

      if (typeof body.raw === 'string' && body.raw.trim()) {
        const rawInput = body.rawEncoding === 'base64'
          ? Buffer.from(body.raw, 'base64')
          : body.raw;
        const parsed = await simpleParser(rawInput);

        if (recipients.length === 0 && parsed.to && Array.isArray(parsed.to.value)) {
          recipients = parsed.to.value.map((v) => normalizeAddress(v.address || '')).filter(Boolean);
        }

        const fromEntry = parsed.from && Array.isArray(parsed.from.value) && parsed.from.value[0];
        const from = normalizeAddress((fromEntry && fromEntry.address) || body.from || 'unknown@unknown');
        const fromName = (fromEntry && fromEntry.name ? String(fromEntry.name).trim() : '')
          || (body.fromName ? String(body.fromName).trim() : '');
        const subject = parsed.subject ? String(parsed.subject).trim() : '(No subject)';
        const date = parsed.date instanceof Date && !Number.isNaN(parsed.date.getTime())
          ? parsed.date.toISOString()
          : new Date().toISOString();
        const rawHtml = typeof parsed.html === 'string' ? parsed.html : '';
        const text = parsed.text
          ? String(parsed.text)
          : (rawHtml ? stripHtmlToText(rawHtml) : '');
        const html = rawHtml ? sanitizeEmailHtml(rawHtml) : '';
        const snippet = createSnippet(text, rawHtml);
        const attachments = Array.isArray(parsed.attachments)
          ? parsed.attachments.map((att) => ({
            filename: String(att.filename || 'attachment'),
            size: Number(att.size || (att.content ? att.content.length : 0)),
            contentType: String(att.contentType || 'application/octet-stream'),
          }))
          : [];

        messagePayload = { from, fromName, subject, date, text, html, snippet, attachments };
      } else {
        if (recipients.length === 0) {
          return res.status(400).json({ error: 'Recipient "to" address is required.' });
        }
        const from = normalizeAddress(String(body.from || 'unknown@unknown')) || 'unknown@unknown';
        const fromName = body.fromName ? String(body.fromName).trim() : '';
        const subject = body.subject ? String(body.subject).trim() : '(No subject)';
        let date = new Date().toISOString();
        if (body.date) {
          const parsedDate = new Date(body.date);
          if (!Number.isNaN(parsedDate.getTime())) {
            date = parsedDate.toISOString();
          }
        }
        const rawHtml = typeof body.html === 'string' ? body.html : '';
        const text = body.text
          ? String(body.text)
          : (rawHtml ? stripHtmlToText(rawHtml) : '');
        const html = rawHtml ? sanitizeEmailHtml(rawHtml) : '';
        const snippet = createSnippet(text, rawHtml);
        const attachments = Array.isArray(body.attachments)
          ? body.attachments.map((att) => ({
            filename: String((att && att.filename) || 'attachment'),
            size: Number((att && att.size) || 0),
            contentType: String((att && att.contentType) || 'application/octet-stream'),
          }))
          : [];

        messagePayload = { from, fromName, subject, date, text, html, snippet, attachments };
      }

      const delivered = [];
      for (const addr of Array.from(new Set(recipients)).slice(0, 10)) {
        const saved = await store.saveMessage(addr, messagePayload);
        if (saved) delivered.push(addr);
      }

      if (delivered.length === 0) {
        return res.status(404).json({ error: 'Mailbox not found.' });
      }

      return res.status(202).json({ delivered: true, recipients: delivered });
    } catch (err) {
      console.error('Inbound webhook error:', err.message);
      return res.status(400).json({ error: 'Could not process inbound message.' });
    }
  });

  // Outbound Send Email from an authorized inbox (128kb body limit)
  apiRouter.post(
    '/inbox/:address/send',
    otherApiLimiter,
    requireInboxAuth,
    composeJsonParser,
    jsonErrorHandler,
    async (req, res) => {
      try {
        const auth = await store.getAuthorizedInbox(req.inboxAddress, req.inboxToken);
        if (!auth) {
          return res.status(404).json({ error: 'Inbox not found.' });
        }

        const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
        const rawTo = typeof body.to === 'string' ? body.to : '';
        const toCheck = validateAddressSyntax(rawTo);
        if (!toCheck.valid) {
          return res.status(400).json({ error: toCheck.error || 'Valid recipient email address is required.' });
        }

        const subject = typeof body.subject === 'string'
          ? body.subject.replace(/[\r\n]+/g, ' ').trim().slice(0, 200)
          : '';
        const text = typeof body.text === 'string' ? body.text : '';
        const html = typeof body.html === 'string' ? body.html : '';

        if (!text.trim() && !html.trim()) {
          return res.status(400).json({ error: 'Message body is required.' });
        }

        const sendOpts = {
          config,
          smtpServer,
          store,
          relay: store.relay || null,
          from: auth.address,
          to: toCheck.address,
          subject: subject || '(No subject)',
          text,
          html,
        };
        if (typeof resolveMx === 'function') {
          sendOpts.resolveMx = resolveMx;
        }
        if (typeof createTransport === 'function') {
          sendOpts.createTransport = createTransport;
        }

        const result = await sendOutboundEmail(sendOpts);
        return res.status(202).json({
          sent: true,
          from: result.from,
          to: result.to,
          transport: result.transport,
        });
      } catch (err) {
        const status = err && err.statusCode ? err.statusCode : 502;
        return res.status(status).json({ error: (err && err.message) || 'Could not send email.' });
      }
    }
  );

  // Standard 2kb JSON body parser for all other API routes
  apiRouter.use(smallJsonParser);
  apiRouter.use(jsonErrorHandler);

  apiRouter.get('/health', async (_req, res) => {
    const checks = await runReadinessChecks();
    return res.status(checks.ok ? 200 : 503).json({
      status: checks.ok ? 'ok' : 'error',
      checks: {
        redis: checks.redis.ok ? 'ok' : 'error',
        smtp: checks.smtp.ok ? 'ok' : 'error',
      },
    });
  });

  apiRouter.get('/openapi.json', otherApiLimiter, (_req, res) => {
    res.json(buildOpenApiSpec(config));
  });

  apiRouter.get('/domains', otherApiLimiter, async (_req, res) => {
    try {
      const domains = typeof store.getDomains === 'function' ? await store.getDomains() : config.domains;
      res.json({ domains });
    } catch {
      res.json({ domains: config.domains });
    }
  });

  apiRouter.get('/domains/status', otherApiLimiter, async (_req, res) => {
    const [smtpCheck, domainStatuses] = await Promise.all([
      checkSmtpStatus(),
      Promise.all(config.domains.map((d) => inspectDomainMx(d))),
    ]);

    res.json({
      smtp: {
        ok: Boolean(smtpCheck.ok),
        port: smtpCheck.port || null,
      },
      inboundWebhookEnabled: Boolean(config.inboundWebhookSecret),
      domains: domainStatuses,
    });
  });

  apiRouter.get('/meta', otherApiLimiter, async (_req, res) => {
    let domains = config.domains;
    try {
      if (typeof store.getDomains === 'function') {
        domains = await store.getDomains();
      }
    } catch {
      // Fallback to config domains
    }
    res.json({
      domains,
      ownDomains: config.domains,
      ttlMinutes: config.inboxTtlMinutes,
      maxMessages: config.maxMessages,
      abuseEmail: config.abuseEmail,
      inboundWebhookEnabled: Boolean(config.inboundWebhookSecret),
      publicMailRelay: config.publicMailRelay,
    });
  });

  // Developer API Keys (Secrets API)
  apiRouter.post('/keys', keyCreateLimiter, async (req, res) => {
    try {
      const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
      const label = typeof body.label === 'string' ? body.label : 'default';
      const created = await store.createApiKey({ label });
      return res.status(201).json(created);
    } catch (err) {
      console.error('Create API key error:', err.message);
      return res.status(500).json({ error: 'Could not create API key.' });
    }
  });

  apiRouter.get('/keys/me', otherApiLimiter, requireApiKeyAuth, (req, res) => {
    res.json(req.apiKey);
  });

  apiRouter.delete('/keys/me', otherApiLimiter, requireApiKeyAuth, async (req, res) => {
    try {
      await store.revokeApiKey(req.rawApiKey);
      return res.status(204).end();
    } catch {
      return res.status(500).json({ error: 'Could not revoke API key.' });
    }
  });

  // Admin Secrets Status Endpoint
  apiRouter.get('/admin/status', otherApiLimiter, async (req, res) => {
    const provided = extractBearerToken(req);
    if (!config.adminSecret || !verifySharedSecret(provided, config.adminSecret)) {
      return res.status(404).json({ error: 'Not found.' });
    }

    const checks = await runReadinessChecks();
    const redisStatus = checks.redis.ok ? 'ok' : 'error';
    const smtpStatus = checks.smtp.ok ? 'ok' : 'error';

    return res.status(200).json({
      status: checks.ok ? 'ok' : 'degraded',
      uptimeSec: Math.floor(process.uptime()),
      redisStatus,
      smtpStatus,
      smtpPort: checks.smtp.port || null,
      domains: config.domains,
      ttlMinutes: config.inboxTtlMinutes,
      maxMessages: config.maxMessages,
      maxMessageBytes: config.maxMessageBytes,
      inboundWebhookEnabled: Boolean(config.inboundWebhookSecret),
      tlsEnabled: Boolean(config.tlsKeyPath && config.tlsCertPath),
    });
  });

  // Inbox Endpoints
  apiRouter.post('/inbox', createInboxLimiter, async (req, res) => {
    try {
      const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {};
      const username = typeof body.username === 'string' ? body.username : undefined;
      const domain = typeof body.domain === 'string' ? body.domain : undefined;

      const created = await store.createInbox({ username, domain });
      return res.status(201).json(created);
    } catch (err) {
      const status = err.statusCode || 500;
      return res.status(status).json({ error: err.message || 'Could not create inbox.' });
    }
  });

  apiRouter.get('/inbox/:address', readInboxLimiter, requireInboxAuth, async (req, res) => {
    try {
      const data = await store.listMessages(req.inboxAddress, req.inboxToken);
      if (!data) {
        return res.status(404).json({ error: 'Inbox not found.' });
      }

      const etag = computeInboxEtag(data);
      res.set('ETag', etag);

      const ifNoneMatch = req.get('if-none-match');
      if (ifNoneMatch && ifNoneMatch.split(',').map((s) => s.trim()).includes(etag)) {
        return res.status(304).end();
      }

      return res.status(200).json(data);
    } catch (err) {
      console.error('List inbox error:', err.message);
      return res.status(500).json({ error: 'Failed to load inbox.' });
    }
  });

  apiRouter.get('/inbox/:address/stream', readInboxLimiter, requireInboxAuth, async (req, res) => {
    try {
      const auth = await store.getAuthorizedInbox(req.inboxAddress, req.inboxToken);
      if (!auth) {
        return res.status(404).json({ error: 'Inbox not found.' });
      }

      res.setHeader('Content-Type', 'text/event-stream');
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Connection', 'keep-alive');
      res.setHeader('X-Accel-Buffering', 'no');
      res.flushHeaders();

      res.write(`event: connected\ndata: ${JSON.stringify({ address: auth.address, expiresAt: auth.inbox.expiresAt })}\n\n`);

      let closed = false;
      const unsubscribe = store.subscribeInbox(auth.address, (evt) => {
        if (!closed && !res.writableEnded) {
          res.write(`event: ${evt.type}\ndata: ${JSON.stringify(evt.payload)}\n\n`);
        }
      });

      const heartbeat = setInterval(() => {
        if (!closed && !res.writableEnded) {
          res.write(': keepalive\n\n');
        }
      }, 25000);
      heartbeat.unref();

      let upstreamTimer = null;
      if (auth.inbox && auth.inbox.upstream && typeof store.syncUpstreamMessages === 'function') {
        upstreamTimer = setInterval(() => {
          if (!closed && !res.writableEnded) {
            store.syncUpstreamMessages(auth.address).catch(() => {});
          }
        }, 4000);
        if (upstreamTimer.unref) upstreamTimer.unref();
      }

      const cleanup = () => {
        if (closed) return;
        closed = true;
        clearInterval(heartbeat);
        if (upstreamTimer) clearInterval(upstreamTimer);
        unsubscribe();
      };

      req.on('close', cleanup);
      res.on('close', cleanup);
      return undefined;
    } catch (err) {
      console.error('SSE stream error:', err.message);
      return res.status(500).json({ error: 'Failed to open inbox stream.' });
    }
  });

  apiRouter.post('/inbox/:address/rotate-token', otherApiLimiter, requireInboxAuth, async (req, res) => {
    try {
      const rotated = await store.rotateInboxToken(req.inboxAddress, req.inboxToken);
      if (!rotated) {
        return res.status(404).json({ error: 'Inbox not found.' });
      }
      return res.status(200).json(rotated);
    } catch (err) {
      console.error('Rotate token error:', err.message);
      return res.status(500).json({ error: 'Failed to rotate inbox token.' });
    }
  });

  apiRouter.get('/inbox/:address/messages/:id', readInboxLimiter, requireInboxAuth, async (req, res) => {
    try {
      const result = await store.getMessage(req.inboxAddress, req.params.id, req.inboxToken);
      if (result.notFound) {
        return res.status(404).json({ error: 'Message not found.' });
      }
      return res.status(200).json(result.message);
    } catch (err) {
      console.error('Read message error:', err.message);
      return res.status(500).json({ error: 'Failed to read message.' });
    }
  });

  apiRouter.delete('/inbox/:address/messages/:id', otherApiLimiter, requireInboxAuth, async (req, res) => {
    try {
      const result = await store.deleteMessage(req.inboxAddress, req.params.id, req.inboxToken);
      if (result.notFound) {
        return res.status(404).json({ error: 'Message not found.' });
      }
      return res.status(204).end();
    } catch (err) {
      console.error('Delete message error:', err.message);
      return res.status(500).json({ error: 'Failed to delete message.' });
    }
  });

  apiRouter.post('/inbox/:address/extend', otherApiLimiter, requireInboxAuth, async (req, res) => {
    try {
      const result = await store.extendInbox(req.inboxAddress, req.inboxToken);
      if (!result) {
        return res.status(404).json({ error: 'Inbox not found.' });
      }
      return res.status(200).json(result);
    } catch (err) {
      console.error('Extend inbox error:', err.message);
      return res.status(500).json({ error: 'Failed to extend inbox.' });
    }
  });

  apiRouter.post('/inbox/:address/test-email', otherApiLimiter, requireInboxAuth, async (req, res) => {
    try {
      const auth = await store.getAuthorizedInbox(req.inboxAddress, req.inboxToken);
      if (!auth) {
        return res.status(404).json({ error: 'Inbox not found.' });
      }
      if (auth.inbox && auth.inbox.upstream) {
        return res.status(400).json({
          error: 'Internal SMTP test delivery only applies to your own-server domains.',
        });
      }

      const senderDomain = config.domains[0] || 'localhost';
      await sendInternalSmtpMail({
        smtpServer,
        to: auth.address,
        from: `postmaster@${senderDomain}`,
        subject: `SMTP delivery test for ${auth.address}`,
        text: [
          `Hello,`,
          ``,
          `This message was delivered over SMTP directly to ${auth.address} via your internal server.`,
          `Your @${senderDomain} SMTP receiver, MIME parser, HTML sanitizer, and storage pipeline are working.`,
        ].join('\n'),
        html: [
          `<p>Hello,</p>`,
          `<p>This message was delivered over <strong>SMTP</strong> directly to <code>${auth.address}</code> via your internal server.</p>`,
          `<p>Your <strong>@${senderDomain}</strong> SMTP receiver, MIME parser, HTML sanitizer, and storage pipeline are working.</p>`,
        ].join(''),
      });

      return res.status(202).json({ sent: true, to: auth.address });
    } catch (err) {
      console.error('Internal SMTP test email error:', err.message);
      return res.status(503).json({
        error: 'Internal SMTP server is unavailable right now.',
      });
    }
  });

  apiRouter.delete('/inbox/:address', otherApiLimiter, requireInboxAuth, async (req, res) => {
    try {
      const deleted = await store.deleteInbox(req.inboxAddress, req.inboxToken);
      if (!deleted) {
        return res.status(404).json({ error: 'Inbox not found.' });
      }
      return res.status(204).end();
    } catch (err) {
      console.error('Delete inbox error:', err.message);
      return res.status(500).json({ error: 'Failed to delete inbox.' });
    }
  });

  apiRouter.use((_req, res) => {
    res.status(404).json({ error: 'Endpoint not found.' });
  });

  app.use('/api/v1', apiRouter);
  app.use('/api', apiRouter);

  const publicDir = path.join(__dirname, '..', 'public');
  app.use(express.static(publicDir, {
    extensions: ['html'],
    maxAge: '1h',
  }));

  app.use((_req, res) => {
    res.status(404).sendFile(path.join(publicDir, 'index.html'));
  });

  return app;
}

module.exports = {
  createApp,
  computeInboxEtag,
};
