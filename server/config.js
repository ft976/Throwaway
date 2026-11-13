'use strict';

const dotenv = require('dotenv');

dotenv.config({ quiet: true });

const DOMAIN_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function parsePositiveNumber(rawValue, fallback, name) {
  if (rawValue === undefined || rawValue === null || String(rawValue).trim() === '') {
    return fallback;
  }
  const num = Number(rawValue);
  if (!Number.isFinite(num) || num <= 0) {
    throw new Error(`Configuration error: ${name} must be a positive number.`);
  }
  return num;
}

function parsePort(rawValue, fallback, name, allowZero = false) {
  if (rawValue === undefined || rawValue === null || String(rawValue).trim() === '') {
    return fallback;
  }
  const num = Number(rawValue);
  const min = allowZero ? 0 : 1;
  if (!Number.isInteger(num) || num < min || num > 65535) {
    throw new Error(`Configuration error: ${name} must be an integer between ${min} and 65535.`);
  }
  return num;
}

function parseTrustProxy(rawValue) {
  if (rawValue === undefined || rawValue === null || String(rawValue).trim() === '') {
    return 1;
  }
  const trimmed = String(rawValue).trim().toLowerCase();
  if (trimmed === 'true') return true;
  if (trimmed === 'false') return false;
  const asNum = Number(trimmed);
  if (Number.isInteger(asNum) && asNum >= 0) {
    return asNum;
  }
  return trimmed;
}

function loadConfig(env = process.env) {
  const rawDomains = env.DOMAINS;
  if (!rawDomains || !String(rawDomains).trim()) {
    throw new Error(
      'Configuration error: DOMAINS environment variable is required (comma-separated list, e.g. mail1.com,mail2.com).'
    );
  }

  const domains = Array.from(
    new Set(
      String(rawDomains)
        .split(',')
        .map((d) => d.trim().toLowerCase())
        .filter(Boolean)
    )
  );

  if (domains.length === 0) {
    throw new Error('Configuration error: DOMAINS must contain at least one valid domain.');
  }

  for (const domain of domains) {
    if (!DOMAIN_REGEX.test(domain)) {
      throw new Error(`Configuration error: invalid domain "${domain}" in DOMAINS.`);
    }
  }

  const httpPort = parsePort(env.HTTP_PORT, 3000, 'HTTP_PORT');
  const smtpPort = parsePort(env.SMTP_PORT, 25, 'SMTP_PORT', true);
  const redisUrl = env.REDIS_URL && String(env.REDIS_URL).trim()
    ? String(env.REDIS_URL).trim()
    : 'redis://127.0.0.1:6379';
  const redisMode = env.REDIS_MODE && String(env.REDIS_MODE).trim().toLowerCase() === 'memory'
    ? 'memory'
    : 'redis';

  const inboxTtlMinutes = parsePositiveNumber(env.INBOX_TTL_MINUTES, 60, 'INBOX_TTL_MINUTES');
  const inboxTtlMs = Math.round(inboxTtlMinutes * 60 * 1000);
  const maxMessages = Math.floor(parsePositiveNumber(env.MAX_MESSAGES, 50, 'MAX_MESSAGES'));
  const maxMessageBytes = Math.floor(
    parsePositiveNumber(env.MAX_MESSAGE_BYTES, 2097152, 'MAX_MESSAGE_BYTES')
  );

  const tlsKeyPath = env.TLS_KEY_PATH ? String(env.TLS_KEY_PATH).trim() : '';
  const tlsCertPath = env.TLS_CERT_PATH ? String(env.TLS_CERT_PATH).trim() : '';
  if ((tlsKeyPath && !tlsCertPath) || (!tlsKeyPath && tlsCertPath)) {
    throw new Error('Configuration error: TLS_KEY_PATH and TLS_CERT_PATH must both be set to enable STARTTLS.');
  }

  const trustProxy = parseTrustProxy(env.TRUST_PROXY);
  const abuseEmail = env.ABUSE_EMAIL && String(env.ABUSE_EMAIL).trim()
    ? String(env.ABUSE_EMAIL).trim()
    : `abuse@${domains[0]}`;

  const inboundWebhookSecret = env.INBOUND_WEBHOOK_SECRET
    ? String(env.INBOUND_WEBHOOK_SECRET).trim()
    : '';
  const adminSecret = env.ADMIN_SECRET ? String(env.ADMIN_SECRET).trim() : '';
  const apiKeyTtlDays = parsePositiveNumber(env.API_KEY_TTL_DAYS, 30, 'API_KEY_TTL_DAYS');
  const apiKeyTtlMs = Math.round(apiKeyTtlDays * 24 * 60 * 60 * 1000);
  const corsOrigins = env.PUBLIC_API_CORS_ORIGINS
    ? String(env.PUBLIC_API_CORS_ORIGINS)
      .split(',')
      .map((o) => o.trim())
      .filter(Boolean)
    : [];

  const rawRelay = env.PUBLIC_MAIL_RELAY ? String(env.PUBLIC_MAIL_RELAY).trim().toLowerCase() : 'auto';
  const publicMailRelay = ['auto', 'on', 'off'].includes(rawRelay) ? rawRelay : 'auto';

  const rawPersist = env.PERSIST_FILE !== undefined ? String(env.PERSIST_FILE).trim() : '';
  let persistFile = '';
  if (rawPersist.toLowerCase() !== 'none' && rawPersist !== 'false') {
    if (rawPersist) {
      persistFile = rawPersist;
    } else if (redisMode === 'memory') {
      persistFile = '.data/throwaway-store.json';
    }
  }

  const outboundSmtpHost = env.OUTBOUND_SMTP_HOST ? String(env.OUTBOUND_SMTP_HOST).trim() : '';
  const outboundSmtpPort = parsePort(env.OUTBOUND_SMTP_PORT, 587, 'OUTBOUND_SMTP_PORT');
  const outboundSmtpSecure = String(env.OUTBOUND_SMTP_SECURE || '').trim().toLowerCase() === 'true';
  const outboundSmtpUser = env.OUTBOUND_SMTP_USER ? String(env.OUTBOUND_SMTP_USER).trim() : '';
  const outboundSmtpPass = env.OUTBOUND_SMTP_PASS ? String(env.OUTBOUND_SMTP_PASS) : '';
  const outboundSmtpFrom = env.OUTBOUND_SMTP_FROM ? String(env.OUTBOUND_SMTP_FROM).trim() : '';

  return {
    domains,
    httpPort,
    smtpPort,
    redisUrl,
    redisMode,
    inboxTtlMinutes,
    inboxTtlMs,
    maxMessages,
    maxMessageBytes,
    tlsKeyPath,
    tlsCertPath,
    trustProxy,
    abuseEmail,
    inboundWebhookSecret,
    adminSecret,
    apiKeyTtlDays,
    apiKeyTtlMs,
    corsOrigins,
    publicMailRelay,
    persistFile,
    outboundSmtpHost,
    outboundSmtpPort,
    outboundSmtpSecure,
    outboundSmtpUser,
    outboundSmtpPass,
    outboundSmtpFrom,
  };
}

module.exports = {
  loadConfig,
};
