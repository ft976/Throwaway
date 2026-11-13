import http from 'node:http';
import { createRequire } from 'node:module';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

const require = createRequire(import.meta.url);
const { MemoryRedisClient } = require('../server/redis');
const { createStore } = require('../server/store');
const { createApp } = require('../server/api');
const { createSmtpServer } = require('../server/smtp');

function createTestConfig(overrides = {}) {
  return {
    domains: ['testmail.local', 'second.local'],
    httpPort: 0,
    smtpPort: 0,
    redisUrl: 'redis://127.0.0.1:6379',
    redisMode: 'memory',
    inboxTtlMinutes: 60,
    inboxTtlMs: 60 * 60 * 1000,
    maxMessages: 50,
    maxMessageBytes: 2097152,
    tlsKeyPath: '',
    tlsCertPath: '',
    trustProxy: 1,
    abuseEmail: 'abuse@testmail.local',
    inboundWebhookSecret: 'whsec_test_secret_123',
    adminSecret: 'adm_test_secret_456',
    apiKeyTtlDays: 30,
    apiKeyTtlMs: 30 * 24 * 60 * 60 * 1000,
    corsOrigins: ['https://app.example.com'],
    publicMailRelay: 'off',
    persistFile: '',
    ...overrides,
  };
}

describe('Public API v1 and Secrets APIs', () => {
  let server;
  let smtpServer;
  let baseUrl;
  let redis;
  let store;
  let config;

  beforeEach(async () => {
    config = createTestConfig();
    redis = new MemoryRedisClient();
    store = createStore(redis, config);
    smtpServer = createSmtpServer({ config, store });
    await new Promise((resolve) => smtpServer.listen(0, '127.0.0.1', resolve));

    const app = createApp({ config, redis, store, smtpServer });
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    baseUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterEach(async () => {
    if (smtpServer && smtpServer.server && smtpServer.server.listening) {
      await new Promise((resolve) => smtpServer.close(resolve));
    }
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    if (redis) {
      await redis.quit();
    }
  });

  it('serves OpenAPI 3.0.3 spec, /api/v1/health, /api/v1/meta, and optional CORS', async () => {
    const specRes = await fetch(`${baseUrl}/api/v1/openapi.json`, {
      headers: { Origin: 'https://app.example.com' },
    });
    expect(specRes.status).toBe(200);
    expect(specRes.headers.get('access-control-allow-origin')).toBe('https://app.example.com');
    const spec = await specRes.json();
    expect(spec.openapi).toBe('3.0.3');
    expect(spec.paths['/inbound/email']).toBeTruthy();
    expect(spec.paths['/keys']).toBeTruthy();
    expect(spec.paths['/inbox/{address}/rotate-token']).toBeTruthy();

    const healthRes = await fetch(`${baseUrl}/api/v1/health`);
    expect(healthRes.status).toBe(200);
    expect(await healthRes.json()).toEqual({
      status: 'ok',
      checks: { redis: 'ok', smtp: 'ok' },
    });

    const metaRes = await fetch(`${baseUrl}/api/v1/meta`);
    expect(metaRes.status).toBe(200);
    const meta = await metaRes.json();
    expect(meta.inboundWebhookEnabled).toBe(true);
    expect(meta.domains).toEqual(['testmail.local', 'second.local']);
  });

  it('issues, inspects, authenticates, and revokes scoped developer API keys', async () => {
    const invalidRes = await fetch(`${baseUrl}/api/v1/domains`, {
      headers: { 'X-API-Key': 'tw_live_invalid_key' },
    });
    expect(invalidRes.status).toBe(401);

    const noKeyMe = await fetch(`${baseUrl}/api/v1/keys/me`);
    expect(noKeyMe.status).toBe(401);

    const createKeyRes = await fetch(`${baseUrl}/api/v1/keys`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: 'ci-runner' }),
    });
    expect(createKeyRes.status).toBe(201);
    const keyData = await createKeyRes.json();
    expect(keyData.apiKey.startsWith('tw_live_')).toBe(true);
    expect(keyData.label).toBe('ci-runner');

    const meRes = await fetch(`${baseUrl}/api/v1/keys/me`, {
      headers: { 'X-API-Key': keyData.apiKey },
    });
    expect(meRes.status).toBe(200);
    const me = await meRes.json();
    expect(me.keyId).toBe(keyData.keyId);
    expect(me.label).toBe('ci-runner');

    // Using valid API key works on inbox creation
    const inboxRes = await fetch(`${baseUrl}/api/v1/inbox`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': keyData.apiKey,
      },
      body: JSON.stringify({}),
    });
    expect(inboxRes.status).toBe(201);

    // Revoke key
    const revokeRes = await fetch(`${baseUrl}/api/v1/keys/me`, {
      method: 'DELETE',
      headers: { 'X-API-Key': keyData.apiKey },
    });
    expect(revokeRes.status).toBe(204);

    const afterRevoke = await fetch(`${baseUrl}/api/v1/keys/me`, {
      headers: { 'X-API-Key': keyData.apiKey },
    });
    expect(afterRevoke.status).toBe(401);
  });

  it('rotates inbox Bearer secret token and invalidates the previous token', async () => {
    const createRes = await fetch(`${baseUrl}/api/v1/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'rotatetest', domain: 'testmail.local' }),
    });
    expect(createRes.status).toBe(201);
    const created = await createRes.json();

    const rotateRes = await fetch(`${baseUrl}/api/v1/inbox/${created.address}/rotate-token`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(rotateRes.status).toBe(200);
    const rotated = await rotateRes.json();
    expect(rotated.address).toBe(created.address);
    expect(rotated.token).not.toBe(created.token);

    // Old token must now return 404
    const oldCheck = await fetch(`${baseUrl}/api/v1/inbox/${created.address}`, {
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(oldCheck.status).toBe(404);

    // New token works
    const newCheck = await fetch(`${baseUrl}/api/v1/inbox/${created.address}`, {
      headers: { Authorization: `Bearer ${rotated.token}` },
    });
    expect(newCheck.status).toBe(200);
  });

  it('enforces INBOUND_WEBHOOK_SECRET and delivers JSON + raw RFC822 MIME mail', async () => {
    const createRes = await fetch(`${baseUrl}/api/v1/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'hookbox', domain: 'testmail.local' }),
    });
    const inbox = await createRes.json();

    // Missing secret -> 401
    const unauthRes = await fetch(`${baseUrl}/api/v1/inbound/email`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to: inbox.address, from: 'a@b.com', text: 'hi' }),
    });
    expect(unauthRes.status).toBe(401);

    // Wrong secret -> 401
    const wrongRes = await fetch(`${baseUrl}/api/v1/inbound/email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': 'wrong-secret',
      },
      body: JSON.stringify({ to: inbox.address, from: 'a@b.com', text: 'hi' }),
    });
    expect(wrongRes.status).toBe(401);

    // Unknown recipient -> 404
    const unknownRes = await fetch(`${baseUrl}/api/v1/inbound/email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': config.inboundWebhookSecret,
      },
      body: JSON.stringify({ to: 'nobody@testmail.local', from: 'a@b.com', text: 'hi' }),
    });
    expect(unknownRes.status).toBe(404);

    // Valid JSON delivery with XSS + remote image blocking
    const jsonDeliver = await fetch(`${baseUrl}/api/v1/inbound/email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': config.inboundWebhookSecret,
      },
      body: JSON.stringify({
        to: inbox.address,
        from: 'notify@github.com',
        fromName: 'GitHub',
        subject: 'Verification code: 491022',
        text: 'Your code is 491022',
        html: '<p>Your code is <b>491022</b></p><script>alert(1)</script><img src="https://example.com/pixel.png">',
      }),
    });
    expect(jsonDeliver.status).toBe(202);

    // Valid raw RFC822 MIME delivery (e.g. Cloudflare Email Worker)
    const rawMime = [
      'From: Alice <alice@example.org>',
      `To: ${inbox.address}`,
      'Subject: Raw MIME Test',
      'MIME-Version: 1.0',
      'Content-Type: multipart/mixed; boundary="BOUND"',
      '',
      '--BOUND',
      'Content-Type: text/plain; charset="utf-8"',
      '',
      'Hello from Cloudflare Email Routing!',
      '--BOUND',
      'Content-Type: text/plain; name="note.txt"',
      'Content-Disposition: attachment; filename="note.txt"',
      '',
      'attachment-secret-content',
      '--BOUND--',
    ].join('\r\n');

    const mimeDeliver = await fetch(`${baseUrl}/api/v1/inbound/email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': config.inboundWebhookSecret,
      },
      body: JSON.stringify({ to: inbox.address, raw: rawMime }),
    });
    expect(mimeDeliver.status).toBe(202);

    const listRes = await fetch(`${baseUrl}/api/v1/inbox/${inbox.address}`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
    });
    expect(listRes.status).toBe(200);
    const listData = await listRes.json();
    expect(listData.messages).toHaveLength(2);

    // Read newest (Raw MIME) message and verify attachment metadata only
    const mimeMsgRes = await fetch(`${baseUrl}/api/v1/inbox/${inbox.address}/messages/${listData.messages[0].id}`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
    });
    const mimeMsg = await mimeMsgRes.json();
    expect(mimeMsg.subject).toBe('Raw MIME Test');
    expect(mimeMsg.from).toBe('alice@example.org');
    expect(mimeMsg.text).toContain('Hello from Cloudflare Email Routing!');
    expect(mimeMsg.attachments).toHaveLength(1);
    expect(mimeMsg.attachments[0].filename).toBe('note.txt');
    expect(mimeMsg.attachments[0].content).toBeUndefined();

    // Read JSON message and verify HTML sanitization
    const jsonMsgRes = await fetch(`${baseUrl}/api/v1/inbox/${inbox.address}/messages/${listData.messages[1].id}`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
    });
    const jsonMsg = await jsonMsgRes.json();
    expect(jsonMsg.html).not.toContain('<script');
    expect(jsonMsg.html).toContain('data-src="https://example.com/pixel.png"');
    expect(jsonMsg.html).not.toContain(' src="https://example.com/pixel.png"');
  });

  it('returns 503 for inbound webhook when INBOUND_WEBHOOK_SECRET is unset', async () => {
    const noSecretServerApp = createApp({
      config: createTestConfig({ inboundWebhookSecret: '', adminSecret: '' }),
      redis,
      store,
    });
    const tempServer = http.createServer(noSecretServerApp);
    await new Promise((resolve) => tempServer.listen(0, '127.0.0.1', resolve));
    const tempUrl = `http://127.0.0.1:${tempServer.address().port}`;

    try {
      const res = await fetch(`${tempUrl}/api/v1/inbound/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: 'a@testmail.local', text: 'hi' }),
      });
      expect(res.status).toBe(503);

      const adminRes = await fetch(`${tempUrl}/api/v1/admin/status`);
      expect(adminRes.status).toBe(404);
    } finally {
      await new Promise((resolve) => tempServer.close(resolve));
    }
  });

  it('protects /api/v1/admin/status with ADMIN_SECRET and returns 404 when invalid', async () => {
    const noAuth = await fetch(`${baseUrl}/api/v1/admin/status`);
    expect(noAuth.status).toBe(404);

    const badAuth = await fetch(`${baseUrl}/api/v1/admin/status`, {
      headers: { Authorization: 'Bearer wrong-admin-secret' },
    });
    expect(badAuth.status).toBe(404);

    const okAuth = await fetch(`${baseUrl}/api/v1/admin/status`, {
      headers: { Authorization: `Bearer ${config.adminSecret}` },
    });
    expect(okAuth.status).toBe(200);
    const status = await okAuth.json();
    expect(status.status).toBe('ok');
    expect(status.redisStatus).toBe('ok');
    expect(status.smtpStatus).toBe('ok');
    expect(status.inboundWebhookEnabled).toBe(true);
  });

  it('streams real-time incoming messages over SSE /api/v1/inbox/:address/stream', async () => {
    const createRes = await fetch(`${baseUrl}/api/v1/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'ssebox', domain: 'testmail.local' }),
    });
    const inbox = await createRes.json();

    const controller = new AbortController();
    const streamRes = await fetch(`${baseUrl}/api/v1/inbox/${inbox.address}/stream`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
      signal: controller.signal,
    });
    expect(streamRes.status).toBe(200);
    expect(streamRes.headers.get('content-type')).toContain('text/event-stream');

    const reader = streamRes.body.getReader();
    const decoder = new TextDecoder();
    let collected = '';

    // Wait for initial 'connected' event
    while (!collected.includes('event: connected')) {
      const { value, done } = await reader.read();
      if (done) break;
      collected += decoder.decode(value, { stream: true });
    }
    expect(collected).toContain(inbox.address);

    // Deliver a message via inbound webhook and confirm SSE receives it immediately
    const deliverRes = await fetch(`${baseUrl}/api/v1/inbound/email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Webhook-Secret': config.inboundWebhookSecret,
      },
      body: JSON.stringify({
        to: inbox.address,
        from: 'sse@example.com',
        subject: 'Live SSE Push',
        text: 'Real-time notification payload',
      }),
    });
    expect(deliverRes.status).toBe(202);

    while (!collected.includes('Live SSE Push')) {
      const { value, done } = await reader.read();
      if (done) break;
      collected += decoder.decode(value, { stream: true });
    }
    expect(collected).toContain('event: message');
    expect(collected).toContain('Live SSE Push');

    controller.abort();
    await reader.cancel().catch(() => {});
  });
});
