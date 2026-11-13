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
    publicMailRelay: 'off',
    persistFile: '',
    ...overrides,
  };
}

describe('REST API endpoints and security controls', () => {
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

  it('serves /healthz (verifying Redis + SMTP), /api/health, and /api/domains', async () => {
    const health = await fetch(`${baseUrl}/healthz`);
    expect(health.status).toBe(200);
    expect(await health.text()).toBe('ok');
    expect(health.headers.get('cache-control')).toBe('no-store');

    const apiHealth = await fetch(`${baseUrl}/api/health`);
    expect(apiHealth.status).toBe(200);
    expect(await apiHealth.json()).toEqual({
      status: 'ok',
      checks: { redis: 'ok', smtp: 'ok' },
    });

    const domainsRes = await fetch(`${baseUrl}/api/domains`);
    expect(domainsRes.status).toBe(200);
    expect(await domainsRes.json()).toEqual({ domains: ['testmail.local', 'second.local'] });
  });

  it('reports 503 on /healthz and /api/health when internal SMTP server or Redis is unreachable', async () => {
    await new Promise((resolve) => smtpServer.close(resolve));

    const healthDownSmtp = await fetch(`${baseUrl}/healthz`);
    expect(healthDownSmtp.status).toBe(503);
    expect(await healthDownSmtp.text()).toBe('error');

    const apiHealthDownSmtp = await fetch(`${baseUrl}/api/health`);
    expect(apiHealthDownSmtp.status).toBe(503);
    expect(await apiHealthDownSmtp.json()).toEqual({
      status: 'error',
      checks: { redis: 'ok', smtp: 'error' },
    });

    // Re-open SMTP on ephemeral port and simulate Redis failure
    smtpServer = createSmtpServer({ config, store });
    await new Promise((resolve) => smtpServer.listen(0, '127.0.0.1', resolve));
    const originalPing = redis.ping.bind(redis);
    redis.ping = async () => {
      throw new Error('Redis disconnected');
    };

    const appWithBadRedis = createApp({ config, redis, store, smtpServer });
    const badRedisServer = http.createServer(appWithBadRedis);
    await new Promise((resolve) => badRedisServer.listen(0, '127.0.0.1', resolve));

    try {
      const badRedisUrl = `http://127.0.0.1:${badRedisServer.address().port}`;
      const healthDownRedis = await fetch(`${badRedisUrl}/healthz`);
      expect(healthDownRedis.status).toBe(503);

      const apiHealthDownRedis = await fetch(`${badRedisUrl}/api/health`);
      expect(apiHealthDownRedis.status).toBe(503);
      expect(await apiHealthDownRedis.json()).toEqual({
        status: 'error',
        checks: { redis: 'error', smtp: 'ok' },
      });
    } finally {
      redis.ping = originalPing;
      await new Promise((resolve) => badRedisServer.close(resolve));
    }
  });

  it('creates, lists with ETag/304, reads, extends, deletes messages, and deletes inbox', async () => {
    const createRes = await fetch(`${baseUrl}/api/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'Custom.User', domain: 'SECOND.LOCAL' }),
    });
    expect(createRes.status).toBe(201);
    const created = await createRes.json();
    expect(created.address).toBe('custom.user@second.local');
    expect(typeof created.token).toBe('string');
    expect(created.token.length).toBeGreaterThan(20);

    const dupRes = await fetch(`${baseUrl}/api/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'custom.user', domain: 'second.local' }),
    });
    expect(dupRes.status).toBe(409);

    const noTokenRes = await fetch(`${baseUrl}/api/inbox/${created.address}`);
    expect(noTokenRes.status).toBe(404);

    const badTokenRes = await fetch(`${baseUrl}/api/inbox/${created.address}`, {
      headers: { Authorization: 'Bearer wrong-token-value' },
    });
    expect(badTokenRes.status).toBe(404);

    await store.saveMessage(created.address, {
      from: 'sender@example.com',
      fromName: 'Sender',
      subject: 'Hello World',
      date: new Date().toISOString(),
      text: 'Test body',
      html: '<p>Test body</p>',
      snippet: 'Test body',
      attachments: [{ filename: 'doc.pdf', size: 1024, contentType: 'application/pdf' }],
    });

    const listRes = await fetch(`${baseUrl}/api/inbox/${created.address}`, {
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(listRes.status).toBe(200);
    const etag = listRes.headers.get('etag');
    expect(etag).toBeTruthy();

    const listBody = await listRes.json();
    expect(listBody.messages).toHaveLength(1);
    expect(listBody.messages[0].read).toBe(false);
    expect(listBody.messages[0].hasAttachments).toBe(true);

    const notModifiedRes = await fetch(`${baseUrl}/api/inbox/${created.address}`, {
      headers: {
        Authorization: `Bearer ${created.token}`,
        'If-None-Match': etag,
      },
    });
    expect(notModifiedRes.status).toBe(304);

    const msgId = listBody.messages[0].id;
    const readRes = await fetch(`${baseUrl}/api/inbox/${created.address}/messages/${msgId}`, {
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(readRes.status).toBe(200);
    const fullMsg = await readRes.json();
    expect(fullMsg.html).toBe('<p>Test body</p>');
    expect(fullMsg.read).toBe(true);

    const listAfterRead = await fetch(`${baseUrl}/api/inbox/${created.address}`, {
      headers: { Authorization: `Bearer ${created.token}` },
    });
    const listAfterReadBody = await listAfterRead.json();
    expect(listAfterReadBody.messages[0].read).toBe(true);

    const extendRes = await fetch(`${baseUrl}/api/inbox/${created.address}/extend`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(extendRes.status).toBe(200);
    const extended = await extendRes.json();
    expect(extended.expiresAt).toBeGreaterThanOrEqual(created.expiresAt);

    const delMsgRes = await fetch(`${baseUrl}/api/inbox/${created.address}/messages/${msgId}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(delMsgRes.status).toBe(204);

    const listAfterDel = await fetch(`${baseUrl}/api/inbox/${created.address}`, {
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect((await listAfterDel.json()).messages).toHaveLength(0);

    const delInboxRes = await fetch(`${baseUrl}/api/inbox/${created.address}`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(delInboxRes.status).toBe(204);

    const afterDeleteRes = await fetch(`${baseUrl}/api/inbox/${created.address}`, {
      headers: { Authorization: `Bearer ${created.token}` },
    });
    expect(afterDeleteRes.status).toBe(404);
  });

  it('enforces POST /api/inbox rate limit and returns 429 with Retry-After', async () => {
    for (let i = 0; i < 20; i += 1) {
      const res = await fetch(`${baseUrl}/api/inbox`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      expect(res.status).toBe(201);
    }

    const limitedRes = await fetch(`${baseUrl}/api/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(limitedRes.status).toBe(429);
    expect(Number(limitedRes.headers.get('retry-after'))).toBeGreaterThan(0);
    const body = await limitedRes.json();
    expect(body.error).toBeTruthy();
  });
});
