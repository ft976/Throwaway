import http from 'node:http';
import { createRequire } from 'node:module';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

const require = createRequire(import.meta.url);
const { MemoryRedisClient } = require('../server/redis');
const { createStore } = require('../server/store');
const { createApp } = require('../server/api');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

describe('inbox and message TTL expiry', () => {
  let redis;
  let store;
  let server;
  let baseUrl;

  beforeEach(async () => {
    const config = {
      domains: ['ttlbox.local'],
      httpPort: 0,
      smtpPort: 0,
      redisUrl: 'redis://127.0.0.1:6379',
      redisMode: 'memory',
      inboxTtlMinutes: 2 / 60,
      inboxTtlMs: 2000,
      maxMessages: 50,
      maxMessageBytes: 2097152,
      tlsKeyPath: '',
      tlsCertPath: '',
      trustProxy: 1,
      abuseEmail: 'abuse@ttlbox.local',
      publicMailRelay: 'off',
      persistFile: '',
    };

    redis = new MemoryRedisClient();
    store = createStore(redis, config);
    const app = createApp({ config, redis, store });
    server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  afterEach(async () => {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    if (redis) {
      await redis.quit();
    }
  });

  it('expires the inbox and all its messages after the 2-second TTL', async () => {
    const createRes = await fetch(`${baseUrl}/api/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'ephemeral', domain: 'ttlbox.local' }),
    });
    expect(createRes.status).toBe(201);
    const inbox = await createRes.json();

    const saved = await store.saveMessage(inbox.address, {
      from: 'a@b.com',
      fromName: 'A',
      subject: 'Short lived',
      date: new Date().toISOString(),
      text: 'Gone soon',
      html: '<p>Gone soon</p>',
      snippet: 'Gone soon',
      attachments: [],
    });
    expect(saved).toBe(true);

    const listBefore = await fetch(`${baseUrl}/api/inbox/${inbox.address}`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
    });
    expect(listBefore.status).toBe(200);
    const beforeData = await listBefore.json();
    expect(beforeData.messages).toHaveLength(1);
    const msgId = beforeData.messages[0].id;

    await sleep(2200);

    const listAfter = await fetch(`${baseUrl}/api/inbox/${inbox.address}`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
    });
    expect(listAfter.status).toBe(404);

    const msgAfter = await fetch(`${baseUrl}/api/inbox/${inbox.address}/messages/${msgId}`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
    });
    expect(msgAfter.status).toBe(404);

    expect(await redis.get(`inbox:${inbox.address}`)).toBeNull();
    expect(await redis.get(`msg:${inbox.address}:${msgId}`)).toBeNull();
  });
});
