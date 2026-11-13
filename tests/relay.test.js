import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createRequire } from 'node:module';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

const require = createRequire(import.meta.url);
const { MemoryRedisClient } = require('../server/redis');
const { createStore } = require('../server/store');
const { createApp } = require('../server/api');
const { createPublicMailRelay, parseFromHeader } = require('../server/relay');

function createTestConfig(overrides = {}) {
  return {
    domains: ['throwaway.local', 'tempdrop.local'],
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
    abuseEmail: 'abuse@throwaway.local',
    inboundWebhookSecret: '',
    adminSecret: '',
    apiKeyTtlDays: 30,
    apiKeyTtlMs: 30 * 24 * 60 * 60 * 1000,
    corsOrigins: [],
    publicMailRelay: 'auto',
    persistFile: '',
    ...overrides,
  };
}

function makeMockFetch(handlers) {
  return async (url, options = {}) => {
    const method = (options.method || 'GET').toUpperCase();
    for (const h of handlers) {
      if (h.match(url, method, options)) {
        const res = h.handle(url, method, options);
        return {
          status: res.status ?? 200,
          ok: (res.status ?? 200) >= 200 && (res.status ?? 200) < 300,
          text: async () => (typeof res.body === 'string' ? res.body : JSON.stringify(res.body)),
        };
      }
    }
    return { status: 404, ok: false, text: async () => '{}' };
  };
}

describe('Public Mail Relay and Disk Snapshot Persistence', () => {
  let tmpDir;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'throwaway-relay-'));
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('parses RFC 5322 From headers accurately', () => {
    expect(parseFromHeader('GitHub <noreply@github.com>')).toEqual({
      from: 'noreply@github.com',
      fromName: 'GitHub',
    });
    expect(parseFromHeader('"Alice Smith" <Alice@Example.COM>')).toEqual({
      from: 'alice@example.com',
      fromName: 'Alice Smith',
    });
    expect(parseFromHeader('plain@example.com')).toEqual({
      from: 'plain@example.com',
      fromName: '',
    });
  });

  it('provisions real public domains via mail.tm, syncs sanitized mail, and deduplicates across refreshes', async () => {
    let messagePollCount = 0;
    const mockFetch = makeMockFetch([
      {
        match: (url, method) => url === 'https://api.mail.tm/domains' && method === 'GET',
        handle: () => ({
          status: 200,
          body: { 'hydra:member': [{ domain: 'realmail.test', isActive: true, isPrivate: false }] },
        }),
      },
      {
        match: (url, method) => url === 'https://api.mail.tm/accounts' && method === 'POST',
        handle: (_u, _m, opts) => {
          const body = JSON.parse(opts.body);
          return { status: 201, body: { id: 'acc_1', address: body.address } };
        },
      },
      {
        match: (url, method) => url === 'https://api.mail.tm/token' && method === 'POST',
        handle: () => ({ status: 200, body: { id: 'acc_1', token: 'jwt_secret_123' } }),
      },
      {
        match: (url, method) => url === 'https://api.mail.tm/messages' && method === 'GET',
        handle: () => {
          messagePollCount += 1;
          return {
            status: 200,
            body: {
              'hydra:member': [
                { id: 'msg_ext_1', subject: 'Welcome from Gmail' },
              ],
            },
          };
        },
      },
      {
        match: (url, method) => url === 'https://api.mail.tm/messages/msg_ext_1' && method === 'GET',
        handle: () => ({
          status: 200,
          body: {
            id: 'msg_ext_1',
            from: { address: 'sender@gmail.com', name: 'Real Sender' },
            subject: 'Welcome from Gmail',
            createdAt: '2026-11-13T12:00:00.000Z',
            text: 'Your verification code is 884411',
            html: ['<p>Code: <b>884411</b></p><script>alert(1)</script><img src="https://img.example/t.png">'],
            attachments: [{ filename: 'receipt.pdf', size: 2048, contentType: 'application/pdf' }],
          },
        }),
      },
    ]);

    const config = createTestConfig();
    const redis = new MemoryRedisClient();
    const relay = createPublicMailRelay({ fetchImpl: mockFetch });
    const store = createStore(redis, config, { relay });
    const app = createApp({ config, redis, store });
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;

    try {
      // Exposes real public domain instead of .local dev domains
      const domRes = await fetch(`${baseUrl}/api/v1/domains`);
      expect(domRes.status).toBe(200);
      expect(await domRes.json()).toEqual({ domains: ['realmail.test'] });

      // Creating an inbox gets an @realmail.test address
      const createRes = await fetch(`${baseUrl}/api/v1/inbox`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      expect(createRes.status).toBe(201);
      const created = await createRes.json();
      expect(created.address.endsWith('@realmail.test')).toBe(true);
      expect(created.provider).toBe('mail.tm');

      // Listing messages syncs upstream mail, sanitizes XSS, blocks remote img src
      const listRes = await fetch(`${baseUrl}/api/v1/inbox/${encodeURIComponent(created.address)}`, {
        headers: { Authorization: `Bearer ${created.token}` },
      });
      expect(listRes.status).toBe(200);
      const listData = await listRes.json();
      expect(listData.messages).toHaveLength(1);
      expect(listData.messages[0].subject).toBe('Welcome from Gmail');
      expect(listData.messages[0].from).toBe('sender@gmail.com');

      const msgId = listData.messages[0].id;
      const readRes = await fetch(
        `${baseUrl}/api/v1/inbox/${encodeURIComponent(created.address)}/messages/${msgId}`,
        { headers: { Authorization: `Bearer ${created.token}` } }
      );
      expect(readRes.status).toBe(200);
      const full = await readRes.json();
      expect(full.html).not.toContain('<script');
      expect(full.html).toContain('data-src="https://img.example/t.png"');
      expect(full.attachments).toEqual([
        { filename: 'receipt.pdf', size: 2048, contentType: 'application/pdf' },
      ]);

      // Forced second sync must NOT duplicate msg_ext_1
      await store.syncUpstreamMessages(created.address, { force: true });
      const listRes2 = await fetch(`${baseUrl}/api/v1/inbox/${encodeURIComponent(created.address)}`, {
        headers: { Authorization: `Bearer ${created.token}` },
      });
      const listData2 = await listRes2.json();
      expect(listData2.messages).toHaveLength(1);
      expect(messagePollCount).toBe(2);
    } finally {
      await new Promise((resolve) => server.close(resolve));
      await redis.quit();
    }
  });

  it('falls back to tempmail.lol when mail.tm is unavailable and syncs mail', async () => {
    const mockFetch = makeMockFetch([
      {
        match: (url) => url.startsWith('https://api.mail.tm/'),
        handle: () => ({ status: 503, body: { error: 'unavailable' } }),
      },
      {
        match: (url, method) => url === 'https://api.tempmail.lol/v2/inbox/create' && method === 'POST',
        handle: () => ({
          status: 201,
          body: { address: 'fallback42@rooms.test', token: 'tmlol_tok_abc' },
        }),
      },
      {
        match: (url, method) => url.startsWith('https://api.tempmail.lol/v2/inbox?token=tmlol_tok_abc') && method === 'GET',
        handle: () => ({
          status: 200,
          body: {
            emails: [
              {
                from: 'Support <help@example.org>',
                to: 'fallback42@rooms.test',
                subject: 'Fallback Delivery Works',
                body: 'Delivered via tempmail.lol',
                html: '<p>Delivered via <strong>tempmail.lol</strong></p>',
                date: '2026-11-13T12:05:00.000Z',
              },
            ],
            expired: false,
          },
        }),
      },
    ]);

    const config = createTestConfig();
    const redis = new MemoryRedisClient();
    const relay = createPublicMailRelay({ fetchImpl: mockFetch });
    const store = createStore(redis, config, { relay });

    const created = await store.createInbox({});
    expect(created.address).toBe('fallback42@rooms.test');
    expect(created.provider).toBe('tempmail.lol');

    const listed = await store.listMessages(created.address, created.token);
    expect(listed.messages).toHaveLength(1);
    expect(listed.messages[0].subject).toBe('Fallback Delivery Works');
    expect(listed.messages[0].from).toBe('help@example.org');

    await redis.quit();
  });

  it('persists active inboxes and messages across MemoryRedisClient server restarts', async () => {
    const snapshotPath = path.join(tmpDir, 'store.json');
    const config = createTestConfig({ publicMailRelay: 'off', persistFile: snapshotPath });

    const redis1 = new MemoryRedisClient({ persistFile: snapshotPath });
    const store1 = createStore(redis1, config);
    const created = await store1.createInbox({ username: 'persistbox', domain: 'throwaway.local' });
    await store1.saveMessage(created.address, {
      from: 'friend@gmail.com',
      fromName: 'Friend',
      subject: 'Survives Restart',
      date: new Date().toISOString(),
      text: 'Still here after refresh & restart!',
      html: '<p>Still here after refresh &amp; restart!</p>',
      snippet: 'Still here after refresh & restart!',
      attachments: [],
    });
    await redis1.quit();

    expect(fs.existsSync(snapshotPath)).toBe(true);

    // Boot a brand-new MemoryRedisClient + store pointing to the same snapshot file
    const redis2 = new MemoryRedisClient({ persistFile: snapshotPath });
    const store2 = createStore(redis2, config);
    const listed = await store2.listMessages(created.address, created.token);
    expect(listed).not.toBeNull();
    expect(listed.address).toBe(created.address);
    expect(listed.messages).toHaveLength(1);
    expect(listed.messages[0].subject).toBe('Survives Restart');

    await redis2.quit();
  });

  it('uses own backend for ft97.com while exposing and routing all working public domains via public APIs', async () => {
    const mockFetch = makeMockFetch([
      {
        match: (url, method) => url === 'https://api.mail.tm/domains' && method === 'GET',
        handle: () => ({ status: 200, body: { 'hydra:member': [{ domain: 'external.test', isActive: true, isPrivate: false }] } }),
      },
      {
        match: (url, method) => url === 'https://api.tempmail.lol/v2/inbox/create' && method === 'POST',
        handle: () => ({ status: 201, body: { address: 'probe1@rooms.test', token: 'tm_tok_1' } }),
      },
      {
        match: (url) => url.startsWith('https://api.guerrillamail.com/ajax.php?f=get_email_address'),
        handle: () => ({
          status: 200,
          body: { email_addr: 'probe@guerrillamailblock.com', sid_token: 'gsid_probe' },
        }),
      },
      {
        match: (url) => url.startsWith('https://api.guerrillamail.com/ajax.php?f=set_email_user'),
        handle: (url) => {
          const u = new URL(url);
          const user = u.searchParams.get('email_user') || 'randuser';
          return {
            status: 200,
            body: { email_addr: `${user}@guerrillamailblock.com`, sid_token: 'gsid_active' },
          };
        },
      },
      {
        match: (url) => url.startsWith('https://api.guerrillamail.com/ajax.php?f=check_email') && url.includes('sid_token=gsid_active'),
        handle: () => ({
          status: 200,
          body: {
            list: [
              { mail_id: '1', mail_from: 'no-reply@guerrillamail.com', mail_subject: 'Promo', mail_timestamp: 0 },
              { mail_id: '901', mail_from: 'Alice <alice@gmail.com>', mail_subject: 'OTP Code', mail_timestamp: 1794570000 },
            ],
          },
        }),
      },
      {
        match: (url) => url.startsWith('https://api.guerrillamail.com/ajax.php?f=fetch_email') && url.includes('email_id=901'),
        handle: () => ({
          status: 200,
          body: {
            mail_id: '901',
            mail_from: 'Alice <alice@gmail.com>',
            mail_subject: 'OTP Code',
            mail_timestamp: 1794570000,
            mail_body: '<p>Your code is <b>991122</b></p><script>evil()</script>',
          },
        }),
      },
      {
        match: (url, method) => url === 'https://api.mail.tm/accounts' && method === 'POST',
        handle: (_u, _m, opts) => {
          const body = JSON.parse(opts.body);
          return { status: 201, body: { id: 'acc_ext', address: body.address } };
        },
      },
      {
        match: (url, method) => url === 'https://api.mail.tm/token' && method === 'POST',
        handle: () => ({ status: 200, body: { id: 'acc_ext', token: 'jwt_ext_1' } }),
      },
    ]);

    const config = createTestConfig({ domains: ['ft97.com'], publicMailRelay: 'auto' });
    const redis = new MemoryRedisClient();
    const relay = createPublicMailRelay({ fetchImpl: mockFetch });
    const store = createStore(redis, config, { relay });

    const domains = await store.getDomains();
    expect(domains[0]).toBe('ft97.com');
    expect(domains).toContain('external.test');
    expect(domains).toContain('rooms.test');
    expect(domains).toContain('sharklasers.com');
    expect(domains).toContain('guerrillamail.com');

    // Default inbox uses own server (@ft97.com, local)
    const ownDefault = await store.createInbox({});
    expect(ownDefault.address.endsWith('@ft97.com')).toBe(true);
    expect(ownDefault.provider).toBe('local');

    // Explicit ft97.com uses own server (local)
    const ownExplicit = await store.createInbox({ username: 'mybox', domain: 'ft97.com' });
    expect(ownExplicit.address).toBe('mybox@ft97.com');
    expect(ownExplicit.provider).toBe('local');

    // Picking a Guerrilla domain routes through Guerrilla public API and filters promo welcome email
    const guerrillaInbox = await store.createInbox({ username: 'mybox', domain: 'sharklasers.com' });
    expect(guerrillaInbox.address).toBe('mybox@sharklasers.com');
    expect(guerrillaInbox.provider).toBe('guerrilla');

    const listed = await store.listMessages(guerrillaInbox.address, guerrillaInbox.token);
    expect(listed.messages).toHaveLength(1);
    expect(listed.messages[0].subject).toBe('OTP Code');
    expect(listed.messages[0].from).toBe('alice@gmail.com');

    const fullMsg = await store.getMessage(guerrillaInbox.address, listed.messages[0].id, guerrillaInbox.token);
    expect(fullMsg.notFound).toBe(false);
    expect(fullMsg.message.html).toContain('991122');
    expect(fullMsg.message.html).not.toContain('<script');

    // Picking a mail.tm domain routes through mail.tm
    const mailTmInbox = await store.createInbox({ domain: 'external.test' });
    expect(mailTmInbox.address.endsWith('@external.test')).toBe(true);
    expect(mailTmInbox.provider).toBe('mail.tm');

    await redis.quit();
  });
});
