import http from 'node:http';
import { createRequire } from 'node:module';
import { describe, it, expect, beforeEach, afterEach } from 'vitest';

const require = createRequire(import.meta.url);
const nodemailer = require('nodemailer');
const { MemoryRedisClient } = require('../server/redis');
const { createStore } = require('../server/store');
const { createApp } = require('../server/api');
const { createSmtpServer } = require('../server/smtp');

describe('SMTP server integration', () => {
  let redis;
  let store;
  let httpServer;
  let smtpServer;
  let baseUrl;
  let smtpPort;

  beforeEach(async () => {
    const config = {
      domains: ['smtpbox.local'],
      httpPort: 0,
      smtpPort: 0,
      redisUrl: 'redis://127.0.0.1:6379',
      redisMode: 'memory',
      inboxTtlMinutes: 60,
      inboxTtlMs: 60 * 60 * 1000,
      maxMessages: 50,
      maxMessageBytes: 10240,
      tlsKeyPath: '',
      tlsCertPath: '',
      trustProxy: 1,
      abuseEmail: 'abuse@smtpbox.local',
      publicMailRelay: 'off',
      persistFile: '',
    };

    redis = new MemoryRedisClient();
    store = createStore(redis, config);
    smtpServer = createSmtpServer({ config, store });
    await new Promise((resolve) => smtpServer.listen(0, '127.0.0.1', resolve));
    smtpPort = smtpServer.server.address().port;

    const app = createApp({ config, redis, store, smtpServer });

    httpServer = http.createServer(app);
    await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${httpServer.address().port}`;
  });

  afterEach(async () => {
    if (smtpServer) {
      await new Promise((resolve) => smtpServer.close(resolve));
    }
    if (httpServer) {
      await new Promise((resolve) => httpServer.close(resolve));
    }
    if (redis) {
      await redis.quit();
    }
  });

  it('delivers mail to a created inbox and exposes sanitized content + attachment metadata via API', async () => {
    const createRes = await fetch(`${baseUrl}/api/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'recipient1', domain: 'smtpbox.local' }),
    });
    const inbox = await createRes.json();

    const transporter = nodemailer.createTransport({
      host: '127.0.0.1',
      port: smtpPort,
      secure: false,
      tls: { rejectUnauthorized: false },
    });

    await transporter.sendMail({
      from: '"Alice Sender" <alice@example.org>',
      to: inbox.address.toUpperCase(),
      subject: 'Your verification code',
      text: 'Code is 482910',
      html: '<p>Code is <strong>482910</strong></p><script>alert(1)</script><img src="https://cdn.example/px.png">',
      attachments: [
        {
          filename: 'receipt.txt',
          content: 'receipt-bytes',
          contentType: 'text/plain',
        },
      ],
    });

    const listRes = await fetch(`${baseUrl}/api/inbox/${inbox.address}`, {
      headers: { Authorization: `Bearer ${inbox.token}` },
    });
    expect(listRes.status).toBe(200);
    const listData = await listRes.json();
    expect(listData.messages).toHaveLength(1);
    expect(listData.messages[0].subject).toBe('Your verification code');
    expect(listData.messages[0].from).toBe('alice@example.org');
    expect(listData.messages[0].fromName).toBe('Alice Sender');
    expect(listData.messages[0].hasAttachments).toBe(true);

    const msgRes = await fetch(
      `${baseUrl}/api/inbox/${inbox.address}/messages/${listData.messages[0].id}`,
      { headers: { Authorization: `Bearer ${inbox.token}` } }
    );
    const msg = await msgRes.json();
    expect(msg.html).not.toContain('<script');
    expect(msg.html).toContain('data-src="https://cdn.example/px.png"');
    expect(msg.html).not.toMatch(/\ssrc=/i);
    expect(msg.attachments).toEqual([
      {
        filename: 'receipt.txt',
        size: 13,
        contentType: 'text/plain',
      },
    ]);
  });

  it('rejects mail to an unknown address with 550', async () => {
    const transporter = nodemailer.createTransport({
      host: '127.0.0.1',
      port: smtpPort,
      secure: false,
      tls: { rejectUnauthorized: false },
    });

    await expect(
      transporter.sendMail({
        from: 'sender@example.org',
        to: 'doesnotexist@smtpbox.local',
        subject: 'Spam',
        text: 'Hello',
      })
    ).rejects.toThrow(/550/);
  });

  it('rejects an oversized message with 552', async () => {
    const createRes = await fetch(`${baseUrl}/api/inbox`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'bigbox', domain: 'smtpbox.local' }),
    });
    const inbox = await createRes.json();

    const transporter = nodemailer.createTransport({
      host: '127.0.0.1',
      port: smtpPort,
      secure: false,
      tls: { rejectUnauthorized: false },
    });

    await expect(
      transporter.sendMail({
        from: 'sender@example.org',
        to: inbox.address,
        subject: 'Too big',
        text: 'A'.repeat(20000),
      })
    ).rejects.toThrow(/552/);
  });

  it('delivers internal SMTP test email and reports domain MX readiness for ft97.com', async () => {
    const ftConfig = {
      domains: ['ft97.com'],
      httpPort: 0,
      smtpPort: 0,
      redisUrl: 'redis://127.0.0.1:6379',
      redisMode: 'memory',
      inboxTtlMinutes: 60,
      inboxTtlMs: 60 * 60 * 1000,
      maxMessages: 50,
      maxMessageBytes: 10240,
      tlsKeyPath: '',
      tlsCertPath: '',
      trustProxy: 1,
      abuseEmail: 'abuse@ft97.com',
      publicMailRelay: 'off',
      persistFile: '',
    };

    const ftRedis = new MemoryRedisClient();
    const ftStore = createStore(ftRedis, ftConfig);
    const ftSmtp = createSmtpServer({ config: ftConfig, store: ftStore });
    await new Promise((resolve) => ftSmtp.listen(0, '127.0.0.1', resolve));

    const ftApp = createApp({
      config: ftConfig,
      redis: ftRedis,
      store: ftStore,
      smtpServer: ftSmtp,
      resolveMx: async () => [{ exchange: '', priority: 0 }],
    });
    const ftHttp = http.createServer(ftApp);
    await new Promise((resolve) => ftHttp.listen(0, '127.0.0.1', resolve));
    const ftUrl = `http://127.0.0.1:${ftHttp.address().port}`;

    try {
      const statusRes = await fetch(`${ftUrl}/api/v1/domains/status`);
      expect(statusRes.status).toBe(200);
      const statusData = await statusRes.json();
      expect(statusData.smtp.ok).toBe(true);
      expect(statusData.domains[0]).toEqual({
        domain: 'ft97.com',
        mxStatus: 'null-mx',
        mxRecords: [],
        readyForExternalMail: false,
      });

      const createRes = await fetch(`${ftUrl}/api/v1/inbox`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'rehan97', domain: 'ft97.com' }),
      });
      expect(createRes.status).toBe(201);
      const inbox = await createRes.json();

      const testMailRes = await fetch(`${ftUrl}/api/v1/inbox/${inbox.address}/test-email`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${inbox.token}` },
      });
      expect(testMailRes.status).toBe(202);

      const listRes = await fetch(`${ftUrl}/api/v1/inbox/${inbox.address}`, {
        headers: { Authorization: `Bearer ${inbox.token}` },
      });
      expect(listRes.status).toBe(200);
      const listData = await listRes.json();
      expect(listData.messages).toHaveLength(1);
      expect(listData.messages[0].from).toBe('postmaster@ft97.com');
      expect(listData.messages[0].subject).toContain('rehan97@ft97.com');
    } finally {
      await new Promise((resolve) => ftSmtp.close(resolve));
      await new Promise((resolve) => ftHttp.close(resolve));
      await ftRedis.quit();
    }
  });

  it('sends email between local @ft97.com inboxes over internal SMTP and validates errors', async () => {
    const ftConfig = {
      domains: ['ft97.com'],
      httpPort: 0,
      smtpPort: 0,
      redisUrl: 'redis://127.0.0.1:6379',
      redisMode: 'memory',
      inboxTtlMinutes: 60,
      inboxTtlMs: 60 * 60 * 1000,
      maxMessages: 50,
      maxMessageBytes: 10240,
      tlsKeyPath: '',
      tlsCertPath: '',
      trustProxy: 1,
      abuseEmail: 'abuse@ft97.com',
      publicMailRelay: 'off',
      persistFile: '',
    };

    const ftRedis = new MemoryRedisClient();
    const ftStore = createStore(ftRedis, ftConfig);
    const ftSmtp = createSmtpServer({ config: ftConfig, store: ftStore });
    await new Promise((resolve) => ftSmtp.listen(0, '127.0.0.1', resolve));

    const ftApp = createApp({
      config: ftConfig,
      redis: ftRedis,
      store: ftStore,
      smtpServer: ftSmtp,
    });
    const ftHttp = http.createServer(ftApp);
    await new Promise((resolve) => ftHttp.listen(0, '127.0.0.1', resolve));
    const ftUrl = `http://127.0.0.1:${ftHttp.address().port}`;

    try {
      const senderRes = await fetch(`${ftUrl}/api/v1/inbox`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'sender97', domain: 'ft97.com' }),
      });
      const senderInbox = await senderRes.json();

      const rcptRes = await fetch(`${ftUrl}/api/v1/inbox`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'rcpt97', domain: 'ft97.com' }),
      });
      const rcptInbox = await rcptRes.json();

      // Missing auth returns 404
      const unauthRes = await fetch(`${ftUrl}/api/v1/inbox/${senderInbox.address}/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to: rcptInbox.address, subject: 'Hi', text: 'Body' }),
      });
      expect(unauthRes.status).toBe(404);

      // Invalid body returns 400
      const emptyBodyRes = await fetch(`${ftUrl}/api/v1/inbox/${senderInbox.address}/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${senderInbox.token}`,
        },
        body: JSON.stringify({ to: rcptInbox.address, subject: 'Hi', text: '   ' }),
      });
      expect(emptyBodyRes.status).toBe(400);

      // Missing local target inbox returns 404
      const missingTargetRes = await fetch(`${ftUrl}/api/v1/inbox/${senderInbox.address}/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${senderInbox.token}`,
        },
        body: JSON.stringify({ to: 'nobody97@ft97.com', subject: 'Hi', text: 'Hello' }),
      });
      expect(missingTargetRes.status).toBe(404);

      // Valid local send delivers directly to recipient inbox
      const sendRes = await fetch(`${ftUrl}/api/v1/inbox/${senderInbox.address}/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${senderInbox.token}`,
        },
        body: JSON.stringify({
          to: rcptInbox.address,
          subject: 'Direct Local Delivery',
          text: 'Hey rcpt97, send and receive both work!',
        }),
      });
      expect(sendRes.status).toBe(202);
      expect(await sendRes.json()).toEqual({
        sent: true,
        from: 'sender97@ft97.com',
        to: 'rcpt97@ft97.com',
        transport: 'internal-smtp',
      });

      const listRes = await fetch(`${ftUrl}/api/v1/inbox/${rcptInbox.address}`, {
        headers: { Authorization: `Bearer ${rcptInbox.token}` },
      });
      expect(listRes.status).toBe(200);
      const listData = await listRes.json();
      expect(listData.messages).toHaveLength(1);
      expect(listData.messages[0].from).toBe('sender97@ft97.com');
      expect(listData.messages[0].subject).toBe('Direct Local Delivery');
      expect(listData.messages[0].snippet).toContain('send and receive both work');
    } finally {
      await new Promise((resolve) => ftSmtp.close(resolve));
      await new Promise((resolve) => ftHttp.close(resolve));
      await ftRedis.quit();
    }
  });

  it('routes external recipients through configured OUTBOUND_SMTP_HOST relay when set', async () => {
    const capturedMails = [];
    const relayConfig = {
      domains: ['ft97.com'],
      httpPort: 0,
      smtpPort: 0,
      redisUrl: 'redis://127.0.0.1:6379',
      redisMode: 'memory',
      inboxTtlMinutes: 60,
      inboxTtlMs: 60 * 60 * 1000,
      maxMessages: 50,
      maxMessageBytes: 10240,
      tlsKeyPath: '',
      tlsCertPath: '',
      trustProxy: 1,
      abuseEmail: 'abuse@ft97.com',
      publicMailRelay: 'off',
      persistFile: '',
      outboundSmtpHost: 'smtp.relay.test',
      outboundSmtpPort: 587,
      outboundSmtpSecure: false,
      outboundSmtpUser: 'relay-user',
      outboundSmtpPass: 'relay-pass',
      outboundSmtpFrom: 'mailer@ft97.com',
    };

    const relayRedis = new MemoryRedisClient();
    const relayStore = createStore(relayRedis, relayConfig);
    const relayApp = createApp({
      config: relayConfig,
      redis: relayRedis,
      store: relayStore,
      createTransport: (opts) => ({
        sendMail: async (mail) => {
          capturedMails.push({ opts, mail });
          return { accepted: [mail.to] };
        },
      }),
    });
    const relayHttp = http.createServer(relayApp);
    await new Promise((resolve) => relayHttp.listen(0, '127.0.0.1', resolve));
    const relayUrl = `http://127.0.0.1:${relayHttp.address().port}`;

    try {
      const createRes = await fetch(`${relayUrl}/api/v1/inbox`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'outbox1', domain: 'ft97.com' }),
      });
      const inbox = await createRes.json();

      const sendRes = await fetch(`${relayUrl}/api/v1/inbox/${inbox.address}/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${inbox.token}`,
        },
        body: JSON.stringify({
          to: 'friend@gmail.com',
          subject: 'External Relay Test',
          text: 'Sent via configured SMTP relay!',
        }),
      });
      expect(sendRes.status).toBe(202);
      expect(await sendRes.json()).toEqual({
        sent: true,
        from: 'outbox1@ft97.com',
        to: 'friend@gmail.com',
        transport: 'smtp-relay',
      });
      expect(capturedMails).toHaveLength(1);
      expect(capturedMails[0].opts.host).toBe('smtp.relay.test');
      expect(capturedMails[0].mail.from).toBe('mailer@ft97.com');
      expect(capturedMails[0].mail.replyTo).toBe('outbox1@ft97.com');
      expect(capturedMails[0].mail.to).toBe('friend@gmail.com');
    } finally {
      await new Promise((resolve) => relayHttp.close(resolve));
      await relayRedis.quit();
    }
  });
});
