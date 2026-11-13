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
    const app = createApp({ config, redis, store });

    httpServer = http.createServer(app);
    await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    baseUrl = `http://127.0.0.1:${httpServer.address().port}`;

    smtpServer = createSmtpServer({ config, store });
    await new Promise((resolve) => smtpServer.listen(0, '127.0.0.1', resolve));
    smtpPort = smtpServer.server.address().port;
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
});
