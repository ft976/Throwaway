'use strict';

const crypto = require('node:crypto');
const dns = require('node:dns');
const fs = require('node:fs');
const net = require('node:net');
const nodemailer = require('nodemailer');
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const sanitizeHtml = require('sanitize-html');
const { normalizeAddress } = require('./validate');
const { sanitizeEmailHtml, createSnippet } = require('./sanitize');
const { TEMPMAIL_PLUS_DOMAINS } = require('./relay');

const MAX_RECIPIENTS = 10;

function stripHtmlToText(html) {
  return sanitizeHtml(String(html || ''), {
    allowedTags: [],
    allowedAttributes: {},
  })
    .replace(/\r\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function escapeHtmlBasic(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function buildSmtpError(message, responseCode) {
  const err = new Error(message);
  err.responseCode = responseCode;
  return err;
}

function resolveSmtpConnectTarget(smtpServer) {
  const rawServer = smtpServer && smtpServer.server;
  if (!rawServer || !rawServer.listening) {
    return null;
  }
  const addr = rawServer.address();
  if (!addr || typeof addr !== 'object' || !addr.port) {
    return null;
  }
  let host = addr.address;
  if (!host || host === '0.0.0.0' || host === '::' || host === '::0') {
    host = '127.0.0.1';
  }
  return { host, port: addr.port };
}

function verifySmtpConnectivity(smtpServer, timeoutMs = 2000) {
  const target = resolveSmtpConnectTarget(smtpServer);
  if (!target) {
    return Promise.resolve({ ok: false, error: 'SMTP server is not listening.' });
  }

  return new Promise((resolve) => {
    let settled = false;
    let buffer = '';
    const socket = net.createConnection({ host: target.host, port: target.port });

    const finish = (result) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';
      for (const line of lines) {
        if (!line) continue;
        // Final response line has space at index 3 (e.g. "220 domain ESMTP")
        if (line.length >= 3 && (line.length === 3 || line[3] === ' ')) {
          if (line.startsWith('220')) {
            try {
              socket.write('QUIT\r\n');
            } catch {
              // Ignore write-on-close errors
            }
            finish({ ok: true, port: target.port });
          } else {
            finish({ ok: false, error: `Unexpected SMTP greeting: ${line}` });
          }
          return;
        }
      }
    });

    socket.on('timeout', () => {
      finish({ ok: false, error: 'SMTP health check timed out.' });
    });

    socket.on('error', (err) => {
      finish({ ok: false, error: err && err.message ? err.message : 'SMTP connection failed.' });
    });

    socket.on('end', () => {
      finish({ ok: false, error: 'SMTP server closed connection before greeting.' });
    });
  });
}

function dotStuffBody(content) {
  return String(content || '')
    .replace(/\r?\n/g, '\r\n')
    .split('\r\n')
    .map((line) => (line.startsWith('.') ? `.${line}` : line))
    .join('\r\n');
}

function sendInternalSmtpMail({
  smtpServer,
  to,
  from,
  subject,
  text,
  html,
  timeoutMs = 5000,
}) {
  const target = resolveSmtpConnectTarget(smtpServer);
  if (!target) {
    return Promise.reject(new Error('Internal SMTP server is not listening.'));
  }

  const recipient = normalizeAddress(to);
  const sender = normalizeAddress(from) || 'postmaster@localhost';
  if (!recipient) {
    return Promise.reject(new Error('Valid recipient address is required.'));
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    let buffer = '';
    let step = 'greeting';
    const socket = net.createConnection({ host: target.host, port: target.port });

    const done = (err, value) => {
      if (settled) return;
      settled = true;
      socket.removeAllListeners();
      socket.destroy();
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
    };

    const boundary = `tw_${crypto.randomBytes(12).toString('hex')}`;
    const safeSubject = String(subject || 'SMTP Delivery Test').replace(/[\r\n]+/g, ' ').trim();
    const plainText = String(text || '');
    const htmlBody = String(html || '');

    const fromHeader = sender.startsWith('postmaster@')
      ? `Throwaway Postmaster <${sender}>`
      : `<${sender}>`;

    const headers = [
      `From: ${fromHeader}`,
      `To: <${recipient}>`,
      `Subject: ${safeSubject}`,
      `Date: ${new Date().toUTCString()}`,
      `Message-ID: <${crypto.randomUUID()}@${sender.split('@')[1] || 'localhost'}>`,
      'MIME-Version: 1.0',
      `Content-Type: multipart/alternative; boundary="${boundary}"`,
    ];

    const mimeParts = [
      ...headers,
      '',
      `--${boundary}`,
      'Content-Type: text/plain; charset="utf-8"',
      '',
      plainText,
      `--${boundary}`,
      'Content-Type: text/html; charset="utf-8"',
      '',
      htmlBody || `<pre>${escapeHtmlBasic(plainText)}</pre>`,
      `--${boundary}--`,
      '',
    ].join('\r\n');

    socket.setTimeout(timeoutMs);

    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (!line) continue;
        if (line.length >= 4 && line[3] === '-') {
          continue;
        }
        const code = Number(line.slice(0, 3));
        if (step === 'greeting') {
          if (code !== 220) {
            return done(new Error(`SMTP greeting rejected (${line})`));
          }
          step = 'ehlo';
          socket.write('EHLO localhost\r\n');
        } else if (step === 'ehlo') {
          if (code !== 250) {
            return done(new Error(`SMTP EHLO failed (${line})`));
          }
          step = 'mailFrom';
          socket.write(`MAIL FROM:<${sender}>\r\n`);
        } else if (step === 'mailFrom') {
          if (code !== 250) {
            return done(new Error(`SMTP MAIL FROM failed (${line})`));
          }
          step = 'rcptTo';
          socket.write(`RCPT TO:<${recipient}>\r\n`);
        } else if (step === 'rcptTo') {
          if (code !== 250) {
            return done(new Error(`SMTP RCPT TO rejected (${line})`));
          }
          step = 'dataCmd';
          socket.write('DATA\r\n');
        } else if (step === 'dataCmd') {
          if (code !== 354) {
            return done(new Error(`SMTP DATA rejected (${line})`));
          }
          step = 'dataBody';
          socket.write(`${dotStuffBody(mimeParts)}\r\n.\r\n`);
        } else if (step === 'dataBody') {
          if (code !== 250) {
            return done(new Error(`SMTP delivery failed (${line})`));
          }
          step = 'quit';
          try {
            socket.write('QUIT\r\n');
          } catch {
            // Ignore write-on-close errors
          }
          return done(null, { accepted: [recipient] });
        }
      }
      return undefined;
    });

    socket.on('timeout', () => {
      done(new Error('Internal SMTP test delivery timed out.'));
    });

    socket.on('error', (err) => {
      done(err instanceof Error ? err : new Error('Internal SMTP socket error.'));
    });

    socket.on('end', () => {
      if (step !== 'quit') {
        done(new Error('Internal SMTP connection closed unexpectedly.'));
      }
    });
  });
}

function createSmtpServer({ config, store }) {
  const hasTls = Boolean(config.tlsKeyPath && config.tlsCertPath);

  const serverOptions = {
    name: config.domains[0],
    banner: `${config.domains[0]} ESMTP`,
    size: config.maxMessageBytes,
    maxClients: 100,
    socketTimeout: 30000,
    closeTimeout: 5000,
    disabledCommands: hasTls ? ['AUTH'] : ['AUTH', 'STARTTLS'],
    authOptional: true,
    secure: false,
    allowInsecureAuth: false,
    onConnect(_session, callback) {
      callback();
    },
    onMailFrom(_address, _session, callback) {
      callback();
    },
    async onRcptTo(address, session, callback) {
      try {
        const currentRecipients = (session.envelope && session.envelope.rcptTo) || [];
        if (currentRecipients.length >= MAX_RECIPIENTS) {
          return callback(buildSmtpError('452 4.5.3 Too many recipients', 452));
        }

        const recipient = normalizeAddress(address && address.address);
        if (!recipient) {
          return callback(buildSmtpError('550 5.1.1 Mailbox not found', 550));
        }

        const exists = await store.inboxExists(recipient);
        if (!exists) {
          return callback(buildSmtpError('550 5.1.1 Mailbox not found', 550));
        }

        return callback();
      } catch (err) {
        console.error('SMTP RCPT check error:', err.message);
        return callback(buildSmtpError('451 4.3.0 Temporary lookup failure', 451));
      }
    },
    onData(stream, session, callback) {
      let finished = false;
      const done = (err) => {
        if (finished) return;
        finished = true;
        callback(err);
      };

      stream.on('error', (err) => {
        console.error('SMTP stream error:', err.message);
        done(buildSmtpError('451 4.3.0 Message stream error', 451));
      });

      simpleParser(stream, async (parseErr, parsed) => {
        if (stream.sizeExceeded) {
          return done(buildSmtpError('552 5.3.4 Message size exceeds maximum allowed limit', 552));
        }

        if (parseErr) {
          console.error('SMTP parse error:', parseErr.message);
          return done(buildSmtpError('550 5.6.0 Could not parse message', 550));
        }

        try {
          const fromEntry = parsed.from && Array.isArray(parsed.from.value) && parsed.from.value[0];
          const envelopeFrom = session.envelope && session.envelope.mailFrom && session.envelope.mailFrom.address;
          const from = normalizeAddress(
            (fromEntry && fromEntry.address) || envelopeFrom || 'unknown@unknown'
          ) || 'unknown@unknown';
          const fromName = fromEntry && fromEntry.name ? String(fromEntry.name).trim() : '';
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

          const recipients = (session.envelope && Array.isArray(session.envelope.rcptTo))
            ? session.envelope.rcptTo
            : [];

          const seen = new Set();
          let storedCount = 0;

          for (const rcpt of recipients) {
            const addr = normalizeAddress(rcpt && rcpt.address);
            if (!addr || seen.has(addr)) continue;
            seen.add(addr);

            const saved = await store.saveMessage(addr, {
              from,
              fromName,
              subject,
              date,
              text,
              html,
              snippet,
              attachments,
            });
            if (saved) {
              storedCount += 1;
            }
          }

          console.log(`SMTP message processed: delivered=${storedCount}, recipients=${seen.size}`);

          if (storedCount > 0) {
            return done();
          }
          return done(buildSmtpError('550 5.1.1 Mailbox not found', 550));
        } catch (err) {
          console.error('SMTP delivery error:', err.message);
          return done(buildSmtpError('451 4.3.0 Temporary storage failure', 451));
        }
      });
    },
  };

  if (hasTls) {
    serverOptions.key = fs.readFileSync(config.tlsKeyPath);
    serverOptions.cert = fs.readFileSync(config.tlsCertPath);
  }

  const server = new SMTPServer(serverOptions);

  server.on('error', (err) => {
    console.error('SMTP server error:', err.message);
  });

  return server;
}

async function sendOutboundEmail({
  config,
  smtpServer,
  store,
  relay = null,
  from,
  to,
  subject,
  text,
  html,
  resolveMx = (domain) => dns.promises.resolveMx(domain),
  createTransport = (opts) => nodemailer.createTransport(opts),
}) {
  const sender = normalizeAddress(from);
  const recipient = normalizeAddress(to);
  if (!sender || !recipient) {
    const err = new Error('Valid sender and recipient email addresses are required.');
    err.statusCode = 400;
    throw err;
  }

  const fromDomain = sender.split('@')[1] || '';
  const toDomain = recipient.split('@')[1] || '';
  const safeSubject = String(subject || '(No subject)').replace(/[\r\n]+/g, ' ').trim() || '(No subject)';
  const plainText = String(text || '');
  const htmlBody = String(html || '');

  // 1. Recipient belongs to our own local/configured server domain
  if (Array.isArray(config.domains) && config.domains.includes(toDomain)) {
    const exists = await store.inboxExists(recipient);
    if (!exists) {
      const err = new Error(`Recipient mailbox "${recipient}" not found on this server.`);
      err.statusCode = 404;
      throw err;
    }

    await sendInternalSmtpMail({
      smtpServer,
      to: recipient,
      from: sender,
      subject: safeSubject,
      text: plainText,
      html: htmlBody,
    });

    return {
      delivered: true,
      transport: 'internal-smtp',
      from: sender,
      to: recipient,
    };
  }

  // 2. Public tempmail.plus -> tempmail.plus free send API
  const activeRelay = relay || (store && store.relay);
  if (
    TEMPMAIL_PLUS_DOMAINS.includes(fromDomain)
    && TEMPMAIL_PLUS_DOMAINS.includes(toDomain)
    && activeRelay
    && typeof activeRelay.sendTempmailPlusMail === 'function'
  ) {
    const result = await activeRelay.sendTempmailPlusMail({
      from: sender,
      to: recipient,
      subject: safeSubject,
      text: plainText || stripHtmlToText(htmlBody),
    });
    return {
      delivered: true,
      transport: result.transport || 'tempmail.plus',
      from: sender,
      to: recipient,
    };
  }

  // 3. Configured external SMTP relay (if set in .env)
  if (config.outboundSmtpHost) {
    const transportOpts = {
      host: config.outboundSmtpHost,
      port: config.outboundSmtpPort || 587,
      secure: Boolean(config.outboundSmtpSecure),
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 10000,
      tls: { rejectUnauthorized: false },
    };
    if (config.outboundSmtpUser) {
      transportOpts.auth = {
        user: config.outboundSmtpUser,
        pass: config.outboundSmtpPass || '',
      };
    }
    const mailFrom = config.outboundSmtpFrom || sender;
    const transporter = createTransport(transportOpts);
    await transporter.sendMail({
      from: mailFrom,
      replyTo: sender,
      to: recipient,
      subject: safeSubject,
      text: plainText || stripHtmlToText(htmlBody),
      html: htmlBody || undefined,
    });
    return {
      delivered: true,
      transport: 'smtp-relay',
      from: sender,
      to: recipient,
    };
  }

  // 4. Direct MX port-25 SMTP delivery
  let mxRecords;
  try {
    mxRecords = await resolveMx(toDomain);
  } catch (err) {
    const outErr = new Error(`No receiving mail server (MX record) found for "${toDomain}".`);
    outErr.statusCode = 400;
    outErr.cause = err;
    throw outErr;
  }

  const validMx = (Array.isArray(mxRecords) ? mxRecords : [])
    .filter((r) => r && typeof r.exchange === 'string' && r.exchange.trim() && r.exchange.trim() !== '.')
    .sort((a, b) => (a.priority || 0) - (b.priority || 0));

  if (validMx.length === 0) {
    const outErr = new Error(`"${toDomain}" does not accept external email (missing or Null MX record).`);
    outErr.statusCode = 400;
    throw outErr;
  }

  let lastErr = null;
  for (const mx of validMx.slice(0, 2)) {
    const mxHost = mx.exchange.trim();
    const transporter = createTransport({
      host: mxHost,
      port: 25,
      secure: false,
      connectionTimeout: 4000,
      greetingTimeout: 4000,
      socketTimeout: 6000,
      tls: { rejectUnauthorized: false },
    });
    try {
      await transporter.sendMail({
        from: sender,
        to: recipient,
        subject: safeSubject,
        text: plainText || stripHtmlToText(htmlBody),
        html: htmlBody || undefined,
      });
      return {
        delivered: true,
        transport: `mx:${mxHost}`,
        from: sender,
        to: recipient,
      };
    } catch (err) {
      lastErr = err;
    }
  }

  const ownDomainHint = config.domains && config.domains[0] ? `@${config.domains[0]}` : 'local inboxes';
  const detail = lastErr && lastErr.message ? lastErr.message : 'connection failed';
  const err = new Error(
    `Direct outbound SMTP to ${toDomain}:25 failed (${detail}). Outbound port 25 may be blocked by this host — configure OUTBOUND_SMTP_HOST in .env for external delivery, or send between ${ownDomainHint} or @mailto.plus / @fexpost.com inboxes.`
  );
  err.statusCode = 502;
  throw err;
}

module.exports = {
  createSmtpServer,
  verifySmtpConnectivity,
  sendInternalSmtpMail,
  sendOutboundEmail,
  stripHtmlToText,
};
