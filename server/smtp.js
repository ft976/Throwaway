'use strict';

const fs = require('node:fs');
const { SMTPServer } = require('smtp-server');
const { simpleParser } = require('mailparser');
const { normalizeAddress } = require('./validate');
const { sanitizeEmailHtml, createSnippet } = require('./sanitize');

const MAX_RECIPIENTS = 10;

function buildSmtpError(message, responseCode) {
  const err = new Error(message);
  err.responseCode = responseCode;
  return err;
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

          const text = parsed.text ? String(parsed.text) : '';
          const rawHtml = typeof parsed.html === 'string' ? parsed.html : '';
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

module.exports = {
  createSmtpServer,
};
