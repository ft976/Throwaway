'use strict';

const http = require('node:http');
const { loadConfig } = require('./config');
const { createRedisClient } = require('./redis');
const { createStore } = require('./store');
const { createSmtpServer } = require('./smtp');
const { createApp } = require('./api');

async function start() {
  let config;
  try {
    config = loadConfig();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  const redis = createRedisClient(config);
  const store = createStore(redis, config);
  const app = createApp({ config, redis, store });

  const httpServer = http.createServer(app);
  const smtpServer = createSmtpServer({ config, store });

  await new Promise((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(config.httpPort, '0.0.0.0', resolve);
  });
  console.log(`HTTP server listening on port ${config.httpPort} (domains: ${config.domains.join(', ')})`);

  await new Promise((resolve, reject) => {
    smtpServer.once('error', reject);
    smtpServer.listen(config.smtpPort, '0.0.0.0', resolve);
  });
  console.log(`SMTP server listening on port ${config.smtpPort}`);

  let shuttingDown = false;
  const shutdown = async (signal) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`Received ${signal}, shutting down gracefully...`);

    const forceTimer = setTimeout(() => {
      console.error('Forced exit after shutdown timeout.');
      process.exit(1);
    }, 10000);
    forceTimer.unref();

    try {
      await new Promise((resolve) => {
        smtpServer.close(() => resolve());
      });
      await new Promise((resolve) => {
        httpServer.close(() => resolve());
      });
      await redis.quit();
      console.log('Shutdown complete.');
      process.exit(0);
    } catch (err) {
      console.error('Error during shutdown:', err.message);
      process.exit(1);
    }
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

if (require.main === module) {
  start().catch((err) => {
    console.error('Fatal boot error:', err.message);
    process.exit(1);
  });
}

module.exports = {
  start,
};
