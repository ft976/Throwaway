'use strict';

const fs = require('node:fs');
const path = require('node:path');
const Redis = require('ioredis');

class MemoryRedisClient {
  constructor(options = {}) {
    this.strings = new Map();
    this.lists = new Map();
    this.expiries = new Map();
    this.status = 'ready';
    this.persistFile = options.persistFile ? path.resolve(options.persistFile) : '';
    this._saveTimer = null;

    if (this.persistFile) {
      this._loadFromDisk();
    }
  }

  _loadFromDisk() {
    try {
      if (!fs.existsSync(this.persistFile)) return;
      const raw = fs.readFileSync(this.persistFile, 'utf8');
      if (!raw.trim()) return;
      const parsed = JSON.parse(raw);
      const now = Date.now();

      if (parsed && typeof parsed.expiries === 'object') {
        for (const [k, ts] of Object.entries(parsed.expiries)) {
          if (typeof ts === 'number' && ts > now) {
            this.expiries.set(k, ts);
          }
        }
      }
      if (parsed && typeof parsed.strings === 'object') {
        for (const [k, v] of Object.entries(parsed.strings)) {
          const exp = this.expiries.get(k);
          if (exp === undefined || exp > now) {
            this.strings.set(k, String(v));
          }
        }
      }
      if (parsed && typeof parsed.lists === 'object') {
        for (const [k, v] of Object.entries(parsed.lists)) {
          const exp = this.expiries.get(k);
          if (Array.isArray(v) && (exp === undefined || exp > now)) {
            this.lists.set(k, v.map(String));
          }
        }
      }
    } catch (err) {
      console.error('Failed to load persistent store snapshot:', err.message);
    }
  }

  _scheduleSave() {
    if (!this.persistFile || this._saveTimer) return;
    this._saveTimer = setTimeout(() => {
      this._saveTimer = null;
      this._flushToDisk();
    }, 40);
    if (this._saveTimer.unref) this._saveTimer.unref();
  }

  _flushToDisk() {
    if (!this.persistFile) return;
    try {
      const now = Date.now();
      const strings = {};
      const lists = {};
      const expiries = {};

      for (const [k, v] of this.strings.entries()) {
        if (k.startsWith('rl:')) continue;
        const exp = this.expiries.get(k);
        if (exp !== undefined && exp <= now) continue;
        strings[k] = v;
        if (exp !== undefined) expiries[k] = exp;
      }

      for (const [k, v] of this.lists.entries()) {
        if (k.startsWith('rl:')) continue;
        const exp = this.expiries.get(k);
        if (exp !== undefined && exp <= now) continue;
        lists[k] = v;
        if (exp !== undefined) expiries[k] = exp;
      }

      const dir = path.dirname(this.persistFile);
      fs.mkdirSync(dir, { recursive: true });
      const tmpFile = `${this.persistFile}.${process.pid}.tmp`;
      fs.writeFileSync(tmpFile, JSON.stringify({ strings, lists, expiries }), 'utf8');
      fs.renameSync(tmpFile, this.persistFile);
    } catch (err) {
      console.error('Failed to persist store snapshot:', err.message);
    }
  }

  _purgeIfExpired(key) {
    const exp = this.expiries.get(key);
    if (exp !== undefined && Date.now() >= exp) {
      this.strings.delete(key);
      this.lists.delete(key);
      this.expiries.delete(key);
      return true;
    }
    return false;
  }

  async ping() {
    return 'PONG';
  }

  async get(key) {
    this._purgeIfExpired(key);
    if (!this.strings.has(key)) return null;
    return this.strings.get(key);
  }

  async mget(...keys) {
    const flatKeys = Array.isArray(keys[0]) ? keys[0] : keys;
    return Promise.all(flatKeys.map((k) => this.get(k)));
  }

  async set(key, value, ...args) {
    this._purgeIfExpired(key);
    let nx = false;
    let px = null;

    for (let i = 0; i < args.length; i += 1) {
      const token = String(args[i]).toUpperCase();
      if (token === 'NX') {
        nx = true;
      } else if (token === 'PX') {
        px = Number(args[i + 1]);
        i += 1;
      } else if (token === 'EX') {
        px = Number(args[i + 1]) * 1000;
        i += 1;
      }
    }

    if (nx && (this.strings.has(key) || this.lists.has(key))) {
      return null;
    }

    this.lists.delete(key);
    this.strings.set(key, String(value));

    if (px !== null && Number.isFinite(px)) {
      this.expiries.set(key, Date.now() + px);
    } else {
      this.expiries.delete(key);
    }

    if (!key.startsWith('rl:')) this._scheduleSave();
    return 'OK';
  }

  async del(...keys) {
    const flatKeys = Array.isArray(keys[0]) ? keys[0] : keys;
    let count = 0;
    for (const key of flatKeys) {
      this._purgeIfExpired(key);
      const existed = this.strings.delete(key) || this.lists.delete(key);
      this.expiries.delete(key);
      if (existed) count += 1;
    }
    if (count > 0) this._scheduleSave();
    return count;
  }

  async lpush(key, ...values) {
    this._purgeIfExpired(key);
    let list = this.lists.get(key);
    if (!list) {
      list = [];
      this.lists.set(key, list);
    }
    for (const v of values) {
      list.unshift(String(v));
    }
    this._scheduleSave();
    return list.length;
  }

  async ltrim(key, start, stop) {
    this._purgeIfExpired(key);
    const list = this.lists.get(key);
    if (!list) return 'OK';
    const len = list.length;
    const normStart = start < 0 ? Math.max(0, len + start) : start;
    const normStop = stop < 0 ? len + stop : stop;
    if (normStart > normStop || normStart >= len) {
      this.lists.delete(key);
      this.expiries.delete(key);
      return 'OK';
    }
    this.lists.set(key, list.slice(normStart, normStop + 1));
    this._scheduleSave();
    return 'OK';
  }

  async lrange(key, start, stop) {
    this._purgeIfExpired(key);
    const list = this.lists.get(key);
    if (!list) return [];
    const len = list.length;
    const normStart = start < 0 ? Math.max(0, len + start) : start;
    const normStop = stop < 0 ? len + stop : stop;
    if (normStart > normStop || normStart >= len) return [];
    return list.slice(normStart, normStop + 1);
  }

  async lrem(key, count, value) {
    this._purgeIfExpired(key);
    const list = this.lists.get(key);
    if (!list) return 0;
    const target = String(value);
    let removed = 0;
    if (count === 0) {
      const next = list.filter((item) => {
        if (item === target) {
          removed += 1;
          return false;
        }
        return true;
      });
      if (next.length === 0) {
        this.lists.delete(key);
        this.expiries.delete(key);
      } else {
        this.lists.set(key, next);
      }
      return removed;
    }
    const next = [];
    for (const item of list) {
      if (item === target && removed < Math.abs(count)) {
        removed += 1;
      } else {
        next.push(item);
      }
    }
    this.lists.set(key, next);
    if (removed > 0) this._scheduleSave();
    return removed;
  }

  async pexpireat(key, timestampMs) {
    this._purgeIfExpired(key);
    if (!this.strings.has(key) && !this.lists.has(key)) {
      return 0;
    }
    const ts = Number(timestampMs);
    if (Date.now() >= ts) {
      await this.del(key);
      return 1;
    }
    this.expiries.set(key, ts);
    if (!key.startsWith('rl:')) this._scheduleSave();
    return 1;
  }

  async pexpire(key, ms) {
    return this.pexpireat(key, Date.now() + Number(ms));
  }

  async pttl(key) {
    this._purgeIfExpired(key);
    if (!this.strings.has(key) && !this.lists.has(key)) return -2;
    const exp = this.expiries.get(key);
    if (exp === undefined) return -1;
    return Math.max(0, exp - Date.now());
  }

  async incr(key) {
    this._purgeIfExpired(key);
    const current = this.strings.has(key) ? Number(this.strings.get(key)) : 0;
    const next = Number.isFinite(current) ? current + 1 : 1;
    this.strings.set(key, String(next));
    return next;
  }

  pipeline() {
    const ops = [];
    const self = this;
    const builder = {
      get(k) { ops.push(['get', [k]]); return builder; },
      set(k, v, ...a) { ops.push(['set', [k, v, ...a]]); return builder; },
      del(...k) { ops.push(['del', k]); return builder; },
      lpush(k, ...v) { ops.push(['lpush', [k, ...v]]); return builder; },
      ltrim(k, s, e) { ops.push(['ltrim', [k, s, e]]); return builder; },
      lrange(k, s, e) { ops.push(['lrange', [k, s, e]]); return builder; },
      lrem(k, c, v) { ops.push(['lrem', [k, c, v]]); return builder; },
      pexpireat(k, ts) { ops.push(['pexpireat', [k, ts]]); return builder; },
      pexpire(k, ms) { ops.push(['pexpire', [k, ms]]); return builder; },
      async exec() {
        const results = [];
        for (const [method, args] of ops) {
          try {
            const res = await self[method](...args);
            results.push([null, res]);
          } catch (err) {
            results.push([err, null]);
          }
        }
        return results;
      },
    };
    return builder;
  }

  multi() {
    return this.pipeline();
  }

  on() {
    return this;
  }

  async quit() {
    if (this._saveTimer) {
      clearTimeout(this._saveTimer);
      this._saveTimer = null;
    }
    this._flushToDisk();
    this.status = 'end';
    return 'OK';
  }
}

function createRedisClient(config) {
  if (config && config.redisMode === 'memory') {
    return new MemoryRedisClient({ persistFile: config.persistFile || '' });
  }

  const client = new Redis(config.redisUrl, {
    maxRetriesPerRequest: 3,
    enableReadyCheck: true,
    retryStrategy(times) {
      return Math.min(times * 200, 2000);
    },
  });

  client.on('error', (err) => {
    console.error('Redis error:', err.message);
  });

  return client;
}

module.exports = {
  createRedisClient,
  MemoryRedisClient,
};
