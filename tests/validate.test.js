import { describe, it, expect } from 'vitest';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  RESERVED_USERNAMES,
  validateUsername,
  validateDomain,
  validateAddress,
  generateRandomUsername,
} = require('../server/validate');

describe('username and address validation', () => {
  it('accepts valid usernames and normalizes uppercase and whitespace', () => {
    const res1 = validateUsername('  Alex.Demo_01-x  ');
    expect(res1).toEqual({ valid: true, username: 'alex.demo_01-x' });

    const res2 = validateUsername('A1B');
    expect(res2).toEqual({ valid: true, username: 'a1b' });
  });

  it('rejects usernames that are too short or too long', () => {
    expect(validateUsername('ab').valid).toBe(false);
    expect(validateUsername('a').valid).toBe(false);
    expect(validateUsername('').valid).toBe(false);
    expect(validateUsername('a'.repeat(31)).valid).toBe(false);
    expect(validateUsername('a'.repeat(30)).valid).toBe(true);
  });

  it('rejects usernames with consecutive dots or invalid boundary characters', () => {
    expect(validateUsername('alex..demo').valid).toBe(false);
    expect(validateUsername('.alex').valid).toBe(false);
    expect(validateUsername('alex.').valid).toBe(false);
    expect(validateUsername('-alex').valid).toBe(false);
    expect(validateUsername('alex_').valid).toBe(false);
    expect(validateUsername('alex+tag').valid).toBe(false);
  });

  it('rejects all reserved usernames case-insensitively', () => {
    for (const reserved of RESERVED_USERNAMES) {
      const upper = reserved.toUpperCase();
      const res = validateUsername(upper);
      expect(res.valid).toBe(false);
    }
    expect(validateUsername('postmaster').valid).toBe(false);
    expect(validateUsername('No-Reply').valid).toBe(false);
  });

  it('validates domains and full addresses with lowercase normalization', () => {
    const domains = ['mail1.com', 'mail2.com'];
    expect(validateDomain('MAIL1.COM', domains)).toEqual({ valid: true, domain: 'mail1.com' });
    expect(validateDomain('unknown.org', domains).valid).toBe(false);

    expect(validateAddress('User.One@MAIL2.COM', domains)).toEqual({
      valid: true,
      address: 'user.one@mail2.com',
      username: 'user.one',
      domain: 'mail2.com',
    });
    expect(validateAddress('invalid-email', domains).valid).toBe(false);
  });

  it('generates 10-character lowercase alphanumeric random usernames', () => {
    for (let i = 0; i < 20; i += 1) {
      const name = generateRandomUsername();
      expect(name).toMatch(/^[a-z0-9]{10}$/);
      expect(validateUsername(name).valid).toBe(true);
    }
  });
});
